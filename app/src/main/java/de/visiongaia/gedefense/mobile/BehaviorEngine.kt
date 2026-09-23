package de.visiongaia.gedefense.mobile

import android.content.Context
import java.util.Calendar
import java.util.Locale
import kotlin.math.max

class BehaviorEngine(context: Context, private val xdr: XdrEngine) {
    private val lock = Any()
    private val store = BehaviorBaselineStore(context)
    private var lastEvaluationMillis = 0L

    fun initialize() = store.initialize()
    fun snapshot(): BehaviorSnapshot = store.snapshot()
    fun setAutoQuarantineCritical(enabled: Boolean): Boolean = store.setAutoQuarantineCritical(enabled)
    fun resetLearning(): Boolean = synchronized(lock) { lastEvaluationMillis = 0L; store.resetLearning() }
    fun beginSession() = synchronized(lock) { lastEvaluationMillis = 0L }

    fun evaluateLive(snapshot: FullFlowAnalyticsSnapshot, now: Long = System.currentTimeMillis(), force: Boolean = false): List<BehaviorAnomaly> = synchronized(lock) {
        if (snapshot.state != "ACTIVE" || snapshot.startedAtMillis <= 0L) return@synchronized emptyList()
        if (!store.snapshot(now).baselineIntegrityOk) return@synchronized emptyList()
        if (!force && now - lastEvaluationMillis < EVALUATION_INTERVAL_MS) return@synchronized emptyList()
        lastEvaluationMillis = now
        val duration = max(60_000L, snapshot.updatedAtMillis - snapshot.startedAtMillis)
        val anomalies = snapshot.apps.asSequence()
            .filter { isPackage(it.owner) }
            .flatMap { app -> detect(app, duration, now).asSequence() }
            .sortedWith(compareByDescending<BehaviorAnomaly> { it.severity.ordinal }.thenByDescending { it.riskPoints }.thenByDescending { it.confidence })
            .take(MAX_ANOMALIES_PER_PASS)
            .toList()

        val recorded = ArrayList<BehaviorAnomaly>(anomalies.size)
        anomalies.forEach { anomaly ->
            val emitted = xdr.recordBehaviorAnomaly(anomaly)
            if (emitted) {
                recorded += anomaly
                if (anomaly.severity == XdrSeverity.CRITICAL && anomaly.confidence >= AUTO_QUARANTINE_MIN_CONFIDENCE && store.autoQuarantineCritical() && !xdr.isQuarantined(anomaly.packageName)) {
                    xdr.setQuarantined(anomaly.packageName, true)
                }
            }
        }
        store.markAnomalies(recorded)
        anomalies
    }

    fun commitSession(snapshot: FullFlowAnalyticsSnapshot, now: Long = System.currentTimeMillis()) = synchronized(lock) {
        if (snapshot.startedAtMillis <= 0L) return@synchronized
        if (!store.snapshot(now).baselineIntegrityOk) return@synchronized
        val anomalies = evaluateLive(snapshot, now, force = true)
        val excludedPackages = anomalies.asSequence()
            .filter { it.severity == XdrSeverity.HIGH || it.severity == XdrSeverity.CRITICAL }
            .mapTo(linkedSetOf()) { it.packageName }
        snapshot.apps.asSequence()
            .filter { isPackage(it.owner) }
            .filter { !xdr.isQuarantined(it.owner) }
            .filter { it.totalBytes >= MIN_BASELINE_BYTES || snapshot.updatedAtMillis - snapshot.startedAtMillis >= MIN_BASELINE_DURATION_MS }
            .take(MAX_APPS_PER_SESSION)
            .toList()
            .also { apps ->
                val duration = max(60_000L, snapshot.updatedAtMillis - snapshot.startedAtMillis)
                store.observeBatch(apps, duration, now, excludedPackages)
            }
    }

    private fun detect(app: AppFlowTraffic, durationMillis: Long, now: Long): List<BehaviorAnomaly> {
        val profile = store.profile(app.owner) ?: return emptyList()
        if (!profile.mature) return emptyList()
        val minutes = durationMillis.toDouble() / 60_000.0
        val txRate = (app.txBytes / minutes).toLong().coerceAtLeast(0L)
        val totalRate = (app.totalBytes / minutes).toLong().coerceAtLeast(0L)
        val flowRate = (app.openedFlows / minutes).toLong().coerceAtLeast(0L)
        val txRatioPermille = if (app.totalBytes > 0L) ((app.txBytes * 1000L) / app.totalBytes).toInt().coerceIn(0, 1000) else 0
        val out = ArrayList<BehaviorAnomaly>(7)

        val baselineTx = profile.avgTxPerMinute.coerceAtLeast(1L)
        val baselineTotal = profile.avgTotalPerMinute.coerceAtLeast(1L)
        val baselineFlows = profile.avgFlowsPerMinute.coerceAtLeast(1L)
        val txFactor = txRate.toDouble() / baselineTx.toDouble()
        val totalFactor = totalRate.toDouble() / baselineTotal.toDouble()
        val flowFactor = flowRate.toDouble() / baselineFlows.toDouble()
        val txThreshold = robustRateThreshold(baselineTx, profile.txDeviationPerMinute, factor = 4L)
        val totalThreshold = robustRateThreshold(baselineTotal, profile.totalDeviationPerMinute, factor = 4L)
        val flowThreshold = robustRateThreshold(baselineFlows, profile.flowDeviationPerMinute, factor = 4L)

        if (app.txBytes >= 8L * MIB && txRatioPermille >= max(720, profile.avgUploadRatioPermille + 220) && txRate >= max(2L * MIB, txThreshold)) {
            val critical = (app.txBytes >= 64L * MIB && txFactor >= 6.0) || txFactor >= 10.0
            val confidence = confidence(profile, if (critical) 20 else bucketBoost(txFactor))
            out += anomaly(
                app, profile, BehaviorAnomalyType.POTENTIAL_EXFILTRATION,
                if (critical) XdrSeverity.CRITICAL else XdrSeverity.HIGH,
                if (critical) 80 else 62,
                confidence,
                "Potential data-exfiltration pattern",
                "upload=${app.txBytes}; download=${app.rxBytes}; upload_per_min=$txRate; baseline_upload_per_min=${profile.avgTxPerMinute}; tx_deviation=${profile.txDeviationPerMinute}; factor=${fmt(txFactor)}; upload_ratio_pm=$txRatioPermille; baseline_ratio_pm=${profile.avgUploadRatioPermille}",
                "exfil:${bucket(txFactor)}:${bucketRatio(txRatioPermille)}",
                now,
            )
        }

        if (app.totalBytes >= 12L * MIB && totalRate >= max(3L * MIB, totalThreshold) && totalFactor >= 4.0) {
            val confidence = confidence(profile, bucketBoost(totalFactor))
            out += anomaly(
                app, profile, BehaviorAnomalyType.TRAFFIC_SPIKE, XdrSeverity.HIGH, 50, confidence,
                "Unusual traffic-volume spike",
                "traffic=${app.totalBytes}; traffic_per_min=$totalRate; baseline_per_min=${profile.avgTotalPerMinute}; total_deviation=${profile.totalDeviationPerMinute}; factor=${fmt(totalFactor)}",
                "spike:${bucket(totalFactor)}", now,
            )
        }

        if (profile.avgUploadRatioPermille > 0 && app.txBytes >= 4L * MIB) {
            val ratioDelta = txRatioPermille - profile.avgUploadRatioPermille
            if (txRatioPermille >= 700 && ratioDelta >= 300 && txFactor >= 2.5) {
                val high = ratioDelta >= 500 && app.txBytes >= 16L * MIB
                val confidence = confidence(profile, (ratioDelta / 25).coerceAtMost(20))
                out += anomaly(
                    app, profile, BehaviorAnomalyType.EGRESS_RATIO_SHIFT,
                    if (high) XdrSeverity.HIGH else XdrSeverity.MEDIUM,
                    if (high) 48 else 32,
                    confidence,
                    "Upload/download ratio shifted",
                    "upload_ratio_pm=$txRatioPermille; baseline_ratio_pm=${profile.avgUploadRatioPermille}; delta_pm=$ratioDelta; upload=${app.txBytes}; factor=${fmt(txFactor)}",
                    "ratio:${bucketRatio(txRatioPermille)}:${bucketRatio(ratioDelta.coerceAtLeast(0))}", now,
                )
            }
        }

        if (app.openedFlows >= 40L && flowRate >= max(30L, flowThreshold) && flowFactor >= 4.0) {
            val high = app.openedFlows >= 120L && flowFactor >= 8.0
            val confidence = confidence(profile, bucketBoost(flowFactor))
            out += anomaly(
                app, profile, BehaviorAnomalyType.CONNECTION_FANOUT,
                if (high) XdrSeverity.HIGH else XdrSeverity.MEDIUM,
                if (high) 44 else 28,
                confidence,
                "Connection fan-out exceeded baseline",
                "opened_flows=${app.openedFlows}; flows_per_min=$flowRate; baseline_flows_per_min=${profile.avgFlowsPerMinute}; flow_deviation=${profile.flowDeviationPerMinute}; factor=${fmt(flowFactor)}",
                "fanout:${bucket(flowFactor)}", now,
            )
        }

        val newDomains = app.topDomains.asSequence().map { normalizeDomain(it.domain) }.filter(String::isNotEmpty)
            .filterNot { it in profile.knownDomains }.distinct().take(8).toList()
        val novelDomainThreshold = max(2, ((profile.avgDomainCardinality + 1) / 2).coerceAtMost(5))
        if (newDomains.size >= novelDomainThreshold && app.totalBytes >= 512L * 1024L) {
            val high = newDomains.size >= max(4, novelDomainThreshold + 1) && app.totalBytes >= 5L * MIB
            val confidence = confidence(profile, (newDomains.size * 3).coerceAtMost(18))
            out += anomaly(
                app, profile, BehaviorAnomalyType.NEW_DESTINATION_BURST,
                if (high) XdrSeverity.HIGH else XdrSeverity.MEDIUM,
                if (high) 44 else 28,
                confidence,
                "New network-destination burst",
                "new_domains=${newDomains.take(8).joinToString(",")}; required=$novelDomainThreshold; baseline_domain_cardinality=${profile.avgDomainCardinality}; known_domains=${profile.knownDomains.size}; traffic=${app.totalBytes}",
                "domains:${newDomains.sorted().joinToString(",")}", now,
            )
        }

        val newCountries = app.topCountries.filter { it.countryCode.uppercase(Locale.ROOT) !in profile.knownCountries && it.bytes >= 2L * MIB }
        if (newCountries.isNotEmpty()) {
            val bytes = newCountries.fold(0L) { acc, country -> saturatingAdd(acc, country.bytes) }
            val high = newCountries.size >= max(2, profile.avgCountryCardinality + 1) || bytes >= 16L * MIB
            val confidence = confidence(profile, (newCountries.size * 5).coerceAtMost(18))
            out += anomaly(
                app, profile, BehaviorAnomalyType.NEW_COUNTRY,
                if (high) XdrSeverity.HIGH else XdrSeverity.MEDIUM,
                if (high) 42 else 26,
                confidence,
                "New network geography observed",
                "new_countries=${newCountries.joinToString(",") { it.countryCode.uppercase(Locale.ROOT) }}; bytes=$bytes; baseline_country_cardinality=${profile.avgCountryCardinality}; known_countries=${profile.knownCountries.size}",
                "countries:${newCountries.map { it.countryCode.uppercase(Locale.ROOT) }.sorted().joinToString(",")}", now,
            )
        }

        if (profile.observations >= 10 && app.totalBytes >= 5L * MIB) {
            val hour = Calendar.getInstance().apply { timeInMillis = now }.get(Calendar.HOUR_OF_DAY)
            val h = profile.hourHistogram
            val seenNearby = listOf((hour + 23) % 24, hour, (hour + 1) % 24).any { h.getOrElse(it) { 0 } > 0 }
            if (!seenNearby) {
                out += anomaly(
                    app, profile, BehaviorAnomalyType.OFF_HOURS_ACTIVITY, XdrSeverity.MEDIUM, 22,
                    confidence(profile, 4),
                    "Activity outside learned hours",
                    "hour=$hour; traffic=${app.totalBytes}; learned_sessions=${profile.observations}",
                    "hour:$hour", now,
                )
            }
        }
        return out
    }

    private fun anomaly(
        app: AppFlowTraffic,
        profile: BehaviorProfile,
        type: BehaviorAnomalyType,
        severity: XdrSeverity,
        risk: Int,
        confidence: Int,
        title: String,
        detail: String,
        fp: String,
        now: Long,
    ) = BehaviorAnomaly(
        packageName = app.owner,
        label = app.label,
        type = type,
        severity = severity,
        riskPoints = risk.coerceIn(0, 100),
        confidence = confidence.coerceIn(0, 100),
        baselineObservations = profile.observations,
        title = title,
        detail = detail.take(1100),
        fingerprint = fp.take(300),
        atMillis = now,
    )

    private fun confidence(profile: BehaviorProfile, signalBoost: Int): Int =
        (50 + profile.observations.coerceAtMost(20) * 2 + signalBoost.coerceIn(0, 10)).coerceIn(55, 100)

    private fun robustRateThreshold(baseline: Long, deviation: Long, factor: Long): Long {
        val factorFloor = safeMultiply(baseline.coerceAtLeast(1L), factor)
        val deviationFloor = saturatingAdd(baseline.coerceAtLeast(1L), safeMultiply(deviation.coerceAtLeast(1L), 4L))
        return max(factorFloor, deviationFloor)
    }

    private fun bucketBoost(value: Double): Int = when { value >= 12 -> 10; value >= 8 -> 8; value >= 5 -> 6; else -> 4 }
    private fun bucket(value: Double): Int = when { value >= 20 -> 20; value >= 10 -> 10; value >= 5 -> 5; else -> 1 }
    private fun bucketRatio(value: Int): Int = (value.coerceAtLeast(0) / 100) * 100
    private fun fmt(value: Double): String = "%.1f".format(Locale.ROOT, value)
    private fun isPackage(value: String) = value.length in 3..256 && value.contains('.') && !value.startsWith("uid-") && !value.startsWith("uid:") && value.none(Char::isWhitespace)
    private fun normalizeDomain(value: String) = value.trim().lowercase(Locale.ROOT).trimEnd('.').take(253)
    private fun safeMultiply(value: Long, factor: Long): Long = if (factor <= 0L || value <= 0L) 0L else if (value > Long.MAX_VALUE / factor) Long.MAX_VALUE else value * factor
    private fun saturatingAdd(a: Long, b: Long): Long = if (b > 0L && a > Long.MAX_VALUE - b) Long.MAX_VALUE else a + b

    companion object {
        private const val MIB = 1024L * 1024L
        private const val EVALUATION_INTERVAL_MS = 30_000L
        private const val MIN_BASELINE_BYTES = 64L * 1024L
        private const val MIN_BASELINE_DURATION_MS = 2L * 60L * 1000L
        private const val MAX_APPS_PER_SESSION = 128
        private const val MAX_ANOMALIES_PER_PASS = 32
        private const val AUTO_QUARANTINE_MIN_CONFIDENCE = 85
    }
}
