package de.visiongaia.gedefense.mobile

import android.content.Context
import android.util.Base64
import de.visiongaia.gedefense.mobile.core.AuthenticatedSnapshotState
import de.visiongaia.gedefense.mobile.core.BoundedSecretKeyCrypto
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import javax.crypto.Mac

class BehaviorBaselineStore(context: Context) {
    private val lock = Any()
    private val appContext = context.applicationContext
    private val recoveryDir = File(context.noBackupFilesDir, "vault-recovery")
    private val betaRecoveryBoundaryMillis: Long? by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        BetaVaultMigrationPolicy.updateBoundaryMillis(context)
    }
    private val legacyFile = File(context.noBackupFilesDir, "xdr/behavior-baseline.v1.json")
    private val snapshotStore = SecureSnapshotStore(
        file = File(context.noBackupFilesDir, "xdr/behavior-baseline.v2.bin"),
        hmacKey = null,
        domain = VaultDomain.BEHAVIOR_BASELINE,
        schemaVersion = 2,
        maxPlaintextBytes = MAX_FILE_BYTES,
        hmacKeyProvider = { SecureTelemetryVault.hotPathHmacKey(VaultDomain.BEHAVIOR_BASELINE) },
        legacyHmacKeyProvider = { behaviorHmacKey() },
    )

    @Volatile private var integrityOk = false
    @Volatile private var integrityReason: String? = "behavior_baseline_initializing"
    private var autoQuarantine = false
    private var profiles: MutableMap<String, BehaviorProfile> = linkedMapOf()

    fun initialize() = loadVerifiedOrMigrate()

    fun snapshot(now: Long = System.currentTimeMillis()): BehaviorSnapshot = synchronized(lock) {
        BehaviorSnapshot(
            generatedAtMillis = now,
            profiles = profiles.values.sortedWith(compareByDescending<BehaviorProfile> { it.lastAnomalyAtMillis }.thenByDescending { it.lastSeenMillis }).take(MAX_PROFILES),
            autoQuarantineCritical = autoQuarantine,
            baselineIntegrityOk = integrityOk,
        )
    }

    fun integrityFailureReason(): String? = integrityReason

    fun profile(packageName: String): BehaviorProfile? = synchronized(lock) { profiles[packageName] }

    fun observeBatch(apps: List<AppFlowTraffic>, durationMillis: Long, now: Long, excludedPackages: Set<String>) = synchronized(lock) {
        if (!integrityOk || apps.isEmpty()) return@synchronized
        var changed = false
        apps.asSequence()
            .filter { isPackage(it.owner) && it.owner !in excludedPackages }
            .take(MAX_APPS_PER_BATCH)
            .forEach { app ->
                profiles[app.owner] = observedProfile(app, durationMillis, now, profiles[app.owner])
                changed = true
            }
        if (!changed) return@synchronized
        trimProfiles()
        if (!persist()) degrade("behavior baseline batch persist failed")
    }

    fun markAnomalies(anomalies: Collection<BehaviorAnomaly>) = synchronized(lock) {
        if (!integrityOk || anomalies.isEmpty()) return@synchronized
        var changed = false
        anomalies.groupBy { it.packageName }.forEach { (packageName, group) ->
            val old = profiles[packageName] ?: return@forEach
            val latest = group.maxOfOrNull { it.atMillis } ?: return@forEach
            profiles[packageName] = old.copy(
                anomalyCount = (old.anomalyCount + group.size).coerceAtMost(100_000),
                lastAnomalyAtMillis = maxOf(old.lastAnomalyAtMillis, latest),
            )
            changed = true
        }
        if (changed && !persist()) degrade("behavior anomaly state persist failed")
    }

    fun setAutoQuarantineCritical(enabled: Boolean): Boolean = synchronized(lock) {
        if (!integrityOk) return@synchronized false
        val previous = autoQuarantine
        autoQuarantine = enabled
        if (persist()) true else {
            autoQuarantine = previous
            false
        }
    }

    fun autoQuarantineCritical(): Boolean = synchronized(lock) { integrityOk && autoQuarantine }

    fun resetLearning(): Boolean = synchronized(lock) {
        val previous = profiles
        val previousPolicy = autoQuarantine
        profiles = linkedMapOf()
        autoQuarantine = false
        integrityOk = true
        integrityReason = null
        if (!persist()) {
            profiles = previous
            autoQuarantine = previousPolicy
            integrityOk = false
            integrityReason = "behavior baseline reset persist failed"
            return@synchronized false
        }
        legacyFile.delete()
        legacyPrefs().edit().clear().apply()
        true
    }

    private fun observedProfile(app: AppFlowTraffic, durationMillis: Long, now: Long, old: BehaviorProfile?): BehaviorProfile {
        val minutes = durationMillis.coerceAtLeast(60_000L).toDouble() / 60_000.0
        val txRate = (app.txBytes / minutes).toLong().coerceIn(0L, MAX_RATE_BYTES_PER_MINUTE)
        val rxRate = (app.rxBytes / minutes).toLong().coerceIn(0L, MAX_RATE_BYTES_PER_MINUTE)
        val totalRate = (app.totalBytes / minutes).toLong().coerceIn(0L, MAX_RATE_BYTES_PER_MINUTE)
        val flowRate = (app.openedFlows / minutes).toLong().coerceIn(0L, MAX_FLOW_RATE_PER_MINUTE)
        val uploadRatioPermille = if (app.totalBytes > 0L) ((app.txBytes * 1000L) / app.totalBytes).toInt().coerceIn(0, 1000) else 0
        val domainCardinality = app.topDomains.size.coerceIn(0, MAX_DOMAINS_PER_OBSERVATION)
        val countryCardinality = app.topCountries.size.coerceIn(0, MAX_COUNTRIES)
        val txDeviation = deviation(old?.avgTxPerMinute, txRate)
        val totalDeviation = deviation(old?.avgTotalPerMinute, totalRate)
        val flowDeviation = deviation(old?.avgFlowsPerMinute, flowRate)
        val obs = ((old?.observations ?: 0) + 1).coerceAtMost(100_000)

        val knownDomains = LinkedHashSet(old?.knownDomains.orEmpty())
        val pendingDomains = LinkedHashMap(old?.pendingDomains.orEmpty())
        app.topDomains.asSequence().map { normalizeDomain(it.domain) }.filter(String::isNotEmpty).distinct().take(MAX_DOMAINS_PER_OBSERVATION).forEach { domain ->
            if (domain in knownDomains) return@forEach
            val count = ((pendingDomains[domain] ?: 0) + 1).coerceAtMost(PROMOTION_OBSERVATIONS)
            if (count >= PROMOTION_OBSERVATIONS) {
                knownDomains += domain
                pendingDomains.remove(domain)
            } else pendingDomains[domain] = count
        }

        val knownCountries = LinkedHashSet(old?.knownCountries.orEmpty())
        val pendingCountries = LinkedHashMap(old?.pendingCountries.orEmpty())
        app.topCountries.asSequence().map { it.countryCode.uppercase() }.filter { it.length == 2 }.distinct().take(MAX_COUNTRIES).forEach { country ->
            if (country in knownCountries) return@forEach
            val count = ((pendingCountries[country] ?: 0) + 1).coerceAtMost(PROMOTION_OBSERVATIONS)
            if (count >= PROMOTION_OBSERVATIONS) {
                knownCountries += country
                pendingCountries.remove(country)
            } else pendingCountries[country] = count
        }

        val hours = (old?.hourHistogram?.takeIf { it.size == 24 } ?: List(24) { 0 }).toMutableList()
        val hour = java.util.Calendar.getInstance().apply { timeInMillis = now }.get(java.util.Calendar.HOUR_OF_DAY)
        hours[hour] = (hours[hour] + 1).coerceAtMost(100_000)

        return BehaviorProfile(
            packageName = app.owner,
            label = app.label.take(120),
            observations = obs,
            firstSeenMillis = old?.firstSeenMillis ?: now,
            lastSeenMillis = now,
            avgTxPerMinute = ewma(old?.avgTxPerMinute, txRate),
            avgRxPerMinute = ewma(old?.avgRxPerMinute, rxRate),
            avgTotalPerMinute = ewma(old?.avgTotalPerMinute, totalRate),
            peakTxPerMinute = maxOf(old?.peakTxPerMinute ?: 0L, txRate),
            peakTotalPerMinute = maxOf(old?.peakTotalPerMinute ?: 0L, totalRate),
            txDeviationPerMinute = ewma(old?.txDeviationPerMinute, txDeviation),
            totalDeviationPerMinute = ewma(old?.totalDeviationPerMinute, totalDeviation),
            avgUploadRatioPermille = ewmaInt(old?.avgUploadRatioPermille, uploadRatioPermille, 1000),
            avgFlowsPerMinute = ewma(old?.avgFlowsPerMinute, flowRate),
            flowDeviationPerMinute = ewma(old?.flowDeviationPerMinute, flowDeviation),
            avgDomainCardinality = ewmaInt(old?.avgDomainCardinality, domainCardinality, MAX_DOMAINS_PER_OBSERVATION),
            avgCountryCardinality = ewmaInt(old?.avgCountryCardinality, countryCardinality, MAX_COUNTRIES),
            knownDomains = knownDomains.takeLastBounded(MAX_DOMAINS),
            knownCountries = knownCountries.takeLastBounded(MAX_COUNTRIES),
            pendingDomains = pendingDomains.takeNewestBounded(MAX_PENDING_DOMAINS),
            pendingCountries = pendingCountries.takeNewestBounded(MAX_PENDING_COUNTRIES),
            hourHistogram = hours,
            anomalyCount = old?.anomalyCount ?: 0,
            lastAnomalyAtMillis = old?.lastAnomalyAtMillis ?: 0L,
        )
    }

    private fun loadVerifiedOrMigrate() {
        val read = snapshotStore.read()
        when (read.state) {
                AuthenticatedSnapshotState.VALID -> {
                    val decoded = decodePayload(read.payload ?: ByteArray(0))
                    if (decoded == null) degrade("behavior baseline payload invalid")
                    else {
                        profiles = decoded.first
                        autoQuarantine = decoded.second
                        integrityOk = true
                        integrityReason = null
                        legacyFile.delete()
                        legacyPrefs().edit().clear().apply()
                    }
                }
                AuthenticatedSnapshotState.INVALID -> {
                    if (snapshotStore.archiveAndClearReconstructibleStartupFailure(recoveryDir, betaRecoveryBoundaryMillis) != null) {
                        profiles = linkedMapOf()
                        autoQuarantine = false
                        integrityOk = true
                        integrityReason = null
                        if (!persist()) degrade("behavior continuity recovery initialization failed")
                    } else degrade(read.reason ?: "behavior baseline authentication failed")
                }
                AuthenticatedSnapshotState.ABSENT -> migrateLegacyOrInitialize()
        }
    }

    private fun migrateLegacyOrInitialize() {
        if (!legacyFile.isFile) {
            profiles = linkedMapOf()
            autoQuarantine = false
            integrityOk = true
            integrityReason = null
            if (!persist()) degrade("behavior baseline initialization failed")
            return
        }
        val legacy = readLegacyVerified()
        if (legacy == null) {
            degrade("legacy behavior baseline authentication failed")
            return
        }
        profiles = legacy
        autoQuarantine = false
        integrityOk = true
        integrityReason = null
        if (!persist()) {
            degrade("behavior baseline migration failed")
            return
        }
        legacyFile.delete()
        legacyPrefs().edit().clear().apply()
    }

    private fun readLegacyVerified(): MutableMap<String, BehaviorProfile>? {
        return try {
            if (legacyFile.length() !in 1..MAX_FILE_BYTES.toLong()) null
            else {
                val wrapper = JSONObject(legacyFile.readText(StandardCharsets.UTF_8))
                val payload = wrapper.getString("payload")
                val expected = wrapper.getString("mac")
                val actual = legacySign(payload.toByteArray(StandardCharsets.UTF_8))
                if (!MessageDigest.isEqual(expected.toByteArray(StandardCharsets.US_ASCII), actual.toByteArray(StandardCharsets.US_ASCII))) null
                else {
                    val root = JSONObject(payload)
                    val arr = root.optJSONArray("profiles") ?: JSONArray()
                    linkedMapOf<String, BehaviorProfile>().also { out ->
                        for (i in 0 until minOf(arr.length(), MAX_PROFILES)) decodeLegacyProfile(arr.optJSONObject(i) ?: continue)?.let { out[it.packageName] = it }
                    }
                }
            }
        } catch (_: Throwable) { null }
    }

    /** Legacy preferences are acquired only inside the background migration path. */
    private fun legacyPrefs() = appContext.getSharedPreferences("gedefense_behavior", Context.MODE_PRIVATE)

    private fun persist(): Boolean {
        return try {
            val arr = JSONArray()
            profiles.values.sortedByDescending { it.lastSeenMillis }.take(MAX_PROFILES).forEach { arr.put(encodeProfile(it)) }
            val payload = JSONObject().put("version", 2).put("autoQuarantineCritical", autoQuarantine).put("profiles", arr)
                .toString().toByteArray(StandardCharsets.UTF_8)
            if (payload.size > MAX_FILE_BYTES) false
            else { snapshotStore.write(payload); true }
        } catch (_: Exception) { false }
    }

    private fun encodeProfile(p: BehaviorProfile) = JSONObject()
        .put("package", p.packageName).put("label", p.label).put("obs", p.observations)
        .put("first", p.firstSeenMillis).put("last", p.lastSeenMillis)
        .put("avgTx", p.avgTxPerMinute).put("avgRx", p.avgRxPerMinute).put("avgTotal", p.avgTotalPerMinute)
        .put("peakTx", p.peakTxPerMinute).put("peakTotal", p.peakTotalPerMinute)
        .put("txDev", p.txDeviationPerMinute).put("totalDev", p.totalDeviationPerMinute)
        .put("uploadRatioPm", p.avgUploadRatioPermille).put("avgFlows", p.avgFlowsPerMinute).put("flowDev", p.flowDeviationPerMinute)
        .put("avgDomainCount", p.avgDomainCardinality).put("avgCountryCount", p.avgCountryCardinality)
        .put("domains", JSONArray(p.knownDomains.toList())).put("countries", JSONArray(p.knownCountries.toList()))
        .put("pendingDomains", JSONObject(p.pendingDomains)).put("pendingCountries", JSONObject(p.pendingCountries))
        .put("hours", JSONArray(p.hourHistogram)).put("anomalies", p.anomalyCount).put("lastAnomaly", p.lastAnomalyAtMillis)

    private fun decodePayload(payload: ByteArray): Pair<MutableMap<String, BehaviorProfile>, Boolean>? {
        return try {
            if (payload.size > MAX_FILE_BYTES) null
            else {
                val root = JSONObject(payload.toString(StandardCharsets.UTF_8))
                if (root.optInt("version") != 2) null
                else {
                    val arr = root.optJSONArray("profiles") ?: JSONArray()
                    val out = linkedMapOf<String, BehaviorProfile>()
                    for (i in 0 until minOf(arr.length(), MAX_PROFILES)) decodeProfile(arr.optJSONObject(i) ?: continue)?.let { out[it.packageName] = it }
                    out to root.optBoolean("autoQuarantineCritical", false)
                }
            }
        } catch (_: Throwable) { null }
    }

    private fun decodeProfile(j: JSONObject): BehaviorProfile? {
        return try {
            val pkg = j.getString("package").take(256)
            if (!isPackage(pkg)) null else BehaviorProfile(
            packageName = pkg,
            label = j.optString("label", pkg).take(120),
            observations = j.optInt("obs").coerceIn(0, 100_000),
            firstSeenMillis = j.optLong("first").coerceAtLeast(0L),
            lastSeenMillis = j.optLong("last").coerceAtLeast(0L),
            avgTxPerMinute = j.optLong("avgTx").coerceIn(0L, MAX_RATE_BYTES_PER_MINUTE),
            avgRxPerMinute = j.optLong("avgRx").coerceIn(0L, MAX_RATE_BYTES_PER_MINUTE),
            avgTotalPerMinute = j.optLong("avgTotal").coerceIn(0L, MAX_RATE_BYTES_PER_MINUTE),
            peakTxPerMinute = j.optLong("peakTx").coerceIn(0L, MAX_RATE_BYTES_PER_MINUTE),
            peakTotalPerMinute = j.optLong("peakTotal").coerceIn(0L, MAX_RATE_BYTES_PER_MINUTE),
            txDeviationPerMinute = j.optLong("txDev", 0L).coerceIn(0L, MAX_RATE_BYTES_PER_MINUTE),
            totalDeviationPerMinute = j.optLong("totalDev", 0L).coerceIn(0L, MAX_RATE_BYTES_PER_MINUTE),
            avgUploadRatioPermille = j.optInt("uploadRatioPm", 0).coerceIn(0, 1000),
            avgFlowsPerMinute = j.optLong("avgFlows", 0L).coerceIn(0L, MAX_FLOW_RATE_PER_MINUTE),
            flowDeviationPerMinute = j.optLong("flowDev", 0L).coerceIn(0L, MAX_FLOW_RATE_PER_MINUTE),
            avgDomainCardinality = j.optInt("avgDomainCount", 0).coerceIn(0, MAX_DOMAINS_PER_OBSERVATION),
            avgCountryCardinality = j.optInt("avgCountryCount", 0).coerceIn(0, MAX_COUNTRIES),
            knownDomains = jsonStrings(j.optJSONArray("domains"), MAX_DOMAINS),
            knownCountries = jsonStrings(j.optJSONArray("countries"), MAX_COUNTRIES),
            pendingDomains = jsonCountMap(j.optJSONObject("pendingDomains"), MAX_PENDING_DOMAINS),
            pendingCountries = jsonCountMap(j.optJSONObject("pendingCountries"), MAX_PENDING_COUNTRIES),
            hourHistogram = jsonInts(j.optJSONArray("hours"), 24),
            anomalyCount = j.optInt("anomalies").coerceIn(0, 100_000),
            lastAnomalyAtMillis = j.optLong("lastAnomaly").coerceAtLeast(0L),
            )
        } catch (_: Throwable) { null }
    }

    private fun decodeLegacyProfile(j: JSONObject): BehaviorProfile? {
        return try {
            val pkg = j.getString("package").take(256)
            if (!isPackage(pkg)) null else BehaviorProfile(
            packageName = pkg,
            label = j.optString("label", pkg).take(120),
            observations = j.optInt("obs").coerceIn(0, 100_000),
            firstSeenMillis = j.optLong("first").coerceAtLeast(0L),
            lastSeenMillis = j.optLong("last").coerceAtLeast(0L),
            avgTxPerMinute = j.optLong("avgTx").coerceIn(0L, MAX_RATE_BYTES_PER_MINUTE),
            avgRxPerMinute = j.optLong("avgRx").coerceIn(0L, MAX_RATE_BYTES_PER_MINUTE),
            avgTotalPerMinute = j.optLong("avgTotal").coerceIn(0L, MAX_RATE_BYTES_PER_MINUTE),
            peakTxPerMinute = j.optLong("peakTx").coerceIn(0L, MAX_RATE_BYTES_PER_MINUTE),
            peakTotalPerMinute = j.optLong("peakTotal").coerceIn(0L, MAX_RATE_BYTES_PER_MINUTE),
            txDeviationPerMinute = j.optLong("txDev", 0L).coerceIn(0L, MAX_RATE_BYTES_PER_MINUTE),
            totalDeviationPerMinute = j.optLong("totalDev", 0L).coerceIn(0L, MAX_RATE_BYTES_PER_MINUTE),
            avgUploadRatioPermille = j.optInt("uploadRatioPm", 0).coerceIn(0, 1000),
            avgFlowsPerMinute = j.optLong("avgFlows", 0L).coerceIn(0L, MAX_FLOW_RATE_PER_MINUTE),
            flowDeviationPerMinute = j.optLong("flowDev", 0L).coerceIn(0L, MAX_FLOW_RATE_PER_MINUTE),
            avgDomainCardinality = j.optInt("avgDomainCount", 0).coerceIn(0, MAX_DOMAINS_PER_OBSERVATION),
            avgCountryCardinality = j.optInt("avgCountryCount", 0).coerceIn(0, MAX_COUNTRIES),
            knownDomains = jsonStrings(j.optJSONArray("domains"), MAX_DOMAINS),
            knownCountries = jsonStrings(j.optJSONArray("countries"), MAX_COUNTRIES),
            pendingDomains = emptyMap(),
            pendingCountries = emptyMap(),
            hourHistogram = jsonInts(j.optJSONArray("hours"), 24),
            anomalyCount = j.optInt("anomalies").coerceIn(0, 100_000),
            lastAnomalyAtMillis = j.optLong("lastAnomaly").coerceAtLeast(0L),
            )
        } catch (_: Throwable) { null }
    }

    private fun jsonStrings(a: JSONArray?, limit: Int): Set<String> {
        if (a == null) return emptySet()
        val out = linkedSetOf<String>()
        for (i in 0 until minOf(a.length(), limit)) a.optString(i).trim().takeIf { it.isNotEmpty() }?.let(out::add)
        return out
    }

    private fun jsonCountMap(o: JSONObject?, limit: Int): Map<String, Int> {
        if (o == null) return emptyMap()
        val out = linkedMapOf<String, Int>()
        val keys = o.keys()
        while (keys.hasNext() && out.size < limit) {
            val key = keys.next().take(253)
            val value = o.optInt(key).coerceIn(1, PROMOTION_OBSERVATIONS)
            if (key.isNotBlank()) out[key] = value
        }
        return out
    }

    private fun jsonInts(a: JSONArray?, size: Int): List<Int> = List(size) { index -> a?.optInt(index)?.coerceIn(0, 100_000) ?: 0 }
    private fun ewma(old: Long?, current: Long): Long {
        val boundedCurrent = current.coerceIn(0L, MAX_RATE_BYTES_PER_MINUTE)
        if (old == null || old <= 0L) return boundedCurrent
        val boundedOld = old.coerceAtMost(MAX_RATE_BYTES_PER_MINUTE)
        return (boundedOld - boundedOld / 4L + boundedCurrent / 4L).coerceAtMost(MAX_RATE_BYTES_PER_MINUTE)
    }

    private fun ewmaInt(old: Int?, current: Int, max: Int): Int {
        val boundedCurrent = current.coerceIn(0, max)
        if (old == null || old <= 0) return boundedCurrent
        val boundedOld = old.coerceIn(0, max)
        return ((boundedOld * 3L + boundedCurrent) / 4L).toInt().coerceIn(0, max)
    }

    private fun deviation(oldAverage: Long?, current: Long): Long {
        val old = oldAverage ?: return 0L
        val a = old.coerceIn(0L, MAX_RATE_BYTES_PER_MINUTE)
        val b = current.coerceIn(0L, MAX_RATE_BYTES_PER_MINUTE)
        return if (a >= b) a - b else b - a
    }
    private fun <T> LinkedHashSet<T>.takeLastBounded(limit: Int): Set<T> = if (size <= limit) toSet() else toList().takeLast(limit).toSet()
    private fun <K, V> LinkedHashMap<K, V>.takeNewestBounded(limit: Int): Map<K, V> = if (size <= limit) toMap() else entries.toList().takeLast(limit).associate { it.toPair() }

    private fun trimProfiles() {
        if (profiles.size <= MAX_PROFILES) return
        profiles.values.sortedBy { it.lastSeenMillis }.take(profiles.size - MAX_PROFILES).forEach { profiles.remove(it.packageName) }
    }

    private fun legacySign(bytes: ByteArray): String {
        val activeKey = behaviorHmacKey() ?: throw IllegalStateException("behavior baseline key unavailable")
        val signed = BoundedSecretKeyCrypto.execute(activeKey) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(activeKey)
            mac.doFinal(bytes)
        }
        return Base64.encodeToString(signed, Base64.NO_WRAP)
    }

    private fun behaviorHmacKey() =
        AndroidSecrets.hmacSha256OrNull("vgt.gedefense.mobile.behavior.hmac.v1")

    private fun degrade(reason: String) {
        profiles.clear()
        autoQuarantine = false
        integrityOk = false
        integrityReason = reason.take(160)
    }

    private fun normalizeDomain(value: String): String = value.trim().lowercase().trimEnd('.').take(253)
    private fun isPackage(value: String): Boolean = value.length in 3..256 && value.contains('.') && !value.startsWith("uid-") && !value.startsWith("uid:") && value.none(Char::isWhitespace)

    companion object {
        private const val MAX_PROFILES = 256
        private const val MAX_DOMAINS = 64
        private const val MAX_COUNTRIES = 24
        private const val MAX_PENDING_DOMAINS = 128
        private const val MAX_PENDING_COUNTRIES = 32
        private const val MAX_DOMAINS_PER_OBSERVATION = 24
        private const val PROMOTION_OBSERVATIONS = 3
        private const val MAX_APPS_PER_BATCH = 128
        private const val MAX_FILE_BYTES = 2 * 1024 * 1024
        private const val MAX_RATE_BYTES_PER_MINUTE = 1L shl 40
        private const val MAX_FLOW_RATE_PER_MINUTE = 1_000_000L
    }
}
