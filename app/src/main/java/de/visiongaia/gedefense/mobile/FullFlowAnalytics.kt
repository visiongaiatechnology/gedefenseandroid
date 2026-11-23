package de.visiongaia.gedefense.mobile

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.os.ParcelFileDescriptor
import de.visiongaia.gedefense.mobile.core.EvidenceEvent
import de.visiongaia.gedefense.mobile.core.IpAddress
import de.visiongaia.gedefense.mobile.core.IpPrefix
import de.visiongaia.gedefense.mobile.core.PrivacyAction
import de.visiongaia.gedefense.mobile.core.ThreatFeedCatalog
import java.io.BufferedReader
import java.io.FileInputStream
import java.io.InputStreamReader
import java.util.LinkedHashMap
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

/** Session-scoped full-flow analytics. Durable security events remain in EvidenceLedger. */
data class CountryTraffic(val countryCode: String, val bytes: Long, val flows: Int)
data class DomainTraffic(val domain: String, val queries: Long)

data class AppFlowTraffic(
    val owner: String,
    val label: String,
    val txBytes: Long,
    val rxBytes: Long,
    val activeFlows: Int,
    val openedFlows: Long,
    val blockedFlows: Long,
    val correlatedFlows: Long,
    val annotatedFlows: Long,
    val topCountries: List<CountryTraffic>,
    val topDomains: List<DomainTraffic>,
) {
    val totalBytes: Long get() = saturatingAdd(txBytes, rxBytes)
    private fun saturatingAdd(a: Long, b: Long): Long = if (Long.MAX_VALUE - a < b) Long.MAX_VALUE else a + b
}

data class FullFlowAnalyticsSnapshot(
    val state: String,
    val startedAtMillis: Long,
    val updatedAtMillis: Long,
    val txBytes: Long,
    val rxBytes: Long,
    val activeFlows: Int,
    val blockedFlows: Long,
    val correlatedFlows: Long,
    val annotatedFlows: Long,
    val topCountries: List<CountryTraffic>,
    val topDomains: List<DomainTraffic>,
    val apps: List<AppFlowTraffic>,
    val transportErrors: Long,
    val uniqueDestinations: Int = 0,
    val uniqueCountries: Int = 0,
) {
    val totalBytes: Long get() = if (Long.MAX_VALUE - txBytes < rxBytes) Long.MAX_VALUE else txBytes + rxBytes

    companion object {
        fun idle() = FullFlowAnalyticsSnapshot("IDLE", 0L, 0L, 0L, 0L, 0, 0L, 0L, 0L, emptyList(), emptyList(), emptyList(), 0L, 0, 0)
    }
}

class FullFlowAnalytics(private val context: Context) {
    private data class FlowMeta(
        val owner: String,
        val label: String,
        var country: String,
        val action: Int,
        val destinationIp: IpAddress? = null,
        var tx: Long = 0L,
        var rx: Long = 0L,
    )
    private data class MutableCountry(var bytes: Long = 0L, var flows: Int = 0)
    private data class MutableApp(
        val owner: String,
        val label: String,
        var tx: Long = 0L,
        var rx: Long = 0L,
        var active: Int = 0,
        var opened: Long = 0L,
        var blocked: Long = 0L,
        var correlated: Long = 0L,
        var annotated: Long = 0L,
        val countries: MutableMap<String, MutableCountry> = HashMap(),
        val domains: MutableMap<String, Long> = HashMap(),
    )

    private val lock = Any()
    private val flows = LinkedHashMap<Long, FlowMeta>()
    private val apps = LinkedHashMap<String, MutableApp>()
    private val countries = HashMap<String, MutableCountry>()
    private val domains = HashMap<String, Long>()
    private val destinations = LinkedHashSet<String>()
    private val historyBuckets = LinkedHashMap<Long, HourlyHistoryBucket>()
    private data class UnresolvedSample(val owner: String, val ip: IpAddress, var bytes: Long = 0L, var flows: Int = 0)
    private val unresolvedClosed = LinkedHashMap<Pair<String, IpAddress>, UnresolvedSample>()
    private var startedAt = 0L
    private var updatedAt = 0L
    private var txBytes = 0L
    private var rxBytes = 0L
    private var blocked = 0L
    private var correlated = 0L
    private var annotated = 0L
    private var transportErrors = 0L
    private var state = "IDLE"

    private class HourlyHistoryBucket(
        val hourStartMillis: Long,
        val apps: MutableMap<String, MutableApp> = HashMap(),
        val countries: MutableMap<String, MutableCountry> = HashMap(),
        val domains: MutableMap<String, Long> = HashMap(),
        var txBytes: Long = 0L,
        var rxBytes: Long = 0L,
        var blockedFlows: Long = 0L,
    )

    private fun currentBucketLocked(now: Long = System.currentTimeMillis()): HourlyHistoryBucket {
        val hourKey = (now / HOUR_MS) * HOUR_MS
        historyBuckets[hourKey]?.let { return it }
        while (historyBuckets.size >= MAX_HISTORY_HOURS) {
            val oldest = historyBuckets.keys.minOrNull() ?: break
            historyBuckets.remove(oldest)
        }
        return HourlyHistoryBucket(hourKey).also { historyBuckets[hourKey] = it }
    }

    fun snapshotForWindow(windowHours: Int, now: Long = System.currentTimeMillis()): FullFlowAnalyticsSnapshot = synchronized(lock) {
        if (windowHours <= 0) return@synchronized snapshotLocked()
        val cutoff = now - windowHours.toLong() * HOUR_MS
        val mergedApps = LinkedHashMap<String, MutableApp>()
        val mergedCountries = HashMap<String, MutableCountry>()
        val mergedDomains = HashMap<String, Long>()
        var wTx = 0L
        var wRx = 0L
        var wBlocked = 0L
        var earliest = 0L

        for (bucket in historyBuckets.values) {
            if (bucket.hourStartMillis + HOUR_MS < cutoff) continue
            if (earliest == 0L || bucket.hourStartMillis < earliest) earliest = bucket.hourStartMillis
            wTx = saturatingAdd(wTx, bucket.txBytes)
            wRx = saturatingAdd(wRx, bucket.rxBytes)
            wBlocked = saturatingAdd(wBlocked, bucket.blockedFlows)
            for ((cc, c) in bucket.countries) {
                val target = mergedCountries.getOrPut(cc) { MutableCountry() }
                target.bytes = saturatingAdd(target.bytes, c.bytes)
                target.flows += c.flows
            }
            for ((dom, q) in bucket.domains) {
                mergedDomains[dom] = saturatingAdd(mergedDomains[dom] ?: 0L, q)
            }
            for ((owner, srcApp) in bucket.apps) {
                val dstApp = mergedApps.getOrPut(owner) { MutableApp(owner, srcApp.label) }
                dstApp.tx = saturatingAdd(dstApp.tx, srcApp.tx)
                dstApp.rx = saturatingAdd(dstApp.rx, srcApp.rx)
                dstApp.opened = saturatingAdd(dstApp.opened, srcApp.opened)
                dstApp.blocked = saturatingAdd(dstApp.blocked, srcApp.blocked)
                for ((cc, c) in srcApp.countries) {
                    val target = dstApp.countries.getOrPut(cc) { MutableCountry() }
                    target.bytes = saturatingAdd(target.bytes, c.bytes)
                    target.flows += c.flows
                }
                for ((dom, q) in srcApp.domains) {
                    dstApp.domains[dom] = saturatingAdd(dstApp.domains[dom] ?: 0L, q)
                }
            }
        }
        val appList = mergedApps.values.asSequence()
            .map { app ->
                AppFlowTraffic(
                    app.owner, app.label, app.tx, app.rx, apps[app.owner]?.active ?: 0, app.opened, app.blocked, 0L, 0L,
                    topCountries(app.countries), topDomains(app.domains),
                )
            }
            .sortedByDescending { it.totalBytes }
            .take(MAX_APPS)
            .toList()
        FullFlowAnalyticsSnapshot(
            state = state,
            startedAtMillis = if (earliest > 0L) earliest else startedAt,
            updatedAtMillis = updatedAt,
            txBytes = wTx,
            rxBytes = wRx,
            activeFlows = flows.size,
            blockedFlows = wBlocked,
            correlatedFlows = correlated,
            annotatedFlows = annotated,
            topCountries = topCountries(mergedCountries),
            topDomains = topDomains(mergedDomains),
            apps = appList,
            transportErrors = transportErrors,
            uniqueDestinations = destinations.size,
            uniqueCountries = mergedCountries.size,
        )
    }

    fun reset(now: Long = System.currentTimeMillis()) = synchronized(lock) {
        flows.clear(); apps.clear(); countries.clear(); domains.clear(); destinations.clear(); unresolvedClosed.clear()
        startedAt = now; updatedAt = now; txBytes = 0L; rxBytes = 0L
        blocked = 0L; correlated = 0L; annotated = 0L; transportErrors = 0L; state = "ACTIVE"
    }

    fun stop() = synchronized(lock) {
        flows.clear(); apps.values.forEach { it.active = 0 }
        updatedAt = System.currentTimeMillis(); state = "STOPPED"
    }

    fun open(id: Long, owner: String, label: String, country: String, action: Int, destination: String? = null, destinationIp: IpAddress? = null) = synchronized(lock) {
        if (flows.size >= MAX_FLOWS) return@synchronized
        if (!destination.isNullOrBlank()) {
            if (destination !in destinations) {
                if (destinations.size >= MAX_DESTINATIONS) {
                    val it = destinations.iterator()
                    if (it.hasNext()) { it.next(); it.remove() }
                }
                destinations += destination.take(256)
            }
        }
        val app = apps.getOrPut(owner) { MutableApp(owner, label) }
        app.active = (app.active + 1).coerceAtMost(MAX_FLOWS)
        app.opened = saturatingAdd(app.opened, 1L)
        if (action == ACTION_CORRELATE) { app.correlated++; correlated++ }
        if (action == ACTION_ANNOTATE) { app.annotated++; annotated++ }
        flows[id] = FlowMeta(owner, label, country, action, destinationIp)
        countries.getOrPut(country) { MutableCountry() }.flows++
        app.countries.getOrPut(country) { MutableCountry() }.flows++
        val bucket = currentBucketLocked()
        bucket.countries.getOrPut(country) { MutableCountry() }.flows++
        val hApp = bucket.apps.getOrPut(owner) { MutableApp(owner, label) }
        hApp.opened = saturatingAdd(hApp.opened, 1L)
        hApp.countries.getOrPut(country) { MutableCountry() }.flows++
        updatedAt = System.currentTimeMillis()
    }

    fun update(id: Long, txTotal: Long, rxTotal: Long) = synchronized(lock) {
        val flow = flows[id] ?: return@synchronized
        val tx = txTotal.coerceAtLeast(0L); val rx = rxTotal.coerceAtLeast(0L)
        val dtx = (tx - flow.tx).coerceAtLeast(0L); val drx = (rx - flow.rx).coerceAtLeast(0L)
        flow.tx = maxOf(flow.tx, tx); flow.rx = maxOf(flow.rx, rx)
        addBytes(flow.owner, flow.country, dtx, drx)
        updatedAt = System.currentTimeMillis()
    }

    fun close(id: Long, txTotal: Long, rxTotal: Long) = synchronized(lock) {
        val flow = flows[id] ?: return@synchronized
        val dtx = (txTotal.coerceAtLeast(0L) - flow.tx).coerceAtLeast(0L)
        val drx = (rxTotal.coerceAtLeast(0L) - flow.rx).coerceAtLeast(0L)
        addBytes(flow.owner, flow.country, dtx, drx)
        if (flow.country == "ZZ" && flow.destinationIp != null) {
            val key = flow.owner to flow.destinationIp
            if (unresolvedClosed.size >= MAX_DESTINATIONS && key !in unresolvedClosed) {
                val it = unresolvedClosed.iterator()
                if (it.hasNext()) { it.next(); it.remove() }
            }
            val sample = unresolvedClosed.getOrPut(key) { UnresolvedSample(flow.owner, flow.destinationIp) }
            sample.bytes = saturatingAdd(sample.bytes, saturatingAdd(flow.tx, flow.rx))
            sample.flows++
        }
        apps[flow.owner]?.let { it.active = (it.active - 1).coerceAtLeast(0) }
        flows.remove(id); updatedAt = System.currentTimeMillis()
    }

    fun blocked(owner: String, label: String, country: String, bytes: Long, destination: String? = null) = synchronized(lock) {
        if (!destination.isNullOrBlank()) {
            if (destination !in destinations) {
                if (destinations.size >= MAX_DESTINATIONS) {
                    val it = destinations.iterator()
                    if (it.hasNext()) { it.next(); it.remove() }
                }
                destinations += destination.take(256)
            }
        }
        val app = apps.getOrPut(owner) { MutableApp(owner, label) }
        app.blocked++; blocked++
        val safe = bytes.coerceIn(0L, MAX_EVENT_BYTES)
        app.tx = saturatingAdd(app.tx, safe); txBytes = saturatingAdd(txBytes, safe)
        app.countries.getOrPut(country) { MutableCountry() }.apply { this.bytes = saturatingAdd(this.bytes, safe); flows++ }
        countries.getOrPut(country) { MutableCountry() }.apply { this.bytes = saturatingAdd(this.bytes, safe); flows++ }
        val bucket = currentBucketLocked()
        bucket.blockedFlows = saturatingAdd(bucket.blockedFlows, 1L)
        bucket.txBytes = saturatingAdd(bucket.txBytes, safe)
        bucket.countries.getOrPut(country) { MutableCountry() }.apply { this.bytes = saturatingAdd(this.bytes, safe); flows++ }
        val hApp = bucket.apps.getOrPut(owner) { MutableApp(owner, label) }
        hApp.blocked = saturatingAdd(hApp.blocked, 1L)
        hApp.tx = saturatingAdd(hApp.tx, safe)
        hApp.countries.getOrPut(country) { MutableCountry() }.apply { this.bytes = saturatingAdd(this.bytes, safe); flows++ }
        updatedAt = System.currentTimeMillis()
    }

    fun dnsQuery(id: Long, domain: String) = synchronized(lock) {
        val flow = flows[id] ?: return@synchronized
        val safe = normalizeDomain(domain) ?: return@synchronized
        val app = apps[flow.owner] ?: return@synchronized
        app.domains[safe] = saturatingAdd(app.domains[safe] ?: 0L, 1L)
        domains[safe] = saturatingAdd(domains[safe] ?: 0L, 1L)
        trimCounterMap(app.domains, MAX_DOMAINS_PER_APP)
        trimCounterMap(domains, MAX_GLOBAL_DOMAINS)
        val bucket = currentBucketLocked()
        bucket.domains[safe] = saturatingAdd(bucket.domains[safe] ?: 0L, 1L)
        trimCounterMap(bucket.domains, MAX_GLOBAL_DOMAINS)
        val hApp = bucket.apps.getOrPut(flow.owner) { MutableApp(flow.owner, flow.label) }
        hApp.domains[safe] = saturatingAdd(hApp.domains[safe] ?: 0L, 1L)
        trimCounterMap(hApp.domains, MAX_DOMAINS_PER_APP)
        updatedAt = System.currentTimeMillis()
    }

    fun clientHello(
        id: Long,
        @Suppress("UNUSED_PARAMETER") transport: String,
        sni: String?,
        @Suppress("UNUSED_PARAMETER") alpn: String?,
        @Suppress("UNUSED_PARAMETER") ja4: String,
        @Suppress("UNUSED_PARAMETER") ja3: String,
        @Suppress("UNUSED_PARAMETER") ech: Boolean,
    ) = synchronized(lock) {
        val flow = flows[id] ?: return@synchronized
        if (!sni.isNullOrBlank()) {
            val safe = normalizeDomain(sni)
            if (safe != null) {
                val app = apps[flow.owner]
                if (app != null && safe !in app.domains) {
                    app.domains[safe] = saturatingAdd(app.domains[safe] ?: 0L, 1L)
                    trimCounterMap(app.domains, MAX_DOMAINS_PER_APP)
                }
                if (safe !in domains) {
                    domains[safe] = saturatingAdd(domains[safe] ?: 0L, 1L)
                    trimCounterMap(domains, MAX_GLOBAL_DOMAINS)
                }
            }
        }
        updatedAt = System.currentTimeMillis()
    }

    fun transportError() = synchronized(lock) { transportErrors++; updatedAt = System.currentTimeMillis() }

    fun activeFlowCount(): Int = synchronized(lock) { flows.size }

    fun reclassifyUnknownCountries(lookup: (IpAddress) -> String?) = synchronized(lock) {
        for (flow in flows.values) {
            if (flow.country != "ZZ") continue
            val resolved = lookup(flow.destinationIp ?: continue) ?: continue
            if (resolved == "ZZ") continue
            val flowBytes = saturatingAdd(flow.tx, flow.rx)
            flow.country = resolved
            moveCountryStats(countries, "ZZ", resolved, flowBytes, 1)
            apps[flow.owner]?.let { app -> moveCountryStats(app.countries, "ZZ", resolved, flowBytes, 1) }
            historyBuckets.values.forEach { bucket ->
                if ("ZZ" in bucket.countries) moveCountryStats(bucket.countries, "ZZ", resolved, flowBytes, 1)
                bucket.apps[flow.owner]?.let { hApp ->
                    if ("ZZ" in hApp.countries) moveCountryStats(hApp.countries, "ZZ", resolved, flowBytes, 1)
                }
            }
        }
        val iterator = unresolvedClosed.iterator()
        while (iterator.hasNext()) {
            val sample = iterator.next().value
            val resolved = lookup(sample.ip) ?: continue
            if (resolved == "ZZ") continue
            moveCountryStats(countries, "ZZ", resolved, sample.bytes, sample.flows)
            apps[sample.owner]?.let { app -> moveCountryStats(app.countries, "ZZ", resolved, sample.bytes, sample.flows) }
            historyBuckets.values.forEach { bucket ->
                if ("ZZ" in bucket.countries) moveCountryStats(bucket.countries, "ZZ", resolved, sample.bytes, sample.flows)
                bucket.apps[sample.owner]?.let { hApp ->
                    if ("ZZ" in hApp.countries) moveCountryStats(hApp.countries, "ZZ", resolved, sample.bytes, sample.flows)
                }
            }
            iterator.remove()
        }
        updatedAt = System.currentTimeMillis()
    }

    private fun moveCountryStats(map: MutableMap<String, MutableCountry>, from: String, to: String, bytes: Long, flowsDelta: Int) {
        val src = map[from] ?: return
        val moveBytes = bytes.coerceIn(0L, src.bytes)
        val moveFlows = flowsDelta.coerceIn(0, src.flows)
        src.bytes = (src.bytes - moveBytes).coerceAtLeast(0L)
        src.flows = (src.flows - moveFlows).coerceAtLeast(0)
        if (src.flows == 0 && src.bytes == 0L) map.remove(from)
        val dst = map.getOrPut(to) { MutableCountry() }
        dst.bytes = saturatingAdd(dst.bytes, moveBytes)
        dst.flows += moveFlows
    }

    fun snapshot(): FullFlowAnalyticsSnapshot = synchronized(lock) {
        snapshotLocked()
    }

    private fun snapshotLocked(): FullFlowAnalyticsSnapshot {
        val appList = apps.values.asSequence()
            .map { app ->
                AppFlowTraffic(
                    app.owner, app.label, app.tx, app.rx, app.active, app.opened, app.blocked, app.correlated, app.annotated,
                    topCountries(app.countries), topDomains(app.domains),
                )
            }
            .sortedByDescending { it.totalBytes }
            .take(MAX_APPS)
            .toList()
        return FullFlowAnalyticsSnapshot(
            state, startedAt, updatedAt, txBytes, rxBytes, flows.size, blocked, correlated, annotated,
            topCountries(countries), topDomains(domains), appList, transportErrors,
            destinations.size, countries.size,
        )
    }

    private fun addBytes(owner: String, country: String, dtx: Long, drx: Long) {
        val app = apps[owner] ?: return
        app.tx = saturatingAdd(app.tx, dtx); app.rx = saturatingAdd(app.rx, drx)
        txBytes = saturatingAdd(txBytes, dtx); rxBytes = saturatingAdd(rxBytes, drx)
        val total = saturatingAdd(dtx, drx)
        app.countries.getOrPut(country) { MutableCountry() }.bytes = saturatingAdd(app.countries[country]?.bytes ?: 0L, total)
        countries.getOrPut(country) { MutableCountry() }.bytes = saturatingAdd(countries[country]?.bytes ?: 0L, total)
        if (total > 0L) {
            val bucket = currentBucketLocked()
            bucket.txBytes = saturatingAdd(bucket.txBytes, dtx)
            bucket.rxBytes = saturatingAdd(bucket.rxBytes, drx)
            bucket.countries.getOrPut(country) { MutableCountry() }.bytes = saturatingAdd(bucket.countries[country]?.bytes ?: 0L, total)
            val hApp = bucket.apps.getOrPut(owner) { MutableApp(owner, app.label) }
            hApp.tx = saturatingAdd(hApp.tx, dtx)
            hApp.rx = saturatingAdd(hApp.rx, drx)
            hApp.countries.getOrPut(country) { MutableCountry() }.bytes = saturatingAdd(hApp.countries[country]?.bytes ?: 0L, total)
        }
    }

    private fun topCountries(source: Map<String, MutableCountry>): List<CountryTraffic> = source.entries.asSequence()
        .map { CountryTraffic(it.key, it.value.bytes, it.value.flows) }
        .sortedByDescending { it.bytes }
        .take(6)
        .toList()

    private fun topDomains(source: Map<String, Long>): List<DomainTraffic> = source.entries.asSequence()
        .map { DomainTraffic(it.key, it.value) }
        .sortedByDescending { it.queries }
        .take(8)
        .toList()

    private fun normalizeDomain(value: String): String? {
        val v = value.trim().lowercase(Locale.ROOT)
        if (v.length !in 1..253 || v.any { !(it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' || it == '.') }) return null
        val labels = v.split('.')
        if (labels.any { it.isEmpty() || it.length > 63 }) return null
        return v
    }

    private fun trimCounterMap(map: MutableMap<String, Long>, limit: Int) {
        if (map.size <= limit) return
        val victims = map.entries.sortedBy { it.value }.take(map.size - limit)
        victims.forEach { map.remove(it.key) }
    }

    private fun saturatingAdd(a: Long, b: Long): Long = if (b <= 0L) a else if (Long.MAX_VALUE - a < b) Long.MAX_VALUE else a + b

    companion object {
        const val ACTION_ANNOTATE = 1
        const val ACTION_CORRELATE = 2
        const val ACTION_BLOCK = 3
        private const val MAX_FLOWS = 8192
        private const val MAX_DESTINATIONS = 4096
        private const val MAX_APPS = 96
        private const val MAX_EVENT_BYTES = 65_535L
        private const val MAX_DOMAINS_PER_APP = 256
        private const val MAX_GLOBAL_DOMAINS = 1024
        private const val MAX_HISTORY_HOURS = 168
        private const val HOUR_MS = 60L * 60L * 1000L
    }
}

/** Reads the native engine's bounded telemetry channel and resolves UID/package/country locally. */
class FullFlowTelemetryReader(
    context: Context,
    private val runtime: AppRuntime,
    private val descriptor: ParcelFileDescriptor,
    private val onBlockObserved: (() -> Unit)? = null,
    private val onFatal: (String) -> Unit,
) : AutoCloseable {
    private val appContext = context.applicationContext
    private val owners = ConnectionOwnerResolver(appContext, capacity = 8192, ttlMillis = 5 * 60_000L)
    private val running = AtomicBoolean(true)
    private val expectedClose = AtomicBoolean(false)
    private val dedupe = EventDedupe(cap = 4096, windowMs = 60_000L)
    private val asnDedupe = EventDedupe(cap = 8192, windowMs = 6L * 60L * 60L * 1000L)
    private val retryStorms = TelemetryRetryStormTracker()
    private val readerThread = Thread(::loop, "gedefense-fullflow-telemetry").apply { isDaemon = true }
    private val main = Handler(Looper.getMainLooper())
    private var lastBehaviorEvaluationMillis = 0L
    private var lastUiNotifyElapsedMillis = 0L
    private val labelCache = LinkedHashMap<String, String>(128, 0.75f, true)
    private val labelCacheLock = Any()

    init { readerThread.start() }

    private fun loop() {
        var fatal: String? = null
        try {
            BufferedReader(InputStreamReader(FileInputStream(descriptor.fileDescriptor), Charsets.US_ASCII), 16 * 1024).use { reader ->
                while (running.get()) {
                    val line = reader.readLine()
                    if (line == null) {
                        if (!expectedClose.get()) fatal = "fullflow_telemetry_eof"
                        break
                    }
                    if (line.length !in 2..1024) { fatal = "fullflow_telemetry_frame_invalid"; break }
                    if (!handle(line)) { fatal = "fullflow_telemetry_frame_invalid"; break }
                }
            }
        } catch (_: Exception) {
            if (!expectedClose.get()) fatal = "fullflow_telemetry_io_failure"
        } finally {
            if (fatal != null && running.get()) main.post { onFatal(fatal!!) }
        }
    }

    private fun handle(line: String): Boolean {
        val p = line.split('\t', limit = 12)
        return when (p.firstOrNull()) {
            "O" -> handleOpen(p)
            "U" -> handleUpdate(p)
            "C" -> handleClose(p)
            "B" -> handleBlocked(p)
            "D" -> handleDns(p)
            "H" -> handleClientHello(p)
            "P" -> handlePrivacy(p)
            "Y" -> handleEncryptedDns(p)
            "Q" -> handlePackageQuarantine(p)
            "E" -> { runtime.fullFlowAnalytics.transportError(); notifyUi(force = true); true }
            else -> false
        }
    }

    private fun handleOpen(p: List<String>): Boolean {
        if (p.size != 10) return false
        val id = p[1].toLongOrNull() ?: return false
        val proto = p[2].toIntOrNull() ?: return false
        val src = IpPrefix.parseAddress(p[4]) ?: return false
        val sport = p[5].toIntOrNull()?.takeIf { it in 1..65535 } ?: return false
        val dst = IpPrefix.parseAddress(p[6]) ?: return false
        val dport = p[7].toIntOrNull()?.takeIf { it in 1..65535 } ?: return false
        val action = p[8].toIntOrNull()?.takeIf { it in 0..3 } ?: return false
        p[9].toULongOrNull() ?: return false
        val owner = owners.resolveTuple(proto, src, sport, dst, dport) ?: "uid-unresolved"
        val resolvedCountry = runtime.geoCountry.lookup(dst)
        if (resolvedCountry == null && !runtime.geoCountry.snapshot().ready) {
            runtime.ensureGeoCountryReadyAsync()
        }
        runtime.fullFlowAnalytics.open(id, owner, labelFor(owner), resolvedCountry ?: "ZZ", action, dst.toString(), dst)
        emitAsnEvidence(owner, dst)
        runtime.metrics.setActiveFlows(runtime.fullFlowAnalytics.activeFlowCount())
        notifyUi()
        return true
    }

    private fun handleUpdate(p: List<String>): Boolean {
        if (p.size != 4) return false
        val id = p[1].toLongOrNull() ?: return false
        val tx = p[2].toLongOrNull() ?: return false
        val rx = p[3].toLongOrNull() ?: return false
        runtime.fullFlowAnalytics.update(id, tx, rx)
        maybeEvaluateBehavior()
        notifyUi()
        return true
    }

    private fun handleClose(p: List<String>): Boolean {
        if (p.size != 5) return false
        val id = p[1].toLongOrNull() ?: return false
        val tx = p[2].toLongOrNull() ?: return false
        val rx = p[3].toLongOrNull() ?: return false
        runtime.fullFlowAnalytics.close(id, tx, rx)
        maybeEvaluateBehavior()
        runtime.metrics.setActiveFlows(runtime.fullFlowAnalytics.activeFlowCount())
        notifyUi()
        return true
    }

    private fun handleDns(p: List<String>): Boolean {
        if (p.size != 3) return false
        val id = p[1].toLongOrNull() ?: return false
        val domain = p[2]
        if (domain.length !in 1..253) return false
        runtime.fullFlowAnalytics.dnsQuery(id, domain)
        maybeEvaluateBehavior()
        notifyUi()
        return true
    }

    private fun handleClientHello(p: List<String>): Boolean {
        if (p.size != 8) return false
        val id = p[1].toLongOrNull() ?: return false
        val transport = p[2].takeIf { it == "tls" || it == "quic" } ?: return false
        val sni = p[3].takeIf { it == "-" || it.length in 1..253 } ?: return false
        val alpn = p[4].takeIf { it == "-" || it.length in 1..32 } ?: return false
        val ja4 = p[5].takeIf { it.length in 1..64 } ?: return false
        val ja3 = p[6].takeIf { it.length in 1..64 } ?: return false
        val ech = p[7] == "1"
        runtime.fullFlowAnalytics.clientHello(id, transport, sni.takeIf { it != "-" }, alpn.takeIf { it != "-" }, ja4, ja3, ech)
        maybeEvaluateBehavior()
        notifyUi()
        return true
    }

    private fun handlePrivacy(p: List<String>): Boolean {
        if (p.size != 9) return false
        val nativeAction = p[1].toIntOrNull()?.takeIf { it in 1..2 } ?: return false
        val proto = p[2].toIntOrNull() ?: return false
        val src = IpPrefix.parseAddress(p[3]) ?: return false
        val sport = p[4].toIntOrNull()?.takeIf { it in 1..65535 } ?: return false
        val dst = IpPrefix.parseAddress(p[5]) ?: return false
        val dport = p[6].toIntOrNull()?.takeIf { it in 1..65535 } ?: return false
        val domain = p[7].takeIf { it.length in 1..253 } ?: return false
        val nativeRuleId = p[8].takeIf { it.length in 3..96 } ?: return false
        val decision = runtime.privacyIntelligence.registry().decide(domain, runtime.state.privacyProfile())
        val expectedAction = when (decision.action) {
            PrivacyAction.OBSERVE -> 1
            PrivacyAction.BLOCK -> 2
            PrivacyAction.ALLOW -> 0
        }
        if (expectedAction != nativeAction || decision.ruleId != nativeRuleId) {
            runtime.fullFlowAnalytics.transportError()
            val desyncKey = "privacy-desync:$domain:$nativeRuleId:$nativeAction"
            if (dedupe.shouldEmit(desyncKey)) {
                try {
                    runtime.evidence.append(
                        EvidenceEvent(
                            type = "privacy.policy_desync",
                            severity = "warning",
                            subject = domain,
                            detail = "native_rule=$nativeRuleId native_action=$nativeAction local_rule=${decision.ruleId ?: "none"} local_action=${decision.action.name}",
                        ),
                    )
                } catch (error: Exception) { RuntimeFailureLog.nonCritical("full-flow-analytics", error) }
            }
            return true
        }
        val owner = owners.resolveTuple(proto, src, sport, dst, dport) ?: "uid-unresolved"
        val blocked = decision.action == PrivacyAction.BLOCK
        if (blocked) {
            val country = runtime.geoCountry.lookup(dst) ?: "ZZ"
            runtime.fullFlowAnalytics.blocked(owner, labelFor(owner), country, 64L, domain)
            runtime.metrics.recordBlockedFlow(domain, 64L, owner)
            onBlockObserved?.invoke()
            val stormHits = retryStorms.recordBlockedHit("$owner:$domain")
            if (stormHits != null) {
                try {
                    runtime.evidence.append(
                        EvidenceEvent(
                            type = "privacy.retry_storm",
                            severity = "high",
                            subject = domain,
                            detail = "app=$owner category=${decision.category.name} hits=$stormHits window_s=60 rule=${decision.ruleId}",
                        ),
                    )
                } catch (error: Exception) { RuntimeFailureLog.nonCritical("full-flow-analytics", error) }
                try {
                    runtime.xdr.ingestPrivacyRetryStorm(
                        owner = owner,
                        domain = domain,
                        category = decision.category.name,
                        hitCount = stormHits,
                        windowSeconds = 60,
                    )
                } catch (_: Exception) {
                    runtime.state.recordXdrPersistenceFailure("write_failed")
                }
            }
        }
        val eventKey = "privacy:$owner:$domain:${decision.action.name}"
        if (dedupe.shouldEmit(eventKey)) {
            try {
                runtime.evidence.append(
                    EvidenceEvent(
                        type = if (blocked) "privacy.block" else "privacy.observe",
                        severity = if (blocked) "medium" else "info",
                        subject = domain,
                        detail = "app=$owner category=${decision.category.name} confidence=${decision.confidence.name} breakage=${decision.breakageRisk.name} rule=${decision.ruleId} source=${decision.sourceId} profile=${runtime.state.privacyProfile().name}",
                    ),
                )
            } catch (error: Exception) { RuntimeFailureLog.nonCritical("full-flow-analytics", error) }
            try {
                runtime.xdr.ingestPrivacyDecision(
                    owner = owner,
                    domain = domain,
                    action = decision.action.name,
                    category = decision.category.name,
                    confidence = decision.confidence.name,
                    ruleId = decision.ruleId ?: nativeRuleId,
                )
            } catch (_: Exception) {
                runtime.state.recordXdrPersistenceFailure("write_failed")
            }
        }
        notifyUi(force = blocked)
        return true
    }

    private fun handleEncryptedDns(p: List<String>): Boolean {
        if (p.size != 8) return false
        val nativeAction = p[1].toIntOrNull()?.takeIf { it in 1..2 } ?: return false
        val proto = p[2].toIntOrNull()?.takeIf { it == 6 || it == 17 } ?: return false
        val src = IpPrefix.parseAddress(p[3]) ?: return false
        val sport = p[4].toIntOrNull()?.takeIf { it in 1..65535 } ?: return false
        val dst = IpPrefix.parseAddress(p[5]) ?: return false
        val dport = p[6].toIntOrNull()?.takeIf { it == 853 } ?: return false
        val transport = p[7].takeIf { it == "dot" || it == "doq" } ?: return false
        val profile = runtime.state.privacyProfile()
        val expectedAction = when (profile) {
            de.visiongaia.gedefense.mobile.core.PrivacyProfile.OFF -> 0
            de.visiongaia.gedefense.mobile.core.PrivacyProfile.STRICT -> 2
            else -> 1
        }
        if (expectedAction != nativeAction) {
            runtime.fullFlowAnalytics.transportError()
            val key = "encrypted-dns-desync:$transport:$nativeAction:${profile.name}"
            if (dedupe.shouldEmit(key)) {
                try {
                    runtime.evidence.append(
                        EvidenceEvent(
                            type = "privacy.policy_desync",
                            severity = "warning",
                            subject = "encrypted-dns-$transport",
                            detail = "native_action=$nativeAction expected_action=$expectedAction profile=${profile.name} dport=$dport",
                        ),
                    )
                } catch (error: Exception) { RuntimeFailureLog.nonCritical("full-flow-analytics", error) }
            }
            return true
        }
        val owner = owners.resolveTuple(proto, src, sport, dst, dport) ?: "uid-unresolved"
        val blocked = nativeAction == 2
        if (blocked) {
            val country = runtime.geoCountry.lookup(dst) ?: "ZZ"
            runtime.fullFlowAnalytics.blocked(owner, labelFor(owner), country, 64L, dst.toString())
            runtime.metrics.recordBlockedFlow(dst.toString(), 64L, owner)
            onBlockObserved?.invoke()
        }
        val eventKey = "encrypted-dns:$owner:$transport:${profile.name}:$blocked"
        if (dedupe.shouldEmit(eventKey)) {
            try {
                runtime.evidence.append(
                    EvidenceEvent(
                        type = if (blocked) "privacy.encrypted_dns_block" else "privacy.encrypted_dns_observe",
                        severity = if (blocked) "medium" else "info",
                        subject = "encrypted-dns-$transport",
                        detail = "app=$owner transport=$transport destination=$dst port=$dport profile=${profile.name}",
                    ),
                )
            } catch (error: Exception) { RuntimeFailureLog.nonCritical("full-flow-analytics", error) }
            try {
                runtime.xdr.ingestPrivacyDecision(
                    owner = owner,
                    domain = "encrypted-dns-$transport",
                    action = if (blocked) "BLOCK" else "OBSERVE",
                    category = "ENCRYPTED_DNS",
                    confidence = "HIGH",
                    ruleId = "transport-port-853",
                )
            } catch (_: Exception) {
                runtime.state.recordXdrPersistenceFailure("write_failed")
            }
        }
        notifyUi(force = blocked)
        return true
    }

    private fun handlePackageQuarantine(p: List<String>): Boolean {
        if (p.size != 8) return false
        val proto = p[1].toIntOrNull() ?: return false
        val src = IpPrefix.parseAddress(p[3]) ?: return false
        val sport = p[4].toIntOrNull()?.takeIf { it in 1..65535 } ?: return false
        val dst = IpPrefix.parseAddress(p[5]) ?: return false
        val dport = p[6].toIntOrNull()?.takeIf { it in 1..65535 } ?: return false
        val bytes = p[7].toLongOrNull()?.coerceIn(0L, 65_535L) ?: return false
        val owner = owners.resolveTuple(proto, src, sport, dst, dport) ?: "uid-unresolved"
        val country = runtime.geoCountry.lookup(dst) ?: "ZZ"
        runtime.fullFlowAnalytics.blocked(owner, labelFor(owner), country, bytes, dst.toString())
        runtime.metrics.recordBlockedFlow(dst.toString(), bytes, owner)
        onBlockObserved?.invoke()
        val key = "package-egress:$owner:$dst:$proto:$dport"
        if (dedupe.shouldEmit(key)) {
            try {
                runtime.evidence.append(
                    EvidenceEvent(
                        type = "install_guard.network_block",
                        severity = "high",
                        subject = dst.toString(),
                        detail = "app=$owner protocol=$proto dport=$dport mode=full-flow reason=package_quarantine",
                    ),
                )
            } catch (error: Exception) { RuntimeFailureLog.nonCritical("full-flow-analytics", error) }
            try {
                runtime.xdr.recordPackageQuarantineBlock(owner, dst.toString(), proto, dport)
            } catch (_: Exception) {
                runtime.state.recordXdrPersistenceFailure("write_failed")
            }
        }
        notifyUi(force = true)
        return true
    }

    private fun handleBlocked(p: List<String>): Boolean {
        if (p.size != 10) return false
        val proto = p[1].toIntOrNull() ?: return false
        val src = IpPrefix.parseAddress(p[3]) ?: return false
        val sport = p[4].toIntOrNull()?.takeIf { it in 1..65535 } ?: return false
        val dst = IpPrefix.parseAddress(p[5]) ?: return false
        val dport = p[6].toIntOrNull()?.takeIf { it in 1..65535 } ?: return false
        val action = p[7].toIntOrNull() ?: return false
        val bits = p[8].toULongOrNull() ?: return false
        val bytes = p[9].toLongOrNull()?.coerceIn(0L, 65_535L) ?: return false
        if (action != FullFlowAnalytics.ACTION_BLOCK) return false
        val owner = owners.resolveTuple(proto, src, sport, dst, dport) ?: "uid-unresolved"
        val country = runtime.geoCountry.lookup(dst) ?: "ZZ"
        runtime.fullFlowAnalytics.blocked(owner, labelFor(owner), country, bytes, dst.toString())
        runtime.metrics.recordBlockedFlow(dst.toString(), bytes, owner)
        onBlockObserved?.invoke()
        val key = "$dst|$proto|$owner"
        if (dedupe.shouldEmit(key)) {
            val feeds = feedNames(bits.toLong())
            try {
                runtime.evidence.append(
                    EvidenceEvent(
                        "threat.block",
                        "high",
                        dst.toString(),
                        "app=$owner protocol=$proto dport=$dport feeds=$feeds mode=full-flow",
                    ),
                )
            } catch (error: Exception) {
                val code = EvidenceWriteFailureClassifier.code(error)
                runtime.state.recordEvidencePersistenceFailure(code)
                main.post { onFatal(code) }
                return true
            }
            try {
                runtime.xdr.recordThreatBlock(owner, dst.toString(), proto, dport)
            } catch (_: Exception) {
                // XDR enrichment is secondary to the already enforced packet block and durable
                // Evidence journal. Keep the tunnel enforcing, degrade XDR telemetry separately.
                runtime.state.recordXdrPersistenceFailure("write_failed")
            }
        }
        notifyUi(force = true)
        return true
    }

    private fun emitAsnEvidence(owner: String, destination: de.visiongaia.gedefense.mobile.core.IpAddress) {
        val asn = runtime.asnEvidence.lookup(destination) ?: return
        val snapshot = runtime.asnEvidence.snapshot()
        if (!snapshot.ready) return
        val key = "asn:$owner:${asn.asn}:${destination.family}:${snapshot.fetchedAtMillis}"
        if (!asnDedupe.shouldEmit(key)) return
        val sourceHash = if (destination.family == 4) snapshot.v4SourceSha256 else snapshot.v6SourceSha256
        val indexHash = if (destination.family == 4) snapshot.v4IndexSha256 else snapshot.v6IndexSha256
        val organization = asn.organization.replace(';', ',').replace('=', ':').take(192)
        try {
            runtime.evidence.append(
                EvidenceEvent(
                    type = "network.asn",
                    severity = "info",
                    subject = "AS${asn.asn}",
                    detail = "app=$owner family=IPv${destination.family} organization=$organization upstream=${snapshot.upstreamId} source=${snapshot.sourceId} license=${snapshot.licenseId} source_sha256=$sourceHash index_sha256=$indexHash snapshot_at=${snapshot.fetchedAtMillis} evidence_only=true",
                ),
            )
        } catch (error: Exception) { RuntimeFailureLog.nonCritical("full-flow-analytics", error) }
        // Intentionally no runtime.xdr call: ASN is context/evidence, never a risk signal.
    }

    private fun notifyUi(force: Boolean = false) {
        if (!runtime.hasStateListeners()) return
        val now = SystemClock.elapsedRealtime()
        if (force || now - lastUiNotifyElapsedMillis >= UI_NOTIFY_MIN_INTERVAL_MS) {
            lastUiNotifyElapsedMillis = now
            runtime.notifyStateChanged()
        }
    }

    private fun maybeEvaluateBehavior() {
        val now = System.currentTimeMillis()
        if (now - lastBehaviorEvaluationMillis < 30_000L) return
        lastBehaviorEvaluationMillis = now
        try { runtime.behavior.evaluateLive(runtime.fullFlowAnalytics.snapshot(), now) } catch (error: Exception) { RuntimeFailureLog.nonCritical("full-flow-analytics", error) }
    }

    private fun feedNames(bits: Long): String = ThreatFeedCatalog.all.mapIndexedNotNull { index, feed ->
        if (bits and (1L shl index) != 0L) feed.id else null
    }.joinToString(",").take(320)

    private fun labelFor(owner: String): String {
        if (owner.startsWith("uid:")) return owner
        val pkg = owner.substringBefore(',')
        synchronized(labelCacheLock) { labelCache[pkg]?.let { return it } }
        val label = try {
            val app = appContext.packageManager.getApplicationInfo(pkg, 0)
            appContext.packageManager.getApplicationLabel(app).toString().take(120)
        } catch (_: Exception) { pkg.take(120) }
        synchronized(labelCacheLock) {
            labelCache[pkg] = label
            while (labelCache.size > LABEL_CACHE_CAPACITY) {
                val iterator = labelCache.entries.iterator()
                if (!iterator.hasNext()) break
                iterator.next(); iterator.remove()
            }
        }
        return label
    }

    companion object {
        private const val UI_NOTIFY_MIN_INTERVAL_MS = 500L
        private const val LABEL_CACHE_CAPACITY = 512
    }

    private class TelemetryRetryStormTracker(
        private val maxKeys: Int = 512,
        private val windowMillis: Long = 60_000L,
        private val threshold: Int = 25,
    ) {
        private data class Bucket(var windowStartMs: Long, var count: Int, var reportedInWindow: Boolean)

        private val buckets = object : LinkedHashMap<String, Bucket>(64, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Bucket>?): Boolean = size > maxKeys
        }

        @Synchronized
        fun recordBlockedHit(key: String, nowMs: Long = SystemClock.elapsedRealtime()): Int? {
            val entry = buckets[key]
            if (entry == null || nowMs - entry.windowStartMs >= windowMillis) {
                buckets[key] = Bucket(nowMs, 1, false)
                return null
            }
            entry.count++
            if (entry.count >= threshold && !entry.reportedInWindow) {
                entry.reportedInWindow = true
                return entry.count
            }
            return null
        }
    }

    override fun close() {
        expectedClose.set(true); running.set(false)
        try { descriptor.close() } catch (error: Exception) { RuntimeFailureLog.nonCritical("full-flow-analytics", error) }
        readerThread.interrupt(); owners.clear()
    }
}
