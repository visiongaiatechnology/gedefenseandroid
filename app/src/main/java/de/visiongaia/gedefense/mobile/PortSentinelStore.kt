package de.visiongaia.gedefense.mobile

import android.content.Context
import de.visiongaia.gedefense.mobile.core.AuthenticatedSnapshotState
import de.visiongaia.gedefense.mobile.core.IpPrefix
import java.net.Inet4Address
import java.net.InetAddress
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.charset.StandardCharsets

// STATUS: DIAMANT VGT SUPREME
class PortSentinelStore(context: Context) {
    private val lock = Any()
    private val recoveryDir = File(context.noBackupFilesDir, "vault-recovery")
    private val betaRecoveryBoundaryMillis: Long? by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        BetaVaultMigrationPolicy.updateBoundaryMillis(context)
    }
    private val stateFile = File(context.filesDir, "security/port-sentinel.v1.bin")
    private val store = SecureSnapshotStore(
        stateFile,
        hmacKey = null,
        domain = VaultDomain.PORT_SENTINEL,
        schemaVersion = 1,
        maxPlaintextBytes = MAX_PAYLOAD_BYTES,
        hmacKeyProvider = { SecureTelemetryVault.hotPathHmacKey(VaultDomain.PORT_SENTINEL) },
        legacyHmacKeyProvider = { AndroidSecrets.hmacSha256OrNull("vgt.gedefense.mobile.port-sentinel.hmac.v1") },
    )
    private var hits = ArrayDeque<PortSentinelHit>()
    private var blocked = linkedSetOf<String>()
    private var integrityOk = false
    private var integrityReason: String? = "port_sentinel_initializing"
    private var dirty = false
    private var lastPersistMillis = 0L

    fun initialize() = load()

    fun integrityOk(): Boolean = synchronized(lock) { integrityOk }
    fun integrityFailureReason(): String? = synchronized(lock) { integrityReason }

    fun snapshot(runtime: PortSentinelRuntimeState): PortSentinelSnapshot = synchronized(lock) {
        PortSentinelSnapshot(
            generatedAtMillis = System.currentTimeMillis(),
            runtime = runtime,
            hits = hits.toList().asReversed(),
            blockedSources = blocked.toSet(),
            integrityOk = integrityOk,
            integrityFailureReason = integrityReason,
        )
    }

    fun isBlocked(address: String): Boolean = synchronized(lock) { !integrityOk || address in blocked }
    fun blockedSources(): Set<String> = synchronized(lock) { if (integrityOk) blocked.toSet() else emptySet() }

    fun setBlocked(address: String, value: Boolean): Boolean = synchronized(lock) {
        if (!integrityOk || !isBlockableAddress(address)) return@synchronized false
        val before = blocked.toSet()
        if (value) {
            if (blocked.size >= MAX_BLOCKED && address !in blocked) return@synchronized false
            blocked.add(address)
        } else blocked.remove(address)
        if (before == blocked) return@synchronized true
        dirty = true
        if (persist()) true else {
            blocked = LinkedHashSet(before)
            dirty = false
            false
        }
    }

    fun recordHit(hit: PortSentinelHit): Boolean = synchronized(lock) {
        if (!integrityOk || !isBlockableAddress(hit.sourceAddress)) return@synchronized false
        while (hits.size >= MAX_HITS) hits.removeFirst()
        hits.addLast(hit.copy(blockedSource = hit.sourceAddress in blocked))
        dirty = true
        val now = System.currentTimeMillis()
        if (now - lastPersistMillis < MIN_PERSIST_INTERVAL_MS) true
        else if (persist()) true else { degrade("sentinel hit persist failed"); false }
    }

    fun flush(): Boolean = synchronized(lock) { !dirty || persist() }

    fun resetHistory(): Boolean = synchronized(lock) {
        if (!integrityOk) return@synchronized false
        val old = hits
        hits = ArrayDeque()
        dirty = true
        if (persist()) true else { hits = old; dirty = false; false }
    }

    fun resetAll(): Boolean = synchronized(lock) {
        hits = ArrayDeque(); blocked = linkedSetOf(); integrityOk = true; integrityReason = null; dirty = true
        persist()
    }

    private fun load() = synchronized(lock) {
        val read = store.read()
        when (read.state) {
            AuthenticatedSnapshotState.ABSENT -> {
                hits = ArrayDeque(); blocked = linkedSetOf(); integrityOk = true; integrityReason = null; dirty = true
                if (!persist()) degrade("sentinel state initialization failed")
            }
            AuthenticatedSnapshotState.INVALID -> {
                if (store.archiveAndClearReconstructibleStartupFailure(recoveryDir, betaRecoveryBoundaryMillis) != null) {
                    hits = ArrayDeque(); blocked = linkedSetOf(); integrityOk = true; integrityReason = null; dirty = true
                    if (!persist()) degrade("sentinel continuity recovery initialization failed")
                } else degrade(read.reason ?: "sentinel state authentication failed")
            }
            AuthenticatedSnapshotState.VALID -> {
                if (!decode(read.payload ?: ByteArray(0))) degrade("sentinel state payload invalid")
                else { integrityOk = true; integrityReason = null; dirty = false }
            }
        }
    }

    private fun persist(): Boolean {
        if (!integrityOk) return false
        return try {
            val payload = encode().toByteArray(StandardCharsets.UTF_8)
            if (payload.size > MAX_PAYLOAD_BYTES) false else {
                store.write(payload); lastPersistMillis = System.currentTimeMillis(); dirty = false; true
            }
        } catch (_: Exception) { false }
    }

    private fun encode(): String {
        val root = JSONObject().put("schema", 1)
        root.put("blocked", JSONArray(blocked.sorted().take(MAX_BLOCKED)))
        val events = JSONArray()
        hits.takeLast(MAX_HITS).forEach { hit ->
            events.put(JSONObject()
                .put("id", hit.id.take(80)).put("at", hit.atMillis)
                .put("src", hit.sourceAddress).put("sport", hit.sourcePort)
                .put("dport", hit.targetPort).put("proto", hit.protocol.name)
                .put("zone", hit.sourceZone.take(32)).put("severity", hit.severity.name)
                .put("code", hit.eventCode.take(96)).put("risk", hit.riskPoints))
        }
        root.put("hits", events)
        return root.toString()
    }

    private fun decode(payload: ByteArray): Boolean = try {
        if (payload.isEmpty() || payload.size > MAX_PAYLOAD_BYTES) false else {
            val root = JSONObject(String(payload, StandardCharsets.UTF_8))
            if (root.optInt("schema", -1) != 1) false else {
                val nextBlocked = linkedSetOf<String>()
                val b = root.optJSONArray("blocked") ?: JSONArray()
                for (i in 0 until minOf(b.length(), MAX_BLOCKED)) {
                    val address = b.optString(i)
                    if (isBlockableAddress(address)) nextBlocked.add(address)
                }
                val nextHits = ArrayDeque<PortSentinelHit>()
                val h = root.optJSONArray("hits") ?: JSONArray()
                val start = (h.length() - MAX_HITS).coerceAtLeast(0)
                for (i in start until h.length()) {
                    val o = h.optJSONObject(i) ?: continue
                    val address = o.optString("src")
                    val target = o.optInt("dport", -1)
                    if (!isBlockableAddress(address) || target !in de.visiongaia.gedefense.mobile.core.PortSentinelClassifier.monitoredPorts) continue
                    val proto = runCatching { SentinelProtocol.valueOf(o.optString("proto")) }.getOrNull() ?: continue
                    val severity = runCatching { XdrSeverity.valueOf(o.optString("severity")) }.getOrNull() ?: continue
                    nextHits.addLast(PortSentinelHit(
                        id = o.optString("id").take(80), atMillis = o.optLong("at", 0L), sourceAddress = address,
                        sourcePort = o.optInt("sport", 0).coerceIn(0, 65535), targetPort = target, protocol = proto,
                        sourceZone = o.optString("zone", "LAN").take(32), severity = severity,
                        eventCode = o.optString("code", "LAN_SENTINEL_HIT").take(96), riskPoints = o.optInt("risk", 0).coerceIn(0, 100),
                        blockedSource = address in nextBlocked,
                    ))
                }
                blocked = nextBlocked; hits = nextHits; true
            }
        }
    } catch (_: Exception) { false }

    private fun degrade(reason: String) { integrityOk = false; integrityReason = reason.take(180); hits = ArrayDeque(); blocked = linkedSetOf(); dirty = false }

    companion object {
        private const val MAX_PAYLOAD_BYTES = 256 * 1024
        private const val MAX_HITS = 256
        private const val MAX_BLOCKED = 256
        private const val MIN_PERSIST_INTERVAL_MS = 5_000L

        fun isBlockableAddress(address: String): Boolean {
            val parsed = IpPrefix.parseAddress(address) ?: return false
            return isBlockableAddress(parsed.toInetAddress())
        }

        fun isBlockableAddress(address: InetAddress): Boolean {
            if (address.isAnyLocalAddress || address.isLoopbackAddress || address.isMulticastAddress || address.isLinkLocalAddress) return false
            if (address is Inet4Address && address.address.all { (it.toInt() and 0xff) == 0xff }) return false
            return true
        }

        fun isUniqueLocalIpv6(address: InetAddress): Boolean {
            val bytes = address.address
            return bytes.size == 16 && (bytes[0].toInt() and 0xfe) == 0xfc
        }

        fun isCarrierGradeNat(address: Inet4Address): Boolean {
            val bytes = address.address
            val first = bytes[0].toInt() and 0xff
            val second = bytes[1].toInt() and 0xff
            return first == 100 && second in 64..127
        }

        fun isPrivateIpv4(address: String): Boolean {
            val parsed = IpPrefix.parseAddress(address) ?: return false
            if (parsed.family != 4) return false
            val bytes = parsed.toInetAddress().address
            val a = bytes[0].toInt() and 0xff
            val b = bytes[1].toInt() and 0xff
            return a == 10 || (a == 172 && b in 16..31) || (a == 192 && b == 168)
        }
    }
}
