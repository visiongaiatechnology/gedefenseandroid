package de.visiongaia.gedefense.mobile

import android.content.Context
import de.visiongaia.gedefense.mobile.core.AuthenticatedSnapshotState
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Locale

class XdrEventStore(context: Context) {
    data class RecoveryArchive(val fileName: String?, val sha256: String?)

    private val lock = Any()
    private val baseDir = File(context.noBackupFilesDir, "xdr")
    private val recoveryDir = File(context.noBackupFilesDir, "vault-recovery")
    private val betaRecoveryBoundaryMillis: Long? by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        BetaVaultMigrationPolicy.updateBoundaryMillis(context)
    }
    private val legacyFile = File(baseDir, "events.v1.jsonl")
    @Volatile private var authenticatedStore: SecureSnapshotStore? = null
    private val random = SecureRandom()
    private val events = ArrayList<XdrEvent>(MAX_EVENTS)
    @Volatile private var integrityOk = false
    @Volatile private var integrityReason: String? = "xdr_store_initializing"
    @Volatile private var initializationAttempted = false

    fun initialize() = synchronized(lock) {
        if (initializationAttempted) return@synchronized
        initializationAttempted = true
        val bootstrap = try {
            createAuthenticatedStoreWithHmacMigration()
        } catch (error: Exception) {
            val code = VaultStartupFailure.code("xdr", error)
            VaultStartupFailure.report("xdr", code, error)
            integrityOk = false
            integrityReason = code
            null
        }
        authenticatedStore = bootstrap
        if (bootstrap != null) {
            try {
                loadVerified(bootstrap)
            } catch (error: Exception) {
                val code = VaultStartupFailure.code("xdr", error)
                VaultStartupFailure.report("xdr", code, error)
                events.clear()
                integrityOk = false
                integrityReason = code
            }
        }
    }

    fun integrityOk(): Boolean = integrityOk
    fun integrityFailureReason(): String? = integrityReason

    fun append(event: XdrEvent) = synchronized(lock) {
        check(integrityOk) { "XDR event store integrity degraded" }
        val sanitized = sanitize(event)
        require(sanitized.id.isNotBlank() && sanitized.incidentKey.isNotBlank()) { "XDR event identity invalid" }
        val next = ArrayList<XdrEvent>(minOf(events.size + 1, MAX_EVENTS))
        val keepFrom = (events.size - (MAX_EVENTS - 1)).coerceAtLeast(0)
        for (i in keepFrom until events.size) next += events[i]
        next += sanitized
        if (!persist(next)) throw IllegalStateException("XDR event store write failed")
        events.clear()
        events += next
    }

    fun newId(now: Long = System.currentTimeMillis()): String {
        val suffix = ByteArray(6).also(random::nextBytes).toHex()
        return "$now-$suffix"
    }

    fun removeEvents(dedupePrefix: String, source: String? = null): Int = synchronized(lock) {
        if (!integrityOk || dedupePrefix.isBlank()) return@synchronized 0
        val next = events.filterNot { event ->
            event.dedupeKey.startsWith(dedupePrefix) && (source == null || event.source == source)
        }
        val removed = events.size - next.size
        if (removed <= 0) return@synchronized 0
        if (!persist(next)) return@synchronized 0
        events.clear()
        events += next
        removed
    }

    fun hasRecent(dedupeKey: String, withinMs: Long, now: Long = System.currentTimeMillis()): Boolean = synchronized(lock) {
        if (!integrityOk || dedupeKey.isBlank() || withinMs <= 0L) return@synchronized false
        for (i in events.lastIndex downTo 0) {
            val event = events[i]
            val age = now - event.atMillis
            if (age > withinMs && event.atMillis <= now) break
            if (age in 0..withinMs && event.dedupeKey == dedupeKey) return@synchronized true
        }
        false
    }

    fun snapshot(maxEvents: Int = 180): XdrSnapshot = synchronized(lock) {
        val now = System.currentTimeMillis()
        val recent = if (integrityOk) {
            events.asSequence()
                .filter { now - it.atMillis in 0..INCIDENT_WINDOW_MS }
                .sortedByDescending { it.atMillis }
                .toList()
        } else emptyList()
        val incidents = recent.groupBy { it.incidentKey }
            .mapNotNull { (key, incidentEvents) -> correlate(key, incidentEvents) }
            .sortedWith(compareByDescending<XdrIncident> { it.score }.thenByDescending { it.lastSeenMillis })
            .take(MAX_INCIDENTS)
        XdrSnapshot(
            generatedAtMillis = now,
            events = recent.take(maxEvents.coerceIn(1, MAX_EVENTS)),
            incidents = incidents,
            quarantinedPackages = emptySet(),
            eventStoreIntegrityOk = integrityOk,
            packageBaselineIntegrityOk = true,
            firewallPolicyIntegrityOk = true,
            networkDiscoveryIntegrityOk = true,
            portSentinelIntegrityOk = true,
            titanPolicyIntegrityOk = true,
        )
    }

    fun recoverCorruptStore(): RecoveryArchive? = synchronized(lock) {
        if (integrityOk) return@synchronized null
        val store = authenticatedStore ?: return@synchronized null
        baseDir.mkdirs()
        val source = store.path()
        var archive: RecoveryArchive? = null
        if (source.exists() && Files.isRegularFile(source.toPath(), LinkOption.NOFOLLOW_LINKS) && source.length() <= MAX_ARCHIVE_BYTES) {
            val recoveryDir = File(baseDir, "recovery")
            if (recoveryDir.mkdirs() || recoveryDir.isDirectory) {
                pruneRecoveryArchives(recoveryDir)
                val destination = File(recoveryDir, "events-corrupt-${System.currentTimeMillis()}-${ByteArray(4).also(random::nextBytes).toHex()}.bin")
                try {
                    Files.copy(source.toPath(), destination.toPath())
                    val hash = sha256(destination)
                    if (destination.length() == source.length()) archive = RecoveryArchive(destination.name, hash)
                    else destination.delete()
                 } catch (error: Exception) {
                    RuntimeFailureLog.nonCritical("xdr-recovery-archive", error)
                    destination.delete()
                }
            }
        }
        if (!store.clear()) return@synchronized null
        events.clear()
        integrityOk = true
        integrityReason = null
        if (!persist(emptyList())) {
            integrityOk = false
            integrityReason = "XDR recovery initialization failed"
            return@synchronized null
        }
        archive ?: RecoveryArchive(fileName = null, sha256 = null)
    }

    private fun createSnapshotStore(hmacKey: javax.crypto.SecretKey): SecureSnapshotStore =
        SecureSnapshotStore(
            file = File(baseDir, "events.v2.bin"),
            hmacKey = hmacKey,
            domain = VaultDomain.XDR_EVENTS,
            schemaVersion = 2,
            maxPlaintextBytes = MAX_PAYLOAD_BYTES,
        )

    private fun createActiveSnapshotStore(): SecureSnapshotStore =
        SecureSnapshotStore(
            file = File(baseDir, "events.v2.bin"),
            hmacKey = null,
            domain = VaultDomain.XDR_EVENTS,
            schemaVersion = 2,
            maxPlaintextBytes = MAX_PAYLOAD_BYTES,
            hmacKeyProvider = { SecureTelemetryVault.hotPathHmacKey(VaultDomain.XDR_EVENTS) },
        )

    private fun createAuthenticatedStoreWithHmacMigration(): SecureSnapshotStore {
        val active = createActiveSnapshotStore()
        val source = active.path()
        if (!source.exists() || source.length() == 0L) return active

        val activeRead = try { active.read() } catch (error: Exception) {
            RuntimeFailureLog.nonCritical("xdr-active-read", error)
            null
        }
        if (activeRead?.state != AuthenticatedSnapshotState.INVALID) return active

        for (version in (VaultDomain.XDR_EVENTS.activeKeyVersion - 1) downTo VaultDomain.XDR_EVENTS.wrappedKeyVersion) {
            val legacyKey = SecureTelemetryVault.historicalHotPathHmacKey(VaultDomain.XDR_EVENTS, version) ?: continue
            val legacy = createSnapshotStore(legacyKey)
            val legacyRead = try { legacy.read() } catch (error: Exception) {
                RuntimeFailureLog.nonCritical("xdr-legacy-read", error)
                null
            }
            if (legacyRead?.state != AuthenticatedSnapshotState.VALID) continue
            val payload = legacyRead.payload ?: continue
            try {
                active.write(payload)
                return active
             } catch (error: Exception) {
                RuntimeFailureLog.nonCritical("xdr-hmac-migration", error)
                // Preserve the historical generation and continue to older migration material.
            } finally {
                payload.fill(0)
            }
        }

        for (alias in LEGACY_HMAC_ALIASES) {
            val legacyKey = AndroidSecrets.secretKeyIfPresent(alias) ?: continue
            val legacy = createSnapshotStore(legacyKey)
            val legacyRead = try { legacy.read() } catch (error: Exception) {
                RuntimeFailureLog.nonCritical("xdr-legacy-alias-read", error)
                null
            }
            if (legacyRead?.state != AuthenticatedSnapshotState.VALID) continue
            val payload = legacyRead.payload ?: continue
            try {
                active.write(payload)
                return active
             } catch (error: Exception) {
                RuntimeFailureLog.nonCritical("xdr-legacy-alias-migration", error)
                // Continue to the next historical key generation if one exists.
            } finally {
                payload.fill(0)
            }
        }
        return active
    }

    private fun loadVerified(store: SecureSnapshotStore) {
        synchronized(lock) {
            events.clear()
            val read = store.read()
            when (read.state) {
                AuthenticatedSnapshotState.ABSENT -> {
                    integrityOk = true
                    integrityReason = null
                    if (persist(emptyList())) legacyFile.delete()
                    Unit
                }
                AuthenticatedSnapshotState.INVALID -> {
                    integrityOk = false
                    integrityReason = (read.reason ?: "XDR event store authentication failed").take(160)
                    val recovered = store.archiveAndClearReconstructibleStartupFailure(
                        recoveryDir, betaRecoveryBoundaryMillis,
                    )
                    if (recovered != null) {
                        events.clear()
                        integrityOk = true
                        integrityReason = null
                        if (!persist(emptyList())) {
                            integrityOk = false
                            integrityReason = "XDR continuity recovery initialization failed"
                        } else return@synchronized
                    }
                }
                AuthenticatedSnapshotState.VALID -> {
                    val decoded = decodePayload(read.payload ?: ByteArray(0))
                    if (decoded == null) {
                        integrityOk = false
                        integrityReason = "XDR event payload invalid"
                    } else {
                        events += decoded.takeLast(MAX_EVENTS)
                        integrityOk = true
                        integrityReason = null
                        legacyFile.delete()
                    }
                }
            }
        }
    }

    private fun persist(items: List<XdrEvent>): Boolean {
        if (!integrityOk) return false
        val store = authenticatedStore ?: return false
        return try {
            val bytes = encodePayload(items)
            if (bytes.size > MAX_PAYLOAD_BYTES) return false
            store.write(bytes)
            true
        } catch (error: Exception) {
            RuntimeFailureLog.nonCritical("xdr-persist", error)
            false
        }
    }

    private fun encodePayload(items: List<XdrEvent>): ByteArray {
        val array = JSONArray()
        items.takeLast(MAX_EVENTS).forEach { array.put(encode(it)) }
        return JSONObject().put("version", 2).put("events", array).toString().toByteArray(StandardCharsets.UTF_8)
    }

    private fun decodePayload(payload: ByteArray): List<XdrEvent>? {
        return try {
            if (payload.size > MAX_PAYLOAD_BYTES) null
            else {
                val root = JSONObject(payload.toString(StandardCharsets.UTF_8))
                if (root.optInt("version") != 2) null
                else {
                    val array = root.optJSONArray("events") ?: JSONArray()
                    buildList {
                        for (i in 0 until minOf(array.length(), MAX_EVENTS)) decode(array.optJSONObject(i) ?: continue)?.let(::add)
                    }
                }
            }
        } catch (error: Exception) {
            RuntimeFailureLog.nonCritical("xdr-decode-payload", error)
            null
        }
    }

    private fun correlate(key: String, eventList: List<XdrEvent>): XdrIncident? {
        if (eventList.isEmpty()) return null
        val ordered = eventList.sortedByDescending { it.atMillis }
        val breakdown = xdrScoreBreakdown(eventList)
        val categories = eventList.mapTo(linkedSetOf()) { it.category }
        val score = breakdown.finalScore
        val latest = ordered.first()
        return XdrIncident(
            key = key,
            subject = latest.subject,
            packageName = ordered.firstNotNullOfOrNull { it.packageName },
            score = score,
            severity = xdrSeverityForScore(score),
            eventCount = eventList.size,
            categories = categories,
            firstSeenMillis = eventList.minOf { it.atMillis },
            lastSeenMillis = eventList.maxOf { it.atMillis },
            summary = ordered.take(3).joinToString(" · ") { it.title }.take(300),
        )
    }

    private fun encode(e: XdrEvent): JSONObject {
        val out = JSONObject()
            .put("id", e.id).put("at", e.atMillis).put("category", e.category.name)
            .put("severity", e.severity.name).put("source", e.source.take(80))
            .put("subject", e.subject.take(256)).put("title", e.title.take(160))
            .put("detail", e.detail.take(1200)).put("risk", e.riskPoints.coerceIn(0, 100))
            .put("incident", e.incidentKey.take(256)).put("package", e.packageName ?: JSONObject.NULL)
            .put("dedupe", e.dedupeKey.take(300))
        e.detectorScore?.let { out.put("detector_score", it.coerceIn(0, 100)) }
        if (e.forensicReasons.isNotEmpty()) {
            out.put("forensic_reasons", JSONArray().apply {
                e.forensicReasons.take(MAX_FORENSIC_REASONS).forEach { reason ->
                    put(JSONObject().put("code", reason.code.take(96)).put("points", reason.points.coerceIn(0, 100)).put("detail", reason.detail.take(320)))
                }
            })
        }
        if (e.forensicFacts.isNotEmpty()) {
            out.put("forensic_facts", JSONArray().apply {
                e.forensicFacts.take(MAX_FORENSIC_FACTS).forEach { fact ->
                    put(JSONObject().put("key", fact.key.take(80)).put("value", fact.value.take(700)))
                }
            })
        }
        return out
    }

    private fun decode(j: JSONObject): XdrEvent? = try {
        val reasons = buildList {
            val array = j.optJSONArray("forensic_reasons") ?: JSONArray()
            for (i in 0 until minOf(array.length(), MAX_FORENSIC_REASONS)) {
                val item = array.optJSONObject(i) ?: continue
                val code = item.optString("code").take(96)
                if (code.isNotBlank()) add(XdrForensicReason(code, item.optInt("points").coerceIn(0, 100), item.optString("detail").take(320)))
            }
        }
        val facts = buildList {
            val array = j.optJSONArray("forensic_facts") ?: JSONArray()
            for (i in 0 until minOf(array.length(), MAX_FORENSIC_FACTS)) {
                val item = array.optJSONObject(i) ?: continue
                val key = item.optString("key").take(80)
                val value = item.optString("value").take(700)
                if (key.isNotBlank() && value.isNotBlank()) add(XdrForensicFact(key, value))
            }
        }
        XdrEvent(
            id = j.getString("id").take(128), atMillis = j.getLong("at").coerceAtLeast(0L),
            category = XdrCategory.valueOf(j.getString("category").uppercase(Locale.ROOT)),
            severity = XdrSeverity.valueOf(j.getString("severity").uppercase(Locale.ROOT)),
            source = j.optString("source").take(80), subject = j.optString("subject").take(256),
            title = j.optString("title").take(160), detail = j.optString("detail").take(1200),
            riskPoints = j.optInt("risk").coerceIn(0, 100), incidentKey = j.optString("incident").take(256),
            packageName = if (j.isNull("package")) null else j.optString("package").take(256),
            dedupeKey = j.optString("dedupe").take(300),
            detectorScore = if (j.has("detector_score")) j.optInt("detector_score").coerceIn(0, 100) else null,
            forensicReasons = reasons,
            forensicFacts = facts,
        ).takeIf { it.id.isNotBlank() && it.incidentKey.isNotBlank() }
    } catch (error: Exception) {
        RuntimeFailureLog.nonCritical("xdr-decode-event", error)
        null
    }

    private fun sanitize(e: XdrEvent): XdrEvent = e.copy(
        id = e.id.take(128),
        source = e.source.take(80),
        subject = e.subject.take(256),
        title = e.title.take(160),
        detail = e.detail.take(1200),
        riskPoints = e.riskPoints.coerceIn(0, 100),
        incidentKey = e.incidentKey.take(256),
        packageName = e.packageName?.take(256),
        dedupeKey = e.dedupeKey.take(300),
        detectorScore = e.detectorScore?.coerceIn(0, 100),
        forensicReasons = e.forensicReasons.take(MAX_FORENSIC_REASONS).map { it.copy(code = it.code.take(96), points = it.points.coerceIn(0, 100), detail = it.detail.take(320)) },
        forensicFacts = e.forensicFacts.take(MAX_FORENSIC_FACTS).map { it.copy(key = it.key.take(80), value = it.value.take(700)) }.filter { it.key.isNotBlank() && it.value.isNotBlank() },
    )

    private fun pruneRecoveryArchives(dir: File) {
        val files = BoundedDirectoryFiles.list(dir, MAX_RECOVERY_DIRECTORY_ENTRIES) ?: return
        files.filter { it.isFile && it.name.startsWith("events-corrupt-") }
            .sortedByDescending { it.lastModified() }
            .drop(MAX_RECOVERY_ARCHIVES - 1)
            .forEach { it.delete() }
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().buffered(16 * 1024).use { input ->
            val buffer = ByteArray(16 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().toHex()
    }

    private fun ByteArray.toHex(): String = buildString(size * 2) {
        for (byte in this@toHex) {
            val value = byte.toInt() and 0xff
            append(HEX[value ushr 4])
            append(HEX[value and 0x0f])
        }
    }

    companion object {
        private val LEGACY_HMAC_ALIASES = listOf(
            "vgt.gedefense.mobile.xdr-events.hmac.v3",
            "vgt.gedefense.mobile.xdr-events.hmac.v2",
        )
        private const val MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
        private const val MAX_ARCHIVE_BYTES = MAX_PAYLOAD_BYTES + 128L
        private const val MAX_EVENTS = 1200
        private const val MAX_INCIDENTS = 80
        private const val MAX_RECOVERY_ARCHIVES = 3
        private const val MAX_RECOVERY_DIRECTORY_ENTRIES = 32
        private const val MAX_FORENSIC_REASONS = 24
        private const val MAX_FORENSIC_FACTS = 24
        private const val INCIDENT_WINDOW_MS = 7L * 24L * 60L * 60L * 1000L
        private val HEX = "0123456789abcdef".toCharArray()
    }
}
