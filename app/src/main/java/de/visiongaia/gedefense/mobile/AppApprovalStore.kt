package de.visiongaia.gedefense.mobile

import android.content.Context
import android.content.pm.PackageManager
import de.visiongaia.gedefense.mobile.core.AuthenticatedSnapshotState
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

// STATUS: DIAMANT VGT SUPREME
/**
 * User trust decisions for installed applications.
 *
 * Approval is deliberately bound to the package signer and the exact capability baseline that the
 * user reviewed. It never suppresses Threat-Intelligence, signer drift, network, behavior or
 * integrity evidence. A signer change or a newly gained capability makes the approval STALE.
 */
class AppApprovalStore(context: Context) {
    data class ApprovalRecord(
        val packageName: String,
        val signerSha256: String,
        val approvedAtMillis: Long,
        val capabilityCodes: Set<String>,
    )

    private val appContext = context.applicationContext
    private val pm = appContext.packageManager
    private val lock = Any()
    private val store = SecureSnapshotStore(
        file = File(appContext.noBackupFilesDir, "trust/app-approvals.vgt"),
        hmacKey = null,
        domain = VaultDomain.APP_APPROVALS,
        schemaVersion = 1,
        maxPlaintextBytes = MAX_PAYLOAD_BYTES,
        hmacKeyProvider = { SecureTelemetryVault.hotPathHmacKey(VaultDomain.APP_APPROVALS) },
        legacyHmacKeyProvider = { AndroidSecrets.hmacSha256OrNull("vgt.gedefense.mobile.app-approvals.hmac.v1") },
    )
    private val records = linkedMapOf<String, ApprovalRecord>()
    @Volatile private var integrityOk = false
    @Volatile private var failureReason: String? = "app_approval_initializing"

    fun initialize() = load()

    fun integrityOk(): Boolean = integrityOk
    fun integrityFailureReason(): String? = failureReason

    fun status(packageName: String, signerSha256: String?, findingCodes: Set<String>): AppApprovalState = synchronized(lock) {
        if (!integrityOk) return@synchronized AppApprovalState.STALE
        val record = records[packageName] ?: return@synchronized AppApprovalState.NONE
        val signer = signerSha256?.lowercase()?.takeIf(HEX_64::matches) ?: return@synchronized AppApprovalState.STALE
        if (!MessageDigest.isEqual(record.signerSha256.toByteArray(Charsets.US_ASCII), signer.toByteArray(Charsets.US_ASCII))) {
            return@synchronized AppApprovalState.STALE
        }
        val currentCapabilities = findingCodes.asSequence().filter(::isCapabilityFinding).toSet()
        if (!record.capabilityCodes.containsAll(currentCapabilities)) AppApprovalState.STALE else AppApprovalState.APPROVED
    }

    fun currentStatus(packageName: String): AppApprovalState = synchronized(lock) {
        if (!integrityOk) return@synchronized AppApprovalState.STALE
        val record = records[packageName] ?: return@synchronized AppApprovalState.NONE
        val signer = currentSignerSha256(packageName) ?: return@synchronized AppApprovalState.STALE
        if (MessageDigest.isEqual(record.signerSha256.toByteArray(Charsets.US_ASCII), signer.toByteArray(Charsets.US_ASCII))) {
            AppApprovalState.APPROVED
        } else AppApprovalState.STALE
    }

    fun approvedAt(packageName: String): Long? = synchronized(lock) {
        if (!integrityOk) null else records[packageName]?.approvedAtMillis
    }

    fun approve(result: AppRiskResult): Boolean = synchronized(lock) {
        if (!integrityOk) return@synchronized false
        val signer = result.signerSha256?.lowercase()?.takeIf(HEX_64::matches) ?: return@synchronized false
        if (result.threatMatches.any { it.endsWith(":BLOCK") }) return@synchronized false
        val capabilities = result.findings.asSequence().map { it.code }.filter(::isCapabilityFinding).take(MAX_CAPABILITIES).toSet()
        val next = LinkedHashMap(records)
        next[result.packageName] = ApprovalRecord(
            packageName = result.packageName,
            signerSha256 = signer,
            approvedAtMillis = System.currentTimeMillis(),
            capabilityCodes = capabilities,
        )
        if (!persist(next.values)) return@synchronized false
        records.clear(); records.putAll(next)
        true
    }

    fun revoke(packageName: String): Boolean = synchronized(lock) {
        if (!integrityOk) return@synchronized false
        if (packageName !in records) return@synchronized true
        val next = LinkedHashMap(records).apply { remove(packageName) }
        if (!persist(next.values)) return@synchronized false
        records.clear(); records.putAll(next)
        true
    }

    fun reset(): Boolean = synchronized(lock) {
        if (!store.clear()) return@synchronized false
        records.clear(); integrityOk = true; failureReason = null
        persist(emptyList())
    }

    private fun load() = synchronized(lock) {
        records.clear()
        val read = store.read()
        when (read.state) {
            AuthenticatedSnapshotState.ABSENT -> {
                integrityOk = true; failureReason = null
                persist(emptyList())
            }
            AuthenticatedSnapshotState.INVALID -> {
                integrityOk = false
                failureReason = (read.reason ?: "app approval authentication failed").take(160)
            }
            AuthenticatedSnapshotState.VALID -> {
                val payload = read.payload ?: ByteArray(0)
                try {
                    val root = JSONObject(payload.toString(Charsets.UTF_8))
                    if (root.optInt("version") != 1) throw IllegalStateException("approval schema mismatch")
                    val array = root.optJSONArray("records") ?: JSONArray()
                    for (i in 0 until minOf(array.length(), MAX_RECORDS)) {
                        val item = array.optJSONObject(i) ?: continue
                        val pkg = item.optString("package").take(256)
                        val signer = item.optString("signer").lowercase()
                        val at = item.optLong("approved_at").coerceAtLeast(1L)
                        if (!PACKAGE_PATTERN.matches(pkg) || !HEX_64.matches(signer)) continue
                        val caps = linkedSetOf<String>()
                        val capArray = item.optJSONArray("capabilities") ?: JSONArray()
                        for (j in 0 until minOf(capArray.length(), MAX_CAPABILITIES)) {
                            capArray.optString(j).takeIf { it.length in 1..96 && isCapabilityFinding(it) }?.let(caps::add)
                        }
                        records[pkg] = ApprovalRecord(pkg, signer, at, caps)
                    }
                    integrityOk = true; failureReason = null
                } catch (_: Exception) {
                    integrityOk = false; failureReason = "app approval payload invalid"
                    records.clear()
                }
            }
        }
    }

    private fun persist(values: Collection<ApprovalRecord>): Boolean {
        if (!integrityOk) return false
        return try {
            val array = JSONArray()
            values.sortedBy { it.packageName }.take(MAX_RECORDS).forEach { record ->
                array.put(JSONObject()
                    .put("package", record.packageName)
                    .put("signer", record.signerSha256)
                    .put("approved_at", record.approvedAtMillis)
                    .put("capabilities", JSONArray(record.capabilityCodes.sorted().take(MAX_CAPABILITIES))))
            }
            store.write(JSONObject().put("version", 1).put("records", array).toString().toByteArray(Charsets.UTF_8))
            true
        } catch (_: Exception) {
            integrityOk = false; failureReason = "app approval write failed"; false
        }
    }

    private fun currentSignerSha256(packageName: String): String? {
        return try {
            val pkg = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            val signing = pkg.signingInfo ?: return null
            val certs = if (signing.hasMultipleSigners()) signing.apkContentsSigners else signing.signingCertificateHistory
            val cert = certs.firstOrNull() ?: return null
            MessageDigest.getInstance("SHA-256").digest(cert.toByteArray()).joinToString("") { byte ->
                val value = byte.toInt() and 0xff
                HEX[value ushr 4].toString() + HEX[value and 0x0f]
            }
        } catch (_: Exception) { null }
    }

    private fun isCapabilityFinding(code: String): Boolean = code !in NON_CAPABILITY_CODES && !code.startsWith("embedded_")

    companion object {
        private const val MAX_PAYLOAD_BYTES = 256 * 1024
        private const val MAX_RECORDS = 1024
        private const val MAX_CAPABILITIES = 32
        private val PACKAGE_PATTERN = Regex("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+")
        private val HEX_64 = Regex("[0-9a-f]{64}")
        private const val HEX = "0123456789abcdef"
        private val NON_CAPABILITY_CODES = setOf("unknown_install_source", "signer_identity_unavailable")
    }
}
