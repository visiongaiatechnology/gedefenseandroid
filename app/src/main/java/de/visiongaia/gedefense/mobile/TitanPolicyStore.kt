package de.visiongaia.gedefense.mobile

import android.content.Context
import de.visiongaia.gedefense.mobile.core.AuthenticatedSnapshotState
import org.json.JSONObject
import java.io.File

class TitanPolicyStore(context: Context) {
    private val lock = Any()
    private val store = SecureSnapshotStore(
        file = File(context.applicationContext.filesDir, "policy/titan-policy.vgt"),
        hmacKey = null,
        domain = VaultDomain.TITAN_POLICY,
        schemaVersion = SCHEMA_VERSION,
        maxPlaintextBytes = MAX_PAYLOAD_BYTES,
        hmacKeyProvider = { SecureTelemetryVault.hotPathHmacKey(VaultDomain.TITAN_POLICY) },
        legacyHmacKeyProvider = { AndroidSecrets.hmacSha256OrNull("gedefense-titan-policy-v1") },
    )

    @Volatile private var integrityOk = false
    @Volatile private var failureReason: String? = "titan_policy_initializing"
    private var autoSuspend = false

    fun initialize() = load()

    fun integrityOk(): Boolean = integrityOk
    fun integrityFailureReason(): String? = failureReason
    fun autoSuspendOnQuarantine(): Boolean = synchronized(lock) { integrityOk && autoSuspend }

    fun setAutoSuspendOnQuarantine(enabled: Boolean): Boolean = synchronized(lock) {
        if (!integrityOk) return@synchronized false
        val next = JSONObject().put("autoSuspendOnQuarantine", enabled).toString().toByteArray(Charsets.UTF_8)
        return@synchronized try {
            store.write(next)
            autoSuspend = enabled
            true
        } catch (_: Exception) {
            integrityOk = false
            failureReason = "titan policy write failed"
            false
        }
    }

    fun reset(): Boolean = synchronized(lock) {
        if (!store.clear()) return@synchronized false
        integrityOk = true
        failureReason = null
        autoSuspend = false
        true
    }

    private fun load() = synchronized(lock) {
        val read = store.read()
        when (read.state) {
            AuthenticatedSnapshotState.ABSENT -> {
                integrityOk = true
                failureReason = null
                autoSuspend = false
            }
            AuthenticatedSnapshotState.INVALID -> {
                integrityOk = false
                failureReason = read.reason ?: "titan policy authentication failed"
                autoSuspend = false
            }
            AuthenticatedSnapshotState.VALID -> {
                val payload = read.payload ?: run {
                    integrityOk = false
                    failureReason = "titan policy payload missing"
                    return@synchronized
                }
                try {
                    val json = JSONObject(payload.toString(Charsets.UTF_8))
                    autoSuspend = json.optBoolean("autoSuspendOnQuarantine", false)
                    integrityOk = true
                    failureReason = null
                } catch (_: Exception) {
                    integrityOk = false
                    failureReason = "titan policy decode failed"
                    autoSuspend = false
                }
            }
        }
    }

    companion object {
        private const val SCHEMA_VERSION = 1
        private const val MAX_PAYLOAD_BYTES = 4096
    }
}
