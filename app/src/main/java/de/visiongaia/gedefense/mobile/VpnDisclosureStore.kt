package de.visiongaia.gedefense.mobile

import de.visiongaia.gedefense.mobile.core.AuthenticatedSnapshotState
import de.visiongaia.gedefense.mobile.core.AuthenticatedSnapshotStore
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.GeneralSecurityException
import java.util.concurrent.atomic.AtomicReference

// STATUS: DIAMANT VGT SUPREME

data class VpnDisclosureSnapshot(
    val accepted: Boolean,
    val acceptedAtMillis: Long,
    val integrityOk: Boolean,
    val failureReason: String? = null,
)

/**
 * Versioned, authenticated proof of the product-level VPN disclosure decision.
 *
 * This receipt is intentionally authenticated but not confidentiality-encrypted. It contains no
 * sensitive telemetry, only a disclosure version and acceptance timestamp. Keeping authorization
 * state independent from payload confidentiality while retaining fail-closed tamper detection.
 * The active receipt HMAC is derived from the installation-stable vault root so ordinary app
 * updates do not strand an otherwise valid disclosure decision on an OEM-specific per-store key.
 *
 * 0.27.0 briefly stored this receipt inside the AES-GCM vault. Existing encrypted receipts are
 * read compatibly and migrated back to the authenticated receipt format after successful AEAD
 * verification. If that legacy key is unavailable, a fresh explicit acceptance can overwrite the
 * invalid legacy state without weakening the disclosure requirement.
 */
class VpnDisclosureStore(context: android.content.Context) {
    private val appContext = context.applicationContext
    private val receiptFile = File(appContext.noBackupFilesDir, "privacy/vpn-disclosure.v1.bin")
    private val store = AuthenticatedSnapshotStore(
        file = receiptFile,
        key = null,
        schemaVersion = RECEIPT_SCHEMA_VERSION,
        // Accept the short receipt plus the one historical AES-GCM envelope used by 0.27.0.
        maxPayloadBytes = MAX_STORED_PAYLOAD_BYTES,
        keyProvider = { SecureTelemetryVault.hotPathHmacKey(VaultDomain.VPN_DISCLOSURE) },
    )
    private val legacyStore = AuthenticatedSnapshotStore(
        file = receiptFile,
        key = null,
        schemaVersion = RECEIPT_SCHEMA_VERSION,
        maxPayloadBytes = MAX_STORED_PAYLOAD_BYTES,
        keyProvider = { AndroidSecrets.hmacSha256OrNull(LEGACY_HMAC_ALIAS) },
    )
    private val cachedSnapshot = AtomicReference(
        VpnDisclosureSnapshot(
            accepted = false,
            acceptedAtMillis = 0L,
            integrityOk = false,
            failureReason = "vpn_disclosure_initializing",
        ),
    )

    @Synchronized
    fun initialize(): VpnDisclosureSnapshot = readSnapshot(System.currentTimeMillis()).also(cachedSnapshot::set)

    fun snapshot(): VpnDisclosureSnapshot = cachedSnapshot.get()

    fun isAccepted(): Boolean = cachedSnapshot.get().let { it.integrityOk && it.accepted }

    @Synchronized
    fun accept(nowMillis: Long = System.currentTimeMillis()): Boolean {
        if (nowMillis < MIN_ACCEPTED_AT_MILLIS) return false
        val payload = receiptPayload(nowMillis)
        return try {
            store.write(payload)
            val verified = readSnapshot(nowMillis)
            cachedSnapshot.set(verified)
            verified.integrityOk && verified.accepted && verified.acceptedAtMillis == nowMillis
        } catch (error: Exception) {
            RuntimeFailureLog.nonCritical("vpn-disclosure-accept", error)
            false
        } finally {
            payload.fill(0)
        }
    }

    @Synchronized
    fun revoke(): Boolean {
        if (!store.clear()) return false
        val revoked = readSnapshot(System.currentTimeMillis())
        cachedSnapshot.set(revoked)
        return revoked.integrityOk && !revoked.accepted
    }

    private fun readSnapshot(nowMillis: Long): VpnDisclosureSnapshot {
        val active = store.read()
        when (active.state) {
            AuthenticatedSnapshotState.ABSENT -> return VpnDisclosureSnapshot(
                accepted = false,
                acceptedAtMillis = 0L,
                integrityOk = true,
            )
            AuthenticatedSnapshotState.VALID -> return decodeStored(active.payload, nowMillis)
            AuthenticatedSnapshotState.INVALID -> Unit
        }

        // One-way migration from the historical direct AndroidKeyStore HMAC. If that OEM key can
        // still authenticate the receipt, rewrite it under the installation-stable domain HMAC
        // before accepting the decision. If the historical key itself is unusable, fail closed and
        // require one explicit re-acceptance; plaintext authorization state is never recovered
        // without authentication.
        val legacy = legacyStore.read()
        if (legacy.state == AuthenticatedSnapshotState.VALID) {
            val decoded = decodeStored(legacy.payload, nowMillis)
            if (decoded.integrityOk && decoded.accepted) {
                val payload = legacy.payload ?: return invalid("vpn_disclosure_payload_invalid")
                try {
                    store.write(payload)
                    val verified = store.read()
                    if (verified.state != AuthenticatedSnapshotState.VALID || verified.payload == null) {
                        return invalid("vpn_disclosure_migration_failed")
                    }
                    return decodeStored(verified.payload, nowMillis)
                } catch (error: Exception) {
                    RuntimeFailureLog.nonCritical("vpn-disclosure-hmac-migration", error)
                    return invalid("vpn_disclosure_migration_failed")
                }
            }
            return decoded
        }

        return invalid("vpn_disclosure_reaccept_required_after_key_migration")
    }

    private fun decodeStored(payload: ByteArray?, nowMillis: Long): VpnDisclosureSnapshot {
        if (payload == null) return invalid("vpn_disclosure_payload_invalid")
        if (!SecureTelemetryVault.isEncryptedEnvelope(payload)) return decodeReceipt(payload, nowMillis)

        val plaintext = try {
            SecureTelemetryVault.open(
                domain = VaultDomain.VPN_DISCLOSURE_LEGACY,
                binding = receiptFile.name,
                expectedSchemaVersion = RECEIPT_SCHEMA_VERSION,
                envelope = payload,
                maxPlaintextBytes = MAX_RECEIPT_PAYLOAD_BYTES,
            )
        } catch (_: GeneralSecurityException) {
            return invalid("vpn_disclosure_legacy_vault_authentication_failed")
        } catch (_: RuntimeException) {
            return invalid("vpn_disclosure_legacy_vault_decode_failed")
        }

        return try {
            val decoded = decodeReceipt(plaintext, nowMillis)
            if (decoded.integrityOk && decoded.accepted) {
                // Best-effort one-way migration. Successful AEAD + outer-HMAC verification is
                // already sufficient to trust this receipt for the current read; a failed rewrite
                // is retried later and must never downgrade to an unauthenticated state.
                try {
                    store.write(plaintext)
                } catch (error: Exception) {
                    RuntimeFailureLog.nonCritical("vpn-disclosure-migration", error)
                }
            }
            decoded
        } finally {
            plaintext.fill(0)
        }
    }

    private fun decodeReceipt(payload: ByteArray, nowMillis: Long): VpnDisclosureSnapshot {
        if (payload.size != RECEIPT_PAYLOAD_BYTES) return invalid("vpn_disclosure_payload_invalid")
        return try {
            val buffer = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN)
            val version = buffer.int
            val acceptedAt = buffer.long
            if (version != CURRENT_DISCLOSURE_VERSION) return invalid("vpn_disclosure_version_mismatch")
            if (acceptedAt < MIN_ACCEPTED_AT_MILLIS || acceptedAt > nowMillis + MAX_CLOCK_SKEW_MILLIS) {
                return invalid("vpn_disclosure_timestamp_invalid")
            }
            VpnDisclosureSnapshot(
                accepted = true,
                acceptedAtMillis = acceptedAt,
                integrityOk = true,
            )
        } catch (_: RuntimeException) {
            invalid("vpn_disclosure_decode_failed")
        }
    }

    private fun receiptPayload(nowMillis: Long): ByteArray = ByteBuffer.allocate(RECEIPT_PAYLOAD_BYTES)
        .order(ByteOrder.BIG_ENDIAN)
        .putInt(CURRENT_DISCLOSURE_VERSION)
        .putLong(nowMillis)
        .array()

    private fun invalid(reason: String) = VpnDisclosureSnapshot(
        accepted = false,
        acceptedAtMillis = 0L,
        integrityOk = false,
        failureReason = reason,
    )


    companion object {
        const val CURRENT_DISCLOSURE_VERSION = 1
        private const val RECEIPT_SCHEMA_VERSION = 1
        private const val RECEIPT_PAYLOAD_BYTES = 12
        private const val MAX_RECEIPT_PAYLOAD_BYTES = 64
        private const val MAX_STORED_PAYLOAD_BYTES = MAX_RECEIPT_PAYLOAD_BYTES + SecureTelemetryVault.ENVELOPE_OVERHEAD_BYTES
        private const val MIN_ACCEPTED_AT_MILLIS = 1_577_836_800_000L // 2020-01-01 UTC
        private const val MAX_CLOCK_SKEW_MILLIS = 5L * 60L * 1000L
        private const val LEGACY_HMAC_ALIAS = "vgt.gedefense.mobile.vpn-disclosure.hmac.v1"
    }
}
