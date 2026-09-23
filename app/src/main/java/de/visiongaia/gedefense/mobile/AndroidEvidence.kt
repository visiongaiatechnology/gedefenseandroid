package de.visiongaia.gedefense.mobile

import android.content.Context
import de.visiongaia.gedefense.mobile.core.EvidenceLedger
import de.visiongaia.gedefense.mobile.core.EvidencePayloadProtector
import de.visiongaia.gedefense.mobile.core.EvidenceStore
import de.visiongaia.gedefense.mobile.core.UnavailableEvidenceStore
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

// STATUS: DIAMANT VGT SUPREME
object AndroidEvidence {
    data class BootstrapResult(
        val store: EvidenceStore,
        val failureCode: String?,
    )

    private val LEGACY_HMAC_ALIASES = listOf(
        "vgt.gedefense.mobile.evidence.hmac.v2",
        "vgt.gedefense.mobile.evidence.hmac.v1",
    )
    private const val VAULT_SCHEMA = 1
    private const val MAX_EVENT_PLAINTEXT_BYTES = 12 * 1024

    fun bootstrap(context: Context): BootstrapResult {
        val preflightFailure = SecureTelemetryVault.preflightHotPath(VaultDomain.EVIDENCE)
        if (preflightFailure != null) {
            val code = when (preflightFailure) {
                "crypto_unavailable" -> "evidence_crypto_failure"
                "roundtrip_mismatch" -> "evidence_crypto_auth_failure"
                "validation_unavailable" -> "evidence_validation_failure"
                "state_unavailable" -> "evidence_state_failure"
                "runtime_unavailable" -> "evidence_startup_failure"
                else -> "evidence_startup_failure"
            }
            VaultStartupFailure.report("evidence", code)
            return BootstrapResult(UnavailableEvidenceStore(code), code)
        }
        return try {
            BootstrapResult(create(context), null)
        } catch (error: Exception) {
            val code = VaultStartupFailure.code("evidence", error)
            VaultStartupFailure.report("evidence", code, error)
            BootstrapResult(UnavailableEvidenceStore(code), code)
        }
    }

    private fun create(context: Context): EvidenceLedger {
        val appContext = context.applicationContext
        val target = migrateToNoBackup(appContext)
        val protector = object : EvidencePayloadProtector {
            override fun protect(sequence: Long, atMillis: Long, plaintext: ByteArray): ByteArray =
                SecureTelemetryVault.seal(
                    domain = VaultDomain.EVIDENCE,
                    binding = evidenceBinding(sequence, atMillis),
                    schemaVersion = VAULT_SCHEMA,
                    plaintext = plaintext,
                )

            override fun unprotect(sequence: Long, atMillis: Long, protectedPayload: ByteArray): ByteArray =
                SecureTelemetryVault.open(
                    domain = VaultDomain.EVIDENCE,
                    binding = evidenceBinding(sequence, atMillis),
                    expectedSchemaVersion = VAULT_SCHEMA,
                    envelope = protectedPayload,
                    maxPlaintextBytes = MAX_EVENT_PLAINTEXT_BYTES,
                )
        }
        // 0.27.5 removes all per-record AndroidKeyStore operations from the Evidence hot path.
        // A TEE-backed KEK unwraps one random domain root per process; independent AES/HMAC
        // subkeys are then used in memory for high-frequency journaling. Historical HMAC aliases
        // remain read-only migration material and are never regenerated.
        val activeKey = SecureTelemetryVault.hotPathHmacKey(VaultDomain.EVIDENCE)
        val activeLedger = EvidenceLedger(target, activeKey, 16L shl 20, protector)
        if (!target.exists() || target.length() == 0L) return activeLedger

        val activeHealth = try { activeLedger.verify() } catch (_: Exception) { null }
        if (activeHealth?.ok == true) return activeLedger
        for (version in (VaultDomain.EVIDENCE.activeKeyVersion - 1) downTo VaultDomain.EVIDENCE.wrappedKeyVersion) {
            val legacyKey = SecureTelemetryVault.historicalHotPathHmacKey(VaultDomain.EVIDENCE, version) ?: continue
            val legacyLedger = EvidenceLedger(target, legacyKey, 16L shl 20, protector)
            val legacyHealth = try { legacyLedger.verify() } catch (_: Exception) { null }
            if (legacyHealth?.ok != true) continue
            val rotated = legacyLedger.rotateAuthenticationKey(activeKey)
            if (rotated.ok) return EvidenceLedger(target, activeKey, 16L shl 20, protector)
        }
        for (alias in LEGACY_HMAC_ALIASES) {
            val legacyKey = AndroidSecrets.secretKeyIfPresent(alias) ?: continue
            val legacyLedger = EvidenceLedger(target, legacyKey, 16L shl 20, protector)
            val legacyHealth = try { legacyLedger.verify() } catch (_: Exception) { null }
            if (legacyHealth?.ok != true) continue
            val rotated = legacyLedger.rotateAuthenticationKey(activeKey)
            if (rotated.ok) return EvidenceLedger(target, activeKey, 16L shl 20, protector)
        }
        return activeLedger
    }

    private fun evidenceBinding(sequence: Long, atMillis: Long): String = "record/$sequence/$atMillis"

    private fun migrateToNoBackup(context: Context): File {
        val target = File(context.noBackupFilesDir, "evidence/events.v3.log")
        if (target.exists()) return target
        val legacy = File(context.filesDir, "evidence/events.v1.log")
        if (!legacy.exists()) return target
        val legacyPath = legacy.toPath()
        if (Files.isSymbolicLink(legacyPath) || !Files.isRegularFile(legacyPath, LinkOption.NOFOLLOW_LINKS)) {
            throw IllegalStateException("legacy evidence path is not a regular file")
        }
        val parent = target.parentFile ?: error("evidence target parent missing")
        require(parent.mkdirs() || parent.isDirectory)
        durableCopyThenDelete(legacy, target)
        if (!target.isFile || Files.isSymbolicLink(target.toPath())) {
            throw IllegalStateException("migrated evidence target is not a regular file")
        }
        return target
    }

    private fun durableCopyThenDelete(source: File, target: File) {
        val parent = target.parentFile ?: error("evidence target parent missing")
        val temp = Files.createTempFile(parent.toPath(), ".evidence-migrate-", ".tmp").toFile()
        try {
            Files.copy(source.toPath(), temp.toPath(), StandardCopyOption.REPLACE_EXISTING)
            FileOutputStream(temp, true).use { it.fd.sync() }
            val sourceDigest = sha256(source)
            val tempDigest = sha256(temp)
            if (!MessageDigest.isEqual(sourceDigest, tempDigest)) {
                throw IllegalStateException("evidence migration digest mismatch")
            }
            SecureFiles.atomicReplace(temp, target)
            if (!source.delete()) {
                throw IllegalStateException("legacy evidence removal failed after durable copy")
            }
            source.parentFile?.let(SecureFiles::fsyncDirectory)
        } finally {
            if (temp.exists()) temp.delete()
        }
    }

    private fun sha256(file: File): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().buffered().use { input ->
            val buffer = ByteArray(32 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                if (read > 0) digest.update(buffer, 0, read)
            }
            buffer.fill(0)
        }
        return digest.digest()
    }
}
