package de.visiongaia.gedefense.mobile

import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

// STATUS: DIAMANT VGT SUPREME
/**
 * Hardware-bound domain-key derivation that avoids AndroidKeyStore AES operations.
 *
 * A non-exportable AndroidKeyStore HMAC-SHA-256 key acts as the per-domain root PRF. Exactly one
 * hardware-backed HMAC operation is required per domain/process. Its 256-bit output is expanded
 * through HKDF-SHA-256 into independent in-memory AES-256-GCM and HMAC-SHA-256 subkeys.
 *
 * The root key never leaves AndroidKeyStore and no plaintext/wrapped root file exists on disk.
 * This is deliberately used by the active vault generations because several OEM providers can
 * generate AndroidKeyStore AES keys successfully while failing later AES-GCM Cipher operations.
 */
object HardwareDerivedVaultKeys {
    data class DomainKeys(
        val aes: SecretKey,
        val hmac: SecretKey,
        val rootSecurityLevel: AndroidSecrets.KeySecurityLevel,
    )

    data class Status(
        val initialized: Boolean,
        val rootSecurityLevel: AndroidSecrets.KeySecurityLevel?,
    )

    private val lock = Any()
    private val cache = ConcurrentHashMap<String, DomainKeys>()
    private val HKDF_SALT = "VisionGaiaTechnology/VaultDomainKdf/v1".toByteArray(StandardCharsets.US_ASCII)

    fun keys(domain: VaultDomain, version: Int, create: Boolean): DomainKeys {
        require(version >= domain.derivedKeyVersion) { "derived vault key generation not enabled" }
        val id = "${domain.id}/$version"
        cache[id]?.let { return it }
        return synchronized(lock) {
            cache[id]?.let { return@synchronized it }
            val alias = rootAlias(domain, version)
            val rootKey = if (create) {
                // TEE / normal AndroidKeyStore is intentional here. This is one PRF operation per
                // process, not a per-record hot path, and avoids OEM StrongBox availability traps.
                AndroidSecrets.hmacSha256(alias, preferStrongBox = false)
            } else {
                AndroidSecrets.secretKeyIfPresent(alias)
                    ?: throw GeneralSecurityException("vault root continuity unavailable")
            }
            if (!rootKey.algorithm.equals("HmacSHA256", ignoreCase = true)) {
                throw GeneralSecurityException("vault root algorithm mismatch")
            }

            val seed = hardwarePrf(rootKey, domain, version)
            try {
                val aesBytes = hkdf(seed, info(domain, version, "aes-gcm"))
                val hmacBytes = hkdf(seed, info(domain, version, "outer-hmac"))
                try {
                    DomainKeys(
                        aes = SecretKeySpec(aesBytes, "AES"),
                        hmac = SecretKeySpec(hmacBytes, "HmacSHA256"),
                        rootSecurityLevel = AndroidSecrets.securityLevel(rootKey),
                    ).also { cache[id] = it }
                } finally {
                    aesBytes.fill(0)
                    hmacBytes.fill(0)
                }
            } finally {
                seed.fill(0)
            }
        }
    }

    fun status(domain: VaultDomain, version: Int): Status {
        if (version < domain.derivedKeyVersion) return Status(false, null)
        val root = AndroidSecrets.secretKeyIfPresent(rootAlias(domain, version))
        return Status(root != null, root?.let(AndroidSecrets::securityLevel))
    }

    private fun hardwarePrf(rootKey: SecretKey, domain: VaultDomain, version: Int): ByteArray {
        return try {
            AndroidKeystoreGate.call {
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(rootKey)
                mac.doFinal(
                    "VisionGaiaTechnology/VaultRootMaterial/v1/${domain.id}/$version"
                        .toByteArray(StandardCharsets.US_ASCII),
                )
            }
        } catch (error: Exception) {
            throw GeneralSecurityException("vault hardware PRF unavailable", error)
        }
    }

    private fun hkdf(ikm: ByteArray, info: ByteArray): ByteArray {
        val extract = Mac.getInstance("HmacSHA256")
        extract.init(SecretKeySpec(HKDF_SALT, "HmacSHA256"))
        val prk = extract.doFinal(ikm)
        return try {
            val expand = Mac.getInstance("HmacSHA256")
            expand.init(SecretKeySpec(prk, "HmacSHA256"))
            expand.update(info)
            expand.update(1)
            expand.doFinal()
        } finally {
            prk.fill(0)
            info.fill(0)
        }
    }

    private fun info(domain: VaultDomain, version: Int, purpose: String): ByteArray =
        "VisionGaiaTechnology/SecureTelemetryVault/${domain.id}/v$version/$purpose"
            .toByteArray(StandardCharsets.US_ASCII)

    private fun rootAlias(domain: VaultDomain, version: Int): String =
        "vgt.gedefense.mobile.vault.${domain.id}.root-prf.v$version"
}
