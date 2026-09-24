package de.visiongaia.gedefense.mobile

import de.visiongaia.gedefense.mobile.core.BoundedSecretKeyCrypto
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Installation-stable, purpose-separated application HMAC keys.
 *
 * The hardware-backed AndroidKeyStore root is touched only through PersistentVaultKeys. Individual
 * consumers never create or operate their own OEM HMAC aliases. A random wrapped SECURITY_ROOT
 * survives normal APK updates and this object derives independent in-memory subkeys for each
 * purpose. This keeps Xiaomi/HyperOS and other OEM provider failures out of normal hot paths.
 */
object StableSecurityKeys {
    private const val PREFIX = "VisionGaiaTechnology/StableSecurityKey/v1/"
    private val cache = ConcurrentHashMap<String, SecretKey>()

    fun hmac(purpose: String): SecretKey {
        require(purpose.length in 3..80 && purpose.all { it.isLetterOrDigit() || it == '.' || it == '_' || it == '-' }) {
            "invalid stable security key purpose"
        }
        cache[purpose]?.let { return it }
        return synchronized(cache) {
            cache[purpose]?.let { return@synchronized it }
            val root = PersistentVaultKeys.keys(
                VaultDomain.SECURITY_ROOT,
                VaultDomain.SECURITY_ROOT.activeKeyVersion,
                create = true,
            ).hmac
            val derived = BoundedSecretKeyCrypto.execute(root) {
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(root)
                mac.doFinal((PREFIX + purpose).toByteArray(StandardCharsets.US_ASCII))
            }
            try {
                SecretKeySpec(derived, "HmacSHA256").also { cache[purpose] = it }
            } finally {
                derived.fill(0)
            }
        }
    }

    fun hmacOrNull(purpose: String): SecretKey? = try {
        hmac(purpose)
    } catch (_: Exception) {
        null
    }
}
