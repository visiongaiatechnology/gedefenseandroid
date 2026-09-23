package de.visiongaia.gedefense.mobile

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import java.security.ProviderException
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

// STATUS: PLATIN
object AndroidSecrets {
    enum class KeySecurityLevel { STRONGBOX, TRUSTED_ENVIRONMENT, HARDWARE, SOFTWARE, UNKNOWN }

    private val keyCache = ConcurrentHashMap<String, SecretKey>()
    // Accessed only on AndroidKeystoreGate's serialized worker.
    private var loadedKeyStore: KeyStore? = null

    fun secretKeyIfPresent(alias: String): SecretKey? {
        requireValidAlias(alias)
        keyCache[alias]?.let { return it }
        return AndroidKeystoreGate.call {
            (keyStore().getKey(alias, null) as? SecretKey)?.also { keyCache[alias] = it }
        }
    }

    fun hmacSha256(alias: String, preferStrongBox: Boolean = true): SecretKey {
        requireValidAlias(alias)
        keyCache[alias]?.let { return it }
        return AndroidKeystoreGate.call {
            val existing = keyStore().getKey(alias, null)
            if (existing != null) {
                val key = existing as? SecretKey
                    ?: error("Android Keystore alias exists with incompatible key type")
                check(key.algorithm.equals(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ignoreCase = true)) {
                    "Android Keystore alias algorithm mismatch"
                }
                keyCache[alias] = key
                return@call key
            }

            fun generate(strongBox: Boolean): SecretKey {
                val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore")
                val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(false)
                if (strongBox) builder.setIsStrongBoxBacked(true)
                generator.init(builder.build())
                return generator.generateKey()
            }

            if (preferStrongBox) {
                try {
                    return@call generate(true).also { keyCache[alias] = it }
                } catch (_: StrongBoxUnavailableException) {
                    // Fall through to TEE / normal AndroidKeyStore.
                } catch (_: ProviderException) {
                    // Advertised StrongBox can still reject a specific key profile.
                }
            }
            try {
                generate(false).also { keyCache[alias] = it }
            } catch (first: Exception) {
                (reloadKeyStore().getKey(alias, null) as? SecretKey)
                    ?.also { keyCache[alias] = it } ?: throw first
            }
        }
    }

    fun hmacSha256OrNull(alias: String, preferStrongBox: Boolean = true): SecretKey? = try {
        hmacSha256(alias, preferStrongBox)
    } catch (_: Exception) {
        null
    }

    fun aes256Gcm(alias: String, preferStrongBox: Boolean = true): SecretKey {
        requireValidAlias(alias)
        keyCache[alias]?.let { return it }
        return AndroidKeystoreGate.call {
            val existing = keyStore().getKey(alias, null)
            if (existing != null) {
                val key = existing as? SecretKey
                    ?: error("Android Keystore alias exists with incompatible key type")
                check(key.algorithm.equals(KeyProperties.KEY_ALGORITHM_AES, ignoreCase = true)) {
                    "Android Keystore alias algorithm mismatch"
                }
                keyCache[alias] = key
                return@call key
            }

            fun generate(strongBox: Boolean): SecretKey {
                val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
                val builder = KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setKeySize(256)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .setUserAuthenticationRequired(false)
                if (strongBox) builder.setIsStrongBoxBacked(true)
                generator.init(builder.build())
                return generator.generateKey()
            }

            if (preferStrongBox) {
                try {
                    return@call generate(true).also { keyCache[alias] = it }
                } catch (_: StrongBoxUnavailableException) {
                    // Fall through to TEE / normal AndroidKeyStore.
                } catch (_: ProviderException) {
                    // Advertised StrongBox can still reject this AES-GCM profile.
                }
            }
            try {
                generate(false).also { keyCache[alias] = it }
            } catch (first: Exception) {
                (reloadKeyStore().getKey(alias, null) as? SecretKey)
                    ?.also { keyCache[alias] = it } ?: throw first
            }
        }
    }

    @Suppress("DEPRECATION")
    fun securityLevel(key: SecretKey): KeySecurityLevel = try {
        AndroidKeystoreGate.call {
            val factory = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            if (Build.VERSION.SDK_INT >= 31) {
                when (info.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeySecurityLevel.STRONGBOX
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeySecurityLevel.TRUSTED_ENVIRONMENT
                    KeyProperties.SECURITY_LEVEL_SOFTWARE -> KeySecurityLevel.SOFTWARE
                    else -> if (info.isInsideSecureHardware) KeySecurityLevel.HARDWARE else KeySecurityLevel.UNKNOWN
                }
            } else if (info.isInsideSecureHardware) KeySecurityLevel.HARDWARE else KeySecurityLevel.SOFTWARE
        }
    } catch (_: Exception) {
        KeySecurityLevel.UNKNOWN
    }

    private fun keyStore(): KeyStore {
        loadedKeyStore?.let { return it }
        return KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.also { loadedKeyStore = it }
    }

    private fun reloadKeyStore(): KeyStore {
        loadedKeyStore = null
        return keyStore()
    }

    private fun requireValidAlias(alias: String) {
        require(alias.length in 8..120 && alias.all { it.isLetterOrDigit() || it == '.' || it == '_' || it == '-' }) {
            "invalid Android Keystore alias"
        }
    }
}
