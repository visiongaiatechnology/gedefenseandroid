package de.visiongaia.gedefense.mobile

import android.content.Context
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// STATUS: DIAMANT VGT SUPREME
/**
 * Envelope-key custody for high-frequency Security Telemetry Vault domains.
 *
 * The Android Keystore is used only as a non-exportable KEK. A random 256-bit domain root is
 * unwrapped once per process and expanded through HKDF-SHA-256 into independent AES and HMAC
 * subkeys. This keeps the hardware/TEE as the at-rest root of trust without coupling every VPN
 * telemetry record to an OEM keystore operation.
 */
object WrappedHotPathKeys {
    data class DomainKeys(
        val aes: SecretKey,
        val hmac: SecretKey,
        val kekSecurityLevel: AndroidSecrets.KeySecurityLevel,
    )

    data class Status(
        val initialized: Boolean,
        val kekSecurityLevel: AndroidSecrets.KeySecurityLevel?,
    )

    private const val FORMAT_VERSION = 1
    private const val ROOT_BYTES = 32
    private const val NONCE_BYTES = 12
    private const val GCM_TAG_BITS = 128
    private const val WRAPPED_BYTES = ROOT_BYTES + (GCM_TAG_BITS / 8)
    private const val FILE_BYTES = 8 + 4 + 4 + NONCE_BYTES + WRAPPED_BYTES
    private val MAGIC = "VGTHPK01".toByteArray(StandardCharsets.US_ASCII)
    private val HKDF_SALT = "VisionGaiaTechnology/HotPathKey/v1".toByteArray(StandardCharsets.US_ASCII)

    private val lock = Any()
    private val random = SecureRandom()
    private val cache = ConcurrentHashMap<String, DomainKeys>()
    @Volatile private var appContext: Context? = null

    fun initialize(context: Context) {
        appContext = context.applicationContext
    }

    fun keys(domain: VaultDomain, version: Int, create: Boolean): DomainKeys {
        require(domain.hotPathWrapped) { "domain is not configured for wrapped hot-path keys" }
        require(version >= domain.wrappedKeyVersion) { "wrapped key version not enabled" }
        val id = "${domain.id}/$version"
        cache[id]?.let { return it }
        return synchronized(lock) {
            cache[id]?.let { return@synchronized it }
            val context = appContext ?: throw GeneralSecurityException("hot-path key store not initialized")
            val rootDir = File(context.noBackupFilesDir, "secure-vault-keys")
            validateOrCreateDirectory(rootDir)
            val file = File(rootDir, "${domain.id}.v$version.wrap")
            val kekAlias = kekAlias(domain, version)
            val root = if (file.exists()) {
                unwrap(file, domain, version, kekAlias)
            } else {
                if (!create) throw GeneralSecurityException("wrapped hot-path key missing")
                createWrapped(file, domain, version, kekAlias)
            }
            try {
                val aesBytes = hkdf(root, info(domain, version, "aes-gcm"))
                val hmacBytes = hkdf(root, info(domain, version, "hmac-sha256"))
                try {
                    val kek = AndroidSecrets.secretKeyIfPresent(kekAlias)
                        ?: throw GeneralSecurityException("hot-path KEK missing after unwrap")
                    DomainKeys(
                        aes = SecretKeySpec(aesBytes, "AES"),
                        hmac = SecretKeySpec(hmacBytes, "HmacSHA256"),
                        kekSecurityLevel = AndroidSecrets.securityLevel(kek),
                    ).also { cache[id] = it }
                } finally {
                    aesBytes.fill(0)
                    hmacBytes.fill(0)
                }
            } finally {
                root.fill(0)
            }
        }
    }

    fun status(domain: VaultDomain, version: Int): Status {
        if (!domain.hotPathWrapped || version < domain.wrappedKeyVersion) return Status(false, null)
        val context = appContext ?: return Status(false, null)
        val file = File(File(context.noBackupFilesDir, "secure-vault-keys"), "${domain.id}.v$version.wrap")
        val kek = AndroidSecrets.secretKeyIfPresent(kekAlias(domain, version))
        val initialized = file.isFile && !Files.isSymbolicLink(file.toPath()) && file.length() == FILE_BYTES.toLong() && kek != null
        return Status(initialized, kek?.let(AndroidSecrets::securityLevel))
    }

    private fun createWrapped(file: File, domain: VaultDomain, version: Int, kekAlias: String): ByteArray {
        if (file.exists()) return unwrap(file, domain, version, kekAlias)
        val kek = AndroidSecrets.aes256Gcm(kekAlias, preferStrongBox = false)
        val root = ByteArray(ROOT_BYTES).also(random::nextBytes)
        val nonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
        val aad = wrapAad(domain, version)
        var ciphertext: ByteArray? = null
        try {
            ciphertext = AndroidKeystoreGate.call {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, kek, GCMParameterSpec(GCM_TAG_BITS, nonce))
                cipher.updateAAD(aad)
                cipher.doFinal(root)
            }
            if (ciphertext.size != WRAPPED_BYTES) throw GeneralSecurityException("wrapped hot-path key length mismatch")
            val parent = file.parentFile ?: throw GeneralSecurityException("wrapped hot-path parent missing")
            val temp = SecureFiles.createPrivateTempFile(parent, ".whk-${domain.id.take(48)}-")
            try {
                FileOutputStream(temp, false).use { output ->
                    DataOutputStream(output).use { data ->
                        data.write(MAGIC)
                        data.writeInt(FORMAT_VERSION)
                        data.writeInt(version)
                        data.write(nonce)
                        data.write(ciphertext)
                        data.flush()
                        output.fd.sync()
                    }
                }
                if (temp.length() != FILE_BYTES.toLong()) throw GeneralSecurityException("wrapped hot-path file length mismatch")
                SecureFiles.atomicReplace(temp, file)
            } finally {
                if (temp.exists()) temp.delete()
            }
            val verified = unwrap(file, domain, version, kekAlias)
            try {
                if (!MessageDigest.isEqual(root, verified)) {
                    throw GeneralSecurityException("wrapped hot-path persistence verification failed")
                }
            } finally {
                verified.fill(0)
            }
            return root
        } catch (error: Exception) {
            root.fill(0)
            throw GeneralSecurityException("hot-path key wrap failed", error)
        } finally {
            nonce.fill(0)
            aad.fill(0)
            ciphertext?.fill(0)
        }
    }

    private fun unwrap(file: File, domain: VaultDomain, version: Int, kekAlias: String): ByteArray {
        val path = file.toPath()
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || file.length() != FILE_BYTES.toLong()) {
            throw GeneralSecurityException("wrapped hot-path key file invalid")
        }
        val kek = AndroidSecrets.secretKeyIfPresent(kekAlias)
            ?: throw GeneralSecurityException("wrapped hot-path KEK continuity unavailable")
        val bytes = try { Files.readAllBytes(path) } catch (error: Exception) {
            throw GeneralSecurityException("wrapped hot-path key read failed", error)
        }
        val nonce = ByteArray(NONCE_BYTES)
        val ciphertext = ByteArray(WRAPPED_BYTES)
        val aad = wrapAad(domain, version)
        try {
            DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                val magic = ByteArray(MAGIC.size).also(input::readFully)
                if (!MessageDigest.isEqual(magic, MAGIC)) throw GeneralSecurityException("wrapped hot-path magic mismatch")
                if (input.readInt() != FORMAT_VERSION) throw GeneralSecurityException("wrapped hot-path format unsupported")
                if (input.readInt() != version) throw GeneralSecurityException("wrapped hot-path version mismatch")
                input.readFully(nonce)
                input.readFully(ciphertext)
                if (input.read() != -1) throw GeneralSecurityException("wrapped hot-path trailing bytes")
            }
            val root = AndroidKeystoreGate.call {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, kek, GCMParameterSpec(GCM_TAG_BITS, nonce))
                cipher.updateAAD(aad)
                cipher.doFinal(ciphertext)
            }
            if (root.size != ROOT_BYTES) {
                root.fill(0)
                throw GeneralSecurityException("wrapped hot-path root length mismatch")
            }
            return root
        } catch (error: GeneralSecurityException) {
            throw error
        } catch (error: Exception) {
            throw GeneralSecurityException("hot-path key unwrap failed", error)
        } finally {
            bytes.fill(0)
            nonce.fill(0)
            ciphertext.fill(0)
            aad.fill(0)
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

    private fun wrapAad(domain: VaultDomain, version: Int): ByteArray =
        "VisionGaiaTechnology/HotPathWrap/v1/${domain.id}/$version"
            .toByteArray(StandardCharsets.US_ASCII)

    private fun validateOrCreateDirectory(directory: File) {
        if (!(directory.mkdirs() || directory.isDirectory)) throw GeneralSecurityException("hot-path key directory unavailable")
        val path = directory.toPath()
        if (Files.isSymbolicLink(path) || !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            throw GeneralSecurityException("hot-path key directory invalid")
        }
    }

    private fun kekAlias(domain: VaultDomain, version: Int): String =
        "vgt.gedefense.mobile.vault.${domain.id}.wrap-kek.v$version"
}
