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
 * Update-stable vault key lifecycle.
 *
 * One non-exportable AndroidKeyStore HMAC root is created once per installation and deliberately
 * has no dependency on APK bytes, source hashes, versionCode, versionName or runtime-integrity
 * state. A fixed hardware-PRF label derives the process-local wrapping KEK. Each vault domain/key
 * generation owns an independent random 256-bit root (DEK seed) persisted only as authenticated
 * wrapped ciphertext in noBackupFilesDir.
 *
 * Domain roots are expanded with HKDF-SHA-256 into independent AES-256-GCM and HMAC-SHA-256 keys.
 * A normal APK update therefore changes integrity measurements without changing encryption
 * custody. Cryptographic generation changes remain explicit through VaultDomain.activeKeyVersion.
 */
object PersistentVaultKeys {
    data class DomainKeys(
        val aes: SecretKey,
        val hmac: SecretKey,
        val rootSecurityLevel: AndroidSecrets.KeySecurityLevel,
    )

    data class Status(
        val initialized: Boolean,
        val rootSecurityLevel: AndroidSecrets.KeySecurityLevel?,
    )

    private const val FORMAT_VERSION = 1
    private const val ROOT_BYTES = 32
    private const val NONCE_BYTES = 12
    private const val GCM_TAG_BITS = 128
    private const val WRAPPED_BYTES = ROOT_BYTES + (GCM_TAG_BITS / 8)
    private const val FILE_BYTES = 8 + 4 + 4 + NONCE_BYTES + WRAPPED_BYTES
    private const val ROOT_PRF_ALIAS = "vgt.gedefense.mobile.vault.root-prf.v1"
    private val MAGIC = "VGTPVK01".toByteArray(StandardCharsets.US_ASCII)
    private val HKDF_SALT = "VisionGaiaTechnology/PersistentVaultDomainKdf/v1".toByteArray(StandardCharsets.US_ASCII)

    private val lock = Any()
    private val random = SecureRandom()
    private val cache = ConcurrentHashMap<String, DomainKeys>()
    @Volatile private var appContext: Context? = null
    @Volatile private var rootWrapKey: RootWrapKey? = null

    private data class RootWrapKey(
        val key: SecretKey,
        val securityLevel: AndroidSecrets.KeySecurityLevel,
    )

    fun initialize(context: Context) {
        appContext = context.applicationContext
    }

    fun keys(domain: VaultDomain, version: Int, create: Boolean): DomainKeys {
        require(version >= domain.persistentKeyVersion) { "persistent vault key generation not enabled" }
        val id = "${domain.id}/$version"
        cache[id]?.let { return it }
        return synchronized(lock) {
            cache[id]?.let { return@synchronized it }
            val context = appContext ?: throw GeneralSecurityException("persistent vault key store not initialized")
            val rootDir = File(context.noBackupFilesDir, "secure-vault-keysets")
            validateOrCreateDirectory(rootDir)
            val file = File(rootDir, "${domain.id}.v$version.keyset")
            val root = if (file.exists()) {
                unwrap(file, domain, version)
            } else {
                if (!create) throw GeneralSecurityException("persistent vault domain key missing")
                createWrapped(file, domain, version)
            }
            try {
                val aesBytes = hkdf(root, info(domain, version, "aes-gcm"))
                val hmacBytes = hkdf(root, info(domain, version, "outer-hmac"))
                try {
                    val rootWrap = rootWrapKey(create = false)
                    DomainKeys(
                        aes = SecretKeySpec(aesBytes, "AES"),
                        hmac = SecretKeySpec(hmacBytes, "HmacSHA256"),
                        rootSecurityLevel = rootWrap.securityLevel,
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
        if (version < domain.persistentKeyVersion) return Status(false, null)
        val context = appContext ?: return Status(false, null)
        val file = File(File(context.noBackupFilesDir, "secure-vault-keysets"), "${domain.id}.v$version.keyset")
        val root = AndroidSecrets.secretKeyIfPresent(ROOT_PRF_ALIAS)
        val initialized = file.isFile && !Files.isSymbolicLink(file.toPath()) &&
            file.length() == FILE_BYTES.toLong() && root != null
        return Status(initialized, root?.let(AndroidSecrets::securityLevel))
    }

    private fun createWrapped(file: File, domain: VaultDomain, version: Int): ByteArray {
        if (file.exists()) return unwrap(file, domain, version)
        // The AndroidKeyStore root is HMAC, not AES. One hardware PRF operation derives a process-local
        // wrapping KEK and avoids the OEM AndroidKeyStore AES-GCM failures seen on some devices.
        val kek = rootWrapKey(create = true).key
        val root = ByteArray(ROOT_BYTES).also(random::nextBytes)
        val nonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
        val aad = wrapAad(domain, version)
        var ciphertext: ByteArray? = null
        try {
            ciphertext = Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.ENCRYPT_MODE, kek, GCMParameterSpec(GCM_TAG_BITS, nonce))
                updateAAD(aad)
                doFinal(root)
            }
            if (ciphertext.size != WRAPPED_BYTES) throw GeneralSecurityException("persistent vault wrapped root length mismatch")
            val parent = file.parentFile ?: throw GeneralSecurityException("persistent vault key parent missing")
            val temp = SecureFiles.createPrivateTempFile(parent, ".pvk-${domain.id.take(48)}-")
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
                if (temp.length() != FILE_BYTES.toLong()) throw GeneralSecurityException("persistent vault keyset length mismatch")
                SecureFiles.atomicReplace(temp, file)
            } finally {
                if (temp.exists()) temp.delete()
            }
            val verified = unwrap(file, domain, version)
            try {
                if (!MessageDigest.isEqual(root, verified)) {
                    throw GeneralSecurityException("persistent vault key persistence verification failed")
                }
            } finally {
                verified.fill(0)
            }
            return root
        } catch (error: Exception) {
            root.fill(0)
            throw GeneralSecurityException("persistent vault key wrap failed", error)
        } finally {
            nonce.fill(0)
            aad.fill(0)
            ciphertext?.fill(0)
        }
    }

    private fun unwrap(file: File, domain: VaultDomain, version: Int): ByteArray {
        val path = file.toPath()
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || file.length() != FILE_BYTES.toLong()) {
            throw GeneralSecurityException("persistent vault keyset invalid")
        }
        val kek = rootWrapKey(create = false).key
        val bytes = try {
            Files.readAllBytes(path)
        } catch (error: Exception) {
            throw GeneralSecurityException("persistent vault keyset read failed", error)
        }
        val nonce = ByteArray(NONCE_BYTES)
        val ciphertext = ByteArray(WRAPPED_BYTES)
        val aad = wrapAad(domain, version)
        try {
            DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                val magic = ByteArray(MAGIC.size).also(input::readFully)
                if (!MessageDigest.isEqual(magic, MAGIC)) throw GeneralSecurityException("persistent vault keyset magic mismatch")
                if (input.readInt() != FORMAT_VERSION) throw GeneralSecurityException("persistent vault keyset format unsupported")
                if (input.readInt() != version) throw GeneralSecurityException("persistent vault key generation mismatch")
                input.readFully(nonce)
                input.readFully(ciphertext)
                if (input.read() != -1) throw GeneralSecurityException("persistent vault keyset trailing bytes")
            }
            val root = Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, kek, GCMParameterSpec(GCM_TAG_BITS, nonce))
                updateAAD(aad)
                doFinal(ciphertext)
            }
            if (root.size != ROOT_BYTES) {
                root.fill(0)
                throw GeneralSecurityException("persistent vault root length mismatch")
            }
            return root
        } catch (error: GeneralSecurityException) {
            throw error
        } catch (error: Exception) {
            throw GeneralSecurityException("persistent vault key unwrap failed", error)
        } finally {
            bytes.fill(0)
            nonce.fill(0)
            ciphertext.fill(0)
            aad.fill(0)
        }
    }

    private fun rootWrapKey(create: Boolean): RootWrapKey {
        rootWrapKey?.let { return it }
        val root = if (create) {
            AndroidSecrets.hmacSha256(ROOT_PRF_ALIAS, preferStrongBox = false)
        } else {
            AndroidSecrets.secretKeyIfPresent(ROOT_PRF_ALIAS)
                ?: throw GeneralSecurityException("persistent vault root continuity unavailable")
        }
        if (!root.algorithm.equals("HmacSHA256", ignoreCase = true)) {
            throw GeneralSecurityException("persistent vault root algorithm mismatch")
        }
        val seed = try {
            AndroidKeystoreGate.call {
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(root)
                mac.doFinal("VisionGaiaTechnology/PersistentVaultRootWrapMaterial/v1".toByteArray(StandardCharsets.US_ASCII))
            }
        } catch (error: Exception) {
            throw GeneralSecurityException("persistent vault root PRF unavailable", error)
        }
        return try {
            val wrapBytes = hkdf(seed, "VisionGaiaTechnology/PersistentVaultRootWrapKey/v1".toByteArray(StandardCharsets.US_ASCII))
            try {
                RootWrapKey(
                    key = SecretKeySpec(wrapBytes, "AES"),
                    securityLevel = AndroidSecrets.securityLevel(root),
                ).also { rootWrapKey = it }
            } finally {
                wrapBytes.fill(0)
            }
        } finally {
            seed.fill(0)
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
        "VisionGaiaTechnology/PersistentVault/${domain.id}/keygen/$version/$purpose"
            .toByteArray(StandardCharsets.US_ASCII)

    private fun wrapAad(domain: VaultDomain, version: Int): ByteArray =
        "VisionGaiaTechnology/PersistentVaultWrap/v1/${domain.id}/keygen/$version"
            .toByteArray(StandardCharsets.US_ASCII)

    private fun validateOrCreateDirectory(directory: File) {
        if (!(directory.mkdirs() || directory.isDirectory)) throw GeneralSecurityException("persistent vault key directory unavailable")
        val path = directory.toPath()
        if (Files.isSymbolicLink(path) || !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            throw GeneralSecurityException("persistent vault key directory invalid")
        }
    }
}
