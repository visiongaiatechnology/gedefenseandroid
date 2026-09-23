package de.visiongaia.gedefense.mobile

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import org.json.JSONObject
import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.ProviderException
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

// STATUS: DIAMANT VGT SUPREME
/**
 * Hybrid detached signatures for durable/exportable security artifacts.
 *
 * ECDSA P-256 is always attempted through AndroidKeyStore and prefers StrongBox. On Android 17+
 * devices whose hardware Keystore reports KeyMint >= 5, ML-DSA-87 is added as a second signature.
 * ML-DSA is deliberately not used for encryption: FIPS 204 defines a digital-signature primitive.
 */
class HybridArtifactSigner(private val context: Context) {
    data class Capability(
        val classicalAvailable: Boolean,
        val mlDsa87HardwareAvailable: Boolean,
    )

    fun capability(): Capability = Capability(
        classicalAvailable = runCatching { getOrCreateEcdsa() }.isSuccess,
        mlDsa87HardwareAvailable = hardwareMlDsaAvailable(context),
    )

    fun writeDetachedSignature(source: File): File {
        require(source.isFile && source.length() in 1..MAX_SIGNED_FILE_BYTES) { "signed artifact missing or oversized" }
        val bytes = source.readBytes()
        try {
            val root = JSONObject()
                .put("schema", 1)
                .put("signed_file", source.name)
                .put("sha256", sha256(bytes))
                .put("classical", signEcdsa(bytes))

            val pq = if (hardwareMlDsaAvailable(context)) runCatching { signMlDsa87(bytes) }.getOrNull() else null
            root.put("post_quantum", pq ?: JSONObject().put("status", "UNAVAILABLE").put("algorithm", "ML-DSA-87"))

            val target = File(source.parentFile, "${source.name}.sig.json")
            SecureFiles.writeAtomic(target, root.toString(2).toByteArray(Charsets.UTF_8))
            return target
        } finally {
            bytes.fill(0)
        }
    }

    private fun signEcdsa(payload: ByteArray): JSONObject {
        val pair = getOrCreateEcdsa()
        val signature = AndroidKeystoreGate.call {
            val signer = Signature.getInstance("SHA256withECDSA")
            signer.initSign(pair.private)
            signer.update(payload)
            signer.sign()
        }
        return signatureJson("SHA256withECDSA", pair.public, signature, "SIGNED")
    }

    private fun signMlDsa87(payload: ByteArray): JSONObject {
        check(hardwareMlDsaAvailable(context)) { "hardware ML-DSA unavailable" }
        val pair = getOrCreateMlDsa87()
        val signature = AndroidKeystoreGate.call {
            val signer = Signature.getInstance(ML_DSA_87)
            signer.initSign(pair.private)
            signer.update(payload)
            signer.sign()
        }
        return signatureJson(ML_DSA_87, pair.public, signature, "SIGNED_HARDWARE")
    }

    private fun signatureJson(algorithm: String, publicKey: PublicKey, signature: ByteArray, status: String): JSONObject {
        val encoded = publicKey.encoded ?: error("public key encoding unavailable")
        return try {
            JSONObject()
                .put("status", status)
                .put("algorithm", algorithm)
                .put("public_key_format", publicKey.format ?: "X.509")
                .put("public_key_sha256", sha256(encoded))
                .put("public_key_der_b64", Base64.getEncoder().encodeToString(encoded))
                .put("signature_b64", Base64.getEncoder().encodeToString(signature))
        } finally {
            signature.fill(0)
        }
    }

    private fun getOrCreateEcdsa(): KeyPair = AndroidKeystoreGate.call {
        existingKeyPairUnsafe(ECDSA_ALIAS)?.let { return@call it }
        fun generate(strongBox: Boolean): KeyPair {
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            val builder = KeyGenParameterSpec.Builder(
                ECDSA_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
            if (strongBox) builder.setIsStrongBoxBacked(true)
            generator.initialize(builder.build())
            return generator.generateKeyPair()
        }
        try {
            return@call generate(true)
        } catch (_: StrongBoxUnavailableException) {
            // Use normal AndroidKeyStore/TEE if dedicated secure hardware is unavailable.
        } catch (_: ProviderException) {
            // A device may expose StrongBox while rejecting this specific key profile.
        }
        runCatching { generate(false) }.getOrElse { first -> existingKeyPairUnsafe(ECDSA_ALIAS) ?: throw first }
    }

    private fun getOrCreateMlDsa87(): KeyPair = AndroidKeystoreGate.call {
        existingKeyPairUnsafe(ML_DSA_ALIAS)?.let { return@call it }
        val generator = KeyPairGenerator.getInstance(ML_DSA_87, "AndroidKeyStore")
        generator.initialize(
            KeyGenParameterSpec.Builder(
                ML_DSA_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .setDigests(KeyProperties.DIGEST_NONE)
                .setUserAuthenticationRequired(false)
                .build(),
        )
        generator.generateKeyPair()
    }

    private fun existingKeyPairUnsafe(alias: String): KeyPair? {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val privateKey = keyStore.getKey(alias, null) as? PrivateKey ?: return null
        val publicKey = keyStore.getCertificate(alias)?.publicKey ?: return null
        return KeyPair(publicKey, privateKey)
    }


    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { "%02x".format(it) }

    companion object {
        fun hardwareMlDsaAvailable(context: Context): Boolean {
            if (Build.VERSION.SDK_INT < ANDROID_17_API) return false
            return runCatching {
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_HARDWARE_KEYSTORE, KEYMINT_5_FEATURE_VERSION)
            }.getOrDefault(false)
        }

        private const val ANDROID_17_API = 37
        private const val KEYMINT_5_FEATURE_VERSION = 500
        private const val ML_DSA_87 = "ML-DSA-87"
        private const val ECDSA_ALIAS = "vgt.gedefense.mobile.artifact-signing.ecdsa-p256.v1"
        private const val ML_DSA_ALIAS = "vgt.gedefense.mobile.artifact-signing.mldsa87.v1"
        private const val MAX_SIGNED_FILE_BYTES = 256 * 1024L
    }
}
