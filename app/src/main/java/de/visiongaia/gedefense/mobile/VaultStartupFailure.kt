package de.visiongaia.gedefense.mobile

import android.util.Log
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.ProviderException

// STATUS: DIAMANT VGT SUPREME
object VaultStartupFailure {
    private const val TAG = "GeDefenseVault"
    private val DOMAIN = Regex("[a-z][a-z0-9-]{2,31}")

    fun code(domain: String, error: Throwable): String {
        require(DOMAIN.matches(domain)) { "invalid vault failure domain" }
        var current: Throwable? = error
        repeat(MAX_CAUSE_DEPTH) {
            when (current) {
                is GeneralSecurityException,
                is ProviderException -> return "${domain}_crypto_failure"
                is IOException -> return "${domain}_io_failure"
                is IllegalArgumentException -> return "${domain}_validation_failure"
                is IllegalStateException -> return "${domain}_state_failure"
            }
            current = current?.cause ?: return "${domain}_startup_failure"
        }
        return "${domain}_startup_failure"
    }

    fun report(domain: String, code: String, error: Throwable? = null) {
        require(DOMAIN.matches(domain)) { "invalid vault failure domain" }
        val expectedPrefix = "${domain}_"
        require(code.startsWith(expectedPrefix) && code.length <= MAX_CODE_LENGTH) { "invalid vault failure code" }
        val types = error?.let(::boundedCauseTypes) ?: "preflight"
        // Exception messages are deliberately excluded: OEM providers may embed aliases or paths.
        Log.e(TAG, "domain=$domain code=$code types=$types")
    }

    private fun boundedCauseTypes(error: Throwable): String {
        val types = ArrayList<String>(MAX_CAUSE_DEPTH)
        var current: Throwable? = error
        repeat(MAX_CAUSE_DEPTH) {
            val item = current ?: return@repeat
            types += item.javaClass.simpleName
                .filter { character -> character.isLetterOrDigit() || character == '_' }
                .take(MAX_TYPE_LENGTH)
            current = item.cause
        }
        return types.filter(String::isNotBlank).joinToString(">").take(MAX_TYPES_LENGTH).ifBlank { "Throwable" }
    }

    private const val MAX_CAUSE_DEPTH = 8
    private const val MAX_CODE_LENGTH = 96
    private const val MAX_TYPE_LENGTH = 64
    private const val MAX_TYPES_LENGTH = 320
}
