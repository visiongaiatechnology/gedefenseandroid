package de.visiongaia.gedefense.mobile

import de.visiongaia.gedefense.mobile.core.EnforcementClass
import de.visiongaia.gedefense.mobile.core.IpPrefix
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import java.io.InputStream

/**
 * Allocation-light scanner for textual IPv4/IPv6 candidates embedded in arbitrary binary data.
 *
 * Unlike the earlier implementation this never converts whole 16 KiB binary windows into Strings.
 * Only bounded candidate tokens are decoded, which materially reduces GC pressure during APK/DEX
 * and native-library inspection. Parsing through IpPrefix remains the authority boundary.
 */
object ThreatTokenScanner {
    data class Result(val indicators: List<String>, val bytesRead: Long, val complete: Boolean)

    fun extractPublicIndicators(
        input: InputStream,
        maxBytes: Long,
        maxIndicators: Int = MAX_INDICATORS,
        cancelled: () -> Boolean = { false },
        allowance: (requested: Int) -> Int = { it },
        consumed: (bytes: Int) -> Unit = { },
    ): Result {
        if (maxBytes <= 0L || maxIndicators <= 0) return Result(emptyList(), 0L, false)
        val indicators = LinkedHashSet<String>()
        val buffer = ByteArray(BUFFER_BYTES)
        val token = ByteArray(MAX_TOKEN_BYTES + 1)
        var tokenLength = 0
        var tokenOverflow = false
        var total = 0L
        var complete = true

        fun flushToken() {
            if (!tokenOverflow && tokenLength in MIN_TOKEN_BYTES..MAX_TOKEN_BYTES && indicators.size < maxIndicators) {
                var hasSeparator = false
                for (i in 0 until tokenLength) {
                    val b = token[i]
                    if (b == '.'.code.toByte() || b == ':'.code.toByte()) { hasSeparator = true; break }
                }
                if (hasSeparator) {
                    val raw = String(token, 0, tokenLength, Charsets.US_ASCII)
                    val address = IpPrefix.parseAddress(raw)
                    if (address != null && address.isPublic()) indicators += raw
                }
            }
            tokenLength = 0
            tokenOverflow = false
        }

        while (total < maxBytes && indicators.size < maxIndicators) {
            if (Thread.currentThread().isInterrupted || cancelled()) throw InterruptedException("token scan interrupted")
            val remaining = (maxBytes - total).coerceAtMost(buffer.size.toLong()).toInt()
            val permitted = allowance(remaining).coerceIn(0, remaining)
            if (permitted <= 0) { complete = false; break }
            val read = input.read(buffer, 0, permitted)
            if (read < 0) break
            if (read == 0) continue
            consumed(read)
            total += read
            for (i in 0 until read) {
                val b = buffer[i]
                if (isTokenByte(b)) {
                    if (tokenLength < token.size) token[tokenLength++] = b else tokenOverflow = true
                    if (tokenLength > MAX_TOKEN_BYTES) tokenOverflow = true
                } else {
                    flushToken()
                }
            }
        }
        flushToken()
        if (total >= maxBytes) complete = false
        if (indicators.size >= maxIndicators) complete = false
        return Result(indicators.toList(), total, complete)
    }

    fun correlate(indicators: Collection<String>, index: ThreatIndex, maxMatches: Int): List<String> {
        if (indicators.isEmpty() || maxMatches <= 0) return emptyList()
        val matches = LinkedHashSet<String>()
        for (raw in indicators) {
            if (matches.size >= maxMatches) break
            val address = IpPrefix.parseAddress(raw) ?: continue
            if (!address.isPublic()) continue
            val threat = index.match(address) ?: continue
            val className = when {
                threat.hasBlockingSignal -> "BLOCK"
                threat.feeds.any { it.enforcement == EnforcementClass.CORRELATE_ONLY } -> "CORRELATE"
                else -> "ANNOTATE"
            }
            matches += "$raw:$className"
        }
        return matches.toList()
    }

    private fun isTokenByte(value: Byte): Boolean {
        val c = value.toInt() and 0xff
        return c in '0'.code..'9'.code || c in 'a'.code..'f'.code || c in 'A'.code..'F'.code || c == '.'.code || c == ':'.code
    }

    private const val BUFFER_BYTES = 32 * 1024
    private const val MIN_TOKEN_BYTES = 3
    private const val MAX_TOKEN_BYTES = 49
    private const val MAX_INDICATORS = 256
}
