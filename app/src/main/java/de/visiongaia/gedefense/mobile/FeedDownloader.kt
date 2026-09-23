package de.visiongaia.gedefense.mobile

import de.visiongaia.gedefense.mobile.core.ThreatFeed
import java.io.File
import java.io.FileOutputStream
import java.net.Proxy
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection

data class DownloadedFeed(val file: File, val sha256: String, val bytes: Long)

object FeedDownloader {
    private const val MAX_LINE_BYTES = 8192
    private const val CONNECT_TIMEOUT_MS = 10_000
    private const val READ_TIMEOUT_MS = 15_000
    private const val MAX_REDIRECTS = 2

    @Throws(InterruptedException::class)
    fun download(feed: ThreatFeed, dir: File): DownloadedFeed {
        throwIfInterrupted()
        require(dir.mkdirs() || dir.isDirectory) { "threat-intel cache directory unavailable" }
        val original = URL(feed.url)
        require(original.protocol == "https" && original.userInfo == null && original.ref == null) {
            "feed URL must be plain HTTPS"
        }

        var current = original
        var redirects = 0
        while (true) {
            throwIfInterrupted()
            val connection = (current.openConnection(Proxy.NO_PROXY) as? HttpsURLConnection)
                ?: error("HTTPS connection required")
            connection.instanceFollowRedirects = false
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.useCaches = false
            connection.setRequestProperty("User-Agent", "VGT-GeDefense-Mobile/0.3 threat-intel")
            connection.setRequestProperty("Accept", "text/plain, application/json;q=0.9, text/json;q=0.9, application/octet-stream;q=0.5")

            val code = connection.responseCode
            if (code in intArrayOf(301, 302, 303, 307, 308)) {
                val location = connection.getHeaderField("Location") ?: error("redirect without location")
                connection.disconnect()
                if (++redirects > MAX_REDIRECTS) error("too many redirects")
                val next = URL(current, location)
                require(
                    next.protocol == "https" &&
                        next.host.equals(original.host, ignoreCase = true) &&
                        next.userInfo == null && next.ref == null
                ) { "cross-host or insecure redirect refused" }
                current = next
                continue
            }
            if (code != HttpsURLConnection.HTTP_OK) {
                connection.disconnect()
                error("feed HTTP $code")
            }

            val mediaType = connection.contentType
                ?.substringBefore(';')
                ?.trim()
                ?.lowercase()
                .orEmpty()
            if (mediaType == "text/html" || mediaType == "application/xhtml+xml") {
                connection.disconnect()
                error("HTML response refused")
            }

            val declaredLength = connection.contentLengthLong
            if (declaredLength > feed.maxDownloadBytes) {
                connection.disconnect()
                error("feed exceeds size limit")
            }

            val temp = SecureFiles.createPrivateTempFile(dir, ".${feed.id.take(48)}.download-")
            val digest = MessageDigest.getInstance("SHA-256")
            var total = 0L
            var lineLength = 0
            try {
                connection.inputStream.use { input ->
                    FileOutputStream(temp).use { output ->
                        val buffer = ByteArray(16 * 1024)
                        while (true) {
                            throwIfInterrupted()
                            val read = input.read(buffer)
                            if (read < 0) break
                            total += read
                            if (total > feed.maxDownloadBytes) error("feed exceeds size limit")
                            for (i in 0 until read) {
                                if (buffer[i].toInt() == '\n'.code) {
                                    lineLength = 0
                                } else if (++lineLength > MAX_LINE_BYTES) {
                                    error("feed line exceeds limit")
                                }
                            }
                            digest.update(buffer, 0, read)
                            output.write(buffer, 0, read)
                        }
                        output.fd.sync()
                    }
                }
                if (total == 0L) error("empty feed")
                return DownloadedFeed(temp, hex(digest.digest()), total)
            } catch (t: Throwable) {
                temp.delete()
                throw t
            } finally {
                connection.disconnect()
            }
        }
    }

    private fun throwIfInterrupted() {
        if (Thread.currentThread().isInterrupted) throw InterruptedException("feed download interrupted")
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
}
