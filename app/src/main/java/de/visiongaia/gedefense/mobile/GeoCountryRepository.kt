package de.visiongaia.gedefense.mobile

import de.visiongaia.gedefense.mobile.core.BoundedSecretKeyCrypto

import android.content.Context
import de.visiongaia.gedefense.mobile.core.IpAddress
import de.visiongaia.gedefense.mobile.core.IpPrefix
import java.io.BufferedInputStream
import java.io.BufferedReader
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStreamReader
import java.net.Proxy
import java.net.URI
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.net.ssl.HttpsURLConnection

/** Local-only IP-to-country database. No observed destination IP is ever sent to a lookup service. */
class GeoCountryRepository(
    context: Context,
    private val integrityKeyProvider: () -> SecretKey?,
) {
    private val root = File(context.filesDir, "geo-country")
    private val generations = File(root, "generations")
    private val activePointer = File(root, ACTIVE_POINTER_FILE)
    @Volatile private var index: GeoCountryIndex? = null
    @Volatile private var state: GeoCountryState = GeoCountryState("MISSING", 0L, 0, 0)

    @Synchronized
    fun loadCached(): GeoCountryState {
        if (integrityKey() == null) {
            index = null
            state = GeoCountryState("UNAVAILABLE", 0L, 0, 0)
            return state
        }
        val loaded = tryLoadIndex() ?: recoverLatestValidGeneration()
        index = loaded
        state = if (loaded == null) GeoCountryState("MISSING", 0L, 0, 0)
        else GeoCountryState("READY", loaded.fetchedAtMillis, loaded.v4Records, loaded.v6Records)
        return state
    }

    fun lookup(address: IpAddress): String? = index?.lookup(address)
    fun snapshot(): GeoCountryState = state

    @Synchronized
    @Throws(InterruptedException::class)
    fun syncDue(now: Long = System.currentTimeMillis()): GeoCountryState {
        check(integrityKey() != null) { "geo integrity key unavailable" }
        val current = state
        if (current.ready && now - current.fetchedAtMillis < MIN_REFRESH_MS) return current
        ensureStorageJail()

        val previousPointer = readAuthenticatedPointer()
        val generationName = "gen-$now-${UUID.randomUUID().toString().replace("-", "")}".lowercase(Locale.ROOT)
        require(GENERATION_REGEX.matches(generationName)) { "geo generation name invalid" }
        val stage = File(generations, ".$generationName.stage")
        if (!stage.mkdir()) error("geo generation staging unavailable")
        var committed: File? = null
        var pointerPublished = false
        try {
            val v4 = syncOne(V4_SOURCE, 4, MAX_V4_BYTES, File(stage, V4_FILE))
            val v6 = syncOne(V6_SOURCE, 6, MAX_V6_BYTES, File(stage, V6_FILE))
            SecureFiles.writeAtomic(File(stage, MANIFEST_FILE), buildManifest(now, v4.records, v6.records, v4.sha256, v6.sha256))
            val staged = verifyGeneration(stage) ?: error("geo staged generation verification failed")
            if (staged.fetchedAtMillis != now) error("geo staged timestamp mismatch")

            committed = File(generations, generationName)
            moveDirectoryAtomic(stage, committed)

            // Publish only after the immutable generation verifies. If any post-publish check fails,
            // the authenticated previous pointer is restored before this method returns an error.
            SecureFiles.writeAtomic(activePointer, buildPointer(generationName, now))
            pointerPublished = true
            val active = readAuthenticatedPointer() ?: error("geo active pointer verification failed")
            if (active.generationName != generationName || active.fetchedAtMillis != now) error("geo active pointer mismatch")
            val loaded = tryLoadIndex() ?: error("geo-country committed generation verification failed")
            if (loaded.fetchedAtMillis != now) error("geo committed generation timestamp mismatch")

            index = loaded
            state = GeoCountryState("READY", loaded.fetchedAtMillis, loaded.v4Records, loaded.v6Records)
            cleanupGenerations(generationName)
            return state
        } catch (t: Throwable) {
            if (stage.exists()) safeDeleteGeneration(stage)
            if (pointerPublished) restorePointer(previousPointer)
            if (committed != null && readAuthenticatedPointer()?.generationName != committed.name) safeDeleteGeneration(committed)
            // Preserve the last-known-good in-memory state. A failed refresh must never turn a
            // previously valid local database into a missing or partially published generation.
            throw t
        }
    }

    private fun syncOne(source: GeoSource, family: Int, maxBytes: Long, target: File): CompiledGeo {
        throwIfInterrupted()
        val checksumText = downloadSmallText(source.checksumUrl, MAX_CHECKSUM_BYTES)
        val expected = checksumText.trim().split(Regex("\\s+")).firstOrNull()?.lowercase(Locale.ROOT)
            ?.takeIf { it.matches(Regex("[0-9a-f]{64}")) } ?: error("geo checksum invalid")
        val csv = downloadFile(source.dataUrl, maxBytes)
        try {
            val actual = sha256(csv)
            if (!MessageDigest.isEqual(expected.toByteArray(Charsets.US_ASCII), actual.toByteArray(Charsets.US_ASCII))) {
                error("geo checksum mismatch")
            }
            val records = compileCsv(csv, target, family)
            return CompiledGeo(records, sha256(target))
        } finally {
            csv.delete()
        }
    }

    private fun compileCsv(csv: File, outFile: File, family: Int): Int {
        var records = 0
        var prev4End = -1L
        var prev6Hi = 0L
        var prev6Lo = 0L
        var hasPrev6 = false
        FileOutputStream(outFile).use { raw ->
            DataOutputStream(raw).use { out ->
                out.write(if (family == 4) MAGIC4 else MAGIC6)
                out.writeInt(FORMAT_VERSION)
                out.writeInt(0) // record count patched after validation
                BufferedReader(InputStreamReader(FileInputStream(csv), Charsets.US_ASCII), 64 * 1024).use { reader ->
                    while (true) {
                        throwIfInterrupted()
                        val line = reader.readLine() ?: break
                        if (line.length > MAX_CSV_LINE) error("geo line exceeds bound")
                        if (line.isBlank()) continue
                        val parts = line.split(',')
                        if (parts.size != 3) error("geo csv shape invalid")
                        val start = IpPrefix.parseAddress(parts[0].trim()) ?: error("geo start invalid")
                        val end = IpPrefix.parseAddress(parts[1].trim()) ?: error("geo end invalid")
                        if (start.family != family || end.family != family) error("geo family mismatch")
                        val cc = parts[2].trim().uppercase(Locale.ROOT)
                        if (!cc.matches(Regex("[A-Z]{2}"))) error("geo country code invalid")
                        if (family == 4) {
                            val s = start.v4.toLong() and 0xffff_ffffL
                            val e = end.v4.toLong() and 0xffff_ffffL
                            if (s > e || (records > 0 && s <= prev4End)) error("geo ipv4 ranges unsorted or overlapping")
                            out.writeInt(start.v4); out.writeInt(end.v4); out.writeShort(packCountry(cc)); out.writeShort(0)
                            prev4End = e
                        } else {
                            if (compare128(start.v6Hi, start.v6Lo, end.v6Hi, end.v6Lo) > 0) error("geo ipv6 range reversed")
                            if (hasPrev6 && compare128(start.v6Hi, start.v6Lo, prev6Hi, prev6Lo) <= 0) error("geo ipv6 ranges unsorted or overlapping")
                            out.writeLong(start.v6Hi); out.writeLong(start.v6Lo); out.writeLong(end.v6Hi); out.writeLong(end.v6Lo)
                            out.writeShort(packCountry(cc)); out.writeShort(0); out.writeInt(0)
                            prev6Hi = end.v6Hi; prev6Lo = end.v6Lo; hasPrev6 = true
                        }
                        if (++records > MAX_RECORDS) error("geo record bound exceeded")
                    }
                }
                if (records < MIN_RECORDS) error("geo dataset implausibly small")
                out.flush(); raw.fd.sync()
            }
        }
        java.io.RandomAccessFile(outFile, "rw").use { raf ->
            raf.seek(8L); raf.writeInt(records); raf.fd.sync()
        }
        return records
    }

    private fun tryLoadIndex(): GeoCountryIndex? {
        val generationName = activeGenerationName() ?: return null
        val base = try { generations.canonicalFile } catch (_: Throwable) { return null }
        val generation = try { File(base, generationName).canonicalFile } catch (_: Throwable) { return null }
        if (generation.parentFile != base || !generation.isDirectory) return null
        return try { verifyGeneration(generation) } catch (_: Throwable) { null }
    }

    private fun verifyGeneration(generation: File): GeoCountryIndex? {
        val manifest = File(generation, MANIFEST_FILE)
        val v4 = File(generation, V4_FILE)
        val v6 = File(generation, V6_FILE)
        if (!manifest.isFile || !v4.isFile || !v6.isFile) return null
        val meta = verifyManifest(manifest, v4, v6) ?: return null
        return GeoCountryIndex.open(v4, v6, meta.first, meta.second, meta.third)
    }

    private fun buildPointer(generationName: String, at: Long): ByteArray {
        val payload = "v1\n$generationName\n$at\n".toByteArray(Charsets.US_ASCII)
        val mac = hmac(payload)
        return payload + hex(mac).toByteArray(Charsets.US_ASCII) + byteArrayOf('\n'.code.toByte())
    }

    private data class AuthenticatedPointer(
        val generationName: String,
        val fetchedAtMillis: Long,
        val encoded: ByteArray,
    )

    private fun readAuthenticatedPointer(): AuthenticatedPointer? {
        if (!activePointer.isFile || activePointer.length() !in 1..512) return null
        val encoded = try { activePointer.readBytes() } catch (_: Throwable) { return null }
        if (encoded.size !in 1..512) return null
        val lines = try { encoded.toString(Charsets.US_ASCII).lineSequence().toList() } catch (_: Throwable) { return null }
        // A trailing newline creates an empty terminal sequence entry. Reject any other shape.
        val normalized = if (lines.isNotEmpty() && lines.last().isEmpty()) lines.dropLast(1) else lines
        if (normalized.size != 4 || normalized[0] != "v1") return null
        val name = normalized[1]
        val at = normalized[2].toLongOrNull() ?: return null
        if (!GENERATION_REGEX.matches(name) || at <= 0L) return null
        val payload = "v1\n$name\n$at\n".toByteArray(Charsets.US_ASCII)
        val actual = hex(hmac(payload))
        val expected = normalized[3].lowercase(Locale.ROOT)
        if (!expected.matches(Regex("[0-9a-f]{64}"))) return null
        if (!MessageDigest.isEqual(expected.toByteArray(Charsets.US_ASCII), actual.toByteArray(Charsets.US_ASCII))) return null
        return AuthenticatedPointer(name, at, encoded)
    }

    private fun activeGenerationName(): String? = readAuthenticatedPointer()?.generationName

    private fun restorePointer(previous: AuthenticatedPointer?) {
        if (previous != null) {
            SecureFiles.writeAtomic(activePointer, previous.encoded)
            val restored = readAuthenticatedPointer() ?: error("geo pointer rollback verification failed")
            if (restored.generationName != previous.generationName || restored.fetchedAtMillis != previous.fetchedAtMillis) {
                error("geo pointer rollback mismatch")
            }
            return
        }
        if (activePointer.exists() && !activePointer.delete()) error("geo pointer rollback delete failed")
    }

    private fun recoverLatestValidGeneration(): GeoCountryIndex? {
        if (!generations.isDirectory) return null
        val base = try { generations.canonicalFile } catch (_: Throwable) { return null }
        val candidates = (BoundedDirectoryFiles.list(base, MAX_GENERATION_DIRECTORY_ENTRIES) ?: return null)
            .asSequence()
            .filter { it.isDirectory && GENERATION_REGEX.matches(it.name) }
            .mapNotNull { dir ->
                val canonical = try { dir.canonicalFile } catch (_: Throwable) { return@mapNotNull null }
                if (canonical.parentFile != base) return@mapNotNull null
                val loaded = try { verifyGeneration(canonical) } catch (_: Throwable) { null } ?: return@mapNotNull null
                canonical to loaded
            }
            .sortedByDescending { it.second.fetchedAtMillis }
            .toList()
        val best = candidates.firstOrNull() ?: return null
        return try {
            SecureFiles.writeAtomic(activePointer, buildPointer(best.first.name, best.second.fetchedAtMillis))
            val verifiedPointer = readAuthenticatedPointer() ?: return null
            if (verifiedPointer.generationName != best.first.name) return null
            best.second
        } catch (_: Throwable) { null }
    }

    private fun ensureStorageJail() {
        if (!generations.isDirectory && !generations.mkdirs()) error("geo-country storage unavailable")
        val rootCanonical = root.canonicalFile
        val generationsCanonical = generations.canonicalFile
        if (generationsCanonical.parentFile != rootCanonical || !generationsCanonical.isDirectory) error("geo-country storage escaped jail")
    }

    private fun safeDeleteGeneration(dir: File) {
        try {
            val base = generations.canonicalFile
            val canonical = dir.canonicalFile
            if (canonical.parentFile == base && (GENERATION_REGEX.matches(canonical.name) || canonical.name.startsWith(".gen-"))) {
                canonical.deleteRecursively()
            }
        } catch (error: Throwable) { RuntimeFailureLog.nonCritical("geo-country-repository", error) }
    }

    private fun moveDirectoryAtomic(source: File, target: File) {
        require(source.parentFile?.canonicalFile == target.parentFile?.canonicalFile) { "geo generation path escaped jail" }
        if (target.exists()) error("geo generation collision")
        SecureFiles.atomicReplace(source, target)
    }

    private fun cleanupGenerations(active: String) {
        val base = try { generations.canonicalFile } catch (_: Throwable) { return }
        val entries = BoundedDirectoryFiles.list(base, MAX_GENERATION_DIRECTORY_ENTRIES) ?: return
        val candidates = entries.filter { it.isDirectory && GENERATION_REGEX.matches(it.name) }
            .sortedByDescending { it.lastModified() }
        var retainedPrevious = false
        for (dir in candidates) {
            if (dir.name == active) continue
            if (!retainedPrevious) { retainedPrevious = true; continue }
            try { if (dir.canonicalFile.parentFile == base) dir.deleteRecursively() } catch (error: Throwable) { RuntimeFailureLog.nonCritical("geo-country-repository", error) }
        }
        entries.filter { it.isDirectory && it.name.startsWith(".gen-") && it.name.endsWith(".stage") }.forEach { stage ->
            try { if (stage.canonicalFile.parentFile == base) stage.deleteRecursively() } catch (error: Throwable) { RuntimeFailureLog.nonCritical("geo-country-repository", error) }
        }
    }

    private fun buildManifest(at: Long, v4Records: Int, v6Records: Int, v4Hash: String, v6Hash: String): ByteArray {
        val payload = "v1\n$at\n$v4Records\n$v6Records\n$v4Hash\n$v6Hash\n".toByteArray(Charsets.US_ASCII)
        val mac = hmac(payload)
        return payload + hex(mac).toByteArray(Charsets.US_ASCII) + byteArrayOf('\n'.code.toByte())
    }

    private fun verifyManifest(manifest: File, v4: File, v6: File): Triple<Long, Int, Int>? {
        if (!manifest.isFile || manifest.length() !in 1..MAX_MANIFEST_BYTES) return null
        val lines = manifest.readLines(Charsets.US_ASCII)
        if (lines.size != 7 || lines[0] != "v1") return null
        val at = lines[1].toLongOrNull()?.takeIf { it > 0L } ?: return null
        val v4Records = lines[2].toIntOrNull()?.takeIf { it in MIN_RECORDS..MAX_RECORDS } ?: return null
        val v6Records = lines[3].toIntOrNull()?.takeIf { it in MIN_RECORDS..MAX_RECORDS } ?: return null
        if (!lines[4].matches(Regex("[0-9a-f]{64}")) || !lines[5].matches(Regex("[0-9a-f]{64}"))) return null
        val payload = (lines.take(6).joinToString("\n") + "\n").toByteArray(Charsets.US_ASCII)
        val expectedMac = lines[6].lowercase(Locale.ROOT)
        val actualMac = hex(hmac(payload))
        if (!MessageDigest.isEqual(expectedMac.toByteArray(Charsets.US_ASCII), actualMac.toByteArray(Charsets.US_ASCII))) return null
        if (!MessageDigest.isEqual(lines[4].toByteArray(Charsets.US_ASCII), sha256(v4).toByteArray(Charsets.US_ASCII))) return null
        if (!MessageDigest.isEqual(lines[5].toByteArray(Charsets.US_ASCII), sha256(v6).toByteArray(Charsets.US_ASCII))) return null
        return Triple(at, v4Records, v6Records)
    }

    private fun downloadSmallText(url: String, maxBytes: Long): String {
        val file = downloadFile(url, maxBytes)
        return try { file.readText(Charsets.US_ASCII) } finally { file.delete() }
    }

    private fun downloadFile(url: String, maxBytes: Long): File {
        var current = URI(url).toURL()
        var redirects = 0
        while (true) {
            throwIfInterrupted()
            require(current.protocol == "https" && current.userInfo == null && current.ref == null) { "geo URL must be HTTPS" }
            if (!allowedGeoHost(current.host)) error("geo host refused")
            val c = current.openConnection(Proxy.NO_PROXY) as? HttpsURLConnection ?: error("geo HTTPS required")
            c.instanceFollowRedirects = false; c.connectTimeout = 10_000; c.readTimeout = 25_000; c.useCaches = false
            c.setRequestProperty("User-Agent", "VGT-GeDefense-Mobile/0.6 geo-country")
            val code = c.responseCode
            if (code in intArrayOf(301, 302, 303, 307, 308)) {
                val next = current.toURI().resolve(c.getHeaderField("Location") ?: error("geo redirect missing")).toURL(); c.disconnect()
                if (++redirects > 4 || !allowedGeoHost(next.host)) error("geo redirect refused")
                current = next; continue
            }
            if (code != HttpsURLConnection.HTTP_OK) { c.disconnect(); error("geo HTTP $code") }
            val declared = c.contentLengthLong
            if (declared > maxBytes) { c.disconnect(); error("geo download exceeds bound") }
            val temp = SecureFiles.createPrivateTempFile(root, ".geo-download-")
            var total = 0L
            try {
                BufferedInputStream(c.inputStream, 64 * 1024).use { input ->
                    FileOutputStream(temp).use { output ->
                        val buffer = ByteArray(64 * 1024)
                        while (true) {
                            throwIfInterrupted(); val n = input.read(buffer); if (n < 0) break
                            total += n; if (total > maxBytes) error("geo download exceeds bound")
                            output.write(buffer, 0, n)
                        }
                        output.fd.sync()
                    }
                }
                if (total <= 0L) error("geo download empty")
                return temp
            } catch (t: Throwable) { temp.delete(); throw t } finally { c.disconnect() }
        }
    }

    private fun allowedGeoHost(host: String?): Boolean {
        val h = host?.lowercase(Locale.ROOT) ?: return false
        return h == "github.com" || h == "release-assets.githubusercontent.com" || h == "objects.githubusercontent.com"
    }

    private fun sha256(file: File): String {
        val d = MessageDigest.getInstance("SHA-256")
        FileInputStream(file).use { input ->
            val b = ByteArray(64 * 1024)
            while (true) { val n = input.read(b); if (n < 0) break; d.update(b, 0, n) }
        }
        return hex(d.digest())
    }

    private fun packCountry(cc: String): Int = (cc[0].code shl 8) or cc[1].code
    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }
    private fun compare128(ahi: Long, alo: Long, bhi: Long, blo: Long): Int {
        val h = java.lang.Long.compareUnsigned(ahi, bhi); return if (h != 0) h else java.lang.Long.compareUnsigned(alo, blo)
    }
    private fun throwIfInterrupted() { if (Thread.currentThread().isInterrupted) throw InterruptedException("geo sync interrupted") }

    private fun requiredIntegrityKey(): SecretKey =
        integrityKey() ?: throw IllegalStateException("geo integrity key unavailable")

    private fun integrityKey(): SecretKey? = try {
        integrityKeyProvider()
    } catch (_: Exception) {
        null
    }

    private fun hmac(payload: ByteArray): ByteArray {
        val activeKey = requiredIntegrityKey()
        return BoundedSecretKeyCrypto.execute(activeKey) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(activeKey)
            mac.doFinal(payload)
        }
    }

    private data class GeoSource(val dataUrl: String, val checksumUrl: String)
    private data class CompiledGeo(val records: Int, val sha256: String)

    companion object {
        private const val MAX_GENERATION_DIRECTORY_ENTRIES = 64
        private const val MAX_MANIFEST_BYTES = 8L * 1024L
        private val MAGIC4 = byteArrayOf('G'.code.toByte(), 'D'.code.toByte(), 'G'.code.toByte(), '4'.code.toByte())
        private val MAGIC6 = byteArrayOf('G'.code.toByte(), 'D'.code.toByte(), 'G'.code.toByte(), '6'.code.toByte())
        private const val FORMAT_VERSION = 1
        private const val ACTIVE_POINTER_FILE = "active.ptr"
        private const val MANIFEST_FILE = "geo.manifest"
        private const val V4_FILE = "country-v4.bin"
        private const val V6_FILE = "country-v6.bin"
        private const val MIN_RECORDS = 1000
        private const val MAX_RECORDS = 2_000_000
        private const val MAX_CSV_LINE = 256
        private const val MAX_CHECKSUM_BYTES = 4096L
        private const val MAX_V4_BYTES = 32L * 1024L * 1024L
        private const val MAX_V6_BYTES = 64L * 1024L * 1024L
        private const val MIN_REFRESH_MS = 24L * 60L * 60L * 1000L
        private val GENERATION_REGEX = Regex("gen-[0-9]{10,17}-[0-9a-f]{32}")
        private val V4_SOURCE = GeoSource(
            "https://github.com/sapics/ip-location-db/releases/download/latest/user-country-ipv4.csv",
            "https://github.com/sapics/ip-location-db/releases/download/checksum/user-country-ipv4.csv.sha256",
        )
        private val V6_SOURCE = GeoSource(
            "https://github.com/sapics/ip-location-db/releases/download/latest/user-country-ipv6.csv",
            "https://github.com/sapics/ip-location-db/releases/download/checksum/user-country-ipv6.csv.sha256",
        )
    }
}

data class GeoCountryState(val state: String, val fetchedAtMillis: Long, val v4Records: Int, val v6Records: Int) {
    val ready: Boolean get() = state == "READY"
}

private class GeoCountryIndex private constructor(
    private val v4: ByteBuffer,
    private val v6: ByteBuffer,
    val fetchedAtMillis: Long,
    val v4Records: Int,
    val v6Records: Int,
) {
    fun lookup(address: IpAddress): String? = if (address.family == 4) lookup4(address) else lookup6(address)

    private fun lookup4(address: IpAddress): String? {
        val needle = address.v4.toLong() and 0xffff_ffffL
        var lo = 0; var hi = v4Records - 1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1; val off = HEADER_BYTES + mid * V4_RECORD_BYTES
            val start = v4.getInt(off).toLong() and 0xffff_ffffL
            val end = v4.getInt(off + 4).toLong() and 0xffff_ffffL
            when { needle < start -> hi = mid - 1; needle > end -> lo = mid + 1; else -> return unpackCountry(v4.getShort(off + 8).toInt() and 0xffff) }
        }
        return null
    }

    private fun lookup6(address: IpAddress): String? {
        var lo = 0; var hi = v6Records - 1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1; val off = HEADER_BYTES + mid * V6_RECORD_BYTES
            val sh = v6.getLong(off); val sl = v6.getLong(off + 8); val eh = v6.getLong(off + 16); val el = v6.getLong(off + 24)
            when {
                compare128(address.v6Hi, address.v6Lo, sh, sl) < 0 -> hi = mid - 1
                compare128(address.v6Hi, address.v6Lo, eh, el) > 0 -> lo = mid + 1
                else -> return unpackCountry(v6.getShort(off + 32).toInt() and 0xffff)
            }
        }
        return null
    }

    private fun unpackCountry(v: Int): String = charArrayOf((v ushr 8).toChar(), (v and 0xff).toChar()).concatToString()
    private fun compare128(ahi: Long, alo: Long, bhi: Long, blo: Long): Int {
        val h = java.lang.Long.compareUnsigned(ahi, bhi); return if (h != 0) h else java.lang.Long.compareUnsigned(alo, blo)
    }

    companion object {
        private const val HEADER_BYTES = 12
        private const val V4_RECORD_BYTES = 12
        private const val V6_RECORD_BYTES = 40
        fun open(v4File: File, v6File: File, fetchedAt: Long, expectedV4: Int, expectedV6: Int): GeoCountryIndex {
            val v4 = FileInputStream(v4File).channel.use { it.map(FileChannel.MapMode.READ_ONLY, 0, it.size()).order(ByteOrder.BIG_ENDIAN) }
            val v6 = FileInputStream(v6File).channel.use { it.map(FileChannel.MapMode.READ_ONLY, 0, it.size()).order(ByteOrder.BIG_ENDIAN) }
            require(v4.getInt(0) == 0x47444734 && v4.getInt(4) == 1 && v4.getInt(8) == expectedV4) { "geo ipv4 header invalid" }
            require(v6.getInt(0) == 0x47444736 && v6.getInt(4) == 1 && v6.getInt(8) == expectedV6) { "geo ipv6 header invalid" }
            require(v4.capacity().toLong() == HEADER_BYTES + expectedV4.toLong() * V4_RECORD_BYTES) { "geo ipv4 size mismatch" }
            require(v6.capacity().toLong() == HEADER_BYTES + expectedV6.toLong() * V6_RECORD_BYTES) { "geo ipv6 size mismatch" }
            return GeoCountryIndex(v4, v6, fetchedAt, expectedV4, expectedV6)
        }
    }
}
