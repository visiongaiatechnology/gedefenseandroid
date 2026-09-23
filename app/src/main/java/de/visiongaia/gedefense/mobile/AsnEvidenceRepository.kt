package de.visiongaia.gedefense.mobile

import android.content.Context
import de.visiongaia.gedefense.mobile.core.AsnEvidence
import de.visiongaia.gedefense.mobile.core.AsnLiteCompiler
import de.visiongaia.gedefense.mobile.core.AsnLiteIndex
import de.visiongaia.gedefense.mobile.core.BoundedSecretKeyCrypto
import de.visiongaia.gedefense.mobile.core.IpAddress
import java.io.BufferedInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.Proxy
import java.net.URI
import java.nio.file.Files
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.net.ssl.HttpsURLConnection

/**
 * STATUS: DIAMANT VGT SUPREME
 *
 * Authenticated local ASN evidence snapshot. The source is IPtoASN-derived PDDL/Public-Domain data
 * distributed by the ip-location-db mirror with published SHA-256 files. Destination addresses are
 * never sent to an ASN service: network I/O only refreshes whole public datasets in the background.
 *
 * This repository exposes lookup/evidence context only. It has deliberately no block/allow/policy
 * API, keeping ASN enrichment evidence_only by construction.
 */
class AsnEvidenceRepository(
    context: Context,
    private val integrityKeyProvider: () -> SecretKey?,
) {
    private val root = File(context.filesDir, "asn-evidence")
    private val generations = File(root, "generations")
    private val activePointer = File(root, ACTIVE_POINTER_FILE)

    @Volatile private var index: AsnLiteIndex? = null
    @Volatile private var state: AsnEvidenceState = AsnEvidenceState.missing()

    @Synchronized
    fun loadCached(): AsnEvidenceState {
        if (integrityKey() == null) {
            index = null
            state = AsnEvidenceState.unavailable()
            return state
        }
        val loaded = tryLoadIndex() ?: recoverLatestValidGeneration()
        index = loaded?.index
        state = loaded?.state ?: AsnEvidenceState.missing()
        return state
    }

    fun lookup(address: IpAddress): AsnEvidence? {
        if (!address.isPublic()) return null
        return index?.lookup(address)
    }

    fun snapshot(): AsnEvidenceState = state

    @Synchronized
    @Throws(InterruptedException::class)
    fun syncDue(now: Long = System.currentTimeMillis()): AsnEvidenceState {
        check(integrityKey() != null) { "ASN evidence integrity key unavailable" }
        val current = state
        if (current.ready && now - current.fetchedAtMillis < MIN_REFRESH_MS) return current
        ensureStorageJail()

        val previousPointer = readAuthenticatedPointer()
        val generationName = "gen-$now-${UUID.randomUUID().toString().replace("-", "")}".lowercase(Locale.ROOT)
        require(GENERATION_REGEX.matches(generationName)) { "ASN generation name invalid" }
        val stage = File(generations, ".$generationName.stage")
        if (!stage.mkdir()) error("ASN generation staging unavailable")
        var committed: File? = null
        var pointerPublished = false
        var v4Download: SourceDownload? = null
        var v6Download: SourceDownload? = null
        try {
            v4Download = downloadVerifiedSource(V4_SOURCE, MAX_V4_BYTES)
            v6Download = downloadVerifiedSource(V6_SOURCE, MAX_V6_BYTES)
            val v4Index = File(stage, V4_FILE)
            val v6Index = File(stage, V6_FILE)
            val organizations = File(stage, ORG_FILE)
            val built = AsnLiteCompiler.compile(
                v4Csv = v4Download.file,
                v6Csv = v6Download.file,
                v4Out = v4Index,
                v6Out = v6Index,
                organizationsOut = organizations,
            )
            if (built.v4Records < MIN_RECORDS || built.v6Records < MIN_RECORDS || built.organizations < MIN_ORGANIZATIONS) {
                error("ASN dataset implausibly small")
            }
            val meta = GenerationMeta(
                fetchedAtMillis = now,
                v4Records = built.v4Records,
                v6Records = built.v6Records,
                organizations = built.organizations,
                v4SourceSha256 = v4Download.sha256,
                v6SourceSha256 = v6Download.sha256,
                v4IndexSha256 = sha256(v4Index),
                v6IndexSha256 = sha256(v6Index),
                organizationsSha256 = sha256(organizations),
            )
            SecureFiles.writeAtomic(File(stage, MANIFEST_FILE), buildManifest(meta))
            val staged = verifyGeneration(stage) ?: error("ASN staged generation verification failed")
            if (staged.state.fetchedAtMillis != now) error("ASN staged timestamp mismatch")

            committed = File(generations, generationName)
            moveDirectoryAtomic(stage, committed)
            SecureFiles.writeAtomic(activePointer, buildPointer(generationName, now))
            pointerPublished = true
            val active = readAuthenticatedPointer() ?: error("ASN active pointer verification failed")
            if (active.generationName != generationName || active.fetchedAtMillis != now) error("ASN active pointer mismatch")
            val loaded = tryLoadIndex() ?: error("ASN committed generation verification failed")
            if (loaded.state.fetchedAtMillis != now) error("ASN committed timestamp mismatch")

            index = loaded.index
            state = loaded.state
            cleanupGenerations(generationName)
            return state
        } catch (t: Throwable) {
            if (stage.exists()) safeDeleteGeneration(stage)
            if (pointerPublished) restorePointer(previousPointer)
            if (committed != null && readAuthenticatedPointer()?.generationName != committed.name) safeDeleteGeneration(committed)
            throw t
        } finally {
            v4Download?.file?.delete()
            v6Download?.file?.delete()
        }
    }

    private fun tryLoadIndex(): LoadedGeneration? {
        val generationName = activeGenerationName() ?: return null
        val base = try { generations.canonicalFile } catch (_: Throwable) { return null }
        val generation = try { File(base, generationName).canonicalFile } catch (_: Throwable) { return null }
        if (generation.parentFile != base || !generation.isDirectory) return null
        return try { verifyGeneration(generation) } catch (_: Throwable) { null }
    }

    private fun verifyGeneration(generation: File): LoadedGeneration? {
        val manifest = File(generation, MANIFEST_FILE)
        val v4 = File(generation, V4_FILE)
        val v6 = File(generation, V6_FILE)
        val organizations = File(generation, ORG_FILE)
        if (!manifest.isFile || !v4.isFile || !v6.isFile || !organizations.isFile) return null
        val meta = verifyManifest(manifest, v4, v6, organizations) ?: return null
        val opened = AsnLiteIndex.open(v4, v6, organizations, meta.v4Records, meta.v6Records, meta.organizations)
        return LoadedGeneration(opened, meta.toState())
    }

    private fun buildPointer(generationName: String, at: Long): ByteArray {
        val payload = "v1\n$generationName\n$at\n".toByteArray(Charsets.US_ASCII)
        val mac = hmac(payload)
        return payload + hex(mac).toByteArray(Charsets.US_ASCII) + byteArrayOf('\n'.code.toByte())
    }

    private fun readAuthenticatedPointer(): AuthenticatedPointer? {
        if (!activePointer.isFile || activePointer.length() !in 1..512) return null
        val encoded = try { activePointer.readBytes() } catch (_: Throwable) { return null }
        if (encoded.size !in 1..512) return null
        val lines = try { encoded.toString(Charsets.US_ASCII).lineSequence().toList() } catch (_: Throwable) { return null }
        val normalized = if (lines.isNotEmpty() && lines.last().isEmpty()) lines.dropLast(1) else lines
        if (normalized.size != 4 || normalized[0] != "v1") return null
        val name = normalized[1]
        val at = normalized[2].toLongOrNull() ?: return null
        if (!GENERATION_REGEX.matches(name) || at <= 0L) return null
        val expected = normalized[3].lowercase(Locale.ROOT)
        if (!SHA256_REGEX.matches(expected)) return null
        val payload = "v1\n$name\n$at\n".toByteArray(Charsets.US_ASCII)
        val actual = hex(hmac(payload))
        if (!constantTimeHexEquals(expected, actual)) return null
        return AuthenticatedPointer(name, at, encoded)
    }

    private fun activeGenerationName(): String? = readAuthenticatedPointer()?.generationName

    private fun restorePointer(previous: AuthenticatedPointer?) {
        if (previous != null) {
            SecureFiles.writeAtomic(activePointer, previous.encoded)
            val restored = readAuthenticatedPointer() ?: error("ASN pointer rollback verification failed")
            if (restored.generationName != previous.generationName || restored.fetchedAtMillis != previous.fetchedAtMillis) {
                error("ASN pointer rollback mismatch")
            }
            return
        }
        if (activePointer.exists() && !activePointer.delete()) error("ASN pointer rollback delete failed")
    }

    private fun recoverLatestValidGeneration(): LoadedGeneration? {
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
            .sortedByDescending { it.second.state.fetchedAtMillis }
            .toList()
        val best = candidates.firstOrNull() ?: return null
        return try {
            SecureFiles.writeAtomic(activePointer, buildPointer(best.first.name, best.second.state.fetchedAtMillis))
            val verified = readAuthenticatedPointer() ?: return null
            if (verified.generationName != best.first.name) return null
            best.second
        } catch (_: Throwable) { null }
    }

    private fun ensureStorageJail() {
        if (!generations.isDirectory && !generations.mkdirs()) error("ASN evidence storage unavailable")
        val rootCanonical = root.canonicalFile
        val generationsCanonical = generations.canonicalFile
        if (generationsCanonical.parentFile != rootCanonical || !generationsCanonical.isDirectory) {
            error("ASN evidence storage escaped jail")
        }
    }

    private fun safeDeleteGeneration(dir: File) {
        try {
            val base = generations.canonicalFile
            val canonical = dir.canonicalFile
            if (canonical.parentFile == base && (GENERATION_REGEX.matches(canonical.name) || canonical.name.startsWith(".gen-"))) {
                canonical.deleteRecursively()
            }
        } catch (error: Throwable) { RuntimeFailureLog.nonCritical("asn-evidence-repository", error) }
    }

    private fun moveDirectoryAtomic(source: File, target: File) {
        require(source.parentFile?.canonicalFile == target.parentFile?.canonicalFile) { "ASN generation path escaped jail" }
        if (target.exists()) error("ASN generation collision")
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
            try { if (dir.canonicalFile.parentFile == base) dir.deleteRecursively() } catch (error: Throwable) { RuntimeFailureLog.nonCritical("asn-evidence-repository", error) }
        }
        entries.filter { it.isDirectory && it.name.startsWith(".gen-") && it.name.endsWith(".stage") }.forEach { stage ->
            try { if (stage.canonicalFile.parentFile == base) stage.deleteRecursively() } catch (error: Throwable) { RuntimeFailureLog.nonCritical("asn-evidence-repository", error) }
        }
    }

    private fun buildManifest(meta: GenerationMeta): ByteArray {
        val payload = listOf(
            "v1",
            meta.fetchedAtMillis.toString(),
            SOURCE_ID,
            UPSTREAM_ID,
            LICENSE_ID,
            V4_SOURCE.dataUrl,
            V4_SOURCE.checksumUrl,
            meta.v4Records.toString(),
            meta.v4SourceSha256,
            meta.v4IndexSha256,
            V6_SOURCE.dataUrl,
            V6_SOURCE.checksumUrl,
            meta.v6Records.toString(),
            meta.v6SourceSha256,
            meta.v6IndexSha256,
            meta.organizations.toString(),
            meta.organizationsSha256,
            EVIDENCE_CLASS,
        ).joinToString("\n", postfix = "\n").toByteArray(Charsets.US_ASCII)
        return payload + hex(hmac(payload)).toByteArray(Charsets.US_ASCII) + byteArrayOf('\n'.code.toByte())
    }

    private fun verifyManifest(manifest: File, v4: File, v6: File, organizations: File): GenerationMeta? {
        if (manifest.length() !in 1..8192) return null
        val lines = try { manifest.readLines(Charsets.US_ASCII) } catch (_: Throwable) { return null }
        if (lines.size != 19 || lines[0] != "v1") return null
        val at = lines[1].toLongOrNull()?.takeIf { it > 0L } ?: return null
        if (lines[2] != SOURCE_ID || lines[3] != UPSTREAM_ID || lines[4] != LICENSE_ID) return null
        if (lines[5] != V4_SOURCE.dataUrl || lines[6] != V4_SOURCE.checksumUrl) return null
        val v4Records = lines[7].toIntOrNull()?.takeIf { it in MIN_RECORDS..MAX_RECORDS } ?: return null
        if (!SHA256_REGEX.matches(lines[8]) || !SHA256_REGEX.matches(lines[9])) return null
        if (lines[10] != V6_SOURCE.dataUrl || lines[11] != V6_SOURCE.checksumUrl) return null
        val v6Records = lines[12].toIntOrNull()?.takeIf { it in MIN_RECORDS..MAX_RECORDS } ?: return null
        if (!SHA256_REGEX.matches(lines[13]) || !SHA256_REGEX.matches(lines[14])) return null
        val organizationCount = lines[15].toIntOrNull()?.takeIf { it in MIN_ORGANIZATIONS..MAX_ORGANIZATIONS } ?: return null
        if (!SHA256_REGEX.matches(lines[16]) || lines[17] != EVIDENCE_CLASS) return null

        val payload = (lines.take(18).joinToString("\n") + "\n").toByteArray(Charsets.US_ASCII)
        val expectedMac = lines[18].lowercase(Locale.ROOT)
        if (!SHA256_REGEX.matches(expectedMac) || !constantTimeHexEquals(expectedMac, hex(hmac(payload)))) return null
        if (!constantTimeHexEquals(lines[9], sha256(v4))) return null
        if (!constantTimeHexEquals(lines[14], sha256(v6))) return null
        if (!constantTimeHexEquals(lines[16], sha256(organizations))) return null

        return GenerationMeta(
            fetchedAtMillis = at,
            v4Records = v4Records,
            v6Records = v6Records,
            organizations = organizationCount,
            v4SourceSha256 = lines[8],
            v6SourceSha256 = lines[13],
            v4IndexSha256 = lines[9],
            v6IndexSha256 = lines[14],
            organizationsSha256 = lines[16],
        )
    }

    private fun downloadVerifiedSource(source: AsnSource, maxBytes: Long): SourceDownload {
        throwIfInterrupted()
        val checksumText = downloadSmallText(source.checksumUrl, MAX_CHECKSUM_BYTES)
        val expected = checksumText.trim().split(Regex("\\s+")).firstOrNull()?.lowercase(Locale.ROOT)
            ?.takeIf { SHA256_REGEX.matches(it) } ?: error("ASN checksum invalid")
        val data = downloadFile(source.dataUrl, maxBytes)
        try {
            val actual = sha256(data)
            if (!constantTimeHexEquals(expected, actual)) error("ASN checksum mismatch")
            return SourceDownload(data, actual)
        } catch (t: Throwable) {
            data.delete()
            throw t
        }
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
            require(current.protocol == "https" && current.userInfo == null && current.ref == null) { "ASN URL must be HTTPS" }
            if (!allowedSourceHost(current.host)) error("ASN source host refused")
            val connection = current.openConnection(Proxy.NO_PROXY) as? HttpsURLConnection ?: error("ASN HTTPS required")
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 10_000
            connection.readTimeout = 30_000
            connection.useCaches = false
            connection.setRequestProperty("User-Agent", "VGT-GeDefense-Mobile/0.27.8 asn-evidence")
            val code = connection.responseCode
            if (code in intArrayOf(301, 302, 303, 307, 308)) {
                val next = current.toURI().resolve(connection.getHeaderField("Location") ?: error("ASN redirect missing")).toURL()
                connection.disconnect()
                if (++redirects > 4 || !allowedSourceHost(next.host)) error("ASN redirect refused")
                current = next
                continue
            }
            if (code != HttpsURLConnection.HTTP_OK) {
                connection.disconnect()
                error("ASN HTTP $code")
            }
            val declared = connection.contentLengthLong
            if (declared > maxBytes) {
                connection.disconnect()
                error("ASN download exceeds bound")
            }
            val temp = SecureFiles.createPrivateTempFile(root, ".asn-download-")
            var total = 0L
            try {
                BufferedInputStream(connection.inputStream, 64 * 1024).use { input ->
                    FileOutputStream(temp).use { output ->
                        val buffer = ByteArray(64 * 1024)
                        while (true) {
                            throwIfInterrupted()
                            val read = input.read(buffer)
                            if (read < 0) break
                            total += read
                            if (total > maxBytes) error("ASN download exceeds bound")
                            output.write(buffer, 0, read)
                        }
                        output.fd.sync()
                    }
                }
                if (total <= 0L) error("ASN download empty")
                return temp
            } catch (t: Throwable) {
                temp.delete()
                throw t
            } finally {
                connection.disconnect()
            }
        }
    }

    private fun allowedSourceHost(host: String?): Boolean {
        val normalized = host?.lowercase(Locale.ROOT) ?: return false
        return normalized == "github.com" ||
            normalized == "release-assets.githubusercontent.com" ||
            normalized == "objects.githubusercontent.com"
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        FileInputStream(file).use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return hex(digest.digest())
    }

    private fun constantTimeHexEquals(expected: String, actual: String): Boolean =
        MessageDigest.isEqual(expected.toByteArray(Charsets.US_ASCII), actual.toByteArray(Charsets.US_ASCII))

    private fun throwIfInterrupted() {
        if (Thread.currentThread().isInterrupted) throw InterruptedException("ASN evidence sync interrupted")
    }

    private fun requiredIntegrityKey(): SecretKey =
        integrityKey() ?: throw IllegalStateException("ASN evidence integrity key unavailable")

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

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    private data class AuthenticatedPointer(
        val generationName: String,
        val fetchedAtMillis: Long,
        val encoded: ByteArray,
    )

    private data class AsnSource(val dataUrl: String, val checksumUrl: String)
    private data class SourceDownload(val file: File, val sha256: String)
    private data class LoadedGeneration(val index: AsnLiteIndex, val state: AsnEvidenceState)

    private data class GenerationMeta(
        val fetchedAtMillis: Long,
        val v4Records: Int,
        val v6Records: Int,
        val organizations: Int,
        val v4SourceSha256: String,
        val v6SourceSha256: String,
        val v4IndexSha256: String,
        val v6IndexSha256: String,
        val organizationsSha256: String,
    ) {
        fun toState(): AsnEvidenceState = AsnEvidenceState(
            state = "READY",
            fetchedAtMillis = fetchedAtMillis,
            v4Records = v4Records,
            v6Records = v6Records,
            organizations = organizations,
            sourceId = SOURCE_ID,
            upstreamId = UPSTREAM_ID,
            licenseId = LICENSE_ID,
            v4SourceSha256 = v4SourceSha256,
            v6SourceSha256 = v6SourceSha256,
            v4IndexSha256 = v4IndexSha256,
            v6IndexSha256 = v6IndexSha256,
            organizationsSha256 = organizationsSha256,
        )
    }

    companion object {
        private const val MAX_GENERATION_DIRECTORY_ENTRIES = 64
        const val SOURCE_ID = "sapics-ip-location-db/iptoasn-asn"
        const val UPSTREAM_ID = "IPtoASN"
        const val LICENSE_ID = "PDDL-1.0"
        const val EVIDENCE_CLASS = "evidence_only"

        private const val ACTIVE_POINTER_FILE = "active.ptr"
        private const val MANIFEST_FILE = "asn.manifest"
        private const val V4_FILE = "asn-v4.bin"
        private const val V6_FILE = "asn-v6.bin"
        private const val ORG_FILE = "asn-org.bin"
        private const val MIN_RECORDS = 1000
        private const val MAX_RECORDS = 2_000_000
        private const val MIN_ORGANIZATIONS = 100
        private const val MAX_ORGANIZATIONS = 500_000
        private const val MAX_CHECKSUM_BYTES = 4096L
        private const val MAX_V4_BYTES = 96L * 1024L * 1024L
        private const val MAX_V6_BYTES = 192L * 1024L * 1024L
        private const val MIN_REFRESH_MS = 24L * 60L * 60L * 1000L
        private val GENERATION_REGEX = Regex("gen-[0-9]{10,17}-[0-9a-f]{32}")
        private val SHA256_REGEX = Regex("[0-9a-f]{64}")

        private val V4_SOURCE = AsnSource(
            "https://github.com/sapics/ip-location-db/releases/download/latest/iptoasn-asn-ipv4.csv",
            "https://github.com/sapics/ip-location-db/releases/download/checksum/iptoasn-asn-ipv4.csv.sha256",
        )
        private val V6_SOURCE = AsnSource(
            "https://github.com/sapics/ip-location-db/releases/download/latest/iptoasn-asn-ipv6.csv",
            "https://github.com/sapics/ip-location-db/releases/download/checksum/iptoasn-asn-ipv6.csv.sha256",
        )
    }
}

data class AsnEvidenceState(
    val state: String,
    val fetchedAtMillis: Long,
    val v4Records: Int,
    val v6Records: Int,
    val organizations: Int,
    val sourceId: String,
    val upstreamId: String,
    val licenseId: String,
    val v4SourceSha256: String,
    val v6SourceSha256: String,
    val v4IndexSha256: String,
    val v6IndexSha256: String,
    val organizationsSha256: String,
) {
    val ready: Boolean get() = state == "READY"

    companion object {
        fun missing() = AsnEvidenceState("MISSING", 0L, 0, 0, 0, AsnEvidenceRepository.SOURCE_ID, AsnEvidenceRepository.UPSTREAM_ID, AsnEvidenceRepository.LICENSE_ID, "", "", "", "", "")
        fun unavailable() = AsnEvidenceState("UNAVAILABLE", 0L, 0, 0, 0, AsnEvidenceRepository.SOURCE_ID, AsnEvidenceRepository.UPSTREAM_ID, AsnEvidenceRepository.LICENSE_ID, "", "", "", "", "")
    }
}
