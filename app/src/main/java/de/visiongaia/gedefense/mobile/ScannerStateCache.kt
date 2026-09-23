package de.visiongaia.gedefense.mobile

import android.content.Context
import de.visiongaia.gedefense.mobile.core.AuthenticatedSnapshotState
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File

internal data class StorageCacheRecord(
    val pathKey: String,
    val size: Long,
    val modified: Long,
    val cachedAt: Long,
    val kind: String,
    val sha256: String?,
    val contentFingerprint: String?,
    val baseFindings: List<FileRiskFinding>,
    val indicators: List<String>,
    val inspected: Boolean,
    val deepComplete: Boolean,
)

internal data class AppPackageCacheRecord(
    val packageName: String,
    val fingerprint: String,
    val inspectedAt: Long,
    val installer: String?,
    val signerSha256: String?,
    val apkSha256: String?,
    val baseFindings: List<AppRiskFinding>,
    val indicators: List<String>,
    val deepComplete: Boolean,
)

/**
 * Authenticated, bounded scanner acceleration state.
 *
 * Cache data is performance state, never an authority boundary: threat decisions are recomputed
 * against the current ThreatIndex on every scan. HMAC authentication prevents a corrupted or
 * tampered cache from silently suppressing static evidence. Invalid snapshots degrade to a cache
 * miss, forcing fresh inspection instead of producing a clean verdict.
 */
internal class ScannerStateCache(context: Context) {
    private val dir = File(context.noBackupFilesDir, "scanner-state")
    private val recoveryDir = File(context.noBackupFilesDir, "vault-recovery")
    private val betaRecoveryBoundaryMillis: Long? by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        BetaVaultMigrationPolicy.updateBoundaryMillis(context)
    }
    private val storageStore = SecureSnapshotStore(
        file = File(dir, "storage-v4.bin"),
        hmacKey = null,
        domain = VaultDomain.SCANNER_STORAGE,
        schemaVersion = STORAGE_SCHEMA,
        maxPlaintextBytes = MAX_STORAGE_PAYLOAD_BYTES,
        hmacKeyProvider = { SecureTelemetryVault.hotPathHmacKey(VaultDomain.SCANNER_STORAGE) },
        legacyHmacKeyProvider = { AndroidSecrets.hmacSha256OrNull("vgt.gedefense.mobile.scanner.storage.hmac.v1") },
    )
    private val appStore = SecureSnapshotStore(
        file = File(dir, "apps-v3.bin"),
        hmacKey = null,
        domain = VaultDomain.SCANNER_APPS,
        schemaVersion = APP_SCHEMA,
        maxPlaintextBytes = MAX_APP_PAYLOAD_BYTES,
        hmacKeyProvider = { SecureTelemetryVault.hotPathHmacKey(VaultDomain.SCANNER_APPS) },
        legacyHmacKeyProvider = { AndroidSecrets.hmacSha256OrNull("vgt.gedefense.mobile.scanner.apps.hmac.v1") },
    )

    fun loadStorage(): Map<String, StorageCacheRecord> {
        var read = storageStore.read()
        if (read.state == AuthenticatedSnapshotState.INVALID &&
            storageStore.archiveAndClearReconstructibleStartupFailure(recoveryDir, betaRecoveryBoundaryMillis) != null
        ) read = storageStore.read()
        if (read.state != AuthenticatedSnapshotState.VALID || read.payload == null) return emptyMap()
        return try {
            DataInputStream(ByteArrayInputStream(read.payload)).use { input ->
                if (input.readInt() != STORAGE_MAGIC) return emptyMap()
                val count = input.readInt()
                if (count !in 0..MAX_STORAGE_RECORDS) return emptyMap()
                val out = LinkedHashMap<String, StorageCacheRecord>(count)
                repeat(count) {
                    val pathKey = readBoundedUtf(input, 128)
                    val size = input.readLong()
                    val modified = input.readLong()
                    val cachedAt = input.readLong()
                    val kind = readBoundedUtf(input, 32)
                    val sha = readBoundedUtf(input, 128).ifBlank { null }
                    val contentFingerprint = readBoundedUtf(input, 128).ifBlank { null }
                    val inspected = input.readBoolean()
                    val deepComplete = input.readBoolean()
                    val findingsCount = input.readUnsignedByte()
                    if (findingsCount > MAX_FINDINGS) throw IllegalStateException("cache findings overflow")
                    val findings = ArrayList<FileRiskFinding>(findingsCount)
                    repeat(findingsCount) {
                        findings += FileRiskFinding(
                            readBoundedUtf(input, 96),
                            input.readInt().coerceIn(0, 100),
                            readBoundedUtf(input, 240),
                        )
                    }
                    val indicatorCount = input.readUnsignedShort()
                    if (indicatorCount > MAX_INDICATORS) throw IllegalStateException("cache indicator overflow")
                    val indicators = ArrayList<String>(indicatorCount)
                    repeat(indicatorCount) { indicators += readBoundedUtf(input, 64) }
                    if (pathKey.matches(HEX_64) && size >= 0L && modified >= 0L && cachedAt > 0L &&
                        (contentFingerprint == null || contentFingerprint.matches(HEX_64))
                    ) {
                        out[pathKey] = StorageCacheRecord(
                            pathKey = pathKey,
                            size = size,
                            modified = modified,
                            cachedAt = cachedAt,
                            kind = kind,
                            sha256 = sha?.takeIf { it.matches(HEX_64) },
                            contentFingerprint = contentFingerprint,
                            baseFindings = findings,
                            indicators = indicators,
                            inspected = inspected,
                            deepComplete = deepComplete,
                        )
                    }
                }
                if (input.read() != -1) return emptyMap()
                out
            }
        } catch (_: Exception) {
            emptyMap()
        }
    }

    fun saveStorage(records: Collection<StorageCacheRecord>) {
        try {
            storageStore.write(encodeStorage(records))
            legacyStorageFiles().forEach(File::delete)
        } catch (_: Exception) {
            // Cache persistence failure only disables acceleration. It never changes a verdict.
        }
    }

    fun loadAppPackages(): Map<String, AppPackageCacheRecord> {
        var read = appStore.read()
        if (read.state == AuthenticatedSnapshotState.INVALID &&
            appStore.archiveAndClearReconstructibleStartupFailure(recoveryDir, betaRecoveryBoundaryMillis) != null
        ) read = appStore.read()
        if (read.state != AuthenticatedSnapshotState.VALID || read.payload == null) return emptyMap()
        return try {
            DataInputStream(ByteArrayInputStream(read.payload)).use { input ->
                if (input.readInt() != APP_MAGIC) return emptyMap()
                val count = input.readInt()
                if (count !in 0..MAX_APP_PACKAGE_RECORDS) return emptyMap()
                val out = LinkedHashMap<String, AppPackageCacheRecord>(count)
                repeat(count) {
                    val packageName = readBoundedUtf(input, 240)
                    val fingerprint = readBoundedUtf(input, 128)
                    val inspectedAt = input.readLong()
                    val installer = readBoundedUtf(input, 240).ifBlank { null }
                    val signer = readBoundedUtf(input, 128).ifBlank { null }
                    val apkHash = readBoundedUtf(input, 128).ifBlank { null }
                    val deepComplete = input.readBoolean()
                    val findingsCount = input.readUnsignedByte()
                    if (findingsCount > MAX_FINDINGS) throw IllegalStateException("app findings overflow")
                    val findings = ArrayList<AppRiskFinding>(findingsCount)
                    repeat(findingsCount) {
                        findings += AppRiskFinding(readBoundedUtf(input, 96), input.readInt().coerceIn(0, 100))
                    }
                    val indicatorCount = input.readUnsignedShort()
                    if (indicatorCount > MAX_PACKAGE_INDICATORS) throw IllegalStateException("app indicator overflow")
                    val indicators = ArrayList<String>(indicatorCount)
                    repeat(indicatorCount) { indicators += readBoundedUtf(input, 64) }
                    if (PACKAGE_PATTERN.matches(packageName) && fingerprint.matches(HEX_64) && inspectedAt > 0L) {
                        out[packageName] = AppPackageCacheRecord(
                            packageName = packageName,
                            fingerprint = fingerprint,
                            inspectedAt = inspectedAt,
                            installer = installer,
                            signerSha256 = signer?.takeIf { it.matches(HEX_64) },
                            apkSha256 = apkHash?.takeIf { it.matches(HEX_64) },
                            baseFindings = findings,
                            indicators = indicators,
                            deepComplete = deepComplete,
                        )
                    }
                }
                if (input.read() != -1) return emptyMap()
                out
            }
        } catch (_: Exception) {
            emptyMap()
        }
    }

    fun saveAppPackages(records: Collection<AppPackageCacheRecord>) {
        try {
            appStore.write(encodeAppPackages(records))
            legacyAppFile().delete()
        } catch (_: Exception) {
            // Cache persistence failure only disables acceleration. It never changes a verdict.
        }
    }

    private fun encodeStorage(records: Collection<StorageCacheRecord>): ByteArray {
        val encoded = ArrayList<ByteArray>()
        var total = HEADER_BYTES
        for (record in records.asSequence().sortedBy { it.pathKey }.take(MAX_STORAGE_RECORDS)) {
            if (!record.pathKey.matches(HEX_64)) continue
            if (record.contentFingerprint != null && !record.contentFingerprint.matches(HEX_64)) continue
            val item = encodeStorageRecord(record)
            if (item.size > MAX_RECORD_BYTES || total + item.size > MAX_STORAGE_PAYLOAD_BYTES) continue
            encoded += item
            total += item.size
        }
        val bytes = ByteArrayOutputStream(total)
        DataOutputStream(bytes).use { out ->
            out.writeInt(STORAGE_MAGIC)
            out.writeInt(encoded.size)
            encoded.forEach(out::write)
        }
        return bytes.toByteArray()
    }

    private fun encodeStorageRecord(record: StorageCacheRecord): ByteArray {
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { out ->
            writeBoundedUtf(out, record.pathKey, 128)
            out.writeLong(record.size.coerceAtLeast(0L))
            out.writeLong(record.modified.coerceAtLeast(0L))
            out.writeLong(record.cachedAt.coerceAtLeast(1L))
            writeBoundedUtf(out, record.kind, 32)
            writeBoundedUtf(out, record.sha256.orEmpty(), 128)
            writeBoundedUtf(out, record.contentFingerprint.orEmpty(), 128)
            out.writeBoolean(record.inspected)
            out.writeBoolean(record.deepComplete)
            val findings = record.baseFindings.take(MAX_FINDINGS)
            out.writeByte(findings.size)
            findings.forEach {
                writeBoundedUtf(out, it.code, 96)
                out.writeInt(it.weight.coerceIn(0, 100))
                writeBoundedUtf(out, it.detail, 240)
            }
            val indicators = record.indicators.asSequence().distinct().take(MAX_INDICATORS).toList()
            out.writeShort(indicators.size)
            indicators.forEach { writeBoundedUtf(out, it, 64) }
        }
        return bytes.toByteArray()
    }

    private fun encodeAppPackages(records: Collection<AppPackageCacheRecord>): ByteArray {
        val encoded = ArrayList<ByteArray>()
        var total = HEADER_BYTES
        for (record in records.asSequence().sortedBy { it.packageName }.take(MAX_APP_PACKAGE_RECORDS)) {
            if (!PACKAGE_PATTERN.matches(record.packageName) || !record.fingerprint.matches(HEX_64)) continue
            if (record.indicators.size > MAX_PACKAGE_INDICATORS) continue
            val item = encodeAppPackageRecord(record)
            if (item.size > MAX_PACKAGE_RECORD_BYTES || total + item.size > MAX_APP_PAYLOAD_BYTES) continue
            encoded += item
            total += item.size
        }
        val bytes = ByteArrayOutputStream(total)
        DataOutputStream(bytes).use { out ->
            out.writeInt(APP_MAGIC)
            out.writeInt(encoded.size)
            encoded.forEach(out::write)
        }
        return bytes.toByteArray()
    }

    private fun encodeAppPackageRecord(record: AppPackageCacheRecord): ByteArray {
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { out ->
            writeBoundedUtf(out, record.packageName, 240)
            writeBoundedUtf(out, record.fingerprint, 128)
            out.writeLong(record.inspectedAt.coerceAtLeast(1L))
            writeBoundedUtf(out, record.installer.orEmpty(), 240)
            writeBoundedUtf(out, record.signerSha256.orEmpty(), 128)
            writeBoundedUtf(out, record.apkSha256.orEmpty(), 128)
            out.writeBoolean(record.deepComplete)
            val findings = record.baseFindings.take(MAX_FINDINGS)
            out.writeByte(findings.size)
            findings.forEach {
                writeBoundedUtf(out, it.code, 96)
                out.writeInt(it.weight.coerceIn(0, 100))
            }
            val indicators = record.indicators.asSequence().distinct().take(MAX_PACKAGE_INDICATORS).toList()
            out.writeShort(indicators.size)
            indicators.forEach { writeBoundedUtf(out, it, 64) }
        }
        return bytes.toByteArray()
    }

    private fun readBoundedUtf(input: DataInputStream, maxChars: Int): String {
        val value = input.readUTF()
        if (value.length > maxChars) throw IllegalStateException("cache field overflow")
        return value
    }

    private fun writeBoundedUtf(output: DataOutputStream, value: String, maxChars: Int) {
        output.writeUTF(value.take(maxChars))
    }

    private fun legacyStorageFiles(): List<File> = listOf(File(dir, "storage-v3.bin"), File(dir, "storage-v2.bin"))
    private fun legacyAppFile(): File = File(dir, "apps-v2.bin")

    companion object {
        private const val STORAGE_SCHEMA = 4
        private const val APP_SCHEMA = 3
        private const val STORAGE_MAGIC = 0x47534434
        private const val APP_MAGIC = 0x47415033
        private const val HEADER_BYTES = 8
        private const val MAX_STORAGE_PAYLOAD_BYTES = 12 * 1024 * 1024
        private const val MAX_APP_PAYLOAD_BYTES = 12 * 1024 * 1024
        private const val MAX_RECORD_BYTES = 32 * 1024
        private const val MAX_PACKAGE_RECORD_BYTES = 96 * 1024
        private const val MAX_STORAGE_RECORDS = 25_000
        private const val MAX_APP_PACKAGE_RECORDS = 1_024
        private const val MAX_FINDINGS = 12
        private const val MAX_INDICATORS = 256
        private const val MAX_PACKAGE_INDICATORS = 1_024
        private val HEX_64 = Regex("[0-9a-f]{64}")
        private val PACKAGE_PATTERN = Regex("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+")
    }
}
