package de.visiongaia.gedefense.mobile

import android.Manifest
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import de.visiongaia.gedefense.mobile.core.AuthenticatedSnapshotState
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

class PackageBaselineStore(context: Context) {
    private enum class StoreState { UNINITIALIZED, READY, DEGRADED }

    private val appContext = context.applicationContext
    private val pm = appContext.packageManager
    private val recoveryDir = File(appContext.noBackupFilesDir, "vault-recovery")
    private val migrationSpec = VaultMigrationPolicy.PACKAGE_BASELINE_HMAC_V2_TO_V3
    private val migrationWindow: VaultMigrationPolicy.Window? by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        VaultMigrationPolicy.window(appContext, migrationSpec)
    }
    private val legacyFile = File(appContext.noBackupFilesDir, "xdr/package-baseline.v1.json")
    private val legacyV2File = File(appContext.noBackupFilesDir, "xdr/package-baseline.v2.bin")
    private val legacyV2Store = SecureSnapshotStore(
        file = legacyV2File,
        hmacKey = null,
        domain = VaultDomain.PACKAGE_BASELINE,
        schemaVersion = 2,
        maxPlaintextBytes = MAX_FILE_BYTES,
        hmacKeyProvider = { AndroidSecrets.hmacSha256OrNull("vgt.gedefense.mobile.package-baseline.hmac.v2") },
    )
    private val snapshotStore = SecureSnapshotStore(
        file = File(appContext.noBackupFilesDir, "xdr/package-baseline.v3.bin"),
        hmacKey = null,
        domain = VaultDomain.PACKAGE_BASELINE,
        schemaVersion = 3,
        maxPlaintextBytes = MAX_FILE_BYTES,
        hmacKeyProvider = { SecureTelemetryVault.hotPathHmacKey(VaultDomain.PACKAGE_BASELINE) },
        legacyHmacKeyProvider = {
            AndroidSecrets.hmacSha256OrNull(
                "vgt.gedefense.mobile.package-baseline.hmac.v3",
                preferStrongBox = false,
            )
        },
    )

    @Volatile private var storeState = StoreState.UNINITIALIZED
    @Volatile private var failureReason: String? = null
    private var baselines = linkedMapOf<String, Baseline>()

    fun initialize() = loadAuthenticated()

    data class Baseline(
        val packageName: String,
        val versionCode: Long,
        val signerSha256: String?,
        val signerLineageSha256: Set<String>,
        val systemPackage: Boolean,
        val requested: Set<String>,
        val granted: Set<String>,
        val capabilities: Set<String>,
    )

    data class Change(
        val packageName: String,
        val old: Baseline?,
        val current: Baseline?,
        val newlyRequested: Set<String> = emptySet(),
        val newlyGranted: Set<String> = emptySet(),
        val newCapabilities: Set<String> = emptySet(),
        val signerChanged: Boolean = false,
        val signerRotationTrusted: Boolean = false,
        val signerChangeReviewOnly: Boolean = false,
    )

    data class SignerContext(
        val systemPackage: Boolean,
        val verifiedRotationLineage: Boolean,
    )

    fun integrityOk(): Boolean = storeState != StoreState.DEGRADED
    fun initialized(): Boolean = storeState == StoreState.READY
    fun integrityFailureReason(): String? = failureReason

    fun currentSignerContext(packageName: String): SignerContext? {
        val current = capture(packageName) ?: return null
        return SignerContext(
            systemPackage = current.systemPackage,
            verifiedRotationLineage = current.signerLineageSha256.size > 1,
        )
    }

    @Synchronized
    fun reconcileAll(): List<Change> {
        if (storeState == StoreState.DEGRADED) return emptyList()
        val installed = installed() ?: return emptyList()
        val current = installed.associateByTo(linkedMapOf()) { it.packageName }
        if (storeState != StoreState.READY) {
            if (persist(current)) {
                baselines = current
                storeState = StoreState.READY
                failureReason = null
                legacyFile.delete()
            } else degrade("package_baseline_initialization_failed")
            return emptyList()
        }

        val previous = baselines
        val changes = ArrayList<Change>()
        val allNames = (previous.keys + current.keys).sorted()
        for (name in allNames) {
            if (name == appContext.packageName) continue
            compare(name, previous[name], current[name])?.let(changes::add)
        }
        if (!persist(current)) {
            degrade("package_baseline_update_failed")
            return emptyList()
        }
        baselines = current
        return changes
    }

    @Synchronized
    fun reconcilePackage(packageName: String, removed: Boolean = false): Change? {
        if (!validPackageName(packageName) || packageName == appContext.packageName || storeState == StoreState.DEGRADED) return null
        if (storeState != StoreState.READY) {
            reconcileAll()
            return null
        }
        val old = baselines[packageName]
        val now = if (removed) null else capture(packageName) ?: return null
        val next = LinkedHashMap(baselines)
        if (now == null) next.remove(packageName) else next[packageName] = now
        val change = compare(packageName, old, now)
        if (change == null) return null
        if (!persist(next)) {
            degrade("package_baseline_package_update_failed")
            return null
        }
        baselines = next
        return change
    }

    @Synchronized
    fun resetTrustedBaseline(): Boolean {
        val installed = installed() ?: return false
        val current = installed.associateByTo(linkedMapOf()) { it.packageName }
        if (!persist(current)) return false
        baselines = current
        storeState = StoreState.READY
        failureReason = null
        legacyFile.delete()
        return true
    }

    private fun compare(name: String, old: Baseline?, now: Baseline?): Change? {
        if (old == null && now == null) return null
        if (old == null || now == null) return Change(name, old, now)
        val requested = now.requested - old.requested
        val granted = now.granted - old.granted
        val capabilities = now.capabilities - old.capabilities
        val signerChanged = !old.signerSha256.isNullOrBlank() && !now.signerSha256.isNullOrBlank() &&
            !MessageDigest.isEqual(old.signerSha256.toByteArray(StandardCharsets.US_ASCII), now.signerSha256.toByteArray(StandardCharsets.US_ASCII))
        val signerRotationTrusted = signerChanged && old.signerSha256 in now.signerLineageSha256
        // A system/updated-system package transition that cannot be proven from our legacy baseline
        // remains reviewable context, but is not independently critical. Android's package verifier and
        // Verified Boot are the stronger authorities for this class of package.
        val signerChangeReviewOnly = signerChanged && !signerRotationTrusted && now.systemPackage
        if (old.versionCode == now.versionCode && requested.isEmpty() && granted.isEmpty() && capabilities.isEmpty() && !signerChanged) return null
        return Change(name, old, now, requested, granted, capabilities, signerChanged, signerRotationTrusted, signerChangeReviewOnly)
    }

    private fun installed(): List<Baseline>? {
        val flags = packageFlags()
        val packages = try {
            if (Build.VERSION.SDK_INT >= 33) pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
            else { @Suppress("DEPRECATION") pm.getInstalledPackages(flags) }
        } catch (_: RuntimeException) { return null }
        return packages.asSequence().mapNotNull(::capture).take(MAX_PACKAGES).toList()
    }

    private fun capture(packageName: String): Baseline? = try {
        val flags = packageFlags()
        val pkg = if (Build.VERSION.SDK_INT >= 33) pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
        else { @Suppress("DEPRECATION") pm.getPackageInfo(packageName, flags) }
        capture(pkg)
    } catch (_: PackageManager.NameNotFoundException) { null } catch (_: RuntimeException) { null }

    private fun capture(pkg: PackageInfo): Baseline? {
        val name = pkg.packageName
        if (!validPackageName(name)) return null
        val requested = pkg.requestedPermissions?.asSequence()?.map(String::trim)?.filter(String::isNotEmpty)?.take(MAX_SET_VALUES)?.toSet().orEmpty()
        val flags = pkg.requestedPermissionsFlags
        val granted = LinkedHashSet<String>()
        pkg.requestedPermissions?.forEachIndexed { i, permission ->
            if (granted.size < MAX_SET_VALUES && flags != null && i < flags.size && flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0) granted += permission
        }
        val capabilities = LinkedHashSet<String>()
        if (pkg.services?.any { it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE" } == true) capabilities += "ACCESSIBILITY_SERVICE"
        if (pkg.services?.any { it.permission == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" } == true) capabilities += "NOTIFICATION_LISTENER"
        if (pkg.services?.any { it.permission == "android.permission.BIND_VPN_SERVICE" } == true) capabilities += "VPN_SERVICE"
        if (pkg.receivers?.any { it.permission == "android.permission.BIND_DEVICE_ADMIN" } == true) capabilities += "DEVICE_ADMIN"
        if ("android.permission.SYSTEM_ALERT_WINDOW" in requested) capabilities += "OVERLAY"
        if (Manifest.permission.REQUEST_INSTALL_PACKAGES in requested) capabilities += "PACKAGE_INSTALLER"
        if (Manifest.permission.RECEIVE_BOOT_COMPLETED in requested) capabilities += "BOOT_PERSISTENCE"
        val signer = signerIdentity(pkg)
        val applicationFlags = pkg.applicationInfo?.flags ?: 0
        val systemPackage = applicationFlags and (android.content.pm.ApplicationInfo.FLAG_SYSTEM or android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        return Baseline(
            name, pkg.longVersionCode.coerceAtLeast(0L), signer.current, signer.lineage, systemPackage,
            requested, granted, capabilities,
        )
    }

    private data class SignerIdentity(val current: String?, val lineage: Set<String>)

    private fun signerIdentity(pkg: PackageInfo): SignerIdentity {
        return try {
            val info = pkg.signingInfo ?: return SignerIdentity(null, emptySet())
            val current = aggregateSigners(info.apkContentsSigners?.toList().orEmpty())
            val lineage = if (!info.hasMultipleSigners()) {
                info.signingCertificateHistory.orEmpty().mapNotNull { aggregateSigners(listOf(it)) }.toCollection(linkedSetOf())
            } else emptySet()
            SignerIdentity(current, lineage)
        } catch (_: Exception) { SignerIdentity(null, emptySet()) }
    }

    private fun aggregateSigners(signatures: List<android.content.pm.Signature>): String? {
        val signers = signatures.asSequence()
            .map { MessageDigest.getInstance("SHA-256").digest(it.toByteArray()) }
            .sortedWith { a, b -> compareUnsigned(a, b) }
            .toList()
        if (signers.isEmpty()) return null
        val aggregate = MessageDigest.getInstance("SHA-256")
        aggregate.update("VGT-GEDEFENSE-SIGNER-SET-v1\u0000".toByteArray(StandardCharsets.US_ASCII))
        aggregate.update(byteArrayOf((signers.size ushr 8).toByte(), signers.size.toByte()))
        signers.forEach(aggregate::update)
        return aggregate.digest().toHex()
    }

    private fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
        val limit = minOf(a.size, b.size)
        for (i in 0 until limit) {
            val left = a[i].toInt() and 0xff
            val right = b[i].toInt() and 0xff
            if (left != right) return left - right
        }
        return a.size - b.size
    }

    private fun packageFlags(): Int = PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS

    private fun loadAuthenticated() {
        val read = snapshotStore.read()
        when (read.state) {
            AuthenticatedSnapshotState.ABSENT -> migrateLegacyV2OrInitialize()
            AuthenticatedSnapshotState.INVALID -> degrade(failureCode(snapshotStore.failureKind(), legacy = false))
            AuthenticatedSnapshotState.VALID -> {
                val decoded = decode(read.payload ?: ByteArray(0))
                if (decoded == null) degrade("package_baseline_payload_invalid")
                else {
                    baselines = decoded
                    storeState = StoreState.READY
                    failureReason = null
                    legacyFile.delete()
                    cleanupCompletedLegacyV2()
                }
            }
        }
    }

    /**
     * One-way migration from the v2 outer-HMAC generation to v3.
     *
     * A valid v2 snapshot is migrated without losing continuity. If the historical v2 Android
     * Keystore HMAC cannot be acquired or executed on an OEM provider, only an actual app-update
     * migration window may rebuild this reconstructible baseline. Authentication/format failures
     * are never auto-healed and remain fail-closed.
     */
    private fun migrateLegacyV2OrInitialize() {
        if (!legacyV2File.exists()) {
            baselines.clear()
            storeState = StoreState.UNINITIALIZED
            failureReason = null
            return
        }

        val legacyRead = legacyV2Store.read()
        when (legacyRead.state) {
            AuthenticatedSnapshotState.ABSENT -> {
                baselines.clear()
                storeState = StoreState.UNINITIALIZED
                failureReason = null
            }
            AuthenticatedSnapshotState.VALID -> {
                val decoded = decode(legacyRead.payload ?: ByteArray(0))
                if (decoded == null) {
                    degrade("package_baseline_legacy_payload_invalid")
                    return
                }
                if (!persist(decoded)) {
                    degrade("package_baseline_migration_persist_failed")
                    return
                }
                baselines = decoded
                storeState = StoreState.READY
                failureReason = null
                legacyV2File.delete()
                legacyFile.delete()
            }
            AuthenticatedSnapshotState.INVALID -> recoverLegacyV2KeyFailure()
        }
    }

    private fun recoverLegacyV2KeyFailure() {
        val kind = legacyV2Store.failureKind()
        if (kind !in LEGACY_KEY_RECOVERY_FAILURES) {
            degrade(failureCode(kind, legacy = true))
            return
        }
        val window = migrationWindow
        if (window == null) {
            degrade(failureCode(kind, legacy = true))
            return
        }
        val archive = legacyV2Store.archiveMigrationCandidate(
            recoveryRoot = recoveryDir,
            olderThanMillis = window.updatedAtMillis,
            allowedFailures = LEGACY_KEY_RECOVERY_FAILURES,
        )
        if (archive == null) {
            degrade("package_baseline_migration_archive_failed")
            return
        }
        val installed = installed()
        if (installed == null) {
            degrade("package_baseline_migration_inventory_unavailable")
            return
        }
        val rebuilt = installed.associateByTo(linkedMapOf()) { it.packageName }
        if (!persist(rebuilt)) {
            degrade("package_baseline_migration_persist_failed")
            return
        }
        if (!VaultMigrationPolicy.markCompleted(appContext, window, archive.sha256)) {
            snapshotStore.clear()
            degrade("package_baseline_migration_marker_failed")
            return
        }
        // Source deletion is intentionally last. If cleanup fails, v3 remains authoritative and
        // the archived v2 bytes plus completion marker preserve forensic/migration context.
        legacyV2Store.commitArchivedMigration(recoveryDir, archive)
        baselines = rebuilt
        storeState = StoreState.READY
        failureReason = null
        legacyFile.delete()
    }

    private fun cleanupCompletedLegacyV2() {
        if (!legacyV2File.exists()) return
        if (!VaultMigrationPolicy.isCompleted(appContext, migrationSpec)) return
        // Never parse or trust a leftover migrated source once v3 is valid. The recovery archive and
        // completion marker are the durable audit trail; the old live snapshot is no longer needed.
        try { legacyV2File.delete() } catch (error: Exception) { RuntimeFailureLog.nonCritical("package-baseline-store", error) }
    }

    private fun failureCode(kind: SecureVaultFailureKind, legacy: Boolean): String {
        val prefix = if (legacy) "package_baseline_legacy" else "package_baseline"
        return when (kind) {
            SecureVaultFailureKind.OUTER_KEY_UNAVAILABLE -> "${prefix}_key_unavailable"
            SecureVaultFailureKind.OUTER_KEY_OPERATION -> "${prefix}_key_operation_failed"
            SecureVaultFailureKind.OUTER_IO_UNAVAILABLE -> "${prefix}_io_unavailable"
            SecureVaultFailureKind.OUTER_INTEGRITY -> "${prefix}_integrity_failed"
            SecureVaultFailureKind.OUTER_RUNTIME_FAILURE -> "${prefix}_runtime_failure"
            SecureVaultFailureKind.KEY_CONTINUITY -> "${prefix}_key_continuity_failed"
            SecureVaultFailureKind.LEGACY_MIGRATION -> "${prefix}_vault_migration_failed"
            SecureVaultFailureKind.ENVELOPE_DECODE -> "${prefix}_envelope_invalid"
            SecureVaultFailureKind.NONE -> "${prefix}_state_invalid"
        }
    }

    private fun persist(items: Map<String, Baseline>): Boolean {
        return try {
            val array = JSONArray()
            items.values.sortedBy { it.packageName }.take(MAX_PACKAGES).forEach { b ->
                array.put(JSONObject().put("package", b.packageName).put("version", b.versionCode).put("signer", b.signerSha256 ?: "")
                    .put("signer_lineage", jsonArray(b.signerLineageSha256)).put("system_package", b.systemPackage)
                    .put("requested", jsonArray(b.requested)).put("granted", jsonArray(b.granted)).put("capabilities", jsonArray(b.capabilities)))
            }
            val bytes = JSONObject().put("version", 2).put("packages", array).toString().toByteArray(StandardCharsets.UTF_8)
            if (bytes.size > MAX_FILE_BYTES) false else { snapshotStore.write(bytes); true }
        } catch (_: Exception) { false }
    }

    private fun decode(payload: ByteArray): LinkedHashMap<String, Baseline>? {
        return try {
            if (payload.size > MAX_FILE_BYTES) return null
            val root = JSONObject(payload.toString(StandardCharsets.UTF_8))
            if (root.optInt("version") != 2) return null
            val array = root.optJSONArray("packages") ?: return linkedMapOf()
            val out = linkedMapOf<String, Baseline>()
        for (i in 0 until minOf(array.length(), MAX_PACKAGES)) {
            val j = array.optJSONObject(i) ?: continue
            val name = j.optString("package").take(256)
            if (!validPackageName(name)) continue
            out[name] = Baseline(
                name,
                j.optLong("version").coerceAtLeast(0L),
                j.optString("signer").takeIf { it.matches(HEX_64) },
                jsonSet(j.optJSONArray("signer_lineage")).filterTo(linkedSetOf()) { it.matches(HEX_64) },
                j.optBoolean("system_package", false),
                jsonSet(j.optJSONArray("requested")),
                jsonSet(j.optJSONArray("granted")),
                jsonSet(j.optJSONArray("capabilities")),
            )
        }
            out
        } catch (_: Exception) { null }
    }

    private fun jsonArray(values: Set<String>) = JSONArray().also { a -> values.sorted().take(MAX_SET_VALUES).forEach(a::put) }
    private fun jsonSet(array: JSONArray?): Set<String> = buildSet {
        if (array != null) for (i in 0 until minOf(array.length(), MAX_SET_VALUES)) array.optString(i).trim().takeIf(String::isNotEmpty)?.let(::add)
    }

    private fun degrade(reason: String) {
        baselines.clear()
        storeState = StoreState.DEGRADED
        failureReason = reason.take(160)
    }

    private fun validPackageName(value: String): Boolean = value.length in 3..256 && value.contains('.') && value.none(Char::isWhitespace) &&
        !value.startsWith(".") && !value.endsWith(".")

    private fun ByteArray.toHex(): String = buildString(size * 2) {
        for (byte in this@toHex) {
            val value = byte.toInt() and 0xff
            append(HEX[value ushr 4])
            append(HEX[value and 0x0f])
        }
    }

    companion object {
        private val LEGACY_KEY_RECOVERY_FAILURES = setOf(
            SecureVaultFailureKind.OUTER_KEY_UNAVAILABLE,
            SecureVaultFailureKind.OUTER_KEY_OPERATION,
            SecureVaultFailureKind.KEY_CONTINUITY,
        )
        private const val MAX_PACKAGES = 1600
        private const val MAX_SET_VALUES = 256
        private const val MAX_FILE_BYTES = 2 * 1024 * 1024
        private val HEX_64 = Regex("[0-9a-f]{64}")
        private val HEX = "0123456789abcdef".toCharArray()
    }
}
