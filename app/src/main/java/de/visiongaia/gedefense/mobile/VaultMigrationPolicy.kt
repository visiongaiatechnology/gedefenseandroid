package de.visiongaia.gedefense.mobile

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption

// STATUS: DIAMANT VGT SUPREME
/**
 * Explicit, generation-scoped migration policy for reconstructible authenticated stores.
 *
 * A migration is eligible only on a real package update, only when the current release is at or
 * above the migration's minimum target version, and only until an atomic completion marker exists.
 * Callers must additionally prove that the legacy source predates the package update and that the
 * observed failure belongs to the migration's narrow recoverable set.
 */
internal object VaultMigrationPolicy {
    data class Spec(
        val id: String,
        val domain: VaultDomain,
        val sourceGeneration: Int,
        val targetGeneration: Int,
        val minimumTargetVersionCode: Long,
    ) {
        init {
            require(validMigrationId(id))
            require(sourceGeneration > 0 && targetGeneration > sourceGeneration)
            require(minimumTargetVersionCode > 0L)
        }
    }

    data class Window(
        val spec: Spec,
        val currentVersionCode: Long,
        val updatedAtMillis: Long,
    )

    val PACKAGE_BASELINE_HMAC_V2_TO_V3: Spec by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        Spec(
            id = "package-baseline-hmac-v2-to-v3",
            domain = VaultDomain.PACKAGE_BASELINE,
            sourceGeneration = 2,
            targetGeneration = 3,
            minimumTargetVersionCode = 52L,
        )
    }

    fun window(context: Context, spec: Spec): Window? {
        val app = context.applicationContext
        val info = try {
            if (Build.VERSION.SDK_INT >= 33) {
                app.packageManager.getPackageInfo(app.packageName, PackageManager.PackageInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                app.packageManager.getPackageInfo(app.packageName, 0)
            }
        } catch (_: Exception) {
            return null
        }
        val versionCode = info.longVersionCode
        if (versionCode < spec.minimumTargetVersionCode) return null
        val first = info.firstInstallTime
        val updated = info.lastUpdateTime
        if (first <= 0L || updated <= first) return null
        if (isCompleted(app, spec)) return null
        return Window(spec, versionCode, updated)
    }

    fun markCompleted(context: Context, window: Window, archiveSha256: String): Boolean {
        if (!validSha256Hex(archiveSha256)) return false
        val app = context.applicationContext
        val marker = markerFile(app, window.spec)
        val parent = marker.parentFile ?: return false
        val parentPath = parent.toPath()
        return try {
            if (!Files.exists(parentPath, LinkOption.NOFOLLOW_LINKS)) Files.createDirectories(parentPath)
            if (Files.isSymbolicLink(parentPath) || !Files.isDirectory(parentPath, LinkOption.NOFOLLOW_LINKS)) return false
            if (Files.exists(marker.toPath(), LinkOption.NOFOLLOW_LINKS)) {
                return isCompleted(app, window.spec)
            }
            val body = buildString(256) {
                append("id=").append(window.spec.id).append('\n')
                append("domain=").append(window.spec.domain.id).append('\n')
                append("source_generation=").append(window.spec.sourceGeneration).append('\n')
                append("target_generation=").append(window.spec.targetGeneration).append('\n')
                append("version_code=").append(window.currentVersionCode).append('\n')
                append("update_time_ms=").append(window.updatedAtMillis).append('\n')
                append("archive_sha256=").append(archiveSha256).append('\n')
            }.toByteArray(StandardCharsets.US_ASCII)
            SecureFiles.writeAtomic(marker, body)
            isCompleted(app, window.spec)
        } catch (_: Exception) {
            false
        }
    }

    fun isCompleted(context: Context, spec: Spec): Boolean {
        val marker = markerFile(context.applicationContext, spec)
        val path = marker.toPath()
        return try {
            if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path) ||
                !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) return false
            val size = Files.size(path)
            if (size !in 1..MAX_MARKER_BYTES) return false
            val text = Files.readAllBytes(path).toString(StandardCharsets.US_ASCII)
            val fields = text.lineSequence().mapNotNull { line ->
                val split = line.indexOf('=')
                if (split <= 0 || split == line.lastIndex) null else line.substring(0, split) to line.substring(split + 1)
            }.toMap()
            fields["id"] == spec.id &&
                fields["domain"] == spec.domain.id &&
                fields["source_generation"] == spec.sourceGeneration.toString() &&
                fields["target_generation"] == spec.targetGeneration.toString() &&
                fields["version_code"]?.toLongOrNull()?.let { it >= spec.minimumTargetVersionCode } == true &&
                fields["update_time_ms"]?.toLongOrNull()?.let { it > 0L } == true &&
                fields["archive_sha256"]?.let(::validSha256Hex) == true
        } catch (_: Exception) {
            false
        }
    }

    private fun markerFile(context: Context, spec: Spec): File =
        File(context.noBackupFilesDir, "vault-recovery/migration-markers/${spec.id}.done")

    private fun validMigrationId(value: String): Boolean {
        if (value.length !in 8..96 || value.firstOrNull()?.let { it !in 'a'..'z' && it !in '0'..'9' } != false) return false
        return value.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }
    }

    private fun validSha256Hex(value: String): Boolean =
        value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }

    private const val MAX_MARKER_BYTES = 2_048L
}
