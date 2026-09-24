package de.visiongaia.gedefense.mobile

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import de.visiongaia.gedefense.mobile.core.IntegrityBaselineStore
import de.visiongaia.gedefense.mobile.core.IntegrityIdentity
import javax.crypto.SecretKey
import java.io.File
import java.io.FileInputStream
import java.nio.file.Files
import java.security.MessageDigest

enum class IntegritySeverity { INFO, WARNING, CRITICAL }

data class IntegrityIssue(
    val code: String,
    val severity: IntegritySeverity,
    val detail: String,
)

data class IntegritySnapshot(
    val state: String,
    val checkedAtMillis: Long,
    val installSha256: String,
    val signerSha256: String,
    val filesChecked: Int,
    val issues: List<IntegrityIssue>,
) {
    val ok: Boolean get() = state == "HEALTHY"

    companion object {
        fun pending() = IntegritySnapshot("PENDING", 0L, "", "", 0, emptyList())
    }
}

/**
 * Local self-integrity guard. It verifies the installed APK set, signing identity and the private
 * GeDefense filesystem without requesting broad storage access. Other apps' private sandboxes are
 * intentionally outside this component's authority.
 */
class IntegrityGuardian(
    context: Context,
    integrityKeyProvider: () -> SecretKey?,
) {
    private val appContext = context.applicationContext
    private val baseline = IntegrityBaselineStore(
        File(appContext.filesDir, "integrity/install-baseline.v1"),
        null,
        integrityKeyProvider,
        recoveryBoundaryMillis = IntegrityKeyMigrationPolicy.updateBoundaryMillis(appContext),
    )

    @Throws(InterruptedException::class)
    fun scan(cancelled: () -> Boolean = { false }): IntegritySnapshot {
        val now = System.currentTimeMillis()
        val deadlineNanos = System.nanoTime() + INTEGRITY_SCAN_TIMEOUT_NANOS
        val issues = ArrayList<IntegrityIssue>()
        val identity = try {
            currentIdentity(cancelled, deadlineNanos)
        } catch (e: InterruptedException) {
            throw e
        } catch (_: IntegrityScanTimeoutException) {
            issues += IntegrityIssue("integrity_scan_timeout", IntegritySeverity.CRITICAL, "Integrity identity scan exceeded bounded deadline")
            return IntegritySnapshot("COMPROMISED", now, "", "", 0, issues)
        } catch (t: Throwable) {
            issues += IntegrityIssue("identity_unavailable", IntegritySeverity.CRITICAL, t.javaClass.simpleName.take(80))
            return IntegritySnapshot("COMPROMISED", now, "", "", 0, issues)
        }

        val decision = try { baseline.verifyOrAdvance(identity) } catch (t: Throwable) {
            issues += IntegrityIssue("baseline_io_failure", IntegritySeverity.CRITICAL, t.javaClass.simpleName.take(80))
            null
        }
        if (decision != null && !decision.ok) {
            issues += IntegrityIssue(
                decision.reason ?: "baseline_verification_failed",
                IntegritySeverity.CRITICAL,
                "Authenticated installation identity did not verify",
            )
        }

        val fileResult = try {
            scanPrivateTree(cancelled, deadlineNanos)
        } catch (e: InterruptedException) {
            throw e
        } catch (_: IntegrityScanTimeoutException) {
            FileScanResult(0, listOf(IntegrityIssue(
                "integrity_scan_timeout",
                IntegritySeverity.CRITICAL,
                "Private integrity scan exceeded bounded deadline",
            )))
        }
        issues += fileResult.issues
        val state = if (issues.any { it.severity == IntegritySeverity.CRITICAL }) "COMPROMISED" else "HEALTHY"
        return IntegritySnapshot(
            state = state,
            checkedAtMillis = now,
            installSha256 = identity.installSha256,
            signerSha256 = identity.signerSha256,
            filesChecked = fileResult.filesChecked,
            issues = issues.take(MAX_REPORTED_ISSUES),
        )
    }

    private fun currentIdentity(cancelled: () -> Boolean, deadlineNanos: Long): IntegrityIdentity {
        checkBudget(cancelled, deadlineNanos)
        val pm = appContext.packageManager
        val flags = PackageManager.GET_SIGNING_CERTIFICATES
        val info = if (Build.VERSION.SDK_INT >= 33) {
            pm.getPackageInfo(appContext.packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(appContext.packageName, flags)
        }
        val app = requireNotNull(info.applicationInfo) { "application info unavailable" }
        val apks = buildList {
            add(app.sourceDir)
            app.splitSourceDirs?.forEach { add(it) }
        }.map(::File).sortedBy { it.name }
        require(apks.isNotEmpty() && apks.all { it.isFile && it.canRead() }) { "installed APK set unavailable" }
        val total = apks.sumOf { it.length() }
        require(total in 1..MAX_INSTALL_BYTES) { "installed APK size outside boundary" }

        val installDigest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(32 * 1024)
        for (apk in apks) {
            checkBudget(cancelled, deadlineNanos)
            val name = apk.name.toByteArray(Charsets.UTF_8)
            installDigest.update((name.size ushr 8).toByte())
            installDigest.update(name.size.toByte())
            installDigest.update(name)
            FileInputStream(apk).use { input ->
                while (true) {
                    checkBudget(cancelled, deadlineNanos)
                    val read = input.read(buffer)
                    if (read < 0) break
                    installDigest.update(buffer, 0, read)
                }
            }
        }

        val signers = info.signingInfo?.apkContentsSigners?.map { sha256(it.toByteArray()) }?.sorted().orEmpty()
        require(signers.isNotEmpty()) { "signing identity unavailable" }
        val signerDigest = MessageDigest.getInstance("SHA-256")
        signers.forEach { digest ->
            signerDigest.update(digest.toByteArray(Charsets.US_ASCII))
            signerDigest.update(0)
        }
        return IntegrityIdentity(
            packageName = appContext.packageName,
            versionCode = info.longVersionCode,
            installSha256 = hex(installDigest.digest()),
            signerSha256 = hex(signerDigest.digest()),
        )
    }

    private fun scanPrivateTree(cancelled: () -> Boolean, deadlineNanos: Long): FileScanResult {
        val root = appContext.filesDir
        val rootCanonical = root.canonicalFile
        val issues = ArrayList<IntegrityIssue>()
        var checked = 0
        var discovered = 1 // root
        var entryLimitReached = false
        val stack = ArrayDeque<Pair<File, Int>>()
        stack.add(root to 0)
        while (stack.isNotEmpty()) {
            checkBudget(cancelled, deadlineNanos)
            val (entry, depth) = stack.removeLast()
            if (depth > MAX_DEPTH) {
                issues += IntegrityIssue("filesystem_depth_limit", IntegritySeverity.WARNING, entry.name.take(120))
                continue
            }
            if (Files.isSymbolicLink(entry.toPath())) {
                issues += IntegrityIssue("filesystem_symlink", IntegritySeverity.CRITICAL, entry.name.take(120))
                continue
            }
            val canonical = try { entry.canonicalFile } catch (_: Exception) {
                issues += IntegrityIssue("filesystem_canonicalization_failed", IntegritySeverity.CRITICAL, entry.name.take(120))
                continue
            }
            if (canonical != rootCanonical && !canonical.path.startsWith(rootCanonical.path + File.separator)) {
                issues += IntegrityIssue("filesystem_jail_escape", IntegritySeverity.CRITICAL, entry.name.take(120))
                continue
            }
            if (entry.isDirectory) {
                try {
                    Files.newDirectoryStream(canonical.toPath()).use { children ->
                        for (childPath in children) {
                            checkBudget(cancelled, deadlineNanos)
                            if (discovered >= MAX_ENTRIES) {
                                issues += IntegrityIssue("filesystem_entry_limit", IntegritySeverity.CRITICAL, "Private entry count exceeds $MAX_ENTRIES")
                                entryLimitReached = true
                                break
                            }
                            discovered++
                            stack.add(childPath.toFile() to depth + 1)
                        }
                    }
                } catch (e: InterruptedException) {
                    throw e
                } catch (e: IntegrityScanTimeoutException) {
                    throw e
                } catch (_: Exception) {
                    issues += IntegrityIssue("filesystem_directory_unreadable", IntegritySeverity.WARNING, entry.name.take(120))
                }
                if (entryLimitReached) break
                continue
            }
            if (!entry.isFile) continue
            checked++
            if (checked > MAX_FILES) {
                issues += IntegrityIssue("filesystem_file_limit", IntegritySeverity.CRITICAL, "Private file count exceeds $MAX_FILES")
                break
            }
            val lower = entry.name.lowercase()
            if (FORBIDDEN_RUNTIME_SUFFIXES.any(lower::endsWith)) {
                issues += IntegrityIssue("unexpected_executable_artifact", IntegritySeverity.CRITICAL, entry.name.take(120))
            }
        }
        return FileScanResult(checked, issues)
    }

    private fun checkBudget(cancelled: () -> Boolean, deadlineNanos: Long) {
        if (Thread.currentThread().isInterrupted || cancelled()) throw InterruptedException("integrity scan cancelled")
        if (System.nanoTime() >= deadlineNanos) throw IntegrityScanTimeoutException()
    }

    private class IntegrityScanTimeoutException : RuntimeException()

    private fun sha256(bytes: ByteArray): String = hex(MessageDigest.getInstance("SHA-256").digest(bytes))
    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    private data class FileScanResult(val filesChecked: Int, val issues: List<IntegrityIssue>)

    companion object {
        private const val MAX_INSTALL_BYTES = 2L * 1024L * 1024L * 1024L
        private const val MAX_FILES = 8192
        private const val MAX_ENTRIES = 16_384
        private const val MAX_DEPTH = 8
        private val INTEGRITY_SCAN_TIMEOUT_NANOS = java.util.concurrent.TimeUnit.SECONDS.toNanos(15)
        private const val MAX_REPORTED_ISSUES = 32
        private val FORBIDDEN_RUNTIME_SUFFIXES = listOf(".dex", ".jar", ".apk", ".so", ".sh", ".elf", ".exe", ".dll", ".bat", ".cmd", ".ps1")
    }
}
