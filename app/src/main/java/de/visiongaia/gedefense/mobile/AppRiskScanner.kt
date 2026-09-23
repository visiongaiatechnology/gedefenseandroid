package de.visiongaia.gedefense.mobile

import android.Manifest
import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.zip.ZipFile


enum class AppRiskLevel { LOW, REVIEW, HIGH, SEVERE }
enum class AppRiskConfidence { LOW, MEDIUM, HIGH }
enum class AppApprovalState { NONE, APPROVED, STALE }

data class AppRiskFinding(val code: String, val weight: Int)

data class AppScanMetrics(
    val elapsedMs: Long,
    val packageQueryMs: Long,
    val metadataMs: Long,
    val staticAnalysisMs: Long,
    val hashingMs: Long,
    val correlationMs: Long,
    val cacheHits: Int,
    val cacheMisses: Int,
    val bytesStaticScanned: Long,
    val bytesHashed: Long,
) {
    companion object {
        fun empty() = AppScanMetrics(0L, 0L, 0L, 0L, 0L, 0L, 0, 0, 0L, 0L)
    }
}

data class AppRiskResult(
    val packageName: String,
    val label: String,
    val uid: Int,
    val versionName: String,
    val installer: String?,
    val systemApp: Boolean,
    val capabilityScore: Int,
    val riskScore: Int,
    val riskLevel: AppRiskLevel,
    val confidence: AppRiskConfidence,
    val heuristicScore: Int,
    val analysisMode: String,
    val approvalState: AppApprovalState,
    val apkSha256: String?,
    val signerSha256: String?,
    val threatMatches: List<String>,
    val findings: List<AppRiskFinding>,
)

data class AppPackageScanResult(
    val result: AppRiskResult?,
    val deepInspected: Boolean,
    val budgetLimited: Boolean,
    val elapsedMs: Long,
)

data class AppFastScanResult(
    val result: AppRiskResult?,
    val deepEvidenceReusable: Boolean,
    val signerContinuity: Boolean,
    val elapsedMs: Long,
)

data class AppScanSnapshot(
    val state: String,
    val scannedAtMillis: Long,
    val scannedPackages: Int,
    val userPackages: Int,
    val deepScannedPackages: Int,
    val highRiskPackages: Int,
    val threatMatchedPackages: Int,
    val truncated: Boolean,
    val results: List<AppRiskResult>,
    val metrics: AppScanMetrics = AppScanMetrics.empty(),
) {
    companion object {
        fun idle() = AppScanSnapshot("IDLE", 0L, 0, 0, 0, 0, 0, false, emptyList())
    }
}

/**
 * Bounded local app-risk scanner with authenticated whole-package incremental state.
 *
 * A lightweight package fingerprint (package/version/update-time + APK/split metadata) gates reuse.
 * Unchanged packages never reopen their APK ZIPs: cached static indicators are authenticated and are
 * re-correlated against the current ThreatIndex on every scan. Changed/new packages are deep-scanned
 * in a bounded worker pool. Full APK hashing is deferred until a package has review-worthy evidence,
 * avoiding a second whole-file read for clean packages.
 */
class AppRiskScanner(context: Context, val approvals: AppApprovalStore = AppApprovalStore(context)) {
    private val appContext = context.applicationContext
    private val pm = appContext.packageManager
    private val appOps = appContext.getSystemService(AppOpsManager::class.java)
    private val dpm = appContext.getSystemService(DevicePolicyManager::class.java)
    private val cache = ScannerStateCache(appContext)

    fun hasReusableCache(): Boolean = cache.loadAppPackages().isNotEmpty()

    /**
     * Reconstructs the previous app-analysis from the authenticated 0.19+/0.20 package cache
     * without starting a deep APK scan. This path is intentionally read-only: if even one current
     * user package cannot be proven to match a complete cached package fingerprint, restoration
     * aborts and the caller falls back to an explicit fresh scan.
     *
     * Unlike [scan], this method is not synchronized. Startup restoration must never hold the
     * full-scan monitor and make a user-triggered device scan appear stuck in Integrity Guard.
     */
    fun restoreFromAuthenticatedCache(
        index: ThreatIndex,
        cancelled: () -> Boolean = { false },
        timeoutMillis: Long = RESTORE_TIMEOUT_MS,
    ): AppScanSnapshot? {
        val startedNanos = System.nanoTime()
        val timeoutNanos = TimeUnit.MILLISECONDS.toNanos(timeoutMillis.coerceIn(250L, RESTORE_TIMEOUT_MS))
        val deadlineNanos = startedNanos + timeoutNanos
        fun abortRequested(): Boolean = Thread.currentThread().isInterrupted || cancelled() || System.nanoTime() >= deadlineNanos

        val previous = cache.loadAppPackages()
        if (previous.isEmpty() || abortRequested()) return null

        val queryStarted = System.nanoTime()
        val all = try { installedPackagesLight().sortedBy { it.packageName }.take(MAX_PACKAGES + 1) } catch (_: RuntimeException) { return null }
        val packageQueryMs = nanosToMillis(System.nanoTime() - queryStarted)
        if (abortRequested()) return null
        val truncated = all.size > MAX_PACKAGES
        val selected = all.take(MAX_PACKAGES)
        val userPackages = selected.filter { pkg ->
            val app = pkg.applicationInfo ?: return@filter false
            app.flags and ApplicationInfo.FLAG_SYSTEM == 0 || app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
        }

        val results = ArrayList<AppRiskResult>(userPackages.size)
        var metadataNanos = 0L
        var correlationNanos = 0L
        var restoredAt = 0L

        for (light in userPackages) {
            if (abortRequested()) return null
            val app = light.applicationInfo ?: return null
            val cached = previous[light.packageName] ?: return null
            val now = System.currentTimeMillis()
            if (!cached.deepComplete || cached.inspectedAt <= 0L || now - cached.inspectedAt !in 0..MAX_PACKAGE_CACHE_AGE_MS) return null
            val apks = packageApks(app)
            if (cached.fingerprint != packageFingerprint(light, apks)) return null

            val metadataStarted = System.nanoTime()
            val pkg = detailedPackageInfo(light.packageName) ?: return null
            val detailedApp = pkg.applicationInfo ?: app
            val findings = metadataFindings(pkg, detailedApp)
            val installer = installSource(pkg.packageName)
            val signer = signerDigest(pkg) ?: return null
            // A signer change invalidates restoration even if filesystem metadata happened to collide.
            if (cached.signerSha256 != null && !MessageDigest.isEqual(
                    cached.signerSha256.toByteArray(Charsets.US_ASCII),
                    signer.toByteArray(Charsets.US_ASCII),
                )) return null
            metadataNanos += System.nanoTime() - metadataStarted

            val correlationStarted = System.nanoTime()
            val threatMatches = ThreatTokenScanner.correlate(cached.indicators, index, MAX_THREAT_MATCHES)
            correlationNanos += System.nanoTime() - correlationStarted
            results += buildResult(
                pkg = pkg,
                app = detailedApp,
                label = applicationLabel(detailedApp, pkg.packageName),
                installer = installer,
                signer = signer,
                apkHash = cached.apkSha256,
                baseFindings = findings,
                threatMatches = threatMatches,
                analysisMode = "RESTORED_CACHE",
            )
            restoredAt = maxOf(restoredAt, cached.inspectedAt)
        }

        if (abortRequested()) return null
        val sorted = results.sortedWith(compareByDescending<AppRiskResult> { it.riskScore }.thenBy { it.packageName })
        val elapsedMs = nanosToMillis(System.nanoTime() - startedNanos)
        return AppScanSnapshot(
            state = "COMPLETE",
            scannedAtMillis = restoredAt.coerceAtLeast(1L),
            scannedPackages = selected.size,
            userPackages = userPackages.size,
            deepScannedPackages = 0,
            highRiskPackages = sorted.count { it.riskLevel == AppRiskLevel.HIGH || it.riskLevel == AppRiskLevel.SEVERE },
            threatMatchedPackages = sorted.count { it.threatMatches.isNotEmpty() },
            truncated = truncated,
            results = sorted.take(MAX_RESULTS),
            metrics = AppScanMetrics(
                elapsedMs = elapsedMs,
                packageQueryMs = packageQueryMs,
                metadataMs = nanosToMillis(metadataNanos),
                staticAnalysisMs = 0L,
                hashingMs = 0L,
                correlationMs = nanosToMillis(correlationNanos),
                cacheHits = userPackages.size,
                cacheMisses = 0,
                bytesStaticScanned = 0L,
                bytesHashed = 0L,
            ),
        )
    }

    /**
     * Cheap first-stage install verdict. This never hashes or opens APK payload entries. It uses
     * PackageManager-parsed manifest/capability state, installer identity, signer identity and,
     * only when the exact package fingerprint already has authenticated complete static evidence,
     * re-correlates that cached evidence against the current ThreatIndex. A metadata-only PASS is
     * therefore a release-to-background-deep-scan decision, not a final malware-clean claim.
     */
    @Synchronized
    fun fastScanPackage(packageName: String, index: ThreatIndex): AppFastScanResult {
        val started = System.nanoTime()
        if (!PACKAGE_NAME_PATTERN.matches(packageName)) {
            return AppFastScanResult(null, false, false, 0L)
        }
        val light = try {
            if (Build.VERSION.SDK_INT >= 33) pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0L))
            else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, 0)
            }
        } catch (_: Exception) {
            return AppFastScanResult(null, false, false, nanosToMillis(System.nanoTime() - started))
        }
        val app = light.applicationInfo
            ?: return AppFastScanResult(null, false, false, nanosToMillis(System.nanoTime() - started))
        val pkg = detailedPackageInfo(packageName)
            ?: return AppFastScanResult(null, false, false, nanosToMillis(System.nanoTime() - started))
        val detailedApp = pkg.applicationInfo ?: app
        val findings = metadataFindings(pkg, detailedApp)
        val installer = installSource(packageName)
        val signer = signerDigest(pkg)
        if (signer == null) findings += AppRiskFinding("signer_identity_unavailable", 18)

        val apks = packageApks(detailedApp)
        val fingerprint = packageFingerprint(light, apks)
        val cached = cache.loadAppPackages()[packageName]
        val exactReusable = cached != null && cached.fingerprint == fingerprint && cached.deepComplete &&
            cached.inspectedAt > 0L && System.currentTimeMillis() - cached.inspectedAt in 0..MAX_PACKAGE_CACHE_AGE_MS
        val threatMatches = if (exactReusable) {
            ThreatTokenScanner.correlate(cached!!.indicators, index, MAX_THREAT_MATCHES)
        } else emptyList()
        // "Continuity" means continuity with previously authenticated local evidence. A brand-new
        // package that merely has a readable signer is not released before deep inspection.
        val signerContinuity = signer != null && cached?.signerSha256 != null && cached.signerSha256 == signer
        val result = buildResult(
            pkg = pkg,
            app = detailedApp,
            label = applicationLabel(detailedApp, packageName),
            installer = installer,
            signer = signer,
            apkHash = if (exactReusable) cached?.apkSha256 else null,
            baseFindings = findings,
            threatMatches = threatMatches,
            analysisMode = if (exactReusable) "FAST_CACHE_RECORRELATED" else "FAST_METADATA",
        )
        return AppFastScanResult(
            result = result,
            deepEvidenceReusable = exactReusable,
            signerContinuity = signerContinuity,
            elapsedMs = nanosToMillis(System.nanoTime() - started),
        )
    }

    /**
     * Priority scan for one newly installed or updated package. This reuses the authenticated
     * incremental cache but applies a smaller per-package byte budget so installation protection
     * does not turn into a multi-minute foreground stall. The expensive whole-device scan remains
     * available independently.
     */
    @Synchronized
    fun scanPackage(
        packageName: String,
        index: ThreatIndex,
        cancelled: () -> Boolean = { false },
    ): AppPackageScanResult {
        val started = System.nanoTime()
        if (!PACKAGE_NAME_PATTERN.matches(packageName)) {
            return AppPackageScanResult(null, deepInspected = false, budgetLimited = true, elapsedMs = 0L)
        }
        val light = try {
            if (Build.VERSION.SDK_INT >= 33) pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0L))
            else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, 0)
            }
        } catch (_: PackageManager.NameNotFoundException) {
            return AppPackageScanResult(null, deepInspected = false, budgetLimited = false, elapsedMs = nanosToMillis(System.nanoTime() - started))
        } catch (_: RuntimeException) {
            return AppPackageScanResult(null, deepInspected = false, budgetLimited = true, elapsedMs = nanosToMillis(System.nanoTime() - started))
        }
        val app = light.applicationInfo
            ?: return AppPackageScanResult(null, deepInspected = false, budgetLimited = true, elapsedMs = nanosToMillis(System.nanoTime() - started))
        val previous = cache.loadAppPackages()
        val metrics = MetricsAccumulator()
        val budget = ScanBudget(metrics, INSTALL_SCAN_HASH_BYTES, INSTALL_SCAN_STATIC_BYTES)
        val outcome = try {
            scanOne(light, app, index, budget, previous[packageName], cancelled, metrics)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            return AppPackageScanResult(null, deepInspected = false, budgetLimited = true, elapsedMs = nanosToMillis(System.nanoTime() - started))
        }
        outcome.cacheRecord?.let { record ->
            val merged = LinkedHashMap(previous)
            merged[packageName] = record
            cache.saveAppPackages(merged.values)
        }
        return AppPackageScanResult(
            result = outcome.result,
            deepInspected = outcome.deepInspected,
            budgetLimited = outcome.budgetLimited,
            elapsedMs = nanosToMillis(System.nanoTime() - started),
        )
    }

    @Synchronized
    fun scan(
        index: ThreatIndex,
        cancelled: () -> Boolean = { false },
        onProgress: (processed: Int, total: Int, label: String) -> Unit = { _, _, _ -> },
    ): AppScanSnapshot {
        val scanStarted = System.nanoTime()
        val metrics = MetricsAccumulator()
        val queryStarted = System.nanoTime()
        val all = installedPackagesLight().sortedBy { it.packageName }.take(MAX_PACKAGES + 1)
        metrics.packageQueryNanos.addAndGet(System.nanoTime() - queryStarted)
        val truncated = all.size > MAX_PACKAGES
        val selected = all.take(MAX_PACKAGES)
        val userPackages = selected.filter { pkg ->
            val app = pkg.applicationInfo ?: return@filter false
            app.flags and ApplicationInfo.FLAG_SYSTEM == 0 || app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
        }
        val previous = cache.loadAppPackages()
        val nextPackages = ConcurrentHashMap<String, AppPackageCacheRecord>(minOf(userPackages.size, MAX_PACKAGES))
        val results = Collections.synchronizedList(ArrayList<AppRiskResult>(userPackages.size))
        val budget = ScanBudget(metrics)
        val processed = AtomicInteger(0)
        val deepScanned = AtomicInteger(0)
        val bounded = java.util.concurrent.atomic.AtomicBoolean(truncated)
        val cursor = AtomicInteger(0)
        val progress = ProgressGate(onProgress)
        val workers = workerCount(userPackages.size)
        val executor = BoundedExecutors.direct("gedefense-app-scan", workers)
        val futures = (0 until workers).map {
            executor.submit {
                while (true) {
                    cancelledCheck(cancelled)
                    val i = cursor.getAndIncrement()
                    if (i >= userPackages.size) break
                    val light = userPackages[i]
                    val app = light.applicationInfo ?: continue
                    try {
                        val outcome = scanOne(light, app, index, budget, previous[light.packageName], cancelled, metrics)
                        outcome.cacheRecord?.let { nextPackages[light.packageName] = it }
                        outcome.result?.let(results::add)
                        if (outcome.deepInspected) deepScanned.incrementAndGet()
                        if (outcome.budgetLimited) bounded.set(true)
                    } catch (e: InterruptedException) {
                        throw e
                    } catch (_: Exception) {
                        bounded.set(true)
                    } finally {
                        val done = processed.incrementAndGet()
                        progress.emit(done, userPackages.size, light.packageName)
                    }
                }
            }
        }
        try {
            for (future in futures) future.get()
        } catch (e: ExecutionException) {
            val cause = e.cause
            if (cause is InterruptedException) throw cause
            throw (cause ?: e)
        } finally {
            futures.forEach { if (!it.isDone) it.cancel(true) }
            executor.shutdownNow()
        }
        cache.saveAppPackages(nextPackages.values)
        val sorted = results.toList().sortedWith(compareByDescending<AppRiskResult> { it.riskScore }.thenBy { it.packageName })
        val elapsed = nanosToMillis(System.nanoTime() - scanStarted)
        return AppScanSnapshot(
            state = "COMPLETE",
            scannedAtMillis = System.currentTimeMillis(),
            scannedPackages = selected.size,
            userPackages = userPackages.size,
            deepScannedPackages = deepScanned.get(),
            highRiskPackages = sorted.count { it.riskLevel == AppRiskLevel.HIGH || it.riskLevel == AppRiskLevel.SEVERE },
            threatMatchedPackages = sorted.count { it.threatMatches.isNotEmpty() },
            truncated = bounded.get(),
            results = sorted.take(MAX_RESULTS),
            metrics = metrics.snapshot(elapsed),
        )
    }

    private fun scanOne(
        light: PackageInfo,
        app: ApplicationInfo,
        index: ThreatIndex,
        budget: ScanBudget,
        cached: AppPackageCacheRecord?,
        cancelled: () -> Boolean,
        metrics: MetricsAccumulator,
    ): ScanOutcome {
        cancelledCheck(cancelled)
        val apks = packageApks(app)
        val fingerprint = packageFingerprint(light, apks)
        val now = System.currentTimeMillis()
        if (cached != null && cached.packageName == light.packageName && cached.fingerprint == fingerprint && cached.deepComplete &&
            cached.inspectedAt > 0L && now - cached.inspectedAt in 0..MAX_PACKAGE_CACHE_AGE_MS
        ) {
            metrics.cacheHits.incrementAndGet()
            // Runtime grants and active special capabilities can change without an APK/version change.
            // Re-evaluate cheap PackageManager/AppOps metadata on every cache hit and reuse only the
            // expensive authenticated APK indicator scan.
            val metadataStarted = System.nanoTime()
            val pkg = detailedPackageInfo(light.packageName) ?: return ScanOutcome(null, false, true, null)
            val detailedApp = pkg.applicationInfo ?: app
            val findings = metadataFindings(pkg, detailedApp)
            val installer = installSource(pkg.packageName)
            val signer = signerDigest(pkg)
            if (signer == null) findings += AppRiskFinding("signer_identity_unavailable", 18)
            metrics.metadataNanos.addAndGet(System.nanoTime() - metadataStarted)

            val correlationStarted = System.nanoTime()
            val threatMatches = ThreatTokenScanner.correlate(cached.indicators, index, MAX_THREAT_MATCHES)
            metrics.correlationNanos.addAndGet(System.nanoTime() - correlationStarted)
            val assessment = assess(findings, threatMatches)
            var apkHash = cached.apkSha256
            var hashComplete = true
            if (requiresForensicHash(assessment, threatMatches) && apkHash == null && inspectable(apks)) {
                val hash = packageHash(apks, budget, cancelled, metrics)
                apkHash = hash.hash
                hashComplete = hash.complete
            }
            val result = buildResult(
                pkg = pkg,
                app = detailedApp,
                label = applicationLabel(detailedApp, pkg.packageName),
                installer = installer,
                signer = signer,
                apkHash = apkHash,
                baseFindings = findings,
                threatMatches = threatMatches,
                analysisMode = "CACHE_RECORRELATED",
            )
            return ScanOutcome(
                result = result,
                deepInspected = false,
                budgetLimited = !hashComplete,
                cacheRecord = cached.copy(
                    installer = installer?.take(240),
                    signerSha256 = signer,
                    apkSha256 = apkHash,
                    baseFindings = findings.sortedByDescending { it.weight }.take(MAX_FINDINGS),
                ),
            )
        }

        metrics.cacheMisses.incrementAndGet()
        val metadataStarted = System.nanoTime()
        val pkg = detailedPackageInfo(light.packageName) ?: return ScanOutcome(null, false, true, null)
        val detailedApp = pkg.applicationInfo ?: app
        val findings = metadataFindings(pkg, detailedApp)
        val installer = installSource(pkg.packageName)
        val signer = signerDigest(pkg)
        if (signer == null) findings += AppRiskFinding("signer_identity_unavailable", 18)
        metrics.metadataNanos.addAndGet(System.nanoTime() - metadataStarted)

        val isInspectable = inspectable(apks)
        val threatScan = if (isInspectable && budget.hasStaticBudget()) {
            findEmbeddedThreatIps(apks, index, budget, cancelled, metrics)
        } else {
            ThreatScan(emptyList(), emptyList(), complete = false, coverageAvailable = false)
        }
        val assessment = assess(findings, threatScan.matches)
        val hashOutcome = if (isInspectable && requiresForensicHash(assessment, threatScan.matches)) {
            packageHash(apks, budget, cancelled, metrics)
        } else {
            HashOutcome(null, true)
        }
        val result = buildResult(
            pkg = pkg,
            app = detailedApp,
            label = applicationLabel(detailedApp, pkg.packageName),
            installer = installer,
            signer = signer,
            apkHash = hashOutcome.hash,
            baseFindings = findings,
            threatMatches = threatScan.matches,
            analysisMode = "DEEP",
        )
        val cacheRecord = AppPackageCacheRecord(
            packageName = pkg.packageName,
            fingerprint = fingerprint,
            inspectedAt = now,
            installer = installer?.take(240),
            signerSha256 = signer,
            apkSha256 = hashOutcome.hash,
            baseFindings = findings.sortedByDescending { it.weight }.take(MAX_FINDINGS),
            indicators = threatScan.indicators.take(MAX_CACHED_INDICATORS_PER_PACKAGE),
            deepComplete = threatScan.complete && threatScan.coverageAvailable,
        )
        return ScanOutcome(
            result = result,
            deepInspected = isInspectable && threatScan.coverageAvailable,
            budgetLimited = isInspectable && (!threatScan.complete || !hashOutcome.complete),
            cacheRecord = cacheRecord,
        )
    }

    private fun metadataFindings(pkg: PackageInfo, app: ApplicationInfo): ArrayList<AppRiskFinding> {
        val findings = ArrayList<AppRiskFinding>()
        val requested = pkg.requestedPermissions?.toSet().orEmpty()
        val debuggable = app.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        val hasInternet = Manifest.permission.INTERNET in requested
        val hasBoot = Manifest.permission.RECEIVE_BOOT_COMPLETED in requested
        val canInstall = Manifest.permission.REQUEST_INSTALL_PACKAGES in requested
        val overlayDeclared = "android.permission.SYSTEM_ALERT_WINDOW" in requested
        val smsDeclared = requested.any { it in SMS_PERMISSIONS }
        val smsGranted = SMS_PERMISSIONS.any { permissionGranted(pkg.packageName, it) }
        val callLogDeclared = requested.any { it in CALL_LOG_PERMISSIONS }
        val callLogGranted = CALL_LOG_PERMISSIONS.any { permissionGranted(pkg.packageName, it) }
        val requestedSensors = SENSITIVE_PERMISSIONS.count { it in requested }
        val grantedSensors = SENSITIVE_PERMISSIONS.count { permissionGranted(pkg.packageName, it) }
        val accessibilityDeclared = pkg.services?.any { it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE" } == true
        val accessibilityActive = accessibilityDeclared && accessibilityEnabled(pkg.packageName)
        val deviceAdminDeclared = pkg.receivers?.any { it.permission == "android.permission.BIND_DEVICE_ADMIN" } == true
        val deviceAdminActive = deviceAdminDeclared && deviceAdminActive(pkg.packageName)
        val overlayActive = overlayDeclared && overlayAllowed(pkg.packageName, app.uid)

        if (debuggable) findings += AppRiskFinding("debuggable_release", 12)
        if (canInstall && hasInternet) findings += AppRiskFinding("package_install_capability_network", 8)
        if (canInstall && hasBoot) findings += AppRiskFinding("boot_persistent_installer", 6)
        if (overlayActive && hasInternet) findings += AppRiskFinding("overlay_active_network", 14)
        else if (overlayDeclared && hasInternet) findings += AppRiskFinding("overlay_declared_network", 3)
        if (smsGranted && hasInternet) findings += AppRiskFinding("sms_granted_network", 12)
        else if (smsDeclared && hasInternet) findings += AppRiskFinding("sms_declared_network", 4)
        if (callLogGranted && hasInternet) findings += AppRiskFinding("calllog_granted_network", 10)
        else if (callLogDeclared && hasInternet) findings += AppRiskFinding("calllog_declared_network", 3)
        if (accessibilityActive && hasInternet) findings += AppRiskFinding("accessibility_active_network", 26)
        else if (accessibilityDeclared && hasInternet) findings += AppRiskFinding("accessibility_capability_network", 7)
        if (deviceAdminActive) findings += AppRiskFinding("device_admin_active", 14)
        else if (deviceAdminDeclared) findings += AppRiskFinding("device_admin_capability", 4)
        if (grantedSensors >= 3 && hasBoot && hasInternet) findings += AppRiskFinding("persistent_granted_sensor_bundle", 10)
        else if (requestedSensors >= 3 && hasBoot && hasInternet) findings += AppRiskFinding("persistent_declared_sensor_bundle", 3)
        return findings
    }

    private fun permissionGranted(packageName: String, permission: String): Boolean =
        runCatching { pm.checkPermission(permission, packageName) == PackageManager.PERMISSION_GRANTED }.getOrDefault(false)

    private fun accessibilityEnabled(packageName: String): Boolean = try {
        val enabled = Settings.Secure.getString(appContext.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES).orEmpty()
        enabled.split(':').any { component -> component.substringBefore('/').equals(packageName, ignoreCase = false) }
    } catch (_: RuntimeException) { false }

    private fun deviceAdminActive(packageName: String): Boolean = try {
        dpm.activeAdmins.orEmpty().any { it.packageName == packageName }
    } catch (_: RuntimeException) { false }

    private fun overlayAllowed(packageName: String, uid: Int): Boolean = try {
        val mode = appOps.checkOpNoThrow(AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, uid, packageName)
        mode == AppOpsManager.MODE_ALLOWED
    } catch (_: RuntimeException) { false }

    private fun buildResult(
        pkg: PackageInfo,
        app: ApplicationInfo,
        label: String,
        installer: String?,
        signer: String?,
        apkHash: String?,
        baseFindings: List<AppRiskFinding>,
        threatMatches: List<String>,
        analysisMode: String,
    ): AppRiskResult {
        val findings = ArrayList<AppRiskFinding>(baseFindings)
        if (installer.isNullOrBlank()) findings += AppRiskFinding("unknown_install_source", 2)
        if (threatMatches.any { it.endsWith(":BLOCK") }) findings += AppRiskFinding("embedded_blocklist_endpoint", 60)
        if (threatMatches.any { it.endsWith(":CORRELATE") }) findings += AppRiskFinding("embedded_correlated_endpoint", 25)
        val assessment = assess(findings, threatMatches, threatFindingsAlreadyAdded = true)
        val capabilityScore = baseFindings.asSequence()
            .filter { it.code in CAPABILITY_FINDING_CODES }
            .sumOf { it.weight }
            .coerceIn(0, 100)
        val approvalState = approvals.status(pkg.packageName, signer, findings.map { it.code }.toSet())
        val adjusted = if (approvalState == AppApprovalState.APPROVED && threatMatches.isEmpty()) {
            assessment.copy(
                score = minOf(assessment.score, APPROVED_CAPABILITY_SCORE_CAP),
                level = AppRiskLevel.LOW,
                confidence = AppRiskConfidence.LOW,
            )
        } else assessment
        return AppRiskResult(
            packageName = pkg.packageName,
            label = label,
            uid = app.uid,
            versionName = pkg.versionName?.take(80) ?: "",
            installer = installer?.take(160),
            systemApp = app.flags and ApplicationInfo.FLAG_SYSTEM != 0,
            capabilityScore = capabilityScore,
            riskScore = adjusted.score,
            riskLevel = adjusted.level,
            confidence = adjusted.confidence,
            heuristicScore = assessment.rawScore,
            analysisMode = analysisMode,
            approvalState = approvalState,
            apkSha256 = apkHash,
            signerSha256 = signer,
            threatMatches = threatMatches.take(MAX_THREAT_MATCHES),
            findings = findings.sortedByDescending { it.weight }.take(MAX_FINDINGS),
        )
    }

    private fun assess(
        baseFindings: List<AppRiskFinding>,
        threatMatches: List<String>,
        threatFindingsAlreadyAdded: Boolean = false,
    ): RiskAssessment {
        val findings = if (threatFindingsAlreadyAdded) {
            baseFindings
        } else {
            buildList {
                addAll(baseFindings)
                if (threatMatches.any { it.endsWith(":BLOCK") }) add(AppRiskFinding("embedded_blocklist_endpoint", 60))
                if (threatMatches.any { it.endsWith(":CORRELATE") }) add(AppRiskFinding("embedded_correlated_endpoint", 25))
            }
        }
        val raw = findings.sumOf { it.weight }.coerceIn(0, 100)
        val blockingEvidence = threatMatches.any { it.endsWith(":BLOCK") }
        val correlatedEvidence = threatMatches.any { it.endsWith(":CORRELATE") }
        // Capabilities are context, not a malware verdict. They remain available for forensics but
        // stay below the user-visible incident threshold until an independent signal arrives.
        val calibrated = when {
            blockingEvidence -> maxOf(85, raw)
            correlatedEvidence -> maxOf(48, minOf(raw, 62))
            else -> minOf(raw, HEURISTIC_ONLY_SCORE_CAP)
        }.coerceIn(0, 100)
        val level = when {
            calibrated >= 80 -> AppRiskLevel.SEVERE
            calibrated >= 60 -> AppRiskLevel.HIGH
            calibrated >= USER_VISIBLE_REVIEW_THRESHOLD -> AppRiskLevel.REVIEW
            else -> AppRiskLevel.LOW
        }
        val confidence = when {
            blockingEvidence -> AppRiskConfidence.HIGH
            correlatedEvidence -> AppRiskConfidence.MEDIUM
            else -> AppRiskConfidence.LOW
        }
        return RiskAssessment(raw, calibrated, level, confidence)
    }

    private fun requiresForensicHash(assessment: RiskAssessment, threatMatches: List<String>): Boolean =
        assessment.score >= 20 || threatMatches.isNotEmpty()

    private fun packageHash(
        apks: List<File>,
        budget: ScanBudget,
        cancelled: () -> Boolean,
        metrics: MetricsAccumulator,
    ): HashOutcome {
        val started = System.nanoTime()
        val aggregate = MessageDigest.getInstance("SHA-256")
        var complete = true
        try {
            for (apk in apks) {
                cancelledCheck(cancelled)
                val size = apk.length().coerceAtLeast(0L)
                if (!budget.reserveHash(size)) { complete = false; break }
                val digest = sha256(apk, cancelled)
                metrics.bytesHashed.addAndGet(size)
                val name = apk.name.toByteArray(Charsets.UTF_8)
                aggregate.update((name.size ushr 8).toByte())
                aggregate.update(name.size.toByte())
                aggregate.update(name)
                aggregate.update(digest.toByteArray(Charsets.US_ASCII))
                aggregate.update(0)
            }
        } finally {
            metrics.hashingNanos.addAndGet(System.nanoTime() - started)
        }
        return if (complete) HashOutcome(hex(aggregate.digest()), true) else HashOutcome(null, false)
    }

    private fun findEmbeddedThreatIps(
        apks: List<File>,
        index: ThreatIndex,
        budget: ScanBudget,
        cancelled: () -> Boolean,
        metrics: MetricsAccumulator,
    ): ThreatScan {
        val started = System.nanoTime()
        val indicators = LinkedHashSet<String>()
        var perPackageBytes = 0L
        var coverageAvailable = false
        var complete = true
        try {
            outer@ for (apk in apks) {
                ZipFile(apk).use { zip ->
                    val enumeration = zip.entries()
                    var scannedEntries = 0
                    var enumeratedEntries = 0
                    while (enumeration.hasMoreElements()) {
                        cancelledCheck(cancelled)
                        if (enumeratedEntries >= MAX_ENUMERATED_ZIP_ENTRIES || scannedEntries >= MAX_ZIP_ENTRIES ||
                            perPackageBytes >= MAX_DECOMPRESSED_SCAN_BYTES || indicators.size >= MAX_CACHED_INDICATORS_PER_PACKAGE
                        ) {
                            complete = false
                            break
                        }
                        val entry = enumeration.nextElement()
                        enumeratedEntries++
                        if (entry.isDirectory || !shouldScanEntry(entry.name)) continue
                        scannedEntries++
                        if (entry.size > MAX_ENTRY_BYTES || entry.size < 0L) { complete = false; continue }
                        val remainingPackage = MAX_DECOMPRESSED_SCAN_BYTES - perPackageBytes
                        if (remainingPackage <= 0L || !budget.hasStaticBudget()) { complete = false; break }
                        zip.getInputStream(entry).use { input ->
                            val maxForEntry = minOf(entry.size, remainingPackage, MAX_ENTRY_BYTES)
                            val scan = ThreatTokenScanner.extractPublicIndicators(
                                input = input,
                                maxBytes = maxForEntry,
                                maxIndicators = MAX_CACHED_INDICATORS_PER_PACKAGE - indicators.size,
                                cancelled = cancelled,
                                allowance = { requested -> budget.claimStatic(requested) },
                                consumed = { bytes ->
                                    perPackageBytes += bytes.toLong()
                                    metrics.bytesStaticScanned.addAndGet(bytes.toLong())
                                },
                            )
                            if (scan.bytesRead > 0L || entry.size == 0L) coverageAvailable = true
                            val entryComplete = scan.complete || (maxForEntry == entry.size && scan.bytesRead == entry.size)
                            complete = complete && entryComplete
                            indicators += scan.indicators
                        }
                    }
                }
                if (!complete && (perPackageBytes >= MAX_DECOMPRESSED_SCAN_BYTES || indicators.size >= MAX_CACHED_INDICATORS_PER_PACKAGE || !budget.hasStaticBudget())) break@outer
            }
        } catch (e: InterruptedException) {
            throw e
        } catch (_: Exception) {
            complete = false
        } finally {
            metrics.staticAnalysisNanos.addAndGet(System.nanoTime() - started)
        }
        val correlationStarted = System.nanoTime()
        val matches = ThreatTokenScanner.correlate(indicators, index, MAX_THREAT_MATCHES)
        metrics.correlationNanos.addAndGet(System.nanoTime() - correlationStarted)
        if (complete) coverageAvailable = true
        return ThreatScan(indicators.toList(), matches, complete, coverageAvailable)
    }

    private fun packageFingerprint(pkg: PackageInfo, apks: List<File>): String {
        val digest = MessageDigest.getInstance("SHA-256")
        updateFingerprint(digest, pkg.packageName)
        updateFingerprint(digest, pkg.longVersionCode.toString())
        updateFingerprint(digest, pkg.firstInstallTime.toString())
        updateFingerprint(digest, pkg.lastUpdateTime.toString())
        for (apk in apks) {
            updateFingerprint(digest, apk.absolutePath)
            updateFingerprint(digest, apk.length().coerceAtLeast(0L).toString())
            updateFingerprint(digest, apk.lastModified().coerceAtLeast(0L).toString())
        }
        return hex(digest.digest())
    }

    private fun updateFingerprint(digest: MessageDigest, value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        digest.update((bytes.size ushr 24).toByte())
        digest.update((bytes.size ushr 16).toByte())
        digest.update((bytes.size ushr 8).toByte())
        digest.update(bytes.size.toByte())
        digest.update(bytes)
    }

    private fun inspectable(apks: List<File>): Boolean {
        val combinedBytes = combinedLength(apks)
        return apks.isNotEmpty() && apks.size <= MAX_APK_PARTS && apks.all { it.isFile && it.canRead() } && combinedBytes in 1..MAX_APK_BYTES
    }

    private fun packageApks(app: ApplicationInfo): List<File> = buildList {
        app.sourceDir?.let { add(File(it)) }
        app.splitSourceDirs?.forEach { add(File(it)) }
    }.distinctBy { it.absolutePath }.sortedBy { it.absolutePath }

    private fun combinedLength(files: List<File>): Long {
        var total = 0L
        for (file in files) {
            val length = file.length().coerceAtLeast(0L)
            if (Long.MAX_VALUE - total < length) return Long.MAX_VALUE
            total += length
        }
        return total
    }

    private fun installedPackagesLight(): List<PackageInfo> = if (Build.VERSION.SDK_INT >= 33) {
        pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0L))
    } else {
        @Suppress("DEPRECATION")
        pm.getInstalledPackages(0)
    }

    private fun detailedPackageInfo(packageName: String): PackageInfo? {
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS
        return try {
            if (Build.VERSION.SDK_INT >= 33) pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
            else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, flags)
            }
        } catch (_: PackageManager.NameNotFoundException) {
            null
        } catch (_: RuntimeException) {
            null
        }
    }

    private fun installSource(packageName: String): String? = try {
        if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(packageName).installingPackageName
        else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(packageName)
        }
    } catch (_: RuntimeException) { null }

    private fun signerDigest(pkg: PackageInfo): String? {
        val signers = pkg.signingInfo?.apkContentsSigners ?: return null
        if (signers.isEmpty()) return null
        val digests = signers.map { signature -> hex(MessageDigest.getInstance("SHA-256").digest(signature.toByteArray())) }.sorted()
        val aggregate = MessageDigest.getInstance("SHA-256")
        digests.forEach { aggregate.update(it.toByteArray(Charsets.US_ASCII)); aggregate.update(0) }
        return hex(aggregate.digest())
    }

    private fun applicationLabel(app: ApplicationInfo, fallback: String): String = try {
        pm.getApplicationLabel(app).toString().take(120)
    } catch (_: RuntimeException) {
        fallback.take(120)
    }

    private fun shouldScanEntry(name: String): Boolean {
        val lower = name.lowercase()
        if (lower.startsWith("classes") && lower.endsWith(".dex")) return true
        if (lower.startsWith("lib/") && lower.endsWith(".so")) return true
        return lower.startsWith("assets/") && (lower.endsWith(".json") || lower.endsWith(".txt") || lower.endsWith(".conf"))
    }

    private fun sha256(file: File, cancelled: () -> Boolean): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(128 * 1024)
        FileInputStream(file).use { input ->
            while (true) {
                cancelledCheck(cancelled)
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return hex(digest.digest())
    }

    private fun workerCount(packageCount: Int): Int {
        if (packageCount <= 1) return 1
        val cores = Runtime.getRuntime().availableProcessors().coerceAtLeast(1)
        return minOf(MAX_APP_WORKERS, maxOf(MIN_APP_WORKERS, cores / 2), packageCount)
    }

    private fun cancelledCheck(cancelled: () -> Boolean) {
        if (Thread.currentThread().isInterrupted || cancelled()) throw InterruptedException("app scan interrupted")
    }

    private fun hex(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        var cursor = 0
        for (byte in bytes) {
            val value = byte.toInt() and 0xff
            out[cursor++] = HEX[value ushr 4]
            out[cursor++] = HEX[value and 0x0f]
        }
        return String(out)
    }

    private fun nanosToMillis(value: Long): Long = TimeUnit.NANOSECONDS.toMillis(value.coerceAtLeast(0L))

    private data class ScanOutcome(
        val result: AppRiskResult?,
        val deepInspected: Boolean,
        val budgetLimited: Boolean,
        val cacheRecord: AppPackageCacheRecord?,
    )
    private data class ThreatScan(
        val indicators: List<String>,
        val matches: List<String>,
        val complete: Boolean,
        val coverageAvailable: Boolean,
    )
    private data class HashOutcome(val hash: String?, val complete: Boolean)
    private data class RiskAssessment(
        val rawScore: Int,
        val score: Int,
        val level: AppRiskLevel,
        val confidence: AppRiskConfidence,
    )

    private class ScanBudget(
        private val metrics: MetricsAccumulator,
        hashBytes: Long = MAX_TOTAL_HASH_BYTES,
        staticBytes: Long = MAX_TOTAL_STATIC_SCAN_BYTES,
    ) {
        private val hashRemaining = AtomicLong(hashBytes.coerceIn(0L, MAX_TOTAL_HASH_BYTES))
        private val staticRemaining = AtomicLong(staticBytes.coerceIn(0L, MAX_TOTAL_STATIC_SCAN_BYTES))

        fun reserveHash(bytes: Long): Boolean {
            if (bytes <= 0L) return false
            while (true) {
                val current = hashRemaining.get()
                if (bytes > current) return false
                if (hashRemaining.compareAndSet(current, current - bytes)) return true
            }
        }

        fun hasStaticBudget(): Boolean = staticRemaining.get() > 0L

        fun claimStatic(requested: Int): Int {
            if (requested <= 0) return 0
            while (true) {
                val current = staticRemaining.get()
                if (current <= 0L) return 0
                val allowed = minOf(requested.toLong(), current).toInt()
                if (staticRemaining.compareAndSet(current, current - allowed)) return allowed
            }
        }
    }

    private class MetricsAccumulator {
        val packageQueryNanos = AtomicLong(0L)
        val metadataNanos = AtomicLong(0L)
        val staticAnalysisNanos = AtomicLong(0L)
        val hashingNanos = AtomicLong(0L)
        val correlationNanos = AtomicLong(0L)
        val cacheHits = AtomicInteger(0)
        val cacheMisses = AtomicInteger(0)
        val bytesStaticScanned = AtomicLong(0L)
        val bytesHashed = AtomicLong(0L)

        fun snapshot(elapsedMs: Long) = AppScanMetrics(
            elapsedMs = elapsedMs,
            packageQueryMs = TimeUnit.NANOSECONDS.toMillis(packageQueryNanos.get()),
            metadataMs = TimeUnit.NANOSECONDS.toMillis(metadataNanos.get()),
            staticAnalysisMs = TimeUnit.NANOSECONDS.toMillis(staticAnalysisNanos.get()),
            hashingMs = TimeUnit.NANOSECONDS.toMillis(hashingNanos.get()),
            correlationMs = TimeUnit.NANOSECONDS.toMillis(correlationNanos.get()),
            cacheHits = cacheHits.get(),
            cacheMisses = cacheMisses.get(),
            bytesStaticScanned = bytesStaticScanned.get(),
            bytesHashed = bytesHashed.get(),
        )
    }

    private class ProgressGate(
        private val callback: (processed: Int, total: Int, label: String) -> Unit,
    ) {
        private val lastNanos = AtomicLong(0L)
        fun emit(processed: Int, total: Int, label: String) {
            val now = System.nanoTime()
            while (true) {
                val previous = lastNanos.get()
                val due = processed >= total || previous == 0L || now - previous >= PROGRESS_INTERVAL_NANOS
                if (!due) return
                if (lastNanos.compareAndSet(previous, now)) {
                    callback(processed, total, label.take(120))
                    return
                }
            }
        }
    }

    companion object {
        private const val MAX_PACKAGES = 768
        private const val MAX_RESULTS = 64
        private const val MAX_FINDINGS = 12
        private const val MAX_THREAT_MATCHES = 32
        private const val MAX_APK_BYTES = 512L * 1024L * 1024L
        private const val MAX_APK_PARTS = 32
        private const val MAX_TOTAL_HASH_BYTES = 1024L * 1024L * 1024L
        private const val MAX_TOTAL_STATIC_SCAN_BYTES = 512L * 1024L * 1024L
        private const val MAX_ZIP_ENTRIES = 256
        private const val MAX_ENUMERATED_ZIP_ENTRIES = 32_768
        private const val MAX_ENTRY_BYTES = 64L * 1024L * 1024L
        private const val MAX_DECOMPRESSED_SCAN_BYTES = 48L * 1024L * 1024L
        private const val MAX_CACHED_INDICATORS_PER_PACKAGE = 1024
        private const val MAX_PACKAGE_CACHE_AGE_MS = 7L * 24L * 60L * 60L * 1000L
        private const val INSTALL_SCAN_HASH_BYTES = 192L * 1024L * 1024L
        private const val INSTALL_SCAN_STATIC_BYTES = 96L * 1024L * 1024L
        private const val RESTORE_TIMEOUT_MS = 8_000L
        private const val HEURISTIC_ONLY_SCORE_CAP = 34
        const val USER_VISIBLE_REVIEW_THRESHOLD = 35
        private const val APPROVED_CAPABILITY_SCORE_CAP = 12
        private const val MIN_APP_WORKERS = 2
        private const val MAX_APP_WORKERS = 4
        private val PROGRESS_INTERVAL_NANOS = TimeUnit.MILLISECONDS.toNanos(80)
        private val SMS_PERMISSIONS = setOf(Manifest.permission.READ_SMS, Manifest.permission.RECEIVE_SMS, Manifest.permission.SEND_SMS)
        private val CALL_LOG_PERMISSIONS = setOf(Manifest.permission.READ_CALL_LOG, Manifest.permission.WRITE_CALL_LOG)
        private val SENSITIVE_PERMISSIONS = listOf(Manifest.permission.RECORD_AUDIO, Manifest.permission.CAMERA, Manifest.permission.ACCESS_FINE_LOCATION)
        private val CAPABILITY_FINDING_CODES = setOf(
            "package_install_capability_network",
            "boot_persistent_installer",
            "overlay_active_network",
            "overlay_declared_network",
            "sms_granted_network",
            "sms_declared_network",
            "calllog_granted_network",
            "calllog_declared_network",
            "accessibility_active_network",
            "accessibility_capability_network",
            "device_admin_active",
            "device_admin_capability",
            "persistent_granted_sensor_bundle",
            "persistent_declared_sensor_bundle",
        )
        private val HEX = "0123456789abcdef".toCharArray()
        private val PACKAGE_NAME_PATTERN = Regex("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+")
    }
}
