package de.visiongaia.gedefense.mobile

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import java.util.concurrent.ConcurrentHashMap

enum class InstallGuardStage { FAST_VERDICT, DEEP_SCAN }

data class InstallGuardActiveState(
    val packageName: String,
    val stage: InstallGuardStage,
    val elapsedMs: Long,
)

// STATUS: PLATIN
/**
 * Local-first install/update protection.
 *
 * Every newly installed or updated user application receives a bounded priority scan. On fully
 * managed Device Owner devices, an explicitly enabled TITAN auto-suspend policy provides a real
 * package hold while the scan is running. Ordinary Android applications do not have a public API
 * that can guarantee package-specific pre-first-packet network denial, so Standard/TITAN Light
 * mode never claims such containment. No cloud verdict or external API is required.
 */
class InstallGuard(
    context: Context,
    private val scanner: AppRiskScanner,
    private val xdr: XdrEngine,
) {
    private val appContext = context.applicationContext
    private val pm = appContext.packageManager
    private val active = ConcurrentHashMap<String, ActiveScan>()

    fun handlePackageEvent(packageName: String, action: String, replacing: Boolean, index: ThreatIndex) {
        if (!PACKAGE_PATTERN.matches(packageName) || packageName == appContext.packageName) return
        xdr.handlePackageEvent(packageName, action, replacing)
        if (action.endsWith("PACKAGE_REMOVED")) {
            if (!replacing) xdr.setQuarantined(packageName, false)
            active.remove(packageName)
            return
        }
        if (!action.endsWith("PACKAGE_ADDED") && !action.endsWith("PACKAGE_REPLACED")) return
        // Android emits PACKAGE_ADDED with EXTRA_REPLACING during an update and follows it with
        // PACKAGE_REPLACED. Scan the latter only so one update cannot trigger two sequential holds.
        if (action.endsWith("PACKAGE_ADDED") && replacing) return

        val userPackage = shouldContainDuringScan(packageName)
        if (active.size >= MAX_ACTIVE_PACKAGES && !active.containsKey(packageName)) {
            val held = userPackage && xdr.setQuarantined(packageName, true)
            val suspended = held && resultPackageSuspended(packageName)
            val networkHeld = held && NativeGaiaNet.packageEgressGateActive()
            xdr.ingestInstallGuard(
                packageName = packageName,
                verdict = "INCOMPLETE",
                riskScore = 0,
                reasonCodes = listOf("install_guard_capacity") + containmentReason(userPackage, suspended, networkHeld),
                suspended = suspended,
                networkQuarantined = networkHeld,
                elapsedMs = 0L,
            )
            return
        }
        if (active.putIfAbsent(packageName, ActiveScan(System.currentTimeMillis(), InstallGuardStage.FAST_VERDICT)) != null) return

        var holdStaged = false
        try {
            if (userPackage) holdStaged = xdr.setQuarantined(packageName, true)
            var suspendedDuringScan = holdStaged && resultPackageSuspended(packageName)
            var networkQuarantinedDuringScan = holdStaged && NativeGaiaNet.packageEgressGateActive()

            val fast = try {
                BoundedInstallScanCall.fast { scanner.fastScanPackage(packageName, index) }
            } catch (error: InstallScanUnavailableException) {
                xdr.ingestInstallGuard(
                    packageName = packageName,
                    verdict = "INCOMPLETE",
                    riskScore = 0,
                    reasonCodes = listOf(error.reasonCode, "fast_verdict_unavailable") +
                        containmentReason(userPackage, suspendedDuringScan, networkQuarantinedDuringScan),
                    suspended = suspendedDuringScan,
                    networkQuarantined = networkQuarantinedDuringScan,
                    elapsedMs = elapsedSinceStart(packageName),
                )
                return
            }
            val fastDecision = fastVerdictFor(fast)
            if (fastDecision == InstallFastVerdict.RELEASE_PENDING_DEEP && holdStaged) {
                // Release low-risk metadata-only installs quickly, but do not call them clean yet.
                // The same background worker immediately continues into bounded deep inspection.
                val released = xdr.setQuarantined(packageName, false)
                if (released) {
                    holdStaged = false
                    suspendedDuringScan = false
                    networkQuarantinedDuringScan = false
                    xdr.ingestInstallGuard(
                        packageName = packageName,
                        verdict = "FAST_PASS_DEEP_PENDING",
                        riskScore = fast.result?.riskScore ?: 0,
                        reasonCodes = listOf(
                            if (fast.deepEvidenceReusable) "authenticated_deep_evidence_reused" else "metadata_fast_pass",
                            "deep_scan_pending",
                        ),
                        suspended = false,
                        networkQuarantined = false,
                        elapsedMs = fast.elapsedMs,
                    )
                } else {
                    xdr.ingestInstallGuard(
                        packageName = packageName,
                        verdict = "INCOMPLETE",
                        riskScore = fast.result?.riskScore ?: 0,
                        reasonCodes = listOf("fast_release_failed", "deep_scan_required"),
                        suspended = suspendedDuringScan,
                        networkQuarantined = networkQuarantinedDuringScan,
                        elapsedMs = fast.elapsedMs,
                    )
                }
            }

            active.computeIfPresent(packageName) { _, current -> current.copy(stage = InstallGuardStage.DEEP_SCAN) }
            val scan = try {
                BoundedInstallScanCall.deep {
                    scanner.scanPackage(packageName, index) { Thread.currentThread().isInterrupted }
                }
            } catch (error: InstallScanUnavailableException) {
                // A previously known/signer-continuous update may have been released after the
                // fast verdict. If deep inspection itself becomes unavailable, reinstate the hold
                // before publishing INCOMPLETE so an unverified update cannot remain open-ended.
                if (!holdStaged && userPackage) holdStaged = xdr.setQuarantined(packageName, true)
                val suspendedAfterFailure = holdStaged && resultPackageSuspended(packageName)
                val networkHeldAfterFailure = holdStaged && NativeGaiaNet.packageEgressGateActive()
                xdr.ingestInstallGuard(
                    packageName = packageName,
                    verdict = "INCOMPLETE",
                    riskScore = fast.result?.riskScore ?: 0,
                    reasonCodes = listOf(error.reasonCode, "deep_scan_required") +
                        containmentReason(userPackage, suspendedAfterFailure, networkHeldAfterFailure),
                    suspended = suspendedAfterFailure,
                    networkQuarantined = networkHeldAfterFailure,
                    elapsedMs = elapsedSinceStart(packageName),
                )
                return
            } catch (_: RuntimeException) {
                if (!holdStaged && userPackage) holdStaged = xdr.setQuarantined(packageName, true)
                val suspendedAfterFailure = holdStaged && resultPackageSuspended(packageName)
                val networkHeldAfterFailure = holdStaged && NativeGaiaNet.packageEgressGateActive()
                xdr.ingestInstallGuard(
                    packageName = packageName,
                    verdict = "INCOMPLETE",
                    riskScore = fast.result?.riskScore ?: 0,
                    reasonCodes = listOf("install_scan_runtime_failure", "deep_scan_required") +
                        containmentReason(userPackage, suspendedAfterFailure, networkHeldAfterFailure),
                    suspended = suspendedAfterFailure,
                    networkQuarantined = networkHeldAfterFailure,
                    elapsedMs = elapsedSinceStart(packageName),
                )
                return
            }
            val result = scan.result
            val verdict = verdictFor(result, scan)
            val reasons = buildList {
                if (result == null) add("scan_result_unavailable")
                result?.findings?.asSequence()?.sortedByDescending { it.weight }?.take(8)?.forEach { add(it.code) }
                if (result?.threatMatches?.any { it.endsWith(":BLOCK") } == true) add("threat_block_match")
                if (result?.threatMatches?.any { it.endsWith(":CORRELATE") } == true) add("threat_correlate_match")
                if (scan.budgetLimited) add("scan_budget_limited")
                if (result != null && !scan.deepInspected && result.analysisMode == "DEEP") add("deep_scan_incomplete")
                addAll(containmentReason(userPackage, suspendedDuringScan, networkQuarantinedDuringScan))
            }.distinct().take(12)

            if (verdict == InstallGuardVerdict.PASS && holdStaged) {
                xdr.setQuarantined(packageName, false)
                holdStaged = false
            } else if (verdict != InstallGuardVerdict.PASS && userPackage && !holdStaged) {
                // A low-risk app may have been released after the fast verdict. Any later deep-scan
                // concern immediately reinstates authenticated containment before publishing XDR.
                holdStaged = xdr.setQuarantined(packageName, true)
            }
            val suspendedAfterVerdict = verdict != InstallGuardVerdict.PASS && holdStaged && resultPackageSuspended(packageName)
            val networkQuarantinedAfterVerdict = verdict != InstallGuardVerdict.PASS && holdStaged && NativeGaiaNet.packageEgressGateActive()
            xdr.ingestInstallGuard(
                packageName = packageName,
                verdict = verdict.name,
                riskScore = result?.riskScore ?: 0,
                reasonCodes = reasons,
                suspended = suspendedAfterVerdict,
                networkQuarantined = networkQuarantinedAfterVerdict,
                elapsedMs = scan.elapsedMs,
            )
        } finally {
            active.remove(packageName)
        }
    }

    fun activePackages(): Set<String> = active.keys.asSequence().take(MAX_ACTIVE_PACKAGES).toSet()

    fun activeStates(): List<InstallGuardActiveState> {
        val now = System.currentTimeMillis()
        return active.entries.asSequence()
            .map { (packageName, state) ->
                InstallGuardActiveState(
                    packageName = packageName,
                    stage = state.stage,
                    elapsedMs = (now - state.startedAtMillis).coerceAtLeast(0L),
                )
            }
            .sortedBy { it.packageName }
            .take(MAX_ACTIVE_PACKAGES)
            .toList()
    }

    private fun fastVerdictFor(scan: AppFastScanResult): InstallFastVerdict {
        val result = scan.result
        val risk = when (result?.riskLevel) {
            AppRiskLevel.SEVERE -> InstallFastRisk.SEVERE
            AppRiskLevel.HIGH -> InstallFastRisk.HIGH
            AppRiskLevel.REVIEW -> InstallFastRisk.REVIEW
            else -> InstallFastRisk.LOW
        }
        return InstallGuardPolicy.fastVerdict(
            InstallFastPolicyInput(
                resultAvailable = result != null,
                blockThreat = result?.threatMatches?.any { it.endsWith(":BLOCK") } == true,
                correlateThreat = result?.threatMatches?.any { it.endsWith(":CORRELATE") } == true,
                signerAvailable = result?.signerSha256 != null,
                signerContinuity = scan.signerContinuity,
                approvalStale = result?.approvalState == AppApprovalState.STALE,
                risk = risk,
            ),
        )
    }

    private fun verdictFor(result: AppRiskResult?, scan: AppPackageScanResult): InstallGuardVerdict {
        if (result == null) return InstallGuardVerdict.INCOMPLETE
        if (result.threatMatches.any { it.endsWith(":BLOCK") } || result.riskLevel == AppRiskLevel.SEVERE) {
            return InstallGuardVerdict.BLOCK
        }
        if (scan.budgetLimited || (result.analysisMode == "DEEP" && !scan.deepInspected)) return InstallGuardVerdict.INCOMPLETE
        if (result.threatMatches.any { it.endsWith(":CORRELATE") } || result.riskLevel == AppRiskLevel.HIGH || result.approvalState == AppApprovalState.STALE) {
            return InstallGuardVerdict.REVIEW
        }
        return InstallGuardVerdict.PASS
    }

    private fun shouldContainDuringScan(packageName: String): Boolean {
        val app = try {
            if (android.os.Build.VERSION.SDK_INT >= 33) {
                pm.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                pm.getApplicationInfo(packageName, 0)
            }
        } catch (_: PackageManager.NameNotFoundException) {
            return false
        } catch (_: RuntimeException) {
            return false
        }
        // Never auto-hold platform/system packages during an OTA or OEM component update. They are
        // still scanned and surfaced to XDR, but automatic suspension could destabilize boot.
        return app.flags and ApplicationInfo.FLAG_SYSTEM == 0
    }

    private fun containmentReason(
        userPackage: Boolean,
        actuallySuspended: Boolean,
        networkQuarantined: Boolean,
    ): List<String> = when {
        !userPackage -> emptyList()
        actuallySuspended && networkQuarantined -> listOf("device_owner_scan_hold", "full_flow_package_egress_gate")
        actuallySuspended -> listOf("device_owner_scan_hold")
        networkQuarantined -> listOf("full_flow_package_egress_gate")
        else -> listOf("package_specific_pre_egress_hold_unavailable")
    }

    private fun elapsedSinceStart(packageName: String): Long {
        val started = active[packageName]?.startedAtMillis ?: return 0L
        return (System.currentTimeMillis() - started).coerceAtLeast(0L)
    }

    private fun resultPackageSuspended(packageName: String): Boolean = try {
        AppRuntime.peek()?.titan?.isPackageSuspended(packageName) == true
    } catch (_: RuntimeException) {
        false
    }

    private data class ActiveScan(val startedAtMillis: Long, val stage: InstallGuardStage)

    private enum class InstallGuardVerdict { PASS, REVIEW, BLOCK, INCOMPLETE }

    companion object {
        private const val MAX_ACTIVE_PACKAGES = 32
        private val PACKAGE_PATTERN = Regex("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+")
    }
}
