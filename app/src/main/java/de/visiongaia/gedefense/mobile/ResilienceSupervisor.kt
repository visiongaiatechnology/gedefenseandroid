package de.visiongaia.gedefense.mobile

import android.os.Looper
import android.os.SystemClock
import de.visiongaia.gedefense.mobile.core.EvidenceEvent
import de.visiongaia.gedefense.mobile.core.PrivacyProfile
import de.visiongaia.gedefense.mobile.core.RecoveryAttemptBudget
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

// STATUS: PLATIN
/**
 * Bounded, local-only self-healing coordinator.
 *
 * Only trust-preserving, idempotent repairs are automatic. The supervisor may re-read signed APK
 * assets, re-verify authenticated stores, rebuild derived runtime state and re-assert enforcement.
 * It never clears an authenticated security store, deletes Evidence/XDR history, advances a
 * same-version integrity baseline after a mismatch, disables a kill switch, or downloads repair
 * material. Persistent trust failures remain explicit and fail closed where they protect egress.
 */
class ResilienceSupervisor(private val runtime: AppRuntime) {
    enum class Disposition {
        REPAIRED,
        RETRY_LATER,
        SCAN_REQUIRED,
        SYNC_REQUIRED,
        FAIL_CLOSED,
        OPERATOR_REQUIRED,
    }

    data class Finding(
        val component: String,
        val state: String,
        val action: String,
        val disposition: Disposition,
        val repaired: Boolean,
        val detail: String = "",
    )

    data class Report(
        val atMillis: Long,
        val trigger: String,
        val healthy: Boolean,
        val repairs: Int,
        val unresolved: Int,
        val findings: List<Finding>,
        val skipped: Boolean = false,
    )

    private class RepairCounter(var value: Int = 0)

    private val running = AtomicBoolean(false)
    private val lastReport = AtomicReference<Report?>(null)
    private val repairBudget = RecoveryAttemptBudget(
        maxAttemptsPerWindow = MAX_REPAIR_ATTEMPTS_PER_WINDOW,
        windowMillis = REPAIR_WINDOW_MS,
        cooldownMillis = REPAIR_COOLDOWN_MS,
        maxKeys = MAX_REPAIR_KEYS,
    )

    fun latestReport(): Report? = lastReport.get()
    fun snapshot(): Report? = latestReport()

    fun runOnce(trigger: String = "scheduled"): Report {
        check(Looper.myLooper() != Looper.getMainLooper()) {
            "ResilienceSupervisor is forbidden on the Android main thread"
        }
        val safeTrigger = sanitizeCode(trigger, "scheduled")
        if (!running.compareAndSet(false, true)) {
            return lastReport.get() ?: Report(
                atMillis = System.currentTimeMillis(),
                trigger = safeTrigger,
                healthy = false,
                repairs = 0,
                unresolved = 1,
                findings = listOf(
                    Finding("supervisor", "BUSY", "RETRY_LATER", Disposition.RETRY_LATER, false, "run_in_progress"),
                ),
                skipped = true,
            )
        }
        return try {
            runInternal(safeTrigger).also(lastReport::set)
        } finally {
            running.set(false)
        }
    }

    private fun runInternal(trigger: String): Report {
        val findings = ArrayList<Finding>(MAX_FINDINGS)
        val repairs = RepairCounter()
        val monotonicNow = SystemClock.elapsedRealtime()

        inspectPrivacyIntelligence(monotonicNow, findings, repairs)
        inspectEvidence(findings, repairs)

        val trustStoresReady = runtime.awaitXdrTrustBootstrap(TRUST_BOOTSTRAP_WAIT_MS)
        if (trustStoresReady) {
            inspectFirewallPolicy(monotonicNow, findings, repairs)
            inspectXdrTrustStores(monotonicNow, findings, repairs)
            inspectInstallGuardGate(monotonicNow, findings, repairs)
            reconcileTitanQuarantine(findings, repairs)
        } else {
            findings += Finding(
                "secondary-trust-stores",
                "INITIALIZING",
                "RETRY_LATER",
                Disposition.RETRY_LATER,
                false,
                "trust_bootstrap_pending",
            )
        }

        if (runtime.awaitBehaviorBootstrap(SECONDARY_BOOTSTRAP_WAIT_MS)) {
            inspectBehaviorStore(monotonicNow, findings, repairs)
        } else {
            findings += Finding("behavior-baseline", "INITIALIZING", "RETRY_LATER", Disposition.RETRY_LATER, false, "behavior_bootstrap_pending")
        }

        inspectThreatIntelligence(monotonicNow, findings, repairs)
        inspectGaiaNet(monotonicNow, findings, repairs)
        inspectSelfIntegrity(monotonicNow, findings, repairs)

        if (runtime.awaitMalwareAnalysisBootstrap(SECONDARY_BOOTSTRAP_WAIT_MS)) {
            inspectMalwareAnalysisCache(findings)
        } else {
            findings += Finding("malware-analysis-cache", "INITIALIZING", "RETRY_LATER", Disposition.RETRY_LATER, false, "malware_bootstrap_pending")
        }

        val bounded = findings.take(MAX_FINDINGS)
        val unresolved = bounded.count { !it.repaired }
        val report = Report(
            atMillis = System.currentTimeMillis(),
            trigger = trigger,
            healthy = unresolved == 0,
            repairs = repairs.value,
            unresolved = unresolved,
            findings = bounded,
        )
        appendEvidence(report)
        emitXdr(report)
        runtime.notifyStateChanged()
        return report
    }

    private fun inspectPrivacyIntelligence(now: Long, findings: MutableList<Finding>, repairs: RepairCounter) {
        val registry = runtime.privacyIntelligence.registry()
        if (registry.count > 0 && runtime.privacyIntelligence.healthy()) return
        val critical = runtime.state.privacyProfile() != PrivacyProfile.OFF
        attemptRepair(
            key = "privacy-intelligence",
            component = "privacy-intelligence",
            action = "RELOAD_SIGNED_SNAPSHOT",
            failureAction = if (critical) "FAIL_CLOSED" else "RETRY_LATER",
            failureDisposition = if (critical) Disposition.FAIL_CLOSED else Disposition.RETRY_LATER,
            now = now,
            findings = findings,
            repairs = repairs,
        ) {
            runtime.privacyIntelligence.reloadSignedSnapshot() &&
                runtime.privacyIntelligence.registry().count > 0 &&
                runtime.privacyIntelligence.healthy()
        }
    }

    private fun inspectEvidence(findings: MutableList<Finding>, repairs: RepairCounter) {
        val wasHealthy = runtime.evidenceHealth.ok
        val health = try {
            BoundedRecoveryCall.call(EVIDENCE_VERIFY_TIMEOUT_MS) { runtime.refreshEvidenceHealth() }
        } catch (error: RecoveryCallUnavailableException) {
            findings += Finding("evidence", "VERIFY_UNAVAILABLE", "RETRY_LATER", Disposition.RETRY_LATER, false, error.reasonCode)
            return
        } catch (_: RuntimeException) {
            findings += Finding("evidence", "VERIFY_FAILED", "OPERATOR_REQUIRED", Disposition.OPERATOR_REQUIRED, false, "evidence_verify_failed")
            return
        }
        if (!health.ok) {
            findings += Finding(
                "evidence",
                "INTEGRITY_FAILURE",
                "OPERATOR_REQUIRED",
                Disposition.OPERATOR_REQUIRED,
                false,
                health.reason?.take(MAX_DETAIL_CHARS) ?: "evidence_integrity_unhealthy",
            )
        } else if (!wasHealthy && repairs.value < MAX_REPAIRS_PER_RUN) {
            repairs.value++
            findings += Finding("evidence", "RECOVERED", "REVERIFY", Disposition.REPAIRED, true, "verification_recovered")
        }
    }

    private fun inspectFirewallPolicy(now: Long, findings: MutableList<Finding>, repairs: RepairCounter) {
        if (!runtime.firewallPolicy.integrityOk()) {
            val healed = attemptRepair(
                key = "firewall-policy",
                component = "firewall-policy",
                action = "RELOAD_AUTHENTICATED_STATE",
                failureAction = "OPERATOR_REQUIRED",
                failureDisposition = Disposition.OPERATOR_REQUIRED,
                now = now,
                findings = findings,
                repairs = repairs,
            ) {
                runtime.firewallPolicy.initialize()
                runtime.firewallPolicy.integrityOk()
            }
            if (!healed) return
        }

        val decision = repairBudget.tryAcquire("firewall-prune", now)
        if (!decision.allowed) return
        try {
            val removed = BoundedRecoveryCall.call(REPAIR_TIMEOUT_MS) { runtime.firewallPolicy.pruneMissingPackages() }
            repairBudget.clear("firewall-prune")
            if (removed > 0 && repairs.value < MAX_REPAIRS_PER_RUN) {
                repairs.value++
                findings += Finding(
                    "firewall-policy",
                    "STALE_ENTRIES",
                    "PRUNE_MISSING_PACKAGES",
                    Disposition.REPAIRED,
                    true,
                    "removed=${removed.coerceAtMost(9999)}",
                )
            }
        } catch (error: RecoveryCallUnavailableException) {
            findings += Finding("firewall-policy", "RECONCILE_DEFERRED", "RETRY_LATER", Disposition.RETRY_LATER, false, error.reasonCode)
        } catch (_: RuntimeException) {
            findings += Finding("firewall-policy", "RECONCILE_FAILED", "RETRY_LATER", Disposition.RETRY_LATER, false, "firewall_reconcile_failed")
        }
    }

    private fun inspectXdrTrustStores(now: Long, findings: MutableList<Finding>, repairs: RepairCounter) {
        var snapshot = safeXdrSnapshot(findings) ?: return
        if (!snapshot.eventStoreIntegrityOk || !snapshot.packageBaselineIntegrityOk) {
            attemptRepair(
                key = "xdr-persistence",
                component = "xdr-persistence",
                action = "RELOAD_AUTHENTICATED_STATE",
                failureAction = "OPERATOR_REQUIRED",
                failureDisposition = Disposition.OPERATOR_REQUIRED,
                now = now,
                findings = findings,
                repairs = repairs,
            ) {
                runtime.xdr.initializePersistentState()
                val refreshed = runtime.xdr.snapshot()
                refreshed.eventStoreIntegrityOk && refreshed.packageBaselineIntegrityOk
            }
            snapshot = safeXdrSnapshot(findings) ?: return
        }
        if (!snapshot.eventStoreIntegrityOk) {
            findings += Finding("xdr-events", "INTEGRITY_FAILURE", "OPERATOR_REQUIRED", Disposition.OPERATOR_REQUIRED, false, "xdr_event_store_unhealthy")
        }
        if (!snapshot.packageBaselineIntegrityOk) {
            findings += Finding("package-baseline", "INTEGRITY_FAILURE", "OPERATOR_REQUIRED", Disposition.OPERATOR_REQUIRED, false, "package_baseline_unhealthy")
        } else {
            val decision = repairBudget.tryAcquire("package-baseline-reconcile", now)
            if (decision.allowed) {
                try {
                    BoundedRecoveryCall.call(RECONCILE_TIMEOUT_MS) { runtime.xdr.reconcilePackages() }
                    repairBudget.clear("package-baseline-reconcile")
                } catch (error: RecoveryCallUnavailableException) {
                    findings += Finding("package-baseline", "RECONCILE_DEFERRED", "RETRY_LATER", Disposition.RETRY_LATER, false, error.reasonCode)
                } catch (_: RuntimeException) {
                    findings += Finding("package-baseline", "RECONCILE_FAILED", "RETRY_LATER", Disposition.RETRY_LATER, false, "package_reconcile_failed")
                }
            }
        }

        repairAuthenticatedStore(
            key = "network-discovery",
            component = "network-discovery",
            healthy = runtime.networkDiscoveryStore.integrityOk(),
            now = now,
            findings = findings,
            repairs = repairs,
        ) {
            runtime.networkDiscoveryStore.initialize()
            runtime.networkDiscoveryStore.integrityOk()
        }
        repairAuthenticatedStore(
            key = "port-sentinel",
            component = "port-sentinel",
            healthy = runtime.portSentinelStore.integrityOk(),
            now = now,
            findings = findings,
            repairs = repairs,
        ) {
            runtime.portSentinelStore.initialize()
            runtime.portSentinelStore.integrityOk()
        }
        repairAuthenticatedStore(
            key = "app-approvals",
            component = "app-approvals",
            healthy = runtime.appApprovals.integrityOk(),
            now = now,
            findings = findings,
            repairs = repairs,
        ) {
            runtime.appApprovals.initialize()
            runtime.appApprovals.integrityOk()
        }
        repairAuthenticatedStore(
            key = "titan-policy",
            component = "titan-policy",
            healthy = runtime.titan.snapshot().policyStoreIntegrityOk,
            now = now,
            findings = findings,
            repairs = repairs,
        ) {
            runtime.titan.initialize()
            runtime.titan.snapshot().policyStoreIntegrityOk
        }
    }

    private fun inspectBehaviorStore(now: Long, findings: MutableList<Finding>, repairs: RepairCounter) {
        if (runtime.behavior.snapshot().baselineIntegrityOk) return
        attemptRepair(
            key = "behavior-baseline",
            component = "behavior-baseline",
            action = "RELOAD_AUTHENTICATED_STATE",
            failureAction = "OPERATOR_REQUIRED",
            failureDisposition = Disposition.OPERATOR_REQUIRED,
            now = now,
            findings = findings,
            repairs = repairs,
        ) {
            runtime.behavior.initialize()
            runtime.behavior.snapshot().baselineIntegrityOk
        }
    }

    private fun inspectThreatIntelligence(now: Long, findings: MutableList<Finding>, repairs: RepairCounter) {
        if (runtime.threatIndex.get().count > 0) return
        attemptRepair(
            key = "threat-cache",
            component = "threat-intelligence",
            action = "RELOAD_LAST_KNOWN_GOOD",
            failureAction = "SYNC_REQUIRED",
            failureDisposition = Disposition.SYNC_REQUIRED,
            now = now,
            findings = findings,
            repairs = repairs,
        ) {
            val restored = runtime.feeds.loadCachedSnapshot()
            runtime.refreshFeedHealth()
            restored.count > 0
        }
    }

    private fun inspectGaiaNet(now: Long, findings: MutableList<Finding>, repairs: RepairCounter) {
        if (runtime.state.protectionMode() != ProtectionMode.FULL_FLOW_BETA || NativeGaiaNet.available) return
        val active = runtime.state.isVpnActive()
        attemptRepair(
            key = "gaianet-availability",
            component = "gaianet",
            action = "REVALIDATE_PACKAGED_HELPER",
            failureAction = if (active) "FAIL_CLOSED" else "RETRY_LATER",
            failureDisposition = if (active) Disposition.FAIL_CLOSED else Disposition.RETRY_LATER,
            now = now,
            findings = findings,
            repairs = repairs,
        ) { runtime.refreshNativeGaiaNetAvailability() }
    }

    private fun inspectInstallGuardGate(now: Long, findings: MutableList<Finding>, repairs: RepairCounter) {
        if (!runtime.state.isVpnActive() || runtime.state.protectionMode() != ProtectionMode.FULL_FLOW_BETA) return
        if (!runtime.firewallPolicy.integrityOk()) return
        val quarantined = runtime.firewallPolicy.quarantinedPackages().take(MAX_QUARANTINE_RECONCILE).toSet()
        if (quarantined.isEmpty()) return
        val active = NativeGaiaNet.packageEgressGateActive()
        if (active) return
        attemptRepair(
            key = "installguard-egress-gate",
            component = "installguard-egress-gate",
            action = "RESYNC_QUARANTINE",
            failureAction = "FAIL_CLOSED",
            failureDisposition = Disposition.FAIL_CLOSED,
            now = now,
            findings = findings,
            repairs = repairs,
            timeoutMillis = PACKAGE_GATE_SYNC_TIMEOUT_MS,
        ) {
            NativeGaiaNet.syncPackageEgressQuarantine(quarantined) && NativeGaiaNet.packageEgressGateActive()
        }
    }

    private fun reconcileTitanQuarantine(findings: MutableList<Finding>, repairs: RepairCounter) {
        if (!runtime.firewallPolicy.integrityOk() || repairs.value >= MAX_REPAIRS_PER_RUN) return
        val quarantined = runtime.firewallPolicy.quarantinedPackages().take(MAX_QUARANTINE_RECONCILE).toSet()
        if (quarantined.isEmpty()) return
        val titan = runtime.titan.snapshot()
        if (!titan.isDeviceOwner || !titan.autoSuspendOnQuarantine) return

        try {
            BoundedRecoveryCall.call(TITAN_READBACK_TIMEOUT_MS) { runtime.titan.refreshSuspendedPackages(quarantined) }
        } catch (error: RecoveryCallUnavailableException) {
            findings += Finding("titan-quarantine", "READBACK_DEFERRED", "RETRY_LATER", Disposition.RETRY_LATER, false, error.reasonCode)
            return
        } catch (_: RuntimeException) {
            findings += Finding("titan-quarantine", "READBACK_FAILED", "RETRY_LATER", Disposition.RETRY_LATER, false, "titan_readback_failed")
            return
        }

        var repairedCount = 0
        for (packageName in quarantined) {
            if (repairs.value >= MAX_REPAIRS_PER_RUN) break
            if (runtime.titan.isPackageSuspended(packageName)) continue
            val result = try {
                BoundedRecoveryCall.call(TITAN_ACTION_TIMEOUT_MS) { runtime.titan.enforceQuarantine(packageName, true) }
            } catch (_: RuntimeException) {
                null
            }
            if (result?.ok == true && result.code == "PACKAGE_SUSPENDED") {
                repairs.value++
                repairedCount++
            }
        }
        if (repairedCount > 0) {
            findings += Finding(
                "titan-quarantine",
                "DRIFT_REPAIRED",
                "RESUSPEND_QUARANTINED",
                Disposition.REPAIRED,
                true,
                "count=$repairedCount",
            )
        }
    }

    private fun inspectSelfIntegrity(now: Long, findings: MutableList<Finding>, repairs: RepairCounter) {
        val before = runtime.integritySnapshot.get()
        if (before.ok || before.state == "PENDING") return
        attemptRepair(
            key = "self-integrity",
            component = "self-integrity",
            action = "REVALIDATE_SIGNED_INSTALL",
            failureAction = if (runtime.state.isVpnActive()) "FAIL_CLOSED" else "OPERATOR_REQUIRED",
            failureDisposition = if (runtime.state.isVpnActive()) Disposition.FAIL_CLOSED else Disposition.OPERATOR_REQUIRED,
            now = now,
            findings = findings,
            repairs = repairs,
            timeoutMillis = INTEGRITY_REVALIDATE_TIMEOUT_MS,
        ) {
            val snapshot = runtime.integrityGuardian.scan()
            runtime.integritySnapshot.set(snapshot)
            try { runtime.xdr.ingestIntegrity(snapshot) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("resilience-supervisor", error) }
            snapshot.ok
        }
    }

    private fun inspectMalwareAnalysisCache(findings: MutableList<Finding>) {
        if (runtime.malwareAnalysisStore.integrityOk()) return
        findings += Finding(
            component = "malware-analysis-cache",
            state = "DEGRADED",
            action = "REBUILD_SCAN_REQUIRED",
            disposition = Disposition.SCAN_REQUIRED,
            repaired = false,
            detail = runtime.malwareAnalysisStore.integrityFailureReason()?.take(MAX_DETAIL_CHARS) ?: "malware_analysis_unhealthy",
        )
    }

    private fun repairAuthenticatedStore(
        key: String,
        component: String,
        healthy: Boolean,
        now: Long,
        findings: MutableList<Finding>,
        repairs: RepairCounter,
        repair: () -> Boolean,
    ) {
        if (healthy) return
        attemptRepair(
            key = key,
            component = component,
            action = "RELOAD_AUTHENTICATED_STATE",
            failureAction = "OPERATOR_REQUIRED",
            failureDisposition = Disposition.OPERATOR_REQUIRED,
            now = now,
            findings = findings,
            repairs = repairs,
            repair = repair,
        )
    }

    private fun safeXdrSnapshot(findings: MutableList<Finding>): XdrSnapshot? = try {
        runtime.xdr.snapshot()
    } catch (_: RuntimeException) {
        findings += Finding("xdr", "SNAPSHOT_FAILED", "OPERATOR_REQUIRED", Disposition.OPERATOR_REQUIRED, false, "xdr_snapshot_failed")
        null
    }

    private fun attemptRepair(
        key: String,
        component: String,
        action: String,
        failureAction: String,
        failureDisposition: Disposition,
        now: Long,
        findings: MutableList<Finding>,
        repairs: RepairCounter,
        timeoutMillis: Long = REPAIR_TIMEOUT_MS,
        repair: () -> Boolean,
    ): Boolean {
        if (repairs.value >= MAX_REPAIRS_PER_RUN) {
            findings += Finding(component, "REPAIR_BUDGET_EXHAUSTED", "RETRY_LATER", Disposition.RETRY_LATER, false, "run_budget_exhausted")
            return false
        }
        val decision = repairBudget.tryAcquire(key, now)
        if (!decision.allowed) {
            val exhausted = decision.attemptsInWindow >= MAX_REPAIR_ATTEMPTS_PER_WINDOW
            findings += Finding(
                component,
                if (exhausted) "REPAIR_WINDOW_EXHAUSTED" else "REPAIR_THROTTLED",
                if (exhausted && failureDisposition == Disposition.OPERATOR_REQUIRED) failureAction else "RETRY_LATER",
                if (exhausted && failureDisposition == Disposition.OPERATOR_REQUIRED) Disposition.OPERATOR_REQUIRED else Disposition.RETRY_LATER,
                false,
                if (exhausted) "repair_budget_exhausted" else "retry_after_ms=${decision.retryAfterMillis.coerceAtLeast(0L)}",
            )
            return false
        }

        val ok = try {
            BoundedRecoveryCall.call(timeoutMillis) { repair() }
        } catch (error: RecoveryCallUnavailableException) {
            findings += Finding(component, "REPAIR_UNAVAILABLE", "RETRY_LATER", Disposition.RETRY_LATER, false, error.reasonCode)
            false
        } catch (_: RuntimeException) {
            findings += Finding(component, "REPAIR_FAILED", failureAction, failureDisposition, false, "repair_failed")
            false
        }
        if (ok) {
            repairBudget.clear(key)
            repairs.value++
            findings += Finding(component, "RECOVERED", action, Disposition.REPAIRED, true, "repair_succeeded")
        } else if (findings.none { it.component == component && !it.repaired }) {
            findings += Finding(component, "DEGRADED", failureAction, failureDisposition, false, "repair_no_progress")
        }
        return ok
    }

    private fun appendEvidence(report: Report) {
        val summary = report.findings.joinToString(";") { finding ->
            "${sanitizeCode(finding.component, "component")}:${sanitizeCode(finding.state, "state")}:${sanitizeCode(finding.action, "action")}:${finding.disposition.name}:${if (finding.repaired) 1 else 0}:${sanitizeCode(finding.detail, "none")}" 
        }.take(MAX_EVIDENCE_DETAIL_CHARS)
        try {
            runtime.evidence.append(
                EvidenceEvent(
                    type = "resilience.supervisor",
                    severity = if (report.healthy) "info" else "warning",
                    subject = "local",
                    detail = "trigger=${report.trigger}; healthy=${report.healthy}; repairs=${report.repairs}; unresolved=${report.unresolved}; findings=$summary",
                ),
            )
        } catch (_: Throwable) {
            // Evidence health already models this failure. Never recurse from the repair journal.
        }
    }

    private fun emitXdr(report: Report) {
        report.findings.asSequence()
            .filter { it.repaired || it.disposition == Disposition.FAIL_CLOSED || it.disposition == Disposition.OPERATOR_REQUIRED }
            .take(MAX_XDR_FINDINGS)
            .forEach { finding ->
                try {
                    runtime.xdr.recordResilienceFinding(
                        component = finding.component,
                        state = finding.state,
                        action = finding.action,
                        repaired = finding.repaired,
                        critical = finding.disposition == Disposition.FAIL_CLOSED || finding.disposition == Disposition.OPERATOR_REQUIRED,
                    )
                } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("resilience-supervisor", error) }
            }
    }

    private fun sanitizeCode(value: String, fallback: String): String {
        val cleaned = value.lowercase(Locale.ROOT)
            .map { if (it.isLetterOrDigit() || it == '-' || it == '_') it else '_' }
            .joinToString("")
            .take(64)
        return cleaned.ifBlank { fallback }
    }

    companion object {
        private const val MAX_FINDINGS = 32
        private const val MAX_XDR_FINDINGS = 8
        private const val MAX_DETAIL_CHARS = 192
        private const val MAX_EVIDENCE_DETAIL_CHARS = 1_400
        private const val MAX_REPAIR_KEYS = 64
        private const val MAX_REPAIRS_PER_RUN = 8
        private const val MAX_REPAIR_ATTEMPTS_PER_WINDOW = 3
        private const val REPAIR_WINDOW_MS = 30L * 60L * 1000L
        private const val REPAIR_COOLDOWN_MS = 60_000L
        private const val REPAIR_TIMEOUT_MS = 8_000L
        private const val EVIDENCE_VERIFY_TIMEOUT_MS = 8_000L
        private const val RECONCILE_TIMEOUT_MS = 8_000L
        private const val PACKAGE_GATE_SYNC_TIMEOUT_MS = 3_000L
        private const val TITAN_READBACK_TIMEOUT_MS = 5_000L
        private const val TITAN_ACTION_TIMEOUT_MS = 3_000L
        private const val INTEGRITY_REVALIDATE_TIMEOUT_MS = 20_000L
        private const val TRUST_BOOTSTRAP_WAIT_MS = 5_000L
        private const val SECONDARY_BOOTSTRAP_WAIT_MS = 3_000L
        private const val MAX_QUARANTINE_RECONCILE = 32
    }
}
