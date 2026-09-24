package de.visiongaia.gedefense.mobile

import android.app.Application
import android.content.Context
import android.os.Looper
import android.util.Log
import de.visiongaia.gedefense.mobile.core.EvidenceEvent
import de.visiongaia.gedefense.mobile.core.EvidenceStore
import de.visiongaia.gedefense.mobile.core.LedgerHealth
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

class AppRuntime private constructor(private val application: Application) {
    val state = RuntimeState(application)
    private val workerPool = ThreadPoolExecutor(
        WORKER_THREADS,
        WORKER_THREADS,
        0L,
        TimeUnit.MILLISECONDS,
        ArrayBlockingQueue(WORKER_QUEUE_CAPACITY),
        { runnable -> Thread(runnable, "gedefense-worker").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )
    private val criticalBootstrapPool = ThreadPoolExecutor(
        CRITICAL_BOOTSTRAP_STAGES,
        CRITICAL_BOOTSTRAP_STAGES,
        0L,
        TimeUnit.MILLISECONDS,
        ArrayBlockingQueue(CRITICAL_BOOTSTRAP_STAGES),
        { runnable -> Thread(runnable, "gedefense-critical-bootstrap").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )
    private val criticalBootstrapWatchers = ThreadPoolExecutor(
        CRITICAL_BOOTSTRAP_STAGES,
        CRITICAL_BOOTSTRAP_STAGES,
        0L,
        TimeUnit.MILLISECONDS,
        ArrayBlockingQueue(CRITICAL_BOOTSTRAP_STAGES),
        { runnable -> Thread(runnable, "gedefense-critical-watchdog").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )
    val threatIndex = AtomicReference(ThreatIndex.empty())
    val feedHealth = AtomicReference<List<FeedHealthStatus>>(emptyList())
    private val initialSetupFeedSync = AtomicReference(InitialSetupFeedSyncState())
    private val initialSetupFeedSyncRunning = AtomicBoolean(false)
    val metrics = ProtectionMetrics()
    private val evidenceRuntime = RuntimeEvidenceStore()
    val evidence: EvidenceStore = evidenceRuntime
    val feeds = ThreatIntelRepository(
        application,
        threatIndex,
    ) { StableSecurityKeys.hmacOrNull("threat-intel") }
    val integrityGuardian = IntegrityGuardian(
        application,
    ) { StableSecurityKeys.hmacOrNull("integrity-baseline") }
    val geoCountry by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        GeoCountryRepository(application) { StableSecurityKeys.hmacOrNull("geo-country") }
    }
    val asnEvidence by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        AsnEvidenceRepository(application) { StableSecurityKeys.hmacOrNull("asn-evidence") }
    }
    val fullFlowAnalytics by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { FullFlowAnalytics(application) }
    val originLocator by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { LocalOriginLocator(application) }
    val setup by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { DeviceSetupManager(application) }
    val vpnDisclosure by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { VpnDisclosureStore(application) }
    val firewallPolicy by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { FirewallPolicyStore(application) }
    val networkDiscoveryStore by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { NetworkDiscoveryStore(application) }
    val portSentinelStore by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { PortSentinelStore(application) }
    val wireGuard by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { WireGuardProfileStore(application, state) }
    val portSentinelRuntime = AtomicReference(PortSentinelRuntimeState.standby())
    val titan by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { TitanPolicyManager(application) }
    val appApprovals by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { AppApprovalStore(application) }
    val xdr by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        XdrEngine(application, evidence, firewallPolicy, networkDiscoveryStore, portSentinelStore, titan, appApprovals, state)
    }
    val networkDiscoveryScanner by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { NetworkDiscoveryScanner(application, networkDiscoveryStore) }
    val behavior by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { BehaviorEngine(application, xdr) }
    val hardeningScanner by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { DeviceHardeningScanner(application) }
    val malwareAnalysisStore by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { MalwareAnalysisStore(application) }
    val appRiskScanner by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { AppRiskScanner(application, appApprovals) }
    val privacyIntelligence by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { PrivacyIntelligenceRepository(application) }
    val installGuard by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { InstallGuard(application, appRiskScanner, xdr) }
    val resilienceSupervisor by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { ResilienceSupervisor(this) }
    val storageMalwareScanner by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { StorageMalwareScanner(application) }
    val deviceSecurityScanner by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { DeviceSecurityScanner(integrityGuardian, appRiskScanner, storageMalwareScanner) }
    val trafficUsage by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { TrafficUsageRepository(application) }
    val integritySnapshot = AtomicReference(IntegritySnapshot.pending())
    val appScanSnapshot = AtomicReference(AppScanSnapshot.idle())
    val deviceScanSnapshot = AtomicReference(DeviceScanSnapshot.idle())
    val trafficSnapshot = AtomicReference(TrafficUsageSnapshot.idle())
    val hardeningSnapshot = AtomicReference(HardeningSnapshot.pending())
    val networkDiscoverySnapshot = AtomicReference(NetworkDiscoverySnapshot.idle())
    val threatEnforcementSelfTest = AtomicReference(ThreatEnforcementSelfTestSnapshot.idle())

    private val listeners = CopyOnWriteArraySet<() -> Unit>()
    private val bootstrapComplete = CountDownLatch(CRITICAL_BOOTSTRAP_STAGES)
    private val xdrTrustBootstrap = CountDownLatch(XDR_TRUST_BOOTSTRAP_STAGES)
    private val nativeGaiaNetBootstrap = CountDownLatch(1)
    private val vpnDisclosureBootstrap = CountDownLatch(1)
    private val firewallPolicyBootstrap = CountDownLatch(1)
    private val portSentinelBootstrap = CountDownLatch(1)
    private val wireGuardBootstrap = CountDownLatch(1)
    private val behaviorBootstrap = CountDownLatch(1)
    private val malwareAnalysisBootstrap = CountDownLatch(1)
    private val evidenceVerifyRunning = AtomicBoolean(false)
    private val integrityRunning = AtomicBoolean(false)
    private val appScanRunning = AtomicBoolean(false)
    private val analysisRestoreRunning = AtomicBoolean(false)
    private val analysisRestoreCancel = AtomicBoolean(false)
    private val deviceScanRunning = AtomicBoolean(false)
    private val deviceScanCancel = AtomicBoolean(false)
    private val trafficQueryRunning = AtomicBoolean(false)
    private val networkDiscoveryRunning = AtomicBoolean(false)
    private val networkDiscoveryCancel = AtomicBoolean(false)
    private val threatSelfTestSequence = AtomicInteger(0)

    fun executeBackground(name: String, action: () -> Unit): Boolean = submitWorker(name, action)

    fun runThreatEnforcementSelfTest(): Boolean {
        if (!state.isVpnActive() || state.protectionMode() != ProtectionMode.FULL_FLOW_BETA || state.lastVpnStatus() != "FULL_GUARDED") {
            recordThreatSelfTestImmediateFailure("full_flow_not_guarded")
            return false
        }
        while (true) {
            val current = threatEnforcementSelfTest.get()
            if (current.state == "RUNNING") return false
            val sequence = threatSelfTestSequence.updateAndGet { previous -> if (previous >= 255) 1 else previous + 1 }
            val started = ThreatEnforcementSelfTestSnapshot(
                state = "RUNNING",
                sequence = sequence,
                startedAtMillis = System.currentTimeMillis(),
                completedAtMillis = 0L,
                target = null,
                feeds = emptyList(),
                reason = null,
            )
            if (!threatEnforcementSelfTest.compareAndSet(current, started)) continue
            notifyStateChanged()
            if (!submitWorker("threat-policy-self-test") { executeThreatPolicySelfTest(sequence) }) {
                completeThreatSelfTest(sequence, null, emptyList(), "worker_queue_busy")
                return false
            }
            return true
        }
    }

    private fun executeThreatPolicySelfTest(sequence: Int) {
        val index = threatIndex.get()
        var target: String? = null
        var feedIds: List<String> = emptyList()
        val reason = when {
            index.count <= 0 -> "policy_empty"
            index.routeOverflow -> "route_policy_overflow"
            index.routePrefixes.isEmpty() -> "no_block_routes"
            else -> {
                val route = index.routePrefixes.first()
                val address = route.toInetAddress().hostAddress ?: return completeThreatSelfTest(sequence, null, emptyList(), "route_address_unavailable")
                target = address
                val match = index.match(address)
                feedIds = match?.blockingFeeds?.map { it.id }?.take(THREAT_SELF_TEST_MAX_FEEDS).orEmpty()
                when {
                    match == null -> "route_match_missing"
                    !match.hasBlockingSignal -> "block_authority_missing"
                    !index.routePrefixes.any { it.contains(match.address) } -> "route_coverage_missing"
                    !NativeGaiaNet.validateThreatPolicySnapshot(index, application.cacheDir) -> "policy_serialization_failed"
                    else -> "policy_index_route_serialization_ok"
                }
            }
        }
        completeThreatSelfTest(sequence, target, feedIds, reason)
    }

    private fun completeThreatSelfTest(sequence: Int, target: String?, feeds: List<String>, reason: String) {
        while (true) {
            val current = threatEnforcementSelfTest.get()
            if (current.state != "RUNNING" || current.sequence != sequence) return
            val completed = current.copy(
                state = if (reason == "policy_index_route_serialization_ok") "PASS" else "FAIL",
                completedAtMillis = System.currentTimeMillis(),
                target = target?.take(80),
                feeds = feeds.take(THREAT_SELF_TEST_MAX_FEEDS),
                reason = reason.take(64),
            )
            if (threatEnforcementSelfTest.compareAndSet(current, completed)) {
                notifyStateChanged()
                return
            }
        }
    }

    private fun recordThreatSelfTestImmediateFailure(reason: String) {
        threatEnforcementSelfTest.set(
            ThreatEnforcementSelfTestSnapshot.idle().copy(
                state = "FAIL",
                completedAtMillis = System.currentTimeMillis(),
                reason = reason.take(64),
            ),
        )
        notifyStateChanged()
    }

    internal fun recordXdrFailure(operation: String, error: Throwable) {
        val safeOperation = sanitizeFailureCode(operation)
        try {
            state.recordXdrPersistenceFailure("xdr_${safeOperation}_failed")
        } catch (stateError: RuntimeException) {
            RuntimeFailureLog.nonCritical("xdr-failure-state", stateError)
        }
        RuntimeFailureLog.nonCritical("xdr-$safeOperation", error)
    }

    internal fun recordEvidenceFailure(operation: String, error: Throwable) {
        val safeOperation = sanitizeFailureCode(operation)
        val code = EvidenceWriteFailureClassifier.code(error)
        try {
            state.recordEvidencePersistenceFailure(code)
        } catch (stateError: RuntimeException) {
            RuntimeFailureLog.nonCritical("evidence-failure-state", stateError)
        }
        RuntimeFailureLog.nonCritical("evidence-$safeOperation", error)
    }

    internal fun requestIntegrityFailClosed(reason: String) {
        if (!state.isVpnActive()) return
        val safeReason = sanitizeFailureCode(reason)
        try {
            application.startService(
                android.content.Intent(application, GeDefenseVpnService::class.java)
                    .setAction(GeDefenseVpnService.ACTION_INTEGRITY_FAILURE),
            )
        } catch (dispatchError: RuntimeException) {
            state.setVpnStatus("DEGRADED_INTEGRITY", "integrity_dispatch_$safeReason")
            RuntimeFailureLog.nonCritical("integrity-fail-closed-dispatch", dispatchError)
            try {
                if (!application.stopService(android.content.Intent(application, GeDefenseVpnService::class.java))) {
                    RuntimeFailureLog.nonCritical(
                        "integrity-fail-closed-stop",
                        IllegalStateException("service_not_stopped"),
                    )
                }
            } catch (stopError: RuntimeException) {
                RuntimeFailureLog.nonCritical("integrity-fail-closed-stop", stopError)
            }
        }
    }

    private fun sanitizeFailureCode(value: String): String = value.asSequence()
        .map { character -> if (character.isLetterOrDigit() || character == '_' || character == '-') character.lowercaseChar() else '_' }
        .joinToString("")
        .take(48)
        .ifBlank { "operation" }

    fun refreshNativeGaiaNetAvailability(): Boolean = try {
        NativeGaiaNet.initialize(application)
        NativeGaiaNet.available
    } catch (error: RuntimeException) {
        RuntimeFailureLog.nonCritical("gaianet-availability", error)
        false
    }

    @Volatile
    var evidenceHealth: LedgerHealth = LedgerHealth(
        ok = false,
        records = 0L,
        reason = RuntimeEvidenceStore.INITIAL_REASON,
    )
        private set

    init {
        // Native helper validation touches the APK/native-lib filesystem. It is deliberately not
        // part of AppRuntime construction; Full Flow waits on its own bounded readiness latch.
        launchEnrichment("gaianet-helper", nativeGaiaNetBootstrap) {
            NativeGaiaNet.initialize(application)
        }
        state.setEvidenceHealth(evidenceHealth)
        scheduleCriticalBootstrap(
            name = "evidence",
            action = { AndroidEvidence.bootstrap(application) },
            onSuccess = { result ->
                evidenceRuntime.install(result.store)
                evidenceHealth = result.failureCode?.let { LedgerHealth(ok = false, records = 0L, reason = it) }
                    ?: safeEvidenceOperation("open") { evidence.open() }
                state.setEvidenceHealth(evidenceHealth)
            },
            onFailure = { error ->
                evidenceHealth = LedgerHealth(
                    ok = false,
                    records = 0L,
                    reason = if (error is TimeoutException) "evidence_bootstrap_timeout" else "evidence_bootstrap_failure",
                )
                state.setEvidenceHealth(evidenceHealth)
                Log.w(RUNTIME_LOG_TAG, "critical_bootstrap_failed:evidence:${error.javaClass.simpleName.take(48)}")
            },
        )
        scheduleCriticalBootstrap(
            name = "integrity",
            action = { integrityGuardian.scan() },
            onSuccess = integritySnapshot::set,
            onFailure = { error ->
                integritySnapshot.set(
                    IntegritySnapshot(
                        state = "COMPROMISED",
                        checkedAtMillis = System.currentTimeMillis(),
                        installSha256 = "",
                        signerSha256 = "",
                        filesChecked = 0,
                        issues = listOf(
                            IntegrityIssue(
                                if (error is TimeoutException) "integrity_bootstrap_timeout" else "integrity_bootstrap_failure",
                                IntegritySeverity.CRITICAL,
                                error.javaClass.simpleName.take(80),
                            ),
                        ),
                    ),
                )
            },
        )
        scheduleCriticalBootstrap(
            name = "threat-cache",
            action = { feeds.loadCachedSnapshot() to feeds.healthSnapshot() },
            onSuccess = { (index, health) ->
                threatIndex.set(index)
                feedHealth.set(health)
            },
            onFailure = { error ->
                threatIndex.set(ThreatIndex.empty())
                feedHealth.set(emptyList())
                Log.w(RUNTIME_LOG_TAG, "critical_bootstrap_failed:threat-cache:${error.javaClass.simpleName.take(48)}")
            },
        )

        // Stage 2 never participates in Runtime publication or the protection bootstrap latch.
        // Each authenticated domain initializes independently so one provider/store failure cannot
        // suppress unrelated security state. All stores remain fail-closed until their own init ends.
        submitWorker("stage2-coordinator") {
            try {
                bootstrapComplete.await()
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return@submitWorker
            }
            notifyStateChanged()

            launchEnrichment("setup-state") { setup.refreshSnapshot() }
            launchEnrichment("vpn-disclosure", vpnDisclosureBootstrap) { vpnDisclosure.initialize() }
            launchTrustStoreBootstrap("firewall-policy", firewallPolicyBootstrap) { firewallPolicy.initialize() }
            launchTrustStoreBootstrap("network-discovery-store") { networkDiscoveryStore.initialize() }
            launchTrustStoreBootstrap("port-sentinel-store", portSentinelBootstrap) { portSentinelStore.initialize() }
            launchEnrichment("wireguard-profile", wireGuardBootstrap) { wireGuard.initialize() }
            launchTrustStoreBootstrap("titan-policy") { titan.initialize() }
            launchTrustStoreBootstrap("app-approvals") { appApprovals.initialize() }
            launchTrustStoreBootstrap("xdr-persistence") { xdr.initializePersistentState() }
            launchEnrichment("behavior-state", behaviorBootstrap) { behavior.initialize() }

            launchEnrichment("xdr-post-init") {
                val complete = try {
                    xdrTrustBootstrap.await(SECONDARY_TRUST_BOOTSTRAP_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    false
                }
                if (!complete) {
                    Log.w(RUNTIME_LOG_TAG, "xdr_trust_bootstrap_timeout")
                } else {
                    if (setup.isWizardCompleted()) xdr.reconcilePackages()
                    if (!networkDiscoveryStore.integrityOk()) {
                        xdr.recordNetworkDiscoveryIntegrityFailure(networkDiscoveryStore.integrityFailureReason())
                    }
                    if (!portSentinelStore.integrityOk()) {
                        xdr.recordPortSentinelIntegrityFailure(portSentinelStore.integrityFailureReason())
                    }
                    titan.refreshSuspendedPackages(firewallPolicy.quarantinedPackages())
                }
            }
            launchEnrichment("vault-journal") { recordVaultRecoveryJournal() }
            launchEnrichment("geo-cache") { geoCountry.loadCached() }
            launchEnrichment("asn-evidence-cache") { asnEvidence.loadCached() }
            launchEnrichment("origin") { originLocator.refresh() }
            launchEnrichment("malware-snapshot", malwareAnalysisBootstrap) {
                malwareAnalysisStore.load()?.let(appScanSnapshot::set)
                if (appScanSnapshot.get().state == "IDLE" && appRiskScanner.hasReusableCache()) {
                    appScanSnapshot.set(AppScanSnapshot.idle().copy(state = "RESTORING"))
                    restoreAppAnalysisAsync()
                }
            }
            launchEnrichment("hardening") {
                val hardening = hardeningScanner.scan()
                hardeningSnapshot.set(hardening)
                xdr.ingestHardening(hardening)
            }
        }
    }

    private fun <T> scheduleCriticalBootstrap(
        name: String,
        action: () -> T,
        onSuccess: (T) -> Unit,
        onFailure: (Throwable) -> Unit,
    ) {
        val future = try {
            criticalBootstrapPool.submit<T> { action() }
        } catch (error: RejectedExecutionException) {
            try { onFailure(error) } catch (error: Throwable) { RuntimeFailureLog.nonCritical("app-runtime", error) }
            completeCriticalBootstrapStage()
            return
        }
        try {
            criticalBootstrapWatchers.execute {
                try {
                    val result = future.get(CRITICAL_BOOTSTRAP_STAGE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                    try { onSuccess(result) } catch (callbackError: Throwable) {
                        try { onFailure(callbackError) } catch (error: Throwable) { RuntimeFailureLog.nonCritical("app-runtime", error) }
                    }
                } catch (error: TimeoutException) {
                    future.cancel(true)
                    try { onFailure(error) } catch (error: Throwable) { RuntimeFailureLog.nonCritical("app-runtime", error) }
                    Log.w(RUNTIME_LOG_TAG, "critical_bootstrap_timeout:" + name.take(48))
                } catch (error: InterruptedException) {
                    future.cancel(true)
                    Thread.currentThread().interrupt()
                    try { onFailure(error) } catch (error: Throwable) { RuntimeFailureLog.nonCritical("app-runtime", error) }
                } catch (error: ExecutionException) {
                    val cause = error.cause ?: error
                    try { onFailure(cause) } catch (error: Throwable) { RuntimeFailureLog.nonCritical("app-runtime", error) }
                } catch (error: Throwable) {
                    try { onFailure(error) } catch (error: Throwable) { RuntimeFailureLog.nonCritical("app-runtime", error) }
                } finally {
                    completeCriticalBootstrapStage()
                }
            }
        } catch (error: RejectedExecutionException) {
            future.cancel(true)
            try { onFailure(error) } catch (error: Throwable) { RuntimeFailureLog.nonCritical("app-runtime", error) }
            completeCriticalBootstrapStage()
        }
    }

    private fun completeCriticalBootstrapStage() {
        bootstrapComplete.countDown()
        if (bootstrapComplete.count == 0L) {
            criticalBootstrapPool.shutdownNow()
            criticalBootstrapWatchers.shutdown()
        }
        notifyStateChanged()
    }

    private fun launchTrustStoreBootstrap(name: String, completion: CountDownLatch? = null, action: () -> Unit) {
        val accepted = launchEnrichment(name, completion) {
            try {
                action()
            } finally {
                xdrTrustBootstrap.countDown()
            }
        }
        // A saturated runtime worker queue must never strand the XDR trust latch for 30 seconds.
        // Rejection is an explicit fail-closed bootstrap failure, so account for the stage here.
        if (!accepted) xdrTrustBootstrap.countDown()
    }

    private fun launchEnrichment(name: String, completion: CountDownLatch? = null, action: () -> Unit): Boolean {
        val accepted = submitWorker("enrichment-$name") {
            try {
                bootstrapStep(name, action)
            } finally {
                completion?.countDown()
                notifyStateChanged()
            }
        }
        if (!accepted) completion?.countDown()
        return accepted
    }

    private fun submitWorker(name: String, action: () -> Unit): Boolean {
        return try {
            workerPool.execute {
                try {
                    action()
                } catch (error: Throwable) {
                    Log.w(RUNTIME_LOG_TAG, "worker_task_failed:" + name.take(48) + ":" + error.javaClass.simpleName.take(48))
                }
            }
            true
        } catch (_: RejectedExecutionException) {
            Log.w(RUNTIME_LOG_TAG, "worker_queue_rejected:" + name.take(48))
            false
        }
    }

    private inline fun bootstrapStep(name: String, action: () -> Unit): Throwable? {
        return try {
            action()
            null
        } catch (error: Throwable) {
            Log.w(RUNTIME_LOG_TAG, "bootstrap_step_failed:" + name.take(48) + ":" + error.javaClass.simpleName.take(48))
            error
        }
    }

    private fun recordVaultRecoveryJournal() {
        if (!evidenceHealth.ok) return
        val recoveryBatch = VaultRecoveryJournal.drain()
        if (recoveryBatch.records.isEmpty() && recoveryBatch.droppedRecords == 0L) return
        val detail = buildList {
            if (recoveryBatch.droppedRecords > 0L) add("journal_overflow_dropped=${recoveryBatch.droppedRecords}")
            recoveryBatch.records.forEach { record ->
                add("domain=${record.domain},failure=${record.failureKind.name},archive_sha256=${record.archiveSha256}")
            }
        }.joinToString(";").take(3_200)
        try {
            evidence.append(EvidenceEvent(
                type = "VAULT_RECOVERY",
                severity = "WARNING",
                subject = "secure-telemetry-vault",
                detail = detail,
            ))
            refreshEvidenceHealth()
        } catch (error: Throwable) {
            // Recovery archives remain durable even if the independent Evidence ledger is unavailable.
            recordEvidenceFailure("vault_recovery_journal", error)
        }
    }

    fun activatePostSetupInventoryAsync() {
        if (!setup.isWizardCompleted()) return
        submitWorker("post-setup-inventory") {
            try {
                xdr.reconcilePackages()
            } catch (error: Throwable) {
                // Inventory enrichment is non-critical; failures remain local and retryable.
                recordXdrFailure("post_setup_inventory", error)
            } finally {
                notifyStateChanged()
            }
        }
    }

    fun refreshEvidenceHealth(): LedgerHealth {
        val health = safeEvidenceOperation("verify") { evidence.verify() }
        evidenceHealth = health
        state.setEvidenceHealth(health)
        return health
    }

    fun verifyEvidenceAsync(after: ((LedgerHealth) -> Unit)? = null) {
        if (!evidenceVerifyRunning.compareAndSet(false, true)) {
            after?.let { callback -> try { callback(evidenceHealth) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
            return
        }
        if (!submitWorker("verify-evidence") {
            val health = try { refreshEvidenceHealth() } finally { evidenceVerifyRunning.set(false) }
            after?.let { callback -> try { callback(health) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
            notifyStateChanged()
        }) {
            evidenceVerifyRunning.set(false)
            after?.let { callback -> try { callback(evidenceHealth) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
        }
    }

    fun verifyIntegrityAsync(after: ((IntegritySnapshot) -> Unit)? = null) {
        if (!integrityRunning.compareAndSet(false, true)) {
            after?.let { callback -> try { callback(integritySnapshot.get()) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
            return
        }
        if (!submitWorker("verify-integrity") {
            val snapshot = try {
                integrityGuardian.scan()
            } catch (t: Throwable) {
                IntegritySnapshot(
                    state = "COMPROMISED",
                    checkedAtMillis = System.currentTimeMillis(),
                    installSha256 = "",
                    signerSha256 = "",
                    filesChecked = 0,
                    issues = listOf(IntegrityIssue("integrity_scan_failure", IntegritySeverity.CRITICAL, t.javaClass.simpleName.take(80))),
                )
            }
            integritySnapshot.set(snapshot)
            try { xdr.ingestIntegrity(snapshot) } catch (error: Throwable) { recordXdrFailure("integrity_ingest", error) }
            integrityRunning.set(false)
            after?.let { callback -> try { callback(snapshot) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
            notifyStateChanged()
        }) {
            integrityRunning.set(false)
            after?.let { callback -> try { callback(integritySnapshot.get()) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
        }
    }

    private fun restoreAppAnalysisAsync() {
        if (!analysisRestoreRunning.compareAndSet(false, true)) return
        analysisRestoreCancel.set(false)
        if (!submitWorker("restore-app-analysis") {
            val restored = try {
                appRiskScanner.restoreFromAuthenticatedCache(
                    index = threatIndex.get(),
                    cancelled = { analysisRestoreCancel.get() },
                    timeoutMillis = ANALYSIS_RESTORE_TIMEOUT_MS,
                )
            } catch (error: Throwable) {
                RuntimeFailureLog.nonCritical("app-analysis-restore", error)
                null
            }
            val cancelled = analysisRestoreCancel.get()
            if (!cancelled && restored?.state == "COMPLETE") {
                appScanSnapshot.set(restored)
                malwareAnalysisStore.save(restored)
                try { xdr.ingestAppScan(restored) } catch (error: Throwable) { recordXdrFailure("app_restore_ingest", error) }
            } else if (!cancelled && appScanSnapshot.get().state == "RESTORING") {
                // Restoration is acceleration only. Failure/timeout falls back to an explicit scan,
                // never to an indefinitely spinning pseudo-state.
                appScanSnapshot.set(AppScanSnapshot.idle())
            }
            analysisRestoreRunning.set(false)
            notifyStateChanged()
        }) {
            analysisRestoreRunning.set(false)
            analysisRestoreCancel.set(false)
            if (appScanSnapshot.get().state == "RESTORING") appScanSnapshot.set(AppScanSnapshot.idle())
            notifyStateChanged()
        }
    }

    private fun cancelAppAnalysisRestore() {
        analysisRestoreCancel.set(true)
        if (appScanSnapshot.get().state == "RESTORING") appScanSnapshot.set(AppScanSnapshot.idle())
    }

    fun scanAppsAsync(after: ((AppScanSnapshot) -> Unit)? = null) {
        cancelAppAnalysisRestore()
        if (!appScanRunning.compareAndSet(false, true)) {
            after?.let { callback -> try { callback(appScanSnapshot.get()) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
            return
        }
        if (!submitWorker("scan-apps") {
            val snapshot = try {
                appRiskScanner.scan(threatIndex.get())
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                AppScanSnapshot.idle()
            } catch (error: Throwable) {
                RuntimeFailureLog.nonCritical("app-scan", error)
                AppScanSnapshot("FAILED", System.currentTimeMillis(), 0, 0, 0, 0, 0, false, emptyList())
            }
            appScanSnapshot.set(snapshot)
            if (snapshot.state == "COMPLETE") malwareAnalysisStore.save(snapshot)
            try { xdr.ingestAppScan(snapshot) } catch (error: Throwable) { recordXdrFailure("app_scan_ingest", error) }
            appScanRunning.set(false)
            after?.let { callback -> try { callback(snapshot) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
            notifyStateChanged()
        }) {
            appScanRunning.set(false)
            val failed = AppScanSnapshot("FAILED", System.currentTimeMillis(), 0, 0, 0, 0, 0, false, emptyList())
            appScanSnapshot.set(failed)
            after?.let { callback -> try { callback(failed) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
            notifyStateChanged()
        }
    }


    fun startDeviceScanAsync(after: ((DeviceScanSnapshot) -> Unit)? = null) {
        cancelAppAnalysisRestore()
        if (!deviceScanRunning.compareAndSet(false, true)) {
            after?.let { callback -> try { callback(deviceScanSnapshot.get()) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
            return
        }
        deviceScanCancel.set(false)
        val started = DeviceScanSnapshot.idle().copy(
            state = "RUNNING",
            startedAtMillis = System.currentTimeMillis(),
            progress = DeviceScanProgress(DeviceScanPhase.INTEGRITY, 0f, 0, 0, "", 0),
        )
        deviceScanSnapshot.set(started)
        notifyStateChanged()
        if (!submitWorker("device-scan") {
            val result = deviceSecurityScanner.scan(
                index = threatIndex.get(),
                cancelled = { deviceScanCancel.get() },
                onProgress = { progress ->
                    val current = deviceScanSnapshot.get()
                    deviceScanSnapshot.set(current.copy(state = "RUNNING", progress = progress))
                    notifyStateChanged()
                },
            )
            deviceScanSnapshot.set(result)
            if (result.state == "COMPLETE") {
                integritySnapshot.set(result.integrity)
                appScanSnapshot.set(result.apps)
                malwareAnalysisStore.save(result.apps)
                try { xdr.ingestDeviceScan(result) } catch (error: Throwable) { recordXdrFailure("device_scan_ingest", error) }
                try {
                    evidence.append(EvidenceEvent(
                        type = "DEVICE_SCAN_COMPLETE",
                        severity = if (result.integrity.ok && result.apps.highRiskPackages == 0 && result.storage.highRiskFiles == 0) "INFO" else "WARNING",
                        subject = "local-device-scan",
                        detail = "apps=${result.apps.userPackages};high_apps=${result.apps.highRiskPackages};files=${result.storage.enumeratedFiles};high_files=${result.storage.highRiskFiles};ti_files=${result.storage.threatMatchedFiles};storage_access=${result.storage.accessGranted}",
                    ))
                    refreshEvidenceHealth()
                } catch (error: Throwable) { recordEvidenceFailure("device_scan", error) }
                if (!result.integrity.ok) requestIntegrityFailClosed("device_scan")
            }
            deviceScanRunning.set(false)
            deviceScanCancel.set(false)
            after?.let { callback -> try { callback(result) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
            notifyStateChanged()
        }) {
            deviceScanRunning.set(false)
            deviceScanCancel.set(false)
            val failed = deviceScanSnapshot.get().copy(state = "FAILED")
            deviceScanSnapshot.set(failed)
            after?.let { callback -> try { callback(failed) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
            notifyStateChanged()
        }
    }

    fun approveApp(packageName: String): Boolean {
        val result = currentAppRiskResult(packageName) ?: return false
        val approved = appApprovals.approve(result)
        if (approved) {
            try { xdr.recordAppApproval(result.packageName, true, result.signerSha256) } catch (error: Throwable) { recordXdrFailure("app_approval", error) }
            refreshApprovalStates()
            notifyStateChanged()
        }
        return approved
    }

    fun revokeAppApproval(packageName: String): Boolean {
        val revoked = appApprovals.revoke(packageName)
        if (revoked) {
            try { xdr.recordAppApproval(packageName, false, null) } catch (error: Throwable) { recordXdrFailure("app_approval_revoke", error) }
            refreshApprovalStates()
            notifyStateChanged()
        }
        return revoked
    }

    fun currentAppRiskResult(packageName: String): AppRiskResult? {
        val direct = appScanSnapshot.get().results.firstOrNull { it.packageName == packageName }
        if (direct != null) return direct
        return deviceScanSnapshot.get().apps.results.firstOrNull { it.packageName == packageName }
    }

    fun refreshTitanSnapshotAsync(after: ((TitanSnapshot) -> Unit)? = null) {
        val accepted = submitWorker("titan-refresh") {
            val snapshot = titan.refreshSnapshot()
            after?.let { callback -> try { callback(snapshot) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
            notifyStateChanged()
        }
        if (!accepted) after?.let { callback -> try { callback(titan.snapshot()) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
    }

    fun setAppApprovalAsync(packageName: String, approved: Boolean, after: (Boolean) -> Unit) {
        val accepted = submitWorker("app-approval") {
            val ok = if (approved) approveApp(packageName) else revokeAppApproval(packageName)
            try { after(ok) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) }
        }
        if (!accepted) {
            try { after(false) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) }
        }
    }

    private fun refreshApprovalStates() {
        fun refreshed(snapshot: AppScanSnapshot): AppScanSnapshot {
            if (snapshot.state != "COMPLETE") return snapshot
            val results = snapshot.results.map { result ->
                val status = appApprovals.status(result.packageName, result.signerSha256, result.findings.mapTo(linkedSetOf()) { it.code })
                val score = if (status == AppApprovalState.APPROVED && result.threatMatches.isEmpty()) minOf(result.riskScore, 12) else result.riskScore
                result.copy(
                    approvalState = status,
                    riskScore = score,
                    riskLevel = if (status == AppApprovalState.APPROVED && result.threatMatches.isEmpty()) AppRiskLevel.LOW else result.riskLevel,
                    confidence = if (status == AppApprovalState.APPROVED && result.threatMatches.isEmpty()) AppRiskConfidence.LOW else result.confidence,
                )
            }
            return snapshot.copy(results = results, highRiskPackages = results.count { it.riskLevel == AppRiskLevel.HIGH || it.riskLevel == AppRiskLevel.SEVERE })
        }
        val app = refreshed(appScanSnapshot.get())
        appScanSnapshot.set(app)
        if (app.state == "COMPLETE") malwareAnalysisStore.save(app)
        val device = deviceScanSnapshot.get()
        if (device.state == "COMPLETE") deviceScanSnapshot.set(device.copy(apps = refreshed(device.apps)))
    }

    fun cancelDeviceScan() {
        if (deviceScanRunning.get()) deviceScanCancel.set(true)
    }

    fun isDeviceScanRunning(): Boolean = deviceScanRunning.get()

    fun refreshTrafficAsync(after: ((TrafficUsageSnapshot) -> Unit)? = null) {
        if (!trafficQueryRunning.compareAndSet(false, true)) {
            after?.let { callback -> try { callback(trafficSnapshot.get()) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
            return
        }
        if (!submitWorker("traffic-query") {
            val snapshot = try {
                trafficUsage.queryLast24Hours()
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                TrafficUsageSnapshot.idle()
            } catch (error: Throwable) {
                RuntimeFailureLog.nonCritical("traffic-query", error)
                TrafficUsageSnapshot("FAILED", System.currentTimeMillis(), 0L, 0L, 0L, emptyList(), "FULL_FLOW_REQUIRED")
            }
            trafficSnapshot.set(snapshot)
            trafficQueryRunning.set(false)
            after?.let { callback -> try { callback(snapshot) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
            notifyStateChanged()
        }) {
            trafficQueryRunning.set(false)
            val failed = TrafficUsageSnapshot("FAILED", System.currentTimeMillis(), 0L, 0L, 0L, emptyList(), "WORKER_BUSY")
            trafficSnapshot.set(failed)
            after?.let { callback -> try { callback(failed) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
            notifyStateChanged()
        }
    }


    fun startNetworkDiscoveryAsync(after: ((NetworkDiscoverySnapshot) -> Unit)? = null) {
        if (!networkDiscoveryRunning.compareAndSet(false, true)) {
            after?.let { callback -> try { callback(networkDiscoverySnapshot.get()) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
            return
        }
        networkDiscoveryCancel.set(false)
        val started = NetworkDiscoverySnapshot.idle().copy(state = "SCANNING", startedAtMillis = System.currentTimeMillis())
        networkDiscoverySnapshot.set(started)
        notifyStateChanged()
        if (!submitWorker("network-discovery") {
            val result = try {
                networkDiscoveryScanner.scan(
                    cancelled = { networkDiscoveryCancel.get() },
                    onProgress = { progress ->
                        val current = networkDiscoverySnapshot.get()
                        networkDiscoverySnapshot.set(current.copy(
                            state = "SCANNING",
                            scannedHosts = progress.scannedHosts,
                            totalHosts = progress.totalHosts,
                        ))
                        if (progress.scannedHosts == progress.totalHosts || progress.scannedHosts % 8 == 0) notifyStateChanged()
                    },
                )
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                NetworkDiscoverySnapshot.idle().copy(state = "CANCELLED", completedAtMillis = System.currentTimeMillis())
            } catch (t: Exception) {
                NetworkDiscoverySnapshot.idle().copy(
                    state = "FAILED",
                    completedAtMillis = System.currentTimeMillis(),
                    baselineIntegrityOk = networkDiscoveryStore.integrityOk(),
                    baselineFailureReason = networkDiscoveryStore.integrityFailureReason(),
                    errorReason = t.javaClass.simpleName.take(80),
                )
            }
            networkDiscoverySnapshot.set(result)
            if (result.state == "COMPLETE") {
                try { xdr.ingestNetworkDiscovery(result) } catch (error: Exception) { recordXdrFailure("network_discovery_ingest", error) }
                try {
                    evidence.append(EvidenceEvent(
                        type = "NETWORK_DISCOVERY_COMPLETE",
                        severity = if (result.elevatedDevices > 0) "WARNING" else "INFO",
                        subject = "local-network",
                        detail = "transport=${result.transport};network=${result.networkId.take(16)};hosts=${result.scannedHosts};devices=${result.devices.size};new=${result.newDevices};elevated=${result.elevatedDevices};dns_sd=${result.dnsSdServices};baseline_ok=${result.baselineIntegrityOk}",
                    ))
                    refreshEvidenceHealth()
                } catch (error: Exception) { recordEvidenceFailure("network_discovery", error) }
            } else if (!result.baselineIntegrityOk) {
                try { xdr.recordNetworkDiscoveryIntegrityFailure(result.baselineFailureReason) } catch (error: Exception) { recordXdrFailure("network_discovery_integrity", error) }
            }
            networkDiscoveryRunning.set(false)
            networkDiscoveryCancel.set(false)
            after?.let { callback -> try { callback(result) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
            notifyStateChanged()
        }) {
            networkDiscoveryRunning.set(false)
            networkDiscoveryCancel.set(false)
            val failed = NetworkDiscoverySnapshot.idle().copy(
                state = "FAILED",
                completedAtMillis = System.currentTimeMillis(),
                errorReason = "runtime_worker_busy",
            )
            networkDiscoverySnapshot.set(failed)
            after?.let { callback -> try { callback(failed) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
            notifyStateChanged()
        }
    }

    fun cancelNetworkDiscovery() {
        if (networkDiscoveryRunning.get()) networkDiscoveryCancel.set(true)
    }

    fun isNetworkDiscoveryRunning(): Boolean = networkDiscoveryRunning.get()

    fun resetNetworkDiscoveryBaselineAsync(after: (Boolean) -> Unit) {
        if (!submitWorker("network-baseline-reset") {
            val ok = networkDiscoveryStore.reset()
            if (ok) {
                try { xdr.recordNetworkDiscoveryBaselineReset() } catch (error: Exception) { recordXdrFailure("network_discovery_reset", error) }
                networkDiscoverySnapshot.set(NetworkDiscoverySnapshot.idle())
                notifyStateChanged()
            }
            try { after(ok) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) }
        }) {
            try { after(false) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) }
        }
    }


    fun portSentinelSnapshot(): PortSentinelSnapshot = portSentinelStore.snapshot(portSentinelRuntime.get())

    fun onPortSentinelState(state: PortSentinelRuntimeState) {
        portSentinelRuntime.set(state)
        notifyStateChanged()
    }

    fun onPortSentinelHit(hit: PortSentinelHit) {
        submitWorker("port-sentinel-hit") {
            if (!portSentinelStore.recordHit(hit)) {
                if (!portSentinelStore.integrityOk()) {
                    try { xdr.recordPortSentinelIntegrityFailure(portSentinelStore.integrityFailureReason()) } catch (error: Exception) { recordXdrFailure("port_sentinel_integrity", error) }
                }
                notifyStateChanged()
                return@submitWorker
            }
            try { xdr.recordPortSentinel(hit.copy(blockedSource = portSentinelStore.isBlocked(hit.sourceAddress))) } catch (error: Exception) { recordXdrFailure("port_sentinel_ingest", error) }
            notifyStateChanged()
        }
    }

    fun setSentinelSourceBlockedAsync(address: String, blocked: Boolean, after: (Boolean) -> Unit) {
        if (!submitWorker("sentinel-blocklist") {
            val ok = portSentinelStore.setBlocked(address, blocked)
            if (ok) {
                try { xdr.recordSentinelBlocklistChange(address, blocked) } catch (error: Exception) { recordXdrFailure("port_sentinel_blocklist", error) }
                notifyStateChanged()
            }
            try { after(ok) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) }
        }) {
            try { after(false) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) }
        }
    }

    fun resetSentinelHistoryAsync(after: (Boolean) -> Unit) {
        if (!submitWorker("sentinel-history-reset") {
            val ok = portSentinelStore.resetHistory()
            if (ok) notifyStateChanged()
            try { after(ok) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) }
        }) {
            try { after(false) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) }
        }
    }

    fun resetSentinelStoreAsync(after: (Boolean) -> Unit) {
        if (!submitWorker("sentinel-store-reset") {
            val ok = portSentinelStore.resetAll()
            if (ok) {
                try { xdr.recordPortSentinelStoreReset() } catch (error: Exception) { recordXdrFailure("port_sentinel_reset", error) }
                notifyStateChanged()
            }
            try { after(ok) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) }
        }) {
            try { after(false) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) }
        }
    }

    fun scanHardeningAsync(after: ((HardeningSnapshot) -> Unit)? = null) {
        if (!submitWorker("hardening-scan") {
            val snapshot = try { hardeningScanner.scan() } catch (error: Throwable) {
                RuntimeFailureLog.nonCritical("hardening-scan", error)
                HardeningSnapshot.pending()
            }
            if (snapshot.checkedAtMillis > 0L) {
                hardeningSnapshot.set(snapshot)
                try { xdr.ingestHardening(snapshot) } catch (error: Throwable) { recordXdrFailure("hardening_ingest", error) }
            }
            after?.let { callback -> try { callback(hardeningSnapshot.get()) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
            notifyStateChanged()
        }) {
            after?.let { callback -> try { callback(hardeningSnapshot.get()) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
        }
    }

    fun refreshOriginLocationAsync(after: ((OriginLocationSnapshot) -> Unit)? = null) {
        if (!submitWorker("origin-refresh") {
            val snapshot = originLocator.refresh()
            notifyStateChanged()
            after?.let { callback -> try { callback(snapshot) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
        }) {
            after?.let { callback -> try { callback(originLocator.snapshot()) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
        }
    }

    fun refreshFeedHealth() {
        feedHealth.set(feeds.healthSnapshot())
    }

    fun initialSetupFeedSyncState(): InitialSetupFeedSyncState = initialSetupFeedSync.get()

    fun startInitialSetupFeedSync(): Boolean {
        if (!initialSetupFeedSyncRunning.compareAndSet(false, true)) return false
        val total = de.visiongaia.gedefense.mobile.core.ThreatFeedCatalog.all.size
        initialSetupFeedSync.set(
            InitialSetupFeedSyncState(
                phase = InitialSetupFeedSyncPhase.SYNCING,
                completedFeeds = 0,
                totalFeeds = total,
            ),
        )
        notifyStateChanged()

        if (!submitWorker("setup-initial-feed-sync") {
            try {
                val report = feeds.syncDue { progress ->
                    initialSetupFeedSync.set(
                        InitialSetupFeedSyncState(
                            phase = InitialSetupFeedSyncPhase.SYNCING,
                            completedFeeds = progress.completed,
                            totalFeeds = progress.total,
                            successfulFeeds = progress.successful,
                            totalRecords = threatIndex.get().count,
                            lastFeedId = progress.lastFeedId.take(MAX_SETUP_FEED_ID_LENGTH),
                        ),
                    )
                    notifyStateChanged()
                }
                refreshFeedHealth()
                state.setFeedSync(report.atMillis)
                try { geoCountry.syncDue() } catch (error: Throwable) { RuntimeFailureLog.nonCritical("app-runtime", error) }
                try { asnEvidence.syncDue() } catch (error: Throwable) { RuntimeFailureLog.nonCritical("app-runtime", error) }

                val policyRecords = threatIndex.get().count
                val ready = policyRecords > 0
                initialSetupFeedSync.set(
                    InitialSetupFeedSyncState(
                        phase = if (ready) InitialSetupFeedSyncPhase.READY else InitialSetupFeedSyncPhase.FAILED,
                        completedFeeds = report.statuses.size,
                        totalFeeds = report.statuses.size,
                        successfulFeeds = report.statuses.count { it.ok },
                        totalRecords = policyRecords,
                        failureCode = if (ready) null else "initial_feed_sync_no_policy",
                    ),
                )
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                initialSetupFeedSync.set(
                    InitialSetupFeedSyncState(
                        phase = InitialSetupFeedSyncPhase.FAILED,
                        totalFeeds = total,
                        failureCode = "initial_feed_sync_interrupted",
                    ),
                )
            } catch (t: Throwable) {
                initialSetupFeedSync.set(
                    InitialSetupFeedSyncState(
                        phase = InitialSetupFeedSyncPhase.FAILED,
                        totalFeeds = total,
                        failureCode = "initial_feed_sync_${t.javaClass.simpleName.ifBlank { "failure" }.lowercase()}".take(96),
                    ),
                )
            } finally {
                initialSetupFeedSyncRunning.set(false)
                notifyStateChanged()
            }
        }) {
            initialSetupFeedSyncRunning.set(false)
            initialSetupFeedSync.set(
                InitialSetupFeedSyncState(
                    phase = InitialSetupFeedSyncPhase.FAILED,
                    totalFeeds = total,
                    failureCode = "initial_feed_sync_queue_rejected",
                ),
            )
            notifyStateChanged()
            return false
        }
        return true
    }

    fun addStateListener(listener: () -> Unit) {
        if (listeners.add(listener) && listeners.size == 1) NativeGaiaNet.setTelemetryDetailed(true)
    }

    fun removeStateListener(listener: () -> Unit) {
        if (listeners.remove(listener) && listeners.isEmpty()) NativeGaiaNet.setTelemetryDetailed(false)
    }

    fun hasStateListeners(): Boolean = listeners.isNotEmpty()
    fun securityBootstrapComplete(): Boolean = bootstrapComplete.count == 0L

    fun awaitSecurityBootstrap(timeoutMillis: Long): Boolean {
        if (timeoutMillis <= 0L) return securityBootstrapComplete()
        return awaitLatch(bootstrapComplete, timeoutMillis)
    }

    fun awaitVpnDisclosureBootstrap(timeoutMillis: Long): Boolean = awaitLatch(vpnDisclosureBootstrap, timeoutMillis)

    fun awaitProtectionStoreBootstrap(mode: ProtectionMode, timeoutMillis: Long): Boolean = when (mode) {
        ProtectionMode.LOCKDOWN -> awaitLatch(firewallPolicyBootstrap, timeoutMillis)
        ProtectionMode.SELECTIVE -> awaitLatch(portSentinelBootstrap, timeoutMillis)
        ProtectionMode.FULL_FLOW_BETA -> awaitLatch(nativeGaiaNetBootstrap, timeoutMillis)
    }

    fun awaitWireGuardBootstrap(timeoutMillis: Long): Boolean = awaitLatch(wireGuardBootstrap, timeoutMillis)

    fun awaitXdrTrustBootstrap(timeoutMillis: Long): Boolean = awaitLatch(xdrTrustBootstrap, timeoutMillis)

    fun awaitBehaviorBootstrap(timeoutMillis: Long): Boolean = awaitLatch(behaviorBootstrap, timeoutMillis)

    fun awaitMalwareAnalysisBootstrap(timeoutMillis: Long): Boolean = awaitLatch(malwareAnalysisBootstrap, timeoutMillis)

    private fun awaitLatch(latch: CountDownLatch, timeoutMillis: Long): Boolean {
        if (latch.count == 0L) return true
        if (timeoutMillis <= 0L) return false
        return try {
            latch.await(timeoutMillis, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
    }

    fun notifyStateChanged() {
        listeners.forEach { listener -> try { listener() } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", error) } }
    }

    private fun safeEvidenceOperation(operation: String, action: () -> LedgerHealth): LedgerHealth = try {
        action()
    } catch (error: Throwable) {
        RuntimeFailureLog.nonCritical("evidence-$operation", error)
        LedgerHealth(ok = false, records = 0L, reason = "evidence_${operation}_unavailable")
    }

    companion object {
        private const val WORKER_THREADS = 4
        private const val WORKER_QUEUE_CAPACITY = 96
        private const val MAX_SETUP_FEED_ID_LENGTH = 64
        private const val CRITICAL_BOOTSTRAP_STAGES = 3
        private const val CRITICAL_BOOTSTRAP_STAGE_TIMEOUT_MS = 6_000L
        private const val XDR_TRUST_BOOTSTRAP_STAGES = 6
        private const val SECONDARY_TRUST_BOOTSTRAP_TIMEOUT_MS = 30_000L
        private const val ANALYSIS_RESTORE_TIMEOUT_MS = 8_000L
        private const val THREAT_SELF_TEST_MAX_FEEDS = 9
        private const val RUNTIME_BOOTSTRAP_DEADLINE_MS = 12_000L
        private const val READINESS_QUEUE_CAPACITY = 16
        private const val DIRECT_GET_TIMEOUT_MS = 15_000L
        @Volatile private var INSTANCE: AppRuntime? = null
        private val initializationStarted = AtomicBoolean(false)
        private val initializationComplete = CountDownLatch(1)
        private val initializationFailure = AtomicReference<String?>(null)
        private val initializer = ThreadPoolExecutor(
            1, 1, 0L, TimeUnit.MILLISECONDS, SynchronousQueue(),
            { runnable -> Thread(runnable, "gedefense-runtime-init").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        )
        private val constructorExecutor = ThreadPoolExecutor(
            1, 1, 0L, TimeUnit.MILLISECONDS, SynchronousQueue(),
            { runnable -> Thread(runnable, "gedefense-runtime-constructor").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        )
        private val readinessExecutor = ThreadPoolExecutor(
            2, 2, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue(READINESS_QUEUE_CAPACITY),
            { runnable -> Thread(runnable, "gedefense-runtime-gate").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        )

        fun initializeAsync(context: Context) {
            if (!initializationStarted.compareAndSet(false, true)) return
            val app = context.applicationContext as? Application
            if (app == null) {
                initializationFailure.set("application_context_unavailable")
                initializationComplete.countDown()
                return
            }
            initializer.execute {
                val future = constructorExecutor.submit<AppRuntime> {
                    SecureTelemetryVault.initialize(app)
                    AppRuntime(app)
                }
                try {
                    val runtime = future.get(RUNTIME_BOOTSTRAP_DEADLINE_MS, TimeUnit.MILLISECONDS)
                    synchronized(this) {
                        if (INSTANCE == null) INSTANCE = runtime
                    }
                } catch (_: TimeoutException) {
                    initializationFailure.compareAndSet(null, "runtime_bootstrap_deadline")
                    future.cancel(true)
                    Log.e(RUNTIME_LOG_TAG, "runtime_bootstrap_deadline")
                } catch (error: Throwable) {
                    val cause = error.cause ?: error
                    val code = "runtime_${cause.javaClass.simpleName.ifBlank { "initialization_failure" }.lowercase()}".take(96)
                    initializationFailure.set(code)
                    Log.e(RUNTIME_LOG_TAG, code)
                } finally {
                    future.cancel(true)
                    constructorExecutor.shutdownNow()
                    initializationComplete.countDown()
                    initializer.shutdown()
                }
            }
        }

        fun awaitInitialized(context: Context, timeoutMillis: Long): AppRuntime? {
            INSTANCE?.let { return it }
            initializeAsync(context)
            if (timeoutMillis <= 0L) return INSTANCE
            val completed = try {
                initializationComplete.await(timeoutMillis, TimeUnit.MILLISECONDS)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return null
            }
            if (!completed) initializationFailure.compareAndSet(null, "runtime_initialization_timeout")
            return INSTANCE
        }

        fun initializationFailure(): String? = initializationFailure.get()

        fun peek(): AppRuntime? = INSTANCE

        fun executeWhenReady(
            context: Context,
            timeoutMillis: Long = DIRECT_GET_TIMEOUT_MS,
            action: (AppRuntime?) -> Unit,
        ) {
            val appContext = context.applicationContext
            try {
                readinessExecutor.execute {
                    val runtime = awaitInitialized(appContext, timeoutMillis)
                    try {
                        action(runtime)
                    } catch (error: RuntimeException) {
                        // Each Android component owns its recovery semantics. The readiness gate must
                        // never crash the process when a receiver/job is already being torn down.
                        RuntimeFailureLog.nonCritical("runtime-ready-callback", error)
                    }
                }
            } catch (error: RejectedExecutionException) {
                RuntimeFailureLog.nonCritical("runtime-ready-rejected", error)
                try { action(null) } catch (callbackError: RuntimeException) { RuntimeFailureLog.nonCritical("app-runtime", callbackError) }
            }
        }

        fun initialize(context: Context): AppRuntime {
            check(Looper.myLooper() != Looper.getMainLooper()) {
                "AppRuntime initialization is forbidden on the Android main thread"
            }
            return awaitInitialized(context, DIRECT_GET_TIMEOUT_MS)
                ?: throw IllegalStateException(initializationFailure() ?: "AppRuntime initialization timed out")
        }

        fun get(context: Context): AppRuntime = INSTANCE ?: run {
            check(Looper.myLooper() != Looper.getMainLooper()) {
                "AppRuntime is not ready on the Android main thread"
            }
            initialize(context)
        }

        private const val RUNTIME_LOG_TAG = "GeDefenseRuntime"
    }
}
