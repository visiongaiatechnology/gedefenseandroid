package de.visiongaia.gedefense.mobile

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.text.InputType
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.Toast
import de.visiongaia.gedefense.mobile.core.EvidenceEvent
import de.visiongaia.gedefense.mobile.core.ThreatFeedCatalog
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

class MainActivity : Activity(), UiActions {
    private val uiHandler = Handler(Looper.getMainLooper())
    private val refreshPending = AtomicBoolean(false)
    private val runtimeRefreshRunnable = Runnable {
        refreshPending.set(false)
        if (!isFinishing && !isDestroyed) refresh()
    }
    private val runtimeListener: () -> Unit = {
        if (::runtime.isInitialized && runtime.state.isVpnActive()) runtime.setup.completePendingUpdateAfterProtection()
        scheduleRuntimeRefresh()
    }
    private val setupListener: () -> Unit = {
        uiHandler.post {
            if (!isFinishing && !isDestroyed) {
                routeStartupExperienceIfReady()
                scheduleRuntimeRefresh()
            }
        }
    }
    private lateinit var runtime: AppRuntime
    private lateinit var contentHost: FrameLayout
    private lateinit var safeShell: LinearLayout
    private lateinit var bottomNav: BottomNavBar
    private lateinit var dashboard: DashboardScreen
    private lateinit var threatScreen: ThreatScreen
    private lateinit var protectionHub: ProtectionHubScreen
    private lateinit var analysisHub: AnalysisHubScreen
    private lateinit var systemHub: SystemHubScreen
    private lateinit var screens: List<View>
    private var selectedScreen = 0
    private var startupExperienceRouted = false
    private var syncing = false
    private var verifying = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val initialized = AppRuntime.peek()
        if (initialized == null) {
            startActivity(Intent(this, StartupActivity::class.java))
            finish()
            return
        }
        runtime = initialized
        startupExperienceRouted = savedInstanceState?.getBoolean(STATE_STARTUP_EXPERIENCE_ROUTED, false) ?: false
        configureSystemBars()
        setContentView(buildUi())
        routeStartupExperienceIfReady()
        refresh()
    }

    override fun onStart() {
        super.onStart()
        if (!::runtime.isInitialized) return
        runtime.addStateListener(runtimeListener)
        runtime.setup.addStateListener(setupListener)
        routeStartupExperienceIfReady()
    }

    override fun onResume() {
        super.onResume()
        if (!::runtime.isInitialized) return
        if (TitanVisualMode.refresh(this)) {
            recreate()
            return
        }
        runtime.refreshOriginLocationAsync { runOnUiThread { if (!isFinishing && !isDestroyed) refresh() } }
        if (runtime.state.isVpnActive()) {
            runtime.setup.completePendingUpdateAfterProtection()
            try {
                startService(Intent(this, GeDefenseVpnService::class.java).setAction(GeDefenseVpnService.ACTION_RESILIENCE_PROBE))
            } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("main-activity", error) }
        }
        refresh()
    }

    override fun onStop() {
        if (::runtime.isInitialized) {
            runtime.removeStateListener(runtimeListener)
            runtime.setup.removeStateListener(setupListener)
        }
        uiHandler.removeCallbacks(runtimeRefreshRunnable)
        refreshPending.set(false)
        super.onStop()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putBoolean(STATE_STARTUP_EXPERIENCE_ROUTED, startupExperienceRouted)
        super.onSaveInstanceState(outState)
    }

    private fun routeStartupExperienceIfReady() {
        if (startupExperienceRouted || !::runtime.isInitialized) return
        val setup = runtime.setup
        if (!setup.isPreferenceStateLoaded()) return
        startupExperienceRouted = true
        when {
            !setup.isWizardCompleted() -> startActivityForResult(
                Intent(this, SetupWizardActivity::class.java)
                    .putExtra(SetupWizardActivity.EXTRA_FIRST_RUN, true),
                SETUP_REQUEST,
            )
            setup.shouldShowUpdateExperience() -> startActivityForResult(
                Intent(this, UpdateExperienceActivity::class.java),
                UPDATE_REQUEST,
            )
        }
    }

    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        if (event.actionMasked == MotionEvent.ACTION_DOWN || event.actionMasked == MotionEvent.ACTION_MOVE) {
            VgtUiPerformance.noteInteraction()
        }
        return super.dispatchTouchEvent(event)
    }

    private fun scheduleRuntimeRefresh() {
        if (refreshPending.compareAndSet(false, true)) {
            uiHandler.postDelayed(runtimeRefreshRunnable, UI_REFRESH_COALESCE_MS)
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == MAP_LOCATION_PERMISSION_REQUEST) {
            runtime.refreshOriginLocationAsync { runOnUiThread { if (!isFinishing && !isDestroyed) refresh() } }
            Toast.makeText(
                this,
                getString(if (runtime.originLocator.hasCoarsePermission()) R.string.traffic_map_location_enabled else R.string.traffic_map_location_fallback),
                Toast.LENGTH_LONG,
            ).show()
            refresh()
        }
    }

    @Deprecated("VpnService consent still uses activity result on the current minimum API")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when {
            requestCode == SETUP_REQUEST && resultCode == RESULT_OK &&
                data?.getBooleanExtra(SetupWizardActivity.EXTRA_REQUEST_PROTECTION_ACTIVATION, false) == true -> requestVpn()
            requestCode == UPDATE_REQUEST && resultCode == RESULT_OK &&
                data?.getBooleanExtra(UpdateExperienceActivity.EXTRA_REQUEST_PROTECTION_ACTIVATION, false) == true -> requestVpn()
            requestCode == VPN_DISCLOSURE_REQUEST && resultCode == RESULT_OK -> requestVpn()
            requestCode == VPN_REQUEST && resultCode == RESULT_OK -> startProtection()
        }
    }

    override fun activateProtection() = requestVpn()

    override fun deactivateProtection() {
        val titan = runtime.titan.snapshot()
        val platformAlwaysOn = runtime.state.platformAlwaysOn()
        if (titan.alwaysOnVpn || platformAlwaysOn) {
            Toast.makeText(this, getString(R.string.always_on_release_first), Toast.LENGTH_LONG).show()
            configureAlwaysOnProtection()
            return
        }
        startService(Intent(this, GeDefenseVpnService::class.java).setAction(GeDefenseVpnService.ACTION_STOP))
        refresh()
    }

    override fun synchronizeFeeds() = syncFeeds()

    override fun verifyEvidence() = verifyEvidenceLedger()

    override fun recoverEvidence() = showRecoveryDialog()

    override fun verifyIntegrity() {
        runtime.verifyIntegrityAsync { result ->
            runOnUiThread {
                if (!result.ok) runtime.requestIntegrityFailClosed("manual_integrity_check")
                Toast.makeText(
                    this,
                    if (result.ok) getString(R.string.integrity_check_ok) else getString(R.string.integrity_check_failed),
                    Toast.LENGTH_LONG,
                ).show()
                refresh()
            }
        }
    }

    override fun scanInstalledApps() {
        openMalwareScanner()
    }

    override fun openMalwareScanner() {
        startActivity(Intent(this, ScannerActivity::class.java))
    }

    override fun openSetupWizard() {
        startActivity(Intent(this, SetupWizardActivity::class.java))
    }

    override fun openNetworkFirewall() {
        startActivity(Intent(this, FirewallActivity::class.java))
    }

    override fun openWireGuard() {
        startActivity(Intent(this, WireGuardActivity::class.java))
    }

    override fun openXdrCenter() {
        startActivity(Intent(this, XdrActivity::class.java))
    }

    override fun openXdrForPackage(packageName: String) {
        val safe = packageName.takeIf { it.length in 3..256 && it.contains('.') && it.none(Char::isWhitespace) } ?: return
        startActivity(Intent(this, XdrActivity::class.java).putExtra(XdrActivity.EXTRA_PACKAGE, safe))
    }

    override fun openHardeningCenter() {
        startActivity(Intent(this, HardeningActivity::class.java))
    }

    override fun openNetworkDiscovery() {
        startActivity(Intent(this, NetworkDiscoveryActivity::class.java))
    }

    override fun openPortSentinel() {
        startActivity(Intent(this, PortSentinelActivity::class.java))
    }

    override fun openTitan() {
        startActivity(Intent(this, TitanActivity::class.java))
    }

    override fun openBehaviorCenter() {
        startActivity(Intent(this, BehaviorActivity::class.java))
    }

    override fun configureAlwaysOnProtection() {
        val titan = runtime.titan.snapshot()
        if (titan.titanActive) {
            if (titan.alwaysOnVpn && titan.alwaysOnLockdown) {
                openTitan()
                return
            }
            val accepted = runtime.executeBackground("main-enable-always-on") {
                val result = runtime.titan.setAlwaysOnVpnLockdown(true)
                if (result.ok) runtime.state.setResilienceDesired(true)
                runOnUiThread {
                    if (isFinishing || isDestroyed) return@runOnUiThread
                    if (result.ok) {
                        Toast.makeText(this, getString(R.string.always_on_titan_enabled), Toast.LENGTH_LONG).show()
                        if (!runtime.state.isVpnActive()) requestVpn()
                    } else {
                        Toast.makeText(this, getString(R.string.always_on_titan_failed, result.code), Toast.LENGTH_LONG).show()
                    }
                    refresh()
                }
            }
            if (!accepted) Toast.makeText(this, getString(R.string.always_on_titan_failed, "runtime_worker_busy"), Toast.LENGTH_LONG).show()
            return
        }

        runtime.state.setResilienceDesired(true)
        val opened = runtime.setup.openVpnSettings(this)
        if (!opened) {
            try { startActivity(Intent(Settings.ACTION_SETTINGS)) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("main-activity", error) }
        }
        Toast.makeText(this, getString(R.string.always_on_system_instructions), Toast.LENGTH_LONG).show()
        refresh()
    }

    override fun runResilienceSelfTest() {
        val snapshot = snapshot()
        if (!snapshot.vpnActive || !snapshot.killSwitchConfigured || snapshot.protectionMode != ProtectionMode.FULL_FLOW_BETA || snapshot.vpnStatus == "RECOVERING" || snapshot.resilienceSelfTestStatus == "RUNNING") {
            Toast.makeText(this, getString(R.string.resilience_self_test_unavailable), Toast.LENGTH_LONG).show()
            return
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.resilience_self_test_title)
            .setMessage(R.string.resilience_self_test_confirm)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.resilience_self_test_action) { _, _ ->
                try {
                    startService(Intent(this, GeDefenseVpnService::class.java).setAction(GeDefenseVpnService.ACTION_RECOVERY_SELF_TEST))
                    Toast.makeText(this, getString(R.string.resilience_self_test_started), Toast.LENGTH_LONG).show()
                } catch (_: RuntimeException) {
                    Toast.makeText(this, getString(R.string.resilience_self_test_failed), Toast.LENGTH_LONG).show()
                }
            }
            .show()
    }

    override fun refreshTrafficUsage() {
        runtime.refreshTrafficAsync { result ->
            runOnUiThread {
                if (result.state == "PERMISSION_REQUIRED") {
                    Toast.makeText(this, getString(R.string.traffic_usage_required), Toast.LENGTH_LONG).show()
                }
                refresh()
            }
        }
    }

    override fun openUsageAccessSettings() {
        if (!runtime.setup.openUsageAccess(this)) {
            try { startActivity(Intent(Settings.ACTION_SETTINGS)) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("main-activity", error) }
        }
    }

    override fun requestTrafficMapLocation() {
        if (runtime.originLocator.hasCoarsePermission()) {
            runtime.refreshOriginLocationAsync { runOnUiThread { if (!isFinishing && !isDestroyed) refresh() } }
            return
        }
        requestPermissions(arrayOf(Manifest.permission.ACCESS_COARSE_LOCATION), MAP_LOCATION_PERMISSION_REQUEST)
    }

    override fun setProtectionMode(mode: ProtectionMode) {
        if (runtime.state.isVpnActive()) {
            Toast.makeText(this, getString(R.string.mode_change_while_active), Toast.LENGTH_LONG).show()
            return
        }
        if (mode == ProtectionMode.FULL_FLOW_BETA && !NativeGaiaNet.available) {
            Toast.makeText(this, getString(R.string.full_flow_native_missing), Toast.LENGTH_LONG).show()
            return
        }
        try { runtime.state.setProtectionMode(mode) } catch (_: IllegalArgumentException) { return }
        refresh()
    }

    override fun navigateTo(index: Int) {
        if (index !in screens.indices || index == selectedScreen) return
        VgtUiPerformance.noteInteraction()
        selectedScreen = index
        contentHost.removeAllViews()
        contentHost.addView(screens[index], FrameLayout.LayoutParams(-1, -1))
        bottomNav.select(index)
        refresh()
    }

    private fun buildUi(): View {
        val root = FrameLayout(this).apply { setBackgroundColor(GeDefenseUi.bg) }
        root.addView(CyberBackgroundView(this), FrameLayout.LayoutParams(-1, -1))

        safeShell = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        root.addView(safeShell, FrameLayout.LayoutParams(-1, -1))

        dashboard = DashboardScreen(this, this)
        threatScreen = ThreatScreen(this, this)
        protectionHub = ProtectionHubScreen(this, this)
        analysisHub = AnalysisHubScreen(this, this)
        systemHub = SystemHubScreen(this, this)
        screens = listOf(dashboard.view, threatScreen.view, protectionHub.view, analysisHub.view, systemHub.view)

        if (TitanVisualMode.active) {
            safeShell.addView(
                TitanManagedBanner(this) { openTitan() },
                LinearLayout.LayoutParams(-1, -2).apply {
                    leftMargin = GeDefenseUi.dp(this@MainActivity, 18)
                    rightMargin = GeDefenseUi.dp(this@MainActivity, 18)
                    bottomMargin = GeDefenseUi.dp(this@MainActivity, 8)
                },
            )
        }

        contentHost = FrameLayout(this).apply {
            clipToPadding = false
            addView(screens[selectedScreen], FrameLayout.LayoutParams(-1, -1))
        }
        safeShell.addView(contentHost, LinearLayout.LayoutParams(-1, 0, 1f))

        bottomNav = BottomNavBar(this) { navigateTo(it) }
        safeShell.addView(bottomNav, LinearLayout.LayoutParams(-1, -2).apply {
            leftMargin = GeDefenseUi.dp(this@MainActivity, 18)
            rightMargin = GeDefenseUi.dp(this@MainActivity, 18)
            bottomMargin = GeDefenseUi.dp(this@MainActivity, GeDefenseUi.BOTTOM_NAV_MARGIN_DP)
        })

        root.setOnApplyWindowInsetsListener { _, insets ->
            val safe = VgtWindowInsets.safeArea(insets)
            safeShell.setPadding(safe.left, safe.top + GeDefenseUi.dp(this, 8), safe.right, 0)
            bottomNav.setBottomInset(safe.bottom)

            val scrollReserved = GeDefenseUi.scrollReservedBottomPadding(this, safe.bottom)
            dashboard.setBottomPadding(scrollReserved)
            threatScreen.setBottomPadding(scrollReserved)
            protectionHub.setBottomPadding(scrollReserved)
            analysisHub.setBottomPadding(scrollReserved)
            systemHub.setBottomPadding(scrollReserved)

            insets
        }
        root.post { root.requestApplyInsets() }
        return root
    }

    private fun configureSystemBars() = VgtWindowInsets.configureSystemBars(window)

    private fun refresh() {
        if (!::dashboard.isInitialized) return
        val snapshot = snapshot()
        when (selectedScreen) {
            0 -> {
                dashboard.update(snapshot)
                dashboard.setSyncing(syncing)
            }
            1 -> threatScreen.update(snapshot)
            2 -> {
                protectionHub.update(snapshot)
                protectionHub.setSyncing(syncing)
            }
            3 -> {
                analysisHub.update(snapshot)
                analysisHub.setVerifying(verifying)
            }
            4 -> systemHub.update(snapshot)
        }
    }

    private fun snapshot(): UiSnapshot {
        val index = runtime.threatIndex.get()
        val metrics = runtime.metrics.snapshot()
        val evidence = runtime.evidenceHealth
        val healthById = runtime.feedHealth.get().associateBy { it.id }
        val feeds = ThreatFeedCatalog.all.map { feed ->
            val health = healthById[feed.id]
            FeedUiSnapshot(
                id = feed.id,
                name = feed.name,
                enforcement = feed.enforcement,
                available = health?.available == true,
                fresh = health?.fresh == true,
                records = health?.records ?: 0,
                fetchedAtMillis = health?.fetchedAtMillis ?: 0L,
            )
        }
        return UiSnapshot(
            vpnStatus = runtime.state.lastVpnStatus(),
            vpnReason = runtime.state.lastVpnReason(),
            vpnActive = runtime.state.isVpnActive(),
            indexedPrefixes = index.count,
            routeCandidates = index.routeCandidateCount,
            compactedRoutes = index.routePrefixes.size,
            routeOverflow = index.routeOverflow,
            routePolicySha256 = index.routePolicySha256,
            fullPolicySha256 = index.fullPolicySha256,
            lastFeedSync = runtime.state.lastFeedSync(),
            blockedPackets = metrics.blockedPackets,
            blockedBytes = metrics.blockedBytes,
            uniqueDestinations = metrics.uniqueDestinations,
            attributedApps = metrics.attributedApps,
            activeFlows = metrics.activeFlows,
            lastBlockedAtMillis = metrics.lastBlockedAtMillis,
            evidenceOk = evidence.ok,
            evidenceRecords = evidence.records,
            evidenceReason = evidence.reason,
            evidenceInvalidLine = evidence.invalidLine,
            feeds = feeds,
            integrity = runtime.integritySnapshot.get(),
            appScan = runtime.appScanSnapshot.get(),
            deviceScan = runtime.deviceScanSnapshot.get(),
            traffic = runtime.trafficSnapshot.get(),
            usageAccessGranted = runtime.trafficUsage.hasUsageAccess(),
            protectionMode = runtime.state.protectionMode(),
            wireGuardEgressMode = runtime.state.wireGuardEgressMode(),
            wireGuard = runtime.wireGuard.status(),
            nativeFullFlowAvailable = NativeGaiaNet.available,
            fullFlow = runtime.fullFlowAnalytics.snapshot(),
            geoCountry = runtime.geoCountry.snapshot(),
            originLocation = runtime.originLocator.snapshot(),
            hardening = runtime.hardeningSnapshot.get(),
            titan = runtime.titan.snapshot(),
            setup = runtime.setup.snapshot(),
            xdr = runtime.xdr.snapshot(),
            resilienceDesired = runtime.state.resilienceDesired(),
            platformAlwaysOn = runtime.state.platformAlwaysOn(),
            platformLockdown = runtime.state.platformLockdown(),
            platformPolicyObservedAtMillis = runtime.state.platformPolicyObservedAtMillis(),
            transportPowerConstrained = runtime.state.transportPowerConstrained(),
            vpnRecoveryCount = runtime.state.vpnRecoveryCount(),
            lastVpnRecoveryAtMillis = runtime.state.lastVpnRecoveryAtMillis(),
            lastVpnRecoveryReason = runtime.state.lastVpnRecoveryReason(),
            resilienceSelfTestStatus = runtime.state.lastResilienceSelfTestStatus(),
            resilienceSelfTestAtMillis = runtime.state.lastResilienceSelfTestAtMillis(),
            resilienceSelfTestDurationMillis = runtime.state.lastResilienceSelfTestDurationMillis(),
        )
    }

    private fun syncFeeds() {
        if (syncing) return
        syncing = true
        refresh()
        if (!runtime.executeBackground("feed-sync") {
            val report = try { runtime.feeds.syncDue() } catch (error: Throwable) {
                RuntimeFailureLog.nonCritical("manual-feed-sync", error)
                null
            }
            val geo = try { runtime.geoCountry.syncDue() } catch (error: Throwable) {
                RuntimeFailureLog.nonCritical("manual-geo-sync", error)
                runtime.geoCountry.snapshot()
            }
            if (report != null) runtime.refreshFeedHealth()
            runOnUiThread {
                syncing = false
                if (report != null) {
                    runtime.state.setFeedSync(report.atMillis)
                    val message = if (report.routeOverflow) {
                        getString(R.string.sync_result_overflow, report.statuses.count { it.ok }, report.statuses.size, report.totalRecords)
                    } else {
                        getString(R.string.sync_result, report.statuses.count { it.ok }, report.statuses.size, report.totalRecords)
                    }
                    val combined = if (geo.ready) message + " · " + getString(R.string.geo_ready_short, geo.v4Records + geo.v6Records)
                    else message + " · " + getString(R.string.geo_not_ready_short)
                    Toast.makeText(this, combined, Toast.LENGTH_LONG).show()
                    if (runtime.state.isVpnActive()) {
                        startService(Intent(this, GeDefenseVpnService::class.java).setAction(GeDefenseVpnService.ACTION_REFRESH))
                    }
                } else {
                    Toast.makeText(this, getString(R.string.sync_failed), Toast.LENGTH_LONG).show()
                }
                refresh()
            }
        }) {
            syncing = false
            Toast.makeText(this, getString(R.string.sync_failed), Toast.LENGTH_LONG).show()
            refresh()
        }
    }

    private fun verifyEvidenceLedger() {
        if (verifying) return
        verifying = true
        refresh()
        runtime.verifyEvidenceAsync {
            runOnUiThread {
                verifying = false
                if (runtime.state.isVpnActive()) {
                    startService(Intent(this, GeDefenseVpnService::class.java).setAction(GeDefenseVpnService.ACTION_REEVALUATE))
                }
                refresh()
            }
        }
    }

    @Suppress("DEPRECATION")
    private fun requestVpn() {
        if (runtime.state.isVpnActive()) return

        // Activation readiness intentionally avoids constructing the full UI/XDR snapshot. The
        // consent path must remain a bounded main-thread operation even when trust stores contain
        // substantial history. Heavy policy/tunnel work is owned by GeDefenseVpnService.
        val mode = runtime.state.protectionMode()
        val index = runtime.threatIndex.get()
        val wireGuardMode = runtime.state.wireGuardEgressMode()
        val wireGuardStatus = runtime.wireGuard.status()
        val wireGuardReady = when (wireGuardMode) {
            WireGuardEgressMode.DIRECT -> true
            WireGuardEgressMode.WIREGUARD -> wireGuardStatus.initialized && wireGuardStatus.integrityOk && wireGuardStatus.configured
            WireGuardEgressMode.WIREGUARD_STRICT -> wireGuardStatus.initialized && wireGuardStatus.integrityOk && wireGuardStatus.configured &&
                (runtime.state.platformLockdown() || runtime.titan.snapshot().alwaysOnLockdown)
        }
        val policyReady = when (mode) {
            ProtectionMode.SELECTIVE -> index.routePrefixes.isNotEmpty() && !index.routeOverflow
            ProtectionMode.FULL_FLOW_BETA -> index.count > 0 && NativeGaiaNet.available && wireGuardReady
            ProtectionMode.LOCKDOWN -> true
        }
        val evidence = runtime.evidenceHealth
        val integrity = runtime.integritySnapshot.get()
        if (!policyReady || !evidence.ok || !integrity.ok) {
            if (!integrity.ok) {
                val reason = integrity.issues.firstOrNull { it.severity == IntegritySeverity.CRITICAL }?.code
                    ?: integrity.issues.firstOrNull()?.code
                    ?: if (integrity.state == "PENDING") "integrity_scan_pending" else "application_integrity_unhealthy"
                runtime.state.setVpnStatus("DEGRADED_INTEGRITY", reason)
                runtime.notifyStateChanged()
                refresh()
            }
            Toast.makeText(this, getString(R.string.ui_protection_not_ready), Toast.LENGTH_LONG).show()
            return
        }
        if (!runtime.vpnDisclosure.isAccepted()) {
            startActivityForResult(Intent(this, VpnDisclosureActivity::class.java), VPN_DISCLOSURE_REQUEST)
            return
        }
        val intent = VpnService.prepare(this)
        if (intent != null) startActivityForResult(intent, VPN_REQUEST) else startProtection()
    }

    private fun startProtection() {
        runtime.state.setVpnStatus("STARTING", null)
        try {
            startForegroundService(Intent(this, GeDefenseVpnService::class.java).setAction(GeDefenseVpnService.ACTION_START))
        } catch (t: RuntimeException) {
            val reason = "service_start_${t.javaClass.simpleName.ifBlank { "runtime_failure" }.lowercase()}".take(120)
            runtime.state.setVpnActive(false)
            runtime.state.setVpnStatus("START_FAILED", reason)
            runtime.notifyStateChanged()
            Toast.makeText(this, getString(R.string.ui_protection_not_ready), Toast.LENGTH_LONG).show()
        }
        refresh()
    }

    private fun showRecoveryDialog() {
        if (runtime.evidenceHealth.ok) return
        val input = EditText(this).apply {
            hint = getString(R.string.recovery_reason_hint)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
            maxLines = 4
            setTextColor(GeDefenseUi.text)
            setHintTextColor(GeDefenseUi.textDim)
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle(R.string.recovery_title)
            .setMessage(R.string.recovery_warning)
            .setView(input)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.recover_confirm, null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val reason = input.text?.toString()?.trim().orEmpty()
                if (reason.length < 8) {
                    input.error = getString(R.string.recovery_reason_short)
                    return@setOnClickListener
                }
                dialog.dismiss()
                recoverEvidenceInternal(reason)
            }
        }
        dialog.show()
    }

    private fun recoverEvidenceInternal(reason: String) {
        if (!runtime.executeBackground("evidence-recovery") {
            val ok = try {
                val recovered = runtime.evidence.recover(File(noBackupFilesDir, "evidence/recovery"), reason)
                val signatureOk = try {
                    HybridArtifactSigner(applicationContext).writeDetachedSignature(recovered.manifest)
                    true
                } catch (error: Throwable) {
                    RuntimeFailureLog.nonCritical("evidence-recovery-signature", error)
                    false
                }
                if (!signatureOk) {
                    try {
                        runtime.evidence.append(EvidenceEvent(
                            type = "evidence.recovery.signature",
                            severity = "medium",
                            subject = "local",
                            detail = "detached artifact signature unavailable",
                        ))
                    } catch (error: Throwable) {
                        runtime.recordEvidenceFailure("recovery_signature_event", error)
                    }
                }
                runtime.refreshEvidenceHealth()
                true
            } catch (error: Throwable) {
                RuntimeFailureLog.nonCritical("evidence-recovery", error)
                false
            }
            runOnUiThread {
                Toast.makeText(
                    this,
                    if (ok) getString(R.string.recovery_ok) else getString(R.string.recovery_failed),
                    Toast.LENGTH_LONG,
                ).show()
                refresh()
            }
        }) {
            Toast.makeText(this, getString(R.string.recovery_failed), Toast.LENGTH_LONG).show()
        }
    }

    companion object {
        private const val VPN_REQUEST = 4701
        private const val VPN_DISCLOSURE_REQUEST = 4702
        private const val SETUP_REQUEST = 4703
        private const val UPDATE_REQUEST = 1005
        private const val STATE_STARTUP_EXPERIENCE_ROUTED = "main_startup_experience_routed"
        private const val NOTIFICATION_PERMISSION_REQUEST = 77
        private const val MAP_LOCATION_PERMISSION_REQUEST = 78
        private const val UI_REFRESH_COALESCE_MS = 120L
    }
}
