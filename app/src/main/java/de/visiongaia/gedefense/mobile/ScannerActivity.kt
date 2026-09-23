package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

class ScannerActivity : Activity() {
    private lateinit var runtime: AppRuntime
    private val listener: () -> Unit = { runOnUiThread { if (!isFinishing) refresh() } }

    private lateinit var rootLayout: LinearLayout
    private lateinit var radar: ScannerRadarView
    private lateinit var progress: VgtProgressView
    private lateinit var phaseText: TextView
    private lateinit var currentText: TextView
    private lateinit var statApps: TextView
    private lateinit var statFiles: TextView
    private lateinit var statFindings: TextView
    private lateinit var actionButton: TextView
    private lateinit var storageAccessCard: View
    private lateinit var installGuardState: TextView
    private lateinit var installGuardDetail: TextView
    private lateinit var tabOverview: TextView
    private lateinit var tabApps: TextView
    private lateinit var tabFiles: TextView
    private lateinit var resultsHost: LinearLayout
    private var selectedTab = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runtime = RuntimeActivityEntry.requireReady(this) ?: return
        configureSystemBars()
        setContentView(buildUi())
        refresh()
    }

    override fun onStart() {
        super.onStart()
        runtime.addStateListener(listener)
    }

    override fun onStop() {
        runtime.removeStateListener(listener)
        super.onStop()
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    private fun buildUi(): View {
        val root = FrameLayout(this).apply { setBackgroundColor(GeDefenseUi.bg) }
        root.addView(CyberBackgroundView(this), FrameLayout.LayoutParams(-1, -1))

        val scroll = ScrollView(this).apply {
            clipToPadding = false
            overScrollMode = View.OVER_SCROLL_NEVER
        }
        VgtUiPerformance.bindScroll(scroll)
        rootLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(18), dp(24), dp(40))
        }
        scroll.addView(rootLayout, FrameLayout.LayoutParams(-1, -2))
        root.addView(scroll, FrameLayout.LayoutParams(-1, -1))

        rootLayout.addView(VgtUiComponents.screenHeader(
            this,
            getString(R.string.scanner_title),
            getString(R.string.scanner_subtitle),
        ))
        GeDefenseUi.addVerticalGap(rootLayout, this, 16)

        rootLayout.addView(buildScannerHero())
        GeDefenseUi.addVerticalGap(rootLayout, this, 16)

        rootLayout.addView(buildInstallGuardCard())
        GeDefenseUi.addVerticalGap(rootLayout, this, 16)

        storageAccessCard = buildStorageAccessCard()
        rootLayout.addView(storageAccessCard)
        GeDefenseUi.addVerticalGap(rootLayout, this, 16)

        rootLayout.addView(buildTabs())
        GeDefenseUi.addVerticalGap(rootLayout, this, 12)

        resultsHost = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        rootLayout.addView(resultsHost)

        root.setOnApplyWindowInsetsListener { _, insets ->
            val safe = VgtWindowInsets.safeArea(insets)
            rootLayout.setPadding(dp(24) + safe.left, dp(18) + safe.top, dp(24) + safe.right, dp(40) + safe.bottom)
            insets
        }
        root.post { root.requestApplyInsets() }
        return root
    }

    private fun buildScannerHero(): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@ScannerActivity, accent = GeDefenseUi.cyan, radius = 22)
        val content = LinearLayout(this@ScannerActivity).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(20), dp(20), dp(20), dp(20))

            radar = ScannerRadarView(this@ScannerActivity)
            addView(radar, LinearLayout.LayoutParams(dp(168), dp(168)))

            phaseText = GeDefenseUi.textView(this@ScannerActivity, "", 18f, GeDefenseUi.cyan, bold = true).apply {
                gravity = Gravity.CENTER
            }
            addView(phaseText, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })

            currentText = GeDefenseUi.textView(this@ScannerActivity, "", 10.2f, GeDefenseUi.textDim).apply {
                gravity = Gravity.CENTER
                maxLines = 2
            }
            addView(currentText, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(6) })

            progress = VgtProgressView(this@ScannerActivity, GeDefenseUi.cyan)
            addView(progress, LinearLayout.LayoutParams(-1, dp(6)).apply { topMargin = dp(16) })

            val stats = LinearLayout(this@ScannerActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER
            }
            statApps = metricValue()
            statFiles = metricValue()
            statFindings = metricValue()
            stats.addView(metricColumn(getString(R.string.scanner_stat_apps), statApps), LinearLayout.LayoutParams(0, -2, 1f))
            stats.addView(metricColumn(getString(R.string.scanner_stat_files), statFiles), LinearLayout.LayoutParams(0, -2, 1f))
            stats.addView(metricColumn(getString(R.string.scanner_stat_findings), statFindings), LinearLayout.LayoutParams(0, -2, 1f))
            addView(stats, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(18) })

            actionButton = GeDefenseUi.actionButton(this@ScannerActivity, getString(R.string.scanner_start), goldStyle = true) {
                if (runtime.isDeviceScanRunning()) runtime.cancelDeviceScan()
                else runtime.startDeviceScanAsync()
            }
            addView(actionButton, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(18) })
        }
        addView(content, FrameLayout.LayoutParams(-1, -2))
    }

    private fun buildInstallGuardCard(): View = FrameLayout(this).apply {
        background = GeDefenseUi.softPanelBackground(this@ScannerActivity, 16, GeDefenseUi.cyan)
        addView(LinearLayout(this@ScannerActivity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(18), dp(14), dp(18), dp(14))
            addView(VgtUiComponents.iconWell(this@ScannerActivity, VgtIcon.SHIELD, GeDefenseUi.cyan, 34), LinearLayout.LayoutParams(dp(34), dp(34)))
            addView(LinearLayout(this@ScannerActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(12), 0, 0, 0)
                addView(GeDefenseUi.textView(this@ScannerActivity, getString(R.string.scanner_install_guard_title), 12.3f, GeDefenseUi.text, bold = true))
                installGuardState = GeDefenseUi.textView(this@ScannerActivity, "", 10f, GeDefenseUi.cyan, bold = true).apply {
                    setPadding(0, dp(3), 0, 0)
                }
                addView(installGuardState)
                installGuardDetail = GeDefenseUi.textView(this@ScannerActivity, "", 9.4f, GeDefenseUi.textDim).apply {
                    setPadding(0, dp(3), 0, 0)
                    maxLines = 3
                }
                addView(installGuardDetail)
            }, LinearLayout.LayoutParams(0, -2, 1f))
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun buildStorageAccessCard(): View = FrameLayout(this).apply {
        background = GeDefenseUi.softPanelBackground(this@ScannerActivity, 16, GeDefenseUi.gold)
        val content = LinearLayout(this@ScannerActivity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(18), dp(14), dp(18), dp(14))
            addView(VgtUiComponents.iconWell(this@ScannerActivity, VgtIcon.SCANNER, GeDefenseUi.gold, 34), LinearLayout.LayoutParams(dp(34), dp(34)))
            addView(LinearLayout(this@ScannerActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(12), 0, dp(10), 0)
                addView(GeDefenseUi.textView(this@ScannerActivity, getString(R.string.scanner_storage_access_title), 12.3f, GeDefenseUi.text, bold = true))
                addView(GeDefenseUi.textView(this@ScannerActivity, getString(R.string.scanner_storage_access_body), 9.7f, GeDefenseUi.textDim).apply {
                    setPadding(0, dp(3), 0, 0)
                })
            }, LinearLayout.LayoutParams(0, -2, 1f))
            addView(GeDefenseUi.pill(this@ScannerActivity, getString(R.string.setup_status_open), GeDefenseUi.gold).apply {
                setOnClickListener {
                    val manager = runtime.setup
                    if (Build.VERSION.SDK_INT >= 30) manager.openAllFilesAccess(this@ScannerActivity)
                    else startActivity(Intent(this@ScannerActivity, SetupWizardActivity::class.java))
                }
                isClickable = true
                isFocusable = true
            })
        }
        addView(content, FrameLayout.LayoutParams(-1, -2))
    }

    private fun buildTabs(): View = FrameLayout(this).apply {
        background = GeDefenseUi.softPanelBackground(this@ScannerActivity, 16, GeDefenseUi.cyan)
        val row = LinearLayout(this@ScannerActivity).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(6), dp(6), dp(6), dp(6))
        }
        tabOverview = tabButton(getString(R.string.scanner_tab_overview), 0)
        tabApps = tabButton(getString(R.string.scanner_tab_apps), 1)
        tabFiles = tabButton(getString(R.string.scanner_tab_files), 2)
        row.addView(tabOverview, LinearLayout.LayoutParams(0, dp(44), 1f))
        row.addView(tabApps, LinearLayout.LayoutParams(0, dp(44), 1f).apply { leftMargin = dp(6) })
        row.addView(tabFiles, LinearLayout.LayoutParams(0, dp(44), 1f).apply { leftMargin = dp(6) })
        addView(row, FrameLayout.LayoutParams(-1, -2))
    }

    private fun tabButton(label: String, tab: Int): TextView = GeDefenseUi.textView(this, label, 10.8f, GeDefenseUi.textMuted, bold = true).apply {
        gravity = Gravity.CENTER
        isClickable = true
        isFocusable = true
        setOnClickListener {
            selectedTab = tab
            refreshTabs()
            renderResults(runtime.deviceScanSnapshot.get())
        }
    }

    private fun refresh() {
        val snapshot = runtime.deviceScanSnapshot.get()
        val running = runtime.isDeviceScanRunning()
        val access = runtime.setup.hasAllFilesAccess()
        storageAccessCard.visibility = if (access) View.GONE else View.VISIBLE
        val installGuardActive = runtime.installGuard.activeStates()
        installGuardState.text = if (installGuardActive.isEmpty()) {
            getString(R.string.scanner_install_guard_ready)
        } else {
            resources.getQuantityString(R.plurals.scanner_install_guard_scanning, installGuardActive.size, installGuardActive.size)
        }
        installGuardState.setTextColor(if (installGuardActive.isEmpty()) GeDefenseUi.green else GeDefenseUi.gold)
        installGuardDetail.text = if (installGuardActive.isEmpty()) {
            getString(R.string.scanner_install_guard_body)
        } else {
            installGuardActive.take(3).joinToString("\n") { state ->
                val stage = when (state.stage) {
                    InstallGuardStage.FAST_VERDICT -> getString(R.string.scanner_install_guard_stage_fast)
                    InstallGuardStage.DEEP_SCAN -> getString(R.string.scanner_install_guard_stage_deep)
                }
                getString(R.string.scanner_install_guard_active_body, state.packageName, stage)
            }
        }

        val phaseColor = when (snapshot.progress.phase) {
            DeviceScanPhase.FAILED -> GeDefenseUi.red
            DeviceScanPhase.COMPLETE -> GeDefenseUi.green
            DeviceScanPhase.STORAGE -> GeDefenseUi.gold
            else -> GeDefenseUi.cyan
        }
        radar.setRunning(running, phaseColor)
        progress.setProgress(snapshot.progress.fraction.coerceIn(0f, 1f), phaseColor)
        phaseText.setTextColor(phaseColor)
        phaseText.text = phaseLabel(snapshot.progress.phase)
        currentText.text = when {
            running && snapshot.progress.current.isNotBlank() -> getString(R.string.scanner_current, snapshot.progress.current)
            snapshot.state == "COMPLETE" -> getString(R.string.scanner_completed_at, GeDefenseUi.formatTime(this, snapshot.completedAtMillis))
            snapshot.state == "FAILED" -> getString(R.string.scanner_failed)
            snapshot.state == "CANCELLED" -> getString(R.string.scanner_cancelled)
            else -> getString(R.string.scanner_idle_body)
        }

        val apps = if (snapshot.state == "IDLE") runtime.appScanSnapshot.get() else snapshot.apps
        statApps.text = apps.userPackages.toString()
        statFiles.text = snapshot.storage.enumeratedFiles.toString()
        statFindings.text = snapshot.progress.findings.toString()

        actionButton.text = getString(if (running) R.string.scanner_cancel else R.string.scanner_start)
        actionButton.background = if (running) GeDefenseUi.destructiveButtonBackground(this) else GeDefenseUi.goldButtonBackground(this)
        actionButton.setTextColor(if (running) GeDefenseUi.text else Color.rgb(18, 19, 20))
        refreshTabs()
        renderResults(snapshot)
    }

    private fun refreshTabs() {
        listOf(tabOverview, tabApps, tabFiles).forEachIndexed { index, view ->
            val active = index == selectedTab
            view.setTextColor(if (active) GeDefenseUi.gold else GeDefenseUi.textMuted)
            view.background = if (active) GeDefenseUi.badgeBackground(this, GeDefenseUi.gold) else null
        }
    }

    private fun renderResults(snapshot: DeviceScanSnapshot) {
        resultsHost.removeAllViews()
        when (selectedTab) {
            1 -> renderAppResults(snapshot)
            2 -> renderFileResults(snapshot)
            else -> renderOverview(snapshot)
        }
    }

    private fun renderOverview(snapshot: DeviceScanSnapshot) {
        val appScan = if (snapshot.state == "IDLE") runtime.appScanSnapshot.get() else snapshot.apps
        val integrityState = if (snapshot.state == "IDLE") runtime.integritySnapshot.get() else snapshot.integrity
        val cards = buildList {
            add(Triple(getString(R.string.scanner_overview_integrity), integrityOverview(integrityState), if (integrityState.ok) GeDefenseUi.green else GeDefenseUi.gold))
            add(Triple(getString(R.string.scanner_overview_apps), getString(R.string.app_scanner_summary, appScan.userPackages, appScan.highRiskPackages, appScan.threatMatchedPackages), if (appScan.highRiskPackages > 0) GeDefenseUi.orange else GeDefenseUi.cyan))
            if (appScan.metrics.elapsedMs > 0L) {
                add(Triple(
                    getString(R.string.scanner_overview_app_performance),
                    getString(
                        R.string.scanner_app_performance,
                        appScan.metrics.elapsedMs,
                        appScan.metrics.cacheHits,
                        appScan.deepScannedPackages,
                        GeDefenseUi.formatBytes(appScan.metrics.bytesStaticScanned),
                    ),
                    GeDefenseUi.cyan,
                ))
            }
            add(Triple(getString(R.string.scanner_overview_files), storageOverview(snapshot.storage), if (snapshot.storage.highRiskFiles > 0) GeDefenseUi.orange else GeDefenseUi.gold))
            if (snapshot.storage.metrics.elapsedMs > 0L) {
                add(Triple(
                    getString(R.string.scanner_overview_storage_performance),
                    getString(
                        R.string.scanner_storage_performance,
                        snapshot.storage.metrics.elapsedMs,
                        snapshot.storage.metrics.cacheHits,
                        snapshot.storage.inspectedFiles,
                        GeDefenseUi.formatBytes(snapshot.storage.metrics.contentBytesRead),
                    ),
                    GeDefenseUi.gold,
                ))
            }
        }
        cards.forEachIndexed { index, card ->
            if (index > 0) gap(12)
            resultsHost.addView(resultSummaryCard(card.first, card.second, card.third))
        }
        gap(16)
        resultsHost.addView(GeDefenseUi.textView(this, getString(R.string.scanner_disclaimer), 9.7f, GeDefenseUi.textDim).apply {
            setLineSpacing(dp(2).toFloat(), 1f)
        })
    }

    private fun renderAppResults(snapshot: DeviceScanSnapshot) {
        val appScan = if (snapshot.state == "IDLE") runtime.appScanSnapshot.get() else snapshot.apps
        val visible = appScan.results.filter { result ->
            result.riskScore >= AppRiskScanner.USER_VISIBLE_REVIEW_THRESHOLD ||
                result.approvalState == AppApprovalState.STALE ||
                result.threatMatches.isNotEmpty()
        }
        if (visible.isEmpty()) {
            resultsHost.addView(emptyResult(getString(R.string.scanner_no_actionable_app_findings)))
            return
        }
        visible.take(32).forEachIndexed { index, result ->
            if (index > 0) gap(10)
            resultsHost.addView(appResultCard(result))
        }
    }

    private fun renderFileResults(snapshot: DeviceScanSnapshot) {
        if (!runtime.setup.hasAllFilesAccess()) {
            resultsHost.addView(emptyResult(getString(R.string.scanner_files_permission_required)))
            return
        }
        val storage = snapshot.storage
        if (storage.results.isEmpty()) {
            resultsHost.addView(emptyResult(if (storage.state == "COMPLETE") getString(R.string.scanner_no_file_findings) else getString(R.string.scanner_scan_first)))
            return
        }
        storage.results.take(48).forEachIndexed { index, result ->
            if (index > 0) gap(10)
            resultsHost.addView(fileResultCard(result))
        }
    }

    private fun resultSummaryCard(title: String, detail: String, accent: Int): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@ScannerActivity, radius = 16)
        val content = LinearLayout(this@ScannerActivity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(18), dp(16), dp(18), dp(16))
            addView(VgtUiComponents.iconWell(this@ScannerActivity, VgtIcon.INTEGRITY, accent, 34), LinearLayout.LayoutParams(dp(34), dp(34)))
            addView(LinearLayout(this@ScannerActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(12), 0, 0, 0)
                addView(GeDefenseUi.textView(this@ScannerActivity, title, 12.4f, GeDefenseUi.text, bold = true))
                addView(GeDefenseUi.textView(this@ScannerActivity, detail, 9.8f, GeDefenseUi.textDim).apply { setPadding(0, dp(4), 0, 0) })
            }, LinearLayout.LayoutParams(0, -2, 1f))
        }
        addView(content, FrameLayout.LayoutParams(-1, -2))
    }

    private fun appResultCard(result: AppRiskResult): View {
        val color = when (result.riskLevel) {
            AppRiskLevel.SEVERE -> GeDefenseUi.red
            AppRiskLevel.HIGH -> GeDefenseUi.orange
            AppRiskLevel.REVIEW -> GeDefenseUi.gold
            AppRiskLevel.LOW -> GeDefenseUi.green
        }
        return FrameLayout(this).apply {
            background = GeDefenseUi.softPanelBackground(this@ScannerActivity, 14, color)
            addView(LinearLayout(this@ScannerActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(18), dp(14), dp(18), dp(14))
                addView(LinearLayout(this@ScannerActivity).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    addView(VgtUiComponents.appIdentityBadge(this@ScannerActivity, result.packageName, result.label, 38), LinearLayout.LayoutParams(dp(38), dp(38)))
                    addView(LinearLayout(this@ScannerActivity).apply {
                        orientation = LinearLayout.VERTICAL
                        setPadding(dp(12), 0, dp(8), 0)
                        addView(GeDefenseUi.textView(this@ScannerActivity, result.label, 12.5f, GeDefenseUi.text, bold = true))
                        addView(GeDefenseUi.textView(this@ScannerActivity, appFindingSummary(result), 9.5f, GeDefenseUi.textDim).apply { setPadding(0, dp(3), 0, 0) })
                    }, LinearLayout.LayoutParams(0, -2, 1f))
                    addView(GeDefenseUi.pill(this@ScannerActivity, "${result.riskScore}/100", color))
                })
                addView(GeDefenseUi.textView(
                    this@ScannerActivity,
                    getString(R.string.scanner_app_score_detail, result.capabilityScore, result.riskScore, approvalLabel(result.approvalState)),
                    8.9f,
                    GeDefenseUi.textDim,
                ).apply { setPadding(dp(50), dp(7), 0, 0) })
                if (result.signerSha256 != null && result.threatMatches.none { it.endsWith(":BLOCK") }) {
                    addView(GeDefenseUi.actionButton(
                        this@ScannerActivity,
                        getString(if (result.approvalState == AppApprovalState.APPROVED) R.string.scanner_approval_revoke else R.string.scanner_approval_approve),
                        goldStyle = result.approvalState != AppApprovalState.APPROVED,
                    ) { confirmAppApproval(result) }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })
                }
            }, FrameLayout.LayoutParams(-1, -2))
        }
    }

    private fun approvalLabel(state: AppApprovalState): String = getString(when (state) {
        AppApprovalState.APPROVED -> R.string.scanner_approval_state_approved
        AppApprovalState.STALE -> R.string.scanner_approval_state_stale
        AppApprovalState.NONE -> R.string.scanner_approval_state_none
    })

    private fun confirmAppApproval(result: AppRiskResult) {
        val revoke = result.approvalState == AppApprovalState.APPROVED
        AlertDialog.Builder(this)
            .setTitle(if (revoke) R.string.scanner_approval_revoke_title else R.string.scanner_approval_confirm_title)
            .setMessage(if (revoke) getString(R.string.scanner_approval_revoke_body, result.label) else getString(R.string.scanner_approval_confirm_body, result.label, result.packageName))
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(if (revoke) R.string.scanner_approval_revoke else R.string.scanner_approval_approve) { _, _ ->
                runtime.setAppApprovalAsync(result.packageName, approved = !revoke) { ok ->
                    runOnUiThread {
                        if (isFinishing || isDestroyed) return@runOnUiThread
                        Toast.makeText(this, getString(if (ok) R.string.scanner_approval_saved else R.string.scanner_approval_failed), Toast.LENGTH_LONG).show()
                        refresh()
                    }
                }
            }.show()
    }

    private fun fileResultCard(result: FileRiskResult): View {
        val color = when (result.riskLevel) {
            FileRiskLevel.SEVERE -> GeDefenseUi.red
            FileRiskLevel.HIGH -> GeDefenseUi.orange
            FileRiskLevel.REVIEW -> GeDefenseUi.gold
            FileRiskLevel.LOW -> GeDefenseUi.green
        }
        return FrameLayout(this).apply {
            background = GeDefenseUi.softPanelBackground(this@ScannerActivity, 14, color)
            val content = LinearLayout(this@ScannerActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(18), dp(14), dp(18), dp(14))
                addView(LinearLayout(this@ScannerActivity).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    addView(VgtUiComponents.iconWell(this@ScannerActivity, VgtIcon.EVIDENCE, color, 34), LinearLayout.LayoutParams(dp(34), dp(34)))
                    addView(LinearLayout(this@ScannerActivity).apply {
                        orientation = LinearLayout.VERTICAL
                        setPadding(dp(12), 0, dp(8), 0)
                        addView(GeDefenseUi.textView(this@ScannerActivity, result.displayName, 12.2f, GeDefenseUi.text, bold = true))
                        addView(GeDefenseUi.textView(this@ScannerActivity, "${result.kind} · ${GeDefenseUi.formatBytes(result.sizeBytes)}", 9.3f, GeDefenseUi.textDim))
                    }, LinearLayout.LayoutParams(0, -2, 1f))
                    addView(GeDefenseUi.pill(this@ScannerActivity, "${result.riskScore}/100", color))
                })
                addView(GeDefenseUi.monoTextView(this@ScannerActivity, result.path, 9f, GeDefenseUi.textDim).apply {
                    setPadding(dp(46), dp(8), 0, 0)
                    maxLines = 2
                })
            }
            addView(content, FrameLayout.LayoutParams(-1, -2))
        }
    }

    private fun emptyResult(text: String): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@ScannerActivity, radius = 16)
        addView(GeDefenseUi.textView(this@ScannerActivity, text, 10.5f, GeDefenseUi.textMuted).apply {
            setPadding(dp(18), dp(18), dp(18), dp(18))
            gravity = Gravity.CENTER
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun metricValue(): TextView = GeDefenseUi.textView(this, "0", 18f, GeDefenseUi.text, bold = true).apply { gravity = Gravity.CENTER }
    private fun metricColumn(label: String, value: TextView): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER
        addView(value)
        addView(GeDefenseUi.textView(this@ScannerActivity, label, 9.2f, GeDefenseUi.textDim).apply {
            gravity = Gravity.CENTER
            setPadding(0, dp(3), 0, 0)
        })
    }

    private fun phaseLabel(phase: DeviceScanPhase): String = getString(when (phase) {
        DeviceScanPhase.INTEGRITY -> R.string.scanner_phase_integrity
        DeviceScanPhase.APPS -> R.string.scanner_phase_apps
        DeviceScanPhase.STORAGE -> R.string.scanner_phase_storage
        DeviceScanPhase.FINALIZING -> R.string.scanner_phase_finalizing
        DeviceScanPhase.COMPLETE -> R.string.scanner_phase_complete
        DeviceScanPhase.FAILED -> R.string.scanner_failed
        DeviceScanPhase.CANCELLED -> R.string.scanner_cancelled
        else -> R.string.scanner_ready
    })

    private fun integrityOverview(value: IntegritySnapshot): String = when (value.state) {
        "HEALTHY" -> getString(R.string.integrity_healthy, value.filesChecked, GeDefenseUi.formatTime(this, value.checkedAtMillis))
        "COMPROMISED" -> getString(R.string.integrity_compromised, value.issues.size)
        else -> getString(R.string.integrity_pending)
    }

    private fun storageOverview(value: StorageScanSnapshot): String = when (value.state) {
        "COMPLETE" -> getString(R.string.scanner_storage_summary, value.enumeratedFiles, value.highRiskFiles, value.threatMatchedFiles)
        "PERMISSION_REQUIRED" -> getString(R.string.scanner_files_permission_required)
        else -> getString(R.string.scanner_scan_first)
    }

    private fun appFindingSummary(result: AppRiskResult): String {
        val finding = result.findings.firstOrNull()?.code ?: getString(R.string.ui_clean)
        return "$finding · ${result.threatMatches.size} TI · ${result.confidence.name} · ${result.analysisMode}"
    }

    private fun gap(v: Int) = GeDefenseUi.addVerticalGap(resultsHost, this, v)
    private fun dp(v: Int) = GeDefenseUi.dp(this, v)

    private fun configureSystemBars() = VgtWindowInsets.configureSystemBars(window)
}
