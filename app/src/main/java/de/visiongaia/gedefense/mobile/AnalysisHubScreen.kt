package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

// STATUS: DIAMANT VGT SUPREME
class AnalysisHubScreen(
    private val activity: Activity,
    private val actions: UiActions,
) {
    val view: View
    private val rootLayout: LinearLayout

    private val scanBadge: TextView
    private val scanTitle: TextView
    private val scanDetail: TextView
    private val scanProgress: VgtProgressView
    private val findingsHost: LinearLayout
    private val xdrBadge: TextView
    private val xdrSummary: TextView
    private val incidentsHost: LinearLayout
    private val evidenceBadge: TextView
    private val evidenceSummary: TextView
    private val verifyButton: TextView
    private var verifying = false
    private var lastFindingKey = ""
    private var lastIncidentKey = ""

    init {
        val scroll = ScrollView(activity).apply {
            clipToPadding = false
            overScrollMode = View.OVER_SCROLL_NEVER
        }
        VgtUiPerformance.bindScroll(scroll)
        rootLayout = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                GeDefenseUi.screenHorizontalPadding(activity),
                dp(16),
                GeDefenseUi.screenHorizontalPadding(activity),
                GeDefenseUi.scrollReservedBottomPadding(activity),
            )
        }
        scroll.addView(rootLayout, FrameLayout.LayoutParams(-1, -2))

        rootLayout.addView(VgtUiComponents.screenHeader(
            activity,
            activity.getString(R.string.analysis_hub_title),
            activity.getString(R.string.analysis_hub_subtitle),
        ))
        gap(GeDefenseUi.SPACING_CARD_GAP_DP)

        scanBadge = GeDefenseUi.pill(activity, activity.getString(R.string.ui_waiting), GeDefenseUi.gold)
        scanTitle = GeDefenseUi.displayTextView(activity, activity.getString(R.string.analysis_no_scan), 18f, GeDefenseUi.text)
        scanDetail = GeDefenseUi.textView(activity, activity.getString(R.string.scanner_idle_body), 10.4f, GeDefenseUi.textMuted)
        scanProgress = VgtProgressView(activity, GeDefenseUi.cyan)
        rootLayout.addView(scanCard())

        gap(GeDefenseUi.SPACING_SECTION_GAP_DP)
        rootLayout.addView(GeDefenseUi.sectionTitle(activity, activity.getString(R.string.analysis_findings_title)))
        gap(10)
        findingsHost = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
        rootLayout.addView(findingsHost)

        gap(GeDefenseUi.SPACING_SECTION_GAP_DP)
        xdrBadge = GeDefenseUi.pill(activity, activity.getString(R.string.ui_waiting), GeDefenseUi.orange)
        xdrSummary = GeDefenseUi.textView(activity, "", 10.5f, GeDefenseUi.textMuted)
        incidentsHost = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
        rootLayout.addView(xdrCard())

        gap(GeDefenseUi.SPACING_SECTION_GAP_DP)
        rootLayout.addView(GeDefenseUi.sectionTitle(activity, activity.getString(R.string.analysis_tools_title)))
        gap(10)
        val scanner = VgtActionTile(activity, VgtIcon.SCANNER, activity.getString(R.string.scanner_open), VgtActionStyle.PRIMARY) { actions.openMalwareScanner() }
        val xdr = VgtActionTile(activity, VgtIcon.CORRELATE, activity.getString(R.string.xdr_open)) { actions.openXdrCenter() }
        val network = VgtActionTile(activity, VgtIcon.ROUTES, activity.getString(R.string.network_discovery_open)) { actions.openNetworkDiscovery() }
        val behavior = VgtActionTile(activity, VgtIcon.ACTIVITY, activity.getString(R.string.behavior_open)) { actions.openBehaviorCenter() }
        rootLayout.addView(actionGrid(scanner, xdr, network, behavior))

        gap(GeDefenseUi.SPACING_CARD_GAP_DP)
        evidenceBadge = GeDefenseUi.pill(activity, activity.getString(R.string.ui_waiting), GeDefenseUi.gold)
        evidenceSummary = GeDefenseUi.textView(activity, "", 10.5f, GeDefenseUi.textMuted)
        verifyButton = GeDefenseUi.actionButton(activity, activity.getString(R.string.verify_evidence)) { actions.verifyEvidence() }
        rootLayout.addView(evidenceCard())

        view = scroll
    }

    fun setBottomPadding(bottomPx: Int) {
        rootLayout.setPadding(rootLayout.paddingLeft, rootLayout.paddingTop, rootLayout.paddingRight, bottomPx)
    }

    fun setVerifying(value: Boolean) {
        verifying = value
        verifyButton.isEnabled = !value
        verifyButton.alpha = if (value) 0.55f else 1f
        verifyButton.text = activity.getString(if (value) R.string.verifying else R.string.verify_evidence)
    }

    fun update(snapshot: UiSnapshot) {
        updateScan(snapshot)
        updateFindings(snapshot)
        updateXdr(snapshot.xdr)

        val evidenceHealthy = snapshot.evidenceOk && snapshot.integrity.ok && snapshot.xdr.trustStoresHealthy
        val evidenceColor = if (evidenceHealthy) GeDefenseUi.green else GeDefenseUi.red
        evidenceBadge.text = activity.getString(if (evidenceHealthy) R.string.analysis_trust_verified else R.string.analysis_trust_attention)
        evidenceBadge.setTextColor(evidenceColor)
        evidenceBadge.background = GeDefenseUi.badgeBackground(activity, evidenceColor)
        evidenceSummary.text = activity.getString(
            R.string.analysis_evidence_summary,
            snapshot.evidenceRecords,
            snapshot.integrity.state,
            xdrStoreStateLabel(snapshot.xdr),
        )
        evidenceSummary.setTextColor(if (evidenceHealthy) GeDefenseUi.textMuted else GeDefenseUi.red)
        if (verifying) setVerifying(true)
    }


    private fun xdrStoreStateLabel(xdr: XdrSnapshot): String {
        if (xdr.trustStoresHealthy) return activity.getString(R.string.analysis_xdr_store_ok)
        val failed = buildList {
            if (!xdr.eventStoreIntegrityOk) add("EVENT")
            if (!xdr.packageBaselineIntegrityOk) add("PACKAGE")
            if (!xdr.firewallPolicyIntegrityOk) add("FIREWALL")
            if (!xdr.networkDiscoveryIntegrityOk) add("LAN")
            if (!xdr.portSentinelIntegrityOk) add("SENTINEL")
            if (!xdr.titanPolicyIntegrityOk) add("TITAN")
        }
        return activity.getString(R.string.analysis_xdr_store_bad) + if (failed.isEmpty()) "" else " · " + failed.joinToString(" · ")
    }

    private fun updateScan(snapshot: UiSnapshot) {
        val scan = snapshot.deviceScan
        val running = scan.state == "RUNNING"
        val app = if (scan.state == "COMPLETE") scan.apps else snapshot.appScan
        val storage = scan.storage
        val color = when {
            running -> GeDefenseUi.cyan
            scan.state == "FAILED" -> GeDefenseUi.red
            app.highRiskPackages > 0 || storage.highRiskFiles > 0 -> GeDefenseUi.orange
            scan.state == "COMPLETE" || app.state == "COMPLETE" -> GeDefenseUi.green
            else -> GeDefenseUi.gold
        }
        scanBadge.text = activity.getString(when {
            running -> R.string.analysis_scan_running
            scan.state == "FAILED" -> R.string.scanner_failed
            scan.state == "COMPLETE" || app.state == "COMPLETE" -> R.string.analysis_scan_complete
            else -> R.string.analysis_scan_idle
        })
        scanBadge.setTextColor(color)
        scanBadge.background = GeDefenseUi.badgeBackground(activity, color)
        scanProgress.setProgress(if (running) scan.progress.fraction.coerceIn(0f, 1f) else if (scan.state == "COMPLETE") 1f else 0f, color)

        if (running) {
            val percent = (scan.progress.fraction.coerceIn(0f, 1f) * 100f).toInt()
            scanTitle.text = activity.getString(R.string.analysis_scan_progress, percent, phaseLabel(scan.progress.phase))
            scanTitle.setTextColor(color)
            scanDetail.text = activity.getString(
                R.string.analysis_scan_progress_detail,
                scan.progress.processed,
                scan.progress.total,
                scan.progress.findings,
                scan.progress.current.ifBlank { activity.getString(R.string.ui_waiting) },
            )
        } else {
            val highApps = app.highRiskPackages
            val highFiles = storage.highRiskFiles
            val matches = app.threatMatchedPackages + storage.threatMatchedFiles
            scanTitle.text = activity.getString(R.string.analysis_scan_result_title, highApps + highFiles, matches)
            scanTitle.setTextColor(color)
            scanDetail.text = when {
                scan.state == "COMPLETE" -> activity.getString(
                    R.string.analysis_scan_result_detail,
                    app.userPackages,
                    storage.enumeratedFiles,
                    GeDefenseUi.formatTime(activity, scan.completedAtMillis),
                )
                app.state == "COMPLETE" -> activity.getString(
                    R.string.analysis_app_scan_result_detail,
                    app.userPackages,
                    app.deepScannedPackages,
                    GeDefenseUi.formatTime(activity, app.scannedAtMillis),
                )
                else -> activity.getString(R.string.scanner_idle_body)
            }
        }
    }

    private fun updateFindings(snapshot: UiSnapshot) {
        val app = if (snapshot.deviceScan.state == "COMPLETE") snapshot.deviceScan.apps else snapshot.appScan
        val file = snapshot.deviceScan.storage
        val rows = ArrayList<FindingRow>()
        app.results.asSequence()
            .filter { it.riskScore >= AppRiskScanner.USER_VISIBLE_REVIEW_THRESHOLD || it.threatMatches.isNotEmpty() || it.approvalState == AppApprovalState.STALE }
            .take(4)
            .forEach { result ->
                rows += FindingRow(
                    title = result.label,
                    subtitle = activity.getString(R.string.analysis_app_finding_detail, result.packageName, result.riskLevel.name),
                    score = result.riskScore,
                    accent = appRiskColor(result.riskLevel),
                )
            }
        file.results.asSequence()
            .filter { it.riskScore > 0 }
            .take(4)
            .forEach { result ->
                rows += FindingRow(
                    title = result.displayName,
                    subtitle = activity.getString(R.string.analysis_file_finding_detail, result.kind, result.riskLevel.name),
                    score = result.riskScore,
                    accent = fileRiskColor(result.riskLevel),
                )
            }
        val top = rows.sortedByDescending { it.score }.take(MAX_FINDINGS)
        val key = top.joinToString("|") { "${it.title}:${it.score}:${it.subtitle}" }
        if (key == lastFindingKey) return
        lastFindingKey = key
        findingsHost.removeAllViews()
        if (top.isEmpty()) {
            findingsHost.addView(emptyState(activity.getString(R.string.analysis_no_findings)))
            return
        }
        top.forEachIndexed { index, row ->
            findingsHost.addView(findingCard(row), LinearLayout.LayoutParams(-1, -2).apply {
                if (index > 0) topMargin = GeDefenseUi.cardGap(activity)
            })
        }
    }

    private fun updateXdr(xdr: XdrSnapshot) {
        val maxScore = xdr.incidents.maxOfOrNull { it.score } ?: 0
        val color = when {
            !xdr.trustStoresHealthy -> GeDefenseUi.red
            maxScore >= 80 -> GeDefenseUi.red
            maxScore >= 60 -> GeDefenseUi.orange
            xdr.incidents.isNotEmpty() -> GeDefenseUi.gold
            else -> GeDefenseUi.green
        }
        xdrBadge.text = if (xdr.incidents.isEmpty()) {
            activity.getString(R.string.analysis_xdr_clear)
        } else {
            activity.getString(R.string.analysis_xdr_active, xdr.incidents.size)
        }
        xdrBadge.setTextColor(color)
        xdrBadge.background = GeDefenseUi.badgeBackground(activity, color)
        xdrSummary.text = activity.getString(
            R.string.analysis_xdr_summary,
            xdr.criticalIncidents,
            xdr.highIncidents,
            xdr.events.size,
        )
        val top = xdr.incidents.take(MAX_INCIDENTS)
        val key = top.joinToString("|") { "${it.key}:${it.score}:${it.lastSeenMillis}" }
        if (key == lastIncidentKey) return
        lastIncidentKey = key
        incidentsHost.removeAllViews()
        if (top.isEmpty()) {
            incidentsHost.addView(GeDefenseUi.textView(activity, activity.getString(R.string.analysis_xdr_empty), 9.8f, GeDefenseUi.textDim).apply {
                setPadding(0, dp(9), 0, 0)
            })
            return
        }
        top.forEachIndexed { index, incident ->
            incidentsHost.addView(incidentRow(incident), LinearLayout.LayoutParams(-1, -2).apply { if (index > 0) topMargin = dp(8) })
        }
    }

    private fun scanCard(): View = FrameLayout(activity).apply {
        background = GeDefenseUi.glassPanelBackground(activity, strong = true, accent = GeDefenseUi.cyan, radius = 20)
        addView(LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(20))
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(activity, VgtIcon.SCANNER, GeDefenseUi.cyan, 40), LinearLayout.LayoutParams(dp(40), dp(40)))
                addView(LinearLayout(activity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(dp(14), 0, dp(10), 0)
                    addView(scanTitle)
                    addView(scanDetail.apply { setPadding(0, dp(5), 0, 0) })
                }, LinearLayout.LayoutParams(0, -2, 1f))
                addView(scanBadge)
            })
            addView(scanProgress, LinearLayout.LayoutParams(-1, dp(5)).apply { topMargin = dp(15) })
            addView(GeDefenseUi.actionButton(activity, activity.getString(R.string.scanner_open), goldStyle = true) { actions.openMalwareScanner() }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(15) })
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun xdrCard(): View = FrameLayout(activity).apply {
        background = GeDefenseUi.glassPanelBackground(activity, accent = GeDefenseUi.orange, radius = 18)
        addView(LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(activity, VgtIcon.CORRELATE, GeDefenseUi.orange, 36), LinearLayout.LayoutParams(dp(36), dp(36)))
                addView(LinearLayout(activity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(dp(13), 0, dp(10), 0)
                    addView(GeDefenseUi.textView(activity, activity.getString(R.string.xdr_title), 14f, GeDefenseUi.text, bold = true))
                    addView(xdrSummary.apply { setPadding(0, dp(4), 0, 0) })
                }, LinearLayout.LayoutParams(0, -2, 1f))
                addView(xdrBadge)
            })
            addView(incidentsHost, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })
            addView(GeDefenseUi.actionButton(activity, activity.getString(R.string.xdr_open)) { actions.openXdrCenter() }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(14) })
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun evidenceCard(): View = FrameLayout(activity).apply {
        background = GeDefenseUi.glassPanelBackground(activity, accent = GeDefenseUi.gold, radius = 18)
        addView(LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(activity, VgtIcon.EVIDENCE, GeDefenseUi.gold, 36), LinearLayout.LayoutParams(dp(36), dp(36)))
                addView(LinearLayout(activity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(dp(13), 0, dp(10), 0)
                    addView(GeDefenseUi.textView(activity, activity.getString(R.string.analysis_trust_title), 14f, GeDefenseUi.text, bold = true))
                    addView(evidenceSummary.apply { setPadding(0, dp(4), 0, 0) })
                }, LinearLayout.LayoutParams(0, -2, 1f))
                addView(evidenceBadge)
            })
            addView(verifyButton, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(14) })
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun findingCard(row: FindingRow): View = FrameLayout(activity).apply {
        background = GeDefenseUi.softPanelBackground(activity, 16, row.accent)
        addView(LinearLayout(activity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(16), dp(13), dp(16), dp(13))
            addView(VgtUiComponents.iconWell(activity, VgtIcon.ALERT, row.accent, 32), LinearLayout.LayoutParams(dp(32), dp(32)))
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(12), 0, dp(10), 0)
                addView(GeDefenseUi.textView(activity, row.title, 11.5f, GeDefenseUi.text, bold = true).apply { maxLines = 1 })
                addView(GeDefenseUi.textView(activity, row.subtitle, 9f, GeDefenseUi.textDim).apply { setPadding(0, dp(3), 0, 0); maxLines = 2 })
            }, LinearLayout.LayoutParams(0, -2, 1f))
            addView(GeDefenseUi.pill(activity, "${row.score}/100", row.accent))
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun incidentRow(incident: XdrIncident): View = FrameLayout(activity).apply {
        val accent = when (incident.severity) {
            XdrSeverity.CRITICAL -> GeDefenseUi.red
            XdrSeverity.HIGH -> GeDefenseUi.orange
            XdrSeverity.MEDIUM -> GeDefenseUi.gold
            XdrSeverity.LOW -> GeDefenseUi.cyan
            XdrSeverity.INFO -> GeDefenseUi.green
        }
        background = GeDefenseUi.softPanelBackground(activity, 14, accent)
        addView(LinearLayout(activity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(14), dp(11), dp(14), dp(11))
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.VERTICAL
                addView(GeDefenseUi.textView(activity, incident.subject, 10.6f, GeDefenseUi.text, bold = true).apply { maxLines = 1 })
                addView(GeDefenseUi.textView(activity, incident.summary, 8.8f, GeDefenseUi.textDim).apply { setPadding(0, dp(3), 0, 0); maxLines = 2 })
            }, LinearLayout.LayoutParams(0, -2, 1f))
            addView(GeDefenseUi.pill(activity, "${incident.score}/100", accent))
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun emptyState(text: String): View = FrameLayout(activity).apply {
        background = GeDefenseUi.softPanelBackground(activity, 16, GeDefenseUi.green)
        addView(GeDefenseUi.textView(activity, text, 10.2f, GeDefenseUi.textMuted).apply {
            setPadding(dp(16), dp(14), dp(16), dp(14))
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun actionGrid(vararg tiles: View): View {
        val root = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
        val halfGap = GeDefenseUi.cardHorizontalGap(activity) / 2
        val cardGap = GeDefenseUi.cardGap(activity)
        for (i in tiles.indices step 2) {
            val row = LinearLayout(activity).apply { orientation = LinearLayout.HORIZONTAL }
            row.addView(tiles[i], LinearLayout.LayoutParams(0, -2, 1f).apply { rightMargin = halfGap })
            tiles.getOrNull(i + 1)?.let { tile ->
                row.addView(tile, LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = halfGap })
            }
            root.addView(row, LinearLayout.LayoutParams(-1, -2).apply { if (i > 0) topMargin = cardGap })
        }
        return root
    }

    private fun phaseLabel(phase: DeviceScanPhase): String = activity.getString(when (phase) {
        DeviceScanPhase.INTEGRITY -> R.string.scanner_phase_integrity
        DeviceScanPhase.APPS -> R.string.scanner_phase_apps
        DeviceScanPhase.STORAGE -> R.string.scanner_phase_storage
        DeviceScanPhase.FINALIZING -> R.string.scanner_phase_finalizing
        DeviceScanPhase.COMPLETE -> R.string.scanner_phase_complete
        DeviceScanPhase.FAILED -> R.string.scanner_failed
        DeviceScanPhase.CANCELLED -> R.string.scanner_cancelled
        DeviceScanPhase.IDLE -> R.string.scanner_ready
    })

    private fun appRiskColor(level: AppRiskLevel): Int = when (level) {
        AppRiskLevel.SEVERE -> GeDefenseUi.red
        AppRiskLevel.HIGH -> GeDefenseUi.orange
        AppRiskLevel.REVIEW -> GeDefenseUi.gold
        AppRiskLevel.LOW -> GeDefenseUi.green
    }

    private fun fileRiskColor(level: FileRiskLevel): Int = when (level) {
        FileRiskLevel.SEVERE -> GeDefenseUi.red
        FileRiskLevel.HIGH -> GeDefenseUi.orange
        FileRiskLevel.REVIEW -> GeDefenseUi.gold
        FileRiskLevel.LOW -> GeDefenseUi.green
    }

    private data class FindingRow(
        val title: String,
        val subtitle: String,
        val score: Int,
        val accent: Int,
    )

    private fun gap(value: Int) = GeDefenseUi.addVerticalGap(rootLayout, activity, value)
    private fun dp(value: Int) = GeDefenseUi.dp(activity, value)

    companion object {
        private const val MAX_FINDINGS = 4
        private const val MAX_INCIDENTS = 3
    }
}
