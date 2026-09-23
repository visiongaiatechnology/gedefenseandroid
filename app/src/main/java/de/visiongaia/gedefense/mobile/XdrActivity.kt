package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

class XdrActivity : Activity() {
    private lateinit var runtime: AppRuntime
    private lateinit var rootLayout: LinearLayout
    private lateinit var postureText: TextView
    private lateinit var statusText: TextView
    private lateinit var coverageHost: LinearLayout
    private lateinit var incidentHost: LinearLayout
    private lateinit var eventHost: LinearLayout
    private lateinit var forensicHost: LinearLayout
    private lateinit var findingsSection: LinearLayout
    private lateinit var forensicSection: LinearLayout
    private lateinit var findingsTab: TextView
    private lateinit var forensicTab: TextView
    private lateinit var quarantineText: TextView
    private lateinit var behaviorText: TextView
    private lateinit var trustHost: LinearLayout
    private var selectedIncidentKey: String? = null
    private var requestedPackage: String? = null
    private var viewMode = XdrViewMode.FINDINGS

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runtime = RuntimeActivityEntry.requireReady(this) ?: return
        requestedPackage = intent.getStringExtra(EXTRA_PACKAGE)?.takeIf { it.length in 3..256 && it.contains('.') && it.none(Char::isWhitespace) }
        if (requestedPackage != null) viewMode = XdrViewMode.FORENSICS
        configureSystemBars()
        setContentView(buildUi())
        refresh()
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    private fun buildUi(): View {
        val root = FrameLayout(this).apply { setBackgroundColor(GeDefenseUi.bg) }
        root.addView(CyberBackgroundView(this), FrameLayout.LayoutParams(-1, -1))
        val scroll = ScrollView(this).apply { clipToPadding = false; overScrollMode = View.OVER_SCROLL_NEVER }
        rootLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(18), dp(24), dp(44))
        }
        scroll.addView(rootLayout, FrameLayout.LayoutParams(-1, -2))
        root.addView(scroll, FrameLayout.LayoutParams(-1, -1))

        rootLayout.addView(VgtUiComponents.screenHeader(this, getString(R.string.xdr_title), getString(R.string.xdr_subtitle)))
        gap(16)

        postureText = GeDefenseUi.textView(this, "", 18f, GeDefenseUi.gold, bold = true)
        statusText = GeDefenseUi.textView(this, "", 11f, GeDefenseUi.textMuted)
        quarantineText = GeDefenseUi.textView(this, "", 10f, GeDefenseUi.textDim)
        behaviorText = GeDefenseUi.textView(this, "", 10f, GeDefenseUi.textDim)
        coverageHost = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        trustHost = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        rootLayout.addView(sectionCard(
            icon = VgtIcon.CORRELATE,
            accent = GeDefenseUi.gold,
            title = getString(R.string.xdr_status_title),
            content = arrayOf(
                postureText,
                statusText,
                quarantineText,
                behaviorText,
                coverageHost,
                trustHost,
                GeDefenseUi.actionButton(this, getString(R.string.behavior_open)) { startActivity(Intent(this, BehaviorActivity::class.java)) },
                GeDefenseUi.actionButton(this, getString(R.string.hardening_open)) { startActivity(Intent(this, HardeningActivity::class.java)) },
                GeDefenseUi.actionButton(this, getString(R.string.titan_open), goldStyle = true) { startActivity(Intent(this, TitanActivity::class.java)) },
                GeDefenseUi.actionButton(this, getString(R.string.xdr_refresh)) { reconcile() },
                GeDefenseUi.actionButton(this, getString(R.string.xdr_emergency_lockdown), goldStyle = true) { activateEmergencyLockdown() },
            ),
        ))

        gap(16)
        rootLayout.addView(GeDefenseUi.sectionTitle(this, getString(R.string.xdr_analysis_views)))
        gap(8)
        rootLayout.addView(LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            findingsTab = GeDefenseUi.actionButton(this@XdrActivity, getString(R.string.xdr_tab_findings), goldStyle = true) { setViewMode(XdrViewMode.FINDINGS) }
            forensicTab = GeDefenseUi.actionButton(this@XdrActivity, getString(R.string.xdr_tab_forensics)) { setViewMode(XdrViewMode.FORENSICS) }
            addView(findingsTab, LinearLayout.LayoutParams(0, -2, 1f).apply { rightMargin = dp(5) })
            addView(forensicTab, LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(5) })
        })
        gap(12)

        findingsSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(GeDefenseUi.sectionTitle(this@XdrActivity, getString(R.string.xdr_findings_title)))
            addView(LinearLayout(this@XdrActivity).also { incidentHost = it; it.orientation = LinearLayout.VERTICAL }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })
        }
        rootLayout.addView(findingsSection)

        forensicSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
            addView(GeDefenseUi.sectionTitle(this@XdrActivity, getString(R.string.xdr_forensics_title)))
            addView(LinearLayout(this@XdrActivity).also { forensicHost = it; it.orientation = LinearLayout.VERTICAL }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })
            addView(GeDefenseUi.sectionTitle(this@XdrActivity, getString(R.string.xdr_evidence_timeline)), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(18) })
            addView(LinearLayout(this@XdrActivity).also { eventHost = it; it.orientation = LinearLayout.VERTICAL }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })
        }
        rootLayout.addView(forensicSection)

        root.setOnApplyWindowInsetsListener { _, insets ->
            val safe = VgtWindowInsets.safeArea(insets)
            rootLayout.setPadding(dp(24) + safe.left, dp(18) + safe.top, dp(24) + safe.right, dp(44) + safe.bottom)
            insets
        }
        root.post { root.requestApplyInsets() }
        return root
    }

    private fun reconcile() {
        statusText.text = getString(R.string.xdr_refreshing)
        if (!runtime.executeBackground("xdr-reconcile") {
            try { runtime.xdr.reconcilePackages() } catch (error: Throwable) { RuntimeFailureLog.nonCritical("xdr-activity", error) }
            runOnUiThread { refresh() }
        }) {
            statusText.text = getString(R.string.ui_attention)
        }
    }

    private fun refresh() {
        if (!::incidentHost.isInitialized) return
        val snapshot = runtime.xdr.snapshot()
        val activeRisk = snapshot.incidents.maxOfOrNull { it.score } ?: 0
        val hardening = runtime.hardeningSnapshot.get()
        val postureColor = severityColor(xdrSeverityForScore(activeRisk))
        postureText.setTextColor(if (activeRisk == 0) GeDefenseUi.green else postureColor)
        postureText.text = getString(R.string.xdr_active_risk, activeRisk, if (hardening.checkedAtMillis > 0L) hardening.score else 0)
        statusText.text = getString(
            R.string.xdr_status_summary,
            snapshot.incidents.size,
            snapshot.criticalIncidents,
            snapshot.highIncidents,
            snapshot.events.size,
        )
        quarantineText.text = if (snapshot.quarantinedPackages.isEmpty()) {
            getString(R.string.xdr_quarantine_empty)
        } else {
            getString(R.string.xdr_quarantine_count, snapshot.quarantinedPackages.size)
        }
        val behavior = runtime.behavior.snapshot()
        behaviorText.text = getString(R.string.xdr_behavior_summary, behavior.matureProfiles, behavior.learningProfiles, behavior.anomalyCount)
        behaviorText.setTextColor(if (behavior.baselineIntegrityOk) GeDefenseUi.textDim else GeDefenseUi.red)
        updateCoverage(hardening)
        updateTrustStores(snapshot)

        if (selectedIncidentKey == null || snapshot.incidents.none { it.key == selectedIncidentKey }) {
            selectedIncidentKey = requestedPackage?.let { pkg -> snapshot.incidents.firstOrNull { it.packageName == pkg }?.key }
                ?: snapshot.incidents.firstOrNull()?.key
        }
        if (requestedPackage != null) {
            requestedPackage = null
            setViewMode(XdrViewMode.FORENSICS)
        }
        incidentHost.removeAllViews()
        if (snapshot.incidents.isEmpty()) {
            incidentHost.addView(emptyText(R.string.xdr_no_incidents))
        } else {
            snapshot.incidents.take(20).forEachIndexed { index, incident ->
                if (index > 0) addHostGap(incidentHost, 8)
                incidentHost.addView(incidentCard(incident, snapshot.quarantinedPackages))
            }
        }
        renderForensics(snapshot)
    }

    private fun incidentCard(incident: XdrIncident, quarantined: Set<String>): View {
        val accent = severityColor(incident.severity)
        return FrameLayout(this).apply {
            background = GeDefenseUi.glassPanelBackground(this@XdrActivity, accent = accent, radius = 17)
            addView(LinearLayout(this@XdrActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(16), dp(14), dp(16), dp(14))
                addView(LinearLayout(this@XdrActivity).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    addView(VgtUiComponents.iconWell(this@XdrActivity, VgtIcon.ALERT, accent, 32), LinearLayout.LayoutParams(dp(32), dp(32)))
                    addView(LinearLayout(this@XdrActivity).apply {
                        orientation = LinearLayout.VERTICAL
                        setPadding(dp(11), 0, dp(8), 0)
                        addView(GeDefenseUi.textView(this@XdrActivity, incident.subject, 11.5f, GeDefenseUi.text, bold = true).apply { maxLines = 1 })
                        addView(GeDefenseUi.textView(this@XdrActivity, incident.categories.joinToString(" · ") { it.name }, 8.8f, GeDefenseUi.textDim).apply { setPadding(0, dp(2), 0, 0) })
                    }, LinearLayout.LayoutParams(0, -2, 1f))
                    addView(GeDefenseUi.pill(this@XdrActivity, getString(R.string.xdr_score, incident.score), accent))
                })
                addView(GeDefenseUi.textView(this@XdrActivity, incident.summary, 9.7f, GeDefenseUi.textMuted).apply {
                    setPadding(0, dp(9), 0, 0); setLineSpacing(dp(2).toFloat(), 1f)
                })
                addView(GeDefenseUi.textView(this@XdrActivity, getString(R.string.xdr_event_count, incident.eventCount, GeDefenseUi.formatTime(this@XdrActivity, incident.lastSeenMillis)), 8.7f, GeDefenseUi.textDim).apply {
                    setPadding(0, dp(6), 0, 0)
                })
                addView(GeDefenseUi.textView(this@XdrActivity, incidentRecommendation(incident), 9f, accent).apply {
                    setPadding(0, dp(7), 0, 0); setLineSpacing(dp(2).toFloat(), 1f)
                })
                addView(GeDefenseUi.actionButton(this@XdrActivity, getString(R.string.xdr_open_forensics)) {
                    selectedIncidentKey = incident.key
                    setViewMode(XdrViewMode.FORENSICS)
                    refresh()
                }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })
                incident.packageName?.let { pkg ->
                    val isQuarantined = pkg in quarantined
                    addView(GeDefenseUi.actionButton(
                        this@XdrActivity,
                        getString(if (isQuarantined) R.string.xdr_unquarantine_action else R.string.xdr_quarantine_action),
                        goldStyle = !isQuarantined,
                    ) { toggleQuarantine(pkg, !isQuarantined) }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })
                    approvalActionFor(pkg)?.let { action ->
                        addView(action, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })
                    }
                }
            }, FrameLayout.LayoutParams(-1, -2))
        }
    }

    private fun eventCard(event: XdrEvent, counted: Boolean? = null): View {
        val accent = severityColor(event.severity)
        return FrameLayout(this).apply {
            background = GeDefenseUi.softPanelBackground(this@XdrActivity, 14, accent)
            addView(LinearLayout(this@XdrActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.TOP
                setPadding(dp(13), dp(11), dp(13), dp(11))
                addView(VgtUiComponents.iconWell(this@XdrActivity, eventIcon(event.category), accent, 28), LinearLayout.LayoutParams(dp(28), dp(28)))
                addView(LinearLayout(this@XdrActivity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(dp(10), 0, 0, 0)
                    addView(LinearLayout(this@XdrActivity).apply {
                        orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                        addView(GeDefenseUi.textView(this@XdrActivity, event.title, 10.5f, GeDefenseUi.text, bold = true), LinearLayout.LayoutParams(0, -2, 1f))
                        addView(GeDefenseUi.pill(this@XdrActivity, getString(R.string.xdr_points, event.riskPoints), accent))
                    })
                    addView(GeDefenseUi.textView(this@XdrActivity, "${event.subject} · ${GeDefenseUi.formatTime(this@XdrActivity, event.atMillis)}", 8.5f, GeDefenseUi.textDim).apply { setPadding(0, dp(2), 0, 0) })
                    addView(GeDefenseUi.textView(this@XdrActivity, getString(R.string.xdr_event_source, event.source, event.category.name), 8.4f, GeDefenseUi.textDim).apply { setPadding(0, dp(3), 0, 0) })
                    counted?.let { contributes ->
                        addView(GeDefenseUi.textView(this@XdrActivity, getString(if (contributes) R.string.xdr_event_counted else R.string.xdr_event_not_counted), 8.5f, if (contributes) GeDefenseUi.green else GeDefenseUi.textDim, bold = true).apply { setPadding(0, dp(3), 0, 0) })
                    }
                    addView(GeDefenseUi.textView(this@XdrActivity, event.detail, 9.2f, GeDefenseUi.textMuted).apply {
                        setPadding(0, dp(5), 0, 0); maxLines = 8; setTextIsSelectable(true)
                    })
                }, LinearLayout.LayoutParams(0, -2, 1f))
            }, FrameLayout.LayoutParams(-1, -2))
        }
    }



    private fun setViewMode(mode: XdrViewMode) {
        viewMode = mode
        if (!::findingsSection.isInitialized) return
        findingsSection.visibility = if (mode == XdrViewMode.FINDINGS) View.VISIBLE else View.GONE
        forensicSection.visibility = if (mode == XdrViewMode.FORENSICS) View.VISIBLE else View.GONE
        findingsTab.background = if (mode == XdrViewMode.FINDINGS) GeDefenseUi.goldButtonBackground(this) else GeDefenseUi.darkButtonBackground(this)
        findingsTab.setTextColor(if (mode == XdrViewMode.FINDINGS) Color.rgb(19, 19, 18) else GeDefenseUi.text)
        forensicTab.background = if (mode == XdrViewMode.FORENSICS) GeDefenseUi.goldButtonBackground(this) else GeDefenseUi.darkButtonBackground(this)
        forensicTab.setTextColor(if (mode == XdrViewMode.FORENSICS) Color.rgb(19, 19, 18) else GeDefenseUi.text)
    }

    private fun renderForensics(snapshot: XdrSnapshot) {
        if (!::forensicHost.isInitialized) return
        forensicHost.removeAllViews()
        eventHost.removeAllViews()
        val incident = snapshot.incidents.firstOrNull { it.key == selectedIncidentKey }
        if (incident == null) {
            forensicHost.addView(emptyText(R.string.xdr_forensics_empty))
            eventHost.addView(emptyText(R.string.xdr_no_events))
            return
        }
        val events = snapshot.events.filter { it.incidentKey == incident.key }.sortedByDescending { it.atMillis }
        val breakdown = xdrScoreBreakdown(events)
        val accent = severityColor(incident.severity)
        val scannerEvent = events.firstOrNull { it.source == "app-scanner" && it.detectorScore != null }
        val detectorScore = scannerEvent?.detectorScore

        forensicHost.addView(forensicPanel(
            icon = VgtIcon.CORRELATE,
            accent = accent,
            title = incident.subject,
            children = buildList {
                add(GeDefenseUi.textView(this@XdrActivity, getString(R.string.xdr_forensic_score_summary, incident.score, detectorScore?.let { getString(R.string.xdr_score, it) } ?: getString(R.string.xdr_not_available)), 11f, GeDefenseUi.text, bold = true))
                add(GeDefenseUi.textView(this@XdrActivity, getString(R.string.xdr_forensic_score_explain), 9.2f, GeDefenseUi.textMuted).apply { setLineSpacing(dp(2).toFloat(), 1f) })
                incident.packageName?.let { add(forensicMetricRow(getString(R.string.xdr_fact_package), it, GeDefenseUi.cyan, mono = true)) }
                add(forensicMetricRow(getString(R.string.xdr_forensic_first_seen), GeDefenseUi.formatTime(this@XdrActivity, incident.firstSeenMillis), GeDefenseUi.textDim))
                add(forensicMetricRow(getString(R.string.xdr_forensic_last_seen), GeDefenseUi.formatTime(this@XdrActivity, incident.lastSeenMillis), GeDefenseUi.textDim))
                incident.packageName?.let { pkg ->
                    runtime.currentAppRiskResult(pkg)?.let { result ->
                        add(forensicMetricRow(getString(R.string.xdr_fact_approval), approvalLabel(result.approvalState), approvalColor(result.approvalState)))
                        approvalActionFor(pkg)?.let(::add)
                    }
                }
            },
        ))

        addHostGap(forensicHost, 10)
        forensicHost.addView(forensicPanel(
            icon = VgtIcon.ACTIVITY,
            accent = GeDefenseUi.gold,
            title = getString(R.string.xdr_score_recipe),
            children = listOf(
                forensicScoreRow(getString(R.string.xdr_score_event_points), breakdown.eventPoints),
                forensicScoreRow(getString(R.string.xdr_score_category_bonus), breakdown.categoryBonus),
                forensicScoreRow(getString(R.string.xdr_score_critical_bonus), breakdown.criticalBonus),
                forensicScoreRow(getString(R.string.xdr_score_volume_bonus), breakdown.volumeBonus),
                forensicMetricRow(getString(R.string.xdr_score_unclamped), breakdown.unclampedScore.toString(), GeDefenseUi.text),
                forensicMetricRow(getString(R.string.xdr_score_final), getString(R.string.xdr_score, breakdown.finalScore), accent),
                GeDefenseUi.textView(this, getString(R.string.xdr_score_recipe_note), 8.8f, GeDefenseUi.textDim).apply { setLineSpacing(dp(2).toFloat(), 1f) },
            ),
        ))

        // Scanner raw score and scanner reasons must come from the exact same event snapshot.
        // Independent behavior/network evidence is shown in the event timeline, not mixed into the
        // scanner recipe where it would make the raw score appear mathematically inconsistent.
        val reasons = scannerEvent?.forensicReasons.orEmpty().sortedByDescending { it.points }
        addHostGap(forensicHost, 10)
        forensicHost.addView(forensicPanel(
            icon = VgtIcon.SCANNER,
            accent = if (reasons.isEmpty()) GeDefenseUi.textDim else accent,
            title = getString(R.string.xdr_forensic_reasons),
            children = if (reasons.isEmpty()) listOf(GeDefenseUi.textView(this, getString(R.string.xdr_forensic_reasons_legacy), 9.2f, GeDefenseUi.textDim)) else reasons.take(24).map(::forensicReasonRow),
        ))

        val facts = linkedMapOf<String, String>()
        scannerEvent?.forensicFacts?.forEach { fact -> if (fact.key !in facts) facts[fact.key] = fact.value }
        events.asSequence().filter { it !== scannerEvent }.forEach { event ->
            event.forensicFacts.forEach { fact -> if (fact.key !in facts) facts[fact.key] = fact.value }
        }
        addHostGap(forensicHost, 10)
        forensicHost.addView(forensicPanel(
            icon = VgtIcon.EVIDENCE,
            accent = GeDefenseUi.cyan,
            title = getString(R.string.xdr_forensic_artifacts),
            children = if (facts.isEmpty()) listOf(GeDefenseUi.textView(this, getString(R.string.xdr_forensic_artifacts_empty), 9.2f, GeDefenseUi.textDim)) else facts.entries.take(24).map { (key, value) -> forensicFactRow(key, value) },
        ))

        if (events.isEmpty()) {
            eventHost.addView(emptyText(R.string.xdr_no_events))
        } else {
            events.take(40).forEachIndexed { index, event ->
                if (index > 0) addHostGap(eventHost, 7)
                eventHost.addView(eventCard(event, event.id in breakdown.countedEventIds))
            }
        }
    }

    private fun forensicPanel(icon: VgtIcon, accent: Int, title: String, children: List<View>): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@XdrActivity, accent = accent, radius = 17)
        addView(LinearLayout(this@XdrActivity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(14), dp(16), dp(14))
            addView(LinearLayout(this@XdrActivity).apply {
                orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(this@XdrActivity, icon, accent, 30), LinearLayout.LayoutParams(dp(30), dp(30)))
                addView(GeDefenseUi.textView(this@XdrActivity, title, 11.2f, GeDefenseUi.text, bold = true), LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(10) })
            })
            children.forEach { addView(it, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(9) }) }
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun forensicScoreRow(label: String, points: Int): View = forensicMetricRow(label, if (points > 0) "+$points" else points.toString(), if (points > 0) GeDefenseUi.gold else GeDefenseUi.textDim)

    private fun forensicMetricRow(label: String, value: String, accent: Int, mono: Boolean = false): View = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL; gravity = Gravity.TOP
        addView(GeDefenseUi.textView(this@XdrActivity, label, 9f, GeDefenseUi.textMuted), LinearLayout.LayoutParams(0, -2, 0.42f))
        val valueView = if (mono) GeDefenseUi.monoTextView(this@XdrActivity, value, 8.8f, accent) else GeDefenseUi.textView(this@XdrActivity, value, 9f, accent, bold = true)
        valueView.setTextIsSelectable(true)
        addView(valueView, LinearLayout.LayoutParams(0, -2, 0.58f).apply { leftMargin = dp(8) })
    }

    private fun forensicReasonRow(reason: XdrForensicReason): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = GeDefenseUi.softPanelBackground(this@XdrActivity, 12, if (reason.points >= 40) GeDefenseUi.red else if (reason.points >= 20) GeDefenseUi.orange else GeDefenseUi.gold)
        setPadding(dp(12), dp(10), dp(12), dp(10))
        addView(LinearLayout(this@XdrActivity).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            addView(GeDefenseUi.textView(this@XdrActivity, forensicReasonDescription(reason.code), 9.6f, GeDefenseUi.text, bold = true), LinearLayout.LayoutParams(0, -2, 1f))
            addView(GeDefenseUi.pill(this@XdrActivity, "+${reason.points}", if (reason.points >= 40) GeDefenseUi.red else if (reason.points >= 20) GeDefenseUi.orange else GeDefenseUi.gold))
        })
        addView(GeDefenseUi.monoTextView(this@XdrActivity, reason.code, 8.2f, GeDefenseUi.textDim).apply { setPadding(0, dp(4), 0, 0); setTextIsSelectable(true) })
        if (reason.detail.isNotBlank()) addView(GeDefenseUi.textView(this@XdrActivity, reason.detail, 8.8f, GeDefenseUi.textMuted).apply { setPadding(0, dp(4), 0, 0); setTextIsSelectable(true) })
    }

    private fun forensicFactRow(key: String, value: String): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        addView(GeDefenseUi.textView(this@XdrActivity, forensicFactLabel(key), 8.6f, GeDefenseUi.textDim, bold = true))
        addView(GeDefenseUi.monoTextView(this@XdrActivity, value, 8.6f, GeDefenseUi.textMuted).apply { setPadding(0, dp(3), 0, 0); setTextIsSelectable(true); maxLines = 5 })
    }

    private fun forensicFactLabel(key: String): String = when (key) {
        "package" -> getString(R.string.xdr_fact_package)
        "version" -> getString(R.string.xdr_fact_version)
        "installer" -> getString(R.string.xdr_fact_installer)
        "risk_level" -> getString(R.string.xdr_fact_risk_level)
        "confidence" -> getString(R.string.xdr_fact_confidence)
        "capability_score" -> getString(R.string.xdr_fact_capability_score)
        "scanner_raw_score" -> getString(R.string.xdr_fact_scanner_raw_score)
        "effective_static_score" -> getString(R.string.xdr_fact_effective_score)
        "approval_state" -> getString(R.string.xdr_fact_approval)
        "analysis_mode" -> getString(R.string.xdr_fact_analysis_mode)
        "signer_sha256" -> getString(R.string.xdr_fact_signer)
        "apk_sha256" -> getString(R.string.xdr_fact_apk_hash)
        "threat_matches" -> getString(R.string.xdr_fact_threat_matches)
        else -> key
    }

    private fun forensicReasonDescription(code: String): String = when (code) {
        "debuggable_release" -> getString(R.string.xdr_reason_debuggable_release)
        "internet_plus_package_install", "package_install_capability_network" -> getString(R.string.xdr_reason_install_network)
        "boot_persistent_installer" -> getString(R.string.xdr_reason_boot_installer)
        "overlay_plus_network", "overlay_active_network" -> getString(R.string.xdr_reason_overlay_network)
        "overlay_declared_network" -> getString(R.string.xdr_reason_overlay_declared)
        "sms_plus_network", "sms_granted_network" -> getString(R.string.xdr_reason_sms_network)
        "sms_declared_network" -> getString(R.string.xdr_reason_sms_declared)
        "calllog_plus_network", "calllog_granted_network" -> getString(R.string.xdr_reason_calllog_network)
        "calllog_declared_network" -> getString(R.string.xdr_reason_calllog_declared)
        "accessibility_plus_network", "accessibility_active_network" -> getString(R.string.xdr_reason_accessibility_network)
        "accessibility_capability_network" -> getString(R.string.xdr_reason_accessibility_declared)
        "device_admin_receiver", "device_admin_active" -> getString(R.string.xdr_reason_device_admin)
        "device_admin_capability" -> getString(R.string.xdr_reason_device_admin_declared)
        "persistent_sensor_bundle", "persistent_granted_sensor_bundle" -> getString(R.string.xdr_reason_sensor_bundle)
        "persistent_declared_sensor_bundle" -> getString(R.string.xdr_reason_sensor_declared)
        "unknown_install_source" -> getString(R.string.xdr_reason_unknown_installer)
        "embedded_blocklist_endpoint" -> getString(R.string.xdr_reason_blocklist_endpoint)
        "embedded_correlated_endpoint" -> getString(R.string.xdr_reason_correlated_endpoint)
        else -> code.replace('_', ' ')
    }


    private fun approvalLabel(state: AppApprovalState): String = getString(when (state) {
        AppApprovalState.APPROVED -> R.string.scanner_approval_state_approved
        AppApprovalState.STALE -> R.string.scanner_approval_state_stale
        AppApprovalState.NONE -> R.string.scanner_approval_state_none
    })

    private fun approvalColor(state: AppApprovalState): Int = when (state) {
        AppApprovalState.APPROVED -> GeDefenseUi.green
        AppApprovalState.STALE -> GeDefenseUi.orange
        AppApprovalState.NONE -> GeDefenseUi.textDim
    }

    private fun approvalActionFor(packageName: String): View? {
        val result = runtime.currentAppRiskResult(packageName) ?: return null
        if (result.signerSha256 == null || result.threatMatches.any { it.endsWith(":BLOCK") }) return null
        val approved = result.approvalState == AppApprovalState.APPROVED
        return GeDefenseUi.actionButton(
            this,
            getString(if (approved) R.string.scanner_approval_revoke else R.string.scanner_approval_approve),
            goldStyle = !approved,
        ) { confirmAppApproval(result) }
    }

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

    private fun activateEmergencyLockdown() {
        if (runtime.state.isVpnActive() && runtime.state.protectionMode() == ProtectionMode.LOCKDOWN) {
            Toast.makeText(this, getString(R.string.xdr_emergency_active), Toast.LENGTH_LONG).show()
            return
        }
        if (runtime.state.isVpnActive()) {
            try { startService(Intent(this, GeDefenseVpnService::class.java).setAction(GeDefenseVpnService.ACTION_STOP)) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("xdr-activity", error) }
            waitForVpnStop(0)
        } else startEmergencyVpn()
    }

    private fun waitForVpnStop(attempt: Int) {
        if (!runtime.state.isVpnActive()) { startEmergencyVpn(); return }
        if (attempt >= 12) {
            Toast.makeText(this, getString(R.string.xdr_emergency_failed), Toast.LENGTH_LONG).show()
            return
        }
        Handler(Looper.getMainLooper()).postDelayed({ waitForVpnStop(attempt + 1) }, 150L)
    }

    private fun startEmergencyVpn() {
        if (!runtime.vpnDisclosure.isAccepted()) {
            startActivityForResult(Intent(this, VpnDisclosureActivity::class.java), VPN_DISCLOSURE_REQUEST)
            return
        }
        val accepted = runtime.executeBackground("xdr-emergency-lockdown") {
            val prepared = try {
                runtime.state.setProtectionMode(ProtectionMode.LOCKDOWN)
                runtime.xdr.recordEmergencyLockdown()
                true
            } catch (_: RuntimeException) {
                false
            }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                if (!prepared) {
                    Toast.makeText(this, getString(R.string.xdr_emergency_failed), Toast.LENGTH_LONG).show()
                    return@runOnUiThread
                }
                val consent = VpnService.prepare(this)
                if (consent != null) startActivityForResult(consent, VPN_REQUEST) else startLockdownService()
            }
        }
        if (!accepted) Toast.makeText(this, getString(R.string.xdr_emergency_failed), Toast.LENGTH_LONG).show()
    }

    @Deprecated("VpnService consent uses activity result on the current minimum API")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when {
            requestCode == VPN_DISCLOSURE_REQUEST && resultCode == RESULT_OK -> startEmergencyVpn()
            requestCode == VPN_REQUEST && resultCode == RESULT_OK -> startLockdownService()
        }
    }

    private fun startLockdownService() {
        try { startService(Intent(this, GeDefenseVpnService::class.java).setAction(GeDefenseVpnService.ACTION_START)) } catch (_: RuntimeException) {
            Toast.makeText(this, getString(R.string.xdr_emergency_failed), Toast.LENGTH_LONG).show(); return
        }
        Toast.makeText(this, getString(R.string.xdr_emergency_started), Toast.LENGTH_LONG).show()
        refresh()
    }

    private fun toggleQuarantine(packageName: String, quarantine: Boolean) {
        val accepted = runtime.executeBackground("xdr-quarantine") {
            val changed = try { runtime.xdr.setQuarantined(packageName, quarantine) } catch (_: RuntimeException) { false }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                if (!changed) {
                    Toast.makeText(this, getString(R.string.xdr_policy_change_failed), Toast.LENGTH_LONG).show()
                    refresh()
                    return@runOnUiThread
                }
                if (runtime.state.isVpnActive() && runtime.state.protectionMode() == ProtectionMode.LOCKDOWN) {
                    try { startService(Intent(this, GeDefenseVpnService::class.java).setAction(GeDefenseVpnService.ACTION_REFRESH)) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("xdr-activity", error) }
                }
                Toast.makeText(
                    this,
                    getString(if (quarantine && runtime.state.protectionMode() == ProtectionMode.LOCKDOWN) R.string.xdr_quarantine_effective else if (quarantine) R.string.xdr_lockdown_required else R.string.xdr_unquarantined),
                    Toast.LENGTH_LONG,
                ).show()
                refresh()
            }
        }
        if (!accepted) Toast.makeText(this, getString(R.string.xdr_policy_change_failed), Toast.LENGTH_LONG).show()
    }

    private fun updateCoverage(hardening: HardeningSnapshot) {
        coverageHost.removeAllViews()
        coverageHost.addView(GeDefenseUi.textView(this, getString(R.string.xdr_sensor_coverage), 9f, GeDefenseUi.textDim, bold = true))
        coverageHost.addView(coverageLine(getString(R.string.xdr_sensor_package), getString(R.string.xdr_sensor_active), GeDefenseUi.green))
        val scannerState = runtime.deviceScanSnapshot.get().state
        coverageHost.addView(coverageLine(getString(R.string.xdr_sensor_scanner), if (scannerState == "RUNNING") getString(R.string.ui_live) else getString(R.string.xdr_sensor_ready), if (scannerState == "FAILED") GeDefenseUi.orange else GeDefenseUi.green))
        val networkLive = runtime.state.isVpnActive()
        coverageHost.addView(coverageLine(getString(R.string.xdr_sensor_network), getString(if (networkLive) R.string.ui_live else R.string.xdr_sensor_standby), if (networkLive) GeDefenseUi.cyan else GeDefenseUi.gold))
        val lan = runtime.networkDiscoverySnapshot.get()
        val lanState = when {
            !runtime.networkDiscoveryStore.integrityOk() -> getString(R.string.ui_attention)
            runtime.isNetworkDiscoveryRunning() -> getString(R.string.ui_live)
            lan.networkBehaviorSignals.isNotEmpty() || lan.anomalousDevices > 0 -> getString(R.string.ui_attention)
            lan.networkBaselineObservations >= 4 -> getString(R.string.xdr_sensor_active)
            lan.state == "COMPLETE" -> getString(R.string.behavior_learning)
            else -> getString(R.string.xdr_sensor_standby)
        }
        val lanColor = when {
            !runtime.networkDiscoveryStore.integrityOk() -> GeDefenseUi.red
            runtime.isNetworkDiscoveryRunning() -> GeDefenseUi.cyan
            lan.networkBehaviorSignals.isNotEmpty() || lan.anomalousDevices > 0 -> GeDefenseUi.orange
            lan.networkBaselineObservations >= 4 -> GeDefenseUi.green
            else -> GeDefenseUi.gold
        }
        coverageHost.addView(coverageLine(getString(R.string.xdr_sensor_lan), lanState, lanColor))
        val sentinel = runtime.portSentinelSnapshot()
        val sentinelState = when {
            !sentinel.integrityOk -> getString(R.string.ui_attention)
            sentinel.runtime.active -> getString(R.string.xdr_sensor_active)
            sentinel.runtime.lastError != null -> getString(R.string.ui_attention)
            else -> getString(R.string.xdr_sensor_standby)
        }
        val sentinelColor = when {
            !sentinel.integrityOk -> GeDefenseUi.red
            sentinel.runtime.active -> GeDefenseUi.cyan
            sentinel.runtime.lastError != null -> GeDefenseUi.orange
            else -> GeDefenseUi.gold
        }
        coverageHost.addView(coverageLine(getString(R.string.xdr_sensor_sentinel), sentinelState, sentinelColor))
        val titan = runtime.titan.snapshot()
        val titanState = when {
            !titan.policyStoreIntegrityOk -> getString(R.string.ui_attention)
            titan.titanActive -> getString(R.string.xdr_sensor_active)
            titan.titanLightActive -> getString(R.string.titan_light_mode)
            else -> getString(R.string.xdr_sensor_standby)
        }
        val titanColor = when {
            !titan.policyStoreIntegrityOk -> GeDefenseUi.red
            titan.titanActive -> GeDefenseUi.gold
            titan.titanLightActive -> GeDefenseUi.cyan
            else -> GeDefenseUi.textDim
        }
        coverageHost.addView(coverageLine(getString(R.string.xdr_sensor_titan), titanState, titanColor))
        val integrity = runtime.integritySnapshot.get()
        coverageHost.addView(coverageLine(getString(R.string.xdr_sensor_integrity), getString(if (integrity.ok) R.string.ui_verified else R.string.ui_attention), if (integrity.ok) GeDefenseUi.green else GeDefenseUi.orange))
        val hardeningState = if (hardening.checkedAtMillis == 0L) getString(R.string.ui_waiting) else getString(R.string.hardening_score, hardening.score)
        coverageHost.addView(coverageLine(getString(R.string.xdr_sensor_hardening), hardeningState, if (hardening.score >= 75) GeDefenseUi.green else GeDefenseUi.gold))
        val behavior = runtime.behavior.snapshot()
        val behaviorState = when {
            !behavior.baselineIntegrityOk -> getString(R.string.ui_attention)
            behavior.matureProfiles > 0 -> getString(R.string.xdr_sensor_active)
            behavior.learningProfiles > 0 -> getString(R.string.behavior_learning)
            else -> getString(R.string.xdr_sensor_standby)
        }
        val behaviorColor = when {
            !behavior.baselineIntegrityOk -> GeDefenseUi.red
            behavior.matureProfiles > 0 -> GeDefenseUi.cyan
            else -> GeDefenseUi.gold
        }
        coverageHost.addView(coverageLine(getString(R.string.xdr_sensor_behavior), behaviorState, behaviorColor))
    }


    private fun updateTrustStores(snapshot: XdrSnapshot) {
        trustHost.removeAllViews()
        trustHost.addView(GeDefenseUi.textView(this, getString(R.string.xdr_trust_state_title), 9f, GeDefenseUi.textDim, bold = true))
        val healthy = snapshot.trustStoresHealthy
        trustHost.addView(GeDefenseUi.textView(
            this,
            getString(if (healthy) R.string.xdr_trust_state_verified else R.string.xdr_trust_state_degraded),
            9.5f,
            if (healthy) GeDefenseUi.green else GeDefenseUi.red,
            bold = true,
        ).apply { setPadding(0, dp(6), 0, 0) })
        if (!snapshot.eventStoreIntegrityOk) {
            trustHost.addView(GeDefenseUi.actionButton(this, getString(R.string.xdr_recover_event_store)) { confirmRecoverEventStore() }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
        }
        if (!snapshot.packageBaselineIntegrityOk) {
            trustHost.addView(GeDefenseUi.actionButton(this, getString(R.string.xdr_reset_package_baseline)) { confirmResetPackageBaseline() }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
        }
        if (!snapshot.firewallPolicyIntegrityOk) {
            trustHost.addView(GeDefenseUi.actionButton(this, getString(R.string.xdr_reset_firewall_policy), goldStyle = true) { confirmResetFirewallPolicy() }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
        }
        if (!snapshot.networkDiscoveryIntegrityOk) {
            trustHost.addView(GeDefenseUi.actionButton(this, getString(R.string.xdr_recover_network_baseline)) {
                startActivity(Intent(this@XdrActivity, NetworkDiscoveryActivity::class.java))
            }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
        }
        if (!snapshot.portSentinelIntegrityOk) {
            trustHost.addView(GeDefenseUi.actionButton(this, getString(R.string.port_sentinel_reset_store), goldStyle = true) {
                startActivity(Intent(this@XdrActivity, PortSentinelActivity::class.java))
            }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
        }
        if (!snapshot.titanPolicyIntegrityOk) {
            trustHost.addView(GeDefenseUi.actionButton(this, getString(R.string.titan_open), goldStyle = true) {
                startActivity(Intent(this@XdrActivity, TitanActivity::class.java))
            }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
        }
    }

    private fun confirmRecoverEventStore() {
        AlertDialog.Builder(this)
            .setTitle(R.string.xdr_recover_event_store_title)
            .setMessage(R.string.xdr_recover_event_store_body)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.xdr_recover_action) { _, _ ->
                if (!runtime.executeBackground("xdr-recover-events") {
                    val recovered = runtime.xdr.recoverXdrEventStore()
                    runOnUiThread {
                        Toast.makeText(this, getString(if (recovered != null) R.string.xdr_recover_done else R.string.xdr_recover_failed), Toast.LENGTH_LONG).show()
                        refresh()
                    }
                }) Toast.makeText(this, R.string.xdr_recover_failed, Toast.LENGTH_LONG).show()
            }.show()
    }

    private fun confirmResetPackageBaseline() {
        AlertDialog.Builder(this)
            .setTitle(R.string.xdr_reset_package_baseline_title)
            .setMessage(R.string.xdr_reset_package_baseline_body)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.xdr_recover_action) { _, _ ->
                if (!runtime.executeBackground("xdr-reset-baseline") {
                    val ok = runtime.xdr.resetPackageBaseline()
                    runOnUiThread { Toast.makeText(this, getString(if (ok) R.string.xdr_recover_done else R.string.xdr_recover_failed), Toast.LENGTH_LONG).show(); refresh() }
                }) Toast.makeText(this, R.string.xdr_recover_failed, Toast.LENGTH_LONG).show()
            }.show()
    }

    private fun confirmResetFirewallPolicy() {
        AlertDialog.Builder(this)
            .setTitle(R.string.xdr_reset_firewall_policy_title)
            .setMessage(R.string.xdr_reset_firewall_policy_body)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.xdr_recover_action) { _, _ ->
                if (!runtime.executeBackground("xdr-reset-firewall") {
                    val ok = runtime.xdr.resetFirewallPolicy()
                    runOnUiThread {
                        if (ok && runtime.state.isVpnActive() && runtime.state.protectionMode() == ProtectionMode.LOCKDOWN) {
                            try { startService(Intent(this, GeDefenseVpnService::class.java).setAction(GeDefenseVpnService.ACTION_REFRESH)) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("xdr-activity", error) }
                        }
                        Toast.makeText(this, getString(if (ok) R.string.xdr_recover_done else R.string.xdr_recover_failed), Toast.LENGTH_LONG).show()
                        refresh()
                    }
                }) Toast.makeText(this, R.string.xdr_recover_failed, Toast.LENGTH_LONG).show()
            }.show()
    }

    private fun coverageLine(label: String, value: String, accent: Int): View = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setPadding(0, dp(6), 0, 0)
        addView(GeDefenseUi.textView(this@XdrActivity, label, 9f, GeDefenseUi.textMuted), LinearLayout.LayoutParams(0, -2, 1f))
        addView(GeDefenseUi.pill(this@XdrActivity, value, accent))
    }

    private fun incidentRecommendation(incident: XdrIncident): String = when {
        incident.severity == XdrSeverity.CRITICAL -> getString(R.string.xdr_recommend_critical)
        incident.severity == XdrSeverity.HIGH -> getString(R.string.xdr_recommend_high)
        XdrCategory.BEHAVIOR in incident.categories -> getString(R.string.xdr_recommend_behavior)
        XdrCategory.NETWORK in incident.categories && incident.key.startsWith("lan:") -> getString(R.string.xdr_recommend_lan)
        XdrCategory.SYSTEM in incident.categories -> getString(R.string.xdr_recommend_hardening)
        else -> getString(R.string.xdr_recommend_monitor)
    }

    private fun sectionCard(icon: VgtIcon, accent: Int, title: String, content: Array<View>): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@XdrActivity, accent = accent, radius = 18)
        addView(LinearLayout(this@XdrActivity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(16), dp(18), dp(16))
            addView(LinearLayout(this@XdrActivity).apply {
                orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(this@XdrActivity, icon, accent, 32), LinearLayout.LayoutParams(dp(32), dp(32)))
                addView(GeDefenseUi.sectionTitle(this@XdrActivity, title), LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(12) })
            })
            content.forEach { child -> addView(child, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) }) }
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun severityColor(severity: XdrSeverity): Int = when (severity) {
        XdrSeverity.CRITICAL -> GeDefenseUi.red
        XdrSeverity.HIGH -> GeDefenseUi.orange
        XdrSeverity.MEDIUM -> GeDefenseUi.gold
        XdrSeverity.LOW -> GeDefenseUi.cyan
        XdrSeverity.INFO -> GeDefenseUi.green
    }

    private fun eventIcon(category: XdrCategory): VgtIcon = when (category) {
        XdrCategory.NETWORK -> VgtIcon.TRAFFIC
        XdrCategory.BEHAVIOR -> VgtIcon.ACTIVITY
        XdrCategory.MALWARE -> VgtIcon.SCANNER
        XdrCategory.INTEGRITY -> VgtIcon.INTEGRITY
        XdrCategory.RESPONSE -> VgtIcon.BLOCK
        XdrCategory.PERMISSION -> VgtIcon.POLICY
        XdrCategory.SIGNER -> VgtIcon.EVIDENCE
        XdrCategory.PACKAGE -> VgtIcon.SHIELD
        XdrCategory.SYSTEM -> VgtIcon.SETTINGS
    }

    private fun emptyText(id: Int) = GeDefenseUi.textView(this, getString(id), 10f, GeDefenseUi.textDim).apply {
        gravity = Gravity.CENTER; setPadding(dp(12), dp(22), dp(12), dp(22))
    }

    private fun addHostGap(host: LinearLayout, value: Int) = host.addView(View(this), LinearLayout.LayoutParams(1, dp(value)))

    private fun configureSystemBars() = VgtWindowInsets.configureSystemBars(window)

    private fun gap(value: Int) = GeDefenseUi.addVerticalGap(rootLayout, this, value)
    private fun dp(value: Int) = GeDefenseUi.dp(this, value)

    private enum class XdrViewMode { FINDINGS, FORENSICS }

    companion object {
        const val EXTRA_PACKAGE = "de.visiongaia.gedefense.mobile.extra.XDR_PACKAGE"
        private const val VPN_REQUEST = 7312
        private const val VPN_DISCLOSURE_REQUEST = 7313
    }
}
