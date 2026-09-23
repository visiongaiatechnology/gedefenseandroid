package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.graphics.Color
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

// STATUS: DIAMANT VGT SUPREME
class DashboardScreen(
    private val activity: Activity,
    private val actions: UiActions,
) {
    val view: View

    private val heroContainer: View
    private val heroPulse: ShieldPulseView
    private val heroTexture: ImageView
    private val heroTitle: TextView
    private val heroDetail: TextView
    private val heroMeta: TextView
    private val modeBadge: TextView
    private val routesValue: TextView
    private val routesLabel: TextView
    private val healthValue: TextView
    private val healthBar: VgtProgressView
    private val feedsValue: TextView
    private val threatsValue: TextView
    private val activeFlowsValue: TextView
    private val sessionBlockedValue: TextView
    private val destinationsValue: TextView
    private val appsValue: TextView
    private val lastEventValue: TextView
    private val modeNotice: TextView
    private val primaryAction: VgtActionTile
    private val syncAction: VgtActionTile
    private val analysisBadge: TextView
    private val analysisTitle: TextView
    private val analysisDetail: TextView
    private val analysisProgress: VgtProgressView
    private val analysisFindingsHost: LinearLayout
    private var lastDashboardAnalysisKey = ""

    private val rootLayout: LinearLayout
    private var lastGuarded: Boolean? = null
    private var lastMode: ProtectionMode? = null
    private var lastHealthy: Boolean? = null
    private var lastPrimaryEnabled: Boolean? = null

    init {
        val scroll = ScrollView(activity).apply {
            isFillViewport = true
            overScrollMode = View.OVER_SCROLL_NEVER
            clipToPadding = false
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

        rootLayout.addView(buildHeader())
        gap(rootLayout, GeDefenseUi.SPACING_CARD_GAP_DP)

        modeBadge = GeDefenseUi.pill(activity, "", GeDefenseUi.cyan)
        heroPulse = ShieldPulseView(activity)
        heroTexture = ImageView(activity).apply {
            setImageResource(R.drawable.hero_energy_texture)
            scaleType = ImageView.ScaleType.CENTER_INSIDE
            alpha = 0.18f
        }

        // 1. DecorationLayer
        heroContainer = FrameLayout(activity).apply {
            background = GeDefenseUi.heroPanelBackground(activity, false)
            elevation = dp(5).toFloat()
        }

        // 2. ContentContainer (HeroContent) with 20dp padding on all sides
        val heroContent = FrameLayout(activity).apply {
            setPadding(dp(20), dp(18), dp(20), dp(20))
        }
        heroContainer.addView(heroContent, FrameLayout.LayoutParams(-1, -2))

        // FULL FLOW badge is positioned relative to HeroContent!
        heroContent.addView(modeBadge, FrameLayout.LayoutParams(-2, -2, Gravity.TOP or Gravity.END))

        val heroStack = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(0, dp(10), 0, dp(4))
        }
        heroContent.addView(heroStack, FrameLayout.LayoutParams(-1, -2))

        val logoStage = FrameLayout(activity).apply { layoutParams = LinearLayout.LayoutParams(-1, dp(165)) }
        logoStage.addView(heroTexture, FrameLayout.LayoutParams(-1, -1))
        logoStage.addView(heroPulse, FrameLayout.LayoutParams(-1, -1))
        logoStage.addView(ImageView(activity).apply {
            setImageResource(R.drawable.gedefense_logo)
            scaleType = ImageView.ScaleType.FIT_CENTER
        }, FrameLayout.LayoutParams(dp(114), dp(114), Gravity.CENTER))
        heroStack.addView(logoStage)

        heroTitle = GeDefenseUi.displayTextView(activity, "", 24f, GeDefenseUi.cyan).apply {
            gravity = Gravity.CENTER
            setPadding(dp(8), dp(6), dp(8), 0)
        }
        heroDetail = GeDefenseUi.textView(activity, "", 11.5f, GeDefenseUi.textMuted).apply {
            gravity = Gravity.CENTER
            setPadding(dp(12), dp(5), dp(12), 0)
        }
        heroMeta = GeDefenseUi.textView(activity, "", 9.5f, GeDefenseUi.textDim, bold = true).apply {
            gravity = Gravity.CENTER
            setPadding(dp(12), dp(8), dp(12), dp(16)) // >= 16dp space below it, never on lower border!
        }
        heroStack.addView(heroTitle)
        heroStack.addView(heroDetail)
        heroStack.addView(heroMeta)
        rootLayout.addView(heroContainer)

        gap(rootLayout, GeDefenseUi.SPACING_CARD_GAP_DP)
        routesValue = GeDefenseUi.displayTextView(activity, "0", 21f)
        routesLabel = GeDefenseUi.textView(activity, activity.getString(R.string.ui_routes_ready), 10f, GeDefenseUi.textMuted)
        healthValue = GeDefenseUi.textView(activity, "", 16f, GeDefenseUi.text, bold = true)
        healthBar = VgtProgressView(activity, GeDefenseUi.green)
        feedsValue = GeDefenseUi.displayTextView(activity, "0/0", 21f)
        threatsValue = GeDefenseUi.displayTextView(activity, "0", 21f)
        rootLayout.addView(metricGrid(
            metricCard(VgtIcon.ROUTES, GeDefenseUi.green, routesValue, routesLabel),
            metricCard(VgtIcon.HEALTH, GeDefenseUi.cyan, healthValue, GeDefenseUi.textView(activity, activity.getString(R.string.ui_protection_health), 10f, GeDefenseUi.textMuted), healthBar),
            metricCard(VgtIcon.INTELLIGENCE, GeDefenseUi.green, feedsValue, GeDefenseUi.textView(activity, activity.getString(R.string.ui_live_intelligence), 10f, GeDefenseUi.textMuted)),
            metricCard(VgtIcon.ALERT, GeDefenseUi.red, threatsValue, GeDefenseUi.textView(activity, activity.getString(R.string.ui_blocked_session), 10f, GeDefenseUi.textMuted)),
        ))

        gap(rootLayout, GeDefenseUi.SPACING_SECTION_GAP_DP)
        rootLayout.addView(GeDefenseUi.sectionTitle(activity, activity.getString(R.string.dashboard_analysis_title)))
        gap(rootLayout, 12)
        analysisBadge = GeDefenseUi.pill(activity, activity.getString(R.string.ui_waiting), GeDefenseUi.gold)
        analysisTitle = GeDefenseUi.textView(activity, activity.getString(R.string.dashboard_analysis_never), 14f, GeDefenseUi.text, bold = true)
        analysisDetail = GeDefenseUi.textView(activity, activity.getString(R.string.scanner_idle_body), 9.8f, GeDefenseUi.textMuted)
        analysisProgress = VgtProgressView(activity, GeDefenseUi.cyan)
        analysisFindingsHost = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
        rootLayout.addView(dashboardAnalysisCard())

        gap(rootLayout, GeDefenseUi.SPACING_SECTION_GAP_DP)
        rootLayout.addView(GeDefenseUi.sectionTitle(activity, activity.getString(R.string.ui_quick_actions)))
        gap(rootLayout, 12)
        primaryAction = VgtActionTile(activity, VgtIcon.ACTIVATE, activity.getString(R.string.activate), VgtActionStyle.PRIMARY) { actions.activateProtection() }
        val activityTile = VgtActionTile(activity, VgtIcon.ACTIVITY, activity.getString(R.string.nav_activity)) { actions.navigateTo(1) }
        syncAction = VgtActionTile(activity, VgtIcon.SYNC, activity.getString(R.string.sync_feeds)) { actions.synchronizeFeeds() }
        val settingsTile = VgtActionTile(activity, VgtIcon.SETTINGS, activity.getString(R.string.nav_more)) { actions.navigateTo(4) }
        rootLayout.addView(actionGrid(primaryAction, activityTile, syncAction, settingsTile))

        gap(rootLayout, GeDefenseUi.SPACING_CARD_GAP_DP)
        activeFlowsValue = GeDefenseUi.displayTextView(activity, "0", 18f)
        sessionBlockedValue = GeDefenseUi.displayTextView(activity, "0", 18f)
        destinationsValue = GeDefenseUi.displayTextView(activity, "0", 18f)
        appsValue = GeDefenseUi.displayTextView(activity, "0", 18f)
        lastEventValue = GeDefenseUi.textView(activity, "", 10f, GeDefenseUi.textDim)
        rootLayout.addView(sessionCard())

        gap(rootLayout, GeDefenseUi.SPACING_CARD_GAP_DP)
        modeNotice = GeDefenseUi.textView(activity, "", 10f, GeDefenseUi.textDim)
        rootLayout.addView(FrameLayout(activity).apply {
            background = GeDefenseUi.softPanelBackground(activity, 15, GeDefenseUi.blue)
            val content = LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(dp(20), dp(16), dp(20), dp(16))
                addView(VgtIconView(activity, VgtIcon.SHIELD, GeDefenseUi.blue), LinearLayout.LayoutParams(dp(18), dp(18)))
                modeNotice.setPadding(dp(12), 0, 0, 0)
                addView(modeNotice, LinearLayout.LayoutParams(0, -2, 1f))
            }
            addView(content, FrameLayout.LayoutParams(-1, -2))
        })

        view = scroll
    }

    fun setBottomPadding(bottomPx: Int) {
        rootLayout.setPadding(rootLayout.paddingLeft, rootLayout.paddingTop, rootLayout.paddingRight, bottomPx)
    }

    fun setSyncing(syncing: Boolean) {
        syncAction.isEnabled = !syncing
        syncAction.setLabel(activity.getString(if (syncing) R.string.syncing else R.string.sync_feeds))
    }

    fun update(snapshot: UiSnapshot) {
        val guarded = snapshot.vpnActive && snapshot.vpnStatus in setOf("GUARDED", "FULL_GUARDED", "LOCKDOWN_GUARDED")
        val policyReady = when (snapshot.protectionMode) {
            ProtectionMode.SELECTIVE -> snapshot.compactedRoutes > 0 && !snapshot.routeOverflow
            ProtectionMode.FULL_FLOW_BETA -> snapshot.indexedPrefixes > 0 && snapshot.nativeFullFlowAvailable
            ProtectionMode.LOCKDOWN -> true
        }
        val healthy = snapshot.evidenceOk && snapshot.integrity.ok && policyReady

        heroPulse.setProtectionActive(guarded)
        if (lastGuarded != guarded) {
            lastGuarded = guarded
            heroTexture.animate().cancel()
            heroTexture.alpha = if (guarded) 0.88f else 0.16f
            heroContainer.background = GeDefenseUi.heroPanelBackground(activity, guarded)
            primaryAction.setLabel(activity.getString(if (guarded) R.string.deactivate else R.string.activate))
            primaryAction.setIcon(if (guarded) VgtIcon.PAUSE else VgtIcon.ACTIVATE)
            primaryAction.setStyle(if (guarded) VgtActionStyle.DESTRUCTIVE else VgtActionStyle.PRIMARY)
            primaryAction.setOnClickListener { if (guarded) actions.deactivateProtection() else actions.activateProtection() }
        }
        heroTitle.text = when {
            guarded -> activity.getString(R.string.ui_protection_active)
            snapshot.vpnStatus == "STARTING" -> activity.getString(R.string.status_starting)
            snapshot.vpnStatus.startsWith("DEGRADED") || snapshot.vpnStatus.contains("FAILED") -> activity.getString(R.string.ui_protection_attention)
            else -> activity.getString(R.string.ui_protection_off)
        }
        heroTitle.setTextColor(if (guarded) GeDefenseUi.cyan else if (healthy) GeDefenseUi.gold else GeDefenseUi.red)
        heroDetail.text = statusDetail(snapshot)

        val fullFlow = snapshot.protectionMode == ProtectionMode.FULL_FLOW_BETA
        val lockdown = snapshot.protectionMode == ProtectionMode.LOCKDOWN
        val vectorCount = if (fullFlow) snapshot.indexedPrefixes else snapshot.compactedRoutes
        if (lastMode != snapshot.protectionMode) {
            lastMode = snapshot.protectionMode
            modeBadge.text = activity.getString(when {
                lockdown -> R.string.ui_lockdown_badge
                fullFlow -> R.string.ui_full_flow_badge
                else -> R.string.ui_selective_badge
            })
            val modeAccent = if (lockdown) GeDefenseUi.red else if (fullFlow) GeDefenseUi.cyan else GeDefenseUi.gold
            modeBadge.setTextColor(modeAccent)
            modeBadge.background = GeDefenseUi.badgeBackground(activity, modeAccent)
            modeNotice.text = activity.getString(if (fullFlow) R.string.mode_full_flow_detail else R.string.ui_selective_route_notice)
        }
        heroMeta.text = if (lockdown) {
            activity.getString(R.string.firewall_default_deny_short)
        } else {
            "${snapshot.healthyFeeds}/${snapshot.feeds.size} ${activity.getString(R.string.ui_live_intelligence)}  ·  $vectorCount ${activity.getString(if (fullFlow) R.string.ui_threat_vectors_active else R.string.ui_routes_ready)}"
        }

        routesValue.text = if (lockdown) activity.getString(R.string.ui_locked) else vectorCount.toString()
        routesLabel.text = activity.getString(if (lockdown) R.string.ui_network_access else if (fullFlow) R.string.ui_threat_vectors_active else R.string.ui_routes_ready)
        healthValue.text = when {
            !healthy -> activity.getString(R.string.ui_attention)
            guarded -> activity.getString(R.string.ui_excellent)
            else -> activity.getString(R.string.ui_ready)
        }
        if (lastHealthy != healthy) {
            lastHealthy = healthy
            healthValue.setTextColor(if (healthy) GeDefenseUi.green else GeDefenseUi.red)
            healthBar.setProgress(if (healthy) 0.98f else 0.38f, if (healthy) GeDefenseUi.cyan else GeDefenseUi.red)
        }
        feedsValue.text = activity.getString(R.string.ui_feed_ratio, snapshot.healthyFeeds, snapshot.feeds.size)
        threatsValue.text = snapshot.blockedPackets.toString()

        activeFlowsValue.text = snapshot.activeFlows.toString()
        sessionBlockedValue.text = snapshot.blockedPackets.toString()
        destinationsValue.text = snapshot.uniqueDestinations.toString()
        appsValue.text = snapshot.attributedApps.toString()
        lastEventValue.text = activity.getString(
            R.string.ui_last_security_event_value,
            if (snapshot.lastBlockedAtMillis > 0L) GeDefenseUi.formatTime(activity, snapshot.lastBlockedAtMillis) else activity.getString(R.string.ui_none),
        )
        updateDashboardAnalysis(snapshot)

        val primaryEnabled = guarded || (!snapshot.vpnActive && policyReady && snapshot.evidenceOk && snapshot.integrity.ok)
        if (lastPrimaryEnabled != primaryEnabled) {
            lastPrimaryEnabled = primaryEnabled
            primaryAction.isEnabled = primaryEnabled
        }
    }

    private fun buildHeader(): View = LinearLayout(activity).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        addView(ImageView(activity).apply {
            setImageResource(R.drawable.gedefense_logo)
            scaleType = ImageView.ScaleType.FIT_CENTER
        }, LinearLayout.LayoutParams(dp(46), dp(46)))
        addView(LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), 0, 0, 0)
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(GeDefenseUi.textView(activity, "GeDefense", 19.5f, GeDefenseUi.gold, bold = true))
                addView(GeDefenseUi.textView(activity, " Mobile", 18.5f, GeDefenseUi.text, bold = false))
            })
            addView(GeDefenseUi.textView(activity, activity.getString(R.string.ui_protect_detect_block), 8.6f, GeDefenseUi.textMuted, bold = true).apply {
                letterSpacing = 0.15f
                setPadding(0, dp(3), 0, 0)
            })
            addView(GeDefenseUi.textView(activity, activity.getString(R.string.powered_by_vgt), 8.2f, GeDefenseUi.cyan, bold = true).apply {
                letterSpacing = 0.08f
                setPadding(0, dp(2), 0, 0)
            })
        }, LinearLayout.LayoutParams(0, -2, 1f))
        addView(VgtUiComponents.iconWell(activity, VgtIcon.BELL, GeDefenseUi.gold, 34), LinearLayout.LayoutParams(dp(34), dp(34)))
    }

    private fun metricGrid(vararg cards: View): View {
        val vertical = activity.resources.configuration.screenWidthDp < 360
        val root = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
        val cardGap = GeDefenseUi.cardGap(activity)
        if (vertical) {
            cards.forEachIndexed { index, card ->
                root.addView(card, LinearLayout.LayoutParams(-1, -2).apply {
                    if (index > 0) topMargin = cardGap
                })
            }
            return root
        }
        val halfGap = GeDefenseUi.cardHorizontalGap(activity) / 2
        for (i in cards.indices step 2) {
            val row = LinearLayout(activity).apply { orientation = LinearLayout.HORIZONTAL }
            row.addView(cards[i], LinearLayout.LayoutParams(0, -2, 1f).apply { rightMargin = halfGap })
            cards.getOrNull(i + 1)?.let {
                row.addView(it, LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = halfGap })
            }
            root.addView(row, LinearLayout.LayoutParams(-1, -2).apply {
                if (i > 0) topMargin = cardGap
            })
        }
        return root
    }

    private fun metricCard(
        icon: VgtIcon,
        accent: Int,
        value: TextView,
        label: TextView,
        progress: VgtProgressView? = null,
    ): View = FrameLayout(activity).apply {
        minimumHeight = dp(132)
        // 1. DecorationLayer
        background = GeDefenseUi.glassPanelBackground(activity, accent = accent, radius = 18)
        elevation = dp(2).toFloat()

        // 2. ContentContainer: Centered horizontally and vertically
        val content = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(dp(16), dp(16), dp(16), dp(16))

            // Centered Icon well
            addView(VgtUiComponents.iconWell(activity, icon, accent, 34), LinearLayout.LayoutParams(dp(34), dp(34)).apply {
                gravity = Gravity.CENTER_HORIZONTAL
            })

            // Centered main metric
            value.setPadding(0, 0, 0, 0)
            value.gravity = Gravity.CENTER
            value.textAlignment = View.TEXT_ALIGNMENT_CENTER
            addView(value, LinearLayout.LayoutParams(-1, -2).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                topMargin = dp(8)
            })

            // Centered label
            label.setPadding(0, 0, 0, 0)
            label.gravity = Gravity.CENTER
            label.textAlignment = View.TEXT_ALIGNMENT_CENTER
            addView(label, LinearLayout.LayoutParams(-1, -2).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                topMargin = dp(4)
            })

            // Optional progress/status element
            if (progress != null) {
                addView(progress, LinearLayout.LayoutParams(-1, dp(4)).apply {
                    gravity = Gravity.CENTER_HORIZONTAL
                    topMargin = dp(8)
                    leftMargin = dp(8)
                    rightMargin = dp(8)
                })
            }
        }
        addView(content, FrameLayout.LayoutParams(-1, -1, Gravity.CENTER))
    }

    private fun actionGrid(vararg tiles: View): View {
        val root = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
        val cardGap = GeDefenseUi.cardGap(activity)
        val halfGap = GeDefenseUi.cardHorizontalGap(activity) / 2
        for (i in tiles.indices step 2) {
            val row = LinearLayout(activity).apply { orientation = LinearLayout.HORIZONTAL }
            row.addView(tiles[i], LinearLayout.LayoutParams(0, -2, 1f).apply { rightMargin = halfGap })
            tiles.getOrNull(i + 1)?.let {
                row.addView(it, LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = halfGap })
            }
            root.addView(row, LinearLayout.LayoutParams(-1, -2).apply {
                if (i > 0) topMargin = cardGap
            })
        }
        return root
    }

    private fun sessionCard(): View = FrameLayout(activity).apply {
        // 1. DecorationLayer
        background = GeDefenseUi.glassPanelBackground(activity, radius = 18)
        elevation = dp(2).toFloat()
        addView(VgtUiComponents.accentRule(activity, GeDefenseUi.cyan, 56), FrameLayout.LayoutParams(dp(56), dp(2)).apply {
            topMargin = dp(10)
            leftMargin = dp(20)
        })

        // 2. ContentContainer
        val content = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(20), dp(20), dp(18))

            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(VgtIconView(activity, VgtIcon.ACTIVITY, GeDefenseUi.cyan), LinearLayout.LayoutParams(dp(18), dp(18)))
                addView(GeDefenseUi.sectionTitle(activity, activity.getString(R.string.session_metrics)).apply { setPadding(dp(10), 0, 0, 0) })
            })
            gap(this, 14)
            addView(metricGrid(
                xdrMetric(activeFlowsValue, activity.getString(R.string.ui_active_flows), GeDefenseUi.cyan),
                xdrMetric(sessionBlockedValue, activity.getString(R.string.ui_blocked_packets), GeDefenseUi.red),
                xdrMetric(destinationsValue, activity.getString(R.string.ui_threat_targets), GeDefenseUi.gold),
                xdrMetric(appsValue, activity.getString(R.string.ui_apps_active), GeDefenseUi.green),
            ))
            addView(lastEventValue, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) })
        }
        addView(content, FrameLayout.LayoutParams(-1, -2))
    }

    private fun xdrMetric(value: TextView, label: String, accent: Int): View = FrameLayout(activity).apply {
        background = GeDefenseUi.softPanelBackground(activity, 14, accent)
        val content = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), dp(12), dp(14), dp(12))
            value.setPadding(0, 0, 0, 0)
            addView(value)
            addView(GeDefenseUi.textView(activity, label, 9.2f, GeDefenseUi.textMuted).apply { setPadding(0, dp(4), 0, 0) })
        }
        addView(content, FrameLayout.LayoutParams(-1, -2))
    }

    private fun dashboardAnalysisCard(): View = FrameLayout(activity).apply {
        background = GeDefenseUi.glassPanelBackground(activity, accent = GeDefenseUi.cyan, radius = 18)
        elevation = dp(2).toFloat()
        addView(LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(17), dp(20), dp(18))
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(activity, VgtIcon.SCANNER, GeDefenseUi.cyan, 36), LinearLayout.LayoutParams(dp(36), dp(36)))
                addView(LinearLayout(activity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(dp(13), 0, dp(9), 0)
                    addView(analysisTitle)
                    addView(analysisDetail.apply { setPadding(0, dp(4), 0, 0) })
                }, LinearLayout.LayoutParams(0, -2, 1f))
                addView(analysisBadge)
            })
            addView(analysisProgress, LinearLayout.LayoutParams(-1, dp(4)).apply { topMargin = dp(13) })
            addView(analysisFindingsHost, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                val gap = dp(6)
                addView(GeDefenseUi.actionButton(activity, activity.getString(R.string.scanner_open), goldStyle = true) { actions.openMalwareScanner() }, LinearLayout.LayoutParams(0, -2, 1f).apply { rightMargin = gap })
                addView(GeDefenseUi.actionButton(activity, activity.getString(R.string.dashboard_analysis_open)) { actions.navigateTo(3) }, LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = gap })
            }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(13) })
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun updateDashboardAnalysis(snapshot: UiSnapshot) {
        val scan = snapshot.deviceScan
        val running = scan.state == "RUNNING"
        val app = if (scan.state == "COMPLETE") scan.apps else snapshot.appScan
        val restoring = !running && app.state == "RESTORING"
        val storage = scan.storage
        val appFindings = app.results.filter {
            it.riskScore >= AppRiskScanner.USER_VISIBLE_REVIEW_THRESHOLD || it.threatMatches.isNotEmpty() || it.approvalState == AppApprovalState.STALE
        }.sortedByDescending { it.riskScore }
        val fileFindings = storage.results.filter { it.riskScore > 0 }.sortedByDescending { it.riskScore }
        val allFindings = buildList {
            appFindings.take(2).forEach { add(DashboardFinding(it.label, it.riskScore, dashboardAppRiskColor(it.riskLevel))) }
            fileFindings.take(2).forEach { add(DashboardFinding(it.displayName, it.riskScore, dashboardFileRiskColor(it.riskLevel))) }
        }.sortedByDescending { it.score }.take(2)
        val matches = app.threatMatchedPackages + storage.threatMatchedFiles
        val findingCount = appFindings.size + fileFindings.size
        val color = when {
            running || restoring -> GeDefenseUi.cyan
            scan.state == "FAILED" -> GeDefenseUi.red
            allFindings.any { it.score >= 70 } -> GeDefenseUi.red
            allFindings.isNotEmpty() -> GeDefenseUi.orange
            scan.state == "COMPLETE" || app.state == "COMPLETE" -> GeDefenseUi.green
            else -> GeDefenseUi.gold
        }
        analysisBadge.text = activity.getString(when {
            running -> R.string.analysis_scan_running
            restoring -> R.string.analysis_scan_restoring
            scan.state == "FAILED" -> R.string.scanner_failed
            scan.state == "COMPLETE" || app.state == "COMPLETE" -> R.string.analysis_scan_complete
            else -> R.string.analysis_scan_idle
        })
        analysisBadge.setTextColor(color)
        analysisBadge.background = GeDefenseUi.badgeBackground(activity, color)
        analysisProgress.setProgress(if (running) scan.progress.fraction.coerceIn(0f, 1f) else if (restoring) 0.18f else if (scan.state == "COMPLETE" || app.state == "COMPLETE") 1f else 0f, color)

        if (running) {
            val percent = (scan.progress.fraction.coerceIn(0f, 1f) * 100f).toInt()
            analysisTitle.text = activity.getString(R.string.dashboard_analysis_running, percent, dashboardScanPhase(scan.progress.phase))
            analysisDetail.text = activity.getString(R.string.dashboard_analysis_running_detail, scan.progress.processed, scan.progress.total, scan.progress.findings)
        } else if (restoring) {
            analysisTitle.text = activity.getString(R.string.dashboard_analysis_restoring)
            analysisDetail.text = activity.getString(R.string.dashboard_analysis_restoring_detail)
        } else if (scan.state == "COMPLETE" || app.state == "COMPLETE") {
            analysisTitle.text = if (findingCount == 0) activity.getString(R.string.dashboard_analysis_clean) else activity.getString(R.string.dashboard_analysis_findings, findingCount, matches)
            val atMillis = if (scan.completedAtMillis > 0L) scan.completedAtMillis else app.scannedAtMillis
            analysisDetail.text = activity.getString(R.string.dashboard_analysis_last_scan, GeDefenseUi.formatTime(activity, atMillis))
        } else {
            analysisTitle.text = activity.getString(R.string.dashboard_analysis_never)
            analysisDetail.text = activity.getString(R.string.dashboard_analysis_never_detail)
        }
        analysisTitle.setTextColor(color)

        val key = allFindings.joinToString("|") { "${it.title}:${it.score}" } + ":$running:$restoring:$findingCount:$matches"
        if (key == lastDashboardAnalysisKey) return
        lastDashboardAnalysisKey = key
        analysisFindingsHost.removeAllViews()
        allFindings.forEachIndexed { index, finding ->
            analysisFindingsHost.addView(dashboardFindingRow(finding), LinearLayout.LayoutParams(-1, -2).apply { if (index > 0) topMargin = dp(6) })
        }
    }

    private fun dashboardFindingRow(finding: DashboardFinding): View = FrameLayout(activity).apply {
        background = GeDefenseUi.softPanelBackground(activity, 13, finding.accent)
        addView(LinearLayout(activity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(12), dp(9), dp(12), dp(9))
            addView(GeDefenseUi.textView(activity, finding.title, 9.7f, GeDefenseUi.text, bold = true).apply { maxLines = 1 }, LinearLayout.LayoutParams(0, -2, 1f))
            addView(GeDefenseUi.pill(activity, "${finding.score}/100", finding.accent))
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun dashboardScanPhase(phase: DeviceScanPhase): String = activity.getString(when (phase) {
        DeviceScanPhase.INTEGRITY -> R.string.scanner_phase_integrity
        DeviceScanPhase.APPS -> R.string.scanner_phase_apps
        DeviceScanPhase.STORAGE -> R.string.scanner_phase_storage
        DeviceScanPhase.FINALIZING -> R.string.scanner_phase_finalizing
        DeviceScanPhase.COMPLETE -> R.string.scanner_phase_complete
        DeviceScanPhase.FAILED -> R.string.scanner_failed
        DeviceScanPhase.CANCELLED -> R.string.scanner_cancelled
        DeviceScanPhase.IDLE -> R.string.scanner_ready
    })

    private fun dashboardAppRiskColor(level: AppRiskLevel): Int = when (level) {
        AppRiskLevel.SEVERE -> GeDefenseUi.red
        AppRiskLevel.HIGH -> GeDefenseUi.orange
        AppRiskLevel.REVIEW -> GeDefenseUi.gold
        AppRiskLevel.LOW -> GeDefenseUi.green
    }

    private fun dashboardFileRiskColor(level: FileRiskLevel): Int = when (level) {
        FileRiskLevel.SEVERE -> GeDefenseUi.red
        FileRiskLevel.HIGH -> GeDefenseUi.orange
        FileRiskLevel.REVIEW -> GeDefenseUi.gold
        FileRiskLevel.LOW -> GeDefenseUi.green
    }

    private data class DashboardFinding(val title: String, val score: Int, val accent: Int)

    private fun statusDetail(snapshot: UiSnapshot): String {
        val base = when (snapshot.vpnStatus) {
            "GUARDED" -> activity.getString(R.string.status_guarded)
            "FULL_GUARDED" -> activity.getString(R.string.status_full_guarded)
            "NETSTACK_UNAVAILABLE" -> activity.getString(R.string.full_flow_native_missing)
            "FULL_FLOW_FAILED" -> activity.getString(R.string.status_full_flow_failed)
            "DEGRADED_EVIDENCE" -> activity.getString(R.string.status_degraded)
            "ROUTE_OVERFLOW" -> activity.getString(R.string.status_route_overflow)
            "NO_THREAT_ROUTES" -> activity.getString(R.string.status_no_feeds)
            "STARTING" -> activity.getString(R.string.status_starting)
            "ESTABLISH_FAILED" -> activity.getString(R.string.status_establish_failed)
            "TUN_FAILED" -> activity.getString(R.string.status_tun_failed)
            "POLICY_INVARIANT_FAILED" -> activity.getString(R.string.status_policy_invariant)
            else -> activity.getString(R.string.status_off)
        }
        return if (snapshot.vpnReason.isNullOrBlank()) base else "$base\n${activity.getString(R.string.status_reason, snapshot.vpnReason)}"
    }

    private fun gap(parent: LinearLayout, value: Int) = GeDefenseUi.addVerticalGap(parent, activity, value)
    private fun dp(value: Int) = GeDefenseUi.dp(activity, value)
}
