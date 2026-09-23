package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

class MoreScreen(
    private val activity: Activity,
    private val actions: UiActions,
) {
    val view: View
    private val rootLayout: LinearLayout
    private val protectionButton: TextView
    private val syncButton: TextView
    private val statusText: TextView
    private val modeStatus: TextView
    private val selectiveButton: TextView
    private val fullFlowButton: TextView
    private val lockdownButton: TextView
    private val titanStatus: TextView
    private val gaiaNetV2Status: TextView

    init {
        val scroll = ScrollView(activity).apply { clipToPadding = false; overScrollMode = View.OVER_SCROLL_NEVER }
        rootLayout = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                GeDefenseUi.screenHorizontalPadding(activity),
                dp(16),
                GeDefenseUi.screenHorizontalPadding(activity),
                GeDefenseUi.scrollReservedBottomPadding(activity),
            )
        }
        val root = rootLayout
        scroll.addView(root, FrameLayout.LayoutParams(-1, -2))
        root.addView(VgtUiComponents.screenHeader(activity, activity.getString(R.string.ui_control_center), activity.getString(R.string.ui_private_control)))
        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)

        statusText = GeDefenseUi.textView(activity, "", 11.5f, GeDefenseUi.textMuted)
        root.addView(card(VgtIcon.SHIELD, GeDefenseUi.cyan, activity.getString(R.string.protection_status), subtitle = statusText))

        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)
        modeStatus = GeDefenseUi.textView(activity, "", 11.5f, GeDefenseUi.textMuted)
        selectiveButton = GeDefenseUi.actionButton(activity, activity.getString(R.string.mode_selective)) { actions.setProtectionMode(ProtectionMode.SELECTIVE) }
        fullFlowButton = GeDefenseUi.actionButton(activity, activity.getString(R.string.mode_full_flow_beta)) { actions.setProtectionMode(ProtectionMode.FULL_FLOW_BETA) }
        lockdownButton = GeDefenseUi.actionButton(activity, activity.getString(R.string.mode_lockdown)) { actions.setProtectionMode(ProtectionMode.LOCKDOWN) }
        gaiaNetV2Status = GeDefenseUi.textView(activity, "", 10.3f, GeDefenseUi.cyan, bold = true)
        root.addView(card(
            icon = VgtIcon.POLICY,
            accent = GeDefenseUi.gold,
            title = activity.getString(R.string.mode_title),
            subtitle = modeStatus,
            selectiveButton,
            fullFlowButton,
            lockdownButton,
            GeDefenseUi.sectionTitle(activity, activity.getString(R.string.gaianet_v2_title)),
            gaiaNetV2Status,
            GeDefenseUi.textView(activity, activity.getString(R.string.mode_full_flow_detail), 10f, GeDefenseUi.textDim),
            GeDefenseUi.actionButton(activity, activity.getString(R.string.firewall_open)) { actions.openNetworkFirewall() },
        ))

        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)
        root.addView(card(
            icon = VgtIcon.CORRELATE,
            accent = GeDefenseUi.orange,
            title = activity.getString(R.string.xdr_title),
            subtitle = GeDefenseUi.textView(activity, activity.getString(R.string.xdr_more_body), 10.5f, GeDefenseUi.textMuted),
            GeDefenseUi.actionButton(activity, activity.getString(R.string.xdr_open), goldStyle = true) { actions.openXdrCenter() },
        ))

        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)
        root.addView(card(
            icon = VgtIcon.ROUTES,
            accent = GeDefenseUi.cyan,
            title = activity.getString(R.string.network_discovery_title),
            subtitle = GeDefenseUi.textView(activity, activity.getString(R.string.network_discovery_more_body), 10.5f, GeDefenseUi.textMuted),
            GeDefenseUi.actionButton(activity, activity.getString(R.string.network_discovery_open), goldStyle = true) { actions.openNetworkDiscovery() },
        ))

        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)
        root.addView(card(
            icon = VgtIcon.ALERT,
            accent = GeDefenseUi.orange,
            title = activity.getString(R.string.port_sentinel_title),
            subtitle = GeDefenseUi.textView(activity, activity.getString(R.string.port_sentinel_subtitle), 10.5f, GeDefenseUi.textMuted),
            GeDefenseUi.actionButton(activity, activity.getString(R.string.port_sentinel_open), goldStyle = true) { actions.openPortSentinel() },
        ))

        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)
        root.addView(card(
            icon = VgtIcon.INTEGRITY,
            accent = GeDefenseUi.green,
            title = activity.getString(R.string.hardening_title),
            subtitle = GeDefenseUi.textView(activity, activity.getString(R.string.hardening_more_body), 10.5f, GeDefenseUi.textMuted),
            GeDefenseUi.actionButton(activity, activity.getString(R.string.hardening_open), goldStyle = true) { actions.openHardeningCenter() },
        ))

        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)
        titanStatus = GeDefenseUi.textView(activity, activity.getString(R.string.titan_state_standard_body), 10.5f, GeDefenseUi.textMuted)
        root.addView(card(
            icon = VgtIcon.SHIELD,
            accent = GeDefenseUi.gold,
            title = activity.getString(R.string.titan_title),
            subtitle = titanStatus,
            GeDefenseUi.actionButton(activity, activity.getString(R.string.titan_open), goldStyle = true) { actions.openTitan() },
        ))

        gap(root, GeDefenseUi.SPACING_SECTION_GAP_DP)
        root.addView(GeDefenseUi.sectionTitle(activity, activity.getString(R.string.ui_controls)))
        gap(root, 12)
        protectionButton = GeDefenseUi.actionButton(activity, activity.getString(R.string.activate), goldStyle = true) { actions.activateProtection() }
        syncButton = GeDefenseUi.actionButton(activity, activity.getString(R.string.sync_feeds)) { actions.synchronizeFeeds() }
        val verifyButton = GeDefenseUi.actionButton(activity, activity.getString(R.string.verify_evidence)) { actions.verifyEvidence() }
        root.addView(protectionButton); root.addView(syncButton, spaced()); root.addView(verifyButton, spaced())

        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)
        root.addView(card(
            icon = VgtIcon.SETTINGS,
            accent = GeDefenseUi.cyan,
            title = activity.getString(R.string.setup_title),
            subtitle = GeDefenseUi.textView(activity, activity.getString(R.string.setup_more_body), 10.5f, GeDefenseUi.textMuted),
            GeDefenseUi.actionButton(activity, activity.getString(R.string.setup_open)) { actions.openSetupWizard() },
        ))


        gap(root, GeDefenseUi.SPACING_SECTION_GAP_DP)
        root.addView(card(
            icon = VgtIcon.INTELLIGENCE,
            accent = GeDefenseUi.blue,
            title = activity.getString(R.string.ui_architecture),
            subtitle = GeDefenseUi.textView(activity, activity.getString(R.string.ui_architecture_detail_beta), 11f, GeDefenseUi.textMuted),
        ))
        root.addView(card(
            icon = VgtIcon.SHIELD,
            accent = GeDefenseUi.gold,
            title = activity.getString(R.string.ui_alpha_scope_title),
            subtitle = GeDefenseUi.textView(activity, activity.getString(R.string.beta_scope), 10.5f, GeDefenseUi.textMuted),
        ), spaced())
        root.addView(card(
            icon = VgtIcon.COUNTRY,
            accent = GeDefenseUi.green,
            title = activity.getString(R.string.feed_sources),
            subtitle = GeDefenseUi.textView(activity, activity.getString(R.string.data_attribution_beta), 10.5f, GeDefenseUi.textDim),
        ), spaced())

        gap(root, GeDefenseUi.SPACING_SECTION_GAP_DP)
        val versionName = BuildConfig.VERSION_NAME
        root.addView(GeDefenseUi.textView(activity, "GeDefense Mobile · $versionName", 10.5f, GeDefenseUi.gold, bold = true).apply {
            gravity = Gravity.CENTER; setPadding(0, dp(8), 0, dp(8))
        })
        view = scroll
    }

    fun setBottomPadding(bottomPx: Int) {
        rootLayout.setPadding(rootLayout.paddingLeft, rootLayout.paddingTop, rootLayout.paddingRight, bottomPx)
    }

    fun setSyncing(syncing: Boolean) {
        syncButton.isEnabled = !syncing; syncButton.alpha = if (syncing) 0.55f else 1f
        syncButton.text = activity.getString(if (syncing) R.string.syncing else R.string.sync_feeds)
    }

    fun update(snapshot: UiSnapshot) {
        val guarded = snapshot.vpnActive && snapshot.vpnStatus in setOf("GUARDED", "FULL_GUARDED", "LOCKDOWN_GUARDED")
        titanStatus.text = when {
            !snapshot.titan.policyStoreIntegrityOk -> activity.getString(R.string.titan_state_degraded)
            snapshot.titan.titanActive -> activity.getString(R.string.titan_state_active_body)
            snapshot.titan.adminActive -> activity.getString(R.string.titan_state_admin_only_body)
            else -> activity.getString(R.string.titan_state_standard_body)
        }
        gaiaNetV2Status.text = activity.getString(if (snapshot.nativeFullFlowAvailable) R.string.gaianet_v2_ready else R.string.gaianet_v2_missing)
        gaiaNetV2Status.setTextColor(if (snapshot.nativeFullFlowAvailable) GeDefenseUi.green else GeDefenseUi.red)
        protectionButton.text = activity.getString(if (guarded) R.string.deactivate else R.string.activate)
        protectionButton.background = if (guarded) GeDefenseUi.destructiveButtonBackground(activity) else GeDefenseUi.goldButtonBackground(activity)
        protectionButton.setTextColor(if (guarded) GeDefenseUi.text else android.graphics.Color.rgb(18, 19, 20))
        protectionButton.setOnClickListener { if (guarded) actions.deactivateProtection() else actions.activateProtection() }
        val policyReady = when (snapshot.protectionMode) {
            ProtectionMode.SELECTIVE -> snapshot.compactedRoutes > 0 && !snapshot.routeOverflow
            ProtectionMode.FULL_FLOW_BETA -> snapshot.indexedPrefixes > 0 && snapshot.nativeFullFlowAvailable
            ProtectionMode.LOCKDOWN -> true
        }
        val canActivate = !snapshot.vpnActive && policyReady && snapshot.evidenceOk && snapshot.integrity.ok
        protectionButton.isEnabled = guarded || canActivate; protectionButton.alpha = if (protectionButton.isEnabled) 1f else 0.45f

        statusText.text = buildString {
            append(snapshot.vpnStatus)
            if (!snapshot.vpnReason.isNullOrBlank()) append(" · ").append(snapshot.vpnReason)
            append("\n").append(activity.getString(R.string.ui_routes_and_feeds, snapshot.compactedRoutes, snapshot.healthyFeeds, snapshot.feeds.size))
            if (snapshot.protectionMode == ProtectionMode.FULL_FLOW_BETA) append("\n").append(activity.getString(R.string.full_flow_active_flows, snapshot.fullFlow.activeFlows))
        }
        updateMode(snapshot)
    }

    private fun updateMode(snapshot: UiSnapshot) {
        modeStatus.text = when (snapshot.protectionMode) {
            ProtectionMode.SELECTIVE -> activity.getString(R.string.mode_selected_selective)
            ProtectionMode.FULL_FLOW_BETA -> activity.getString(R.string.mode_selected_full_flow)
            ProtectionMode.LOCKDOWN -> activity.getString(R.string.mode_selected_lockdown)
        }
        modeStatus.setTextColor(when (snapshot.protectionMode) {
            ProtectionMode.FULL_FLOW_BETA -> GeDefenseUi.cyan
            ProtectionMode.LOCKDOWN -> GeDefenseUi.red
            ProtectionMode.SELECTIVE -> GeDefenseUi.gold
        })
        styleModeButton(selectiveButton, snapshot.protectionMode == ProtectionMode.SELECTIVE, !snapshot.vpnActive)
        styleModeButton(fullFlowButton, snapshot.protectionMode == ProtectionMode.FULL_FLOW_BETA, !snapshot.vpnActive && snapshot.nativeFullFlowAvailable)
        styleModeButton(lockdownButton, snapshot.protectionMode == ProtectionMode.LOCKDOWN, !snapshot.vpnActive)
        fullFlowButton.text = activity.getString(if (!snapshot.nativeFullFlowAvailable) R.string.mode_full_flow_missing_native else R.string.mode_full_flow_beta)
    }

    private fun styleModeButton(button: TextView, selected: Boolean, enabled: Boolean) {
        button.isEnabled = enabled; button.alpha = if (enabled) 1f else 0.45f
        button.background = if (selected) GeDefenseUi.goldButtonBackground(activity) else GeDefenseUi.darkButtonBackground(activity)
        button.setTextColor(if (selected) android.graphics.Color.rgb(18, 19, 20) else GeDefenseUi.text)
    }


    private fun card(icon: VgtIcon, accent: Int, title: String, subtitle: TextView? = null, vararg content: View): View = FrameLayout(activity).apply {
        background = GeDefenseUi.glassPanelBackground(activity, accent = accent, radius = 18)
        val contentContainer = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(activity, icon, accent, 32), LinearLayout.LayoutParams(dp(32), dp(32)))
                val titleCol = LinearLayout(activity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(dp(12), 0, 0, 0)
                    addView(GeDefenseUi.sectionTitle(activity, title))
                    if (subtitle != null) {
                        addView(subtitle.apply { setPadding(0, dp(3), 0, 0) })
                    }
                }
                addView(titleCol, LinearLayout.LayoutParams(0, -2, 1f))
            })
            content.forEach { child -> gap(this, 12); addView(child) }
        }
        addView(contentContainer, FrameLayout.LayoutParams(-1, -2))
    }

    private fun spaced() = LinearLayout.LayoutParams(-1, -2).apply { topMargin = GeDefenseUi.cardGap(activity) }
    private fun gap(parent: LinearLayout, value: Int) = GeDefenseUi.addVerticalGap(parent, activity, value)
    private fun dp(value: Int) = GeDefenseUi.dp(activity, value)
}
