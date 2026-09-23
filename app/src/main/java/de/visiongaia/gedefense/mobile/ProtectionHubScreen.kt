package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.graphics.Color
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

// STATUS: DIAMANT VGT SUPREME
class ProtectionHubScreen(
    private val activity: Activity,
    private val actions: UiActions,
) {
    val view: View
    private val rootLayout: LinearLayout

    private val protectionBadge: TextView
    private val protectionTitle: TextView
    private val protectionDetail: TextView
    private val protectionAction: TextView

    private val resilienceBadge: TextView
    private val resilienceSummary: TextView
    private val alwaysOnState: TextView
    private val killSwitchState: TextView
    private val restartState: TextView
    private val batteryState: TextView
    private val powerGovernorState: TextView
    private val recoveryState: TextView
    private val resilienceAction: TextView
    private val resilienceTestAction: TextView

    private val modeStatus: TextView
    private val selectiveButton: TextView
    private val fullFlowButton: TextView
    private val lockdownButton: TextView

    private val intelligenceDetail: TextView
    private val integrityDetail: TextView
    private val syncButton: VgtActionTile
    private var syncing = false

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
            activity.getString(R.string.protection_hub_title),
            activity.getString(R.string.protection_hub_subtitle),
        ))
        gap(GeDefenseUi.SPACING_CARD_GAP_DP)

        protectionBadge = GeDefenseUi.pill(activity, activity.getString(R.string.ui_waiting), GeDefenseUi.orange)
        protectionTitle = GeDefenseUi.displayTextView(activity, "", 20f, GeDefenseUi.text)
        protectionDetail = GeDefenseUi.textView(activity, "", 10.6f, GeDefenseUi.textMuted)
        protectionAction = GeDefenseUi.actionButton(activity, activity.getString(R.string.activate), goldStyle = true) {
            actions.activateProtection()
        }
        rootLayout.addView(overviewCard())

        gap(GeDefenseUi.SPACING_CARD_GAP_DP)
        resilienceBadge = GeDefenseUi.pill(activity, activity.getString(R.string.always_on_state_setup), GeDefenseUi.gold)
        resilienceSummary = GeDefenseUi.textView(activity, "", 10.7f, GeDefenseUi.textMuted)
        alwaysOnState = stateValue()
        killSwitchState = stateValue()
        restartState = stateValue()
        batteryState = stateValue()
        powerGovernorState = stateValue()
        recoveryState = stateValue()
        resilienceAction = GeDefenseUi.actionButton(activity, activity.getString(R.string.always_on_configure), goldStyle = true) {
            actions.configureAlwaysOnProtection()
        }
        resilienceTestAction = GeDefenseUi.actionButton(activity, activity.getString(R.string.resilience_self_test_action)) {
            actions.runResilienceSelfTest()
        }
        rootLayout.addView(resilienceCard())

        gap(GeDefenseUi.SPACING_SECTION_GAP_DP)
        rootLayout.addView(GeDefenseUi.sectionTitle(activity, activity.getString(R.string.protection_mode_section)))
        gap(10)
        modeStatus = GeDefenseUi.textView(activity, "", 10.8f, GeDefenseUi.textMuted)
        selectiveButton = GeDefenseUi.actionButton(activity, activity.getString(R.string.mode_selective)) {
            actions.setProtectionMode(ProtectionMode.SELECTIVE)
        }
        fullFlowButton = GeDefenseUi.actionButton(activity, activity.getString(R.string.mode_full_flow_beta)) {
            actions.setProtectionMode(ProtectionMode.FULL_FLOW_BETA)
        }
        lockdownButton = GeDefenseUi.actionButton(activity, activity.getString(R.string.mode_lockdown)) {
            actions.setProtectionMode(ProtectionMode.LOCKDOWN)
        }
        rootLayout.addView(modeCard())

        gap(GeDefenseUi.SPACING_SECTION_GAP_DP)
        rootLayout.addView(GeDefenseUi.sectionTitle(activity, activity.getString(R.string.protection_modules_section)))
        gap(10)
        syncButton = VgtActionTile(activity, VgtIcon.SYNC, activity.getString(R.string.sync_feeds)) { actions.synchronizeFeeds() }
        val firewall = VgtActionTile(activity, VgtIcon.POLICY, activity.getString(R.string.firewall_open)) { actions.openNetworkFirewall() }
        val wireGuard = VgtActionTile(activity, VgtIcon.SHIELD, activity.getString(R.string.wireguard_open)) { actions.openWireGuard() }
        val sentinel = VgtActionTile(activity, VgtIcon.ALERT, activity.getString(R.string.port_sentinel_open)) { actions.openPortSentinel() }
        val integrity = VgtActionTile(activity, VgtIcon.INTEGRITY, activity.getString(R.string.integrity_run)) { actions.verifyIntegrity() }
        rootLayout.addView(actionGrid(firewall, wireGuard, sentinel, syncButton, integrity))

        gap(GeDefenseUi.SPACING_CARD_GAP_DP)
        intelligenceDetail = GeDefenseUi.textView(activity, "", 10.4f, GeDefenseUi.textMuted)
        integrityDetail = GeDefenseUi.textView(activity, "", 10.4f, GeDefenseUi.textMuted)
        rootLayout.addView(moduleStateCard())

        view = scroll
    }

    fun setBottomPadding(bottomPx: Int) {
        rootLayout.setPadding(rootLayout.paddingLeft, rootLayout.paddingTop, rootLayout.paddingRight, bottomPx)
    }

    fun setSyncing(value: Boolean) {
        syncing = value
        syncButton.isEnabled = !value
        syncButton.setLabel(activity.getString(if (value) R.string.syncing else R.string.sync_feeds))
    }

    fun update(snapshot: UiSnapshot) {
        val guarded = snapshot.vpnActive && snapshot.vpnStatus in setOf("GUARDED", "FULL_GUARDED", "LOCKDOWN_GUARDED")
        val ready = protectionReady(snapshot)
        val statusColor = when {
            guarded -> GeDefenseUi.green
            ready -> GeDefenseUi.gold
            else -> GeDefenseUi.red
        }
        protectionBadge.text = activity.getString(when {
            guarded -> R.string.protection_hub_guarded
            ready -> R.string.ui_ready
            else -> R.string.ui_attention
        })
        protectionBadge.setTextColor(statusColor)
        protectionBadge.background = GeDefenseUi.badgeBackground(activity, statusColor)
        protectionTitle.text = activity.getString(when {
            guarded -> R.string.ui_protection_active
            ready -> R.string.ui_protection_off
            else -> R.string.ui_protection_attention
        })
        protectionTitle.setTextColor(statusColor)
        protectionDetail.text = buildString {
            when {
                !snapshot.integrity.ok -> append("DEGRADED_INTEGRITY")
                !snapshot.evidenceOk -> append("DEGRADED_EVIDENCE")
                else -> append(snapshot.vpnStatus)
            }
            val visibleReason = when {
                !snapshot.integrity.ok -> snapshot.integrity.issues.firstOrNull()?.code
                !snapshot.evidenceOk -> snapshot.evidenceReason
                else -> snapshot.vpnReason
            }
            visibleReason?.takeIf { it.isNotBlank() }?.let { append(" · ").append(it) }
            append("\n").append(modeLabel(snapshot.protectionMode))
            if (snapshot.protectionMode == ProtectionMode.FULL_FLOW_BETA) {
                append(" · ").append(activity.getString(when (snapshot.wireGuardEgressMode) {
                    WireGuardEgressMode.DIRECT -> R.string.wireguard_mode_direct
                    WireGuardEgressMode.WIREGUARD -> R.string.wireguard_mode_tunnel
                    WireGuardEgressMode.WIREGUARD_STRICT -> R.string.wireguard_mode_strict
                }))
            }
            append(" · ").append(activity.getString(R.string.ui_routes_and_feeds, snapshot.compactedRoutes, snapshot.healthyFeeds, snapshot.feeds.size))
        }
        protectionAction.text = activity.getString(if (guarded) R.string.deactivate else R.string.activate)
        protectionAction.background = if (guarded) GeDefenseUi.destructiveButtonBackground(activity) else GeDefenseUi.goldButtonBackground(activity)
        protectionAction.setTextColor(if (guarded) GeDefenseUi.text else Color.rgb(18, 19, 20))
        protectionAction.setOnClickListener { if (guarded) actions.deactivateProtection() else actions.activateProtection() }
        protectionAction.isEnabled = guarded || ready
        protectionAction.alpha = if (protectionAction.isEnabled) 1f else 0.45f

        val alwaysOn = snapshot.alwaysOnConfigured
        val lockdown = snapshot.killSwitchConfigured
        val resilienceReady = alwaysOn && lockdown
        val resilienceColor = when {
            resilienceReady -> GeDefenseUi.green
            snapshot.resilienceDesired -> GeDefenseUi.gold
            else -> GeDefenseUi.orange
        }
        resilienceBadge.text = activity.getString(when {
            resilienceReady -> R.string.always_on_state_ready
            snapshot.resilienceDesired -> R.string.always_on_state_pending
            else -> R.string.always_on_state_setup
        })
        resilienceBadge.setTextColor(resilienceColor)
        resilienceBadge.background = GeDefenseUi.badgeBackground(activity, resilienceColor)
        resilienceSummary.text = activity.getString(
            when {
                snapshot.titan.titanActive -> R.string.always_on_summary_titan
                resilienceReady -> R.string.always_on_summary_ready
                else -> R.string.always_on_summary_standard
            },
        )
        applyState(alwaysOnState, alwaysOn)
        applyState(killSwitchState, lockdown)
        applyState(restartState, snapshot.resilienceDesired || alwaysOn)
        applyBatteryState(batteryState, snapshot.setup)
        powerGovernorState.text = activity.getString(if (snapshot.transportPowerConstrained) R.string.power_governor_efficiency else R.string.power_governor_interactive)
        powerGovernorState.setTextColor(if (snapshot.transportPowerConstrained) GeDefenseUi.green else GeDefenseUi.cyan)
        val selfTestRunning = snapshot.resilienceSelfTestStatus == "RUNNING"
        recoveryState.text = if (selfTestRunning) "TEST" else snapshot.vpnRecoveryCount.toString()
        recoveryState.setTextColor(when {
            selfTestRunning -> GeDefenseUi.gold
            snapshot.vpnRecoveryCount > 0L -> GeDefenseUi.green
            else -> GeDefenseUi.textDim
        })
        resilienceAction.text = activity.getString(
            if (snapshot.titan.titanActive && resilienceReady) R.string.always_on_manage else R.string.always_on_configure,
        )
        val canSelfTest = guarded && snapshot.killSwitchConfigured && snapshot.protectionMode == ProtectionMode.FULL_FLOW_BETA && snapshot.nativeFullFlowAvailable && snapshot.vpnStatus != "RECOVERING" && !selfTestRunning
        resilienceTestAction.isEnabled = canSelfTest
        resilienceTestAction.alpha = if (canSelfTest) 1f else 0.45f

        modeStatus.text = modeLabel(snapshot.protectionMode)
        modeStatus.setTextColor(when (snapshot.protectionMode) {
            ProtectionMode.SELECTIVE -> GeDefenseUi.gold
            ProtectionMode.FULL_FLOW_BETA -> GeDefenseUi.cyan
            ProtectionMode.LOCKDOWN -> GeDefenseUi.red
        })
        styleModeButton(selectiveButton, snapshot.protectionMode == ProtectionMode.SELECTIVE, !snapshot.vpnActive)
        styleModeButton(fullFlowButton, snapshot.protectionMode == ProtectionMode.FULL_FLOW_BETA, !snapshot.vpnActive && snapshot.nativeFullFlowAvailable)
        styleModeButton(lockdownButton, snapshot.protectionMode == ProtectionMode.LOCKDOWN, !snapshot.vpnActive)

        intelligenceDetail.text = activity.getString(
            R.string.protection_intel_summary,
            snapshot.healthyFeeds,
            snapshot.feeds.size,
            snapshot.indexedPrefixes,
            GeDefenseUi.formatTime(activity, snapshot.lastFeedSync),
        )
        intelligenceDetail.setTextColor(if (snapshot.healthyFeeds > 0 && snapshot.indexedPrefixes > 0) GeDefenseUi.green else GeDefenseUi.orange)
        integrityDetail.text = activity.getString(
            if (snapshot.integrity.ok && snapshot.evidenceOk) R.string.protection_integrity_verified else R.string.protection_integrity_attention,
        )
        integrityDetail.setTextColor(if (snapshot.integrity.ok && snapshot.evidenceOk) GeDefenseUi.green else GeDefenseUi.red)
        if (syncing) setSyncing(true)
    }

    private fun overviewCard(): View = FrameLayout(activity).apply {
        background = GeDefenseUi.glassPanelBackground(activity, strong = true, accent = GeDefenseUi.cyan, radius = 20)
        addView(LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(20))
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(activity, VgtIcon.SHIELD, GeDefenseUi.cyan, 40), LinearLayout.LayoutParams(dp(40), dp(40)))
                addView(LinearLayout(activity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(dp(14), 0, 0, 0)
                    addView(protectionTitle)
                    addView(protectionDetail.apply { setPadding(0, dp(6), 0, 0) })
                }, LinearLayout.LayoutParams(0, -2, 1f))
                addView(protectionBadge)
            })
            addView(protectionAction, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(16) })
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun resilienceCard(): View = FrameLayout(activity).apply {
        background = GeDefenseUi.glassPanelBackground(activity, accent = GeDefenseUi.gold, radius = 20)
        addView(LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(20))
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(activity, VgtIcon.HEALTH, GeDefenseUi.gold, 38), LinearLayout.LayoutParams(dp(38), dp(38)))
                addView(LinearLayout(activity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(dp(13), 0, 0, 0)
                    addView(GeDefenseUi.textView(activity, activity.getString(R.string.always_on_title), 14f, GeDefenseUi.text, bold = true))
                    addView(resilienceSummary.apply { setPadding(0, dp(4), 0, 0) })
                }, LinearLayout.LayoutParams(0, -2, 1f))
                addView(resilienceBadge)
            })
            addView(stateRow(activity.getString(R.string.always_on_platform), alwaysOnState), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(15) })
            addView(stateRow(activity.getString(R.string.always_on_kill_switch), killSwitchState), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(7) })
            addView(stateRow(activity.getString(R.string.always_on_restart), restartState), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(7) })
            addView(stateRow(activity.getString(R.string.always_on_battery), batteryState), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(7) })
            addView(stateRow(activity.getString(R.string.power_governor_label), powerGovernorState), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(7) })
            addView(stateRow(activity.getString(R.string.always_on_recovery), recoveryState), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(7) })
            addView(resilienceAction, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(16) })
            addView(resilienceTestAction, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(9) })
            addView(GeDefenseUi.textView(activity, activity.getString(R.string.resilience_self_test_hint), 9.3f, GeDefenseUi.textDim).apply {
                setPadding(0, dp(7), 0, 0)
            })
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun modeCard(): View = FrameLayout(activity).apply {
        background = GeDefenseUi.glassPanelBackground(activity, accent = GeDefenseUi.cyan, radius = 18)
        addView(LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(modeStatus)
            addView(selectiveButton, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) })
            addView(fullFlowButton, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(9) })
            addView(lockdownButton, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(9) })
            addView(GeDefenseUi.textView(activity, activity.getString(R.string.protection_mode_hint), 9.5f, GeDefenseUi.textDim).apply {
                setPadding(0, dp(10), 0, 0)
            })
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun moduleStateCard(): View = FrameLayout(activity).apply {
        background = GeDefenseUi.softPanelBackground(activity, 16, GeDefenseUi.blue)
        addView(LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(15), dp(18), dp(15))
            addView(GeDefenseUi.sectionTitle(activity, activity.getString(R.string.protection_module_state)))
            addView(intelligenceDetail.apply { setPadding(0, dp(8), 0, 0) })
            addView(integrityDetail.apply { setPadding(0, dp(6), 0, 0) })
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

    private fun stateRow(label: String, value: TextView): View = LinearLayout(activity).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        addView(GeDefenseUi.textView(activity, label, 10.4f, GeDefenseUi.textMuted), LinearLayout.LayoutParams(0, -2, 1f))
        addView(value)
    }

    private fun stateValue(): TextView = GeDefenseUi.textView(activity, activity.getString(R.string.ui_waiting), 10.2f, GeDefenseUi.textDim, bold = true)

    private fun applyState(view: TextView, active: Boolean) {
        view.text = activity.getString(if (active) R.string.always_on_enabled else R.string.always_on_disabled)
        view.setTextColor(if (active) GeDefenseUi.green else GeDefenseUi.orange)
    }

    private fun applyBatteryState(view: TextView, setup: DeviceSetupSnapshot) {
        val label = when {
            setup.batteryExempt -> R.string.battery_state_doze_exempt
            !setup.batteryBackgroundRestricted -> R.string.battery_state_background_allowed
            else -> R.string.battery_state_restricted
        }
        view.text = activity.getString(label)
        view.setTextColor(if (setup.batteryReady) GeDefenseUi.green else GeDefenseUi.orange)
    }

    private fun styleModeButton(button: TextView, selected: Boolean, enabled: Boolean) {
        button.isEnabled = enabled
        button.alpha = if (enabled) 1f else 0.45f
        button.background = if (selected) GeDefenseUi.goldButtonBackground(activity) else GeDefenseUi.darkButtonBackground(activity)
        button.setTextColor(if (selected) Color.rgb(18, 19, 20) else GeDefenseUi.text)
    }

    private fun protectionReady(snapshot: UiSnapshot): Boolean {
        val wireGuardReady = when (snapshot.wireGuardEgressMode) {
            WireGuardEgressMode.DIRECT -> true
            WireGuardEgressMode.WIREGUARD -> snapshot.wireGuard.initialized && snapshot.wireGuard.integrityOk && snapshot.wireGuard.configured
            WireGuardEgressMode.WIREGUARD_STRICT -> snapshot.wireGuard.initialized && snapshot.wireGuard.integrityOk && snapshot.wireGuard.configured && snapshot.killSwitchConfigured
        }
        val policyReady = when (snapshot.protectionMode) {
            ProtectionMode.SELECTIVE -> snapshot.compactedRoutes > 0 && !snapshot.routeOverflow
            ProtectionMode.FULL_FLOW_BETA -> snapshot.indexedPrefixes > 0 && snapshot.nativeFullFlowAvailable && wireGuardReady
            ProtectionMode.LOCKDOWN -> true
        }
        return policyReady && snapshot.evidenceOk && snapshot.integrity.ok
    }

    private fun modeLabel(mode: ProtectionMode): String = activity.getString(when (mode) {
        ProtectionMode.SELECTIVE -> R.string.mode_selected_selective
        ProtectionMode.FULL_FLOW_BETA -> R.string.mode_selected_full_flow
        ProtectionMode.LOCKDOWN -> R.string.mode_selected_lockdown
    })

    private fun gap(value: Int) = GeDefenseUi.addVerticalGap(rootLayout, activity, value)
    private fun dp(value: Int) = GeDefenseUi.dp(activity, value)
}
