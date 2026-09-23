package de.visiongaia.gedefense.mobile

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.os.Build
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout

// STATUS: DIAMANT VGT SUPREME
class SetupWizardPageRenderer(
    private val activity: Activity,
    private val setup: DeviceSetupManager,
    private val runtime: AppRuntime,
) {

    fun render(step: SetupWizardStep, parent: LinearLayout) {
        when (step) {
            SetupWizardStep.WELCOME -> renderWelcome(parent)
            SetupWizardStep.PROTECTION_MODEL -> renderProtectionModel(parent)
            SetupWizardStep.LOCAL_VPN -> renderLocalVpn(parent)
            SetupWizardStep.XDR_INTELLIGENCE -> renderXdr(parent)
            SetupWizardStep.RELIABILITY -> renderReliability(parent)
            SetupWizardStep.STORAGE_SCANNER -> renderStorage(parent)
            SetupWizardStep.VISIBILITY -> renderVisibility(parent)
            SetupWizardStep.TITAN -> renderTitan(parent)
            SetupWizardStep.PRIVACY -> renderPrivacy(parent)
            SetupWizardStep.INITIAL_SYNC -> Unit
            SetupWizardStep.SUMMARY -> renderSummary(parent)
        }
    }

    private fun renderWelcome(parent: LinearLayout) {
        parent.addView(infoCard(
            VgtIcon.SHIELD,
            GeDefenseUi.cyan,
            activity.getString(R.string.setup_welcome_title),
            activity.getString(R.string.setup_welcome_body),
        ))
        gap(parent)
        parent.addView(bulletCard(
            VgtIcon.CORRELATE,
            GeDefenseUi.gold,
            activity.getString(R.string.setup_layers_title),
            listOf(
                activity.getString(R.string.setup_layer_network),
                activity.getString(R.string.setup_layer_xdr),
                activity.getString(R.string.setup_layer_scanner),
                activity.getString(R.string.setup_layer_integrity),
                activity.getString(R.string.setup_layer_titan),
            ),
        ))
        gap(parent)
        parent.addView(infoCard(
            VgtIcon.INTEGRITY,
            GeDefenseUi.green,
            activity.getString(R.string.setup_control_title),
            activity.getString(R.string.setup_control_body),
        ))
    }

    private fun renderProtectionModel(parent: LinearLayout) {
        parent.addView(infoCard(
            VgtIcon.SHIELD,
            GeDefenseUi.cyan,
            activity.getString(R.string.setup_model_defense_title),
            activity.getString(R.string.setup_model_defense_body),
        ))
        gap(parent)
        parent.addView(infoCard(
            VgtIcon.CORRELATE,
            GeDefenseUi.gold,
            activity.getString(R.string.setup_model_correlation_title),
            activity.getString(R.string.setup_model_correlation_body),
        ))
        gap(parent)
        parent.addView(infoCard(
            VgtIcon.ALERT,
            GeDefenseUi.orange,
            activity.getString(R.string.setup_model_limits_title),
            activity.getString(R.string.setup_model_limits_body),
        ))
    }

    private fun renderLocalVpn(parent: LinearLayout) {
        val accepted = runtime.vpnDisclosure.isAccepted()
        parent.addView(requirementCard(
            VgtIcon.TRAFFIC,
            GeDefenseUi.cyan,
            SetupRequirementLevel.CORE,
            activity.getString(R.string.setup_vpn_local_title),
            activity.getString(R.string.setup_vpn_local_body),
            accepted,
            activity.getString(R.string.setup_vpn_review_action),
        ) {
            activity.startActivity(Intent(activity, VpnDisclosureActivity::class.java))
        })
        gap(parent)
        parent.addView(bulletCard(
            VgtIcon.ROUTES,
            GeDefenseUi.green,
            activity.getString(R.string.setup_vpn_not_title),
            listOf(
                activity.getString(R.string.setup_vpn_not_remote),
                activity.getString(R.string.setup_vpn_not_mitm),
                activity.getString(R.string.setup_vpn_not_history_upload),
            ),
        ))
        gap(parent)
        parent.addView(infoCard(
            VgtIcon.POLICY,
            GeDefenseUi.gold,
            activity.getString(R.string.setup_vpn_android_title),
            activity.getString(R.string.setup_vpn_android_body),
        ))
    }

    private fun renderXdr(parent: LinearLayout) {
        parent.addView(infoCard(
            VgtIcon.INTELLIGENCE,
            GeDefenseUi.gold,
            activity.getString(R.string.setup_xdr_title),
            activity.getString(R.string.setup_xdr_body),
        ))
        gap(parent)
        parent.addView(infoCard(
            VgtIcon.CORRELATE,
            GeDefenseUi.cyan,
            activity.getString(R.string.setup_xdr_apps_title),
            activity.getString(R.string.setup_xdr_apps_body),
        ))
        gap(parent)
        parent.addView(infoCard(
            VgtIcon.EVIDENCE,
            GeDefenseUi.green,
            activity.getString(R.string.setup_xdr_evidence_title),
            activity.getString(R.string.setup_xdr_evidence_body),
        ))
    }

    private fun renderReliability(parent: LinearLayout) {
        val state = setup.snapshot()
        parent.addView(requirementCard(
            VgtIcon.HEALTH,
            GeDefenseUi.green,
            SetupRequirementLevel.RECOMMENDED,
            activity.getString(R.string.setup_battery_title),
            activity.getString(R.string.setup_battery_body),
            state.batteryReady,
            activity.getString(R.string.setup_battery_action),
        ) { setup.openBatteryOptimizationSettings(activity) })
        gap(parent)
        parent.addView(requirementCard(
            VgtIcon.SYNC,
            GeDefenseUi.gold,
            SetupRequirementLevel.RECOMMENDED,
            activity.getString(R.string.setup_autostart_title),
            activity.getString(R.string.setup_autostart_body),
            state.autostartVisited,
            activity.getString(R.string.setup_autostart_action),
        ) { setup.openAutostartSettings(activity) })
        if (Build.VERSION.SDK_INT >= 33) {
            gap(parent)
            parent.addView(requirementCard(
                VgtIcon.BELL,
                GeDefenseUi.cyan,
                SetupRequirementLevel.RECOMMENDED,
                activity.getString(R.string.setup_notifications_title),
                activity.getString(R.string.setup_notifications_body),
                state.notificationsAllowed,
                activity.getString(R.string.setup_notifications_action),
            ) {
                if (state.notificationsAllowed) setup.openNotificationSettings(activity)
                else activity.requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATIONS)
            })
        }
    }

    private fun renderStorage(parent: LinearLayout) {
        val state = setup.snapshot()
        parent.addView(requirementCard(
            VgtIcon.SCANNER,
            GeDefenseUi.gold,
            SetupRequirementLevel.OPTIONAL,
            activity.getString(R.string.setup_all_files_title),
            activity.getString(R.string.setup_all_files_body),
            state.allFilesAccess,
            activity.getString(R.string.setup_all_files_action),
        ) {
            if (Build.VERSION.SDK_INT >= 30) {
                setup.openAllFilesAccess(activity)
            } else {
                activity.requestPermissions(arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE), REQUEST_STORAGE)
            }
        })
        gap(parent)
        parent.addView(bulletCard(
            VgtIcon.EVIDENCE,
            GeDefenseUi.green,
            activity.getString(R.string.setup_storage_scope_title),
            listOf(
                activity.getString(R.string.setup_storage_scope_shared),
                activity.getString(R.string.setup_storage_scope_readonly),
                activity.getString(R.string.setup_storage_scope_private),
                activity.getString(R.string.setup_storage_scope_upload),
            ),
        ))
    }

    private fun renderVisibility(parent: LinearLayout) {
        val state = setup.snapshot()
        parent.addView(requirementCard(
            VgtIcon.ACTIVITY,
            GeDefenseUi.cyan,
            SetupRequirementLevel.OPTIONAL,
            activity.getString(R.string.setup_usage_title),
            activity.getString(R.string.setup_usage_body),
            state.usageAccess,
            activity.getString(R.string.setup_usage_action),
        ) { setup.openUsageAccess(activity) })
        gap(parent)
        parent.addView(requirementCard(
            VgtIcon.MAP,
            GeDefenseUi.blue,
            SetupRequirementLevel.OPTIONAL,
            activity.getString(R.string.setup_location_title),
            activity.getString(R.string.setup_location_body),
            state.coarseLocationAllowed,
            activity.getString(R.string.setup_location_action),
        ) {
            activity.requestPermissions(arrayOf(Manifest.permission.ACCESS_COARSE_LOCATION), REQUEST_COARSE_LOCATION)
        })
        gap(parent)
        parent.addView(infoCard(
            VgtIcon.COUNTRY,
            GeDefenseUi.green,
            activity.getString(R.string.setup_location_privacy_title),
            activity.getString(R.string.setup_location_privacy_body),
        ))
    }

    private fun renderTitan(parent: LinearLayout) {
        val state = setup.snapshot()
        val full = state.deviceOwnerActive
        val active = state.deviceAdminActive
        parent.addView(infoCard(
            VgtIcon.SHIELD,
            if (full) GeDefenseUi.gold else GeDefenseUi.cyan,
            activity.getString(
                if (full) R.string.setup_titan_full_title
                else if (active) R.string.setup_titan_light_active_title
                else R.string.setup_titan_light_title,
            ),
            activity.getString(
                if (full) R.string.setup_titan_full_body
                else if (active) R.string.setup_titan_light_active_body
                else R.string.setup_titan_light_body,
            ),
        ))
        gap(parent)
        parent.addView(requirementCard(
            VgtIcon.POLICY,
            GeDefenseUi.cyan,
            SetupRequirementLevel.ENTERPRISE,
            activity.getString(R.string.setup_titan_light_admin_title),
            activity.getString(R.string.setup_titan_light_admin_body),
            active,
            activity.getString(R.string.setup_titan_light_admin_action),
        ) { setup.requestTitanLightAdmin(activity) })
        gap(parent)
        parent.addView(infoCard(
            VgtIcon.INTELLIGENCE,
            GeDefenseUi.gold,
            activity.getString(R.string.setup_titan_upgrade_title),
            activity.getString(R.string.setup_titan_upgrade_body),
        ))
    }

    private fun renderPrivacy(parent: LinearLayout) {
        parent.addView(infoCard(
            VgtIcon.INTEGRITY,
            GeDefenseUi.green,
            activity.getString(R.string.setup_local_title),
            activity.getString(R.string.setup_local_body),
        ))
        gap(parent)
        parent.addView(infoCard(
            VgtIcon.SHIELD,
            GeDefenseUi.cyan,
            activity.getString(R.string.setup_privacy_telemetry_title),
            activity.getString(R.string.setup_privacy_telemetry_body),
        ))
        gap(parent)
        parent.addView(bulletCard(
            VgtIcon.POLICY,
            GeDefenseUi.gold,
            activity.getString(R.string.setup_privacy_telemetry_boundary_title),
            listOf(
                activity.getString(R.string.setup_privacy_telemetry_boundary_fullflow),
                activity.getString(R.string.setup_privacy_telemetry_boundary_no_mitm),
                activity.getString(R.string.setup_privacy_telemetry_boundary_control),
            ),
        ))
        gap(parent)
        parent.addView(bulletCard(
            VgtIcon.CLOUD,
            GeDefenseUi.gold,
            activity.getString(R.string.setup_privacy_network_title),
            listOf(
                activity.getString(R.string.setup_privacy_network_feeds),
                activity.getString(R.string.setup_privacy_network_noanalytics),
                activity.getString(R.string.setup_privacy_network_diagnostics),
            ),
        ))
        gap(parent)
        parent.addView(actionCard(
            VgtIcon.EVIDENCE,
            GeDefenseUi.cyan,
            activity.getString(R.string.setup_privacy_center_title),
            activity.getString(R.string.setup_privacy_center_body),
            activity.getString(R.string.setup_privacy_center_action),
        ) { activity.startActivity(Intent(activity, PrivacyActivity::class.java)) })
    }

    private fun renderSummary(parent: LinearLayout) {
        val state = setup.snapshot()
        val vpnAccepted = runtime.vpnDisclosure.isAccepted()
        parent.addView(infoCard(
            VgtIcon.INTEGRITY,
            if (vpnAccepted && state.notificationsAllowed) GeDefenseUi.green else GeDefenseUi.gold,
            activity.getString(R.string.setup_summary_title),
            activity.getString(R.string.setup_summary_body),
        ))
        gap(parent)

        val lines = listOf(
            SummaryLine(activity.getString(R.string.setup_summary_vpn), vpnAccepted, SetupRequirementLevel.CORE),
            SummaryLine(activity.getString(R.string.setup_summary_battery), state.batteryReady, SetupRequirementLevel.RECOMMENDED),
            SummaryLine(activity.getString(R.string.setup_summary_notifications), state.notificationsAllowed, SetupRequirementLevel.RECOMMENDED),
            SummaryLine(activity.getString(R.string.setup_summary_autostart), state.autostartVisited, SetupRequirementLevel.RECOMMENDED),
            SummaryLine(activity.getString(R.string.setup_summary_storage), state.allFilesAccess, SetupRequirementLevel.OPTIONAL),
            SummaryLine(activity.getString(R.string.setup_summary_usage), state.usageAccess, SetupRequirementLevel.OPTIONAL),
            SummaryLine(activity.getString(R.string.setup_summary_location), state.coarseLocationAllowed, SetupRequirementLevel.OPTIONAL),
            SummaryLine(activity.getString(R.string.setup_summary_titan_light), state.deviceAdminActive || state.deviceOwnerActive, SetupRequirementLevel.ENTERPRISE),
        )
        parent.addView(summaryCard(lines))
        gap(parent)
        parent.addView(infoCard(
            VgtIcon.ACTIVATE,
            GeDefenseUi.cyan,
            activity.getString(R.string.setup_after_finish_title),
            activity.getString(R.string.setup_after_finish_body),
        ))
    }

    private fun requirementCard(
        icon: VgtIcon,
        accent: Int,
        level: SetupRequirementLevel,
        title: String,
        body: String,
        granted: Boolean,
        actionLabel: String,
        action: () -> Unit,
    ): View = FrameLayout(activity).apply {
        background = GeDefenseUi.glassPanelBackground(activity, radius = 18)
        addView(LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(20), dp(20), dp(20))
            addView(header(icon, accent, title, granted, level))
            addView(bodyText(body))
            addView(GeDefenseUi.actionButton(
                activity,
                if (granted) activity.getString(R.string.setup_granted) else actionLabel,
                goldStyle = !granted,
            ) {
                if (!granted) action()
            }.apply {
                isEnabled = !granted
                alpha = if (granted) 0.7f else 1f
            }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(16) })
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun actionCard(
        icon: VgtIcon,
        accent: Int,
        title: String,
        body: String,
        actionLabel: String,
        action: () -> Unit,
    ): View = FrameLayout(activity).apply {
        background = GeDefenseUi.glassPanelBackground(activity, accent = accent, radius = 18)
        addView(LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(header(icon, accent, title, null, null))
            addView(bodyText(body))
            addView(GeDefenseUi.actionButton(activity, actionLabel, goldStyle = true) { action() }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(16) })
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun infoCard(icon: VgtIcon, accent: Int, title: String, body: String): View = FrameLayout(activity).apply {
        background = GeDefenseUi.glassPanelBackground(activity, accent = accent, radius = 18)
        addView(LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(header(icon, accent, title, null, null))
            addView(bodyText(body))
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun bulletCard(icon: VgtIcon, accent: Int, title: String, lines: List<String>): View = FrameLayout(activity).apply {
        background = GeDefenseUi.glassPanelBackground(activity, accent = accent, radius = 18)
        addView(LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(header(icon, accent, title, null, null))
            lines.forEachIndexed { index, line ->
                addView(LinearLayout(activity).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.TOP
                    if (index == 0) setPadding(0, dp(12), 0, 0) else setPadding(0, dp(9), 0, 0)
                    addView(GeDefenseUi.textView(activity, "•", 12f, accent, bold = true))
                    addView(GeDefenseUi.textView(activity, line, 10.5f, GeDefenseUi.textMuted).apply {
                        setLineSpacing(dp(2).toFloat(), 1f)
                    }, LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(10) })
                })
            }
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun summaryCard(lines: List<SummaryLine>): View = FrameLayout(activity).apply {
        background = GeDefenseUi.glassPanelBackground(activity, radius = 18)
        addView(LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            lines.forEachIndexed { index, line ->
                if (index > 0) GeDefenseUi.addVerticalGap(this, activity, 11)
                addView(statusRow(line))
            }
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun header(
        icon: VgtIcon,
        accent: Int,
        title: String,
        granted: Boolean?,
        level: SetupRequirementLevel?,
    ): View = LinearLayout(activity).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        addView(VgtUiComponents.iconWell(activity, icon, accent, 36), LinearLayout.LayoutParams(dp(36), dp(36)))
        addView(GeDefenseUi.textView(activity, title, 13f, GeDefenseUi.text, bold = true).apply {
            setPadding(dp(12), 0, dp(8), 0)
        }, LinearLayout.LayoutParams(0, -2, 1f))
        if (granted != null) {
            addView(GeDefenseUi.pill(
                activity,
                activity.getString(if (granted) R.string.setup_status_done else R.string.setup_status_open),
                if (granted) GeDefenseUi.green else GeDefenseUi.gold,
            ))
        } else if (level != null) {
            addView(levelPill(level))
        }
    }

    private fun bodyText(body: String): View = GeDefenseUi.textView(activity, body, 10.7f, GeDefenseUi.textMuted).apply {
        setPadding(0, dp(12), 0, 0)
        setLineSpacing(dp(2).toFloat(), 1f)
    }

    private fun statusRow(line: SummaryLine): View = LinearLayout(activity).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        addView(LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            addView(GeDefenseUi.textView(activity, line.label, 10.8f, GeDefenseUi.textMuted))
            addView(GeDefenseUi.textView(activity, levelLabel(line.level), 8.8f, levelColor(line.level), bold = true).apply {
                letterSpacing = 0.05f
                setPadding(0, dp(2), 0, 0)
            })
        }, LinearLayout.LayoutParams(0, -2, 1f))
        addView(GeDefenseUi.pill(
            activity,
            activity.getString(if (line.ready) R.string.setup_status_done else R.string.setup_status_open),
            if (line.ready) GeDefenseUi.green else GeDefenseUi.gold,
        ))
    }

    private fun levelPill(level: SetupRequirementLevel): View = GeDefenseUi.pill(activity, levelLabel(level), levelColor(level))

    private fun levelLabel(level: SetupRequirementLevel): String = activity.getString(when (level) {
        SetupRequirementLevel.CORE -> R.string.setup_level_core
        SetupRequirementLevel.RECOMMENDED -> R.string.setup_level_recommended
        SetupRequirementLevel.OPTIONAL -> R.string.setup_level_optional
        SetupRequirementLevel.ENTERPRISE -> R.string.setup_level_enterprise
    })

    private fun levelColor(level: SetupRequirementLevel): Int = when (level) {
        SetupRequirementLevel.CORE -> GeDefenseUi.cyan
        SetupRequirementLevel.RECOMMENDED -> GeDefenseUi.gold
        SetupRequirementLevel.OPTIONAL -> GeDefenseUi.textMuted
        SetupRequirementLevel.ENTERPRISE -> GeDefenseUi.blue
    }

    private fun gap(parent: LinearLayout) = GeDefenseUi.addVerticalGap(parent, activity, 14)
    private fun dp(value: Int): Int = GeDefenseUi.dp(activity, value)

    private data class SummaryLine(
        val label: String,
        val ready: Boolean,
        val level: SetupRequirementLevel,
    )

    companion object {
        private const val REQUEST_STORAGE = 701
        private const val REQUEST_NOTIFICATIONS = 702
        private const val REQUEST_COARSE_LOCATION = 703
    }
}
