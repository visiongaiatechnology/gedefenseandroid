package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.content.Intent
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

// STATUS: DIAMANT VGT SUPREME
class SystemHubScreen(
    private val activity: Activity,
    private val actions: UiActions,
) {
    val view: View
    private val rootLayout: LinearLayout

    private val hardeningBadge: TextView
    private val hardeningSummary: TextView
    private val titanBadge: TextView
    private val titanSummary: TextView
    private val setupBadge: TextView
    private val setupSummary: TextView
    private val platformBadge: TextView
    private val platformSummary: TextView

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
            activity.getString(R.string.system_hub_title),
            activity.getString(R.string.system_hub_subtitle),
        ))
        gap(GeDefenseUi.SPACING_CARD_GAP_DP)

        hardeningBadge = GeDefenseUi.pill(activity, activity.getString(R.string.ui_waiting), GeDefenseUi.gold)
        hardeningSummary = GeDefenseUi.textView(activity, "", 10.5f, GeDefenseUi.textMuted)
        rootLayout.addView(sectionCard(
            VgtIcon.INTEGRITY,
            GeDefenseUi.green,
            activity.getString(R.string.hardening_posture_title),
            hardeningBadge,
            hardeningSummary,
            GeDefenseUi.actionButton(activity, activity.getString(R.string.hardening_open), goldStyle = true) { actions.openHardeningCenter() },
        ))

        gap(GeDefenseUi.SPACING_CARD_GAP_DP)
        titanBadge = GeDefenseUi.pill(activity, activity.getString(R.string.ui_waiting), GeDefenseUi.gold)
        titanSummary = GeDefenseUi.textView(activity, "", 10.5f, GeDefenseUi.textMuted)
        rootLayout.addView(sectionCard(
            VgtIcon.SHIELD,
            GeDefenseUi.gold,
            activity.getString(R.string.titan_title),
            titanBadge,
            titanSummary,
            GeDefenseUi.actionButton(activity, activity.getString(R.string.titan_open)) { actions.openTitan() },
        ))

        gap(GeDefenseUi.SPACING_CARD_GAP_DP)
        setupBadge = GeDefenseUi.pill(activity, activity.getString(R.string.ui_waiting), GeDefenseUi.cyan)
        setupSummary = GeDefenseUi.textView(activity, "", 10.5f, GeDefenseUi.textMuted)
        rootLayout.addView(sectionCard(
            VgtIcon.SETTINGS,
            GeDefenseUi.cyan,
            activity.getString(R.string.system_setup_title),
            setupBadge,
            setupSummary,
            GeDefenseUi.actionButton(activity, activity.getString(R.string.setup_open)) { actions.openSetupWizard() },
        ))

        gap(GeDefenseUi.SPACING_CARD_GAP_DP)
        rootLayout.addView(FrameLayout(activity).apply {
            background = GeDefenseUi.glassPanelBackground(activity, accent = GeDefenseUi.green, radius = 18)
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(20), dp(18), dp(20), dp(18))
                addView(LinearLayout(activity).apply {
                    orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                    addView(VgtUiComponents.iconWell(activity, VgtIcon.EVIDENCE, GeDefenseUi.green, 36), LinearLayout.LayoutParams(dp(36), dp(36)))
                    addView(GeDefenseUi.textView(activity, activity.getString(R.string.diagnostics_title), 13.5f, GeDefenseUi.text, bold = true), LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(13) })
                })
                addView(GeDefenseUi.textView(activity, activity.getString(R.string.diagnostics_system_body), 10.5f, GeDefenseUi.textMuted).apply { setPadding(0, dp(10), 0, 0) })
                addView(GeDefenseUi.actionButton(activity, activity.getString(R.string.diagnostics_open), goldStyle = true) {
                    activity.startActivity(Intent(activity, DiagnosticsActivity::class.java))
                }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(14) })
            }, FrameLayout.LayoutParams(-1, -2))
        })

        gap(GeDefenseUi.SPACING_CARD_GAP_DP)
        rootLayout.addView(FrameLayout(activity).apply {
            background = GeDefenseUi.glassPanelBackground(activity, accent = GeDefenseUi.cyan, radius = 18)
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(20), dp(18), dp(20), dp(18))
                addView(LinearLayout(activity).apply {
                    orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                    addView(VgtUiComponents.iconWell(activity, VgtIcon.POLICY, GeDefenseUi.cyan, 36), LinearLayout.LayoutParams(dp(36), dp(36)))
                    addView(GeDefenseUi.textView(activity, activity.getString(R.string.privacy_title), 13.5f, GeDefenseUi.text, bold = true), LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(13) })
                })
                addView(GeDefenseUi.textView(activity, activity.getString(R.string.privacy_system_body), 10.5f, GeDefenseUi.textMuted).apply { setPadding(0, dp(10), 0, 0) })
                addView(GeDefenseUi.actionButton(activity, activity.getString(R.string.privacy_open), goldStyle = true) {
                    activity.startActivity(Intent(activity, PrivacyActivity::class.java))
                }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(14) })
            }, FrameLayout.LayoutParams(-1, -2))
        })

        gap(GeDefenseUi.SPACING_CARD_GAP_DP)
        rootLayout.addView(FrameLayout(activity).apply {
            background = GeDefenseUi.glassPanelBackground(activity, accent = GeDefenseUi.gold, radius = 18)
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(20), dp(18), dp(20), dp(18))
                addView(LinearLayout(activity).apply {
                    orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                    addView(VgtUiComponents.iconWell(activity, VgtIcon.CLOUD, GeDefenseUi.gold, 36), LinearLayout.LayoutParams(dp(36), dp(36)))
                    addView(GeDefenseUi.textView(activity, activity.getString(R.string.support_vgt_title), 13.5f, GeDefenseUi.text, bold = true), LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(13) })
                })
                addView(GeDefenseUi.textView(activity, activity.getString(R.string.support_vgt_system_body), 10.5f, GeDefenseUi.textMuted).apply { setPadding(0, dp(10), 0, 0) })
                addView(GeDefenseUi.actionButton(activity, activity.getString(R.string.support_vgt_open), goldStyle = true) {
                    activity.startActivity(Intent(activity, SupportVgtActivity::class.java))
                }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(14) })
            }, FrameLayout.LayoutParams(-1, -2))
        })

        gap(GeDefenseUi.SPACING_SECTION_GAP_DP)
        rootLayout.addView(GeDefenseUi.sectionTitle(activity, activity.getString(R.string.system_runtime_section)))
        gap(10)
        platformBadge = GeDefenseUi.pill(activity, activity.getString(R.string.ui_waiting), GeDefenseUi.cyan)
        platformSummary = GeDefenseUi.textView(activity, "", 10.3f, GeDefenseUi.textMuted)
        rootLayout.addView(sectionCard(
            VgtIcon.INTELLIGENCE,
            GeDefenseUi.blue,
            activity.getString(R.string.system_runtime_title),
            platformBadge,
            platformSummary,
        ))

        gap(GeDefenseUi.SPACING_CARD_GAP_DP)
        val versionName = BuildConfig.VERSION_NAME
        rootLayout.addView(FrameLayout(activity).apply {
            background = GeDefenseUi.softPanelBackground(activity, 15, GeDefenseUi.gold)
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER_HORIZONTAL
                setPadding(dp(18), dp(14), dp(18), dp(14))
                addView(GeDefenseUi.textView(activity, "GeDefense Mobile · $versionName", 10.5f, GeDefenseUi.gold, bold = true))
                addView(GeDefenseUi.textView(activity, activity.getString(R.string.system_local_first_footer), 9.2f, GeDefenseUi.textDim).apply {
                    gravity = Gravity.CENTER
                    setPadding(0, dp(5), 0, 0)
                })
            }, FrameLayout.LayoutParams(-1, -2))
        })

        view = scroll
    }

    fun setBottomPadding(bottomPx: Int) {
        rootLayout.setPadding(rootLayout.paddingLeft, rootLayout.paddingTop, rootLayout.paddingRight, bottomPx)
    }

    fun update(snapshot: UiSnapshot) {
        val hardening = snapshot.hardening
        val hardeningColor = when {
            hardening.checkedAtMillis <= 0L -> GeDefenseUi.gold
            hardening.critical > 0 || hardening.score < 55 -> GeDefenseUi.red
            hardening.failed > 0 || hardening.review > 0 -> GeDefenseUi.orange
            else -> GeDefenseUi.green
        }
        hardeningBadge.text = if (hardening.checkedAtMillis <= 0L) activity.getString(R.string.ui_waiting) else activity.getString(R.string.hardening_score, hardening.score)
        styleBadge(hardeningBadge, hardeningColor)
        hardeningSummary.text = if (hardening.checkedAtMillis <= 0L) {
            activity.getString(R.string.hardening_pending)
        } else {
            activity.getString(R.string.system_hardening_summary, hardening.passed, hardening.review, hardening.failed, GeDefenseUi.formatTime(activity, hardening.checkedAtMillis))
        }

        val titan = snapshot.titan
        val titanColor = when {
            !titan.policyStoreIntegrityOk -> GeDefenseUi.red
            titan.titanActive -> GeDefenseUi.green
            titan.titanLightActive -> GeDefenseUi.cyan
            else -> GeDefenseUi.textDim
        }
        titanBadge.text = activity.getString(when {
            !titan.policyStoreIntegrityOk -> R.string.titan_state_degraded
            titan.titanActive -> R.string.system_titan_managed
            titan.titanLightActive -> R.string.system_titan_light
            else -> R.string.system_titan_standard
        })
        styleBadge(titanBadge, titanColor)
        titanSummary.text = when {
            !titan.policyStoreIntegrityOk -> titan.policyStoreFailureReason ?: activity.getString(R.string.titan_state_degraded)
            titan.titanActive -> activity.getString(R.string.system_titan_summary_managed, if (titan.alwaysOnLockdown) activity.getString(R.string.always_on_enabled) else activity.getString(R.string.always_on_disabled))
            titan.titanLightActive -> activity.getString(R.string.system_titan_summary_light)
            else -> activity.getString(R.string.titan_state_standard_body)
        }

        val setup = snapshot.setup
        val setupReady = setup.batteryReady && setup.notificationsAllowed && setup.autostartVisited
        val setupColor = if (setupReady) GeDefenseUi.green else GeDefenseUi.gold
        setupBadge.text = activity.getString(if (setupReady) R.string.setup_status_done else R.string.setup_status_open)
        styleBadge(setupBadge, setupColor)
        setupSummary.text = activity.getString(
            R.string.system_setup_summary,
            stateWord(setup.batteryReady),
            stateWord(setup.autostartVisited),
            stateWord(setup.notificationsAllowed),
            stateWord(setup.usageAccess),
            stateWord(setup.allFilesAccess),
        )

        val platformReady = snapshot.nativeFullFlowAvailable && snapshot.integrity.ok && snapshot.evidenceOk
        val platformColor = if (platformReady) GeDefenseUi.green else GeDefenseUi.orange
        platformBadge.text = activity.getString(if (platformReady) R.string.system_runtime_ready else R.string.ui_attention)
        styleBadge(platformBadge, platformColor)
        platformSummary.text = activity.getString(
            R.string.system_runtime_summary,
            if (snapshot.nativeFullFlowAvailable) "GaiaNet V2" else activity.getString(R.string.gaianet_v2_missing),
            snapshot.indexedPrefixes,
            snapshot.evidenceRecords,
            snapshot.xdr.events.size,
        )
    }

    private fun sectionCard(
        icon: VgtIcon,
        accent: Int,
        title: String,
        badge: TextView,
        summary: TextView,
        vararg content: View,
    ): View = FrameLayout(activity).apply {
        background = GeDefenseUi.glassPanelBackground(activity, accent = accent, radius = 18)
        addView(LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(activity, icon, accent, 36), LinearLayout.LayoutParams(dp(36), dp(36)))
                addView(GeDefenseUi.textView(activity, title, 13.5f, GeDefenseUi.text, bold = true), LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(13); rightMargin = dp(10) })
                addView(badge)
            })
            addView(summary.apply { setPadding(0, dp(10), 0, 0) })
            content.forEach { child -> addView(child, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(14) }) }
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun styleBadge(view: TextView, color: Int) {
        view.setTextColor(color)
        view.background = GeDefenseUi.badgeBackground(activity, color)
    }

    private fun stateWord(value: Boolean): String = activity.getString(if (value) R.string.always_on_enabled else R.string.always_on_disabled)


    private fun gap(value: Int) = GeDefenseUi.addVerticalGap(rootLayout, activity, value)
    private fun dp(value: Int) = GeDefenseUi.dp(activity, value)
}
