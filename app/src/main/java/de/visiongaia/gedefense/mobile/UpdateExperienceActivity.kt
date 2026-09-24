package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.content.Intent
import android.content.res.ColorStateList
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView

/**
 * One-shot post-update experience for already configured installations.
 *
 * The first-run setup contract is deliberately not version-gated anymore. App updates land here,
 * where Threat Intelligence is refreshed before protection is activated or revalidated. The notice
 * is acknowledged only after the requested security transition succeeds.
 */
class UpdateExperienceActivity : Activity() {
    private val uiHandler = Handler(Looper.getMainLooper())
    private val runtimeListener: () -> Unit = {
        uiHandler.post {
            if (!isFinishing && !isDestroyed && ::statusText.isInitialized) renderAndAdvance()
        }
    }

    private lateinit var runtime: AppRuntime
    private lateinit var setup: DeviceSetupManager
    private lateinit var statusText: TextView
    private lateinit var statusProgress: VgtProgressView
    private lateinit var actionButton: LinearLayout
    private lateinit var actionLabel: TextView
    private lateinit var actionSpinner: ProgressBar
    private var actionStarted = false
    private var completionHandled = false
    private var localFailure = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runtime = RuntimeActivityEntry.requireReady(this) ?: return
        setup = runtime.setup

        if (!setup.isWizardCompleted()) {
            finish()
            return
        }
        if (runtime.state.isVpnActive()) setup.completePendingUpdateAfterProtection()
        if (!setup.shouldShowUpdateExperience()) {
            finish()
            return
        }

        VgtWindowInsets.configureSystemBars(window)
        setContentView(buildUi())
        renderAndAdvance()
    }

    override fun onStart() {
        super.onStart()
        if (::runtime.isInitialized) runtime.addStateListener(runtimeListener)
    }

    override fun onResume() {
        super.onResume()
        if (!::runtime.isInitialized || !::setup.isInitialized) return
        if (runtime.state.isVpnActive() && setup.completePendingUpdateAfterProtection()) {
            finish()
            return
        }
        renderAndAdvance()
    }

    override fun onStop() {
        if (::runtime.isInitialized) runtime.removeStateListener(runtimeListener)
        uiHandler.removeCallbacksAndMessages(null)
        super.onStop()
    }

    private fun buildUi(): View {
        val root = FrameLayout(this).apply { setBackgroundColor(GeDefenseUi.bg) }
        root.addView(CyberBackgroundView(this), FrameLayout.LayoutParams(-1, -1))

        val scroll = ScrollView(this).apply {
            isFillViewport = true
            overScrollMode = View.OVER_SCROLL_NEVER
            clipToPadding = false
        }
        VgtUiPerformance.bindScroll(scroll)

        val shell = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(GeDefenseUi.SPACING_SCREEN_HORIZONTAL_DP), dp(22), dp(GeDefenseUi.SPACING_SCREEN_HORIZONTAL_DP), dp(178))
        }
        scroll.addView(shell, FrameLayout.LayoutParams(-1, -2))
        root.addView(scroll, FrameLayout.LayoutParams(-1, -1))

        shell.addView(
            VgtUiComponents.screenHeader(
                this,
                getString(R.string.update_experience_title),
                getString(R.string.update_experience_subtitle),
            ),
        )
        GeDefenseUi.addVerticalGap(shell, this, 14)

        shell.addView(
            GeDefenseUi.pill(
                this,
                getString(R.string.update_experience_version, BuildConfig.VERSION_NAME),
                GeDefenseUi.cyan,
            ),
            LinearLayout.LayoutParams(-2, -2),
        )
        GeDefenseUi.addVerticalGap(shell, this, GeDefenseUi.SPACING_SECTION_GAP_DP + 4)

        shell.addView(GeDefenseUi.sectionTitle(this, getString(R.string.update_experience_whats_new)))
        GeDefenseUi.addVerticalGap(shell, this, 12)
        shell.addView(
            featureCard(
                "01",
                getString(R.string.update_experience_threat_title),
                getString(R.string.update_experience_threat_body),
                GeDefenseUi.cyan,
            ),
        )
        GeDefenseUi.addVerticalGap(shell, this, GeDefenseUi.SPACING_CARD_GAP_DP)
        shell.addView(
            featureCard(
                "02",
                getString(R.string.update_experience_state_title),
                getString(R.string.update_experience_state_body),
                GeDefenseUi.gold,
            ),
        )
        GeDefenseUi.addVerticalGap(shell, this, GeDefenseUi.SPACING_CARD_GAP_DP)
        shell.addView(
            featureCard(
                "03",
                getString(R.string.update_experience_flow_title),
                getString(R.string.update_experience_flow_body),
                GeDefenseUi.green,
            ),
        )
        GeDefenseUi.addVerticalGap(shell, this, GeDefenseUi.SPACING_SECTION_GAP_DP + 4)

        val statusPanel = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                dp(GeDefenseUi.CARD_CONTENT_PADDING_HORIZONTAL_DP),
                dp(GeDefenseUi.CARD_CONTENT_PADDING_VERTICAL_DP),
                dp(GeDefenseUi.CARD_CONTENT_PADDING_HORIZONTAL_DP),
                dp(GeDefenseUi.CARD_CONTENT_PADDING_VERTICAL_DP),
            )
            background = GeDefenseUi.glassPanelBackground(
                this@UpdateExperienceActivity,
                strong = true,
                accent = GeDefenseUi.cyan,
                radius = 20,
            )
        }
        statusPanel.addView(GeDefenseUi.sectionTitle(this, getString(R.string.update_experience_security_check)))
        GeDefenseUi.addVerticalGap(statusPanel, this, 12)

        statusText = GeDefenseUi.textView(this, "", 12.1f, GeDefenseUi.textMuted).apply {
            setLineSpacing(dp(2).toFloat(), 1f)
        }
        statusPanel.addView(statusText)
        GeDefenseUi.addVerticalGap(statusPanel, this, 14)

        statusProgress = VgtProgressView(this, GeDefenseUi.cyan).apply {
            visibility = View.GONE
        }
        statusPanel.addView(statusProgress, LinearLayout.LayoutParams(-1, dp(5)))
        shell.addView(statusPanel)

        val actionDock = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), dp(12), dp(12), dp(12))
            background = GeDefenseUi.glassPanelBackground(
                this@UpdateExperienceActivity,
                strong = true,
                accent = GeDefenseUi.gold,
                radius = 22,
            )
        }

        actionButton = buildActionButton()
        actionDock.addView(actionButton, LinearLayout.LayoutParams(-1, -2))
        GeDefenseUi.addVerticalGap(actionDock, this, 11)
        actionDock.addView(
            GeDefenseUi.textView(
                this,
                getString(R.string.update_experience_footer),
                10.0f,
                GeDefenseUi.textDim,
            ).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                setLineSpacing(dp(2).toFloat(), 1f)
                setPadding(dp(6), 0, dp(6), 0)
            },
        )

        val dockLayout = FrameLayout.LayoutParams(-1, -2, Gravity.BOTTOM).apply {
            leftMargin = dp(18)
            rightMargin = dp(18)
            bottomMargin = dp(14)
        }
        root.addView(actionDock, dockLayout)

        root.setOnApplyWindowInsetsListener { _, insets ->
            val safe = VgtWindowInsets.safeArea(insets)
            shell.setPadding(
                dp(GeDefenseUi.SPACING_SCREEN_HORIZONTAL_DP) + safe.left,
                dp(22) + safe.top,
                dp(GeDefenseUi.SPACING_SCREEN_HORIZONTAL_DP) + safe.right,
                dp(178) + safe.bottom,
            )
            dockLayout.leftMargin = dp(18) + safe.left
            dockLayout.rightMargin = dp(18) + safe.right
            dockLayout.bottomMargin = dp(14) + safe.bottom
            actionDock.layoutParams = dockLayout
            insets
        }
        root.post { root.requestApplyInsets() }
        return root
    }

    private fun buildActionButton(): LinearLayout {
        val button = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
            minimumHeight = dp(54)
            setPadding(dp(18), dp(13), dp(18), dp(13))
            background = GeDefenseUi.goldButtonBackground(this@UpdateExperienceActivity)
            isClickable = true
            isFocusable = true
            setOnClickListener { beginUpdateFlow() }
        }
        actionSpinner = ProgressBar(this, null, android.R.attr.progressBarStyleSmall).apply {
            isIndeterminate = true
            indeterminateTintList = ColorStateList.valueOf(GeDefenseUi.withAlpha(GeDefenseUi.bg, 220))
            visibility = View.GONE
            contentDescription = getString(R.string.update_experience_action_running)
        }
        button.addView(
            actionSpinner,
            LinearLayout.LayoutParams(dp(22), dp(22)).apply { rightMargin = dp(10) },
        )
        actionLabel = GeDefenseUi.textView(
            this,
            getString(R.string.update_experience_action),
            13.5f,
            GeDefenseUi.bg,
            bold = true,
        ).apply { gravity = Gravity.CENTER }
        button.addView(actionLabel, LinearLayout.LayoutParams(-2, -2))
        return button
    }

    private fun featureCard(index: String, title: String, body: String, accent: Int): View {
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                dp(GeDefenseUi.CARD_CONTENT_PADDING_HORIZONTAL_DP),
                dp(GeDefenseUi.CARD_CONTENT_PADDING_VERTICAL_DP),
                dp(GeDefenseUi.CARD_CONTENT_PADDING_HORIZONTAL_DP),
                dp(GeDefenseUi.CARD_CONTENT_PADDING_VERTICAL_DP),
            )
            background = GeDefenseUi.glassPanelBackground(
                this@UpdateExperienceActivity,
                accent = accent,
                radius = 19,
            )
        }
        val heading = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        heading.addView(
            GeDefenseUi.pill(this, index, accent),
            LinearLayout.LayoutParams(-2, -2).apply { rightMargin = dp(12) },
        )
        heading.addView(
            GeDefenseUi.textView(this, title, 13.3f, GeDefenseUi.text, bold = true),
            LinearLayout.LayoutParams(0, -2, 1f),
        )
        card.addView(heading)
        GeDefenseUi.addVerticalGap(card, this, 10)
        card.addView(
            GeDefenseUi.textView(this, body, 11.0f, GeDefenseUi.textMuted).apply {
                setLineSpacing(dp(2).toFloat(), 1f)
            },
        )
        return card
    }

    private fun beginUpdateFlow() {
        if (completionHandled) return
        actionStarted = true
        localFailure = false
        renderAndAdvance()

        if (setup.isUpdateThreatSyncCompleteForCurrentVersion() && runtime.threatIndex.get().count > 0) {
            finishSecurityTransition()
            return
        }

        val sync = runtime.initialSetupFeedSyncState()
        if (sync.ready) {
            setup.markUpdateThreatSyncCompleted()
            finishSecurityTransition()
            return
        }
        if (sync.phase != InitialSetupFeedSyncPhase.SYNCING) runtime.startInitialSetupFeedSync()
        renderAndAdvance()
    }

    private fun renderAndAdvance() {
        if (!::statusText.isInitialized || completionHandled) return
        val sync = runtime.initialSetupFeedSyncState()

        if (actionStarted && sync.ready) {
            setup.markUpdateThreatSyncCompleted()
            finishSecurityTransition()
            return
        }

        val alreadySynced = setup.isUpdateThreatSyncCompleteForCurrentVersion() && runtime.threatIndex.get().count > 0
        val status = when {
            localFailure -> getString(R.string.update_experience_refresh_failed)
            alreadySynced && !runtime.state.isVpnActive() -> getString(
                R.string.update_experience_synced_activation_pending,
                runtime.threatIndex.get().count,
            )
            runtime.state.isVpnActive() && alreadySynced -> getString(
                R.string.update_experience_protected,
                runtime.threatIndex.get().count,
            )
            sync.phase == InitialSetupFeedSyncPhase.SYNCING -> getString(
                R.string.update_experience_sync_progress,
                sync.completedFeeds,
                sync.totalFeeds,
            )
            sync.phase == InitialSetupFeedSyncPhase.FAILED -> getString(R.string.update_experience_sync_failed)
            else -> getString(R.string.update_experience_ready)
        }
        statusText.text = status

        val running = actionStarted && !localFailure && (
            sync.phase == InitialSetupFeedSyncPhase.SYNCING ||
                (!alreadySynced && sync.phase != InitialSetupFeedSyncPhase.FAILED)
            )
        actionSpinner.visibility = if (running) View.VISIBLE else View.GONE
        actionButton.isEnabled = !running
        actionButton.alpha = if (running) 0.82f else 1f
        actionLabel.text = getString(
            when {
                running -> R.string.update_experience_action_running
                sync.phase == InitialSetupFeedSyncPhase.FAILED || localFailure -> R.string.update_experience_action_retry
                else -> R.string.update_experience_action
            },
        )
        actionButton.contentDescription = actionLabel.text

        val showProgress = running && sync.totalFeeds > 0
        statusProgress.visibility = if (showProgress) View.VISIBLE else View.GONE
        if (showProgress) {
            statusProgress.setProgress(sync.completedFeeds.toFloat() / sync.totalFeeds.toFloat(), GeDefenseUi.cyan)
        }
    }

    private fun finishSecurityTransition() {
        if (completionHandled) return
        completionHandled = true
        setup.markUpdateThreatSyncCompleted()

        if (runtime.state.isVpnActive()) {
            val refreshRequested = try {
                startService(Intent(this, GeDefenseVpnService::class.java).setAction(GeDefenseVpnService.ACTION_REFRESH))
                true
            } catch (error: RuntimeException) {
                RuntimeFailureLog.nonCritical("update-experience-refresh", error)
                false
            }
            if (!refreshRequested) {
                completionHandled = false
                localFailure = true
                renderAndAdvance()
                return
            }
            setup.markUpdateExperienceAcknowledged()
            setResult(RESULT_OK, Intent().putExtra(EXTRA_REQUEST_PROTECTION_ACTIVATION, false))
            finish()
            return
        }

        setup.markUpdateActivationPending()
        setResult(
            RESULT_OK,
            Intent().putExtra(EXTRA_REQUEST_PROTECTION_ACTIVATION, true),
        )
        finish()
    }

    private fun dp(value: Int): Int = GeDefenseUi.dp(this, value)

    companion object {
        const val EXTRA_REQUEST_PROTECTION_ACTIVATION = "update_request_protection_activation"
    }
}
