package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

// STATUS: DIAMANT VGT SUPREME
class SetupWizardActivity : Activity() {
    private val uiHandler = Handler(Looper.getMainLooper())
    private val renderRunnable = Runnable {
        renderQueued = false
        if (!isFinishing && !isDestroyed && ::pageHost.isInitialized) render()
    }
    private val setupListener: () -> Unit = { scheduleRender() }
    private val runtimeListener: () -> Unit = { scheduleRender() }

    private lateinit var runtime: AppRuntime
    private lateinit var setup: DeviceSetupManager
    private lateinit var renderer: SetupWizardPageRenderer
    private lateinit var pageHost: FrameLayout
    private lateinit var stepLabel: TextView
    private lateinit var pageTitle: TextView
    private lateinit var pageSubtitle: TextView
    private lateinit var progress: VgtProgressView
    private lateinit var nextButton: TextView
    private lateinit var backButton: TextView
    private var stepIndex = 0
    private var renderQueued = false
    private var firstRun = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runtime = RuntimeActivityEntry.requireReady(this) ?: return
        setup = runtime.setup
        renderer = SetupWizardPageRenderer(this, setup, runtime)
        firstRun = intent.getBooleanExtra(EXTRA_FIRST_RUN, false)
        stepIndex = savedInstanceState?.getInt(STATE_STEP_INDEX, 0)
            ?.coerceIn(0, SetupWizardStep.entries.lastIndex) ?: 0
        VgtWindowInsets.configureSystemBars(window)
        setContentView(buildUi())
        render()
    }

    override fun onStart() {
        super.onStart()
        if (!::setup.isInitialized) return
        setup.addStateListener(setupListener)
        runtime.addStateListener(runtimeListener)
        setup.requestRefresh()
    }

    override fun onResume() {
        super.onResume()
        if (!::setup.isInitialized) return
        render()
        setup.requestRefresh()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus && ::setup.isInitialized) setup.requestRefresh()
    }

    override fun onStop() {
        if (::setup.isInitialized) setup.removeStateListener(setupListener)
        if (::runtime.isInitialized) runtime.removeStateListener(runtimeListener)
        uiHandler.removeCallbacks(renderRunnable)
        renderQueued = false
        super.onStop()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putInt(STATE_STEP_INDEX, stepIndex)
        super.onSaveInstanceState(outState)
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        setup.requestRefresh()
    }

    private fun buildUi(): View {
        val root = FrameLayout(this).apply { setBackgroundColor(GeDefenseUi.bg) }
        root.addView(CyberBackgroundView(this), FrameLayout.LayoutParams(-1, -1))

        val shell = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(18), dp(24), dp(24))
        }
        root.addView(shell, FrameLayout.LayoutParams(-1, -1))

        shell.addView(VgtUiComponents.screenHeader(
            this,
            getString(R.string.setup_title),
            getString(R.string.setup_subtitle),
        ))
        GeDefenseUi.addVerticalGap(shell, this, 14)

        stepLabel = GeDefenseUi.textView(this, "", 10.2f, GeDefenseUi.gold, bold = true).apply {
            letterSpacing = 0.08f
        }
        shell.addView(stepLabel)
        progress = VgtProgressView(this, GeDefenseUi.cyan)
        shell.addView(progress, LinearLayout.LayoutParams(-1, dp(5)).apply { topMargin = dp(7) })
        GeDefenseUi.addVerticalGap(shell, this, 12)

        pageTitle = GeDefenseUi.textView(this, "", 18.5f, GeDefenseUi.text, bold = true)
        shell.addView(pageTitle)
        pageSubtitle = GeDefenseUi.textView(this, "", 10.5f, GeDefenseUi.textMuted).apply {
            setPadding(0, dp(4), 0, 0)
            setLineSpacing(dp(1).toFloat(), 1f)
        }
        shell.addView(pageSubtitle)
        GeDefenseUi.addVerticalGap(shell, this, 14)

        pageHost = FrameLayout(this)
        shell.addView(pageHost, LinearLayout.LayoutParams(-1, 0, 1f))

        val nav = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        backButton = GeDefenseUi.actionButton(this, getString(R.string.setup_back)) {
            if (stepIndex > 0) {
                stepIndex--
                render()
            } else {
                finish()
            }
        }
        nextButton = GeDefenseUi.actionButton(this, getString(R.string.setup_next), goldStyle = true) {
            handleNext()
        }
        nav.addView(backButton, LinearLayout.LayoutParams(0, -2, 1f).apply { rightMargin = dp(8) })
        nav.addView(nextButton, LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(8) })
        shell.addView(nav)

        root.setOnApplyWindowInsetsListener { _, insets ->
            val safe = VgtWindowInsets.safeArea(insets)
            shell.setPadding(
                dp(24) + safe.left,
                dp(18) + safe.top,
                dp(24) + safe.right,
                dp(24) + safe.bottom,
            )
            insets
        }
        root.post { root.requestApplyInsets() }
        return root
    }

    private fun handleNext() {
        val step = SetupWizardStep.entries[stepIndex]
        when (step) {
            SetupWizardStep.INITIAL_SYNC -> {
                val sync = runtime.initialSetupFeedSyncState()
                when {
                    sync.ready -> {
                        stepIndex++
                        render()
                    }
                    sync.phase == InitialSetupFeedSyncPhase.SYNCING -> Unit
                    else -> runtime.startInitialSetupFeedSync()
                }
            }
            SetupWizardStep.SUMMARY -> completeSetup()
            else -> {
                if (stepIndex < SetupWizardStep.entries.lastIndex) {
                    stepIndex++
                    render()
                }
            }
        }
    }

    private fun render() {
        if (!::pageHost.isInitialized) return
        val steps = SetupWizardStep.entries
        val step = steps[stepIndex]
        val sync = runtime.initialSetupFeedSyncState()

        stepLabel.text = getString(R.string.setup_step, stepIndex + 1, steps.size)
        pageTitle.text = getString(step.titleRes)
        pageSubtitle.text = getString(step.subtitleRes)
        progress.setProgress(
            (stepIndex + 1f) / steps.size,
            if (step == SetupWizardStep.SUMMARY) GeDefenseUi.green else GeDefenseUi.cyan,
        )
        backButton.text = getString(if (stepIndex == 0) R.string.setup_later else R.string.setup_back)

        when (step) {
            SetupWizardStep.INITIAL_SYNC -> {
                val running = sync.phase == InitialSetupFeedSyncPhase.SYNCING
                backButton.isEnabled = !running
                backButton.alpha = if (running) 0.55f else 1f
                nextButton.isEnabled = !running
                nextButton.alpha = if (running) 0.62f else 1f
                nextButton.text = getString(
                    when {
                        running -> R.string.setup_initial_sync_running_button
                        sync.ready -> R.string.setup_next
                        sync.phase == InitialSetupFeedSyncPhase.FAILED -> R.string.setup_initial_sync_retry
                        else -> R.string.setup_initial_sync_start
                    },
                )
            }
            SetupWizardStep.SUMMARY -> {
                backButton.isEnabled = true
                backButton.alpha = 1f
                nextButton.isEnabled = sync.ready
                nextButton.alpha = if (sync.ready) 1f else 0.55f
                nextButton.text = getString(R.string.setup_finish_activate)
            }
            else -> {
                backButton.isEnabled = true
                backButton.alpha = 1f
                nextButton.isEnabled = true
                nextButton.alpha = 1f
                nextButton.text = getString(R.string.setup_next)
            }
        }

        pageHost.removeAllViews()
        val scroll = ScrollView(this).apply {
            overScrollMode = View.OVER_SCROLL_NEVER
            clipToPadding = false
        }
        VgtUiPerformance.bindScroll(scroll)
        val body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 0, 0, dp(18))
        }
        if (step == SetupWizardStep.INITIAL_SYNC) {
            renderInitialSync(body, sync)
        } else {
            renderer.render(step, body)
        }
        scroll.addView(body, FrameLayout.LayoutParams(-1, -2))
        pageHost.addView(scroll, FrameLayout.LayoutParams(-1, -1))

        if (step == SetupWizardStep.INITIAL_SYNC && sync.phase == InitialSetupFeedSyncPhase.IDLE) {
            pageHost.post { if (!isFinishing && !isDestroyed) runtime.startInitialSetupFeedSync() }
        }
    }

    private fun renderInitialSync(parent: LinearLayout, sync: InitialSetupFeedSyncState) {
        val accent = when (sync.phase) {
            InitialSetupFeedSyncPhase.READY -> GeDefenseUi.green
            InitialSetupFeedSyncPhase.FAILED -> GeDefenseUi.red
            else -> GeDefenseUi.cyan
        }
        val card = FrameLayout(this).apply {
            background = GeDefenseUi.glassPanelBackground(this@SetupWizardActivity, accent = accent, radius = 18)
        }
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(20), dp(20), dp(20))
        }
        content.addView(GeDefenseUi.textView(
            this,
            getString(
                when (sync.phase) {
                    InitialSetupFeedSyncPhase.IDLE -> R.string.setup_initial_sync_preparing
                    InitialSetupFeedSyncPhase.SYNCING -> R.string.setup_initial_sync_running
                    InitialSetupFeedSyncPhase.READY -> R.string.setup_initial_sync_ready
                    InitialSetupFeedSyncPhase.FAILED -> R.string.setup_initial_sync_failed
                },
            ),
            13.2f,
            accent,
            bold = true,
        ))
        content.addView(GeDefenseUi.textView(
            this,
            initialSyncDetail(sync),
            10.5f,
            GeDefenseUi.textMuted,
        ).apply {
            setPadding(0, dp(8), 0, 0)
            setLineSpacing(dp(2).toFloat(), 1f)
        })
        val feedProgress = VgtProgressView(this, accent).apply { setProgress(sync.progress, accent) }
        content.addView(feedProgress, LinearLayout.LayoutParams(-1, dp(7)).apply { topMargin = dp(18) })
        content.addView(GeDefenseUi.textView(
            this,
            resources.getQuantityString(
                R.plurals.setup_initial_sync_progress,
                sync.totalFeeds,
                sync.completedFeeds,
                sync.totalFeeds,
                sync.successfulFeeds,
            ),
            9.8f,
            GeDefenseUi.textDim,
        ).apply { setPadding(0, dp(8), 0, 0) })
        card.addView(content, FrameLayout.LayoutParams(-1, -2))
        parent.addView(card)

        GeDefenseUi.addVerticalGap(parent, this, 12)
        parent.addView(GeDefenseUi.textView(
            this,
            getString(R.string.setup_initial_sync_privacy),
            9.8f,
            GeDefenseUi.textDim,
        ).apply { setLineSpacing(dp(2).toFloat(), 1f) })
    }

    private fun initialSyncDetail(sync: InitialSetupFeedSyncState): String = when (sync.phase) {
        InitialSetupFeedSyncPhase.IDLE -> getString(R.string.setup_initial_sync_detail_idle)
        InitialSetupFeedSyncPhase.SYNCING -> resources.getQuantityString(
            R.plurals.setup_initial_sync_detail_running,
            sync.totalFeeds,
            sync.completedFeeds,
            sync.totalFeeds,
        )
        InitialSetupFeedSyncPhase.READY -> resources.getQuantityString(
            R.plurals.setup_initial_sync_detail_ready,
            sync.totalRecords,
            sync.totalRecords,
            sync.successfulFeeds,
            sync.totalFeeds,
        )
        InitialSetupFeedSyncPhase.FAILED -> getString(R.string.setup_initial_sync_detail_failed)
    }

    private fun completeSetup() {
        if (!runtime.initialSetupFeedSyncState().ready) {
            stepIndex = SetupWizardStep.entries.indexOf(SetupWizardStep.INITIAL_SYNC)
            render()
            return
        }
        setup.markWizardCompleted()
        runtime.activatePostSetupInventoryAsync()
        setResult(
            RESULT_OK,
            android.content.Intent().putExtra(EXTRA_REQUEST_PROTECTION_ACTIVATION, firstRun),
        )
        finish()
    }

    private fun scheduleRender() {
        if (renderQueued) return
        renderQueued = true
        uiHandler.postDelayed(renderRunnable, RENDER_COALESCE_MS)
    }

    private fun dp(value: Int): Int = GeDefenseUi.dp(this, value)

    companion object {
        const val EXTRA_FIRST_RUN = "setup_first_run"
        const val EXTRA_REQUEST_PROTECTION_ACTIVATION = "setup_request_protection_activation"
        private const val STATE_STEP_INDEX = "setup_step_index"
        private const val RENDER_COALESCE_MS = 90L
    }
}
