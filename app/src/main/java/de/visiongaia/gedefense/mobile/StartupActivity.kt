package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import java.util.concurrent.atomic.AtomicBoolean

// STATUS: DIAMANT VGT SUPREME
class StartupActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    @Volatile private var bootstrapThread: Thread? = null
    private val routed = AtomicBoolean(false)
    private val bootstrapResolved = AtomicBoolean(false)
    private lateinit var runtime: AppRuntime
    private lateinit var root: FrameLayout
    private lateinit var coreView: StartupCoreView
    private lateinit var status: TextView
    private lateinit var detail: TextView
    private var startedAt = 0L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        startedAt = SystemClock.uptimeMillis()
        VgtWindowInsets.configureSystemBars(window)
        setContentView(buildUi())
        startBootSequence()
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        bootstrapThread?.interrupt()
        super.onDestroy()
    }

    private fun buildUi(): View {
        root = FrameLayout(this).apply { setBackgroundColor(GeDefenseUi.bg) }
        root.addView(CyberBackgroundView(this), FrameLayout.LayoutParams(-1, -1))

        val shell = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(26), dp(28), dp(26), dp(28))
        }
        root.addView(shell, FrameLayout.LayoutParams(-1, -1))

        shell.addView(GeDefenseUi.monoTextView(this, getString(R.string.startup_secure_boot), 9.4f, GeDefenseUi.gold).apply {
            letterSpacing = 0.16f
            gravity = Gravity.CENTER
        }, LinearLayout.LayoutParams(-1, -2))

        val centerSpacerTop = View(this)
        shell.addView(centerSpacerTop, LinearLayout.LayoutParams(1, 0, 1f))

        val coreHost = FrameLayout(this)
        coreView = StartupCoreView(this)
        coreHost.addView(coreView, FrameLayout.LayoutParams(-1, -1))
        coreHost.addView(ImageView(this).apply {
            setImageResource(R.drawable.gedefense_logo)
            scaleType = ImageView.ScaleType.FIT_CENTER
            alpha = 0.98f
        }, FrameLayout.LayoutParams(dp(104), dp(104), Gravity.CENTER))
        shell.addView(coreHost, LinearLayout.LayoutParams(dp(248), dp(248)))

        shell.addView(GeDefenseUi.displayTextView(this, getString(R.string.app_name), 28f, GeDefenseUi.text).apply {
            gravity = Gravity.CENTER
            letterSpacing = 0.015f
        }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) })

        shell.addView(GeDefenseUi.textView(this, getString(R.string.startup_tagline), 10f, GeDefenseUi.textMuted, bold = true).apply {
            gravity = Gravity.CENTER
            letterSpacing = 0.14f
        }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(6) })

        status = GeDefenseUi.monoTextView(this, getString(R.string.startup_status_vault), 10.2f, GeDefenseUi.cyan).apply {
            gravity = Gravity.CENTER
            letterSpacing = 0.075f
        }
        shell.addView(status, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(26) })

        detail = GeDefenseUi.textView(this, getString(R.string.startup_detail_hardening), 9.3f, GeDefenseUi.textDim).apply {
            gravity = Gravity.CENTER
        }
        shell.addView(detail, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(7) })

        val badges = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
        }
        listOf(
            R.string.startup_badge_gaianet to GeDefenseUi.cyan,
            R.string.startup_badge_xdr to GeDefenseUi.gold,
            R.string.startup_badge_vault to GeDefenseUi.green,
            R.string.startup_badge_integrity to GeDefenseUi.cyan,
        ).forEachIndexed { index, (label, accent) ->
            badges.addView(GeDefenseUi.pill(this, getString(label), accent), LinearLayout.LayoutParams(-2, -2).apply {
                if (index > 0) leftMargin = dp(7)
            })
        }
        shell.addView(badges, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(20) })

        shell.addView(View(this), LinearLayout.LayoutParams(1, 0, 1f))
        shell.addView(GeDefenseUi.monoTextView(this, getString(R.string.startup_local_first), 8.8f, GeDefenseUi.textDim).apply {
            gravity = Gravity.CENTER
            letterSpacing = 0.09f
        })

        root.setOnApplyWindowInsetsListener { _, insets ->
            val safe = VgtWindowInsets.safeArea(insets)
            shell.setPadding(dp(26) + safe.left, dp(28) + safe.top, dp(26) + safe.right, dp(28) + safe.bottom)
            insets
        }
        root.post { root.requestApplyInsets() }
        return root
    }

    private fun startBootSequence() {
        coreView.setReadiness(0.16f)
        postPhase(260L, R.string.startup_status_gaianet, 0.38f)
        postPhase(520L, R.string.startup_status_xdr, 0.61f)
        postPhase(780L, R.string.startup_status_integrity, 0.82f)

        bootstrapThread = Thread({
            val initialized = AppRuntime.awaitInitialized(this, MAX_RUNTIME_INIT_WAIT_MS)
            if (initialized == null) {
                bootstrapResolved.set(true)
                handler.post {
                    if (isFinishing || isDestroyed) return@post
                    coreView.setReadiness(0.18f)
                    status.setText(R.string.startup_status_failed)
                    status.setTextColor(GeDefenseUi.red)
                    detail.text = getString(
                        R.string.startup_detail_runtime_failure,
                        AppRuntime.initializationFailure() ?: "runtime_initialization_timeout",
                    )
                }
                return@Thread
            }
            runtime = initialized
            val complete = runtime.awaitSecurityBootstrap(MAX_BOOTSTRAP_WAIT_MS)
            runtime.setup.awaitPreferenceLoad(MAX_SETUP_PREF_WAIT_MS)
            bootstrapResolved.set(true)
            handler.post {
                if (isFinishing || isDestroyed) return@post
                if (complete) {
                    coreView.setReadiness(1f)
                    status.setText(R.string.startup_status_ready)
                    status.setTextColor(GeDefenseUi.green)
                    detail.setText(R.string.startup_detail_ready)
                } else {
                    coreView.setReadiness(0.92f)
                    status.setText(R.string.startup_status_background)
                    status.setTextColor(GeDefenseUi.gold)
                    detail.setText(R.string.startup_detail_fail_closed)
                }
                val elapsed = SystemClock.uptimeMillis() - startedAt
                handler.postDelayed({ routeIntoApp() }, (MIN_DISPLAY_MS - elapsed).coerceAtLeast(READY_HOLD_MS))
            }
        }, "gedefense-startup-gate").apply {
            isDaemon = true
            start()
        }
    }

    private fun postPhase(delayMs: Long, labelRes: Int, progress: Float) {
        handler.postDelayed({
            if (isFinishing || isDestroyed || routed.get() || bootstrapResolved.get()) return@postDelayed
            status.setText(labelRes)
            coreView.setReadiness(progress)
        }, delayMs)
    }

    private fun routeIntoApp() {
        if (!routed.compareAndSet(false, true) || isFinishing || isDestroyed) return
        root.animate()
            .alpha(0f)
            .setDuration(EXIT_FADE_MS)
            .withEndAction {
                if (isFinishing || isDestroyed) return@withEndAction
                if (runtime.setup.isWizardCompleted()) {
                    startActivity(Intent(this, MainActivity::class.java))
                } else {
                    startActivities(arrayOf(
                        Intent(this, MainActivity::class.java),
                        Intent(this, SetupWizardActivity::class.java),
                    ))
                }
                finish()
            }
            .start()
    }

    private fun dp(value: Int): Int = GeDefenseUi.dp(this, value)

    companion object {
        private const val MIN_DISPLAY_MS = 1_180L
        private const val MAX_RUNTIME_INIT_WAIT_MS = 15_000L
        private const val MAX_BOOTSTRAP_WAIT_MS = 1_650L
        private const val MAX_SETUP_PREF_WAIT_MS = 750L
        private const val READY_HOLD_MS = 180L
        private const val EXIT_FADE_MS = 190L
    }
}
