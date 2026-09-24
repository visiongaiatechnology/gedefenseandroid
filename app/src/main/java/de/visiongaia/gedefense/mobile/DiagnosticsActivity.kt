package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

// STATUS: DIAMANT VGT SUPREME
class DiagnosticsActivity : Activity() {
    private lateinit var runtime: AppRuntime
    private lateinit var rootLayout: LinearLayout
    private lateinit var runtimeBadge: TextView
    private lateinit var runtimeSummary: TextView
    private lateinit var resilienceBadge: TextView
    private lateinit var resilienceSummary: TextView
    private lateinit var threatSelfTestBadge: TextView
    private lateinit var threatSelfTestSummary: TextView
    private lateinit var threatSelfTestButton: TextView
    private lateinit var privacySummary: TextView
    private lateinit var exportButton: TextView
    private val exportRunning = AtomicBoolean(false)
    private val lifecycleGeneration = AtomicLong(0L)
    private val listener: () -> Unit = {
        val generation = lifecycleGeneration.get()
        runOnUiThread {
            if (generation == lifecycleGeneration.get() && !isFinishing && !isDestroyed) refresh()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        VgtWindowInsets.configureSystemBars(window)
        runtime = RuntimeActivityEntry.requireReady(this) ?: return
        setContentView(buildUi())
        refresh()
    }

    override fun onStart() {
        super.onStart()
        lifecycleGeneration.incrementAndGet()
        runtime.addStateListener(listener)
        val exporting = exportRunning.get()
        exportButton.isEnabled = !exporting
        exportButton.alpha = if (exporting) 0.55f else 1f
        refresh()
    }

    override fun onStop() {
        lifecycleGeneration.incrementAndGet()
        runtime.removeStateListener(listener)
        super.onStop()
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    private fun buildUi(): View {
        val root = FrameLayout(this).apply { setBackgroundColor(GeDefenseUi.bg) }
        root.addView(CyberBackgroundView(this), FrameLayout.LayoutParams(-1, -1))
        val scroll = ScrollView(this).apply { clipToPadding = false; overScrollMode = View.OVER_SCROLL_NEVER }
        VgtUiPerformance.bindScroll(scroll)
        rootLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(18), dp(22), dp(48))
        }
        scroll.addView(rootLayout, FrameLayout.LayoutParams(-1, -2))
        root.addView(scroll, FrameLayout.LayoutParams(-1, -1))

        rootLayout.addView(VgtUiComponents.screenHeader(this, getString(R.string.diagnostics_title), getString(R.string.diagnostics_subtitle)))
        gap(14)

        runtimeBadge = GeDefenseUi.pill(this, getString(R.string.ui_waiting), GeDefenseUi.gold)
        runtimeSummary = GeDefenseUi.textView(this, "", 10.4f, GeDefenseUi.textMuted)
        rootLayout.addView(statusCard(VgtIcon.INTELLIGENCE, GeDefenseUi.cyan, getString(R.string.diagnostics_runtime_title), runtimeBadge, runtimeSummary))

        gap(12)
        resilienceBadge = GeDefenseUi.pill(this, getString(R.string.ui_waiting), GeDefenseUi.gold)
        resilienceSummary = GeDefenseUi.textView(this, "", 10.4f, GeDefenseUi.textMuted)
        rootLayout.addView(statusCard(VgtIcon.SHIELD, GeDefenseUi.gold, getString(R.string.diagnostics_resilience_title), resilienceBadge, resilienceSummary))

        gap(12)
        threatSelfTestBadge = GeDefenseUi.pill(this, getString(R.string.ui_waiting), GeDefenseUi.gold)
        threatSelfTestSummary = GeDefenseUi.textView(this, "", 10.4f, GeDefenseUi.textMuted).apply {
            setLineSpacing(dp(2).toFloat(), 1f)
        }
        threatSelfTestButton = GeDefenseUi.actionButton(this, getString(R.string.diagnostics_threat_self_test_action), goldStyle = true) {
            runThreatEnforcementSelfTest()
        }
        rootLayout.addView(statusCard(
            VgtIcon.BLOCK,
            GeDefenseUi.red,
            getString(R.string.diagnostics_threat_self_test_title),
            threatSelfTestBadge,
            threatSelfTestSummary,
            threatSelfTestButton,
        ))

        gap(12)
        privacySummary = GeDefenseUi.textView(this, getString(R.string.diagnostics_privacy_body), 10.2f, GeDefenseUi.textMuted).apply {
            setLineSpacing(dp(2).toFloat(), 1f)
        }
        exportButton = GeDefenseUi.actionButton(this, getString(R.string.diagnostics_export_action), goldStyle = true) { requestExportDestination() }
        rootLayout.addView(FrameLayout(this).apply {
            background = GeDefenseUi.glassPanelBackground(this@DiagnosticsActivity, accent = GeDefenseUi.green, radius = 18)
            addView(LinearLayout(this@DiagnosticsActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(20), dp(18), dp(20), dp(18))
                addView(LinearLayout(this@DiagnosticsActivity).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    addView(VgtUiComponents.iconWell(this@DiagnosticsActivity, VgtIcon.EVIDENCE, GeDefenseUi.green, 36), LinearLayout.LayoutParams(dp(36), dp(36)))
                    addView(GeDefenseUi.textView(this@DiagnosticsActivity, getString(R.string.diagnostics_export_title), 13.5f, GeDefenseUi.text, bold = true), LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(13) })
                })
                addView(privacySummary.apply { setPadding(0, dp(10), 0, 0) })
                addView(exportButton, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(14) })
            }, FrameLayout.LayoutParams(-1, -2))
        })

        gap(12)
        rootLayout.addView(FrameLayout(this).apply {
            background = GeDefenseUi.softPanelBackground(this@DiagnosticsActivity, 16, GeDefenseUi.cyan)
            addView(LinearLayout(this@DiagnosticsActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(18), dp(15), dp(18), dp(15))
                addView(GeDefenseUi.textView(this@DiagnosticsActivity, getString(R.string.diagnostics_android_title), 12.5f, GeDefenseUi.text, bold = true))
                addView(GeDefenseUi.textView(this@DiagnosticsActivity, getString(R.string.diagnostics_android_body), 9.8f, GeDefenseUi.textDim).apply { setPadding(0, dp(8), 0, 0) })
                addView(GeDefenseUi.actionButton(this@DiagnosticsActivity, getString(R.string.diagnostics_android_action)) {
                    try { startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply { data = android.net.Uri.parse("package:$packageName") }) }
                    catch (_: RuntimeException) { Toast.makeText(this@DiagnosticsActivity, R.string.diagnostics_settings_failed, Toast.LENGTH_LONG).show() }
                }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) })
            }, FrameLayout.LayoutParams(-1, -2))
        })

        root.setOnApplyWindowInsetsListener { _, insets ->
            val safe = VgtWindowInsets.safeArea(insets)
            rootLayout.setPadding(dp(22) + safe.left, dp(18) + safe.top, dp(22) + safe.right, dp(48) + safe.bottom)
            insets
        }
        root.post { root.requestApplyInsets() }
        return root
    }

    private fun refresh() {
        val integrity = runtime.integritySnapshot.get()
        val xdr = runtime.xdr.snapshot()
        val setup = runtime.setup.snapshot()
        val vpnStatus = runtime.state.lastVpnStatus()
        val runtimeReady = runtime.securityBootstrapComplete() && integrity.ok && runtime.evidenceHealth.ok && xdr.trustStoresHealthy && NativeGaiaNet.available
        styleBadge(runtimeBadge, if (runtimeReady) GeDefenseUi.green else GeDefenseUi.orange)
        runtimeBadge.text = getString(if (runtimeReady) R.string.diagnostics_state_ready else R.string.ui_attention)
        runtimeSummary.text = getString(
            R.string.diagnostics_runtime_summary,
            if (runtime.securityBootstrapComplete()) getString(R.string.always_on_enabled) else getString(R.string.always_on_disabled),
            integrity.state,
            if (runtime.evidenceHealth.ok) getString(R.string.always_on_enabled) else getString(R.string.always_on_disabled),
            if (xdr.trustStoresHealthy) getString(R.string.always_on_enabled) else getString(R.string.always_on_disabled),
            if (NativeGaiaNet.available) getString(R.string.always_on_enabled) else getString(R.string.always_on_disabled),
        )

        val selfTest = runtime.state.lastResilienceSelfTestStatus() ?: "NONE"
        val selfHealing = runtime.resilienceSupervisor.latestReport()
        val killSwitch = runtime.state.platformLockdown() || runtime.titan.snapshot().alwaysOnLockdown
        val resilienceReady = setup.batteryReady && killSwitch && vpnStatus != "FULL_FLOW_FAILED" && selfHealing?.healthy != false
        styleBadge(resilienceBadge, if (resilienceReady) GeDefenseUi.green else GeDefenseUi.gold)
        resilienceBadge.text = getString(if (resilienceReady) R.string.diagnostics_state_resilient else R.string.diagnostics_state_review)
        resilienceSummary.text = getString(
            R.string.diagnostics_resilience_summary,
            vpnStatus.take(40),
            if (killSwitch) getString(R.string.always_on_enabled) else getString(R.string.always_on_disabled),
            runtime.state.vpnRecoveryCount(),
            selfTest.take(20),
            runtime.state.lastResilienceSelfTestDurationMillis(),
            if (setup.batteryReady) getString(R.string.always_on_enabled) else getString(R.string.always_on_disabled),
        )

        val threatTest = runtime.threatEnforcementSelfTest.get()
        val threatColor = when (threatTest.state) {
            "PASS" -> GeDefenseUi.green
            "FAIL" -> GeDefenseUi.red
            "RUNNING" -> GeDefenseUi.cyan
            else -> GeDefenseUi.gold
        }
        styleBadge(threatSelfTestBadge, threatColor)
        threatSelfTestBadge.text = threatTest.state
        val target = threatTest.target ?: getString(R.string.ui_none)
        val feeds = threatTest.feeds.takeIf { it.isNotEmpty() }?.joinToString(",") ?: getString(R.string.ui_none)
        val reason = threatTest.reason ?: getString(R.string.ui_none)
        threatSelfTestSummary.text = getString(
            R.string.diagnostics_threat_self_test_summary,
            target,
            feeds,
            reason,
        )
        val threatTestAvailable = runtime.state.isVpnActive() &&
            runtime.state.protectionMode() == ProtectionMode.FULL_FLOW_BETA &&
            runtime.state.lastVpnStatus() == "FULL_GUARDED" && threatTest.state != "RUNNING"
        threatSelfTestButton.isEnabled = threatTestAvailable
        threatSelfTestButton.alpha = if (threatTestAvailable) 1f else 0.55f
    }

    private fun runThreatEnforcementSelfTest() {
        val started = runtime.runThreatEnforcementSelfTest()
        Toast.makeText(
            this,
            if (started) R.string.diagnostics_threat_self_test_started else R.string.diagnostics_threat_self_test_unavailable,
            Toast.LENGTH_LONG,
        ).show()
        refresh()
    }

    private fun statusCard(icon: VgtIcon, accent: Int, title: String, badge: TextView, summary: TextView, vararg extras: View): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@DiagnosticsActivity, accent = accent, radius = 18)
        addView(LinearLayout(this@DiagnosticsActivity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(LinearLayout(this@DiagnosticsActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(this@DiagnosticsActivity, icon, accent, 36), LinearLayout.LayoutParams(dp(36), dp(36)))
                addView(GeDefenseUi.textView(this@DiagnosticsActivity, title, 13.5f, GeDefenseUi.text, bold = true), LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(13); rightMargin = dp(10) })
                addView(badge)
            })
            addView(summary.apply { setPadding(0, dp(10), 0, 0); setLineSpacing(dp(2).toFloat(), 1f) })
            extras.forEach { extra ->
                addView(extra, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) })
            }
        }, FrameLayout.LayoutParams(-1, -2))
    }

    @Suppress("DEPRECATION")
    private fun requestExportDestination() {
        if (exportRunning.get()) return
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/zip"
            putExtra(Intent.EXTRA_TITLE, "GeDefense-Diagnostics-$stamp.zip")
        }
        try { startActivityForResult(intent, EXPORT_REQUEST) }
        catch (_: RuntimeException) { Toast.makeText(this, R.string.diagnostics_export_failed, Toast.LENGTH_LONG).show() }
    }

    @Deprecated("Legacy Activity result is used deliberately to keep the app dependency-free.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != EXPORT_REQUEST || resultCode != RESULT_OK) return
        val uri = data?.data ?: return
        if (!exportRunning.compareAndSet(false, true)) return
        exportButton.isEnabled = false
        exportButton.alpha = 0.55f
        val generation = lifecycleGeneration.get()
        val application = applicationContext
        if (!runtime.executeBackground("diagnostics-export") {
            val ok = try {
                contentResolver.openOutputStream(uri, "w")?.use { output ->
                    DiagnosticBundleBuilder(application, runtime).writeTo(output)
                } != null
            } catch (_: Exception) { false }
            exportRunning.set(false)
            runOnUiThread {
                if (generation != lifecycleGeneration.get() || isFinishing || isDestroyed) return@runOnUiThread
                exportButton.isEnabled = true
                exportButton.alpha = 1f
                Toast.makeText(this, if (ok) R.string.diagnostics_export_ok else R.string.diagnostics_export_failed, Toast.LENGTH_LONG).show()
                refresh()
            }
        }) {
            exportRunning.set(false)
            exportButton.isEnabled = true
            exportButton.alpha = 1f
            Toast.makeText(this, R.string.diagnostics_export_failed, Toast.LENGTH_LONG).show()
        }
    }

    private fun styleBadge(view: TextView, color: Int) {
        view.setTextColor(color)
        view.background = GeDefenseUi.badgeBackground(this, color)
    }

    private fun gap(value: Int) = GeDefenseUi.addVerticalGap(rootLayout, this, value)
    private fun dp(value: Int) = GeDefenseUi.dp(this, value)

    companion object { private const val EXPORT_REQUEST = 9301 }
}
