package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.app.AlertDialog
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

class BehaviorActivity : Activity() {
    private lateinit var runtime: AppRuntime
    private lateinit var rootLayout: LinearLayout
    private lateinit var summaryText: TextView
    private lateinit var integrityText: TextView
    private lateinit var policyText: TextView
    private lateinit var profileHost: LinearLayout
    private lateinit var recentHost: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runtime = RuntimeActivityEntry.requireReady(this) ?: return
        configureSystemBars()
        setContentView(buildUi())
        refresh()
    }

    override fun onResume() { super.onResume(); refresh() }

    private fun buildUi(): View {
        val root = FrameLayout(this).apply { setBackgroundColor(GeDefenseUi.bg) }
        root.addView(CyberBackgroundView(this), FrameLayout.LayoutParams(-1, -1))
        val scroll = ScrollView(this).apply { clipToPadding = false; overScrollMode = View.OVER_SCROLL_NEVER }
        rootLayout = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(24), dp(18), dp(24), dp(44)) }
        scroll.addView(rootLayout, FrameLayout.LayoutParams(-1, -2)); root.addView(scroll, FrameLayout.LayoutParams(-1, -1))

        rootLayout.addView(VgtUiComponents.screenHeader(this, getString(R.string.behavior_title), getString(R.string.behavior_subtitle)))
        gap(16)
        summaryText = GeDefenseUi.textView(this, "", 18f, GeDefenseUi.cyan, bold = true)
        integrityText = GeDefenseUi.textView(this, "", 10f, GeDefenseUi.textMuted)
        policyText = GeDefenseUi.textView(this, "", 10f, GeDefenseUi.textMuted)
        rootLayout.addView(sectionCard(VgtIcon.ACTIVITY, GeDefenseUi.cyan, getString(R.string.behavior_status_title), arrayOf(
            summaryText,
            integrityText,
            policyText,
            GeDefenseUi.actionButton(this, getString(R.string.behavior_policy_toggle), goldStyle = true) { togglePolicy() },
            GeDefenseUi.actionButton(this, getString(R.string.behavior_reset)) { confirmReset() },
        )))

        gap(18); rootLayout.addView(GeDefenseUi.sectionTitle(this, getString(R.string.behavior_profiles_title))); gap(10)
        profileHost = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }; rootLayout.addView(profileHost)
        gap(18); rootLayout.addView(GeDefenseUi.sectionTitle(this, getString(R.string.behavior_recent_title))); gap(10)
        recentHost = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }; rootLayout.addView(recentHost)

        root.setOnApplyWindowInsetsListener { _, insets ->
            val safe = VgtWindowInsets.safeArea(insets)
            rootLayout.setPadding(dp(24) + safe.left, dp(18) + safe.top, dp(24) + safe.right, dp(44) + safe.bottom)
            insets
        }
        root.post { root.requestApplyInsets() }
        return root
    }

    private fun refresh() {
        val b = runtime.behavior.snapshot()
        summaryText.text = getString(R.string.behavior_summary, b.matureProfiles, b.learningProfiles, b.anomalyCount)
        integrityText.text = getString(if (b.baselineIntegrityOk) R.string.behavior_integrity_ok else R.string.behavior_integrity_failed)
        integrityText.setTextColor(if (b.baselineIntegrityOk) GeDefenseUi.green else GeDefenseUi.red)
        policyText.text = getString(if (b.autoQuarantineCritical) R.string.behavior_policy_auto else R.string.behavior_policy_alert)
        policyText.setTextColor(if (b.autoQuarantineCritical) GeDefenseUi.orange else GeDefenseUi.cyan)

        profileHost.removeAllViews()
        if (b.profiles.isEmpty()) profileHost.addView(emptyText(R.string.behavior_no_profiles))
        else b.profiles.take(30).forEachIndexed { i, p -> if (i > 0) addGap(profileHost, 8); profileHost.addView(profileCard(p)) }

        recentHost.removeAllViews()
        val recent = runtime.xdr.snapshot().events.filter { it.category == XdrCategory.BEHAVIOR }.take(20)
        if (recent.isEmpty()) recentHost.addView(emptyText(R.string.behavior_no_anomalies))
        else recent.forEachIndexed { i, e -> if (i > 0) addGap(recentHost, 7); recentHost.addView(eventCard(e)) }
    }

    private fun profileCard(p: BehaviorProfile): View = FrameLayout(this).apply {
        val accent = if (p.mature) GeDefenseUi.green else GeDefenseUi.gold
        background = GeDefenseUi.glassPanelBackground(this@BehaviorActivity, accent = accent, radius = 16)
        addView(LinearLayout(this@BehaviorActivity).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(16), dp(13), dp(16), dp(13))
            addView(LinearLayout(this@BehaviorActivity).apply {
                orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(this@BehaviorActivity, VgtIcon.ACTIVITY, accent, 30), LinearLayout.LayoutParams(dp(30), dp(30)))
                addView(LinearLayout(this@BehaviorActivity).apply {
                    orientation = LinearLayout.VERTICAL; setPadding(dp(10), 0, dp(8), 0)
                    addView(GeDefenseUi.textView(this@BehaviorActivity, p.label, 11f, GeDefenseUi.text, bold = true))
                    addView(GeDefenseUi.monoTextView(this@BehaviorActivity, p.packageName, 8.5f, GeDefenseUi.textDim))
                }, LinearLayout.LayoutParams(0, -2, 1f))
                addView(GeDefenseUi.pill(this@BehaviorActivity, getString(if (p.mature) R.string.behavior_learned else R.string.behavior_learning), accent))
            })
            addView(GeDefenseUi.textView(this@BehaviorActivity,
                getString(R.string.behavior_profile_stats, p.observations, GeDefenseUi.formatBytes(p.avgTxPerMinute), GeDefenseUi.formatBytes(p.avgTotalPerMinute), p.knownDomains.size, p.knownCountries.size),
                9.2f, GeDefenseUi.textMuted).apply { setPadding(0, dp(9), 0, 0); setLineSpacing(dp(2).toFloat(), 1f) })
            addView(GeDefenseUi.textView(this@BehaviorActivity,
                getString(R.string.behavior_profile_intelligence, p.learningConfidence, p.avgUploadRatioPermille / 10, p.avgFlowsPerMinute, GeDefenseUi.formatBytes(p.txDeviationPerMinute)),
                8.8f, GeDefenseUi.textDim).apply { setPadding(0, dp(5), 0, 0); setLineSpacing(dp(2).toFloat(), 1f) })
            if (p.anomalyCount > 0) addView(GeDefenseUi.textView(this@BehaviorActivity,
                getString(R.string.behavior_profile_anomalies, p.anomalyCount, GeDefenseUi.formatTime(this@BehaviorActivity, p.lastAnomalyAtMillis)),
                8.8f, GeDefenseUi.orange).apply { setPadding(0, dp(6), 0, 0) })
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun eventCard(e: XdrEvent): View = FrameLayout(this).apply {
        val accent = when (e.severity) { XdrSeverity.CRITICAL -> GeDefenseUi.red; XdrSeverity.HIGH -> GeDefenseUi.orange; XdrSeverity.MEDIUM -> GeDefenseUi.gold; else -> GeDefenseUi.cyan }
        background = GeDefenseUi.softPanelBackground(this@BehaviorActivity, 14, accent)
        addView(LinearLayout(this@BehaviorActivity).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(13), dp(11), dp(13), dp(11))
            addView(GeDefenseUi.textView(this@BehaviorActivity, e.title, 10.5f, accent, bold = true))
            addView(GeDefenseUi.textView(this@BehaviorActivity, e.subject, 9f, GeDefenseUi.text).apply { setPadding(0, dp(4), 0, 0) })
            addView(GeDefenseUi.textView(this@BehaviorActivity, e.detail, 8.5f, GeDefenseUi.textDim).apply { setPadding(0, dp(5), 0, 0); maxLines = 4 })
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun togglePolicy() {
        val current = runtime.behavior.snapshot().autoQuarantineCritical
        if (current) {
            runBehaviorMutation("behavior-policy-disable") { runtime.behavior.setAutoQuarantineCritical(false) }
            return
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.behavior_auto_confirm_title)
            .setMessage(R.string.behavior_auto_confirm_body)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.behavior_enable_auto) { _, _ ->
                runBehaviorMutation("behavior-policy-enable") { runtime.behavior.setAutoQuarantineCritical(true) }
            }
            .show()
    }

    private fun confirmReset() {
        AlertDialog.Builder(this)
            .setTitle(R.string.behavior_reset_confirm_title)
            .setMessage(R.string.behavior_reset_confirm_body)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.behavior_reset_confirm_action) { _, _ ->
                runBehaviorMutation("behavior-reset-learning", successMessage = R.string.behavior_reset_done) {
                    runtime.behavior.resetLearning()
                }
            }.show()
    }

    private fun runBehaviorMutation(taskName: String, successMessage: Int? = null, action: () -> Boolean) {
        val accepted = runtime.executeBackground(taskName) {
            val ok = try { action() } catch (_: RuntimeException) { false }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                if (!ok) {
                    Toast.makeText(this, R.string.behavior_reset_failed, Toast.LENGTH_LONG).show()
                } else if (successMessage != null) {
                    Toast.makeText(this, successMessage, Toast.LENGTH_LONG).show()
                }
                refresh()
            }
        }
        if (!accepted) Toast.makeText(this, R.string.behavior_reset_failed, Toast.LENGTH_LONG).show()
    }

    private fun sectionCard(icon: VgtIcon, accent: Int, title: String, content: Array<View>): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@BehaviorActivity, accent = accent, radius = 18)
        addView(LinearLayout(this@BehaviorActivity).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(18), dp(16), dp(18), dp(16))
            addView(LinearLayout(this@BehaviorActivity).apply {
                orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(this@BehaviorActivity, icon, accent, 32), LinearLayout.LayoutParams(dp(32), dp(32)))
                addView(GeDefenseUi.sectionTitle(this@BehaviorActivity, title), LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(12) })
            })
            content.forEach { addView(it, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) }) }
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun emptyText(id: Int) = GeDefenseUi.textView(this, getString(id), 10f, GeDefenseUi.textDim).apply { gravity = Gravity.CENTER; setPadding(dp(12), dp(22), dp(12), dp(22)) }
    private fun addGap(host: LinearLayout, value: Int) = host.addView(View(this), LinearLayout.LayoutParams(1, dp(value)))
    private fun gap(value: Int) = GeDefenseUi.addVerticalGap(rootLayout, this, value)
    private fun dp(value: Int) = GeDefenseUi.dp(this, value)

    private fun configureSystemBars() = VgtWindowInsets.configureSystemBars(window)
}
