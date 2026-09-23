package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.content.Intent
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

class HardeningActivity : Activity() {
    private lateinit var runtime: AppRuntime
    private lateinit var rootLayout: LinearLayout
    private lateinit var scoreText: TextView
    private lateinit var summaryText: TextView
    private lateinit var findingsHost: LinearLayout
    private lateinit var scanButton: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runtime = RuntimeActivityEntry.requireReady(this) ?: return
        configureSystemBars()
        setContentView(buildUi())
        refresh(runtime.hardeningSnapshot.get())
        if (runtime.hardeningSnapshot.get().checkedAtMillis == 0L) runScan()
    }

    override fun onResume() {
        super.onResume()
        if (::findingsHost.isInitialized) refresh(runtime.hardeningSnapshot.get())
    }

    private fun buildUi(): View {
        val root = FrameLayout(this).apply { setBackgroundColor(GeDefenseUi.bg) }
        root.addView(CyberBackgroundView(this), FrameLayout.LayoutParams(-1, -1))
        val scroll = ScrollView(this).apply { clipToPadding = false; overScrollMode = View.OVER_SCROLL_NEVER }
        rootLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(18), dp(24), dp(44))
        }
        scroll.addView(rootLayout, FrameLayout.LayoutParams(-1, -2))
        root.addView(scroll, FrameLayout.LayoutParams(-1, -1))

        rootLayout.addView(VgtUiComponents.screenHeader(this, getString(R.string.hardening_title), getString(R.string.hardening_subtitle)))
        gap(16)

        scoreText = GeDefenseUi.textView(this, "--/100", 31f, GeDefenseUi.gold, bold = true).apply { gravity = Gravity.CENTER }
        summaryText = GeDefenseUi.textView(this, getString(R.string.hardening_pending), 10.5f, GeDefenseUi.textMuted).apply {
            gravity = Gravity.CENTER; setLineSpacing(dp(2).toFloat(), 1f)
        }
        scanButton = GeDefenseUi.actionButton(this, getString(R.string.hardening_scan), goldStyle = true) { runScan() }
        rootLayout.addView(sectionCard(VgtIcon.SHIELD, GeDefenseUi.gold, getString(R.string.hardening_posture_title), arrayOf(scoreText, summaryText, scanButton)))

        gap(18)
        rootLayout.addView(GeDefenseUi.sectionTitle(this, getString(R.string.hardening_controls_title)))
        gap(10)
        findingsHost = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        rootLayout.addView(findingsHost)

        root.setOnApplyWindowInsetsListener { _, insets ->
            val safe = VgtWindowInsets.safeArea(insets)
            rootLayout.setPadding(dp(24) + safe.left, dp(18) + safe.top, dp(24) + safe.right, dp(44) + safe.bottom)
            insets
        }
        root.post { root.requestApplyInsets() }
        return root
    }

    private fun runScan() {
        scanButton.isEnabled = false
        scanButton.alpha = 0.65f
        summaryText.text = getString(R.string.hardening_scanning)
        runtime.scanHardeningAsync { snapshot ->
            runOnUiThread {
                scanButton.isEnabled = true
                scanButton.alpha = 1f
                refresh(snapshot)
            }
        }
    }

    private fun refresh(snapshot: HardeningSnapshot) {
        if (!::findingsHost.isInitialized) return
        if (snapshot.checkedAtMillis == 0L) {
            scoreText.text = getString(R.string.hardening_score_pending)
            summaryText.text = getString(R.string.hardening_pending)
            return
        }
        val accent = scoreColor(snapshot.score)
        scoreText.text = getString(R.string.hardening_score, snapshot.score)
        scoreText.setTextColor(accent)
        summaryText.text = getString(
            R.string.hardening_summary,
            snapshot.passed,
            snapshot.review,
            snapshot.failed,
            GeDefenseUi.formatTime(this, snapshot.checkedAtMillis),
        )

        findingsHost.removeAllViews()
        snapshot.findings.sortedWith(
            compareBy<HardeningFinding> { statusRank(it.status) }
                .thenBy { severityRank(it.severity) }
                .thenBy { it.title },
        ).forEachIndexed { index, finding ->
            if (index > 0) addGap(findingsHost, 8)
            findingsHost.addView(findingCard(finding))
        }
    }

    private fun findingCard(finding: HardeningFinding): View {
        val accent = findingColor(finding)
        val status = when (finding.status) {
            HardeningStatus.PASS -> getString(R.string.hardening_pass)
            HardeningStatus.REVIEW -> getString(R.string.hardening_review)
            HardeningStatus.FAIL -> getString(R.string.hardening_fail)
            HardeningStatus.UNKNOWN -> getString(R.string.hardening_unknown)
        }
        return FrameLayout(this).apply {
            background = GeDefenseUi.glassPanelBackground(this@HardeningActivity, accent = accent, radius = 16)
            addView(LinearLayout(this@HardeningActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(15), dp(13), dp(15), dp(13))
                addView(LinearLayout(this@HardeningActivity).apply {
                    orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                    addView(VgtUiComponents.iconWell(this@HardeningActivity, iconFor(finding.category), accent, 30), LinearLayout.LayoutParams(dp(30), dp(30)))
                    addView(LinearLayout(this@HardeningActivity).apply {
                        orientation = LinearLayout.VERTICAL; setPadding(dp(10), 0, dp(8), 0)
                        addView(GeDefenseUi.textView(this@HardeningActivity, finding.title, 10.8f, GeDefenseUi.text, bold = true))
                        addView(GeDefenseUi.textView(this@HardeningActivity, finding.category.name.replace('_', ' '), 8.2f, GeDefenseUi.textDim).apply { setPadding(0, dp(2), 0, 0) })
                    }, LinearLayout.LayoutParams(0, -2, 1f))
                    addView(GeDefenseUi.pill(this@HardeningActivity, status, accent))
                })
                addView(GeDefenseUi.textView(this@HardeningActivity, finding.summary, 9.5f, GeDefenseUi.textMuted).apply {
                    setPadding(0, dp(8), 0, 0); setLineSpacing(dp(2).toFloat(), 1f)
                })
                if (finding.evidence.isNotBlank()) {
                    addView(GeDefenseUi.monoTextView(this@HardeningActivity, finding.evidence.take(420), 8.2f, GeDefenseUi.textDim).apply {
                        setPadding(0, dp(7), 0, 0); setLineSpacing(dp(1).toFloat(), 1f)
                    })
                }
                if (finding.remediation.isNotBlank()) {
                    addView(GeDefenseUi.textView(this@HardeningActivity, getString(R.string.hardening_remediation, finding.remediation), 9f, GeDefenseUi.textMuted).apply {
                        setPadding(0, dp(7), 0, 0); setLineSpacing(dp(2).toFloat(), 1f)
                    })
                }
                finding.settingsAction?.let { action ->
                    addView(GeDefenseUi.actionButton(this@HardeningActivity, getString(R.string.hardening_open_settings)) { openSettings(action) }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(9) })
                }
            }, FrameLayout.LayoutParams(-1, -2))
        }
    }

    private fun openSettings(action: String) {
        try { startActivity(Intent(action)) }
        catch (_: RuntimeException) { Toast.makeText(this, getString(R.string.hardening_settings_failed), Toast.LENGTH_LONG).show() }
    }

    private fun sectionCard(icon: VgtIcon, accent: Int, title: String, content: Array<View>): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@HardeningActivity, accent = accent, radius = 18)
        addView(LinearLayout(this@HardeningActivity).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(18), dp(16), dp(18), dp(16))
            addView(LinearLayout(this@HardeningActivity).apply {
                orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(this@HardeningActivity, icon, accent, 32), LinearLayout.LayoutParams(dp(32), dp(32)))
                addView(GeDefenseUi.sectionTitle(this@HardeningActivity, title), LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(12) })
            })
            content.forEach { child -> addView(child, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) }) }
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun scoreColor(score: Int): Int = when {
        score >= 90 -> GeDefenseUi.green
        score >= 75 -> GeDefenseUi.cyan
        score >= 55 -> GeDefenseUi.gold
        score >= 35 -> GeDefenseUi.orange
        else -> GeDefenseUi.red
    }

    private fun findingColor(f: HardeningFinding): Int = when (f.status) {
        HardeningStatus.PASS -> GeDefenseUi.green
        HardeningStatus.UNKNOWN -> GeDefenseUi.cyan
        HardeningStatus.REVIEW -> when (f.severity) {
            HardeningSeverity.CRITICAL, HardeningSeverity.HIGH -> GeDefenseUi.orange
            HardeningSeverity.MEDIUM -> GeDefenseUi.gold
            else -> GeDefenseUi.cyan
        }
        HardeningStatus.FAIL -> when (f.severity) {
            HardeningSeverity.CRITICAL -> GeDefenseUi.red
            HardeningSeverity.HIGH -> GeDefenseUi.orange
            else -> GeDefenseUi.gold
        }
    }

    private fun iconFor(category: HardeningCategory): VgtIcon = when (category) {
        HardeningCategory.LOCKSCREEN -> VgtIcon.SHIELD
        HardeningCategory.PATCHING -> VgtIcon.SYNC
        HardeningCategory.PLATFORM -> VgtIcon.INTEGRITY
        HardeningCategory.DEBUGGING -> VgtIcon.SETTINGS
        HardeningCategory.PRIVILEGED_ACCESS -> VgtIcon.POLICY
        HardeningCategory.NETWORK -> VgtIcon.TRAFFIC
        HardeningCategory.ENCRYPTION -> VgtIcon.EVIDENCE
    }

    private fun statusRank(status: HardeningStatus): Int = when (status) {
        HardeningStatus.FAIL -> 0; HardeningStatus.REVIEW -> 1; HardeningStatus.UNKNOWN -> 2; HardeningStatus.PASS -> 3
    }
    private fun severityRank(severity: HardeningSeverity): Int = when (severity) {
        HardeningSeverity.CRITICAL -> 0; HardeningSeverity.HIGH -> 1; HardeningSeverity.MEDIUM -> 2; HardeningSeverity.LOW -> 3; HardeningSeverity.INFO -> 4
    }

    private fun addGap(host: LinearLayout, value: Int) = host.addView(View(this), LinearLayout.LayoutParams(1, dp(value)))
    private fun gap(value: Int) = GeDefenseUi.addVerticalGap(rootLayout, this, value)
    private fun dp(value: Int) = GeDefenseUi.dp(this, value)

    private fun configureSystemBars() = VgtWindowInsets.configureSystemBars(window)
}
