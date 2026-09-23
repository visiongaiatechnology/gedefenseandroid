package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Toast
import java.util.concurrent.atomic.AtomicBoolean

// STATUS: DIAMANT VGT SUPREME
class VpnDisclosureActivity : Activity() {
    private lateinit var runtime: AppRuntime
    private lateinit var acceptButton: View
    private val acceptancePending = AtomicBoolean(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        VgtWindowInsets.configureSystemBars(window)
        runtime = RuntimeActivityEntry.requireReady(this) ?: return
        setResult(RESULT_CANCELED)
        setContentView(buildUi())
    }

    private fun buildUi(): View {
        val root = FrameLayout(this).apply { setBackgroundColor(GeDefenseUi.bg) }
        root.addView(CyberBackgroundView(this), FrameLayout.LayoutParams(-1, -1))

        val scroll = ScrollView(this).apply {
            clipToPadding = false
            overScrollMode = View.OVER_SCROLL_NEVER
        }
        VgtUiPerformance.bindScroll(scroll)
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(18), dp(22), dp(48))
        }
        scroll.addView(content, FrameLayout.LayoutParams(-1, -2))
        root.addView(scroll, FrameLayout.LayoutParams(-1, -1))

        content.addView(VgtUiComponents.screenHeader(
            this,
            getString(R.string.vpn_disclosure_title),
            getString(R.string.vpn_disclosure_subtitle),
        ))
        gap(content, 14)

        content.addView(infoCard(
            VgtIcon.SHIELD,
            GeDefenseUi.cyan,
            getString(R.string.vpn_disclosure_local_title),
            getString(R.string.vpn_disclosure_local_body),
        ))
        gap(content, 12)
        content.addView(infoCard(
            VgtIcon.INTELLIGENCE,
            GeDefenseUi.gold,
            getString(R.string.vpn_disclosure_data_title),
            getString(R.string.vpn_disclosure_data_body),
        ))
        gap(content, 12)
        content.addView(infoCard(
            VgtIcon.EVIDENCE,
            GeDefenseUi.green,
            getString(R.string.vpn_disclosure_not_collected_title),
            getString(R.string.vpn_disclosure_not_collected_body),
        ))
        gap(content, 12)

        content.addView(GeDefenseUi.actionButton(this, getString(R.string.vpn_disclosure_privacy_action)) {
            startActivity(Intent(this, PrivacyActivity::class.java))
        })
        gap(content, 10)
        acceptButton = GeDefenseUi.actionButton(this, getString(R.string.vpn_disclosure_accept), goldStyle = true) {
            acceptAndContinue()
        }
        content.addView(acceptButton)
        gap(content, 8)
        content.addView(GeDefenseUi.actionButton(this, getString(R.string.vpn_disclosure_decline)) {
            setResult(RESULT_CANCELED)
            finish()
        })

        root.setOnApplyWindowInsetsListener { _, insets ->
            val safe = VgtWindowInsets.safeArea(insets)
            content.setPadding(
                dp(22) + safe.left,
                dp(18) + safe.top,
                dp(22) + safe.right,
                dp(48) + safe.bottom,
            )
            insets
        }
        root.post { root.requestApplyInsets() }

        return root
    }

    private fun acceptAndContinue() {
        if (!acceptancePending.compareAndSet(false, true)) return
        acceptButton.isEnabled = false
        if (!runtime.executeBackground("vpn-disclosure-accept") {
            val accepted = runtime.vpnDisclosure.accept()
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                acceptancePending.set(false)
                if (!accepted) {
                    acceptButton.isEnabled = true
                    Toast.makeText(this, getString(R.string.vpn_disclosure_store_failed), Toast.LENGTH_LONG).show()
                    return@runOnUiThread
                }
                setResult(RESULT_OK)
                finish()
            }
        }) {
            acceptancePending.set(false)
            acceptButton.isEnabled = true
            Toast.makeText(this, getString(R.string.vpn_disclosure_store_failed), Toast.LENGTH_LONG).show()
        }
    }

    private fun infoCard(icon: VgtIcon, accent: Int, title: String, body: String): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@VpnDisclosureActivity, accent = accent, radius = 18)
        addView(LinearLayout(this@VpnDisclosureActivity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(LinearLayout(this@VpnDisclosureActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(this@VpnDisclosureActivity, icon, accent, 36), LinearLayout.LayoutParams(dp(36), dp(36)))
                addView(GeDefenseUi.textView(this@VpnDisclosureActivity, title, 13.5f, GeDefenseUi.text, bold = true), LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(13) })
            })
            addView(GeDefenseUi.textView(this@VpnDisclosureActivity, body, 10.2f, GeDefenseUi.textMuted).apply {
                setPadding(0, dp(10), 0, 0)
                setLineSpacing(dp(2).toFloat(), 1f)
            })
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun gap(parent: LinearLayout, value: Int) = parent.addView(View(this).apply {
        layoutParams = LinearLayout.LayoutParams(1, dp(value))
    })

    private fun dp(value: Int): Int = GeDefenseUi.dp(this, value)
}
