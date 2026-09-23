package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

// STATUS: DIAMANT VGT SUPREME
class SupportVgtActivity : Activity() {
    private lateinit var rootLayout: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        VgtWindowInsets.configureSystemBars(window)
        setContentView(buildUi())
    }

    private fun buildUi(): View {
        val root = FrameLayout(this).apply { setBackgroundColor(GeDefenseUi.bg) }
        root.addView(CyberBackgroundView(this), FrameLayout.LayoutParams(-1, -1))
        val scroll = ScrollView(this).apply { clipToPadding = false; overScrollMode = View.OVER_SCROLL_NEVER }
        VgtUiPerformance.bindScroll(scroll)
        rootLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(18), dp(22), dp(46))
        }
        scroll.addView(rootLayout, FrameLayout.LayoutParams(-1, -2))
        root.addView(scroll, FrameLayout.LayoutParams(-1, -1))
        rootLayout.addView(VgtUiComponents.screenHeader(this, getString(R.string.support_vgt_title), getString(R.string.support_vgt_subtitle)))
        gap(14)
        rootLayout.addView(infoCard())
        gap(14)
        rootLayout.addView(methodCard(
            VgtIcon.CLOUD, GeDefenseUi.cyan, "PayPal", "paypal.me/dergoldenelotus",
            getString(R.string.support_vgt_open_paypal),
        ) { openHttps(PAYPAL_URI) })
        gap(12)
        rootLayout.addView(methodCard(
            VgtIcon.CORRELATE, GeDefenseUi.gold, "Bitcoin", BITCOIN_ADDRESS,
            getString(R.string.support_vgt_copy_address),
        ) { copy("Bitcoin", BITCOIN_ADDRESS) })
        gap(12)
        rootLayout.addView(methodCard(
            VgtIcon.EVIDENCE, GeDefenseUi.cyan, "ETH / USDT (ERC-20)", ETH_ADDRESS,
            getString(R.string.support_vgt_copy_address),
        ) { copy("ETH / USDT", ETH_ADDRESS) })
        gap(16)
        rootLayout.addView(GeDefenseUi.textView(this, getString(R.string.support_vgt_security_note), 9.4f, GeDefenseUi.textDim).apply {
            gravity = Gravity.CENTER
            setLineSpacing(dp(2).toFloat(), 1f)
        })

        root.setOnApplyWindowInsetsListener { _, insets ->
            val safe = VgtWindowInsets.safeArea(insets)
            rootLayout.setPadding(dp(22) + safe.left, dp(18) + safe.top, dp(22) + safe.right, dp(46) + safe.bottom)
            insets
        }
        root.post { root.requestApplyInsets() }
        return root
    }

    private fun infoCard(): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@SupportVgtActivity, accent = GeDefenseUi.gold, radius = 18)
        addView(LinearLayout(this@SupportVgtActivity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(GeDefenseUi.textView(this@SupportVgtActivity, getString(R.string.support_vgt_card_title), 13.5f, GeDefenseUi.text, bold = true))
            addView(GeDefenseUi.textView(this@SupportVgtActivity, getString(R.string.support_vgt_card_body), 10.3f, GeDefenseUi.textMuted).apply {
                setPadding(0, dp(9), 0, 0); setLineSpacing(dp(2).toFloat(), 1f)
            })
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun methodCard(icon: VgtIcon, accent: Int, title: String, value: String, actionLabel: String, action: () -> Unit): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@SupportVgtActivity, accent = accent, radius = 17)
        addView(LinearLayout(this@SupportVgtActivity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(16), dp(18), dp(16))
            addView(LinearLayout(this@SupportVgtActivity).apply {
                orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(this@SupportVgtActivity, icon, accent, 34), LinearLayout.LayoutParams(dp(34), dp(34)))
                addView(GeDefenseUi.textView(this@SupportVgtActivity, title, 12.5f, GeDefenseUi.text, bold = true), LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(12) })
            })
            addView(GeDefenseUi.monoTextView(this@SupportVgtActivity, value, 9.2f, accent).apply {
                setPadding(0, dp(11), 0, 0); setTextIsSelectable(true)
            })
            addView(GeDefenseUi.actionButton(this@SupportVgtActivity, actionLabel, goldStyle = accent == GeDefenseUi.gold) { action() }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(13) })
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun openHttps(uri: String) {
        val parsed = Uri.parse(uri)
        if (parsed.scheme != "https" || parsed.host != "paypal.me") return
        try { startActivity(Intent(Intent.ACTION_VIEW, parsed)) }
        catch (_: RuntimeException) { Toast.makeText(this, R.string.support_vgt_open_failed, Toast.LENGTH_LONG).show() }
    }

    private fun copy(label: String, value: String) {
        val clipboard = getSystemService(ClipboardManager::class.java) ?: return
        clipboard.setPrimaryClip(ClipData.newPlainText(label, value))
        Toast.makeText(this, R.string.support_vgt_copied, Toast.LENGTH_SHORT).show()
    }

    private fun gap(dp: Int) = GeDefenseUi.addVerticalGap(rootLayout, this, dp)
    private fun dp(v: Int) = GeDefenseUi.dp(this, v)

    companion object {
        private const val PAYPAL_URI = "https://paypal.me/dergoldenelotus"
        private const val BITCOIN_ADDRESS = "bc1q3ue5gq822tddmkdrek79adlkm36fatat3lz0dm"
        private const val ETH_ADDRESS = "0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85"
    }
}
