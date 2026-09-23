package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.app.AlertDialog
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

class FirewallActivity : Activity() {
    private lateinit var runtime: AppRuntime
    private lateinit var store: FirewallPolicyStore
    private lateinit var rootLayout: LinearLayout
    private lateinit var countText: TextView
    private lateinit var policyHealthHost: LinearLayout
    private lateinit var appsHost: LinearLayout
    private lateinit var allTab: TextView
    private lateinit var userTab: TextView
    private lateinit var systemTab: TextView
    private lateinit var allowedTab: TextView
    private var filter = Filter.ALL
    private var entries: List<FirewallPolicyStore.AppEntry> = emptyList()

    private enum class Filter { ALL, USER, SYSTEM, ALLOWED }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runtime = RuntimeActivityEntry.requireReady(this) ?: return
        store = runtime.firewallPolicy
        configureSystemBars()
        setContentView(buildUi())
        reload()
    }

    override fun onResume() {
        super.onResume()
        reload()
    }

    private fun buildUi(): View {
        val root = FrameLayout(this).apply { setBackgroundColor(GeDefenseUi.bg) }
        root.addView(CyberBackgroundView(this), FrameLayout.LayoutParams(-1, -1))
        val scroll = ScrollView(this).apply { clipToPadding = false; overScrollMode = View.OVER_SCROLL_NEVER }
        rootLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(18), dp(24), dp(40))
        }
        scroll.addView(rootLayout, FrameLayout.LayoutParams(-1, -2))
        root.addView(scroll, FrameLayout.LayoutParams(-1, -1))

        rootLayout.addView(VgtUiComponents.screenHeader(
            this,
            getString(R.string.firewall_title),
            getString(R.string.firewall_subtitle),
        ))
        gap(16)

        val intro = FrameLayout(this).apply {
            background = GeDefenseUi.glassPanelBackground(this@FirewallActivity, accent = GeDefenseUi.gold, radius = 20)
            addView(LinearLayout(this@FirewallActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(18), dp(16), dp(18), dp(16))
                addView(GeDefenseUi.textView(this@FirewallActivity, getString(R.string.firewall_default_deny_title), 13f, GeDefenseUi.gold, bold = true))
                addView(GeDefenseUi.textView(this@FirewallActivity, getString(R.string.firewall_default_deny_body), 10.2f, GeDefenseUi.textDim).apply {
                    setPadding(0, dp(5), 0, 0)
                    setLineSpacing(dp(2).toFloat(), 1f)
                })
                countText = GeDefenseUi.textView(this@FirewallActivity, "", 11f, GeDefenseUi.cyan, bold = true).apply { setPadding(0, dp(12), 0, 0) }
                addView(countText)
                policyHealthHost = LinearLayout(this@FirewallActivity).apply { orientation = LinearLayout.VERTICAL }
                addView(policyHealthHost, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
                addView(GeDefenseUi.actionButton(this@FirewallActivity, getString(R.string.firewall_select_mode), goldStyle = true) {
                    if (!runtime.state.canMutateProtectionConfiguration()) return@actionButton
                    try {
                        runtime.state.setProtectionMode(ProtectionMode.LOCKDOWN)
                    } catch (_: IllegalArgumentException) {
                        return@actionButton
                    }
                    runtime.notifyStateChanged()
                }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(14) })
            }, FrameLayout.LayoutParams(-1, -2))
        }
        rootLayout.addView(intro)
        gap(16)
        rootLayout.addView(buildTabs())
        gap(12)
        appsHost = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        rootLayout.addView(appsHost)

        root.setOnApplyWindowInsetsListener { _, insets ->
            val safe = VgtWindowInsets.safeArea(insets)
            rootLayout.setPadding(dp(24) + safe.left, dp(18) + safe.top, dp(24) + safe.right, dp(40) + safe.bottom)
            insets
        }
        root.post { root.requestApplyInsets() }
        return root
    }

    private fun buildTabs(): View = FrameLayout(this).apply {
        background = GeDefenseUi.softPanelBackground(this@FirewallActivity, 16, GeDefenseUi.cyan)
        val row = LinearLayout(this@FirewallActivity).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(6), dp(6), dp(6), dp(6))
        }
        allTab = tab(getString(R.string.firewall_filter_all), Filter.ALL)
        userTab = tab(getString(R.string.firewall_filter_user), Filter.USER)
        systemTab = tab(getString(R.string.firewall_filter_system), Filter.SYSTEM)
        allowedTab = tab(getString(R.string.firewall_filter_allowed), Filter.ALLOWED)
        listOf(allTab, userTab, systemTab, allowedTab).forEachIndexed { index, item ->
            row.addView(item, LinearLayout.LayoutParams(0, dp(42), 1f).apply { if (index > 0) leftMargin = dp(5) })
        }
        addView(row, FrameLayout.LayoutParams(-1, -2))
    }

    private fun tab(label: String, value: Filter): TextView = GeDefenseUi.textView(this, label, 9.5f, GeDefenseUi.textMuted, bold = true).apply {
        gravity = Gravity.CENTER
        isClickable = true
        setOnClickListener { filter = value; render() }
    }

    private fun reload() {
        entries = try { store.appEntries() } catch (_: Throwable) { emptyList() }
        render()
    }

    private fun render() {
        if (!::appsHost.isInitialized) return
        val allowed = store.allowedPackages()
        countText.text = getString(R.string.firewall_allowed_count, allowed.size)
        renderPolicyHealth()
        listOf(allTab to Filter.ALL, userTab to Filter.USER, systemTab to Filter.SYSTEM, allowedTab to Filter.ALLOWED).forEach { (view, value) ->
            val active = value == filter
            view.setTextColor(if (active) GeDefenseUi.gold else GeDefenseUi.textMuted)
            view.background = if (active) GeDefenseUi.badgeBackground(this, GeDefenseUi.gold) else null
        }
        appsHost.removeAllViews()
        val filtered = entries.filter {
            when (filter) {
                Filter.ALL -> true
                Filter.USER -> !it.systemApp
                Filter.SYSTEM -> it.systemApp
                Filter.ALLOWED -> it.packageName in allowed
            }
        }
        if (filtered.isEmpty()) {
            appsHost.addView(GeDefenseUi.textView(this, getString(R.string.firewall_no_apps), 10.5f, GeDefenseUi.textDim).apply {
                gravity = Gravity.CENTER; setPadding(dp(12), dp(26), dp(12), dp(26))
            })
            return
        }
        filtered.forEachIndexed { index, item ->
            if (index > 0) gap(8)
            appsHost.addView(appCard(item, item.packageName in allowed))
        }
    }

    private fun appCard(item: FirewallPolicyStore.AppEntry, allowed: Boolean): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@FirewallActivity, accent = if (allowed) GeDefenseUi.green else null, radius = 16)
        val row = LinearLayout(this@FirewallActivity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(16), dp(13), dp(14), dp(13))
            addView(VgtUiComponents.iconWell(this@FirewallActivity, if (item.systemApp) VgtIcon.SETTINGS else VgtIcon.SHIELD, if (allowed) GeDefenseUi.green else GeDefenseUi.cyan, 34), LinearLayout.LayoutParams(dp(34), dp(34)))
            addView(LinearLayout(this@FirewallActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(12), 0, dp(10), 0)
                addView(GeDefenseUi.textView(this@FirewallActivity, item.label, 11.5f, GeDefenseUi.text, bold = true).apply { maxLines = 1 })
                addView(GeDefenseUi.textView(this@FirewallActivity, item.packageName, 8.8f, GeDefenseUi.textDim).apply { maxLines = 1; setPadding(0, dp(2), 0, 0) })
            }, LinearLayout.LayoutParams(0, -2, 1f))
            addView(GeDefenseUi.pill(
                this@FirewallActivity,
                getString(if (allowed) R.string.firewall_allowed else R.string.firewall_blocked),
                if (allowed) GeDefenseUi.green else GeDefenseUi.red,
            ))
        }
        addView(row, FrameLayout.LayoutParams(-1, -2))
        isClickable = true
        isFocusable = true
        setOnClickListener {
            if (!store.setAllowed(item.packageName, !allowed)) {
                Toast.makeText(this@FirewallActivity, R.string.xdr_policy_change_failed, Toast.LENGTH_LONG).show()
                reload()
                return@setOnClickListener
            }
            if (!refreshActiveLockdownOrFailClosed()) {
                Toast.makeText(this@FirewallActivity, R.string.live_policy_refresh_failed_stopped, Toast.LENGTH_LONG).show()
            }
            reload()
        }
    }


    private fun renderPolicyHealth() {
        if (!::policyHealthHost.isInitialized) return
        policyHealthHost.removeAllViews()
        val ok = store.integrityOk()
        policyHealthHost.addView(GeDefenseUi.textView(
            this,
            getString(if (ok) R.string.firewall_integrity_ok else R.string.firewall_integrity_failed),
            9.2f,
            if (ok) GeDefenseUi.green else GeDefenseUi.red,
            bold = true,
        ))
        if (!ok) {
            policyHealthHost.addView(GeDefenseUi.actionButton(this, getString(R.string.firewall_reset_policy), goldStyle = true) { confirmResetPolicy() }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
        }
    }

    private fun confirmResetPolicy() {
        AlertDialog.Builder(this)
            .setTitle(R.string.firewall_reset_policy_title)
            .setMessage(R.string.firewall_reset_policy_body)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.xdr_recover_action) { _, _ ->
                val accepted = runtime.executeBackground("firewall-reset-policy") {
                    val ok = try { runtime.xdr.resetFirewallPolicy() } catch (_: RuntimeException) { false }
                    runOnUiThread {
                        if (isFinishing || isDestroyed) return@runOnUiThread
                        val liveRefreshOk = !ok || refreshActiveLockdownOrFailClosed()
                        val message = when {
                            !ok -> R.string.firewall_reset_failed
                            !liveRefreshOk -> R.string.live_policy_refresh_failed_stopped
                            else -> R.string.firewall_reset_done
                        }
                        Toast.makeText(this, getString(message), Toast.LENGTH_LONG).show()
                        reload()
                    }
                }
                if (!accepted) Toast.makeText(this, R.string.firewall_reset_failed, Toast.LENGTH_LONG).show()
            }.show()
    }

    private fun refreshActiveLockdownOrFailClosed(): Boolean {
        if (!runtime.state.isVpnActive() || runtime.state.protectionMode() != ProtectionMode.LOCKDOWN) return true
        return try {
            startService(Intent(this, GeDefenseVpnService::class.java).setAction(GeDefenseVpnService.ACTION_REFRESH))
            true
        } catch (_: RuntimeException) {
            // A persisted allowlist mutation must never leave a running lockdown tunnel on stale policy.
            try { stopService(Intent(this, GeDefenseVpnService::class.java)) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("firewall-activity", error) }
            false
        }
    }

    private fun configureSystemBars() = VgtWindowInsets.configureSystemBars(window)

    private fun gap(value: Int) = GeDefenseUi.addVerticalGap(rootLayout, this, value)
    private fun dp(value: Int) = GeDefenseUi.dp(this, value)
}
