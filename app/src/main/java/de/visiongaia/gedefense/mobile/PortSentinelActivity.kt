package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.app.AlertDialog
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

// STATUS: DIAMANT VGT SUPREME
class PortSentinelActivity : Activity() {
    private lateinit var runtime: AppRuntime
    private lateinit var rootLayout: LinearLayout
    private lateinit var radar: ScannerRadarView
    private lateinit var statusBadge: TextView
    private lateinit var statusBody: TextView
    private lateinit var listenerText: TextView
    private lateinit var integrityText: TextView
    private lateinit var hitsHost: LinearLayout
    private lateinit var recoveryButton: TextView
    private var lastSnapshot: PortSentinelSnapshot? = null
    private val listener: () -> Unit = { runOnUiThread(::refresh) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runtime = RuntimeActivityEntry.requireReady(this) ?: return
        VgtWindowInsets.configureSystemBars(window)
        setContentView(buildUi())
        refresh()
    }

    override fun onStart() { super.onStart(); runtime.addStateListener(listener); refresh() }
    override fun onStop() { runtime.removeStateListener(listener); super.onStop() }

    private fun buildUi(): View {
        val root = FrameLayout(this).apply { setBackgroundColor(GeDefenseUi.bg) }
        val scroll = ScrollView(this).apply { clipToPadding = false; overScrollMode = View.OVER_SCROLL_NEVER }
        VgtUiPerformance.bindScroll(scroll)
        rootLayout = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(24), dp(18), dp(24), dp(44)) }
        scroll.addView(rootLayout, FrameLayout.LayoutParams(-1, -2)); root.addView(scroll, FrameLayout.LayoutParams(-1, -1))
        rootLayout.addView(VgtUiComponents.screenHeader(this, getString(R.string.port_sentinel_title), getString(R.string.port_sentinel_subtitle)))
        gap(14)

        radar = ScannerRadarView(this).apply { setRunning(false, GeDefenseUi.cyan) }
        statusBadge = GeDefenseUi.pill(this, getString(R.string.port_sentinel_standby), GeDefenseUi.gold)
        statusBody = GeDefenseUi.textView(this, getString(R.string.port_sentinel_standby_body), 9.6f, GeDefenseUi.textMuted)
        listenerText = GeDefenseUi.monoTextView(this, getString(R.string.port_sentinel_ports), 8.6f, GeDefenseUi.textDim)
        val statusCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER_HORIZONTAL
            background = GeDefenseUi.glassPanelBackground(this@PortSentinelActivity, accent = GeDefenseUi.cyan, radius = 18)
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(radar, LinearLayout.LayoutParams(dp(190), dp(190)))
            addView(statusBadge, LinearLayout.LayoutParams(-2, -2).apply { topMargin = dp(4) })
            addView(statusBody, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })
            addView(listenerText, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
        }
        rootLayout.addView(statusCard)

        gap(14)
        integrityText = GeDefenseUi.textView(this, "", 9.2f, GeDefenseUi.textMuted)
        recoveryButton = GeDefenseUi.actionButton(this, getString(R.string.port_sentinel_reset_store), goldStyle = true) { confirmResetStore() }
        rootLayout.addView(sectionCard(getString(R.string.port_sentinel_limit_title), VgtIcon.SHIELD, GeDefenseUi.gold, listOf(
            GeDefenseUi.textView(this, getString(R.string.port_sentinel_limit_body), 9f, GeDefenseUi.textMuted),
            integrityText,
            recoveryButton,
        )))

        gap(14)
        rootLayout.addView(GeDefenseUi.actionButton(this, getString(R.string.port_sentinel_reset_history)) { confirmResetHistory() })
        gap(18)
        rootLayout.addView(GeDefenseUi.sectionTitle(this, getString(R.string.port_sentinel_recent_title)))
        gap(10)
        hitsHost = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        rootLayout.addView(hitsHost)

        root.setOnApplyWindowInsetsListener { _, insets ->
            val safe = VgtWindowInsets.safeArea(insets)
            rootLayout.setPadding(dp(24)+safe.left, dp(18)+safe.top, dp(24)+safe.right, dp(44)+safe.bottom); insets
        }
        root.post { root.requestApplyInsets() }
        return root
    }

    private fun refresh() {
        if (!::statusBadge.isInitialized) return
        val snapshot = runtime.portSentinelSnapshot()
        if (snapshot == lastSnapshot) return
        lastSnapshot = snapshot
        val state = snapshot.runtime
        val accent = when { !snapshot.integrityOk -> GeDefenseUi.red; state.active -> GeDefenseUi.cyan; state.lastError != null -> GeDefenseUi.orange; else -> GeDefenseUi.gold }
        radar.setRunning(state.active, accent)
        statusBadge.text = getString(when { !snapshot.integrityOk || state.lastError != null -> R.string.port_sentinel_degraded; state.active -> R.string.port_sentinel_active; else -> R.string.port_sentinel_standby })
        statusBadge.background = GeDefenseUi.badgeBackground(this, accent)
        statusBadge.setTextColor(accent)
        statusBody.text = getString(when { !snapshot.integrityOk || state.lastError != null -> R.string.port_sentinel_degraded_body; state.active -> R.string.port_sentinel_active_body; else -> R.string.port_sentinel_standby_body })
        listenerText.text = buildString {
            append(getString(R.string.port_sentinel_listener_summary, state.listenerCount, state.transport))
            if (state.localAddresses.isNotEmpty()) append("\n").append(state.localAddresses.joinToString(" · "))
            append("\n").append(getString(R.string.port_sentinel_ports))
            append("\n").append(getString(R.string.port_sentinel_hit_count, snapshot.hits.size, snapshot.uniqueSources, snapshot.criticalHits))
        }
        integrityText.text = if (snapshot.integrityOk) getString(R.string.port_sentinel_integrity_ok) else getString(R.string.port_sentinel_integrity_failed, snapshot.integrityFailureReason ?: "unknown")
        integrityText.setTextColor(if (snapshot.integrityOk) GeDefenseUi.green else GeDefenseUi.red)
        recoveryButton.visibility = if (snapshot.integrityOk) View.GONE else View.VISIBLE

        hitsHost.removeAllViews()
        if (snapshot.hits.isEmpty()) hitsHost.addView(GeDefenseUi.textView(this, getString(R.string.port_sentinel_no_hits), 9.8f, GeDefenseUi.textDim))
        else snapshot.hits.take(80).forEachIndexed { index, hit ->
            if (index > 0) hitsHost.addView(View(this).apply { layoutParams = LinearLayout.LayoutParams(1, dp(8)) })
            hitsHost.addView(hitCard(hit, snapshot.blockedSources))
        }
    }

    private fun hitCard(hit: PortSentinelHit, blocked: Set<String>): View {
        val accent = when (hit.severity) { XdrSeverity.CRITICAL -> GeDefenseUi.red; XdrSeverity.HIGH -> GeDefenseUi.orange; XdrSeverity.MEDIUM -> GeDefenseUi.gold; else -> GeDefenseUi.cyan }
        val denied = hit.sourceAddress in blocked
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = GeDefenseUi.glassPanelBackground(this@PortSentinelActivity, accent = accent, radius = 15)
            setPadding(dp(17), dp(15), dp(17), dp(15))
            addView(LinearLayout(this@PortSentinelActivity).apply {
                orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(this@PortSentinelActivity, VgtIcon.ALERT, accent, 28), LinearLayout.LayoutParams(dp(28), dp(28)))
                addView(LinearLayout(this@PortSentinelActivity).apply {
                    orientation = LinearLayout.VERTICAL; setPadding(dp(10), 0, dp(8), 0)
                    addView(GeDefenseUi.textView(this@PortSentinelActivity, hit.eventCode.replace('_',' '), 10f, GeDefenseUi.text, bold = true))
                    addView(GeDefenseUi.monoTextView(this@PortSentinelActivity, getString(R.string.port_sentinel_source, hit.sourceAddress, hit.sourcePort), 8.7f, GeDefenseUi.textDim))
                }, LinearLayout.LayoutParams(0, -2, 1f))
                if (denied) addView(GeDefenseUi.pill(this@PortSentinelActivity, getString(R.string.port_sentinel_blocked), GeDefenseUi.red))
            })
            addView(GeDefenseUi.monoTextView(this@PortSentinelActivity, getString(R.string.port_sentinel_target, hit.protocol.name, hit.targetPort), 8.8f, GeDefenseUi.textMuted).apply { setPadding(0, dp(7), 0, 0) })
            addView(GeDefenseUi.textView(this@PortSentinelActivity, "${zoneLabel(hit.sourceZone)} · ${GeDefenseUi.formatTime(this@PortSentinelActivity, hit.atMillis)}", 8.5f, GeDefenseUi.textDim).apply { setPadding(0, dp(4), 0, 0) })
            addView(GeDefenseUi.actionButton(this@PortSentinelActivity, getString(if (denied) R.string.port_sentinel_unblock else R.string.port_sentinel_block), goldStyle = !denied) {
                runtime.setSentinelSourceBlockedAsync(hit.sourceAddress, !denied) { ok ->
                    runOnUiThread {
                        if (isFinishing || isDestroyed) return@runOnUiThread
                        if (!ok) {
                            Toast.makeText(this@PortSentinelActivity, getString(R.string.port_sentinel_block_failed), Toast.LENGTH_LONG).show()
                        } else if (!refreshActiveSelectiveOrFailClosed()) {
                            Toast.makeText(this@PortSentinelActivity, R.string.live_policy_refresh_failed_stopped, Toast.LENGTH_LONG).show()
                        }
                        refresh()
                    }
                }
            }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(9) })
        }
    }

    private fun refreshActiveSelectiveOrFailClosed(): Boolean {
        if (!runtime.state.isVpnActive() || runtime.state.protectionMode() != ProtectionMode.SELECTIVE) return true
        return try {
            startService(android.content.Intent(this, GeDefenseVpnService::class.java).setAction(GeDefenseVpnService.ACTION_REFRESH))
            true
        } catch (_: RuntimeException) {
            // A new deny route must not silently coexist with an older, more permissive live tunnel.
            try { stopService(android.content.Intent(this, GeDefenseVpnService::class.java)) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("port-sentinel-activity", error) }
            false
        }
    }

    private fun zoneLabel(zone: String): String = getString(when (zone) {
        "LOCAL_LAN" -> R.string.port_sentinel_zone_lan
        "MOBILE_CARRIER" -> R.string.port_sentinel_zone_carrier
        "MOBILE_INTERNET" -> R.string.port_sentinel_zone_mobile
        "PUBLIC_INTERNET" -> R.string.port_sentinel_zone_public
        else -> R.string.port_sentinel_zone_unknown
    })

    private fun confirmResetHistory() = AlertDialog.Builder(this).setTitle(R.string.port_sentinel_reset_title).setMessage(R.string.port_sentinel_reset_body)
        .setNegativeButton(android.R.string.cancel, null).setPositiveButton(R.string.port_sentinel_confirm) { _, _ ->
            runtime.resetSentinelHistoryAsync { runOnUiThread { if (!isFinishing && !isDestroyed) refresh() } }
        }.show()

    private fun confirmResetStore() = AlertDialog.Builder(this).setTitle(R.string.port_sentinel_reset_store_title).setMessage(R.string.port_sentinel_reset_store_body)
        .setNegativeButton(android.R.string.cancel, null).setPositiveButton(R.string.port_sentinel_confirm) { _, _ ->
            runtime.resetSentinelStoreAsync { runOnUiThread { if (!isFinishing && !isDestroyed) refresh() } }
        }.show()

    private fun sectionCard(title: String, icon: VgtIcon, accent: Int, views: List<View>): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = GeDefenseUi.glassPanelBackground(this@PortSentinelActivity, accent = accent, radius = 16)
        setPadding(dp(18), dp(16), dp(18), dp(16))
        addView(LinearLayout(this@PortSentinelActivity).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; addView(VgtUiComponents.iconWell(this@PortSentinelActivity, icon, accent, 28)); addView(GeDefenseUi.textView(this@PortSentinelActivity, title, 10.5f, GeDefenseUi.text, bold = true), LinearLayout.LayoutParams(0, -2, 1f).apply { marginStart = dp(10) }) })
        views.forEachIndexed { index, view -> addView(view, LinearLayout.LayoutParams(-1, -2).apply { topMargin = if (index == 0) dp(10) else dp(8) }) }
    }

    private fun gap(px: Int) = rootLayout.addView(View(this).apply { layoutParams = LinearLayout.LayoutParams(1, dp(px)) })
    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()
}
