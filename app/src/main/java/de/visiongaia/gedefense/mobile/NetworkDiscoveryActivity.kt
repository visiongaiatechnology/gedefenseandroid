package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.app.AlertDialog
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

class NetworkDiscoveryActivity : Activity() {
    private lateinit var runtime: AppRuntime
    private lateinit var rootLayout: LinearLayout
    private lateinit var statusText: TextView
    private lateinit var statusBadge: TextView
    private lateinit var scanButton: TextView
    private lateinit var networkMeta: TextView
    private lateinit var baselineText: TextView
    private lateinit var resetBaselineButton: TextView
    private lateinit var devicesHost: LinearLayout
    private var lastRenderedSnapshot: NetworkDiscoverySnapshot? = null
    private var lastRenderedRunning = false
    private val listener: () -> Unit = { runOnUiThread(::refresh) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runtime = RuntimeActivityEntry.requireReady(this) ?: return
        configureSystemBars()
        setContentView(buildUi())
        refresh()
    }

    override fun onStart() {
        super.onStart()
        runtime.addStateListener(listener)
        refresh()
    }

    override fun onStop() {
        runtime.removeStateListener(listener)
        super.onStop()
    }

    private fun buildUi(): View {
        val root = FrameLayout(this).apply { setBackgroundColor(GeDefenseUi.bg) }
        val scroll = ScrollView(this).apply { clipToPadding = false; overScrollMode = View.OVER_SCROLL_NEVER }
        VgtUiPerformance.bindScroll(scroll)
        rootLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(18), dp(24), dp(44))
        }
        scroll.addView(rootLayout, FrameLayout.LayoutParams(-1, -2))
        root.addView(scroll, FrameLayout.LayoutParams(-1, -1))

        rootLayout.addView(VgtUiComponents.screenHeader(this, getString(R.string.network_discovery_title), getString(R.string.network_discovery_subtitle)))
        gap(16)

        statusText = GeDefenseUi.textView(this, getString(R.string.network_discovery_idle), 10.5f, GeDefenseUi.textMuted).apply {
            setLineSpacing(dp(2).toFloat(), 1f)
        }
        statusBadge = GeDefenseUi.pill(this, getString(R.string.network_discovery_ready), GeDefenseUi.cyan)
        scanButton = GeDefenseUi.actionButton(this, getString(R.string.network_discovery_scan), goldStyle = true) {
            if (runtime.isNetworkDiscoveryRunning()) runtime.cancelNetworkDiscovery() else startScan()
        }
        rootLayout.addView(sectionCard(VgtIcon.ROUTES, GeDefenseUi.cyan, getString(R.string.network_discovery_status_title), statusBadge, arrayOf(statusText, scanButton)))

        gap(14)
        networkMeta = GeDefenseUi.monoTextView(this, getString(R.string.network_discovery_no_network), 9f, GeDefenseUi.textDim).apply {
            setLineSpacing(dp(2).toFloat(), 1f)
        }
        rootLayout.addView(sectionCard(VgtIcon.TRAFFIC, GeDefenseUi.blue, getString(R.string.network_discovery_network_title), null, arrayOf(networkMeta)))

        gap(14)
        baselineText = GeDefenseUi.textView(this, getString(R.string.network_discovery_baseline_ok), 9.5f, GeDefenseUi.textMuted)
        resetBaselineButton = GeDefenseUi.actionButton(this, getString(R.string.network_discovery_reset_baseline)) { confirmResetBaseline() }
        rootLayout.addView(sectionCard(VgtIcon.INTEGRITY, GeDefenseUi.green, getString(R.string.network_discovery_baseline_title), null, arrayOf(baselineText, resetBaselineButton)))

        gap(18)
        rootLayout.addView(GeDefenseUi.sectionTitle(this, getString(R.string.network_discovery_devices_title)))
        gap(10)
        devicesHost = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        rootLayout.addView(devicesHost)

        gap(16)
        rootLayout.addView(GeDefenseUi.textView(this, getString(R.string.network_discovery_privacy_note), 8.8f, GeDefenseUi.textDim).apply {
            setLineSpacing(dp(2).toFloat(), 1f)
        })

        root.setOnApplyWindowInsetsListener { _, insets ->
            val safe = VgtWindowInsets.safeArea(insets)
            rootLayout.setPadding(dp(24) + safe.left, dp(18) + safe.top, dp(24) + safe.right, dp(44) + safe.bottom)
            insets
        }
        root.post { root.requestApplyInsets() }
        return root
    }

    private fun startScan() {
        scanButton.isEnabled = true
        runtime.startNetworkDiscoveryAsync { result ->
            runOnUiThread {
                if (result.state == "UNAVAILABLE") Toast.makeText(this, getString(R.string.network_discovery_unavailable), Toast.LENGTH_LONG).show()
                else if (result.state == "FAILED") Toast.makeText(this, getString(R.string.network_discovery_failed), Toast.LENGTH_LONG).show()
                refresh()
            }
        }
    }

    private fun refresh() {
        if (!::statusText.isInitialized) return
        val snapshot = runtime.networkDiscoverySnapshot.get()
        val running = runtime.isNetworkDiscoveryRunning()
        if (snapshot == lastRenderedSnapshot && running == lastRenderedRunning) return
        lastRenderedSnapshot = snapshot
        lastRenderedRunning = running
        scanButton.text = getString(if (running) R.string.network_discovery_cancel else R.string.network_discovery_scan)
        scanButton.background = if (running) GeDefenseUi.destructiveButtonBackground(this) else GeDefenseUi.goldButtonBackground(this)
        scanButton.setTextColor(if (running) GeDefenseUi.text else Color.rgb(18, 19, 20))
        resetBaselineButton.isEnabled = !running
        resetBaselineButton.alpha = if (running) 0.45f else 1f

        val accent = when (snapshot.state) {
            "COMPLETE" -> if (snapshot.elevatedDevices > 0) GeDefenseUi.orange else GeDefenseUi.green
            "SCANNING" -> GeDefenseUi.cyan
            "FAILED", "UNAVAILABLE" -> GeDefenseUi.orange
            "CANCELLED" -> GeDefenseUi.gold
            else -> GeDefenseUi.cyan
        }
        stylePill(statusBadge, when (snapshot.state) {
            "COMPLETE" -> getString(R.string.network_discovery_complete)
            "SCANNING" -> getString(R.string.network_discovery_scanning)
            "FAILED" -> getString(R.string.ui_attention)
            "UNAVAILABLE" -> getString(R.string.network_discovery_unavailable_short)
            "CANCELLED" -> getString(R.string.network_discovery_cancelled)
            else -> getString(R.string.network_discovery_ready)
        }, accent)

        statusText.text = when (snapshot.state) {
            "SCANNING" -> getString(R.string.network_discovery_progress, snapshot.scannedHosts, snapshot.totalHosts)
            "COMPLETE" -> getString(
                R.string.network_discovery_summary,
                snapshot.devices.size,
                snapshot.newDevices,
                snapshot.elevatedDevices,
                snapshot.scannedHosts,
            )
            "UNAVAILABLE" -> getString(R.string.network_discovery_unavailable)
            "FAILED" -> getString(R.string.network_discovery_error, snapshot.errorReason ?: "unknown")
            "CANCELLED" -> getString(R.string.network_discovery_cancelled_body)
            else -> getString(R.string.network_discovery_idle)
        }

        networkMeta.text = if (snapshot.localAddress.isBlank()) getString(R.string.network_discovery_no_network) else buildString {
            append(snapshot.transport).append(" · ").append(snapshot.interfaceName.ifBlank { "interface" }).append('\n')
            append("IP ").append(snapshot.localAddress).append('/').append(snapshot.prefixLength)
            append(" · scan /").append(snapshot.effectivePrefixLength).append('\n')
            append("Gateway ").append(snapshot.gatewayAddress ?: "unknown")
            if (snapshot.scopeClamped) append('\n').append(getString(R.string.network_discovery_scope_clamped))
            if (snapshot.networkId.isNotBlank()) append('\n').append("Network ID ").append(snapshot.networkId.take(16))
        }

        baselineText.text = if (snapshot.baselineIntegrityOk && runtime.networkDiscoveryStore.integrityOk()) {
            buildString {
                append(getString(R.string.network_discovery_baseline_ok))
                if (snapshot.networkBaselineObservations > 0) {
                    append('\n').append(getString(
                        R.string.network_discovery_behavior_summary,
                        snapshot.networkBaselineObservations,
                        snapshot.historicalDeviceCount,
                        snapshot.historicalElevatedCount,
                    ))
                }
                if (snapshot.networkBehaviorSignals.isNotEmpty()) {
                    append('\n').append(getString(
                        R.string.network_discovery_network_behavior_alert,
                        snapshot.networkBehaviorSignals.sorted().joinToString(", "),
                    ))
                }
            }
        } else {
            getString(R.string.network_discovery_baseline_bad, snapshot.baselineFailureReason ?: runtime.networkDiscoveryStore.integrityFailureReason() ?: "unknown")
        }
        baselineText.setTextColor(if (snapshot.baselineIntegrityOk && runtime.networkDiscoveryStore.integrityOk()) GeDefenseUi.green else GeDefenseUi.red)

        devicesHost.removeAllViews()
        if (snapshot.devices.isEmpty()) {
            devicesHost.addView(GeDefenseUi.textView(this, getString(if (snapshot.state == "COMPLETE") R.string.network_discovery_no_devices else R.string.network_discovery_waiting), 10f, GeDefenseUi.textDim))
        } else {
            snapshot.devices.forEachIndexed { index, device ->
                if (index > 0) addGap(devicesHost, 8)
                devicesHost.addView(deviceCard(device))
            }
        }
    }

    private fun deviceCard(device: NetworkDevice): View {
        val accent = riskColor(device.risk)
        val title = when {
            device.isGateway -> getString(R.string.network_discovery_gateway)
            device.role == "ANDROID_DEBUG" -> getString(R.string.network_discovery_android_debug)
            device.role == "PRINTER" -> getString(R.string.network_discovery_printer)
            device.role == "CAST_MEDIA" -> getString(R.string.network_discovery_media_device)
            device.role == "CAMERA_MEDIA" -> getString(R.string.network_discovery_camera)
            device.role == "NAS_FILE_SERVER" -> getString(R.string.network_discovery_file_server)
            device.role == "REMOTE_DESKTOP" -> getString(R.string.network_discovery_remote_host)
            device.role == "SMART_HOME" -> getString(R.string.network_discovery_smart_home)
            device.role == "WORKSTATION_SERVER" -> getString(R.string.network_discovery_workstation)
            else -> getString(R.string.network_discovery_device)
        }
        val services = if (device.openServices.isEmpty()) getString(R.string.network_discovery_no_open_services) else
            device.openServices.joinToString(" · ") { "${it.name}/${it.port}" }
        val advertised = device.advertisedServices.joinToString(" · ") { service ->
            val shortType = service.serviceType.removeSuffix(".local")
            if (service.port != null) "$shortType/${service.port}" else shortType
        }
        return FrameLayout(this).apply {
            background = GeDefenseUi.glassPanelBackground(this@NetworkDiscoveryActivity, accent = accent, radius = 16)
            addView(LinearLayout(this@NetworkDiscoveryActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(15), dp(13), dp(15), dp(13))
                addView(LinearLayout(this@NetworkDiscoveryActivity).apply {
                    orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                    addView(VgtUiComponents.iconWell(this@NetworkDiscoveryActivity, deviceIcon(device), accent, 30), LinearLayout.LayoutParams(dp(30), dp(30)))
                    addView(LinearLayout(this@NetworkDiscoveryActivity).apply {
                        orientation = LinearLayout.VERTICAL; setPadding(dp(10), 0, dp(8), 0)
                        addView(GeDefenseUi.textView(this@NetworkDiscoveryActivity, title, 10.8f, GeDefenseUi.text, bold = true))
                        addView(GeDefenseUi.monoTextView(this@NetworkDiscoveryActivity, device.ipAddress, 9f, GeDefenseUi.textDim).apply { setPadding(0, dp(2), 0, 0) })
                    }, LinearLayout.LayoutParams(0, -2, 1f))
                    addView(GeDefenseUi.pill(this@NetworkDiscoveryActivity, riskLabel(device.risk), accent))
                })
                if (device.newToBaseline) addView(GeDefenseUi.textView(this@NetworkDiscoveryActivity, getString(R.string.network_discovery_new_device), 9f, GeDefenseUi.gold, bold = true).apply { setPadding(0, dp(8), 0, 0) })
                device.macAddress?.let { addView(GeDefenseUi.monoTextView(this@NetworkDiscoveryActivity, "MAC $it", 8.6f, GeDefenseUi.textDim).apply { setPadding(0, dp(6), 0, 0) }) }
                device.hostname?.let { addView(GeDefenseUi.monoTextView(this@NetworkDiscoveryActivity, getString(R.string.network_discovery_hostname, it), 8.6f, GeDefenseUi.textDim).apply { setPadding(0, dp(4), 0, 0) }) }
                addView(GeDefenseUi.monoTextView(this@NetworkDiscoveryActivity, getString(R.string.network_discovery_identity_source, device.identitySource.name), 8.2f, GeDefenseUi.textDim).apply { setPadding(0, dp(4), 0, 0) })
                val behaviorColor = when (device.behaviorState) {
                    NetworkBehaviorState.ANOMALOUS -> GeDefenseUi.orange
                    NetworkBehaviorState.NORMAL -> GeDefenseUi.green
                    NetworkBehaviorState.LEARNING -> GeDefenseUi.cyan
                }
                val behaviorLabel = when (device.behaviorState) {
                    NetworkBehaviorState.ANOMALOUS -> getString(R.string.network_discovery_behavior_anomalous)
                    NetworkBehaviorState.NORMAL -> getString(R.string.network_discovery_behavior_normal)
                    NetworkBehaviorState.LEARNING -> getString(R.string.network_discovery_behavior_learning)
                }
                addView(GeDefenseUi.textView(
                    this@NetworkDiscoveryActivity,
                    getString(R.string.network_discovery_behavior_detail, behaviorLabel, device.baselineObservations, device.historicalRiskScore),
                    8.4f,
                    behaviorColor,
                    bold = device.behaviorState == NetworkBehaviorState.ANOMALOUS,
                ).apply { setPadding(0, dp(5), 0, 0) })
                if (device.behaviorSignals.isNotEmpty()) addView(GeDefenseUi.textView(
                    this@NetworkDiscoveryActivity,
                    device.behaviorSignals.sorted().joinToString(" · "),
                    8.4f,
                    GeDefenseUi.orange,
                    bold = true,
                ).apply { setPadding(0, dp(4), 0, 0) })
                addView(GeDefenseUi.textView(this@NetworkDiscoveryActivity, services, 9.2f, GeDefenseUi.textMuted).apply {
                    setPadding(0, dp(7), 0, 0); setLineSpacing(dp(2).toFloat(), 1f)
                })
                if (advertised.isNotBlank()) addView(GeDefenseUi.textView(
                    this@NetworkDiscoveryActivity,
                    getString(R.string.network_discovery_advertised_services, advertised),
                    8.8f,
                    GeDefenseUi.cyan,
                ).apply { setPadding(0, dp(6), 0, 0); setLineSpacing(dp(2).toFloat(), 1f) })
                if (device.newlyExposedPorts.isNotEmpty()) addView(GeDefenseUi.textView(
                    this@NetworkDiscoveryActivity,
                    getString(R.string.network_discovery_new_ports, device.newlyExposedPorts.sorted().joinToString(", ")),
                    8.8f,
                    if (device.risk == NetworkDeviceRisk.CRITICAL || device.risk == NetworkDeviceRisk.HIGH) GeDefenseUi.orange else GeDefenseUi.gold,
                    bold = true,
                ).apply { setPadding(0, dp(6), 0, 0) })
                if (device.newlyAdvertisedServiceTypes.isNotEmpty()) addView(GeDefenseUi.textView(
                    this@NetworkDiscoveryActivity,
                    getString(R.string.network_discovery_new_advertised_services, device.newlyAdvertisedServiceTypes.sorted().joinToString(", ")),
                    8.8f,
                    GeDefenseUi.gold,
                    bold = true,
                ).apply { setPadding(0, dp(6), 0, 0) })
                if (device.changedBaselineAttributes.isNotEmpty()) addView(GeDefenseUi.textView(
                    this@NetworkDiscoveryActivity,
                    getString(R.string.network_discovery_identity_drift, device.changedBaselineAttributes.sorted().joinToString(", ")),
                    8.8f,
                    GeDefenseUi.orange,
                    bold = true,
                ).apply { setPadding(0, dp(6), 0, 0) })
            }, FrameLayout.LayoutParams(-1, -2))
        }
    }

    private fun confirmResetBaseline() {
        AlertDialog.Builder(this)
            .setTitle(R.string.network_discovery_reset_title)
            .setMessage(R.string.network_discovery_reset_body)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.network_discovery_reset_action) { _, _ ->
                runtime.resetNetworkDiscoveryBaselineAsync { ok ->
                    runOnUiThread {
                        if (isFinishing || isDestroyed) return@runOnUiThread
                        Toast.makeText(this, getString(if (ok) R.string.network_discovery_reset_done else R.string.network_discovery_reset_failed), Toast.LENGTH_LONG).show()
                        refresh()
                    }
                }
            }.show()
    }

    private fun deviceIcon(device: NetworkDevice): VgtIcon = when (device.role) {
        "ROUTER_GATEWAY" -> VgtIcon.ROUTES
        "PRINTER" -> VgtIcon.EVIDENCE
        "NAS_FILE_SERVER" -> VgtIcon.CLOUD
        "ANDROID_DEBUG" -> VgtIcon.ALERT
        "REMOTE_DESKTOP" -> VgtIcon.ACTIVITY
        "CAMERA_MEDIA", "CAST_MEDIA" -> VgtIcon.TRAFFIC
        else -> VgtIcon.COUNTRY
    }

    private fun riskColor(risk: NetworkDeviceRisk): Int = when (risk) {
        NetworkDeviceRisk.CRITICAL -> GeDefenseUi.red
        NetworkDeviceRisk.HIGH -> GeDefenseUi.orange
        NetworkDeviceRisk.REVIEW -> GeDefenseUi.gold
        NetworkDeviceRisk.INFO -> GeDefenseUi.cyan
    }

    private fun riskLabel(risk: NetworkDeviceRisk): String = when (risk) {
        NetworkDeviceRisk.CRITICAL -> getString(R.string.network_discovery_risk_critical)
        NetworkDeviceRisk.HIGH -> getString(R.string.network_discovery_risk_high)
        NetworkDeviceRisk.REVIEW -> getString(R.string.network_discovery_risk_review)
        NetworkDeviceRisk.INFO -> getString(R.string.network_discovery_risk_info)
    }

    private fun sectionCard(icon: VgtIcon, accent: Int, title: String, badge: TextView?, content: Array<View>): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@NetworkDiscoveryActivity, accent = accent, radius = 18)
        addView(LinearLayout(this@NetworkDiscoveryActivity).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(18), dp(16), dp(18), dp(16))
            addView(LinearLayout(this@NetworkDiscoveryActivity).apply {
                orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(this@NetworkDiscoveryActivity, icon, accent, 32), LinearLayout.LayoutParams(dp(32), dp(32)))
                addView(GeDefenseUi.sectionTitle(this@NetworkDiscoveryActivity, title), LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(12) })
                if (badge != null) addView(badge)
            })
            content.forEach { child -> addView(child, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) }) }
        }, FrameLayout.LayoutParams(-1, -2))
    }

    private fun stylePill(view: TextView, text: String, color: Int) {
        view.text = text
        view.setTextColor(color)
        view.background = GeDefenseUi.badgeBackground(this, color)
    }

    private fun addGap(host: LinearLayout, value: Int) = host.addView(View(this), LinearLayout.LayoutParams(1, dp(value)))
    private fun gap(value: Int) = GeDefenseUi.addVerticalGap(rootLayout, this, value)
    private fun dp(value: Int) = GeDefenseUi.dp(this, value)

    private fun configureSystemBars() = VgtWindowInsets.configureSystemBars(window)
}
