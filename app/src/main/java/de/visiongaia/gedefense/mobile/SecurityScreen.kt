package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.graphics.Color
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.util.Locale

class SecurityScreen(
    private val activity: Activity,
    private val actions: UiActions,
) {
    val view: View
    private val rootLayout: LinearLayout
    private val integrityStatus: TextView
    private val integrityBadge: TextView
    private val integrityIssues: LinearLayout
    private val hardeningStatus: TextView
    private val hardeningBadge: TextView
    private val hardeningResults: LinearLayout
    private val appScanStatus: TextView
    private val appScanBadge: TextView
    private val appResults: LinearLayout
    private val trafficStatus: TextView
    private val trafficResults: LinearLayout
    private val usageButton: TextView
    private val liveTrafficStatus: TextView
    private val liveTrafficBadge: TextView
    private val liveTrafficResults: LinearLayout
    private val mapStatus: TextView
    private val mapBadge: TextView
    private val trafficMap: TrafficWorldMapView
    private val mapScope: TextView
    private val mapLegend: LinearLayout
    private val mapLocationButton: TextView
    private val countryStatus: TextView
    private val countryBadge: TextView
    private val countryResults: LinearLayout

    private data class AppScanRenderKey(val app: AppScanSnapshot, val deep: DeviceScanSnapshot)
    private data class FullFlowRenderKey(
        val mode: ProtectionMode,
        val vpnStatus: String,
        val flow: FullFlowAnalyticsSnapshot,
        val geo: GeoCountryState,
    )
    private data class MapRenderKey(
        val mode: ProtectionMode,
        val flow: FullFlowAnalyticsSnapshot,
        val origin: OriginLocationSnapshot,
    )
    private data class TrafficRenderKey(val traffic: TrafficUsageSnapshot, val access: Boolean)

    private var lastIntegrity: IntegritySnapshot? = null
    private var lastHardening: HardeningSnapshot? = null
    private var lastAppScan: AppScanRenderKey? = null
    private var lastFullFlow: FullFlowRenderKey? = null
    private var lastMap: MapRenderKey? = null
    private var lastTraffic: TrafficRenderKey? = null

    init {
        val scroll = ScrollView(activity).apply { clipToPadding = false; overScrollMode = View.OVER_SCROLL_NEVER }
        VgtUiPerformance.bindScroll(scroll)
        rootLayout = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                GeDefenseUi.screenHorizontalPadding(activity),
                dp(16),
                GeDefenseUi.screenHorizontalPadding(activity),
                GeDefenseUi.scrollReservedBottomPadding(activity),
            )
        }
        val root = rootLayout
        scroll.addView(root, FrameLayout.LayoutParams(-1, -2))
        root.addView(VgtUiComponents.screenHeader(activity, activity.getString(R.string.security_center_title), activity.getString(R.string.security_center_subtitle)))
        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)

        integrityStatus = GeDefenseUi.textView(activity, "", 11.5f, GeDefenseUi.textMuted)
        integrityBadge = GeDefenseUi.pill(activity, activity.getString(R.string.ui_waiting), GeDefenseUi.orange)
        integrityIssues = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
        root.addView(sectionCard(
            icon = VgtIcon.INTEGRITY,
            accent = GeDefenseUi.green,
            title = activity.getString(R.string.integrity_guard_title),
            badge = integrityBadge,
            subtitle = integrityStatus,
            integrityIssues,
            GeDefenseUi.actionButton(activity, activity.getString(R.string.integrity_run), goldStyle = true) { actions.verifyIntegrity() },
        ))

        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)
        hardeningStatus = GeDefenseUi.textView(activity, "", 11.5f, GeDefenseUi.textMuted)
        hardeningBadge = GeDefenseUi.pill(activity, activity.getString(R.string.ui_waiting), GeDefenseUi.gold)
        hardeningResults = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
        root.addView(sectionCard(
            icon = VgtIcon.SHIELD,
            accent = GeDefenseUi.gold,
            title = activity.getString(R.string.hardening_posture_title),
            badge = hardeningBadge,
            subtitle = hardeningStatus,
            hardeningResults,
            GeDefenseUi.actionButton(activity, activity.getString(R.string.hardening_open)) { actions.openHardeningCenter() },
        ))

        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)
        appScanStatus = GeDefenseUi.textView(activity, "", 11.5f, GeDefenseUi.textMuted)
        appScanBadge = GeDefenseUi.pill(activity, activity.getString(R.string.ui_waiting), GeDefenseUi.orange)
        appResults = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
        root.addView(sectionCard(
            icon = VgtIcon.SCANNER,
            accent = GeDefenseUi.gold,
            title = activity.getString(R.string.app_scanner_title),
            badge = appScanBadge,
            subtitle = appScanStatus,
            appResults,
            GeDefenseUi.actionButton(activity, activity.getString(R.string.scanner_open)) { actions.openMalwareScanner() },
        ))

        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)
        root.addView(sectionCard(
            icon = VgtIcon.ROUTES,
            accent = GeDefenseUi.cyan,
            title = activity.getString(R.string.network_discovery_title),
            badge = GeDefenseUi.pill(activity, activity.getString(R.string.network_discovery_ready), GeDefenseUi.cyan),
            subtitle = GeDefenseUi.textView(activity, activity.getString(R.string.network_discovery_more_body), 10.5f, GeDefenseUi.textMuted),
            GeDefenseUi.actionButton(activity, activity.getString(R.string.network_discovery_open)) { actions.openNetworkDiscovery() },
        ))

        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)
        root.addView(sectionCard(
            icon = VgtIcon.ALERT,
            accent = GeDefenseUi.orange,
            title = activity.getString(R.string.port_sentinel_title),
            badge = GeDefenseUi.pill(activity, activity.getString(R.string.port_sentinel_standby), GeDefenseUi.gold),
            subtitle = GeDefenseUi.textView(activity, activity.getString(R.string.port_sentinel_subtitle), 10.5f, GeDefenseUi.textMuted),
            GeDefenseUi.actionButton(activity, activity.getString(R.string.port_sentinel_open)) { actions.openPortSentinel() },
        ))

        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)
        liveTrafficStatus = GeDefenseUi.textView(activity, "", 11.5f, GeDefenseUi.textMuted)
        liveTrafficBadge = GeDefenseUi.pill(activity, activity.getString(R.string.ui_waiting), GeDefenseUi.cyan)
        liveTrafficResults = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
        root.addView(sectionCard(
            icon = VgtIcon.TRAFFIC,
            accent = GeDefenseUi.cyan,
            title = activity.getString(R.string.live_flow_title),
            badge = liveTrafficBadge,
            subtitle = liveTrafficStatus,
            liveTrafficResults,
        ))

        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)
        mapStatus = GeDefenseUi.textView(activity, "", 10.8f, GeDefenseUi.textMuted)
        mapBadge = GeDefenseUi.pill(activity, activity.getString(R.string.ui_waiting), GeDefenseUi.cyan)
        trafficMap = TrafficWorldMapView(activity)
        mapScope = GeDefenseUi.textView(activity, activity.getString(R.string.traffic_map_country_scope), 9.4f, GeDefenseUi.textDim)
        mapLegend = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
        mapLocationButton = GeDefenseUi.actionButton(activity, activity.getString(R.string.traffic_map_use_location)) { actions.requestTrafficMapLocation() }
        root.addView(sectionCard(
            icon = VgtIcon.MAP,
            accent = GeDefenseUi.cyan,
            title = activity.getString(R.string.traffic_map_title),
            badge = mapBadge,
            subtitle = mapStatus,
            trafficMap,
            mapScope,
            mapLegend,
            mapLocationButton,
        ))

        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)
        countryStatus = GeDefenseUi.textView(activity, "", 11f, GeDefenseUi.textMuted)
        countryBadge = GeDefenseUi.pill(activity, activity.getString(R.string.ui_waiting), GeDefenseUi.gold)
        countryResults = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
        root.addView(sectionCard(
            icon = VgtIcon.COUNTRY,
            accent = GeDefenseUi.gold,
            title = activity.getString(R.string.country_analytics_title),
            badge = countryBadge,
            subtitle = countryStatus,
            countryResults,
        ))

        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)
        trafficStatus = GeDefenseUi.textView(activity, "", 11.5f, GeDefenseUi.textMuted)
        trafficResults = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
        usageButton = GeDefenseUi.actionButton(activity, activity.getString(R.string.traffic_grant_usage)) { actions.openUsageAccessSettings() }
        root.addView(sectionCard(
            icon = VgtIcon.ACTIVITY,
            accent = GeDefenseUi.blue,
            title = activity.getString(R.string.traffic_insights_title),
            badge = null,
            subtitle = trafficStatus,
            trafficResults,
            GeDefenseUi.actionButton(activity, activity.getString(R.string.traffic_refresh)) { actions.refreshTrafficUsage() },
            usageButton,
        ))
        view = scroll
    }

    fun setBottomPadding(bottomPx: Int) {
        rootLayout.setPadding(rootLayout.paddingLeft, rootLayout.paddingTop, rootLayout.paddingRight, bottomPx)
    }

    fun update(snapshot: UiSnapshot) {
        if (lastIntegrity != snapshot.integrity) {
            lastIntegrity = snapshot.integrity
            updateIntegrity(snapshot.integrity)
        }
        if (lastHardening != snapshot.hardening) {
            lastHardening = snapshot.hardening
            updateHardening(snapshot.hardening)
        }
        val appKey = AppScanRenderKey(snapshot.appScan, snapshot.deviceScan)
        if (lastAppScan != appKey) {
            lastAppScan = appKey
            updateAppScan(snapshot.appScan, snapshot.deviceScan)
        }
        val flowKey = FullFlowRenderKey(snapshot.protectionMode, snapshot.vpnStatus, snapshot.fullFlow, snapshot.geoCountry)
        if (lastFullFlow != flowKey) {
            lastFullFlow = flowKey
            updateFullFlow(snapshot)
        }
        val mapKey = MapRenderKey(snapshot.protectionMode, snapshot.fullFlow, snapshot.originLocation)
        if (lastMap != mapKey) {
            lastMap = mapKey
            updateMap(snapshot)
        }
        val trafficKey = TrafficRenderKey(snapshot.traffic, snapshot.usageAccessGranted)
        if (lastTraffic != trafficKey) {
            lastTraffic = trafficKey
            updateTraffic(snapshot.traffic, snapshot.usageAccessGranted)
        }
    }

    private fun updateIntegrity(s: IntegritySnapshot) {
        val color = when (s.state) { "HEALTHY" -> GeDefenseUi.green; "COMPROMISED" -> GeDefenseUi.red; else -> GeDefenseUi.orange }
        val badge = when (s.state) { "HEALTHY" -> activity.getString(R.string.ui_verified); "COMPROMISED" -> activity.getString(R.string.ui_attention); else -> activity.getString(R.string.ui_waiting) }
        stylePill(integrityBadge, badge, color)
        integrityStatus.setTextColor(color)
        integrityStatus.text = when (s.state) {
            "HEALTHY" -> activity.getString(R.string.integrity_healthy, s.filesChecked, GeDefenseUi.formatTime(activity, s.checkedAtMillis))
            "COMPROMISED" -> activity.getString(R.string.integrity_compromised, s.issues.size)
            else -> activity.getString(R.string.integrity_pending)
        }
        integrityIssues.removeAllViews()
        if (s.state == "HEALTHY") {
            integrityIssues.addView(statusMatrix(
                activity.getString(R.string.ui_private_files), s.filesChecked.toString(),
                activity.getString(R.string.ui_signer), activity.getString(R.string.ui_valid),
                activity.getString(R.string.ui_baseline), activity.getString(R.string.ui_authenticated),
            ))
        }
        s.issues.take(4).forEach {
            gap(integrityIssues, 8)
            integrityIssues.addView(detailLine("${it.severity}: ${it.code}", if (it.severity == IntegritySeverity.CRITICAL) GeDefenseUi.red else GeDefenseUi.orange))
        }
        if (s.ok && s.installSha256.length >= 12) {
            gap(integrityIssues, 10)
            integrityIssues.addView(FrameLayout(activity).apply {
                background = GeDefenseUi.softPanelBackground(activity, 10, GeDefenseUi.panelSoft)
                val content = LinearLayout(activity).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER
                    setPadding(dp(14), dp(8), dp(14), dp(8))
                    addView(GeDefenseUi.monoTextView(
                        activity,
                        activity.getString(R.string.integrity_hash, s.installSha256.take(16)),
                        9.5f,
                        GeDefenseUi.textDim,
                    ).apply {
                        letterSpacing = 0.04f
                        gravity = Gravity.CENTER
                    })
                }
                addView(content, FrameLayout.LayoutParams(-1, -2, Gravity.CENTER))
            })
        }
    }

    private fun updateHardening(s: HardeningSnapshot) {
        if (s.checkedAtMillis == 0L) {
            stylePill(hardeningBadge, activity.getString(R.string.ui_waiting), GeDefenseUi.gold)
            hardeningStatus.text = activity.getString(R.string.hardening_pending)
            hardeningResults.removeAllViews()
            return
        }
        val color = when {
            s.score >= 90 -> GeDefenseUi.green
            s.score >= 75 -> GeDefenseUi.cyan
            s.score >= 55 -> GeDefenseUi.gold
            s.score >= 35 -> GeDefenseUi.orange
            else -> GeDefenseUi.red
        }
        val badge = when {
            s.score >= 90 -> activity.getString(R.string.hardening_strong)
            s.score >= 75 -> activity.getString(R.string.hardening_good)
            s.score >= 55 -> activity.getString(R.string.ui_review)
            else -> activity.getString(R.string.ui_attention)
        }
        stylePill(hardeningBadge, badge, color)
        hardeningStatus.setTextColor(color)
        hardeningStatus.text = activity.getString(R.string.hardening_security_summary, s.score, s.failed, s.review)
        hardeningResults.removeAllViews()
        s.findings.filter { it.status == HardeningStatus.FAIL || it.status == HardeningStatus.REVIEW }
            .take(3)
            .forEachIndexed { index, finding ->
                if (index > 0) gap(hardeningResults, 8)
                val accent = if (finding.status == HardeningStatus.FAIL) GeDefenseUi.orange else GeDefenseUi.gold
                hardeningResults.addView(detailLine(finding.title, accent))
            }
        if (hardeningResults.childCount == 0) hardeningResults.addView(detailLine(activity.getString(R.string.hardening_no_action), GeDefenseUi.green))
    }

    private fun updateAppScan(s: AppScanSnapshot, deep: DeviceScanSnapshot) {
        if (deep.state == "RUNNING") {
            stylePill(appScanBadge, activity.getString(R.string.ui_live), GeDefenseUi.cyan)
            appScanStatus.setTextColor(GeDefenseUi.cyan)
            appScanStatus.text = activity.getString(R.string.scanner_current, deep.progress.current.ifBlank { activity.getString(R.string.scanner_ready) })
            appResults.removeAllViews()
            return
        }
        val color = when {
            s.state == "FAILED" -> GeDefenseUi.red
            s.state == "COMPLETE" && s.highRiskPackages > 0 -> GeDefenseUi.orange
            s.state == "COMPLETE" -> GeDefenseUi.green
            else -> GeDefenseUi.gold
        }
        val badge = when (s.state) {
            "COMPLETE" -> if (s.highRiskPackages > 0) activity.getString(R.string.ui_review) else activity.getString(R.string.ui_clean)
            "FAILED" -> activity.getString(R.string.ui_failed)
            else -> activity.getString(R.string.ui_not_scanned)
        }
        stylePill(appScanBadge, badge, color)
        appScanStatus.setTextColor(if (s.state == "FAILED") GeDefenseUi.red else GeDefenseUi.textMuted)
        appScanStatus.text = when (s.state) {
            "COMPLETE" -> activity.getString(R.string.app_scanner_summary, s.userPackages, s.highRiskPackages, s.threatMatchedPackages)
            "FAILED" -> activity.getString(R.string.app_scanner_failed)
            else -> activity.getString(R.string.app_scanner_idle)
        }
        appResults.removeAllViews()
        if (s.state == "COMPLETE" && s.truncated) appResults.addView(detailLine(activity.getString(R.string.app_scanner_limited, s.deepScannedPackages, s.userPackages), GeDefenseUi.orange))
        s.results.take(5).forEachIndexed { index, result ->
            if (index > 0) gap(appResults, 10)
            appResults.addView(appRiskRow(result))
        }
    }

    private fun updateFullFlow(snapshot: UiSnapshot) {
        val f = snapshot.fullFlow
        liveTrafficResults.removeAllViews(); countryResults.removeAllViews()
        val live = snapshot.protectionMode == ProtectionMode.FULL_FLOW_BETA && f.state != "IDLE"
        stylePill(liveTrafficBadge, activity.getString(if (live) R.string.ui_live else R.string.ui_waiting), if (live) GeDefenseUi.green else GeDefenseUi.cyan)
        if (!live) {
            liveTrafficStatus.text = activity.getString(R.string.full_flow_enable_for_live)
            liveTrafficStatus.setTextColor(GeDefenseUi.textMuted)
        } else {
            liveTrafficStatus.text = activity.getString(R.string.full_flow_summary, f.activeFlows, GeDefenseUi.formatBytes(f.txBytes), GeDefenseUi.formatBytes(f.rxBytes), f.blockedFlows)
            liveTrafficStatus.setTextColor(if (snapshot.vpnStatus == "FULL_GUARDED") GeDefenseUi.green else GeDefenseUi.orange)
            f.apps.take(6).forEachIndexed { index, app ->
                if (index > 0) gap(liveTrafficResults, 12)
                liveTrafficResults.addView(appFlowCard(app))
            }
        }

        val geo = snapshot.geoCountry
        stylePill(countryBadge, activity.getString(if (geo.ready) R.string.ui_ready else R.string.ui_waiting), if (geo.ready) GeDefenseUi.green else GeDefenseUi.orange)
        countryStatus.text = if (geo.ready) activity.getString(R.string.geo_database_ready, geo.v4Records + geo.v6Records, GeDefenseUi.formatTime(activity, geo.fetchedAtMillis)) else activity.getString(R.string.geo_database_missing)
        countryStatus.setTextColor(if (geo.ready) GeDefenseUi.green else GeDefenseUi.orange)
        if (f.topCountries.isEmpty()) {
            countryResults.addView(detailLine(activity.getString(R.string.country_no_session_data)))
        } else {
            val total = f.totalBytes.coerceAtLeast(1L)
            f.topCountries.take(3).forEachIndexed { index, country ->
                if (index > 0) gap(countryResults, 12)
                val ratio = (country.bytes.toDouble() / total.toDouble()).coerceIn(0.0, 1.0)
                countryResults.addView(countryRow(index + 1, country, ratio.toFloat()))
            }
        }
    }

    private fun updateMap(snapshot: UiSnapshot) {
        val routes = buildMapRoutes(snapshot.fullFlow)
        trafficMap.setData(snapshot.originLocation, routes)
        mapLegend.removeAllViews()
        routes.groupBy { it.owner }.values
            .mapNotNull { group ->
                val first = group.firstOrNull() ?: return@mapNotNull null
                Triple(first, group.sumOf { it.bytes }, group.sumOf { it.flows })
            }
            .sortedByDescending { it.second }
            .take(4)
            .forEachIndexed { index, entry ->
                if (index > 0) gap(mapLegend, 7)
                mapLegend.addView(mapLegendRow(entry.first, entry.second, entry.third))
            }

        val localCoarse = snapshot.originLocation.usesDeviceLocation
        val live = snapshot.protectionMode == ProtectionMode.FULL_FLOW_BETA && snapshot.fullFlow.state != "IDLE"
        stylePill(
            mapBadge,
            activity.getString(if (live) R.string.ui_live else R.string.ui_waiting),
            if (live) GeDefenseUi.cyan else GeDefenseUi.gold,
        )
        mapStatus.text = when {
            !live -> activity.getString(R.string.traffic_map_enable_full_flow)
            routes.isEmpty() -> activity.getString(R.string.traffic_map_waiting)
            localCoarse -> activity.getString(R.string.traffic_map_status_local, routes.size)
            else -> activity.getString(R.string.traffic_map_status_approx, routes.size)
        }
        mapLocationButton.visibility = if (localCoarse) View.GONE else View.VISIBLE
    }

    private fun buildMapRoutes(flow: FullFlowAnalyticsSnapshot): List<TrafficMapRoute> {
        val palette = intArrayOf(
            GeDefenseUi.cyan, GeDefenseUi.gold, GeDefenseUi.green, GeDefenseUi.blue,
            GeDefenseUi.orange, Color.rgb(195, 118, 255),
        )
        val out = ArrayList<TrafficMapRoute>()
        flow.apps.take(8).forEachIndexed { appIndex, app ->
            app.topCountries.take(3).forEach { country ->
                if (country.countryCode != "ZZ" && country.bytes > 0L && CountryCentroids.lookup(country.countryCode) != null) {
                    out += TrafficMapRoute(
                        owner = app.owner,
                        appLabel = app.label,
                        countryCode = country.countryCode,
                        bytes = country.bytes,
                        flows = country.flows,
                        color = palette[appIndex % palette.size],
                    )
                }
            }
        }
        return out.sortedByDescending { it.bytes }.take(12)
    }

    private fun mapLegendRow(route: TrafficMapRoute, bytes: Long, flows: Int): View = FrameLayout(activity).apply {
        background = GeDefenseUi.softPanelBackground(activity, 14, route.color)
        val content = LinearLayout(activity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(14), dp(10), dp(14), dp(10))
            addView(VgtUiComponents.appIdentityBadge(activity, route.owner, route.appLabel, 32), LinearLayout.LayoutParams(dp(32), dp(32)))
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(11), 0, dp(10), 0)
                addView(GeDefenseUi.textView(activity, route.appLabel, 11.8f, GeDefenseUi.text, bold = true))
                addView(GeDefenseUi.textView(activity, activity.getString(R.string.traffic_map_legend_detail, flows, GeDefenseUi.formatBytes(bytes)), 9.2f, GeDefenseUi.textDim).apply { setPadding(0, dp(3), 0, 0) })
            }, LinearLayout.LayoutParams(0, -2, 1f))
            addView(View(activity).apply { background = GeDefenseUi.iconWellBackground(activity, route.color) }, LinearLayout.LayoutParams(dp(9), dp(9)))
        }
        addView(content, FrameLayout.LayoutParams(-1, -2))
    }

    private fun updateTraffic(s: TrafficUsageSnapshot, access: Boolean) {
        usageButton.visibility = if (access) View.GONE else View.VISIBLE
        trafficStatus.text = when {
            !access -> activity.getString(R.string.traffic_usage_required)
            s.state == "READY" -> activity.getString(R.string.traffic_summary, GeDefenseUi.formatBytes(s.totalBytes), GeDefenseUi.formatTime(activity, s.measuredAtMillis))
            s.state == "FAILED" -> activity.getString(R.string.traffic_failed)
            else -> activity.getString(R.string.traffic_idle)
        }
        trafficResults.removeAllViews()
        val max = s.apps.maxOfOrNull { it.totalBytes }?.coerceAtLeast(1L) ?: 1L
        s.apps.take(6).forEachIndexed { index, app ->
            if (index > 0) gap(trafficResults, 12)
            trafficResults.addView(usageRow(app, (app.totalBytes.toDouble() / max.toDouble()).toFloat()))
        }
    }

    private fun sectionCard(
        icon: VgtIcon,
        accent: Int,
        title: String,
        badge: TextView?,
        subtitle: TextView? = null,
        vararg content: View,
    ): View = FrameLayout(activity).apply {
        background = GeDefenseUi.glassPanelBackground(activity, radius = 18)
        addView(VgtUiComponents.accentRule(activity, accent, 44), FrameLayout.LayoutParams(-2, -2).apply {
            gravity = Gravity.TOP or Gravity.START
            leftMargin = dp(22)
            topMargin = dp(12)
        })
        val contentContainer = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(24), dp(22), dp(20))
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.iconWell(activity, icon, accent, 34), LinearLayout.LayoutParams(dp(34), dp(34)))
                val titleCol = LinearLayout(activity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(dp(14), 0, dp(8), 0)
                    addView(GeDefenseUi.sectionTitle(activity, title))
                    if (subtitle != null) {
                        addView(subtitle.apply { setPadding(0, dp(3), 0, 0) })
                    }
                }
                addView(titleCol, LinearLayout.LayoutParams(0, -2, 1f))
                badge?.let { addView(it) }
            })
            content.forEach { child ->
                gap(this, 12)
                addView(child)
            }
        }
        addView(contentContainer, FrameLayout.LayoutParams(-1, -2))
    }

    private fun appRiskRow(result: AppRiskResult): View {
        val color = when (result.riskLevel) { AppRiskLevel.SEVERE -> GeDefenseUi.red; AppRiskLevel.HIGH -> GeDefenseUi.orange; AppRiskLevel.REVIEW -> GeDefenseUi.gold; AppRiskLevel.LOW -> GeDefenseUi.green }
        return FrameLayout(activity).apply {
            background = GeDefenseUi.softPanelBackground(activity, 14, color)
            val content = LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(dp(16), dp(12), dp(16), dp(12))
                addView(VgtUiComponents.appIdentityBadge(activity, result.packageName, result.label, 36), LinearLayout.LayoutParams(dp(36), dp(36)))
                addView(LinearLayout(activity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(dp(12), 0, dp(10), 0)
                    addView(GeDefenseUi.textView(activity, result.label, 12.5f, GeDefenseUi.text, bold = true))
                    addView(GeDefenseUi.textView(activity, result.packageName, 9.5f, GeDefenseUi.textDim).apply { setPadding(0, dp(3), 0, 0) })
                }, LinearLayout.LayoutParams(0, -2, 1f))
                addView(GeDefenseUi.pill(activity, "${result.riskScore}/100", color))
            }
            addView(content, FrameLayout.LayoutParams(-1, -2))
        }
    }

    private fun appFlowCard(app: AppFlowTraffic): View = FrameLayout(activity).apply {
        background = GeDefenseUi.softPanelBackground(activity, 14, GeDefenseUi.cyan)
        val content = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.appIdentityBadge(activity, app.owner, app.label, 36), LinearLayout.LayoutParams(dp(36), dp(36)))
                addView(LinearLayout(activity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(dp(12), 0, dp(10), 0)
                    addView(GeDefenseUi.textView(activity, app.label, 13f, GeDefenseUi.cyan, bold = true))
                    addView(GeDefenseUi.textView(
                        activity,
                        activity.getString(R.string.full_flow_app_detail, app.activeFlows, app.blockedFlows, app.correlatedFlows, app.annotatedFlows),
                        9.5f,
                        GeDefenseUi.textDim,
                    ).apply { setPadding(0, dp(3), 0, 0) })
                }, LinearLayout.LayoutParams(0, -2, 1f))
                addView(GeDefenseUi.textView(activity, GeDefenseUi.formatBytes(app.totalBytes), 12.5f, GeDefenseUi.text, bold = true).apply {
                    gravity = Gravity.CENTER_VERTICAL or Gravity.END
                })
            })
            if (app.totalBytes > 0L) {
                gap(this, 10)
                val countryList = LinearLayout(activity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(dp(48), 0, 0, 0)
                }
                app.topCountries.take(3).forEach { c ->
                    val ratio = (c.bytes.toDouble() / app.totalBytes.toDouble()).coerceIn(0.0, 1.0).toFloat()
                    countryList.addView(compactCountryRow(c, ratio), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(6) })
                }
                addView(countryList)
            }
            if (app.topDomains.isNotEmpty()) {
                addView(GeDefenseUi.textView(
                    activity,
                    activity.getString(R.string.dns_top, app.topDomains.joinToString(" · ") { it.domain }),
                    9.5f,
                    GeDefenseUi.textDim,
                ).apply { setPadding(dp(48), dp(8), 0, 0) })
            }
            if (app.owner.contains('.') && !app.owner.startsWith("uid-")) {
                addView(GeDefenseUi.textView(activity, activity.getString(R.string.live_flow_open_forensics), 8.8f, GeDefenseUi.gold).apply {
                    setPadding(dp(48), dp(9), 0, 0)
                })
            }
        }
        addView(content, FrameLayout.LayoutParams(-1, -2))
        if (app.owner.contains('.') && !app.owner.startsWith("uid-")) {
            isClickable = true
            isFocusable = true
            setOnClickListener { actions.openXdrForPackage(app.owner) }
        }
    }

    private fun countryRow(rank: Int, c: CountryTraffic, ratio: Float): View = FrameLayout(activity).apply {
        background = GeDefenseUi.softPanelBackground(activity, 14, if (rank == 1) GeDefenseUi.gold else GeDefenseUi.cyan)
        val content = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(GeDefenseUi.textView(activity, "$rank", 12f, if (rank == 1) GeDefenseUi.gold else GeDefenseUi.text, bold = true), LinearLayout.LayoutParams(dp(26), -2))
                addView(GeDefenseUi.textView(activity, countryLabel(c.countryCode), 12.5f, GeDefenseUi.text, bold = true).apply {
                    setPadding(dp(6), 0, dp(8), 0)
                }, LinearLayout.LayoutParams(0, -2, 1f))
                addView(GeDefenseUi.textView(activity, String.format(Locale.ROOT, "%.1f%%", ratio * 100f), 12f, if (rank == 1) GeDefenseUi.gold else GeDefenseUi.textMuted, bold = true).apply {
                    gravity = Gravity.CENTER_VERTICAL or Gravity.END
                })
            })
            addView(VgtProgressView(activity, if (rank == 1) GeDefenseUi.gold else GeDefenseUi.cyan).apply {
                setProgress(ratio, if (rank == 1) GeDefenseUi.gold else GeDefenseUi.cyan)
            }, LinearLayout.LayoutParams(-1, dp(5)).apply { topMargin = dp(8) })
            addView(detailLine(activity.getString(R.string.country_bytes_flows, GeDefenseUi.formatBytes(c.bytes), c.flows)).apply {
                setPadding(0, dp(6), 0, 0)
            })
        }
        addView(content, FrameLayout.LayoutParams(-1, -2))
    }

    private fun compactCountryRow(c: CountryTraffic, ratio: Float): View = LinearLayout(activity).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        addView(GeDefenseUi.textView(activity, c.countryCode, 10f, GeDefenseUi.gold, bold = true).apply {
            gravity = Gravity.CENTER_VERTICAL or Gravity.START
        }, LinearLayout.LayoutParams(dp(34), -2))
        addView(VgtProgressView(activity, GeDefenseUi.cyan).apply {
            setProgress(ratio)
        }, LinearLayout.LayoutParams(0, dp(5), 1f).apply {
            leftMargin = dp(10)
            rightMargin = dp(12)
        })
        addView(GeDefenseUi.textView(activity, GeDefenseUi.formatBytes(c.bytes), 9.5f, GeDefenseUi.textDim).apply {
            gravity = Gravity.CENTER_VERTICAL or Gravity.END
        }, LinearLayout.LayoutParams(dp(62), -2))
    }

    private fun usageRow(app: AppTrafficUsage, ratio: Float): View = FrameLayout(activity).apply {
        background = GeDefenseUi.softPanelBackground(activity, 14, GeDefenseUi.blue)
        val content = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.appIdentityBadge(activity, app.packageNames.firstOrNull(), app.label, 36), LinearLayout.LayoutParams(dp(36), dp(36)))
                addView(GeDefenseUi.textView(activity, app.label, 12.5f, GeDefenseUi.text, bold = true).apply {
                    setPadding(dp(12), 0, dp(10), 0)
                }, LinearLayout.LayoutParams(0, -2, 1f))
                addView(GeDefenseUi.textView(activity, GeDefenseUi.formatBytes(app.totalBytes), 12f, GeDefenseUi.cyan, bold = true).apply {
                    gravity = Gravity.CENTER_VERTICAL or Gravity.END
                })
            })
            val nested = LinearLayout(activity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(48), 0, 0, 0)
                addView(VgtProgressView(activity, GeDefenseUi.blue).apply {
                    setProgress(ratio, GeDefenseUi.blue)
                }, LinearLayout.LayoutParams(-1, dp(4)).apply { topMargin = dp(8) })
                addView(detailLine(activity.getString(R.string.traffic_rx_tx_compact, GeDefenseUi.formatBytes(app.rxBytes), GeDefenseUi.formatBytes(app.txBytes))).apply {
                    setPadding(0, dp(6), 0, 0)
                })
            }
            addView(nested)
        }
        addView(content, FrameLayout.LayoutParams(-1, -2))
    }

    private fun statusMatrix(a: String, av: String, b: String, bv: String, c: String, cv: String): View = FrameLayout(activity).apply {
        background = GeDefenseUi.softPanelBackground(activity, 14, GeDefenseUi.green)
        val content = LinearLayout(activity).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(16), dp(12), dp(16), dp(12))
            val items = listOf(a to av, b to bv, c to cv)
            items.forEachIndexed { index, item ->
                addView(LinearLayout(activity).apply {
                    orientation = LinearLayout.VERTICAL
                    gravity = Gravity.CENTER
                    addView(GeDefenseUi.textView(activity, item.second, 12f, GeDefenseUi.green, bold = true).apply { gravity = Gravity.CENTER })
                    addView(GeDefenseUi.textView(activity, item.first, 9f, GeDefenseUi.textDim).apply { gravity = Gravity.CENTER; setPadding(0, dp(4), 0, 0) })
                }, LinearLayout.LayoutParams(0, -2, 1f))
                if (index < items.lastIndex) {
                    addView(VgtUiComponents.divider(activity), LinearLayout.LayoutParams(dp(1), dp(32)).apply { leftMargin = dp(6); rightMargin = dp(6) })
                }
            }
        }
        addView(content, FrameLayout.LayoutParams(-1, -2))
    }

    private fun stylePill(view: TextView, label: String, color: Int) {
        view.text = label; view.setTextColor(color); view.background = GeDefenseUi.badgeBackground(activity, color)
    }

    private fun countryLabel(code: String): String {
        if (code == "ZZ") return activity.getString(R.string.country_unknown)
        return try { Locale.Builder().setRegion(code).build().displayCountry.takeIf { it.isNotBlank() } ?: code } catch (_: Throwable) { code }
    }

    private fun detailLine(text: String, color: Int = GeDefenseUi.textDim): TextView = GeDefenseUi.textView(activity, text, 9.8f, color)
    private fun gap(parent: LinearLayout, value: Int) = GeDefenseUi.addVerticalGap(parent, activity, value)
    private fun dp(value: Int) = GeDefenseUi.dp(activity, value)
}
