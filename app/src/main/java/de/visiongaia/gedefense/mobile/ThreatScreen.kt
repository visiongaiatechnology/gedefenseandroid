package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.graphics.Color
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import de.visiongaia.gedefense.mobile.core.EnforcementClass
import java.util.Locale

// STATUS: DIAMANT VGT SUPREME
class ThreatScreen(private val activity: Activity, private val actions: UiActions) {
    val view: View
    private val rootLayout: LinearLayout
    private val feedSummary: TextView
    private val blockedValue: TextView
    private val destinationsValue: TextView
    private val feedBox: LinearLayout
    private val modePill: TextView
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
    private val trafficStatus: TextView
    private val trafficResults: LinearLayout
    private val usageButton: TextView

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

    private var lastFeeds: List<FeedUiSnapshot> = emptyList()
    private var lastFullFlow: FullFlowRenderKey? = null
    private var lastMap: MapRenderKey? = null
    private var lastTraffic: TrafficRenderKey? = null

    init {
        val scroll = ScrollView(activity).apply {
            clipToPadding = false
            overScrollMode = View.OVER_SCROLL_NEVER
        }
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

        root.addView(VgtUiComponents.screenHeader(activity, activity.getString(R.string.activity_center_title), activity.getString(R.string.activity_center_subtitle)))
        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)

        feedSummary = GeDefenseUi.textView(activity, "", 13.5f, GeDefenseUi.green, bold = true)
        modePill = GeDefenseUi.pill(activity, "", GeDefenseUi.cyan)
        root.addView(summaryCard())
        gap(root, GeDefenseUi.SPACING_CARD_GAP_DP)

        val sessionRow = LinearLayout(activity).apply { orientation = LinearLayout.HORIZONTAL }
        blockedValue = GeDefenseUi.displayTextView(activity, "0", 22f)
        destinationsValue = GeDefenseUi.displayTextView(activity, "0", 22f)
        val halfGap = GeDefenseUi.cardHorizontalGap(activity) / 2
        sessionRow.addView(smallStat(VgtIcon.BLOCK, activity.getString(R.string.ui_blocked_packets), blockedValue, GeDefenseUi.red), LinearLayout.LayoutParams(0, -2, 1f).apply { rightMargin = halfGap })
        sessionRow.addView(smallStat(VgtIcon.COUNTRY, activity.getString(R.string.ui_unique_destinations), destinationsValue, GeDefenseUi.gold), LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = halfGap })
        root.addView(sessionRow)

        gap(root, GeDefenseUi.SPACING_SECTION_GAP_DP)
        root.addView(LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            addView(VgtUiComponents.accentRule(activity, GeDefenseUi.cyan, 62))
            addView(GeDefenseUi.sectionTitle(activity, activity.getString(R.string.activity_live_network_section)).apply { setPadding(0, dp(8), 0, 0) })
        })
        root.addView(GeDefenseUi.textView(activity, activity.getString(R.string.activity_live_network_hint), 10.2f, GeDefenseUi.textDim).apply {
            setLineSpacing(0f, 1.25f)
            setPadding(0, dp(6), 0, dp(12))
        })

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

        gap(root, GeDefenseUi.SPACING_SECTION_GAP_DP)
        root.addView(LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            addView(VgtUiComponents.accentRule(activity, GeDefenseUi.gold, 62))
            addView(GeDefenseUi.sectionTitle(activity, activity.getString(R.string.feed_sources)).apply { setPadding(0, dp(8), 0, 0) })
        })
        root.addView(GeDefenseUi.textView(activity, activity.getString(R.string.ui_feed_policy_explainer), 10.2f, GeDefenseUi.textDim).apply {
            setLineSpacing(0f, 1.25f)
            setPadding(0, dp(6), 0, dp(12))
        })
        feedBox = LinearLayout(activity).apply { orientation = LinearLayout.VERTICAL }
        root.addView(feedBox)
        view = scroll
    }

    fun setBottomPadding(bottomPx: Int) {
        rootLayout.setPadding(rootLayout.paddingLeft, rootLayout.paddingTop, rootLayout.paddingRight, bottomPx)
    }

    fun update(snapshot: UiSnapshot) {
        val full = snapshot.protectionMode == ProtectionMode.FULL_FLOW_BETA
        feedSummary.text = activity.getString(R.string.ui_feeds_active, snapshot.healthyFeeds, snapshot.feeds.size)
        modePill.text = activity.getString(if (full) R.string.ui_full_flow_badge else R.string.ui_selective_badge)
        modePill.setTextColor(if (full) GeDefenseUi.cyan else GeDefenseUi.gold)
        modePill.background = GeDefenseUi.badgeBackground(activity, if (full) GeDefenseUi.cyan else GeDefenseUi.gold)
        blockedValue.text = snapshot.blockedPackets.toString()
        destinationsValue.text = snapshot.uniqueDestinations.toString()

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

        val cardGap = GeDefenseUi.cardGap(activity)
        if (snapshot.feeds != lastFeeds) {
            lastFeeds = snapshot.feeds
            feedBox.removeAllViews()
            snapshot.feeds.forEachIndexed { index, feed ->
                feedBox.addView(feedCard(feed), LinearLayout.LayoutParams(-1, -2).apply { if (index > 0) topMargin = cardGap })
            }
        }
    }

    private fun summaryCard(): View = FrameLayout(activity).apply {
        background = GeDefenseUi.glassPanelBackground(activity, strong = true, radius = 17)
        val content = LinearLayout(activity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(18))
            addView(VgtUiComponents.statusDot(activity, GeDefenseUi.green, 8), LinearLayout.LayoutParams(dp(8), dp(8)))
            feedSummary.setPadding(dp(11), 0, 0, 0)
            addView(feedSummary, LinearLayout.LayoutParams(0, -2, 1f))
            addView(modePill)
        }
        addView(content, FrameLayout.LayoutParams(-1, -2))
    }

    private fun smallStat(icon: VgtIcon, label: String, value: TextView, accent: Int): View = FrameLayout(activity).apply {
        background = GeDefenseUi.glassPanelBackground(activity, radius = 16)
        minimumHeight = dp(116)
        val content = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(dp(16), dp(16), dp(16), dp(16))
            addView(VgtUiComponents.iconWell(activity, icon, accent, 34), LinearLayout.LayoutParams(dp(34), dp(34)).apply {
                gravity = Gravity.CENTER_HORIZONTAL
            })
            value.gravity = Gravity.CENTER
            value.textAlignment = View.TEXT_ALIGNMENT_CENTER
            addView(value, LinearLayout.LayoutParams(-1, -2).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                topMargin = dp(8)
            })
            val labelView = GeDefenseUi.textView(activity, label, 10.2f, GeDefenseUi.textMuted).apply {
                gravity = Gravity.CENTER
                textAlignment = View.TEXT_ALIGNMENT_CENTER
            }
            addView(labelView, LinearLayout.LayoutParams(-1, -2).apply {
                gravity = Gravity.CENTER_HORIZONTAL
                topMargin = dp(4)
            })
        }
        addView(content, FrameLayout.LayoutParams(-1, -1, Gravity.CENTER))
    }

    private fun feedCard(feed: FeedUiSnapshot): View {
        val accent = when (feed.enforcement) {
            EnforcementClass.ROUTE_BLOCK -> GeDefenseUi.red
            EnforcementClass.CORRELATE_ONLY -> GeDefenseUi.gold
            EnforcementClass.ANNOTATE_ONLY -> GeDefenseUi.blue
        }
        val icon = when (feed.enforcement) {
            EnforcementClass.ROUTE_BLOCK -> if (feed.id.contains("feodo", ignoreCase = true)) VgtIcon.ALERT else VgtIcon.BLOCK
            EnforcementClass.CORRELATE_ONLY -> VgtIcon.CORRELATE
            EnforcementClass.ANNOTATE_ONLY -> VgtIcon.ANNOTATE
        }
        val mode = when (feed.enforcement) {
            EnforcementClass.ROUTE_BLOCK -> activity.getString(R.string.feed_mode_block)
            EnforcementClass.CORRELATE_ONLY -> activity.getString(R.string.feed_mode_correlate)
            EnforcementClass.ANNOTATE_ONLY -> activity.getString(R.string.feed_mode_annotate)
        }
        val state = when {
            !feed.available -> activity.getString(R.string.feed_missing)
            feed.fresh -> activity.getString(R.string.feed_fresh)
            else -> activity.getString(R.string.feed_stale)
        }
        return FrameLayout(activity).apply {
            background = GeDefenseUi.glassPanelBackground(activity, radius = 16)

            // Accent indicator bar with rounded appearance
            addView(View(activity).apply {
                background = GeDefenseUi.accentRuleBackground(activity, accent)
            }, FrameLayout.LayoutParams(dp(3), -1, Gravity.START))

            val contentRow = LinearLayout(activity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(dp(20), dp(18), dp(20), dp(18))

                addView(VgtUiComponents.iconWell(activity, icon, accent, 34), LinearLayout.LayoutParams(dp(34), dp(34)))
                addView(LinearLayout(activity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(dp(12), 0, dp(8), 0)
                    addView(GeDefenseUi.textView(activity, feed.name, 12.5f, GeDefenseUi.text, bold = true))
                    addView(GeDefenseUi.textView(
                        activity,
                        activity.getString(R.string.ui_feed_detail_compact, state, feed.records, GeDefenseUi.formatCompactTime(activity, feed.fetchedAtMillis)),
                        9.3f,
                        if (feed.fresh) GeDefenseUi.textMuted else GeDefenseUi.orange,
                    ).apply { setPadding(0, dp(3), 0, 0) })
                }, LinearLayout.LayoutParams(0, -2, 1f))
                addView(GeDefenseUi.pill(activity, mode, accent))
                addView(VgtIconView(activity, VgtIcon.CHEVRON, GeDefenseUi.textDim), LinearLayout.LayoutParams(dp(12), dp(12)).apply { leftMargin = dp(6) })
            }
            addView(contentRow, FrameLayout.LayoutParams(-1, -2))
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
        }
        addView(content, FrameLayout.LayoutParams(-1, -2))
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
