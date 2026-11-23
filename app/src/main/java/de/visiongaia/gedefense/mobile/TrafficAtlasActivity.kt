package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.util.Locale

class TrafficAtlasActivity : Activity() {
    private enum class WindowRange(val hours: Int, val labelRes: Int) {
        LIVE(0, R.string.atlas_window_live),
        H24(24, R.string.atlas_window_24h),
        H48(48, R.string.atlas_window_48h),
        D7(168, R.string.atlas_window_7d),
    }

    private lateinit var runtime: AppRuntime
    private lateinit var rootLayout: LinearLayout
    private lateinit var atlasMap: TrafficWorldMapView
    private lateinit var summaryText: TextView
    private lateinit var statusBadge: TextView
    private lateinit var detailsHost: LinearLayout
    private val windowButtons = LinkedHashMap<WindowRange, TextView>()
    private var selectedWindow = WindowRange.H24
    private var usageWindowCache: TrafficUsageSnapshot? = null
    private var usageWindowHours: Int = -1
    private val listener: () -> Unit = { runOnUiThread { if (!isFinishing && !isDestroyed) render() } }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runtime = RuntimeActivityEntry.requireReady(this) ?: return
        VgtWindowInsets.configureSystemBars(window)
        setContentView(buildUi())
        selectWindow(WindowRange.H24)
    }

    override fun onStart() {
        super.onStart()
        runtime.addStateListener(listener)
        render()
    }

    override fun onStop() {
        runtime.removeStateListener(listener)
        super.onStop()
    }

    private fun buildUi(): View {
        val root = FrameLayout(this).apply { setBackgroundColor(GeDefenseUi.bg) }
        root.addView(CyberBackgroundView(this), FrameLayout.LayoutParams(-1, -1))
        val scroll = ScrollView(this).apply { clipToPadding = false; overScrollMode = View.OVER_SCROLL_NEVER }
        VgtUiPerformance.bindScroll(scroll)
        rootLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(16), dp(18), dp(40))
        }
        scroll.addView(rootLayout, FrameLayout.LayoutParams(-1, -2))
        root.addView(scroll, FrameLayout.LayoutParams(-1, -1))

        rootLayout.addView(VgtUiComponents.screenHeader(
            this,
            getString(R.string.atlas_fullscreen_title),
            getString(R.string.atlas_fullscreen_subtitle),
        ))
        gap(12)

        rootLayout.addView(buildWindowTabs())
        gap(12)

        statusBadge = GeDefenseUi.pill(this, getString(R.string.ui_live), GeDefenseUi.cyan)
        summaryText = GeDefenseUi.textView(this, "", 10.5f, GeDefenseUi.textMuted)
        atlasMap = TrafficWorldMapView(this).apply {
            minimumHeight = dp(340)
        }
        rootLayout.addView(FrameLayout(this).apply {
            background = GeDefenseUi.glassPanelBackground(this@TrafficAtlasActivity, strong = true, accent = GeDefenseUi.cyan, radius = 20)
            addView(LinearLayout(this@TrafficAtlasActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(14), dp(14), dp(14), dp(14))
                addView(LinearLayout(this@TrafficAtlasActivity).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    setPadding(dp(4), 0, dp(4), dp(10))
                    addView(summaryText, LinearLayout.LayoutParams(0, -2, 1f).apply { rightMargin = dp(8) })
                    addView(statusBadge)
                })
                addView(atlasMap, LinearLayout.LayoutParams(-1, dp(340)))
            }, FrameLayout.LayoutParams(-1, -2))
        })

        gap(14)
        detailsHost = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        rootLayout.addView(detailsHost)

        root.setOnApplyWindowInsetsListener { _, insets ->
            val safe = VgtWindowInsets.safeArea(insets)
            rootLayout.setPadding(dp(18) + safe.left, dp(16) + safe.top, dp(18) + safe.right, dp(40) + safe.bottom)
            insets
        }
        root.post { root.requestApplyInsets() }
        return root
    }

    private fun buildWindowTabs(): View = FrameLayout(this).apply {
        background = GeDefenseUi.softPanelBackground(this@TrafficAtlasActivity, 16, GeDefenseUi.cyan)
        val row = LinearLayout(this@TrafficAtlasActivity).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(6), dp(6), dp(6), dp(6))
        }
        WindowRange.entries.forEachIndexed { idx, range ->
            val btn = GeDefenseUi.textView(this@TrafficAtlasActivity, getString(range.labelRes), 10f, GeDefenseUi.textMuted, bold = true).apply {
                gravity = Gravity.CENTER
                isClickable = true
                setOnClickListener { selectWindow(range) }
            }
            windowButtons[range] = btn
            row.addView(btn, LinearLayout.LayoutParams(0, dp(40), 1f).apply { if (idx > 0) leftMargin = dp(6) })
        }
        addView(row, FrameLayout.LayoutParams(-1, -2))
    }

    private fun selectWindow(range: WindowRange) {
        selectedWindow = range
        if (range.hours > 0 && runtime.trafficUsage.hasUsageAccess()) {
            runtime.executeBackground("atlas-usage-window") {
                val snap = try { runtime.trafficUsage.queryWindow(range.hours) } catch (_: RuntimeException) { null }
                if (snap != null) {
                    runOnUiThread {
                        if (!isFinishing && !isDestroyed) {
                            usageWindowCache = snap
                            usageWindowHours = range.hours
                            render()
                        }
                    }
                }
            }
        }
        render()
    }

    private fun render() {
        if (!::atlasMap.isInitialized) return
        windowButtons.forEach { (range, view) ->
            val active = range == selectedWindow
            view.setTextColor(if (active) GeDefenseUi.gold else GeDefenseUi.textMuted)
            view.background = if (active) GeDefenseUi.badgeBackground(this, GeDefenseUi.gold) else null
        }

        val hours = selectedWindow.hours
        val flowSnapshot = if (hours <= 0) {
            runtime.fullFlowAnalytics.snapshot()
        } else {
            mergeWithBehavioralHistory(runtime.fullFlowAnalytics.snapshotForWindow(hours), hours)
        }
        val origin = runtime.originLocator.snapshot()
        val routes = buildMapRoutes(flowSnapshot)
        atlasMap.setData(origin, routes)

        val live = runtime.state.protectionMode() == ProtectionMode.FULL_FLOW_BETA && flowSnapshot.state != "IDLE"
        statusBadge.text = getString(selectedWindow.labelRes)
        statusBadge.setTextColor(if (live || routes.isNotEmpty()) GeDefenseUi.cyan else GeDefenseUi.gold)
        statusBadge.background = GeDefenseUi.badgeBackground(this, if (live || routes.isNotEmpty()) GeDefenseUi.cyan else GeDefenseUi.gold)

        val usage = if (hours > 0 && usageWindowHours == hours) usageWindowCache else null
        val totalWindowBytes = maxOf(flowSnapshot.totalBytes, usage?.totalBytes ?: 0L)
        summaryText.text = getString(
            R.string.atlas_window_summary,
            routes.size,
            flowSnapshot.topCountries.size,
            GeDefenseUi.formatBytes(totalWindowBytes),
            flowSnapshot.blockedFlows,
        )

        detailsHost.removeAllViews()
        renderSectionTitle(getString(R.string.country_analytics_title))
        if (flowSnapshot.topCountries.isEmpty()) {
            detailsHost.addView(emptyCard(getString(R.string.country_no_session_data)))
        } else {
            val total = flowSnapshot.topCountries.sumOf { it.bytes }.coerceAtLeast(1L)
            flowSnapshot.topCountries.take(10).forEachIndexed { idx, country ->
                if (idx > 0) gapInto(detailsHost, 8)
                detailsHost.addView(countryCard(idx + 1, country, total))
            }
        }

        gapInto(detailsHost, 14)
        renderSectionTitle(getString(R.string.atlas_domains_title))
        if (flowSnapshot.topDomains.isEmpty()) {
            detailsHost.addView(emptyCard(getString(R.string.atlas_no_domains)))
        } else {
            detailsHost.addView(domainsCard(flowSnapshot.topDomains.take(12)))
        }

        gapInto(detailsHost, 14)
        renderSectionTitle(getString(R.string.atlas_apps_title))
        if (flowSnapshot.apps.isEmpty()) {
            detailsHost.addView(emptyCard(getString(R.string.atlas_no_apps)))
        } else {
            flowSnapshot.apps.take(12).forEachIndexed { idx, app ->
                if (idx > 0) gapInto(detailsHost, 8)
                detailsHost.addView(appCard(app))
            }
        }
    }

    private fun mergeWithBehavioralHistory(base: FullFlowAnalyticsSnapshot, hours: Int): FullFlowAnalyticsSnapshot {
        val now = System.currentTimeMillis()
        val cutoff = now - hours.toLong() * 60L * 60L * 1000L
        val profiles = try {
            runtime.behavior.snapshot().profiles.filter { it.lastSeenMillis >= cutoff }
        } catch (_: RuntimeException) {
            emptyList()
        }
        if (profiles.isEmpty()) return base

        val byOwner = base.apps.associateBy { it.owner }.toMutableMap()
        val countryAgg = LinkedHashMap<String, CountryTraffic>()
        base.topCountries.forEach { countryAgg[it.countryCode] = it }
        val domainAgg = LinkedHashMap<String, Long>()
        base.topDomains.forEach { domainAgg[it.domain] = it.queries }

        for (profile in profiles) {
            for (d in profile.knownDomains) {
                domainAgg.putIfAbsent(d, profile.observations.toLong().coerceAtLeast(1L))
            }
            if (profile.packageName in byOwner) continue
            val estTotal = (profile.avgTotalPerMinute * profile.observations.coerceAtLeast(1) * 5L).coerceAtLeast(1024L)
            val estTx = (profile.avgTxPerMinute * profile.observations.coerceAtLeast(1) * 5L).coerceAtLeast(512L)
            val estRx = (estTotal - estTx).coerceAtLeast(512L)
            val appCountries = profile.knownCountries
                .filter { it != "ZZ" && CountryCentroids.lookup(it) != null }
                .take(4)
                .map { cc ->
                    val share = estTotal / profile.knownCountries.size.coerceAtLeast(1)
                    CountryTraffic(cc, share, profile.observations.coerceAtLeast(1)).also { ct ->
                        val prev = countryAgg[cc]
                        countryAgg[cc] = CountryTraffic(cc, (prev?.bytes ?: 0L) + ct.bytes, (prev?.flows ?: 0) + ct.flows)
                    }
                }
            val appDomains = profile.knownDomains.take(6).map { DomainTraffic(it, profile.observations.toLong().coerceAtLeast(1L)) }
            byOwner[profile.packageName] = AppFlowTraffic(
                owner = profile.packageName,
                label = profile.label,
                txBytes = estTx,
                rxBytes = estRx,
                activeFlows = 0,
                openedFlows = profile.observations.toLong(),
                blockedFlows = 0L,
                correlatedFlows = 0L,
                annotatedFlows = 0L,
                topCountries = appCountries,
                topDomains = appDomains,
            )
        }
        val mergedApps = byOwner.values.sortedByDescending { it.totalBytes }.take(24)
        val mergedCountries = countryAgg.values.sortedByDescending { it.bytes }.take(12)
        val mergedDomains = domainAgg.entries.map { DomainTraffic(it.key, it.value) }.sortedByDescending { it.queries }.take(16)
        return base.copy(
            apps = mergedApps,
            topCountries = mergedCountries,
            topDomains = mergedDomains,
            uniqueCountries = mergedCountries.size,
        )
    }

    private fun buildMapRoutes(flow: FullFlowAnalyticsSnapshot): List<TrafficMapRoute> {
        val palette = intArrayOf(
            GeDefenseUi.cyan, GeDefenseUi.gold, GeDefenseUi.green, GeDefenseUi.blue,
            GeDefenseUi.orange, Color.rgb(195, 118, 255),
        )
        val out = ArrayList<TrafficMapRoute>()
        flow.apps.take(10).forEachIndexed { appIndex, app ->
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

    private fun renderSectionTitle(title: String) {
        detailsHost.addView(GeDefenseUi.sectionTitle(this, title).apply { setPadding(dp(4), dp(4), dp(4), dp(8)) })
    }

    private fun emptyCard(message: String): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@TrafficAtlasActivity, radius = 16)
        addView(GeDefenseUi.textView(this@TrafficAtlasActivity, message, 10.5f, GeDefenseUi.textDim).apply {
            setPadding(dp(16), dp(14), dp(16), dp(14))
        })
    }

    private fun countryCard(rank: Int, item: CountryTraffic, totalBytes: Long): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@TrafficAtlasActivity, radius = 14)
        val countryName = if (item.countryCode == "ZZ") getString(R.string.country_unknown) else Locale.Builder().setRegion(item.countryCode).build().displayCountry.ifBlank { item.countryCode }
        val pct = ((item.bytes.toDouble() / totalBytes.toDouble()) * 100.0).coerceIn(0.0, 100.0)
        addView(LinearLayout(this@TrafficAtlasActivity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(16), dp(12), dp(16), dp(12))
            addView(GeDefenseUi.pill(this@TrafficAtlasActivity, "#$rank ${item.countryCode}", GeDefenseUi.gold))
            addView(LinearLayout(this@TrafficAtlasActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(12), 0, dp(8), 0)
                addView(GeDefenseUi.textView(this@TrafficAtlasActivity, countryName, 11.8f, GeDefenseUi.text, bold = true))
                addView(GeDefenseUi.textView(this@TrafficAtlasActivity, "${item.flows} Flows · ${"%.1f".format(pct)}%", 9.2f, GeDefenseUi.textDim).apply { setPadding(0, dp(2), 0, 0) })
            }, LinearLayout.LayoutParams(0, -2, 1f))
            addView(GeDefenseUi.textView(this@TrafficAtlasActivity, GeDefenseUi.formatBytes(item.bytes), 11.5f, GeDefenseUi.cyan, bold = true))
        })
    }

    private fun domainsCard(domains: List<DomainTraffic>): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@TrafficAtlasActivity, radius = 16)
        addView(LinearLayout(this@TrafficAtlasActivity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(14), dp(16), dp(14))
            domains.forEachIndexed { idx, d ->
                addView(LinearLayout(this@TrafficAtlasActivity).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    if (idx > 0) setPadding(0, dp(6), 0, 0)
                    addView(GeDefenseUi.textView(this@TrafficAtlasActivity, d.domain, 10.5f, GeDefenseUi.text).apply { maxLines = 1 }, LinearLayout.LayoutParams(0, -2, 1f))
                    addView(GeDefenseUi.pill(this@TrafficAtlasActivity, "${d.queries}x", GeDefenseUi.cyan))
                })
            }
        })
    }

    private fun appCard(app: AppFlowTraffic): View = FrameLayout(this).apply {
        background = GeDefenseUi.glassPanelBackground(this@TrafficAtlasActivity, accent = if (app.blockedFlows > 0) GeDefenseUi.red else GeDefenseUi.cyan, radius = 16)
        addView(LinearLayout(this@TrafficAtlasActivity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(13), dp(16), dp(13))
            addView(LinearLayout(this@TrafficAtlasActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(VgtUiComponents.appIdentityBadge(this@TrafficAtlasActivity, app.owner, app.label, 32), LinearLayout.LayoutParams(dp(32), dp(32)))
                addView(LinearLayout(this@TrafficAtlasActivity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(dp(10), 0, dp(8), 0)
                    addView(GeDefenseUi.textView(this@TrafficAtlasActivity, app.label, 11.8f, GeDefenseUi.text, bold = true))
                    addView(GeDefenseUi.textView(
                        this@TrafficAtlasActivity,
                        "↑ ${GeDefenseUi.formatBytes(app.txBytes)}  ↓ ${GeDefenseUi.formatBytes(app.rxBytes)}  ·  ${getString(R.string.ui_blocked_packets)}: ${app.blockedFlows}",
                        9.2f,
                        GeDefenseUi.textMuted,
                    ).apply { setPadding(0, dp(2), 0, 0) })
                }, LinearLayout.LayoutParams(0, -2, 1f))
            })
            if (app.topDomains.isNotEmpty()) {
                val domainsLine = app.topDomains.take(4).joinToString(" · ") { it.domain }
                addView(GeDefenseUi.textView(this@TrafficAtlasActivity, domainsLine, 8.9f, GeDefenseUi.textDim).apply { setPadding(0, dp(6), 0, 0) })
            }
        })
    }

    private fun gap(value: Int) = GeDefenseUi.addVerticalGap(rootLayout, this, value)
    private fun gapInto(target: LinearLayout, value: Int) = GeDefenseUi.addVerticalGap(target, this, value)
    private fun dp(value: Int) = GeDefenseUi.dp(this, value)
}
