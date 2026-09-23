package de.visiongaia.gedefense.mobile

import android.app.AppOpsManager
import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import java.util.TreeMap

data class AppTrafficUsage(
    val uid: Int,
    val packageNames: List<String>,
    val label: String,
    val rxBytes: Long,
    val txBytes: Long,
) {
    val totalBytes: Long get() = saturatingAdd(rxBytes, txBytes)

    private fun saturatingAdd(a: Long, b: Long): Long = if (Long.MAX_VALUE - a < b) Long.MAX_VALUE else a + b
}

data class TrafficUsageSnapshot(
    val state: String,
    val measuredAtMillis: Long,
    val windowStartMillis: Long,
    val totalRxBytes: Long,
    val totalTxBytes: Long,
    val apps: List<AppTrafficUsage>,
    val countryAnalyticsState: String,
) {
    val totalBytes: Long get() = if (Long.MAX_VALUE - totalRxBytes < totalTxBytes) Long.MAX_VALUE else totalRxBytes + totalTxBytes

    companion object {
        fun idle() = TrafficUsageSnapshot("IDLE", 0L, 0L, 0L, 0L, emptyList(), "FULL_FLOW_REQUIRED")
    }
}

/** Whole-device per-UID byte accounting using Android's user-granted Usage Access surface. */
class TrafficUsageRepository(context: Context) {
    private val appContext = context.applicationContext
    private val stats = appContext.getSystemService(NetworkStatsManager::class.java)
    private val pm = appContext.packageManager

    fun hasUsageAccess(): Boolean {
        val ops = appContext.getSystemService(AppOpsManager::class.java)
        val mode = ops.checkOpNoThrow(
            AppOpsManager.OPSTR_GET_USAGE_STATS,
            Process.myUid(),
            appContext.packageName,
        )
        return mode == AppOpsManager.MODE_ALLOWED
    }

    @Suppress("DEPRECATION") // NetworkStatsManager querySummary still uses legacy network-type constants.
    fun queryLast24Hours(now: Long = System.currentTimeMillis()): TrafficUsageSnapshot {
        val start = now - WINDOW_MS
        if (!hasUsageAccess()) return TrafficUsageSnapshot("PERMISSION_REQUIRED", now, start, 0, 0, emptyList(), "FULL_FLOW_REQUIRED")

        val usage = HashMap<Int, MutableUsage>()
        val queried = listOf(
            collectSummary(ConnectivityManager.TYPE_WIFI, start, now, usage),
            collectSummary(ConnectivityManager.TYPE_MOBILE, start, now, usage),
            collectSummary(ConnectivityManager.TYPE_ETHERNET, start, now, usage),
        ).count { it }
        if (queried == 0) {
            return TrafficUsageSnapshot("FAILED", now, start, 0, 0, emptyList(), "FULL_FLOW_REQUIRED")
        }
        val appsByUid = visibleAppsByUid()
        val results = ArrayList<AppTrafficUsage>()
        var totalRx = 0L
        var totalTx = 0L

        usage.forEach { (uid, bytes) ->
            if (Thread.currentThread().isInterrupted) throw InterruptedException("traffic query interrupted")
            val apps = appsByUid[uid] ?: return@forEach
            if (bytes.rx == 0L && bytes.tx == 0L) return@forEach
            totalRx = saturatingAdd(totalRx, bytes.rx)
            totalTx = saturatingAdd(totalTx, bytes.tx)
            val packageNames = apps.map { it.packageName }.distinct().sorted().take(8)
            val primary = apps.first()
            val label = try { pm.getApplicationLabel(primary).toString().take(120) } catch (_: RuntimeException) { primary.packageName }
            results += AppTrafficUsage(uid, packageNames, label, bytes.rx, bytes.tx)
        }

        return TrafficUsageSnapshot(
            state = "READY",
            measuredAtMillis = now,
            windowStartMillis = start,
            totalRxBytes = totalRx,
            totalTxBytes = totalTx,
            apps = results.sortedByDescending { it.totalBytes }.take(MAX_RESULTS),
            countryAnalyticsState = "FULL_FLOW_REQUIRED",
        )
    }

    private fun collectSummary(networkType: Int, start: Long, end: Long, out: MutableMap<Int, MutableUsage>): Boolean {
        return try {
            @Suppress("DEPRECATION")
            val summary = stats.querySummary(networkType, null, start, end) ?: return false
            summary.use { networkStats ->
                val bucket = NetworkStats.Bucket()
                while (networkStats.hasNextBucket()) {
                    if (Thread.currentThread().isInterrupted) throw InterruptedException("traffic query interrupted")
                    if (!networkStats.getNextBucket(bucket)) break
                    if (bucket.uid < 0) continue
                    val slot = out.getOrPut(bucket.uid) { MutableUsage() }
                    slot.rx = saturatingAdd(slot.rx, bucket.rxBytes.coerceAtLeast(0L))
                    slot.tx = saturatingAdd(slot.tx, bucket.txBytes.coerceAtLeast(0L))
                }
            }
            true
        } catch (e: InterruptedException) {
            throw e
        } catch (_: SecurityException) {
            false
        } catch (_: RuntimeException) {
            false
        }
    }

    private fun visibleAppsByUid(): Map<Int, List<ApplicationInfo>> {
        val list = if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0L))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledApplications(0)
        }
        val grouped = TreeMap<Int, MutableList<ApplicationInfo>>()
        list.take(MAX_PACKAGES).forEach { app -> grouped.getOrPut(app.uid) { ArrayList() }.add(app) }
        return grouped
    }

    private fun saturatingAdd(a: Long, b: Long): Long = if (Long.MAX_VALUE - a < b) Long.MAX_VALUE else a + b
    private data class MutableUsage(var rx: Long = 0L, var tx: Long = 0L)

    companion object {
        private const val WINDOW_MS = 24L * 60L * 60L * 1000L
        private const val MAX_PACKAGES = 2048
        private const val MAX_RESULTS = 64
    }
}
