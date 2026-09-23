package de.visiongaia.gedefense.mobile

import android.Manifest
import android.app.Activity
import android.app.ActivityManager
import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.app.NotificationManager
import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.CountDownLatch
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference


data class DeviceSetupSnapshot(
    val batteryExempt: Boolean,
    val batteryBackgroundRestricted: Boolean,
    val batteryReady: Boolean,
    val allFilesAccess: Boolean,
    val usageAccess: Boolean,
    val notificationsAllowed: Boolean,
    val coarseLocationAllowed: Boolean,
    val autostartVisited: Boolean,
    val deviceAdminActive: Boolean,
    val deviceOwnerActive: Boolean,
    val wizardCompleted: Boolean,
    val platformQueryOk: Boolean = true,
)

/**
 * Cached Android setup/status layer.
 *
 * UI reads never perform SharedPreferences, PackageManager, AppOps or DevicePolicyManager calls.
 * Platform state is refreshed on a bounded background lane and published atomically.
 */
class DeviceSetupManager(context: Context) {
    private val appContext = context.applicationContext
    private val cached = AtomicReference(conservativeSnapshot())
    private val preferencesLoaded = CountDownLatch(1)
    private val refreshQueued = AtomicBoolean(false)
    private val listeners = CopyOnWriteArraySet<() -> Unit>()
    private val executor = ThreadPoolExecutor(
        1,
        1,
        0L,
        TimeUnit.MILLISECONDS,
        ArrayBlockingQueue(4),
        { runnable -> Thread(runnable, "gedefense-setup-state").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )

    init {
        try {
            executor.execute {
                val prefs = appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                val wizard = runCatching { prefs.getInt(KEY_WIZARD_VERSION, 0) >= CURRENT_WIZARD_VERSION }.getOrDefault(false)
                val visited = runCatching { prefs.getBoolean(KEY_AUTOSTART_VISITED, false) }.getOrDefault(false)
                val previous = cached.get()
                val updated = previous.copy(wizardCompleted = wizard, autostartVisited = visited)
                cached.set(updated)
                if (updated != previous) notifyListeners()
                preferencesLoaded.countDown()
                refreshSnapshot()
            }
        } catch (_: RejectedExecutionException) {
            preferencesLoaded.countDown()
        }
    }

    fun snapshot(): DeviceSetupSnapshot = cached.get()

    fun addStateListener(listener: () -> Unit) {
        listeners.add(listener)
    }

    fun removeStateListener(listener: () -> Unit) {
        listeners.remove(listener)
    }

    fun requestRefresh(): Boolean {
        if (!refreshQueued.compareAndSet(false, true)) return true
        return try {
            executor.execute {
                try {
                    refreshSnapshot()
                } finally {
                    refreshQueued.set(false)
                }
            }
            true
        } catch (_: RejectedExecutionException) {
            refreshQueued.set(false)
            false
        }
    }

    fun isWizardCompleted(): Boolean = cached.get().wizardCompleted
    fun isDeviceAdminActive(): Boolean = cached.get().deviceAdminActive
    fun isDeviceOwnerActive(): Boolean = cached.get().deviceOwnerActive
    fun isBackgroundRestricted(): Boolean = cached.get().batteryBackgroundRestricted
    fun isBatteryOptimizationExempt(): Boolean = cached.get().batteryExempt
    fun hasAllFilesAccess(): Boolean = cached.get().allFilesAccess
    fun hasUsageAccess(): Boolean = cached.get().usageAccess
    fun notificationsAllowed(): Boolean = cached.get().notificationsAllowed
    fun coarseLocationAllowed(): Boolean = cached.get().coarseLocationAllowed

    fun awaitPreferenceLoad(timeoutMillis: Long): Boolean {
        if (timeoutMillis <= 0L) return preferencesLoaded.count == 0L
        return try {
            preferencesLoaded.await(timeoutMillis.coerceAtMost(MAX_PREFERENCE_WAIT_MS), TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
    }

    fun refreshSnapshot(): DeviceSetupSnapshot {
        val base = cached.get()
        val refreshed = try {
            BoundedAndroidCall.call {
                val activityManager = appContext.getSystemService(ActivityManager::class.java)
                val power = appContext.getSystemService(PowerManager::class.java)
                val appOps = appContext.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
                val dpm = appContext.getSystemService(DevicePolicyManager::class.java)
                val notification = appContext.getSystemService(NotificationManager::class.java)
                val admin = ComponentName(appContext, TitanDeviceAdminReceiver::class.java)

                val batteryExempt = power?.isIgnoringBatteryOptimizations(appContext.packageName) == true
                val backgroundRestricted = activityManager?.isBackgroundRestricted ?: true
                val allFiles = if (Build.VERSION.SDK_INT >= 30) {
                    Environment.isExternalStorageManager()
                } else {
                    appContext.checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
                }
                val usage = appOps?.checkOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS,
                    android.os.Process.myUid(),
                    appContext.packageName,
                ) == AppOpsManager.MODE_ALLOWED
                val notifications = if (Build.VERSION.SDK_INT >= 33) {
                    appContext.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
                } else {
                    notification?.areNotificationsEnabled() ?: true
                }
                val coarse = appContext.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED
                val adminActive = dpm?.isAdminActive(admin) == true
                val ownerActive = dpm?.isDeviceOwnerApp(appContext.packageName) == true

                base.copy(
                    batteryExempt = batteryExempt,
                    batteryBackgroundRestricted = backgroundRestricted,
                    batteryReady = batteryExempt || !backgroundRestricted,
                    allFilesAccess = allFiles,
                    usageAccess = usage,
                    notificationsAllowed = notifications,
                    coarseLocationAllowed = coarse,
                    deviceAdminActive = adminActive,
                    deviceOwnerActive = ownerActive,
                    platformQueryOk = true,
                )
            }
        } catch (_: RuntimeException) {
            base.copy(
                batteryExempt = false,
                batteryBackgroundRestricted = true,
                batteryReady = false,
                allFilesAccess = false,
                usageAccess = false,
                notificationsAllowed = false,
                coarseLocationAllowed = false,
                deviceAdminActive = false,
                deviceOwnerActive = false,
                platformQueryOk = false,
            )
        }
        cached.set(refreshed)
        if (refreshed != base) notifyListeners()
        return refreshed
    }

    fun markWizardCompleted() {
        val before = cached.get()
        val after = cached.updateAndGet { it.copy(wizardCompleted = true) }
        if (after != before) notifyListeners()
        persistSetup { edit ->
            edit.putBoolean(KEY_WIZARD_COMPLETED, true)
                .putInt(KEY_WIZARD_VERSION, CURRENT_WIZARD_VERSION)
        }
    }

    fun resetWizard() {
        val before = cached.get()
        val after = cached.updateAndGet { it.copy(wizardCompleted = false) }
        if (after != before) notifyListeners()
        persistSetup { edit ->
            edit.putBoolean(KEY_WIZARD_COMPLETED, false)
                .remove(KEY_WIZARD_VERSION)
        }
    }

    fun requestTitanLightAdmin(activity: Activity): Boolean {
        if (isDeviceAdminActive()) return true
        val admin = ComponentName(activity, TitanDeviceAdminReceiver::class.java)
        val intent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
            putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, admin)
            putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, activity.getString(R.string.setup_titan_light_admin_explanation))
        }
        return safeStart(activity, intent)
    }

    fun openBatteryOptimizationSettings(activity: Activity): Boolean {
        if (isBatteryOptimizationExempt()) return true
        if (safeStart(activity, Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))) return true
        return openAppDetails(activity)
    }

    fun openAllFilesAccess(activity: Activity): Boolean {
        if (Build.VERSION.SDK_INT < 30) return false
        val perApp = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
            data = Uri.parse("package:${activity.packageName}")
        }
        if (safeStart(activity, perApp)) return true
        return safeStart(activity, Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
    }

    fun openUsageAccess(activity: Activity): Boolean = safeStart(activity, Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
    fun openVpnSettings(activity: Activity): Boolean = safeStart(activity, Intent(Settings.ACTION_VPN_SETTINGS))

    fun openNotificationSettings(activity: Activity): Boolean {
        val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
            putExtra(Settings.EXTRA_APP_PACKAGE, activity.packageName)
        }
        return safeStart(activity, intent)
    }

    fun openAutostartSettings(activity: Activity): Boolean {
        val manufacturer = Build.MANUFACTURER.lowercase()
        val candidates = when {
            "xiaomi" in manufacturer || "redmi" in manufacturer -> listOf(
                ComponentName("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity"),
            )
            "huawei" in manufacturer || "honor" in manufacturer -> listOf(
                ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity"),
                ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.optimize.process.ProtectActivity"),
            )
            "oppo" in manufacturer || "realme" in manufacturer || "oneplus" in manufacturer -> listOf(
                ComponentName("com.oplus.safecenter", "com.oplus.safecenter.startupapp.StartupAppListActivity"),
                ComponentName("com.coloros.safecenter", "com.coloros.safecenter.permission.startup.StartupAppListActivity"),
            )
            "vivo" in manufacturer || "iqoo" in manufacturer -> listOf(
                ComponentName("com.vivo.permissionmanager", "com.vivo.permissionmanager.activity.BgStartUpManagerActivity"),
                ComponentName("com.iqoo.secure", "com.iqoo.secure.ui.phoneoptimize.AddWhiteListActivity"),
            )
            "asus" in manufacturer -> listOf(
                ComponentName("com.asus.mobilemanager", "com.asus.mobilemanager.entry.FunctionActivity"),
            )
            else -> emptyList()
        }
        markAutostartVisited()
        candidates.forEach { component ->
            if (safeStart(activity, Intent().setComponent(component).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))) return true
        }
        return openAppDetails(activity)
    }

    fun openAppDetails(activity: Activity): Boolean {
        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.parse("package:${activity.packageName}")
        }
        return safeStart(activity, intent)
    }

    private fun markAutostartVisited() {
        val before = cached.get()
        val after = cached.updateAndGet { it.copy(autostartVisited = true) }
        if (after != before) notifyListeners()
        persistSetup { it.putBoolean(KEY_AUTOSTART_VISITED, true) }
    }

    private fun notifyListeners() {
        listeners.forEach { listener ->
            try { listener() } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("device-setup-manager", error) }
        }
    }

    private fun persistSetup(block: (android.content.SharedPreferences.Editor) -> android.content.SharedPreferences.Editor) {
        try {
            executor.execute {
                val prefs = appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                val ok = try { block(prefs.edit()).commit() } catch (_: RuntimeException) { false }
                if (!ok) Log.w(LOG_TAG, "setup_state_commit_failed")
            }
        } catch (_: RejectedExecutionException) {
            Log.w(LOG_TAG, "setup_state_commit_rejected")
        }
    }

    private fun safeStart(activity: Activity, intent: Intent): Boolean = try {
        activity.startActivity(intent)
        true
    } catch (_: ActivityNotFoundException) {
        false
    } catch (_: SecurityException) {
        false
    } catch (_: RuntimeException) {
        false
    }

    private fun conservativeSnapshot() = DeviceSetupSnapshot(
        batteryExempt = false,
        batteryBackgroundRestricted = true,
        batteryReady = false,
        allFilesAccess = false,
        usageAccess = false,
        notificationsAllowed = Build.VERSION.SDK_INT < 33,
        coarseLocationAllowed = false,
        autostartVisited = false,
        deviceAdminActive = false,
        deviceOwnerActive = false,
        wizardCompleted = false,
        platformQueryOk = false,
    )

    companion object {
        private const val LOG_TAG = "GeDefenseSetup"
        private const val PREFS = "gedefense_setup"
        private const val KEY_WIZARD_COMPLETED = "wizard_completed"
        private const val KEY_AUTOSTART_VISITED = "autostart_visited"
        private const val KEY_WIZARD_VERSION = "wizard_version"
        private const val CURRENT_WIZARD_VERSION = 2
        private const val MAX_PREFERENCE_WAIT_MS = 1_000L
    }
}
