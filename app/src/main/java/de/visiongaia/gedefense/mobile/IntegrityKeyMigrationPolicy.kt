package de.visiongaia.gedefense.mobile

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build

/**
 * One-release recovery boundary for moving the installation baseline away from a historical direct
 * AndroidKeyStore HMAC alias. Recovery is allowed only on a real in-place update to VC57 and only
 * for a baseline whose filesystem timestamp predates Android's package update boundary. Any
 * baseline created or modified after the update must authenticate normally and will never be healed.
 */
internal object IntegrityKeyMigrationPolicy {
    private const val RECOVERY_VERSION_CODE = 57L

    fun updateBoundaryMillis(context: Context): Long? {
        val app = context.applicationContext
        val info = try {
            if (Build.VERSION.SDK_INT >= 33) {
                app.packageManager.getPackageInfo(app.packageName, PackageManager.PackageInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                app.packageManager.getPackageInfo(app.packageName, 0)
            }
        } catch (_: Exception) {
            return null
        }
        if (info.longVersionCode != RECOVERY_VERSION_CODE) return null
        val first = info.firstInstallTime
        val updated = info.lastUpdateTime
        if (first <= 0L || updated <= first) return null
        return updated
    }
}
