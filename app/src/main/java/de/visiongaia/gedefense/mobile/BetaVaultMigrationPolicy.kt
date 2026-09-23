package de.visiongaia.gedefense.mobile

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build

// STATUS: DIAMANT VGT SUPREME
/**
 * One-release compatibility gate for pre-public 0.27.x vault migration residue.
 *
 * The beta AES rollout exposed a small class of already-authenticated local stores whose historical
 * outer snapshot could no longer be authenticated on a subset of upgrade installs. Reconstructible
 * stores may be archived and rebuilt only while installing VC43, only on an actual package update,
 * and only when the invalid file predates that update. Fresh installs and post-update tampering are
 * therefore never silently healed by this compatibility path.
 */
internal object BetaVaultMigrationPolicy {
    const val RECOVERY_VERSION_CODE = 43

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
        val versionCode = info.longVersionCode
        if (versionCode != RECOVERY_VERSION_CODE.toLong()) return null
        val first = info.firstInstallTime
        val updated = info.lastUpdateTime
        if (first <= 0L || updated <= first) return null
        return updated
    }
}
