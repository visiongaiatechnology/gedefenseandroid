package androidx.core.app

import android.app.Activity

/**
 * Minimal zero-dependency platform shim for vendored JourneyApps/ZXing CaptureManager
 * (which invokes ActivityCompat.requestPermissions on API 23+).
 */
object ActivityCompat {
    @JvmStatic
    fun requestPermissions(activity: Activity, permissions: Array<String>, requestCode: Int) {
        activity.requestPermissions(permissions, requestCode)
    }
}
