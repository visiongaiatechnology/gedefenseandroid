package androidx.core.content

import android.content.Context

/**
 * Minimal zero-dependency platform shim for vendored JourneyApps/ZXing CaptureManager
 * (which invokes ContextCompat.checkSelfPermission on API 23+).
 */
object ContextCompat {
    @JvmStatic
    fun checkSelfPermission(context: Context, permission: String): Int =
        context.checkSelfPermission(permission)
}
