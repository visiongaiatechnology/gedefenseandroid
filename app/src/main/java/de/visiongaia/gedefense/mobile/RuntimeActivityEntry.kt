package de.visiongaia.gedefense.mobile

import android.app.Activity
import android.content.Intent

// STATUS: PLATIN
/**
 * Non-blocking Activity boundary for the process-scoped AppRuntime.
 *
 * Android may recreate an internal Activity immediately after process death while Application has
 * only just started asynchronous runtime composition. Internal screens must never block or throw on
 * the main thread in that window. They are redirected through StartupActivity, which owns bounded
 * readiness/error rendering.
 */
object RuntimeActivityEntry {
    fun requireReady(activity: Activity): AppRuntime? {
        AppRuntime.peek()?.let { return it }
        AppRuntime.initializeAsync(activity.applicationContext)
        activity.startActivity(
            Intent(activity, StartupActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP),
        )
        activity.finish()
        return null
    }
}
