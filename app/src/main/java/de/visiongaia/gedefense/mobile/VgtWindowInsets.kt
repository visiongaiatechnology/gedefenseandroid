package de.visiongaia.gedefense.mobile

import android.graphics.Color
import android.os.Build
import android.view.View
import android.view.Window
import android.view.WindowInsets
import android.view.WindowManager
import kotlin.math.max

/**
 * Central compatibility boundary for safe-area insets.
 *
 * Android 11+ uses typed inset sources. Android 10 is isolated behind the deprecated compatibility
 * bridge so activities do not duplicate legacy API access and can migrate as one unit when minSdk
 * advances.
 */
object VgtWindowInsets {
    data class SafeArea(val left: Int, val top: Int, val right: Int, val bottom: Int)

    @Suppress("DEPRECATION")
    fun configureSystemBars(window: Window) {
        window.statusBarColor = Color.TRANSPARENT
        window.navigationBarColor = Color.TRANSPARENT
        window.decorView.systemUiVisibility =
            View.SYSTEM_UI_FLAG_LAYOUT_STABLE or
                View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or
                View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
        window.attributes = window.attributes.apply {
            layoutInDisplayCutoutMode = WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES
        }
        window.isNavigationBarContrastEnforced = false
    }

    fun safeArea(insets: WindowInsets): SafeArea {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val safe = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
            SafeArea(safe.left, safe.top, safe.right, safe.bottom)
        } else {
            legacySafeArea(insets)
        }
    }

    @Suppress("DEPRECATION")
    private fun legacySafeArea(insets: WindowInsets): SafeArea {
        val cutout = insets.displayCutout
        return SafeArea(
            left = max(insets.systemWindowInsetLeft, cutout?.safeInsetLeft ?: 0),
            top = max(insets.systemWindowInsetTop, cutout?.safeInsetTop ?: 0),
            right = max(insets.systemWindowInsetRight, cutout?.safeInsetRight ?: 0),
            bottom = max(insets.systemWindowInsetBottom, cutout?.safeInsetBottom ?: 0),
        )
    }
}
