package de.visiongaia.gedefense.mobile

import android.app.ActivityManager
import android.animation.ValueAnimator
import android.content.Context
import android.os.PowerManager
import android.os.SystemClock
import android.view.Choreographer
import android.view.View
import android.view.WindowManager
import android.widget.ScrollView
import kotlin.math.abs

// STATUS: DIAMANT VGT SUPREME
/**
 * Central UI motion budget. Security work is never throttled here; only decorative redraw cadence is.
 * The policy deliberately preserves motion while reducing GPU/main-thread contention during gestures,
 * power-save mode and on low-RAM devices.
 */
object VgtUiPerformance {
    private const val INTERACTION_COOLDOWN_MS = 420L
    private const val PLATFORM_REFRESH_MS = 5_000L
    @Volatile private var interactionUntilMillis = 0L
    @Volatile private var platformSnapshot = PlatformSnapshot(false, false, 60f, 0L)
    private val refreshRunning = java.util.concurrent.atomic.AtomicBoolean(false)
    private val platformExecutor = BoundedExecutors.direct("gedefense-ui-platform")

    private data class PlatformSnapshot(
        val lowRam: Boolean,
        val powerSave: Boolean,
        val refreshRate: Float,
        val checkedAtMillis: Long,
    )

    fun noteInteraction(now: Long = SystemClock.uptimeMillis()) {
        val next = now + INTERACTION_COOLDOWN_MS
        if (next > interactionUntilMillis) interactionUntilMillis = next
    }

    fun animationsEnabled(): Boolean = ValueAnimator.areAnimatorsEnabled()

    fun frameIntervalMillis(context: Context, now: Long = SystemClock.uptimeMillis()): Long {
        if (!animationsEnabled()) return Long.MAX_VALUE
        refreshPlatformSnapshotIfStale(context, now)
        val snapshot = platformSnapshot
        if (snapshot.lowRam || snapshot.powerSave) return 100L
        if (now < interactionUntilMillis) return 50L
        return if (snapshot.refreshRate >= 90f) 33L else 40L
    }

    private fun refreshPlatformSnapshotIfStale(context: Context, now: Long) {
        if (now - platformSnapshot.checkedAtMillis < PLATFORM_REFRESH_MS || !refreshRunning.compareAndSet(false, true)) return
        val app = context.applicationContext
        try {
            platformExecutor.execute {
                try {
                    val refreshed = try {
                        BoundedAndroidCall.call {
                            val lowRam = (app.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager)?.isLowRamDevice == true
                            val powerSave = (app.getSystemService(Context.POWER_SERVICE) as? PowerManager)?.isPowerSaveMode == true
                            @Suppress("DEPRECATION")
                            val refreshRate = (app.getSystemService(Context.WINDOW_SERVICE) as? WindowManager)
                                ?.defaultDisplay?.refreshRate
                                ?.takeIf { it in 30f..240f } ?: 60f
                            PlatformSnapshot(lowRam, powerSave, refreshRate, SystemClock.uptimeMillis())
                        }
                    } catch (_: RuntimeException) {
                        platformSnapshot.copy(checkedAtMillis = SystemClock.uptimeMillis())
                    }
                    platformSnapshot = refreshed
                } finally {
                    refreshRunning.set(false)
                }
            }
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            refreshRunning.set(false)
        }
    }

    fun bindScroll(scroll: ScrollView) {
        scroll.setOnScrollChangeListener { _, _, scrollY, _, oldScrollY ->
            if (abs(scrollY - oldScrollY) > 1) noteInteraction()
        }
    }
}

// STATUS: DIAMANT VGT SUPREME
/** Choreographer-backed ticker with adaptive frame skipping and no per-frame animator allocations. */
class VgtFrameTicker(
    private val view: View,
    private val durationMillis: Long,
    private val onPhase: (Float) -> Unit,
) : Choreographer.FrameCallback {
    private var requested = false
    private var running = false
    private var windowVisible = true
    private var lastDrawNanos = 0L

    fun start() {
        requested = true
        syncRunningState()
    }

    fun stop() {
        requested = false
        stopCallbacks()
    }

    /** Called by the owning View from onWindowVisibilityChanged(). */
    fun onWindowVisibilityChanged(visibility: Int) {
        windowVisible = visibility == View.VISIBLE
        syncRunningState()
    }

    private fun syncRunningState() {
        val shouldRun = requested && windowVisible && view.isAttachedToWindow && view.isShown &&
            VgtUiPerformance.animationsEnabled()
        if (shouldRun) {
            if (!running) {
                running = true
                lastDrawNanos = 0L
                Choreographer.getInstance().postFrameCallback(this)
            }
        } else {
            stopCallbacks()
        }
    }

    private fun stopCallbacks() {
        if (!running) return
        running = false
        Choreographer.getInstance().removeFrameCallback(this)
    }

    override fun doFrame(frameTimeNanos: Long) {
        if (!running) return
        if (!requested || !windowVisible || !view.isAttachedToWindow || view.windowVisibility != View.VISIBLE || !view.isShown) {
            // Never poll an invisible/background window. The owner restarts us through
            // onWindowVisibilityChanged()/its own state transition when rendering is useful again.
            stopCallbacks()
            return
        }
        val now = SystemClock.uptimeMillis()
        val intervalMillis = VgtUiPerformance.frameIntervalMillis(view.context, now)
        if (intervalMillis == Long.MAX_VALUE) {
            stopCallbacks()
            return
        }
        val intervalNanos = intervalMillis * 1_000_000L
        if (lastDrawNanos == 0L || frameTimeNanos - lastDrawNanos >= intervalNanos) {
            lastDrawNanos = frameTimeNanos
            val phase = ((now % durationMillis).toDouble() / durationMillis.toDouble()).toFloat()
            onPhase(phase)
            view.invalidate()
        }
        Choreographer.getInstance().postFrameCallback(this)
    }
}
