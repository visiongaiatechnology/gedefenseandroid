package de.visiongaia.gedefense.mobile

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RadialGradient
import android.graphics.RectF
import android.graphics.Shader
import android.view.View
import kotlin.math.cos
import kotlin.math.sin

/** Decorative protection-energy field. Inactive mode remains intentionally calm and static. */
class ShieldPulseView(context: Context) : View(context) {
    private data class Ray(val x1: Float, val y1: Float, val x2: Float, val y2: Float, val color: Int)
    private data class Dot(val x: Float, val y: Float, val radius: Float, val color: Int)

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private var phase = 0f
    private var active = false
    private var radius = 0f
    private var glow: Shader? = null
    private var arcRect = RectF()
    private var rays: List<Ray> = emptyList()
    private var dots: List<Dot> = emptyList()
    private val ticker = VgtFrameTicker(this, 10_500L) { phase = it * 360f }

    fun setProtectionActive(value: Boolean) {
        if (active == value) return
        active = value
        rebuildGeometry(width, height)
        updateTicker()
        invalidate()
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        updateTicker()
    }

    override fun onWindowVisibilityChanged(visibility: Int) {
        super.onWindowVisibilityChanged(visibility)
        ticker.onWindowVisibilityChanged(visibility)
    }

    override fun onDetachedFromWindow() {
        ticker.stop()
        super.onDetachedFromWindow()
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        rebuildGeometry(w, h)
    }

    private fun updateTicker() {
        if (isAttachedToWindow && active) ticker.start() else ticker.stop()
        if (!active) phase = 18f
    }

    private fun rebuildGeometry(w: Int, h: Int) {
        if (w <= 0 || h <= 0) return
        val cx = w / 2f
        val cy = h / 2f
        radius = minOf(w, h) * .47f
        val r = radius
        glow = RadialGradient(
            cx, cy, r,
            if (active) intArrayOf(
                Color.argb(96, 22, 201, 255), Color.argb(40, 8, 117, 190),
                Color.argb(14, 234, 184, 54), Color.TRANSPARENT,
            ) else intArrayOf(
                Color.argb(25, 219, 176, 63), Color.argb(12, 32, 75, 101), Color.TRANSPARENT,
            ),
            if (active) floatArrayOf(0f, .43f, .73f, 1f) else floatArrayOf(0f, .58f, 1f),
            Shader.TileMode.CLAMP,
        )
        arcRect = RectF(cx - r * .94f, cy - r * .94f, cx + r * .94f, cy + r * .94f)
        rays = List(16) { i ->
            val angle = Math.toRadians(i * 22.5)
            val inner = r * .46f
            val outer = r * if (i % 2 == 0) .90f else .78f
            Ray(
                cos(angle).toFloat() * inner, sin(angle).toFloat() * inner,
                cos(angle).toFloat() * outer, sin(angle).toFloat() * outer,
                if (i % 3 == 0) Color.argb(34, 244, 199, 79) else Color.argb(28, 56, 213, 255),
            )
        }
        dots = List(12) { i ->
            val angle = Math.toRadians(i * 30.0)
            val rr = r * if (i % 2 == 0) .89f else .72f
            Dot(
                cos(angle).toFloat() * rr,
                sin(angle).toFloat() * rr,
                GeDefenseUi.dp(context, if (i % 3 == 0) 2 else 1).toFloat(),
                if (i % 3 == 0) Color.argb(155, 247, 201, 79) else Color.argb(145, 63, 221, 255),
            )
        }
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val cx = width / 2f
        val cy = height / 2f
        val r = radius
        if (r <= 0f) return

        paint.style = Paint.Style.FILL
        paint.shader = glow
        canvas.drawCircle(cx, cy, r, paint)
        paint.shader = null

        paint.style = Paint.Style.STROKE
        paint.strokeCap = Paint.Cap.ROUND
        paint.strokeWidth = GeDefenseUi.dp(context, 1).toFloat()
        val ringAlpha = if (active) 70 else 28
        RING_FRACTIONS.forEachIndexed { index, fraction ->
            paint.color = if (index % 2 == 0) Color.argb(ringAlpha, 54, 214, 255) else Color.argb(ringAlpha - 10, 243, 196, 75)
            canvas.drawCircle(cx, cy, r * fraction, paint)
        }

        if (active) {
            paint.strokeWidth = GeDefenseUi.dp(context, 1).toFloat()
            canvas.save()
            canvas.rotate(phase * .08f, cx, cy)
            rays.forEach { ray ->
                paint.color = ray.color
                canvas.drawLine(cx + ray.x1, cy + ray.y1, cx + ray.x2, cy + ray.y2, paint)
            }
            canvas.restore()

            paint.strokeWidth = GeDefenseUi.dp(context, 2).toFloat()
            paint.color = Color.argb(155, 52, 219, 255)
            canvas.drawArc(arcRect, phase, 58f, false, paint)
            paint.color = Color.argb(123, 246, 199, 76)
            canvas.drawArc(arcRect, phase + 174f, 38f, false, paint)

            paint.style = Paint.Style.FILL
            canvas.save()
            canvas.rotate(phase * .35f, cx, cy)
            dots.forEach { dot ->
                paint.color = dot.color
                canvas.drawCircle(cx + dot.x, cy + dot.y, dot.radius, paint)
            }
            canvas.restore()
        }
        paint.style = Paint.Style.FILL
    }

    companion object {
        private val RING_FRACTIONS = floatArrayOf(.42f, .61f, .79f, .96f)
    }
}
