package de.visiongaia.gedefense.mobile

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RadialGradient
import android.graphics.RectF
import android.graphics.Shader
import android.view.View
import kotlin.math.cos
import kotlin.math.sin

// STATUS: DIAMANT VGT SUPREME
/** Lightweight launch-only security-core visualization. No allocations occur in onDraw(). */
class StartupCoreView(context: Context) : View(context) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val hexPath = Path()
    private val arcRect = RectF()
    private val progressRect = RectF()
    private val activeProgressRect = RectF()
    private var glow: Shader? = null
    private var scanLine: Shader? = null
    private var progressGradient: Shader? = null
    private var phase = 0f
    private var readiness = 0.08f
    private var radius = 0f
    private val ticker = VgtFrameTicker(this, 4_800L) { value ->
        phase = value * 360f
    }

    fun setReadiness(value: Float) {
        readiness = value.coerceIn(0f, 1f)
        invalidate()
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        ticker.start()
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
        if (w <= 0 || h <= 0) return
        val cx = w / 2f
        val cy = h / 2f
        radius = minOf(w, h) * 0.46f
        arcRect.set(cx - radius * 0.92f, cy - radius * 0.92f, cx + radius * 0.92f, cy + radius * 0.92f)
        glow = RadialGradient(
            cx,
            cy,
            radius,
            intArrayOf(
                Color.argb(92, 37, 219, 255),
                Color.argb(42, 19, 112, 183),
                Color.argb(19, 245, 201, 91),
                Color.TRANSPARENT,
            ),
            floatArrayOf(0f, 0.43f, 0.72f, 1f),
            Shader.TileMode.CLAMP,
        )
        scanLine = LinearGradient(
            0f,
            cy - radius,
            0f,
            cy + radius,
            intArrayOf(Color.TRANSPARENT, Color.argb(95, 55, 221, 255), Color.TRANSPARENT),
            floatArrayOf(0f, 0.5f, 1f),
            Shader.TileMode.CLAMP,
        )
        progressRect.set(
            cx - radius * 0.62f,
            cy + radius * 0.67f,
            cx + radius * 0.62f,
            cy + radius * 0.71f,
        )
        progressGradient = LinearGradient(
            progressRect.left,
            0f,
            progressRect.right,
            0f,
            GeDefenseUi.gold,
            GeDefenseUi.cyan,
            Shader.TileMode.CLAMP,
        )
        rebuildHexPath(cx, cy, radius * 0.52f)
    }

    private fun rebuildHexPath(cx: Float, cy: Float, r: Float) {
        hexPath.reset()
        repeat(6) { index ->
            val angle = Math.toRadians(index * 60.0 - 30.0)
            val x = cx + cos(angle).toFloat() * r
            val y = cy + sin(angle).toFloat() * r
            if (index == 0) hexPath.moveTo(x, y) else hexPath.lineTo(x, y)
        }
        hexPath.close()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (radius <= 0f) return
        val cx = width / 2f
        val cy = height / 2f

        paint.style = Paint.Style.FILL
        paint.shader = glow
        canvas.drawCircle(cx, cy, radius, paint)
        paint.shader = null

        paint.style = Paint.Style.STROKE
        paint.strokeCap = Paint.Cap.ROUND
        paint.strokeWidth = GeDefenseUi.dp(context, 1).toFloat()
        RINGS.forEachIndexed { index, fraction ->
            paint.color = if (index % 2 == 0) Color.argb(62, 55, 221, 255) else Color.argb(46, 245, 201, 91)
            canvas.drawCircle(cx, cy, radius * fraction, paint)
        }

        canvas.save()
        canvas.rotate(phase * 0.16f, cx, cy)
        paint.strokeWidth = GeDefenseUi.dp(context, 1).toFloat()
        repeat(12) { index ->
            val angle = Math.toRadians(index * 30.0)
            val inner = radius * if (index % 2 == 0) 0.60f else 0.69f
            val outer = radius * 0.87f
            paint.color = if (index % 3 == 0) Color.argb(58, 245, 201, 91) else Color.argb(46, 55, 221, 255)
            canvas.drawLine(
                cx + cos(angle).toFloat() * inner,
                cy + sin(angle).toFloat() * inner,
                cx + cos(angle).toFloat() * outer,
                cy + sin(angle).toFloat() * outer,
                paint,
            )
        }
        canvas.restore()

        paint.strokeWidth = GeDefenseUi.dp(context, 2).toFloat()
        paint.color = Color.argb(190, 55, 221, 255)
        canvas.drawArc(arcRect, phase, 74f, false, paint)
        paint.color = Color.argb(152, 245, 201, 91)
        canvas.drawArc(arcRect, phase + 168f, 42f, false, paint)

        paint.strokeWidth = GeDefenseUi.dp(context, 2).toFloat()
        paint.color = Color.argb(150, 222, 241, 249)
        canvas.drawPath(hexPath, paint)

        paint.style = Paint.Style.FILL
        paint.color = Color.argb(76, 55, 221, 255)
        canvas.drawRoundRect(progressRect, radius * 0.02f, radius * 0.02f, paint)
        activeProgressRect.set(
            progressRect.left,
            progressRect.top,
            progressRect.left + progressRect.width() * readiness,
            progressRect.bottom,
        )
        paint.shader = progressGradient
        canvas.drawRoundRect(activeProgressRect, radius * 0.02f, radius * 0.02f, paint)
        paint.shader = null

        // Narrow moving scan plane gives the core a live boot/readiness feel without allocations.
        canvas.save()
        val scanOffset = ((phase / 360f) * radius * 1.6f) - radius * 0.8f
        canvas.translate(0f, scanOffset)
        paint.shader = scanLine
        paint.alpha = 95
        canvas.drawRect(cx - radius * 0.55f, cy - radius * 0.08f, cx + radius * 0.55f, cy + radius * 0.08f, paint)
        paint.alpha = 255
        paint.shader = null
        canvas.restore()
    }

    companion object {
        private val RINGS = floatArrayOf(0.43f, 0.60f, 0.76f, 0.94f)
    }
}
