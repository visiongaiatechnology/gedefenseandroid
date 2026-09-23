package de.visiongaia.gedefense.mobile

import android.content.Context
import android.graphics.Canvas
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Shader
import android.view.View
import kotlin.math.min

class ScannerRadarView(context: Context) : View(context) {
    private val ring = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE }
    private val sweep = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE; strokeCap = Paint.Cap.ROUND }
    private val dot = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.FILL }
    private var running = false
    private var phaseColor = GeDefenseUi.cyan
    private var phase = 0f
    private var radarRect = RectF()
    private var sweepShader: Shader? = null
    private var sizePx = 0f
    private val ticker = VgtFrameTicker(this, 2_800L) { phase = it }

    fun setRunning(value: Boolean, accent: Int = GeDefenseUi.cyan) {
        val colorChanged = phaseColor != accent
        running = value
        phaseColor = accent
        if (colorChanged) rebuildGeometry(width, height)
        if (isAttachedToWindow && running) ticker.start() else ticker.stop()
        invalidate()
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        if (running) ticker.start()
    }

    override fun onWindowVisibilityChanged(visibility: Int) {
        super.onWindowVisibilityChanged(visibility)
        ticker.onWindowVisibilityChanged(visibility)
    }

    override fun onDetachedFromWindow() {
        ticker.stop()
        super.onDetachedFromWindow()
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) = rebuildGeometry(w, h)

    private fun rebuildGeometry(w: Int, h: Int) {
        sizePx = min(w, h).toFloat()
        if (sizePx <= 0f) return
        val cx = w / 2f
        val cy = h / 2f
        val r = sizePx * .40f
        radarRect = RectF(cx - r, cy - r, cx + r, cy + r)
        sweepShader = LinearGradient(
            cx, cy - r, cx + r, cy,
            intArrayOf(GeDefenseUi.withAlpha(phaseColor, 20), GeDefenseUi.withAlpha(phaseColor, 220)),
            null,
            Shader.TileMode.CLAMP,
        )
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val s = sizePx
        if (s <= 0f) return
        val cx = width / 2f
        val cy = height / 2f
        val r = s * .40f
        ring.strokeWidth = s * .008f
        ring.color = GeDefenseUi.withAlpha(phaseColor, 58)
        RINGS.forEach { canvas.drawCircle(cx, cy, r * it, ring) }
        ring.color = GeDefenseUi.withAlpha(GeDefenseUi.gold, 40)
        canvas.drawLine(cx - r, cy, cx + r, cy, ring)
        canvas.drawLine(cx, cy - r, cx, cy + r, ring)

        val angle = if (running) phase * 360f - 90f else -35f
        sweep.strokeWidth = s * .028f
        sweep.shader = sweepShader
        canvas.drawArc(radarRect, angle - 58f, 58f, false, sweep)
        sweep.shader = null

        dot.color = phaseColor
        canvas.drawCircle(cx + r * .52f, cy - r * .25f, s * .016f, dot)
        dot.color = GeDefenseUi.gold
        canvas.drawCircle(cx - r * .38f, cy + r * .48f, s * .012f, dot)

        ring.color = GeDefenseUi.withAlpha(phaseColor, 130)
        ring.strokeWidth = s * .012f
        canvas.drawCircle(cx, cy, s * .085f, ring)
    }

    companion object {
        private val RINGS = floatArrayOf(.34f, .57f, .78f, 1f)
    }
}
