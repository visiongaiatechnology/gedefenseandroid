package de.visiongaia.gedefense.mobile

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.view.View
import kotlin.math.sin

/** Allocation-free ambient TITAN core animation used only on the Device Owner console. */
class TitanCoreView(context: Context) : View(context) {
    var activeState: Boolean = false
        set(value) { field = value; invalidate() }

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val arc = RectF()
    private var phase = 0f
    private val ticker = VgtFrameTicker(this, 4200L) { phase = it }

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

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val cx = width * .5f
        val cy = height * .5f
        val base = minOf(width, height) * .42f
        val pulse = ((sin(phase * Math.PI * 2.0) + 1.0) * .5).toFloat()
        val primary = if (activeState) GeDefenseUi.gold else GeDefenseUi.cyan
        val secondary = GeDefenseUi.cyan

        paint.style = Paint.Style.STROKE
        paint.strokeCap = Paint.Cap.ROUND
        paint.strokeWidth = GeDefenseUi.dp(context, 2).toFloat()
        paint.color = GeDefenseUi.withAlpha(primary, (80 + pulse * 85).toInt())
        arc.set(cx - base, cy - base, cx + base, cy + base)
        canvas.drawArc(arc, -84f + phase * 160f, 215f, false, paint)

        paint.strokeWidth = GeDefenseUi.dp(context, 1).toFloat()
        paint.color = GeDefenseUi.withAlpha(secondary, (54 + (1f - pulse) * 72).toInt())
        val inner = base * .72f
        arc.set(cx - inner, cy - inner, cx + inner, cy + inner)
        canvas.drawArc(arc, 112f - phase * 210f, 245f, false, paint)

        paint.style = Paint.Style.FILL
        paint.color = GeDefenseUi.withAlpha(primary, if (activeState) 33 else 20)
        canvas.drawCircle(cx, cy, base * (.44f + pulse * .05f), paint)
        paint.color = GeDefenseUi.withAlpha(secondary, if (activeState) 28 else 18)
        canvas.drawCircle(cx, cy, base * .28f, paint)

        paint.style = Paint.Style.STROKE
        paint.strokeWidth = GeDefenseUi.dp(context, 1).toFloat()
        paint.color = GeDefenseUi.withAlpha(primary, 145)
        val r = base * .20f
        canvas.drawLine(cx, cy - r, cx + r, cy, paint)
        canvas.drawLine(cx + r, cy, cx, cy + r, paint)
        canvas.drawLine(cx, cy + r, cx - r, cy, paint)
        canvas.drawLine(cx - r, cy, cx, cy - r, paint)
    }
}
