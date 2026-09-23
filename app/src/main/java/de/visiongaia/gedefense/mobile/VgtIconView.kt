package de.visiongaia.gedefense.mobile

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.view.View
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin

/** Small dependency-free line-icon system used across the GeDefense UI. */
enum class VgtIcon {
    HOME,
    ACTIVITY,
    SHIELD,
    EVIDENCE,
    MORE,
    PAUSE,
    ACTIVATE,
    SYNC,
    SETTINGS,
    ROUTES,
    HEALTH,
    INTELLIGENCE,
    ALERT,
    INTEGRITY,
    SCANNER,
    TRAFFIC,
    COUNTRY,
    MAP,
    BLOCK,
    CORRELATE,
    ANNOTATE,
    POLICY,
    CLOUD,
    BELL,
    CHEVRON,
}

class VgtIconView @JvmOverloads constructor(
    context: Context,
    var icon: VgtIcon = VgtIcon.SHIELD,
    var iconColor: Int = GeDefenseUi.text,
) : View(context) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
    }
    private val fill = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.FILL }
    private val path = Path()

    init {
        importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO
    }

    fun setIconState(next: VgtIcon, color: Int = iconColor) {
        icon = next
        iconColor = color
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val side = min(width, height).toFloat()
        if (side <= 0f) return
        val ox = (width - side) / 2f
        val oy = (height - side) / 2f
        canvas.save()
        canvas.translate(ox, oy)
        paint.color = iconColor
        fill.color = iconColor
        paint.strokeWidth = side * 0.075f
        path.reset()
        when (icon) {
            VgtIcon.HOME -> drawHome(canvas, side)
            VgtIcon.ACTIVITY -> drawActivity(canvas, side)
            VgtIcon.SHIELD, VgtIcon.INTEGRITY -> drawShield(canvas, side, icon == VgtIcon.INTEGRITY)
            VgtIcon.EVIDENCE -> drawDocument(canvas, side)
            VgtIcon.MORE -> drawMore(canvas, side)
            VgtIcon.PAUSE -> drawPause(canvas, side)
            VgtIcon.ACTIVATE -> drawActivate(canvas, side)
            VgtIcon.SYNC -> drawSync(canvas, side)
            VgtIcon.SETTINGS -> drawSettings(canvas, side)
            VgtIcon.ROUTES -> drawRoutes(canvas, side)
            VgtIcon.HEALTH -> drawHealth(canvas, side)
            VgtIcon.INTELLIGENCE -> drawRadar(canvas, side)
            VgtIcon.ALERT -> drawAlert(canvas, side)
            VgtIcon.SCANNER -> drawScanner(canvas, side)
            VgtIcon.TRAFFIC -> drawTraffic(canvas, side)
            VgtIcon.COUNTRY -> drawCountry(canvas, side)
            VgtIcon.MAP -> drawMap(canvas, side)
            VgtIcon.BLOCK -> drawBlock(canvas, side)
            VgtIcon.CORRELATE -> drawCorrelate(canvas, side)
            VgtIcon.ANNOTATE -> drawAnnotate(canvas, side)
            VgtIcon.POLICY -> drawPolicy(canvas, side)
            VgtIcon.CLOUD -> drawCloud(canvas, side)
            VgtIcon.BELL -> drawBell(canvas, side)
            VgtIcon.CHEVRON -> drawChevron(canvas, side)
        }
        canvas.restore()
    }

    private fun drawHome(c: Canvas, s: Float) {
        path.moveTo(s * .18f, s * .48f); path.lineTo(s * .5f, s * .2f); path.lineTo(s * .82f, s * .48f)
        path.moveTo(s * .25f, s * .43f); path.lineTo(s * .25f, s * .79f); path.lineTo(s * .75f, s * .79f); path.lineTo(s * .75f, s * .43f)
        c.drawPath(path, paint)
    }

    private fun drawActivity(c: Canvas, s: Float) {
        val xs = floatArrayOf(.23f, .42f, .61f, .8f)
        val tops = floatArrayOf(.55f, .36f, .47f, .22f)
        xs.forEachIndexed { i, x -> c.drawLine(s * x, s * .78f, s * x, s * tops[i], paint) }
    }

    private fun drawShield(c: Canvas, s: Float, check: Boolean) {
        path.moveTo(s * .5f, s * .14f); path.lineTo(s * .78f, s * .26f); path.lineTo(s * .74f, s * .58f)
        path.quadTo(s * .69f, s * .78f, s * .5f, s * .87f); path.quadTo(s * .31f, s * .78f, s * .26f, s * .58f)
        path.lineTo(s * .22f, s * .26f); path.close(); c.drawPath(path, paint)
        if (check) {
            path.reset(); path.moveTo(s * .35f, s * .51f); path.lineTo(s * .46f, s * .62f); path.lineTo(s * .67f, s * .39f); c.drawPath(path, paint)
        }
    }

    private fun drawDocument(c: Canvas, s: Float) {
        val r = RectF(s * .25f, s * .16f, s * .73f, s * .84f); c.drawRoundRect(r, s * .05f, s * .05f, paint)
        c.drawLine(s * .36f, s * .38f, s * .63f, s * .38f, paint); c.drawLine(s * .36f, s * .53f, s * .63f, s * .53f, paint); c.drawLine(s * .36f, s * .68f, s * .56f, s * .68f, paint)
    }

    private fun drawMore(c: Canvas, s: Float) {
        fill.color = iconColor
        listOf(.28f, .5f, .72f).forEach { c.drawCircle(s * it, s * .5f, s * .055f, fill) }
    }

    private fun drawPause(c: Canvas, s: Float) {
        paint.strokeWidth = s * .11f; c.drawLine(s * .38f, s * .27f, s * .38f, s * .73f, paint); c.drawLine(s * .62f, s * .27f, s * .62f, s * .73f, paint)
    }

    private fun drawActivate(c: Canvas, s: Float) {
        paint.strokeWidth = s * .085f
        val r = RectF(s * .22f, s * .22f, s * .78f, s * .78f)
        c.drawArc(r, -42f, 264f, false, paint)
        c.drawLine(s * .5f, s * .16f, s * .5f, s * .49f, paint)
    }

    private fun drawSync(c: Canvas, s: Float) {
        val r = RectF(s * .2f, s * .2f, s * .8f, s * .8f); c.drawArc(r, -45f, 190f, false, paint); c.drawArc(r, 135f, 190f, false, paint)
        path.moveTo(s * .77f, s * .24f); path.lineTo(s * .8f, s * .43f); path.lineTo(s * .62f, s * .38f); c.drawPath(path, paint)
        path.reset(); path.moveTo(s * .23f, s * .76f); path.lineTo(s * .2f, s * .57f); path.lineTo(s * .38f, s * .62f); c.drawPath(path, paint)
    }

    private fun drawSettings(c: Canvas, s: Float) {
        c.drawCircle(s * .5f, s * .5f, s * .16f, paint)
        for (i in 0 until 8) {
            val a = Math.toRadians((i * 45.0) - 90.0); val x1 = s * .5f + cos(a).toFloat() * s * .25f; val y1 = s * .5f + sin(a).toFloat() * s * .25f
            val x2 = s * .5f + cos(a).toFloat() * s * .36f; val y2 = s * .5f + sin(a).toFloat() * s * .36f; c.drawLine(x1, y1, x2, y2, paint)
        }
    }

    private fun drawRoutes(c: Canvas, s: Float) {
        c.drawCircle(s * .27f, s * .29f, s * .07f, paint); c.drawCircle(s * .72f, s * .7f, s * .07f, paint)
        path.moveTo(s * .33f, s * .33f); path.cubicTo(s * .66f, s * .34f, s * .33f, s * .66f, s * .66f, s * .67f); c.drawPath(path, paint)
    }

    private fun drawHealth(c: Canvas, s: Float) {
        path.moveTo(s * .16f, s * .54f); path.lineTo(s * .33f, s * .54f); path.lineTo(s * .41f, s * .33f); path.lineTo(s * .52f, s * .69f); path.lineTo(s * .6f, s * .48f); path.lineTo(s * .83f, s * .48f); c.drawPath(path, paint)
    }

    private fun drawRadar(c: Canvas, s: Float) {
        c.drawCircle(s * .5f, s * .5f, s * .31f, paint); c.drawCircle(s * .5f, s * .5f, s * .18f, paint); c.drawLine(s * .5f, s * .5f, s * .72f, s * .29f, paint); c.drawCircle(s * .68f, s * .35f, s * .045f, fill)
    }

    private fun drawAlert(c: Canvas, s: Float) {
        path.moveTo(s * .5f, s * .16f); path.lineTo(s * .83f, s * .79f); path.lineTo(s * .17f, s * .79f); path.close(); c.drawPath(path, paint)
        c.drawLine(s * .5f, s * .38f, s * .5f, s * .57f, paint); c.drawCircle(s * .5f, s * .68f, s * .035f, fill)
    }

    private fun drawScanner(c: Canvas, s: Float) {
        val a = s * .2f; val b = s * .8f; val d = s * .16f
        c.drawLine(a, a + d, a, a, paint); c.drawLine(a, a, a + d, a, paint); c.drawLine(b - d, a, b, a, paint); c.drawLine(b, a, b, a + d, paint)
        c.drawLine(a, b - d, a, b, paint); c.drawLine(a, b, a + d, b, paint); c.drawLine(b - d, b, b, b, paint); c.drawLine(b, b - d, b, b, paint); c.drawCircle(s * .5f, s * .5f, s * .12f, paint)
    }

    private fun drawTraffic(c: Canvas, s: Float) {
        c.drawLine(s * .33f, s * .74f, s * .33f, s * .28f, paint); path.moveTo(s * .22f, s * .4f); path.lineTo(s * .33f, s * .28f); path.lineTo(s * .44f, s * .4f); c.drawPath(path, paint)
        path.reset(); c.drawLine(s * .67f, s * .26f, s * .67f, s * .72f, paint); path.moveTo(s * .56f, s * .6f); path.lineTo(s * .67f, s * .72f); path.lineTo(s * .78f, s * .6f); c.drawPath(path, paint)
    }

    private fun drawCountry(c: Canvas, s: Float) {
        c.drawCircle(s * .5f, s * .5f, s * .32f, paint); c.drawOval(RectF(s * .36f, s * .18f, s * .64f, s * .82f), paint); c.drawLine(s * .2f, s * .5f, s * .8f, s * .5f, paint)
    }

    private fun drawMap(c: Canvas, s: Float) {
        path.moveTo(s * .16f, s * .28f); path.lineTo(s * .38f, s * .2f); path.lineTo(s * .62f, s * .28f); path.lineTo(s * .84f, s * .2f)
        path.lineTo(s * .84f, s * .72f); path.lineTo(s * .62f, s * .8f); path.lineTo(s * .38f, s * .72f); path.lineTo(s * .16f, s * .8f); path.close(); c.drawPath(path, paint)
        c.drawLine(s * .38f, s * .2f, s * .38f, s * .72f, paint); c.drawLine(s * .62f, s * .28f, s * .62f, s * .8f, paint)
        c.drawCircle(s * .53f, s * .48f, s * .055f, fill)
    }

    private fun drawBlock(c: Canvas, s: Float) {
        c.drawCircle(s * .5f, s * .5f, s * .31f, paint); c.drawLine(s * .28f, s * .72f, s * .72f, s * .28f, paint)
    }

    private fun drawCorrelate(c: Canvas, s: Float) {
        val pts = arrayOf(.28f to .34f, .7f to .3f, .5f to .7f)
        c.drawLine(s * pts[0].first, s * pts[0].second, s * pts[1].first, s * pts[1].second, paint); c.drawLine(s * pts[1].first, s * pts[1].second, s * pts[2].first, s * pts[2].second, paint); c.drawLine(s * pts[2].first, s * pts[2].second, s * pts[0].first, s * pts[0].second, paint)
        pts.forEach { c.drawCircle(s * it.first, s * it.second, s * .065f, fill) }
    }

    private fun drawAnnotate(c: Canvas, s: Float) {
        c.drawCircle(s * .5f, s * .5f, s * .31f, paint); c.drawCircle(s * .5f, s * .34f, s * .035f, fill); c.drawLine(s * .5f, s * .47f, s * .5f, s * .68f, paint)
    }

    private fun drawPolicy(c: Canvas, s: Float) {
        val ys = floatArrayOf(.3f, .5f, .7f); val knobs = floatArrayOf(.62f, .38f, .58f)
        ys.forEachIndexed { i, y -> c.drawLine(s * .23f, s * y, s * .77f, s * y, paint); c.drawCircle(s * knobs[i], s * y, s * .055f, fill) }
    }

    private fun drawBell(c: Canvas, s: Float) {
        path.moveTo(s * .29f, s * .65f)
        path.quadTo(s * .36f, s * .57f, s * .36f, s * .42f)
        path.quadTo(s * .36f, s * .23f, s * .5f, s * .23f)
        path.quadTo(s * .64f, s * .23f, s * .64f, s * .42f)
        path.quadTo(s * .64f, s * .57f, s * .71f, s * .65f)
        path.lineTo(s * .29f, s * .65f)
        c.drawPath(path, paint)
        c.drawLine(s * .39f, s * .73f, s * .61f, s * .73f, paint)
        c.drawCircle(s * .5f, s * .79f, s * .03f, fill)
    }

    private fun drawChevron(c: Canvas, s: Float) {
        paint.strokeWidth = s * .09f
        path.moveTo(s * .38f, s * .25f)
        path.lineTo(s * .63f, s * .5f)
        path.lineTo(s * .38f, s * .75f)
        c.drawPath(path, paint)
    }

    private fun drawCloud(c: Canvas, s: Float) {
        path.moveTo(s * .27f, s * .69f); path.cubicTo(s * .12f, s * .66f, s * .14f, s * .45f, s * .31f, s * .43f)
        path.cubicTo(s * .35f, s * .23f, s * .64f, s * .23f, s * .69f, s * .43f); path.cubicTo(s * .86f, s * .45f, s * .86f, s * .68f, s * .7f, s * .69f); path.close(); c.drawPath(path, paint)
    }
}
