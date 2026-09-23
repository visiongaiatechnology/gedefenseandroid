package de.visiongaia.gedefense.mobile

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Matrix
import android.graphics.Paint
import android.graphics.RadialGradient
import android.graphics.Shader
import android.view.View

/** Atmospheric-only background with a cached, adaptive TITAN MDM treatment. */
class CyberBackgroundView(context: Context) : View(context) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val sweepMatrix = Matrix()
    private var base: Shader? = null
    private var topGlow: Shader? = null
    private var goldGlow: Shader? = null
    private var lowerGlow: Shader? = null
    private var titanSweep: Shader? = null
    private var titanAtBuild = false
    private var phase = 0f
    private val ticker = VgtFrameTicker(this, 10_500L) { phase = it }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        if (TitanVisualMode.active) ticker.start()
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
        rebuildShaders(w, h)
    }

    private fun rebuildShaders(w: Int, h: Int) {
        if (w <= 0 || h <= 0) return
        titanAtBuild = TitanVisualMode.active
        base = LinearGradient(
            0f, 0f, 0f, h.toFloat(),
            if (titanAtBuild) intArrayOf(Color.rgb(8, 15, 22), Color.rgb(3, 10, 17), Color.rgb(1, 5, 9))
            else intArrayOf(Color.rgb(5, 16, 27), Color.rgb(2, 9, 16), Color.rgb(1, 5, 10)),
            floatArrayOf(0f, .48f, 1f), Shader.TileMode.CLAMP,
        )
        topGlow = RadialGradient(
            w * .62f, h * .10f, w * .74f,
            if (titanAtBuild) intArrayOf(Color.argb(64, 0, 171, 225), Color.argb(17, 0, 91, 143), Color.TRANSPARENT)
            else intArrayOf(Color.argb(55, 0, 146, 213), Color.argb(15, 0, 91, 143), Color.TRANSPARENT),
            floatArrayOf(0f, .5f, 1f), Shader.TileMode.CLAMP,
        )
        goldGlow = RadialGradient(
            w * -.03f, h * .38f, w * .53f,
            if (titanAtBuild) intArrayOf(Color.argb(45, 239, 190, 63), Color.argb(14, 182, 124, 23), Color.TRANSPARENT)
            else intArrayOf(Color.argb(24, 226, 172, 52), Color.argb(6, 182, 124, 23), Color.TRANSPARENT),
            floatArrayOf(0f, .5f, 1f), Shader.TileMode.CLAMP,
        )
        lowerGlow = RadialGradient(
            w * .94f, h * .84f, w * .58f,
            if (titanAtBuild) Color.argb(29, 20, 170, 210) else Color.argb(21, 20, 139, 194),
            Color.TRANSPARENT, Shader.TileMode.CLAMP,
        )
        titanSweep = if (titanAtBuild) LinearGradient(
            -w.toFloat(), 0f, 0f, 0f,
            intArrayOf(Color.TRANSPARENT, Color.argb(12, 245, 201, 91), Color.argb(19, 55, 221, 255), Color.TRANSPARENT),
            floatArrayOf(0f, .38f, .58f, 1f), Shader.TileMode.CLAMP,
        ) else null
        if (titanAtBuild) ticker.start() else ticker.stop()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (titanAtBuild != TitanVisualMode.active) rebuildShaders(width, height)
        drawShader(canvas, base)
        drawShader(canvas, topGlow)
        drawShader(canvas, goldGlow)
        drawShader(canvas, lowerGlow)

        if (titanAtBuild) {
            titanSweep?.let { shader ->
                sweepMatrix.reset()
                sweepMatrix.setTranslate(width * (phase * 2.0f), 0f)
                shader.setLocalMatrix(sweepMatrix)
                paint.shader = shader
                canvas.drawRect(0f, 0f, width.toFloat(), height.toFloat(), paint)
                paint.shader = null
            }
        }

        val spacing = GeDefenseUi.dp(context, if (titanAtBuild) 68 else 76).toFloat().coerceAtLeast(1f)
        paint.strokeWidth = 1f
        paint.color = if (titanAtBuild) Color.argb(12, 197, 168, 84) else Color.argb(7, 95, 174, 211)
        var x = 0f
        while (x <= width) {
            canvas.drawLine(x, 0f, x, height.toFloat(), paint)
            x += spacing
        }
        var y = 0f
        while (y <= height) {
            canvas.drawLine(0f, y, width.toFloat(), y, paint)
            y += spacing
        }

        paint.strokeWidth = GeDefenseUi.dp(context, 1).toFloat()
        paint.color = Color.argb(if (titanAtBuild) 34 else 20, 245, 198, 80)
        canvas.drawLine(width * .03f, height * .17f, width * .29f, height * .04f, paint)
        canvas.drawLine(width * .68f, height * .24f, width * .98f, height * .08f, paint)
        paint.color = Color.argb(if (titanAtBuild) 31 else 18, 51, 204, 255)
        canvas.drawLine(width * .14f, height * .86f, width * .46f, height * .68f, paint)
        canvas.drawLine(width * .63f, height * .96f, width * .95f, height * .78f, paint)

        paint.strokeWidth = GeDefenseUi.dp(context, 2).toFloat()
        paint.color = Color.argb(if (titanAtBuild) 82 else 46, 239, 194, 78)
        canvas.drawLine(width * .075f, height * .073f, width * (if (titanAtBuild) .31f else .22f), height * .073f, paint)
        paint.color = Color.argb(if (titanAtBuild) 60 else 34, 48, 199, 255)
        canvas.drawLine(width * .70f, height * .94f, width * .93f, height * .94f, paint)
    }

    private fun drawShader(canvas: Canvas, shader: Shader?) {
        if (shader == null) return
        paint.shader = shader
        canvas.drawRect(0f, 0f, width.toFloat(), height.toFloat(), paint)
        paint.shader = null
    }
}
