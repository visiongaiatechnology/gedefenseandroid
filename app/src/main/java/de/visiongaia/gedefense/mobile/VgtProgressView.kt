package de.visiongaia.gedefense.mobile

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.view.View

class VgtProgressView @JvmOverloads constructor(
    context: Context,
    private var accent: Int = GeDefenseUi.cyan,
) : View(context) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val trackRect = RectF()
    private val progressRect = RectF()
    private var progress = 0f

    fun setProgress(value: Float, color: Int = accent) {
        progress = value.coerceIn(0f, 1f)
        accent = color
        invalidate()
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val desired = GeDefenseUi.dp(context, 5)
        setMeasuredDimension(MeasureSpec.getSize(widthMeasureSpec), resolveSize(desired, heightMeasureSpec))
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        trackRect.set(0f, 0f, w.toFloat(), h.toFloat())
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val r = height / 2f
        paint.color = GeDefenseUi.progressTrack
        canvas.drawRoundRect(trackRect, r, r, paint)
        if (progress <= 0f) return
        progressRect.set(0f, 0f, width * progress, height.toFloat())
        paint.color = accent
        canvas.drawRoundRect(progressRect, r, r, paint)
    }
}
