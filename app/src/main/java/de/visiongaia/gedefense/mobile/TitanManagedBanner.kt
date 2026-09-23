package de.visiongaia.gedefense.mobile

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.util.AttributeSet
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout

/** App-wide marker for TITAN Light or full Device-Owner TITAN mode. */
class TitanManagedBanner @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : LinearLayout(context, attrs, defStyleAttr) {
    private var onOpenTitan: (() -> Unit)? = null

    constructor(context: Context, onOpenTitan: () -> Unit) : this(context) {
        this.onOpenTitan = onOpenTitan
    }

    init {
        val light = TitanVisualMode.light
        val accent = if (light) GeDefenseUi.cyan else GeDefenseUi.gold
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        minimumHeight = GeDefenseUi.dp(context, 42)
        setPadding(GeDefenseUi.dp(context, 13), GeDefenseUi.dp(context, 8), GeDefenseUi.dp(context, 13), GeDefenseUi.dp(context, 8))
        background = GeDefenseUi.titanManagedBannerBackground(context)
        isClickable = true
        isFocusable = true
        contentDescription = context.getString(if (light) R.string.titan_light_banner_title else R.string.titan_managed_banner_title)
        setOnClickListener { onOpenTitan?.invoke() }

        addView(TitanManagedPulseView(context, accent), LayoutParams(GeDefenseUi.dp(context, 22), GeDefenseUi.dp(context, 22)))
        addView(LinearLayout(context).apply {
            orientation = VERTICAL
            setPadding(GeDefenseUi.dp(context, 10), 0, 0, 0)
            addView(GeDefenseUi.monoTextView(context, context.getString(if (light) R.string.titan_light_banner_title else R.string.titan_managed_banner_title), 9.8f, accent).apply {
                letterSpacing = 0.08f
            })
            addView(GeDefenseUi.textView(context, context.getString(if (light) R.string.titan_light_banner_state else R.string.titan_managed_banner_state), 8.9f, GeDefenseUi.textMuted, bold = true).apply {
                setPadding(0, GeDefenseUi.dp(context, 2), 0, 0)
            })
        }, LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f))
        addView(GeDefenseUi.pill(context, context.getString(if (light) R.string.titan_light_banner_enforced else R.string.titan_managed_banner_enforced), if (light) GeDefenseUi.cyan else GeDefenseUi.green))
    }
}

private class TitanManagedPulseView @JvmOverloads constructor(context: Context, private val accent: Int = GeDefenseUi.gold) : View(context) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private var phase = 0f
    private val ticker = VgtFrameTicker(this, 2_800L) { phase = it }

    override fun onAttachedToWindow() { super.onAttachedToWindow(); ticker.start() }
    override fun onWindowVisibilityChanged(visibility: Int) { super.onWindowVisibilityChanged(visibility); ticker.onWindowVisibilityChanged(visibility) }
    override fun onDetachedFromWindow() { ticker.stop(); super.onDetachedFromWindow() }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val cx = width * 0.5f; val cy = height * 0.5f; val min = minOf(width, height).toFloat()
        val pulse = if (phase < 0.5f) phase * 2f else (1f - phase) * 2f
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = GeDefenseUi.dp(context, 1).toFloat()
        paint.color = if (accent == GeDefenseUi.cyan) Color.argb((40 + 80 * pulse).toInt(), 55, 221, 255) else Color.argb((42 + 82 * pulse).toInt(), 245, 201, 91)
        canvas.drawCircle(cx, cy, min * (0.31f + 0.10f * pulse), paint)
        paint.style = Paint.Style.FILL
        paint.color = accent
        canvas.drawCircle(cx, cy, min * 0.15f, paint)
    }
}
