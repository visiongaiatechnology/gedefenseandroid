package de.visiongaia.gedefense.mobile

import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.Drawable
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.InsetDrawable
import android.graphics.drawable.LayerDrawable
import android.graphics.drawable.StateListDrawable
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import java.text.DateFormat
import java.util.Date
import java.util.Locale

object GeDefenseUi {
    val bg = Color.rgb(2, 7, 13)
    val panel = Color.argb(224, 7, 19, 30)
    val panelStrong = Color.argb(242, 8, 23, 36)
    val panelSoft = Color.argb(168, 11, 31, 47)
    val text = Color.rgb(246, 249, 252)
    val textMuted = Color.rgb(164, 184, 201)
    val textDim = Color.rgb(103, 128, 148)
    val cyan = Color.rgb(55, 221, 255)
    val blue = Color.rgb(45, 137, 255)
    val gold = Color.rgb(245, 201, 91)
    val goldSoft = Color.rgb(221, 176, 69)
    val goldDeep = Color.rgb(151, 105, 25)
    val green = Color.rgb(54, 230, 171)
    val red = Color.rgb(255, 84, 103)
    val orange = Color.rgb(255, 174, 70)
    val border = Color.argb(92, 73, 118, 146)
    val borderSoft = Color.argb(55, 78, 122, 148)
    val borderGold = Color.argb(104, 202, 157, 54)
    val progressTrack = Color.argb(128, 26, 47, 63)

    const val SPACING_SCREEN_HORIZONTAL_DP = 20
    const val SPACING_SECTION_GAP_DP = 22
    const val SPACING_CARD_GAP_DP = 14
    const val SPACING_CARD_HORIZONTAL_GAP_DP = 14
    const val SPACING_DEFAULT_CARD_PADDING_DP = 16
    const val SPACING_DENSE_CARD_PADDING_DP = 14
    const val SPACING_BADGE_INSET_DP = 14

    const val CARD_CONTENT_PADDING_HORIZONTAL_DP = 20
    const val CARD_CONTENT_PADDING_VERTICAL_DP = 18

    const val BOTTOM_NAV_DOCK_HEIGHT_DP = 66
    const val BOTTOM_NAV_MARGIN_DP = 8
    const val BOTTOM_NAV_COMFORT_DP = 20
    const val SCROLL_RESERVED_BOTTOM_PADDING_DP = BOTTOM_NAV_DOCK_HEIGHT_DP + BOTTOM_NAV_MARGIN_DP + BOTTOM_NAV_COMFORT_DP // 94dp

    fun dp(context: Context, value: Int): Int = (value * context.resources.displayMetrics.density).toInt()

    fun screenHorizontalPadding(context: Context): Int = dp(context, SPACING_SCREEN_HORIZONTAL_DP)
    fun screenSectionGap(context: Context): Int = dp(context, SPACING_SECTION_GAP_DP)
    fun cardGap(context: Context): Int = dp(context, SPACING_CARD_GAP_DP)
    fun cardHorizontalGap(context: Context): Int = dp(context, SPACING_CARD_HORIZONTAL_GAP_DP)
    fun defaultCardPadding(context: Context): Int = dp(context, SPACING_DEFAULT_CARD_PADDING_DP)
    fun denseCardPadding(context: Context): Int = dp(context, SPACING_DENSE_CARD_PADDING_DP)
    fun badgeInset(context: Context): Int = dp(context, SPACING_BADGE_INSET_DP)
    fun cardContentPaddingH(context: Context): Int = dp(context, CARD_CONTENT_PADDING_HORIZONTAL_DP)
    fun cardContentPaddingV(context: Context): Int = dp(context, CARD_CONTENT_PADDING_VERTICAL_DP)
    fun scrollReservedBottomPadding(context: Context, extraInsetPx: Int = 0): Int =
        dp(context, SCROLL_RESERVED_BOTTOM_PADDING_DP) + extraInsetPx

    fun panelBackground(
        context: Context,
        strong: Boolean = false,
        goldBorder: Boolean = false,
        radius: Int = 20,
    ): Drawable = glassPanelBackground(
        context = context,
        strong = strong,
        accent = if (goldBorder) gold else null,
        radius = radius,
    )

    fun glassPanelBackground(
        context: Context,
        strong: Boolean = false,
        accent: Int? = null,
        radius: Int = 20,
    ): Drawable {
        val r = dp(context, radius).toFloat()
        val titan = TitanVisualMode.active
        val tint = accent ?: if (titan) gold else cyan
        val fill = GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            if (titan) intArrayOf(
                if (strong) Color.argb(248, 18, 26, 36) else Color.argb(230, 13, 22, 31),
                if (strong) Color.argb(244, 8, 24, 37) else Color.argb(218, 7, 20, 31),
                if (strong) Color.argb(248, 8, 14, 23) else Color.argb(226, 5, 13, 22),
            ) else intArrayOf(
                if (strong) Color.argb(246, 10, 27, 41) else Color.argb(226, 8, 22, 34),
                if (strong) Color.argb(238, 7, 20, 32) else Color.argb(212, 6, 17, 28),
                if (strong) Color.argb(245, 5, 15, 25) else Color.argb(222, 5, 14, 24),
            ),
        ).apply {
            cornerRadius = r
            setStroke(dp(context, 1), if (titan) withAlpha(gold, if (strong) 116 else 78) else if (strong) border else borderSoft)
        }
        val accentWash = GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            intArrayOf(withAlpha(tint, if (strong) 26 else 15), Color.TRANSPARENT, Color.TRANSPARENT),
        ).apply { cornerRadius = r }
        val sheen = GradientDrawable(
            GradientDrawable.Orientation.TOP_BOTTOM,
            intArrayOf(Color.argb(if (strong) 30 else 20, 255, 255, 255), Color.argb(5, 255, 255, 255), Color.TRANSPARENT),
        ).apply { cornerRadius = r }
        val titanEdge = GradientDrawable(
            GradientDrawable.Orientation.LEFT_RIGHT,
            intArrayOf(if (titan) withAlpha(gold, 24) else Color.TRANSPARENT, Color.TRANSPARENT, if (titan) withAlpha(cyan, 15) else Color.TRANSPARENT),
        ).apply { cornerRadius = r }
        return LayerDrawable(arrayOf(fill, accentWash, titanEdge, InsetDrawable(sheen, dp(context, 1))))
    }

    fun heroPanelBackground(context: Context, active: Boolean): Drawable {
        val r = dp(context, 25).toFloat()
        val titan = TitanVisualMode.active
        val base = GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            if (titan) intArrayOf(
                Color.argb(250, 19, 27, 35),
                Color.argb(246, 7, 26, 39),
                Color.argb(250, 8, 16, 26),
            ) else if (active) intArrayOf(
                Color.argb(246, 8, 30, 45),
                Color.argb(240, 7, 23, 37),
                Color.argb(246, 8, 18, 29),
            ) else intArrayOf(
                Color.argb(242, 12, 25, 36),
                Color.argb(238, 8, 18, 29),
                Color.argb(244, 6, 14, 23),
            ),
        ).apply {
            cornerRadius = r
            setStroke(dp(context, 1), if (titan) Color.argb(145, 245, 201, 91) else if (active) Color.argb(105, 223, 182, 71) else Color.argb(76, 128, 138, 146))
        }
        val glow = GradientDrawable(
            GradientDrawable.Orientation.LEFT_RIGHT,
            if (titan) intArrayOf(Color.argb(42, 245, 201, 91), Color.argb(18, 55, 221, 255), Color.TRANSPARENT, Color.argb(30, 245, 201, 91))
            else if (active) intArrayOf(Color.argb(34, 39, 200, 255), Color.TRANSPARENT, Color.argb(20, 242, 193, 67))
            else intArrayOf(Color.argb(14, 218, 176, 68), Color.TRANSPARENT, Color.argb(9, 85, 126, 152)),
        ).apply { cornerRadius = r }
        val highlight = GradientDrawable(
            GradientDrawable.Orientation.TOP_BOTTOM,
            intArrayOf(Color.argb(34, 255, 255, 255), Color.argb(6, 255, 255, 255), Color.TRANSPARENT),
        ).apply { cornerRadius = r }
        return LayerDrawable(arrayOf(base, glow, InsetDrawable(highlight, dp(context, 1))))
    }

    fun softPanelBackground(context: Context, radius: Int = 16, accent: Int? = null): Drawable {
        val r = dp(context, radius).toFloat()
        val titan = TitanVisualMode.active
        val tint = accent ?: if (titan) gold else cyan
        val fill = GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            if (titan) intArrayOf(Color.argb(204, 18, 31, 42), Color.argb(178, 7, 24, 36))
            else intArrayOf(Color.argb(184, 12, 34, 51), Color.argb(157, 7, 23, 36)),
        ).apply {
            cornerRadius = r
            setStroke(dp(context, 1), if (titan) withAlpha(tint, 65) else borderSoft)
        }
        val wash = GradientDrawable(
            GradientDrawable.Orientation.LEFT_RIGHT,
            if (titan) intArrayOf(withAlpha(tint, 20), Color.TRANSPARENT, withAlpha(cyan, 8))
            else intArrayOf(withAlpha(tint, 13), Color.TRANSPARENT),
        ).apply { cornerRadius = r }
        return LayerDrawable(arrayOf(fill, wash))
    }

    fun titanManagedBannerBackground(context: Context): Drawable {
        val r = dp(context, 15).toFloat()
        val base = GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            intArrayOf(Color.argb(246, 29, 29, 27), Color.argb(238, 8, 29, 40), Color.argb(247, 8, 15, 24)),
        ).apply {
            cornerRadius = r
            setStroke(dp(context, 1), withAlpha(gold, 130))
        }
        val sweep = GradientDrawable(
            GradientDrawable.Orientation.LEFT_RIGHT,
            intArrayOf(withAlpha(gold, 35), Color.TRANSPARENT, withAlpha(cyan, 20), Color.TRANSPARENT),
        ).apply { cornerRadius = r }
        return LayerDrawable(arrayOf(base, sweep))
    }

    fun iconWellBackground(context: Context, accent: Int): Drawable {
        val fill = GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            intArrayOf(withAlpha(accent, 28), Color.argb(125, 8, 23, 35)),
        ).apply {
            shape = GradientDrawable.OVAL
            setStroke(dp(context, 1), withAlpha(accent, 72))
        }
        val inner = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setColor(Color.TRANSPARENT)
            setStroke(dp(context, 1), Color.argb(20, 255, 255, 255))
        }
        return LayerDrawable(arrayOf(fill, InsetDrawable(inner, dp(context, 2))))
    }

    fun accentRuleBackground(context: Context, accent: Int): Drawable = GradientDrawable(
        GradientDrawable.Orientation.LEFT_RIGHT,
        if (TitanVisualMode.active && accent == gold)
            intArrayOf(withAlpha(gold, 235), withAlpha(cyan, 155), withAlpha(gold, 55), Color.TRANSPARENT)
        else intArrayOf(withAlpha(accent, 220), withAlpha(accent, 95), Color.TRANSPARENT),
    ).apply { cornerRadius = dp(context, 2).toFloat() }

    fun goldButtonBackground(context: Context): Drawable = buttonState(
        context,
        normal = intArrayOf(Color.rgb(112, 76, 17), Color.rgb(240, 190, 63), Color.rgb(153, 104, 21)),
        pressed = intArrayOf(Color.rgb(95, 62, 12), Color.rgb(214, 165, 50), Color.rgb(129, 86, 16)),
        stroke = Color.argb(170, 255, 225, 143),
    )

    fun darkButtonBackground(context: Context): Drawable = buttonState(
        context,
        normal = if (TitanVisualMode.active)
            intArrayOf(Color.argb(220, 20, 29, 38), Color.argb(214, 8, 34, 48), Color.argb(220, 17, 23, 31))
        else intArrayOf(Color.argb(200, 10, 29, 44), Color.argb(192, 12, 36, 54)),
        pressed = if (TitanVisualMode.active)
            intArrayOf(Color.argb(244, 34, 38, 43), Color.argb(244, 13, 48, 64), Color.argb(244, 27, 30, 35))
        else intArrayOf(Color.argb(240, 14, 38, 56), Color.argb(240, 18, 50, 72)),
        stroke = if (TitanVisualMode.active) withAlpha(gold, 92) else borderSoft,
    )

    fun destructiveButtonBackground(context: Context): Drawable = buttonState(
        context,
        normal = intArrayOf(Color.rgb(76, 25, 35), Color.rgb(122, 35, 49)),
        pressed = intArrayOf(Color.rgb(99, 29, 43), Color.rgb(145, 42, 58)),
        stroke = Color.argb(126, 235, 82, 102),
    )

    fun navSelectedBackground(context: Context): Drawable = GradientDrawable(
        GradientDrawable.Orientation.TL_BR,
        if (TitanVisualMode.active) intArrayOf(Color.argb(28, 245, 201, 91), Color.argb(10, 55, 221, 255), Color.argb(4, 245, 201, 91))
        else intArrayOf(Color.argb(16, 241, 199, 91), Color.argb(3, 241, 199, 91)),
    ).apply {
        cornerRadius = dp(context, 14).toFloat()
        if (TitanVisualMode.active) setStroke(dp(context, 1), withAlpha(gold, 62))
    }

    fun badgeBackground(context: Context, color: Int): GradientDrawable = GradientDrawable().apply {
        setColor(withAlpha(color, 24))
        cornerRadius = dp(context, 10).toFloat()
        setStroke(dp(context, 1), withAlpha(color, 92))
    }

    fun textView(
        context: Context,
        value: CharSequence = "",
        sizeSp: Float = 14f,
        color: Int = text,
        bold: Boolean = false,
    ): TextView = TextView(context).apply {
        text = value
        textSize = sizeSp
        setTextColor(color)
        typeface = Typeface.create(if (bold) "sans-serif-medium" else "sans-serif", Typeface.NORMAL)
        includeFontPadding = false
        setLineSpacing(0f, 1.04f)
    }

    fun displayTextView(
        context: Context,
        value: CharSequence = "",
        sizeSp: Float = 24f,
        color: Int = text,
    ): TextView = TextView(context).apply {
        text = value
        textSize = sizeSp
        setTextColor(color)
        typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
        includeFontPadding = false
        letterSpacing = -0.015f
        setLineSpacing(0f, 1f)
    }

    fun monoTextView(
        context: Context,
        value: CharSequence = "",
        sizeSp: Float = 11f,
        color: Int = textDim,
    ): TextView = TextView(context).apply {
        text = value
        textSize = sizeSp
        setTextColor(color)
        typeface = Typeface.create("monospace", Typeface.NORMAL)
        includeFontPadding = false
    }

    fun actionButton(
        context: Context,
        label: String,
        goldStyle: Boolean = false,
        destructive: Boolean = false,
        action: () -> Unit,
    ): TextView = textView(context, label, 13.5f, if (goldStyle) Color.rgb(19, 19, 18) else text, bold = true).apply {
        gravity = Gravity.CENTER
        minHeight = dp(context, 46)
        setPadding(dp(context, 15), dp(context, 12), dp(context, 15), dp(context, 12))
        background = when {
            destructive -> destructiveButtonBackground(context)
            goldStyle -> goldButtonBackground(context)
            else -> darkButtonBackground(context)
        }
        isClickable = true
        isFocusable = true
        setOnClickListener { action() }
    }

    fun sectionTitle(context: Context, title: String): TextView = textView(context, title, 10.5f, goldSoft, bold = true).apply {
        letterSpacing = 0.12f
        setAllCaps(true)
        setPadding(0, dp(context, 2), 0, dp(context, 2))
    }

    fun pill(context: Context, label: String, color: Int): TextView = textView(context, label, 9.2f, color, bold = true).apply {
        gravity = Gravity.CENTER
        letterSpacing = 0.035f
        setPadding(dp(context, 10), dp(context, 6), dp(context, 10), dp(context, 6))
        background = badgeBackground(context, color)
    }

    fun formatTime(context: Context, value: Long): String = if (value <= 0L) {
        context.getString(R.string.never)
    } else {
        DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(value))
    }

    fun formatCompactTime(context: Context, value: Long): String = if (value <= 0L) {
        context.getString(R.string.never)
    } else {
        DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(value))
    }

    fun formatBytes(value: Long): String = when {
        value < 1024L -> "$value B"
        value < 1024L * 1024L -> String.format(Locale.ROOT, "%.1f KiB", value / 1024.0)
        value < 1024L * 1024L * 1024L -> String.format(Locale.ROOT, "%.1f MiB", value / (1024.0 * 1024.0))
        else -> String.format(Locale.ROOT, "%.2f GiB", value / (1024.0 * 1024.0 * 1024.0))
    }

    fun addVerticalGap(parent: LinearLayout, context: Context, dp: Int) {
        parent.addView(View(context), LinearLayout.LayoutParams(1, GeDefenseUi.dp(context, dp)))
    }

    fun withAlpha(color: Int, alpha: Int): Int = Color.argb(
        alpha.coerceIn(0, 255),
        Color.red(color),
        Color.green(color),
        Color.blue(color),
    )

    private fun buttonState(context: Context, normal: IntArray, pressed: IntArray, stroke: Int): Drawable {
        fun item(colors: IntArray) = GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT, colors).apply {
            cornerRadius = dp(context, 16).toFloat()
            setStroke(dp(context, 1), stroke)
        }
        return StateListDrawable().apply {
            addState(intArrayOf(android.R.attr.state_pressed), item(pressed))
            addState(intArrayOf(), item(normal))
        }
    }
}

fun View.linearMargins(left: Int = 0, top: Int = 0, right: Int = 0, bottom: Int = 0) {
    val lp = layoutParams as? LinearLayout.LayoutParams ?: return
    lp.setMargins(left, top, right, bottom)
    layoutParams = lp
}
