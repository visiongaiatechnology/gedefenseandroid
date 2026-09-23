package de.visiongaia.gedefense.mobile

import android.content.Context
import android.view.Gravity
import android.view.View
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView

object VgtUiComponents {
    fun screenHeader(context: Context, title: String, subtitle: String): View = LinearLayout(context).apply {
        orientation = LinearLayout.VERTICAL
        addView(View(context).apply { background = GeDefenseUi.accentRuleBackground(context, if (TitanVisualMode.active) GeDefenseUi.gold else GeDefenseUi.gold) }, LinearLayout.LayoutParams(GeDefenseUi.dp(context, if (TitanVisualMode.active) 82 else 58), GeDefenseUi.dp(context, 2)).apply { bottomMargin = GeDefenseUi.dp(context, 8) })
        addView(GeDefenseUi.displayTextView(context, title, 25f, GeDefenseUi.text))
        if (TitanVisualMode.active) {
            addView(LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(0, GeDefenseUi.dp(context, 7), 0, 0)
                addView(GeDefenseUi.pill(context, context.getString(R.string.titan_global_badge), GeDefenseUi.gold))
                addView(GeDefenseUi.monoTextView(context, context.getString(R.string.titan_global_managed), 9.2f, GeDefenseUi.cyan).apply {
                    setPadding(GeDefenseUi.dp(context, 9), 0, 0, 0)
                    letterSpacing = 0.08f
                })
            })
        }
        addView(GeDefenseUi.textView(context, subtitle, if (TitanVisualMode.active) 9.4f else 9f, GeDefenseUi.textMuted, bold = true).apply {
            letterSpacing = if (TitanVisualMode.active) 0.11f else 0.14f
            setPadding(0, GeDefenseUi.dp(context, 6), 0, 0)
        })
    }

    fun iconWell(context: Context, icon: VgtIcon, accent: Int, sizeDp: Int = 44): View = FrameLayout(context).apply {
        background = GeDefenseUi.iconWellBackground(context, accent)
        val iconSize = (sizeDp * 0.50f).toInt().coerceAtLeast(17)
        addView(VgtIconView(context, icon, accent), FrameLayout.LayoutParams(
            GeDefenseUi.dp(context, iconSize),
            GeDefenseUi.dp(context, iconSize),
            Gravity.CENTER,
        ))
    }

    fun accentRule(context: Context, accent: Int, widthDp: Int = 52): View = View(context).apply {
        background = GeDefenseUi.accentRuleBackground(context, accent)
        layoutParams = LinearLayout.LayoutParams(GeDefenseUi.dp(context, widthDp), GeDefenseUi.dp(context, 2))
    }

    fun divider(context: Context): View = View(context).apply { setBackgroundColor(GeDefenseUi.borderSoft) }

    fun appIdentityBadge(context: Context, owner: String?, label: String, sizeDp: Int = 38): View {
        val frame = FrameLayout(context).apply { background = GeDefenseUi.iconWellBackground(context, GeDefenseUi.cyan) }
        val packageName = owner
            ?.takeIf { !it.startsWith("uid") }
            ?.substringBefore(',')
            ?.takeIf { it.isNotBlank() }
        val image = ImageView(context).apply {
            scaleType = ImageView.ScaleType.FIT_CENTER
            setPadding(GeDefenseUi.dp(context, 5), GeDefenseUi.dp(context, 5), GeDefenseUi.dp(context, 5), GeDefenseUi.dp(context, 5))
        }
        val cachedIcon = packageName?.let(VgtAppIconCache::cached)
        if (cachedIcon != null) {
            image.setImageDrawable(cachedIcon)
            frame.addView(image, FrameLayout.LayoutParams(-1, -1))
        } else {
            val initial = label.trim().firstOrNull()?.uppercaseChar()?.toString() ?: "?"
            frame.addView(GeDefenseUi.textView(context, initial, 15f, GeDefenseUi.cyan, bold = true).apply { gravity = Gravity.CENTER }, FrameLayout.LayoutParams(-1, -1))
            if (packageName != null) {
                frame.addView(image, FrameLayout.LayoutParams(-1, -1))
                VgtAppIconCache.loadInto(context, packageName, image)
            }
        }
        frame.layoutParams = LinearLayout.LayoutParams(GeDefenseUi.dp(context, sizeDp), GeDefenseUi.dp(context, sizeDp))
        return frame
    }

    fun statusDot(context: Context, color: Int, sizeDp: Int = 8): View = View(context).apply {
        background = GeDefenseUi.iconWellBackground(context, color)
        layoutParams = LinearLayout.LayoutParams(GeDefenseUi.dp(context, sizeDp), GeDefenseUi.dp(context, sizeDp))
    }

    fun titleWithPill(context: Context, title: String, pill: TextView): View = LinearLayout(context).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        addView(GeDefenseUi.sectionTitle(context, title), LinearLayout.LayoutParams(0, -2, 1f))
        addView(pill)
    }
}
