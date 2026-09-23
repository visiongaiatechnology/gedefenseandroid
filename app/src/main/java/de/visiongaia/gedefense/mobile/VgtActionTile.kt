package de.visiongaia.gedefense.mobile

import android.content.Context
import android.graphics.Color
import android.view.Gravity
import android.widget.LinearLayout

// STATUS: DIAMANT VGT SUPREME

enum class VgtActionStyle { PRIMARY, DARK, DESTRUCTIVE }

class VgtActionTile @JvmOverloads constructor(
    context: Context,
    icon: VgtIcon = VgtIcon.SHIELD,
    label: String = "",
    style: VgtActionStyle = VgtActionStyle.DARK,
    action: () -> Unit = {},
) : LinearLayout(context) {
    private val iconView = VgtIconView(context, icon)
    private val labelView = GeDefenseUi.textView(context, label, 11.2f, GeDefenseUi.text, bold = true)

    init {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        minimumHeight = GeDefenseUi.dp(context, 70)
        val padH = GeDefenseUi.dp(context, 14)
        val padV = GeDefenseUi.dp(context, 10)
        setPadding(padH, padV, padH, padV)
        addView(iconView, LayoutParams(GeDefenseUi.dp(context, 20), GeDefenseUi.dp(context, 20)))
        labelView.gravity = Gravity.CENTER_VERTICAL
        labelView.maxLines = 2
        labelView.setLineSpacing(0f, 1.05f)
        labelView.setPadding(GeDefenseUi.dp(context, 10), 0, 0, 0)
        addView(labelView, LayoutParams(0, -2, 1f))
        isClickable = true
        isFocusable = true
        setOnClickListener { action() }
        setStyle(style)
    }

    fun setLabel(label: String) {
        labelView.text = label
        contentDescription = label
    }

    fun setIcon(icon: VgtIcon) {
        iconView.icon = icon
        iconView.invalidate()
    }

    fun setStyle(style: VgtActionStyle) {
        when (style) {
            VgtActionStyle.PRIMARY -> {
                background = GeDefenseUi.goldButtonBackground(context)
                labelView.setTextColor(Color.rgb(21, 20, 17))
                iconView.iconColor = Color.rgb(28, 25, 18)
            }
            VgtActionStyle.DARK -> {
                background = GeDefenseUi.darkButtonBackground(context)
                labelView.setTextColor(GeDefenseUi.text)
                iconView.iconColor = GeDefenseUi.gold
            }
            VgtActionStyle.DESTRUCTIVE -> {
                background = GeDefenseUi.destructiveButtonBackground(context)
                labelView.setTextColor(GeDefenseUi.text)
                iconView.iconColor = GeDefenseUi.red
            }
        }
        iconView.invalidate()
    }

    override fun setEnabled(enabled: Boolean) {
        super.setEnabled(enabled)
        iconView.isEnabled = enabled
        labelView.isEnabled = enabled
        alpha = if (enabled) 1f else 0.45f
    }
}
