package de.visiongaia.gedefense.mobile

import android.content.Context
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView

// STATUS: DIAMANT VGT SUPREME
class BottomNavBar @JvmOverloads constructor(
    context: Context,
    onSelected: (Int) -> Unit = {},
) : LinearLayout(context) {
    private val items = ArrayList<NavItem>(5)
    private var bottomInset = 0

    init {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER
        background = GeDefenseUi.glassPanelBackground(context, strong = true, radius = 20)
        elevation = GeDefenseUi.dp(context, 10).toFloat()
        setPadding(GeDefenseUi.dp(context, 9), GeDefenseUi.dp(context, 5), GeDefenseUi.dp(context, 9), GeDefenseUi.dp(context, 5))

        val specs = listOf(
            NavSpec(VgtIcon.HOME, context.getString(R.string.nav_home), 0),
            NavSpec(VgtIcon.ACTIVITY, context.getString(R.string.nav_activity), 1),
            NavSpec(VgtIcon.SHIELD, context.getString(R.string.nav_security), 2),
            NavSpec(VgtIcon.EVIDENCE, context.getString(R.string.nav_evidence), 3),
            NavSpec(VgtIcon.MORE, context.getString(R.string.nav_more), 4),
        )
        specs.forEach { spec ->
            val item = NavItem(context, spec.icon, spec.label).apply { setOnClickListener { onSelected(spec.index) } }
            items += item
            addView(item, LayoutParams(0, GeDefenseUi.dp(context, 56), 1f).apply {
                leftMargin = GeDefenseUi.dp(context, 2)
                rightMargin = GeDefenseUi.dp(context, 2)
            })
        }
        select(0)
    }

    fun setBottomInset(px: Int) {
        val safeInset = px.coerceAtLeast(0)
        if (bottomInset == safeInset) return
        bottomInset = safeInset
        val lp = layoutParams as? LinearLayout.LayoutParams ?: return
        val target = GeDefenseUi.dp(context, GeDefenseUi.BOTTOM_NAV_MARGIN_DP) + safeInset
        if (lp.bottomMargin != target) {
            lp.bottomMargin = target
            layoutParams = lp
        }
    }

    fun select(index: Int) {
        items.forEachIndexed { i, item -> item.setSelectedState(i == index) }
    }

    private data class NavSpec(val icon: VgtIcon, val label: String, val index: Int)

    private class NavItem(context: Context, icon: VgtIcon, label: String) : LinearLayout(context) {
        private val iconView: VgtIconView
        private val labelText: TextView
        private val indicator: View

        init {
            orientation = VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(GeDefenseUi.dp(context, 4), GeDefenseUi.dp(context, 1), GeDefenseUi.dp(context, 4), GeDefenseUi.dp(context, 3))
            isClickable = true
            isFocusable = true
            contentDescription = label

            indicator = View(context).apply { background = GeDefenseUi.accentRuleBackground(context, GeDefenseUi.gold) }
            addView(indicator, LayoutParams(GeDefenseUi.dp(context, 20), GeDefenseUi.dp(context, 2)).apply { bottomMargin = GeDefenseUi.dp(context, 4) })
            iconView = VgtIconView(context, icon, GeDefenseUi.textMuted)
            addView(iconView, LayoutParams(GeDefenseUi.dp(context, 20), GeDefenseUi.dp(context, 20)))
            labelText = GeDefenseUi.textView(context, label, 8.8f, GeDefenseUi.textMuted, bold = true).apply {
                gravity = Gravity.CENTER
                setPadding(0, GeDefenseUi.dp(context, 3), 0, 0)
            }
            addView(labelText)
        }

        fun setSelectedState(selected: Boolean) {
            val color = if (selected) GeDefenseUi.gold else GeDefenseUi.textMuted
            iconView.iconColor = color
            iconView.invalidate()
            labelText.setTextColor(color)
            indicator.visibility = if (selected) View.VISIBLE else View.INVISIBLE
            alpha = if (selected) 1f else 0.66f
            background = if (selected) GeDefenseUi.navSelectedBackground(context) else null
        }
    }
}
