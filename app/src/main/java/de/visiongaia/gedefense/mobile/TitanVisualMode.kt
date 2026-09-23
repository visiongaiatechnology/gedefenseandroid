package de.visiongaia.gedefense.mobile

import android.content.Context

/**
 * Cached app-wide TITAN tier.
 *
 * UI lifecycle callbacks never query DevicePolicyManager directly. The authoritative platform query
 * is performed by TitanPolicyManager on the bounded runtime worker/IPC gate and published as a
 * cached snapshot.
 */
object TitanVisualMode {
    @Volatile var tier: TitanTier = TitanTier.STANDARD
        private set

    val active: Boolean get() = tier != TitanTier.STANDARD
    val full: Boolean get() = tier == TitanTier.FULL
    val light: Boolean get() = tier == TitanTier.LIGHT

    fun refresh(@Suppress("UNUSED_PARAMETER") context: Context): Boolean {
        val current = AppRuntime.peek()?.titan?.snapshot()?.tier ?: tier
        val changed = current != tier
        tier = current
        return changed
    }
}
