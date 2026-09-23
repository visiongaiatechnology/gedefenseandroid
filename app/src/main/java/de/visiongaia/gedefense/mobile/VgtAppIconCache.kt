package de.visiongaia.gedefense.mobile

import android.content.Context
import android.graphics.drawable.Drawable
import android.widget.ImageView
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.RejectedExecutionException

// STATUS: PLATIN
/**
 * Bounded async application-icon loader.
 *
 * PackageManager may cross Binder and touch APK resources. UI construction therefore never resolves
 * icons synchronously. A bounded worker loads at most one copy per package while attached views use a
 * deterministic text fallback until the icon is available.
 */
object VgtAppIconCache {
    private const val MAX_ENTRIES = 96
    private val cache = ConcurrentHashMap<String, Drawable>()
    private val loading = ConcurrentHashMap.newKeySet<String>()
    private val executor = BoundedExecutors.fixed("gedefense-icon-cache", threads = 1, queueCapacity = 24)

    fun cached(packageName: String): Drawable? = cache[packageName]

    fun loadInto(context: Context, packageName: String, view: ImageView) {
        cache[packageName]?.let { view.setImageDrawable(it); return }
        if (!loading.add(packageName)) return
        val app = context.applicationContext
        try {
            executor.execute {
                val icon = try {
                    BoundedAndroidCall.call { app.packageManager.getApplicationIcon(packageName) }
                } catch (_: Throwable) {
                    null
                }
                if (icon != null) {
                    if (cache.size >= MAX_ENTRIES) cache.keys.firstOrNull()?.let(cache::remove)
                    cache[packageName] = icon
                    view.post {
                        if (view.isAttachedToWindow) view.setImageDrawable(icon)
                    }
                }
                loading.remove(packageName)
            }
        } catch (_: RejectedExecutionException) {
            loading.remove(packageName)
        }
    }
}
