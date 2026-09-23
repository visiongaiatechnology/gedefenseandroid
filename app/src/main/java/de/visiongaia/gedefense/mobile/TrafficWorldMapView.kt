package de.visiongaia.gedefense.mobile

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RadialGradient
import android.graphics.RectF
import android.graphics.Shader
import android.view.MotionEvent
import android.view.View
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sqrt

// STATUS: DIAMANT VGT SUPREME
data class TrafficMapRoute(
    val owner: String,
    val appLabel: String,
    val countryCode: String,
    val bytes: Long,
    val flows: Int,
    val color: Int,
)

/**
 * Offline data-flow atlas. Static geometry/shaders are cached; only route particles and pulse radii
 * redraw during animation. No map tile, geocoding or telemetry request occurs.
 */
class TrafficWorldMapView(context: Context) : View(context) {
    private data class CachedRoute(
        val route: TrafficMapRoute,
        val path: Path?,
        val startX: Float,
        val startY: Float,
        val controlX: Float,
        val controlY: Float,
        val endX: Float,
        val endY: Float,
        val weight: Float,
        val particleOffset: Float,
    )

    private val mapBitmap: Bitmap = BitmapFactory.decodeResource(resources, R.drawable.world_map_ambient)
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private var origin = OriginLocationSnapshot.unavailable()
    private var routes: List<TrafficMapRoute> = emptyList()
    private var cachedRoutes: List<CachedRoute> = emptyList()
    private var phase = 0f
    private var selected = -1
    private var mapRect = RectF()
    private var mapTarget = RectF()
    private var projectionRect = RectF()
    private var surfaceShader: Shader? = null
    private var vignetteShader: Shader? = null
    private var originHud = ""
    private var summaryHud = ""
    private val ticker = VgtFrameTicker(this, 3_200L) { phase = it }

    init {
        minimumHeight = GeDefenseUi.dp(context, 220)
        isClickable = true
        isFocusable = true
        contentDescription = context.getString(R.string.traffic_map_accessibility)
        textPaint.typeface = android.graphics.Typeface.create("sans-serif-medium", android.graphics.Typeface.NORMAL)
        updateHudCache()
    }

    fun setData(nextOrigin: OriginLocationSnapshot, nextRoutes: List<TrafficMapRoute>) {
        val normalized = nextRoutes.asSequence()
            .filter { it.bytes >= 0L && it.countryCode.length == 2 && CountryCentroids.lookup(it.countryCode) != null }
            .sortedByDescending { it.bytes }
            .take(MAX_ROUTES)
            .toList()
        if (origin == nextOrigin && routes == normalized) return
        origin = nextOrigin
        routes = normalized
        if (selected !in routes.indices) selected = -1
        rebuildRouteCache()
        updateHudCache()
        updateTicker()
        invalidate()
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        updateTicker()
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
        if (w <= 0 || h <= 0) return
        val inset = dp(8f)
        mapRect = RectF(inset, inset, w - inset, h - inset)
        val padX = dp(12f)
        mapTarget = RectF(mapRect.left + padX, mapRect.top + dp(28f), mapRect.right - padX, mapRect.bottom - dp(22f))
        projectionRect = RectF(mapRect.left + dp(16f), mapRect.top + dp(31f), mapRect.right - dp(16f), mapRect.bottom - dp(24f))
        surfaceShader = LinearGradient(
            mapRect.left, mapRect.top, mapRect.right, mapRect.bottom,
            intArrayOf(Color.argb(230, 5, 20, 31), Color.argb(220, 5, 13, 23), Color.argb(238, 3, 10, 18)),
            null,
            Shader.TileMode.CLAMP,
        )
        vignetteShader = RadialGradient(
            mapRect.centerX(), mapRect.centerY(), max(mapRect.width(), mapRect.height()) * .62f,
            intArrayOf(Color.argb(0, 47, 207, 255), Color.argb(0, 47, 207, 255), Color.argb(135, 1, 7, 13)),
            floatArrayOf(0f, .58f, 1f),
            Shader.TileMode.CLAMP,
        )
        rebuildRouteCache()
    }

    private fun updateTicker() {
        if (isAttachedToWindow && routes.isNotEmpty()) ticker.start() else ticker.stop()
    }

    private fun rebuildRouteCache() {
        if (projectionRect.width() <= 0f || projectionRect.height() <= 0f || routes.isEmpty()) {
            cachedRoutes = emptyList()
            return
        }
        val maxBytes = routes.maxOfOrNull { it.bytes }?.coerceAtLeast(1L) ?: 1L
        val originPoint = origin.point?.let(::project)
        cachedRoutes = routes.mapIndexedNotNull { index, route ->
            val geo = CountryCentroids.lookup(route.countryCode) ?: return@mapIndexedNotNull null
            val end = project(geo)
            val weight = sqrt((route.bytes.toDouble() / maxBytes.toDouble()).coerceIn(0.0, 1.0)).toFloat()
            if (originPoint == null) {
                CachedRoute(route, null, 0f, 0f, 0f, 0f, end.first, end.second, weight, (index * .137f) % 1f)
            } else {
                val sx = originPoint.first
                val sy = originPoint.second
                val dx = end.first - sx
                val dy = end.second - sy
                val distance = sqrt(dx * dx + dy * dy)
                val lift = min(dp(70f), distance * .22f)
                val cx = (sx + end.first) * .5f
                val cy = min(sy, end.second) - lift
                val p = Path().apply { moveTo(sx, sy); quadTo(cx, cy, end.first, end.second) }
                CachedRoute(route, p, sx, sy, cx, cy, end.first, end.second, weight, (abs(end.first + end.second).toInt() % 23) / 23f)
            }
        }
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (mapRect.width() <= 0f || mapRect.height() <= 0f) return
        drawSurface(canvas)
        drawWorld(canvas)
        drawRoutes(canvas)
        drawHud(canvas)
    }

    private fun drawSurface(canvas: Canvas) {
        paint.style = Paint.Style.FILL
        paint.shader = surfaceShader
        canvas.drawRoundRect(mapRect, dp(20f), dp(20f), paint)
        paint.shader = null
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = dp(1f)
        paint.color = Color.argb(58, 81, 137, 164)
        canvas.drawRoundRect(mapRect, dp(20f), dp(20f), paint)
    }

    private fun drawWorld(canvas: Canvas) {
        paint.alpha = 210
        canvas.drawBitmap(mapBitmap, null, mapTarget, paint)
        paint.alpha = 255
        paint.style = Paint.Style.FILL
        paint.shader = vignetteShader
        canvas.drawRoundRect(mapRect, dp(20f), dp(20f), paint)
        paint.shader = null
    }

    private fun drawRoutes(canvas: Canvas) {
        cachedRoutes.forEachIndexed { index, cached ->
            cached.path?.let { drawArc(canvas, cached, index == selected) }
            drawDestination(canvas, cached.endX, cached.endY, cached.route.color, cached.weight, index == selected)
        }
        val start = cachedRoutes.firstOrNull { it.path != null }
        if (start != null) drawOrigin(canvas, start.startX, start.startY)
    }

    private fun drawArc(canvas: Canvas, cached: CachedRoute, highlighted: Boolean) {
        val route = cached.route
        val path = cached.path ?: return
        paint.style = Paint.Style.STROKE
        paint.strokeCap = Paint.Cap.ROUND
        paint.strokeWidth = dp(if (highlighted) 6.5f else 4.5f)
        paint.color = GeDefenseUi.withAlpha(route.color, if (highlighted) 54 else 30)
        canvas.drawPath(path, paint)
        paint.strokeWidth = dp(1.2f + cached.weight * 1.8f)
        paint.color = GeDefenseUi.withAlpha(route.color, if (highlighted) 235 else 175)
        canvas.drawPath(path, paint)

        val t = (phase + cached.particleOffset) % 1f
        val qx = bezier(cached.startX, cached.controlX, cached.endX, t)
        val qy = bezier(cached.startY, cached.controlY, cached.endY, t)
        paint.style = Paint.Style.FILL
        paint.color = GeDefenseUi.withAlpha(route.color, 45)
        canvas.drawCircle(qx, qy, dp(8f), paint)
        paint.color = GeDefenseUi.withAlpha(route.color, 180)
        canvas.drawCircle(qx, qy, dp(4.2f), paint)
        paint.color = Color.WHITE
        canvas.drawCircle(qx, qy, dp(1.35f), paint)
    }

    private fun drawOrigin(canvas: Canvas, x: Float, y: Float) {
        paint.style = Paint.Style.FILL
        paint.color = GeDefenseUi.withAlpha(GeDefenseUi.gold, 32)
        canvas.drawCircle(x, y, dp(18f), paint)
        paint.color = GeDefenseUi.withAlpha(GeDefenseUi.gold, 72)
        canvas.drawCircle(x, y, dp(11f), paint)
        paint.color = GeDefenseUi.gold
        canvas.drawCircle(x, y, dp(4.5f), paint)
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = dp(1.5f)
        paint.color = Color.argb(190, 255, 227, 135)
        canvas.drawCircle(x, y, dp(8f + phase * 4f), paint)
    }

    private fun drawDestination(canvas: Canvas, x: Float, y: Float, color: Int, weight: Float, highlighted: Boolean) {
        paint.style = Paint.Style.FILL
        paint.color = GeDefenseUi.withAlpha(color, if (highlighted) 90 else 54)
        canvas.drawCircle(x, y, dp(7f + weight * 4f), paint)
        paint.color = color
        canvas.drawCircle(x, y, dp(if (highlighted) 4f else 3f), paint)
    }

    private fun drawHud(canvas: Canvas) {
        textPaint.textSize = dp(9.5f)
        textPaint.letterSpacing = .08f
        textPaint.color = GeDefenseUi.textMuted
        canvas.drawText(originHud, mapRect.left + dp(14f), mapRect.top + dp(19f), textPaint)

        if (routes.isEmpty()) {
            textPaint.textSize = dp(11f)
            textPaint.letterSpacing = 0f
            textPaint.color = GeDefenseUi.textDim
            canvas.drawText(context.getString(R.string.traffic_map_waiting), mapRect.left + dp(14f), mapRect.bottom - dp(15f), textPaint)
            return
        }
        textPaint.textSize = dp(10.5f)
        textPaint.letterSpacing = 0f
        textPaint.color = GeDefenseUi.text
        canvas.drawText(summaryHud, mapRect.left + dp(14f), mapRect.bottom - dp(13f), textPaint)
    }

    private fun updateHudCache() {
        originHud = when (origin.source) {
            OriginSource.COARSE_LOCATION -> context.getString(R.string.traffic_map_origin_coarse)
            OriginSource.NETWORK_COUNTRY, OriginSource.LOCALE_COUNTRY -> context.getString(R.string.traffic_map_origin_approx)
            OriginSource.NONE -> context.getString(R.string.traffic_map_origin_missing)
        }.uppercase()
        val route = routes.getOrNull(selected) ?: routes.firstOrNull()
        summaryHud = route?.let { "${it.appLabel.take(22)}  →  ${it.countryCode}  ·  ${GeDefenseUi.formatBytes(it.bytes)}" }.orEmpty()
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        if (event.action == MotionEvent.ACTION_DOWN || event.action == MotionEvent.ACTION_MOVE) VgtUiPerformance.noteInteraction()
        if (event.action != MotionEvent.ACTION_UP) return true
        var best = -1
        var bestDistanceSquared = dp(34f) * dp(34f)
        cachedRoutes.forEachIndexed { index, route ->
            val dx = event.x - route.endX
            val dy = event.y - route.endY
            val distanceSquared = dx * dx + dy * dy
            if (distanceSquared < bestDistanceSquared) {
                best = index
                bestDistanceSquared = distanceSquared
            }
        }
        if (best >= 0) {
            selected = best
            updateHudCache()
            performClick()
            invalidate()
        }
        return true
    }

    override fun performClick(): Boolean {
        super.performClick()
        return true
    }

    private fun project(point: GeoPoint): Pair<Float, Float> {
        val lon = point.longitude.coerceIn(-180.0, 180.0)
        val lat = point.latitude.coerceIn(-60.0, 85.0)
        val x = projectionRect.left + (((lon + 180.0) / 360.0) * projectionRect.width()).toFloat()
        val y = projectionRect.top + (((85.0 - lat) / 145.0) * projectionRect.height()).toFloat()
        return x to y
    }

    private fun bezier(a: Float, b: Float, c: Float, t: Float): Float {
        val u = 1f - t
        return u * u * a + 2f * u * t * b + t * t * c
    }

    private fun dp(value: Float): Float = value * resources.displayMetrics.density

    companion object {
        private const val MAX_ROUTES = 12
    }
}
