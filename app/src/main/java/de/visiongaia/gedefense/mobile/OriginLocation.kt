package de.visiongaia.gedefense.mobile

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationManager
import android.telephony.TelephonyManager
import java.util.Locale
import kotlin.math.round

// STATUS: DIAMANT VGT SUPREME
enum class OriginSource {
    COARSE_LOCATION,
    NETWORK_COUNTRY,
    LOCALE_COUNTRY,
    NONE,
}

data class OriginLocationSnapshot(
    val point: GeoPoint?,
    val countryCode: String?,
    val source: OriginSource,
    val observedAtMillis: Long,
) {
    val ready: Boolean get() = point != null
    val usesDeviceLocation: Boolean get() = source == OriginSource.COARSE_LOCATION

    companion object {
        fun unavailable() = OriginLocationSnapshot(null, null, OriginSource.NONE, 0L)
    }
}

/**
 * Local-only origin resolver for the data-flow atlas.
 *
 * No active background location subscription is started. When coarse location is allowed we use
 * the freshest last-known NETWORK/PASSIVE location and quantize it before exposing it to the UI.
 * Without permission the map falls back to an approximate country anchor derived locally from the
 * mobile network country or the device locale.
 */
class LocalOriginLocator(private val context: Context) {
    @Volatile private var cached = OriginLocationSnapshot.unavailable()

    fun snapshot(): OriginLocationSnapshot = cached

    fun hasCoarsePermission(): Boolean = context.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED

    fun refresh(): OriginLocationSnapshot {
        val now = System.currentTimeMillis()
        if (hasCoarsePermission()) {
            freshestLastKnown()?.let { location ->
                val point = GeoPoint(
                    latitude = quantize(location.latitude).coerceIn(-85.0, 85.0),
                    longitude = quantizeLongitude(location.longitude),
                )
                return OriginLocationSnapshot(
                    point = point,
                    countryCode = localCountryCode(),
                    source = OriginSource.COARSE_LOCATION,
                    observedAtMillis = location.time.takeIf { it > 0L } ?: now,
                ).also { cached = it }
            }
        }

        val code = localCountryCode()
        val fallback = CountryCentroids.lookup(code)
        return OriginLocationSnapshot(
            point = fallback,
            countryCode = code,
            source = when {
                code.isNullOrBlank() -> OriginSource.NONE
                networkCountryCode() == code -> OriginSource.NETWORK_COUNTRY
                else -> OriginSource.LOCALE_COUNTRY
            },
            observedAtMillis = if (fallback != null) now else 0L,
        ).also { cached = it }
    }

    private fun freshestLastKnown(): Location? {
        val manager = context.getSystemService(LocationManager::class.java) ?: return null
        val providers = buildList {
            add(LocationManager.NETWORK_PROVIDER)
            add(LocationManager.PASSIVE_PROVIDER)
        }
        return providers.asSequence()
            .mapNotNull { provider ->
                try { manager.getLastKnownLocation(provider) } catch (_: SecurityException) { null } catch (_: RuntimeException) { null }
            }
            .filter { location ->
                location.latitude.isFinite() && location.longitude.isFinite() &&
                    location.latitude in -90.0..90.0 && location.longitude in -180.0..180.0
            }
            .maxByOrNull { it.time }
    }

    private fun localCountryCode(): String? = networkCountryCode() ?: Locale.getDefault().country
        .trim()
        .uppercase(Locale.ROOT)
        .takeIf { it.length == 2 }

    private fun networkCountryCode(): String? = try {
        context.getSystemService(TelephonyManager::class.java)?.networkCountryIso
            ?.trim()
            ?.uppercase(Locale.ROOT)
            ?.takeIf { it.length == 2 }
    } catch (_: RuntimeException) {
        null
    }

    private fun quantize(value: Double): Double = round(value / QUANTUM_DEGREES) * QUANTUM_DEGREES

    private fun quantizeLongitude(value: Double): Double {
        var normalized = value
        while (normalized > 180.0) normalized -= 360.0
        while (normalized < -180.0) normalized += 360.0
        return quantize(normalized).coerceIn(-180.0, 180.0)
    }

    companion object {
        // ~25-30 km at mid-latitudes: sufficient for a global visualization without exposing a pin.
        private const val QUANTUM_DEGREES = 0.25
    }
}
