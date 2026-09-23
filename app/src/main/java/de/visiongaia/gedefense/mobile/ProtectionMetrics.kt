package de.visiongaia.gedefense.mobile

import de.visiongaia.gedefense.mobile.core.ParsedPacket
import java.util.LinkedHashSet
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/** Runtime-only counters. Evidence remains the authoritative durable record. */
data class ProtectionMetricsSnapshot(
    val startedAtMillis: Long,
    val blockedPackets: Long,
    val blockedBytes: Long,
    val uniqueDestinations: Int,
    val attributedApps: Int,
    val unresolvedOwners: Long,
    val activeFlows: Int,
    val lastBlockedAtMillis: Long,
)

class ProtectionMetrics(
    private val uniqueCapacity: Int = 1024,
) {
    private val lock = Any()
    private val blockedPackets = AtomicLong(0)
    private val blockedBytes = AtomicLong(0)
    private val unresolvedOwners = AtomicLong(0)
    private val lastBlockedAt = AtomicLong(0)
    private val activeFlows = AtomicInteger(0)
    private val destinations = object : LinkedHashSet<String>() {}
    private val apps = object : LinkedHashSet<String>() {}
    @Volatile private var startedAt = 0L

    init {
        require(uniqueCapacity in 64..8192)
    }

    fun reset(now: Long = System.currentTimeMillis()) {
        blockedPackets.set(0)
        blockedBytes.set(0)
        unresolvedOwners.set(0)
        lastBlockedAt.set(0)
        activeFlows.set(0)
        synchronized(lock) {
            destinations.clear()
            apps.clear()
            startedAt = now
        }
    }

    fun recordBlocked(packet: ParsedPacket, owner: String?) {
        blockedPackets.incrementAndGet()
        blockedBytes.addAndGet(packet.length.toLong())
        lastBlockedAt.set(System.currentTimeMillis())
        synchronized(lock) {
            rememberBounded(destinations, packet.destination.toString())
            if (owner.isNullOrBlank() || owner == "uid-unresolved") {
                unresolvedOwners.incrementAndGet()
            } else {
                rememberBounded(apps, owner)
            }
        }
    }

    fun recordBlockedFlow(destination: String, bytes: Long, owner: String?) {
        blockedPackets.incrementAndGet()
        blockedBytes.addAndGet(bytes.coerceIn(0L, 65_535L))
        lastBlockedAt.set(System.currentTimeMillis())
        synchronized(lock) {
            rememberBounded(destinations, destination)
            if (owner.isNullOrBlank() || owner == "uid-unresolved") {
                unresolvedOwners.incrementAndGet()
            } else {
                rememberBounded(apps, owner)
            }
        }
    }

    fun setActiveFlows(value: Int) {
        activeFlows.set(value.coerceIn(0, 65_536))
    }

    fun snapshot(): ProtectionMetricsSnapshot = synchronized(lock) {
        ProtectionMetricsSnapshot(
            startedAtMillis = startedAt,
            blockedPackets = blockedPackets.get(),
            blockedBytes = blockedBytes.get(),
            uniqueDestinations = destinations.size,
            attributedApps = apps.size,
            unresolvedOwners = unresolvedOwners.get(),
            activeFlows = activeFlows.get(),
            lastBlockedAtMillis = lastBlockedAt.get(),
        )
    }

    private fun rememberBounded(set: LinkedHashSet<String>, value: String) {
        if (value in set) return
        if (set.size >= uniqueCapacity) {
            val it = set.iterator()
            if (it.hasNext()) {
                it.next()
                it.remove()
            }
        }
        set += value.take(256)
    }
}
