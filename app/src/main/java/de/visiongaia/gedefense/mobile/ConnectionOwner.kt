package de.visiongaia.gedefense.mobile

import android.content.Context
import android.net.ConnectivityManager
import de.visiongaia.gedefense.mobile.core.FlowKey
import de.visiongaia.gedefense.mobile.core.PacketParser
import de.visiongaia.gedefense.mobile.core.ParsedPacket
import java.net.InetSocketAddress
import java.util.LinkedHashMap

/** Bounded UID/package attribution cache for packets already observed by our active VpnService. */
class ConnectionOwnerResolver(
    context: Context,
    private val capacity: Int = 4096,
    private val ttlMillis: Long = 2 * 60_000L,
) {
    private val appContext = context.applicationContext
    private val connectivity = appContext.getSystemService(ConnectivityManager::class.java)
    private data class Entry(val owner: String?, val atMillis: Long)
    private data class UidEntry(val owner: String, val atMillis: Long)
    private val cache = object : LinkedHashMap<FlowKey, Entry>(capacity, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<FlowKey, Entry>?): Boolean = size > capacity
    }
    private val uidOwners = object : LinkedHashMap<Int, UidEntry>(UID_CACHE_CAPACITY, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, UidEntry>?): Boolean = size > UID_CACHE_CAPACITY
    }

    init {
        require(capacity in 128..16_384)
        require(ttlMillis in 10_000L..15 * 60_000L)
    }

    @Synchronized
    fun resolve(packet: ParsedPacket, now: Long = System.currentTimeMillis()): String? = resolveTuple(
        packet.protocol, packet.source, packet.sourcePort, packet.destination, packet.destinationPort, now
    )

    @Synchronized
    fun resolveTuple(
        protocol: Int,
        source: de.visiongaia.gedefense.mobile.core.IpAddress,
        sourcePort: Int?,
        destination: de.visiongaia.gedefense.mobile.core.IpAddress,
        destinationPort: Int?,
        now: Long = System.currentTimeMillis(),
    ): String? {
        val srcPort = sourcePort ?: return null
        val dstPort = destinationPort ?: return null
        if (protocol != PacketParser.TCP && protocol != PacketParser.UDP) return null
        val key = FlowKey(protocol, source, srcPort, destination, dstPort)
        cache[key]?.let { entry ->
            if (now - entry.atMillis <= ttlMillis) return entry.owner
            cache.remove(key)
        }

        val owner = try {
            val uid = connectivity.getConnectionOwnerUid(
                protocol,
                InetSocketAddress(source.toInetAddress(), srcPort),
                InetSocketAddress(destination.toInetAddress(), dstPort),
            )
            if (uid < 0) null else ownerForUid(uid, now)
        } catch (_: SecurityException) {
            null
        } catch (_: IllegalArgumentException) {
            null
        } catch (_: RuntimeException) {
            null
        }
        cache[key] = Entry(owner, now)
        return owner
    }

    private fun ownerForUid(uid: Int, now: Long): String {
        uidOwners[uid]?.let { entry ->
            if (now - entry.atMillis <= UID_CACHE_TTL_MS) return entry.owner
            uidOwners.remove(uid)
        }
        val packages = appContext.packageManager.getPackagesForUid(uid)
            ?.asSequence()
            ?.filter { it.isNotBlank() }
            ?.sorted()
            ?.take(4)
            ?.toList()
            .orEmpty()
        val owner = if (packages.isEmpty()) "uid:$uid" else packages.joinToString(",").take(256)
        uidOwners[uid] = UidEntry(owner, now)
        return owner
    }

    @Synchronized
    fun clear() {
        cache.clear()
        uidOwners.clear()
    }

    companion object {
        private const val UID_CACHE_CAPACITY = 512
        private const val UID_CACHE_TTL_MS = 2 * 60_000L
    }
}
