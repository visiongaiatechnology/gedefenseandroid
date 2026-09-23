package de.visiongaia.gedefense.mobile

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import de.visiongaia.gedefense.mobile.core.PortSentinelClassifier
import de.visiongaia.gedefense.mobile.core.SentinelRisk
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.StandardProtocolFamily
import java.net.StandardSocketOptions
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

// STATUS: DIAMANT VGT SUPREME
class PortSentinel(
    context: Context,
    private val isBlockedSource: (String) -> Boolean,
    private val onHit: (PortSentinelHit) -> Unit,
    private val onState: (PortSentinelRuntimeState) -> Unit,
) : AutoCloseable {
    private data class Listener(val port: Int, val protocol: SentinelProtocol)
    private data class SourceWindow(var startedAt: Long, val ports: LinkedHashSet<Int>)

    private val appContext = context.applicationContext
    private val connectivity = appContext.getSystemService(ConnectivityManager::class.java)
    private val running = AtomicBoolean(false)
    private val lock = Any()
    private var selector: Selector? = null
    private var worker: Thread? = null
    private var currentNetwork: Network? = null
    private val lastEmitted = LinkedHashMap<String, Long>(256, 0.75f, true)
    private val sourceWindows = LinkedHashMap<String, SourceWindow>(128, 0.75f, true)
    private var minuteStartedAt = 0L
    private var minuteEvents = 0

    fun rebind(network: Network?) = synchronized(lock) {
        if (network == currentNetwork && running.get()) return@synchronized
        stopLocked()
        currentNetwork = network
        if (network == null) {
            onState(PortSentinelRuntimeState.standby())
            return@synchronized
        }
        val capabilities = connectivity.getNetworkCapabilities(network)
        val transport = when {
            capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "ETHERNET"
            capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "WIFI"
            capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "CELLULAR"
            else -> "UNSUPPORTED"
        }
        if (transport == "UNSUPPORTED") {
            onState(PortSentinelRuntimeState(false, 0, emptyList(), transport))
            return@synchronized
        }
        val link = connectivity.getLinkProperties(network)
        val bindAddresses = link?.linkAddresses.orEmpty()
            .asSequence()
            .map { it.address }
            .filter(::isBindableAddress)
            .distinctBy(::normalizedAddress)
            .take(MAX_LOCAL_ADDRESSES)
            .toList()
        val localAddresses = bindAddresses.map(::normalizedAddress)
        if (bindAddresses.isEmpty()) {
            onState(PortSentinelRuntimeState(false, 0, emptyList(), transport, "no_bindable_unicast_address"))
            return@synchronized
        }

        val newSelector = try { Selector.open() } catch (_: Exception) {
            onState(PortSentinelRuntimeState(false, 0, localAddresses, transport, "selector_open_failed"))
            return@synchronized
        }
        var listeners = 0
        bindAddresses.forEach { address ->
            PortSentinelClassifier.monitoredPorts.sorted().forEach { port ->
                listeners += bindTcp(newSelector, address, port)
                listeners += bindUdp(newSelector, address, port)
            }
        }
        if (listeners == 0) {
            try { newSelector.close() } catch (error: Exception) { RuntimeFailureLog.nonCritical("port-sentinel", error) }
            onState(PortSentinelRuntimeState(false, 0, localAddresses, transport, "no_listener_bound"))
            return@synchronized
        }
        selector = newSelector
        running.set(true)
        worker = Thread({ eventLoop(newSelector, localAddresses, transport) }, "gedefense-port-sentinel").apply {
            isDaemon = true
            start()
        }
        onState(PortSentinelRuntimeState(true, listeners, localAddresses, transport))
    }

    private fun bindTcp(selector: Selector, address: InetAddress, port: Int): Int = try {
        val channel = ServerSocketChannel.open()
        channel.configureBlocking(false)
        channel.setOption(StandardSocketOptions.SO_REUSEADDR, true)
        channel.bind(InetSocketAddress(address, port), TCP_BACKLOG)
        channel.register(selector, SelectionKey.OP_ACCEPT, Listener(port, SentinelProtocol.TCP))
        1
    } catch (_: Exception) { 0 }

    private fun bindUdp(selector: Selector, address: InetAddress, port: Int): Int = try {
        val family = if (address is Inet6Address) StandardProtocolFamily.INET6 else StandardProtocolFamily.INET
        val channel = DatagramChannel.open(family)
        channel.configureBlocking(false)
        channel.setOption(StandardSocketOptions.SO_REUSEADDR, true)
        channel.bind(InetSocketAddress(address, port))
        channel.register(selector, SelectionKey.OP_READ, Listener(port, SentinelProtocol.UDP))
        1
    } catch (_: Exception) { 0 }

    private fun eventLoop(selector: Selector, localAddresses: List<String>, transport: String) {
        val udpByte = ByteBuffer.allocateDirect(1)
        var failure: String? = null
        try {
            while (running.get() && this.selector === selector) {
                selector.select()
                val iterator = selector.selectedKeys().iterator()
                while (iterator.hasNext()) {
                    val key = iterator.next()
                    iterator.remove()
                    if (!key.isValid) continue
                    val listener = key.attachment() as? Listener ?: continue
                    when (listener.protocol) {
                        SentinelProtocol.TCP -> handleTcp(key, listener, transport)
                        SentinelProtocol.UDP -> handleUdp(key, listener, udpByte, transport)
                    }
                }
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        } catch (_: Exception) {
            if (running.get()) failure = "listener_failure"
        } finally {
            try { selector.keys().toList().forEach { key -> try { key.channel().close() } catch (error: Exception) { RuntimeFailureLog.nonCritical("port-sentinel", error) } } } catch (error: Exception) { RuntimeFailureLog.nonCritical("port-sentinel", error) }
            try { selector.close() } catch (error: Exception) { RuntimeFailureLog.nonCritical("port-sentinel", error) }
            if (this.selector === selector) {
                running.set(false)
                onState(PortSentinelRuntimeState(false, 0, localAddresses, transport, failure))
            }
        }
    }

    private fun handleTcp(key: SelectionKey, listener: Listener, transport: String) {
        val server = key.channel() as? ServerSocketChannel ?: return
        repeat(MAX_ACCEPTS_PER_KEY) {
            val socket = try { server.accept() } catch (_: Exception) { null } ?: return
            try {
                val remote = socket.remoteAddress as? InetSocketAddress
                if (remote != null) observe(remote, listener, transport)
            } finally {
                try { socket.close() } catch (error: Exception) { RuntimeFailureLog.nonCritical("port-sentinel", error) }
            }
        }
    }

    private fun handleUdp(key: SelectionKey, listener: Listener, buffer: ByteBuffer, transport: String) {
        val channel = key.channel() as? DatagramChannel ?: return
        repeat(MAX_DATAGRAMS_PER_KEY) {
            buffer.clear()
            val remote = try { channel.receive(buffer) as? InetSocketAddress } catch (_: Exception) { null } ?: return
            observe(remote, listener, transport)
        }
    }

    private fun observe(remote: InetSocketAddress, listener: Listener, transport: String) {
        val remoteAddress = remote.address ?: return
        if (!PortSentinelStore.isBlockableAddress(remoteAddress)) return
        val source = normalizedAddress(remoteAddress)
        val now = System.currentTimeMillis()
        synchronized(lock) {
            if (minuteStartedAt == 0L || now - minuteStartedAt >= 60_000L) {
                minuteStartedAt = now
                minuteEvents = 0
            }
            if (minuteEvents >= MAX_EVENTS_PER_MINUTE) return
            val dedupeKey = "$source|${listener.protocol}|${listener.port}"
            val previous = lastEmitted[dedupeKey]
            if (previous != null && now - previous < DEDUPE_MS) return
            lastEmitted[dedupeKey] = now
            trimLru(lastEmitted, MAX_DEDUPE_ENTRIES)

            val window = sourceWindows[source]
            val activeWindow = if (window == null || now - window.startedAt > PortSentinelClassifier.SCAN_WINDOW_MILLIS) {
                SourceWindow(now, linkedSetOf<Int>()).also { sourceWindows[source] = it }
            } else window
            activeWindow.ports.add(listener.port)
            trimLru(sourceWindows, MAX_SOURCE_WINDOWS)
            val assessment = PortSentinelClassifier.assess(listener.port, activeWindow.ports.size)
            minuteEvents++
            onHit(
                PortSentinelHit(
                    id = UUID.randomUUID().toString(),
                    atMillis = now,
                    sourceAddress = source,
                    sourcePort = remote.port.coerceIn(0, 65535),
                    targetPort = listener.port,
                    protocol = listener.protocol,
                    sourceZone = sourceZone(transport, remoteAddress),
                    severity = assessment.risk.toXdrSeverity(),
                    eventCode = assessment.code,
                    riskPoints = assessment.riskPoints,
                    blockedSource = isBlockedSource(source),
                ),
            )
        }
    }

    private fun sourceZone(transport: String, source: InetAddress): String = when {
        transport == "CELLULAR" && (source.isSiteLocalAddress || PortSentinelStore.isUniqueLocalIpv6(source)) -> "MOBILE_CARRIER"
        transport == "CELLULAR" && source is Inet4Address && PortSentinelStore.isCarrierGradeNat(source) -> "MOBILE_CARRIER"
        transport == "CELLULAR" -> "MOBILE_INTERNET"
        source.isSiteLocalAddress || PortSentinelStore.isUniqueLocalIpv6(source) -> "LOCAL_LAN"
        else -> "PUBLIC_INTERNET"
    }

    private fun isBindableAddress(address: InetAddress): Boolean =
        !address.isAnyLocalAddress && !address.isLoopbackAddress && !address.isMulticastAddress && !address.isLinkLocalAddress

    private fun normalizedAddress(address: InetAddress): String = requireNotNull(address.hostAddress).substringBefore('%')

    private fun SentinelRisk.toXdrSeverity(): XdrSeverity = when (this) {
        SentinelRisk.INFO -> XdrSeverity.INFO
        SentinelRisk.REVIEW -> XdrSeverity.MEDIUM
        SentinelRisk.HIGH -> XdrSeverity.HIGH
        SentinelRisk.CRITICAL -> XdrSeverity.CRITICAL
    }

    private fun <K, V> trimLru(map: LinkedHashMap<K, V>, max: Int) {
        while (map.size > max) {
            map.entries.iterator().let { if (it.hasNext()) { it.next(); it.remove() } }
        }
    }

    override fun close() = synchronized(lock) {
        stopLocked()
        currentNetwork = null
        onState(PortSentinelRuntimeState.standby())
    }

    private fun stopLocked() {
        running.set(false)
        try { selector?.wakeup() } catch (error: Exception) { RuntimeFailureLog.nonCritical("port-sentinel", error) }
        val old = worker
        worker = null
        selector = null
        if (old != null && old !== Thread.currentThread()) {
            try { old.join(750L) } catch (_: InterruptedException) { Thread.currentThread().interrupt() }
        }
    }

    companion object {
        private const val MAX_LOCAL_ADDRESSES = 4
        private const val TCP_BACKLOG = 16
        private const val MAX_ACCEPTS_PER_KEY = 8
        private const val MAX_DATAGRAMS_PER_KEY = 8
        private const val DEDUPE_MS = 10_000L
        private const val MAX_EVENTS_PER_MINUTE = 96
        private const val MAX_DEDUPE_ENTRIES = 1024
        private const val MAX_SOURCE_WINDOWS = 512
    }
}
