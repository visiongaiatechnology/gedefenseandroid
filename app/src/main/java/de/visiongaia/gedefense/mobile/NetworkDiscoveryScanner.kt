package de.visiongaia.gedefense.mobile

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import de.visiongaia.gedefense.mobile.core.Ipv4ScanPlan
import de.visiongaia.gedefense.mobile.core.MdnsDnsCodec
import de.visiongaia.gedefense.mobile.core.MdnsDnsMessage
import de.visiongaia.gedefense.mobile.core.NetworkRangePlanner
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket
import java.net.NetworkInterface
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorCompletionService
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class NetworkDiscoveryScanner(
    context: Context,
    private val baselineStore: NetworkDiscoveryStore,
) {
    private data class SelectedNetwork(
        val network: Network,
        val linkProperties: LinkProperties,
        val transport: String,
        val localAddress: Inet4Address,
        val prefixLength: Int,
        val gatewayAddress: String?,
    )

    private data class ProbeResult(val ip: String, val openPorts: Set<Int>)
    private data class MdnsSrv(val targetHost: String, val port: Int)
    private data class MdnsAggregate(
        val ptrs: MutableMap<String, MutableSet<String>> = linkedMapOf(),
        val srvs: MutableMap<String, MdnsSrv> = linkedMapOf(),
        val txtKeys: MutableMap<String, MutableSet<String>> = linkedMapOf(),
        val addresses: MutableMap<String, MutableSet<String>> = linkedMapOf(),
    )
    private data class MdnsDeviceInfo(
        val hostname: String?,
        val services: List<NetworkDnsSdService>,
    )

    private val appContext = context.applicationContext
    private val connectivity = appContext.getSystemService(ConnectivityManager::class.java)
    private val wifiManager = appContext.getSystemService(WifiManager::class.java)

    fun scan(
        cancelled: () -> Boolean,
        onProgress: (NetworkDiscoveryProgress) -> Unit,
    ): NetworkDiscoverySnapshot {
        val started = System.currentTimeMillis()
        val selected = selectLanNetwork() ?: return unavailable(started, "wifi_or_ethernet_required")
        val plan = NetworkRangePlanner.plan(selected.localAddress.address, selected.prefixLength)
            ?: return unavailable(started, "private_ipv4_required")
        val targets = LinkedHashSet(plan.targets)
        selected.gatewayAddress?.takeIf(::isPrivateIpv4Literal)?.let(targets::add)
        targets.remove(plan.localAddress)
        if (targets.size > NetworkRangePlanner.MAX_ACTIVE_HOSTS) {
            val limited = targets.take(NetworkRangePlanner.MAX_ACTIVE_HOSTS)
            targets.clear()
            targets.addAll(limited)
        }

        val total = targets.size
        val discovered = linkedMapOf<String, ProbeResult>()
        val progressCount = AtomicInteger(0)
        val workers = BoundedExecutors.fixed(
            name = "gedefense-lan-probe",
            threads = MAX_WORKERS,
            queueCapacity = NetworkRangePlanner.MAX_ACTIVE_HOSTS,
        )
        var interrupted = false
        try {
            val completion = ExecutorCompletionService<ProbeResult>(workers)
            targets.forEach { ip ->
                completion.submit(Callable {
                    if (cancelled()) ProbeResult(ip, emptySet()) else probeHost(selected.network, ip, selected.gatewayAddress == ip, cancelled)
                })
            }
            for (ignored in 0 until total) {
                if (cancelled()) break
                val result = try {
                    completion.take().get()
                } catch (_: ExecutionException) {
                    null
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    interrupted = true
                    break
                }
                if (result != null && result.openPorts.isNotEmpty()) discovered[result.ip] = result
                val done = progressCount.incrementAndGet()
                onProgress(NetworkDiscoveryProgress(done, total, discovered.size, result?.ip.orEmpty()))
            }
        } finally {
            workers.shutdownNow()
            try {
                workers.awaitTermination(250, TimeUnit.MILLISECONDS)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }

        if (cancelled() || interrupted) {
            return snapshot(
                state = "CANCELLED", started = started, completed = System.currentTimeMillis(), selected = selected,
                plan = plan, scanned = progressCount.get().coerceAtMost(total), total = total, devices = emptyList(),
                error = null,
            )
        }

        discoverSsdp(selected.network, plan, selected.gatewayAddress, cancelled)
            .forEach { ip -> discovered.putIfAbsent(ip, ProbeResult(ip, emptySet())) }
        val mdns = discoverMdns(selected, plan, cancelled)
        mdns.keys.forEach { ip -> discovered.putIfAbsent(ip, ProbeResult(ip, emptySet())) }
        val arp = readArpNeighbors(selected.linkProperties.interfaceName, plan, selected.gatewayAddress)
        arp.keys.forEach { ip -> discovered.putIfAbsent(ip, ProbeResult(ip, emptySet())) }
        selected.gatewayAddress?.takeIf(::isPrivateIpv4Literal)?.let { discovered.putIfAbsent(it, ProbeResult(it, emptySet())) }

        val rawDevices = discovered.values.asSequence()
            .map { result -> buildDevice(result, arp[result.ip], mdns[result.ip], selected.gatewayAddress, plan.localAddress) }
            .sortedWith(compareByDescending<NetworkDevice> { it.riskScore }.thenBy { ipv4SortKey(it.ipAddress) })
            .take(MAX_RESULTS)
            .toList()

        val networkId = networkFingerprint(selected, plan.effectivePrefixLength)
        var completedSnapshot = snapshot(
            state = "COMPLETE", started = started, completed = System.currentTimeMillis(), selected = selected,
            plan = plan, scanned = progressCount.get().coerceAtMost(total), total = total, devices = rawDevices,
            error = null, networkId = networkId,
        )
        if (baselineStore.integrityOk()) {
            val delta = baselineStore.applyScan(networkId, rawDevices, completedSnapshot.completedAtMillis)
            completedSnapshot = baselineStore.markSnapshot(completedSnapshot, delta)
        } else {
            completedSnapshot = completedSnapshot.copy(
                baselineIntegrityOk = false,
                baselineFailureReason = baselineStore.integrityFailureReason(),
            )
        }
        return completedSnapshot
    }

    @Suppress("DEPRECATION")
    private fun selectLanNetwork(): SelectedNetwork? {
        val candidates = connectivity.allNetworks.mapNotNull { network ->
            val caps = connectivity.getNetworkCapabilities(network) ?: return@mapNotNull null
            val transport = when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "WIFI"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ETHERNET"
                else -> return@mapNotNull null
            }
            val links = connectivity.getLinkProperties(network) ?: return@mapNotNull null
            val local = links.linkAddresses.firstOrNull { link ->
                val address = link.address
                address is Inet4Address && NetworkRangePlanner.isPrivateIpv4(address.address)
            } ?: return@mapNotNull null
            val gateway = links.routes.asSequence()
                .filter { it.isDefaultRoute }
                .mapNotNull { it.gateway as? Inet4Address }
                .firstOrNull { NetworkRangePlanner.isPrivateIpv4(it.address) }
                ?.hostAddress
            SelectedNetwork(network, links, transport, local.address as Inet4Address, local.prefixLength, gateway)
        }
        return candidates.firstOrNull { it.transport == "WIFI" } ?: candidates.firstOrNull()
    }

    private fun probeHost(network: Network, ip: String, isGateway: Boolean, cancelled: () -> Boolean): ProbeResult {
        val open = linkedSetOf<Int>()
        val firstPass = if (isGateway) ALL_PORTS else QUICK_PORTS
        for (port in firstPass) {
            if (cancelled()) break
            if (canConnect(network, ip, port)) open += port
        }
        if (open.isNotEmpty() && !isGateway) {
            for (port in ALL_PORTS) {
                if (cancelled()) break
                if (port !in open && port !in QUICK_PORTS && canConnect(network, ip, port)) open += port
            }
        }
        return ProbeResult(ip, open)
    }

    private fun canConnect(network: Network, ip: String, port: Int): Boolean = try {
        network.socketFactory.createSocket().use { socket ->
            socket.tcpNoDelay = true
            socket.connect(InetSocketAddress(ip, port), CONNECT_TIMEOUT_MS)
            true
        }
    } catch (_: Exception) {
        false
    }

    private fun discoverSsdp(
        network: Network,
        plan: Ipv4ScanPlan,
        gateway: String?,
        cancelled: () -> Boolean,
    ): Set<String> {
        val out = linkedSetOf<String>()
        val request = (
            "M-SEARCH * HTTP/1.1\r\n" +
                "HOST: 239.255.255.250:1900\r\n" +
                "MAN: \"ssdp:discover\"\r\n" +
                "MX: 1\r\n" +
                "ST: ssdp:all\r\n\r\n"
            ).toByteArray(Charsets.US_ASCII)
        val target = InetSocketAddress(InetAddress.getByName("239.255.255.250"), 1900)
        val allowed = allowedAddresses(plan, gateway)
        return try {
            DatagramSocket(null).use { socket ->
                socket.reuseAddress = true
                socket.bind(InetSocketAddress(0))
                network.bindSocket(socket)
                socket.soTimeout = SSDP_RECEIVE_TIMEOUT_MS
                repeat(2) { socket.send(DatagramPacket(request, request.size, target)) }
                val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(SSDP_WINDOW_MS)
                val buffer = ByteArray(SSDP_MAX_PACKET_BYTES)
                while (!cancelled() && System.nanoTime() < deadline && out.size < SSDP_MAX_DEVICES) {
                    val packet = DatagramPacket(buffer, buffer.size)
                    try {
                        socket.receive(packet)
                        val ip = packet.address?.hostAddress ?: continue
                        if (ip in allowed) out += ip
                    } catch (_: SocketTimeoutException) {
                        break
                    }
                }
            }
            out
        } catch (_: Exception) {
            emptySet()
        }
    }

    private fun discoverMdns(selected: SelectedNetwork, plan: Ipv4ScanPlan, cancelled: () -> Boolean): Map<String, MdnsDeviceInfo> {
        val interfaceName = selected.linkProperties.interfaceName ?: return emptyMap()
        val networkInterface = try { NetworkInterface.getByName(interfaceName) } catch (_: Exception) { null } ?: return emptyMap()
        val allowed = allowedAddresses(plan, selected.gatewayAddress).apply { add(plan.localAddress) }
        val aggregate = MdnsAggregate()
        val multicastLock = if (selected.transport == "WIFI") {
            try {
                wifiManager?.createMulticastLock("GeDefenseNetworkDiscovery")?.apply {
                    setReferenceCounted(false)
                    acquire()
                }
            } catch (_: SecurityException) {
                null
            }
        } else null

        try {
            MulticastSocket(null).use { socket ->
                socket.reuseAddress = true
                selected.network.bindSocket(socket)
                socket.bind(InetSocketAddress(MDNS_PORT))
                socket.soTimeout = MDNS_RECEIVE_TIMEOUT_MS
                socket.timeToLive = 255
                socket.networkInterface = networkInterface
                val group = InetSocketAddress(InetAddress.getByName(MDNS_GROUP), MDNS_PORT)
                socket.joinGroup(group, networkInterface)
                try {
                    sendMdnsQuery(socket, group, listOf(DNS_SD_META_QUERY))
                    val dynamicTypes = receiveMdns(socket, aggregate, allowed, MDNS_META_WINDOW_MS, cancelled)
                        .filter(::isSafeServiceType)
                        .take(MDNS_MAX_DYNAMIC_TYPES)
                    if (!cancelled()) {
                        val types = (COMMON_MDNS_SERVICE_TYPES + dynamicTypes).distinct().take(MDNS_MAX_QUERY_TYPES)
                        sendMdnsQuery(socket, group, types)
                        receiveMdns(socket, aggregate, allowed, MDNS_SERVICE_WINDOW_MS, cancelled)
                    }
                } finally {
                    try { socket.leaveGroup(group, networkInterface) } catch (error: Exception) { RuntimeFailureLog.nonCritical("network-discovery-scanner", error) }
                }
            }
        } catch (_: Exception) {
            return emptyMap()
        } finally {
            try {
                if (multicastLock?.isHeld == true) multicastLock.release()
            } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("network-discovery-scanner", error) }
        }
        return buildMdnsDeviceMap(aggregate, allowed)
    }

    private fun sendMdnsQuery(socket: MulticastSocket, target: InetSocketAddress, serviceTypes: List<String>) {
        val query = MdnsDnsCodec.buildPtrQuery(serviceTypes) ?: return
        repeat(2) {
            try { socket.send(DatagramPacket(query, query.size, target)) } catch (_: Exception) { return }
        }
    }

    private fun receiveMdns(
        socket: MulticastSocket,
        aggregate: MdnsAggregate,
        allowed: Set<String>,
        windowMs: Long,
        cancelled: () -> Boolean,
    ): Set<String> {
        val discoveredTypes = linkedSetOf<String>()
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(windowMs)
        val buffer = ByteArray(MdnsDnsCodec.MAX_PACKET_BYTES)
        var acceptedPackets = 0
        while (!cancelled() && System.nanoTime() < deadline && acceptedPackets < MDNS_MAX_PACKETS) {
            val packet = DatagramPacket(buffer, buffer.size)
            try {
                socket.receive(packet)
            } catch (_: SocketTimeoutException) {
                continue
            } catch (_: Exception) {
                break
            }
            val sourceIp = packet.address?.hostAddress ?: continue
            if (sourceIp !in allowed || packet.length !in 12..MdnsDnsCodec.MAX_PACKET_BYTES) continue
            val parsed = MdnsDnsCodec.parse(packet.data, packet.length) ?: continue
            acceptedPackets++
            consumeMdns(parsed, aggregate, allowed, discoveredTypes)
        }
        return discoveredTypes
    }

    private fun consumeMdns(
        message: MdnsDnsMessage,
        aggregate: MdnsAggregate,
        allowed: Set<String>,
        discoveredTypes: MutableSet<String>,
    ) {
        message.records.asSequence().take(MdnsDnsCodec.MAX_RECORDS).forEach { record ->
            if (record.ttlSeconds <= 0L) return@forEach
            when (record.type) {
                MdnsDnsCodec.TYPE_A -> {
                    val ip = record.textValue ?: return@forEach
                    if (ip in allowed && isSafeDnsName(record.name)) {
                        aggregate.addresses.getOrPut(record.name) { linkedSetOf() }.let { addresses ->
                            if (addresses.size < MDNS_MAX_ADDRESSES_PER_HOST) addresses += ip
                        }
                    }
                }
                MdnsDnsCodec.TYPE_PTR -> {
                    val target = record.textValue ?: return@forEach
                    if (record.name == DNS_SD_META_QUERY) {
                        if (isSafeServiceType(target) && discoveredTypes.size < MDNS_MAX_DYNAMIC_TYPES) discoveredTypes += target
                    } else if (isSafeServiceType(record.name) && isSafeDnsName(target)) {
                        aggregate.ptrs.getOrPut(record.name) { linkedSetOf() }.let { instances ->
                            if (instances.size < MDNS_MAX_INSTANCES_PER_TYPE) instances += target
                        }
                    }
                }
                MdnsDnsCodec.TYPE_SRV -> {
                    val target = record.textValue ?: return@forEach
                    val port = record.port ?: return@forEach
                    if (isSafeDnsName(record.name) && isSafeDnsName(target) && port in 1..65535 && aggregate.srvs.size < MDNS_MAX_SERVICE_RECORDS) {
                        aggregate.srvs[record.name] = MdnsSrv(target, port)
                    }
                }
                MdnsDnsCodec.TYPE_TXT -> {
                    if (!isSafeDnsName(record.name)) return@forEach
                    val keys = record.txtEntries.asSequence()
                        .map { it.substringBefore('=').trim().lowercase() }
                        .filter { TXT_KEY.matches(it) }
                        .take(MDNS_MAX_TXT_KEYS)
                        .toCollection(linkedSetOf())
                    if (keys.isNotEmpty()) aggregate.txtKeys.getOrPut(record.name) { linkedSetOf() }.addAll(keys)
                }
            }
        }
    }

    private fun buildMdnsDeviceMap(aggregate: MdnsAggregate, allowed: Set<String>): Map<String, MdnsDeviceInfo> {
        val servicesByIp = linkedMapOf<String, MutableList<NetworkDnsSdService>>()
        val hostByIp = linkedMapOf<String, String>()
        aggregate.addresses.forEach { (host, addresses) ->
            addresses.filter { it in allowed }.forEach { ip -> hostByIp.putIfAbsent(ip, host) }
        }
        aggregate.ptrs.forEach { (serviceType, instances) ->
            instances.take(MDNS_MAX_INSTANCES_PER_TYPE).forEach instanceLoop@ { instance ->
                val srv = aggregate.srvs[instance] ?: return@instanceLoop
                val ips = aggregate.addresses[srv.targetHost].orEmpty().filter { it in allowed }
                val instanceName = instanceDisplayName(instance, serviceType)
                val txtKeys = aggregate.txtKeys[instance].orEmpty().take(MDNS_MAX_TXT_KEYS).toSet()
                ips.forEach { ip ->
                    val list = servicesByIp.getOrPut(ip) { mutableListOf() }
                    if (list.size < MDNS_MAX_SERVICES_PER_DEVICE && list.none { it.serviceType == serviceType && it.port == srv.port }) {
                        list += NetworkDnsSdService(
                            serviceType = serviceType,
                            instanceName = instanceName,
                            targetHost = srv.targetHost,
                            port = srv.port,
                            txtKeys = txtKeys,
                        )
                    }
                }
            }
        }
        val allIps = LinkedHashSet<String>().apply { addAll(hostByIp.keys); addAll(servicesByIp.keys) }
        return allIps.take(MAX_RESULTS).associateWith { ip ->
            MdnsDeviceInfo(
                hostname = hostByIp[ip],
                services = servicesByIp[ip].orEmpty().sortedWith(compareBy<NetworkDnsSdService> { it.serviceType }.thenBy { it.port ?: 0 }),
            )
        }
    }

    private fun readArpNeighbors(interfaceName: String?, plan: Ipv4ScanPlan, gateway: String?): Map<String, String> {
        val file = File("/proc/net/arp")
        if (!file.isFile || !file.canRead() || file.length() !in 1..MAX_ARP_BYTES) return emptyMap()
        val allowed = allowedAddresses(plan, gateway)
        val out = linkedMapOf<String, String>()
        return try {
            file.bufferedReader().useLines { lines ->
                lines.drop(1).take(MAX_ARP_LINES).forEach { line ->
                    val parts = line.trim().split(Regex("\\s+"))
                    if (parts.size < 6) return@forEach
                    val ip = parts[0]
                    val flags = parts[2]
                    val mac = parts[3].lowercase()
                    val dev = parts[5]
                    if (ip !in allowed || !isValidMac(mac) || flags == "0x0") return@forEach
                    if (!interfaceName.isNullOrBlank() && dev != interfaceName) return@forEach
                    out[ip] = mac
                }
            }
            out
        } catch (_: Exception) {
            emptyMap()
        }
    }

    private fun buildDevice(
        result: ProbeResult,
        mac: String?,
        mdns: MdnsDeviceInfo?,
        gateway: String?,
        localIp: String,
    ): NetworkDevice {
        val exposures = result.openPorts.sorted().mapNotNull(PORTS::get)
        val advertised = mdns?.services.orEmpty().take(MDNS_MAX_SERVICES_PER_DEVICE)
        val score = (exposures.sumOf { serviceRiskPoints(it.port) } + advertised.sumOf { advertisedServiceRiskPoints(it.serviceType) }).coerceAtMost(100)
        val risk = when {
            score >= 65 -> NetworkDeviceRisk.CRITICAL
            score >= 35 -> NetworkDeviceRisk.HIGH
            score >= 15 -> NetworkDeviceRisk.REVIEW
            else -> NetworkDeviceRisk.INFO
        }
        val role = inferRole(result.ip, result.openPorts, advertised, gateway, localIp)
        val hostname = mdns?.hostname?.take(MAX_HOST_CHARS)
        val identitySource: NetworkIdentitySource
        val stableId = when {
            mac != null -> {
                identitySource = NetworkIdentitySource.MAC
                "mac:$mac"
            }
            !hostname.isNullOrBlank() -> {
                identitySource = NetworkIdentitySource.MDNS_HOST
                "mdns:${sha256Hex(hostname).take(40)}"
            }
            else -> {
                identitySource = NetworkIdentitySource.IP
                "ip:${result.ip}"
            }
        }
        return NetworkDevice(
            stableId = stableId,
            identitySource = identitySource,
            ipAddress = result.ip,
            macAddress = mac,
            hostname = hostname,
            role = role,
            openServices = exposures,
            advertisedServices = advertised,
            riskScore = score,
            risk = risk,
            isGateway = result.ip == gateway,
            isThisDevice = result.ip == localIp,
        )
    }

    private fun inferRole(
        ip: String,
        ports: Set<Int>,
        advertised: List<NetworkDnsSdService>,
        gateway: String?,
        localIp: String,
    ): String {
        val serviceTypes = advertised.asSequence().map { it.serviceType }.toSet()
        return when {
            ip == localIp -> "THIS_DEVICE"
            ip == gateway -> "ROUTER_GATEWAY"
            5555 in ports || serviceTypes.any { it.startsWith("_adb-tls-") } -> "ANDROID_DEBUG"
            631 in ports || 9100 in ports || "_ipp._tcp.local" in serviceTypes || "_printer._tcp.local" in serviceTypes -> "PRINTER"
            8008 in ports || 8009 in ports || "_googlecast._tcp.local" in serviceTypes || "_airplay._tcp.local" in serviceTypes || "_raop._tcp.local" in serviceTypes -> "CAST_MEDIA"
            554 in ports || "_rtsp._tcp.local" in serviceTypes -> "CAMERA_MEDIA"
            445 in ports || 139 in ports || "_smb._tcp.local" in serviceTypes || "_afpovertcp._tcp.local" in serviceTypes -> "NAS_FILE_SERVER"
            3389 in ports || "_rdp._tcp.local" in serviceTypes || "_rfb._tcp.local" in serviceTypes -> "REMOTE_DESKTOP"
            "_hap._tcp.local" in serviceTypes || "_homekit._tcp.local" in serviceTypes -> "SMART_HOME"
            "_workstation._tcp.local" in serviceTypes || "_ssh._tcp.local" in serviceTypes -> "WORKSTATION_SERVER"
            else -> "NETWORK_DEVICE"
        }
    }

    private fun snapshot(
        state: String,
        started: Long,
        completed: Long,
        selected: SelectedNetwork,
        plan: Ipv4ScanPlan,
        scanned: Int,
        total: Int,
        devices: List<NetworkDevice>,
        error: String?,
        networkId: String = networkFingerprint(selected, plan.effectivePrefixLength),
    ) = NetworkDiscoverySnapshot(
        state = state,
        startedAtMillis = started,
        completedAtMillis = completed,
        networkId = networkId,
        transport = selected.transport,
        interfaceName = selected.linkProperties.interfaceName.orEmpty().take(64),
        localAddress = plan.localAddress,
        prefixLength = selected.prefixLength,
        effectivePrefixLength = plan.effectivePrefixLength,
        gatewayAddress = selected.gatewayAddress,
        scopeClamped = plan.scopeClamped,
        scannedHosts = scanned,
        totalHosts = total,
        devices = devices,
        baselineIntegrityOk = baselineStore.integrityOk(),
        baselineFailureReason = baselineStore.integrityFailureReason(),
        errorReason = error,
    )

    private fun unavailable(started: Long, reason: String) = NetworkDiscoverySnapshot.idle().copy(
        state = "UNAVAILABLE",
        startedAtMillis = started,
        completedAtMillis = System.currentTimeMillis(),
        baselineIntegrityOk = baselineStore.integrityOk(),
        baselineFailureReason = baselineStore.integrityFailureReason(),
        errorReason = reason,
    )

    private fun networkFingerprint(selected: SelectedNetwork, effectivePrefix: Int): String {
        val local = selected.localAddress.address
        val prefixBytes = networkAddress(local, effectivePrefix)
        val dns = selected.linkProperties.dnsServers.asSequence()
            .filterIsInstance<Inet4Address>()
            .mapNotNull { it.hostAddress }
            .sorted()
            .joinToString(",")
        val material = "${selected.transport}|${selected.linkProperties.interfaceName.orEmpty()}|${prefixBytes.joinToString(".") { (it.toInt() and 0xff).toString() }}/$effectivePrefix|${selected.gatewayAddress.orEmpty()}|$dns"
        return sha256Hex(material)
    }

    private fun networkAddress(address: ByteArray, prefix: Int): ByteArray {
        val out = address.copyOf()
        var bits = prefix
        for (i in out.indices) {
            val keep = bits.coerceIn(0, 8)
            val mask = if (keep == 0) 0 else (0xff shl (8 - keep)) and 0xff
            out[i] = ((out[i].toInt() and 0xff) and mask).toByte()
            bits -= keep
        }
        return out
    }

    private fun allowedAddresses(plan: Ipv4ScanPlan, gateway: String?): LinkedHashSet<String> =
        LinkedHashSet(plan.targets).apply { gateway?.takeIf(::isPrivateIpv4Literal)?.let(::add) }

    private fun parseIpv4Literal(value: String): ByteArray? {
        val parts = value.split('.')
        if (parts.size != 4) return null
        val octets = IntArray(4)
        for (index in parts.indices) {
            val octet = parts[index].toIntOrNull() ?: return null
            if (octet !in 0..255) return null
            octets[index] = octet
        }
        return ByteArray(4) { index -> octets[index].toByte() }
    }

    private fun isPrivateIpv4Literal(value: String): Boolean =
        parseIpv4Literal(value)?.let(NetworkRangePlanner::isPrivateIpv4) == true

    private fun isValidMac(value: String): Boolean =
        MAC.matches(value) && value != "00:00:00:00:00:00" && value != "ff:ff:ff:ff:ff:ff"

    private fun isSafeDnsName(value: String): Boolean =
        value.length in 1..253 && DNS_NAME.matches(value)

    private fun isSafeServiceType(value: String): Boolean =
        value.length in 7..160 && SERVICE_TYPE.matches(value)

    private fun instanceDisplayName(instance: String, serviceType: String): String {
        val suffix = ".$serviceType"
        val raw = if (instance.endsWith(suffix)) instance.dropLast(suffix.length) else instance
        return raw.take(MAX_INSTANCE_CHARS)
    }

    private fun ipv4SortKey(ip: String): Long {
        val address = parseIpv4Literal(ip) ?: return Long.MAX_VALUE
        return address.fold(0L) { acc, octet -> (acc shl 8) or (octet.toLong() and 0xffL) }
    }

    private fun sha256Hex(value: String): String =
        MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

    private fun serviceRiskPoints(port: Int): Int = when (port) {
        5555 -> 70
        23 -> 55
        3389, 5900 -> 35
        21 -> 28
        445 -> 24
        139 -> 18
        554 -> 14
        22 -> 8
        631, 9100 -> 6
        80, 8080 -> 4
        53, 443, 8443, 8008, 8009 -> 2
        else -> 1
    }

    private fun advertisedServiceRiskPoints(serviceType: String): Int = when (serviceType) {
        "_adb-tls-connect._tcp.local", "_adb-tls-pairing._tcp.local" -> 38
        "_telnet._tcp.local" -> 34
        "_rdp._tcp.local", "_rfb._tcp.local" -> 22
        "_smb._tcp.local", "_afpovertcp._tcp.local" -> 12
        "_ssh._tcp.local" -> 6
        else -> 1
    }

    companion object {
        private const val MAX_WORKERS = 32
        private const val CONNECT_TIMEOUT_MS = 140
        private const val MAX_RESULTS = 512
        private const val MAX_HOST_CHARS = 160
        private const val MAX_INSTANCE_CHARS = 120
        private const val MAX_ARP_BYTES = 256L * 1024L
        private const val MAX_ARP_LINES = 1024
        private const val SSDP_WINDOW_MS = 900L
        private const val SSDP_RECEIVE_TIMEOUT_MS = 180
        private const val SSDP_MAX_PACKET_BYTES = 2048
        private const val SSDP_MAX_DEVICES = 128
        private const val MDNS_GROUP = "224.0.0.251"
        private const val MDNS_PORT = 5353
        private const val MDNS_RECEIVE_TIMEOUT_MS = 140
        private const val MDNS_META_WINDOW_MS = 350L
        private const val MDNS_SERVICE_WINDOW_MS = 1_000L
        private const val MDNS_MAX_PACKETS = 128
        private const val MDNS_MAX_DYNAMIC_TYPES = 12
        private const val MDNS_MAX_QUERY_TYPES = 24
        private const val MDNS_MAX_SERVICE_RECORDS = 256
        private const val MDNS_MAX_INSTANCES_PER_TYPE = 64
        private const val MDNS_MAX_ADDRESSES_PER_HOST = 8
        private const val MDNS_MAX_SERVICES_PER_DEVICE = 32
        private const val MDNS_MAX_TXT_KEYS = 16
        private const val DNS_SD_META_QUERY = "_services._dns-sd._udp.local"
        private val MAC = Regex("(?i)^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
        private val DNS_NAME = Regex("^[a-z0-9_ .()'&+@-]+(?:\\.[a-z0-9_ .()'&+@-]+)*$")
        private val SERVICE_TYPE = Regex("^_[a-z0-9-]{1,32}\\._(?:tcp|udp)\\.local$")
        private val TXT_KEY = Regex("^[a-z0-9_.-]{1,40}$")
        private val QUICK_PORTS = intArrayOf(22, 23, 53, 80, 443, 445, 554, 631, 3389, 5555, 5900, 8008, 8080, 9100)
        private val ALL_PORTS = intArrayOf(21, 22, 23, 53, 80, 139, 443, 445, 548, 554, 631, 3389, 5555, 5900, 8008, 8009, 8080, 8443, 9100)
        private val COMMON_MDNS_SERVICE_TYPES = listOf(
            "_http._tcp.local",
            "_https._tcp.local",
            "_ssh._tcp.local",
            "_smb._tcp.local",
            "_afpovertcp._tcp.local",
            "_ipp._tcp.local",
            "_printer._tcp.local",
            "_googlecast._tcp.local",
            "_airplay._tcp.local",
            "_raop._tcp.local",
            "_rtsp._tcp.local",
            "_workstation._tcp.local",
            "_hap._tcp.local",
            "_homekit._tcp.local",
            "_rdp._tcp.local",
            "_rfb._tcp.local",
            "_adb-tls-connect._tcp.local",
            "_adb-tls-pairing._tcp.local",
        )
        private val PORTS = mapOf(
            21 to NetworkServiceExposure(21, "FTP", NetworkDeviceRisk.REVIEW),
            22 to NetworkServiceExposure(22, "SSH", NetworkDeviceRisk.INFO),
            23 to NetworkServiceExposure(23, "TELNET", NetworkDeviceRisk.HIGH),
            53 to NetworkServiceExposure(53, "DNS", NetworkDeviceRisk.INFO),
            80 to NetworkServiceExposure(80, "HTTP", NetworkDeviceRisk.INFO),
            139 to NetworkServiceExposure(139, "NETBIOS", NetworkDeviceRisk.REVIEW),
            443 to NetworkServiceExposure(443, "HTTPS", NetworkDeviceRisk.INFO),
            445 to NetworkServiceExposure(445, "SMB", NetworkDeviceRisk.REVIEW),
            548 to NetworkServiceExposure(548, "AFP", NetworkDeviceRisk.REVIEW),
            554 to NetworkServiceExposure(554, "RTSP", NetworkDeviceRisk.REVIEW),
            631 to NetworkServiceExposure(631, "IPP", NetworkDeviceRisk.INFO),
            3389 to NetworkServiceExposure(3389, "RDP", NetworkDeviceRisk.HIGH),
            5555 to NetworkServiceExposure(5555, "ADB", NetworkDeviceRisk.CRITICAL),
            5900 to NetworkServiceExposure(5900, "VNC", NetworkDeviceRisk.HIGH),
            8008 to NetworkServiceExposure(8008, "CAST", NetworkDeviceRisk.INFO),
            8009 to NetworkServiceExposure(8009, "CAST", NetworkDeviceRisk.INFO),
            8080 to NetworkServiceExposure(8080, "HTTP-ALT", NetworkDeviceRisk.INFO),
            8443 to NetworkServiceExposure(8443, "HTTPS-ALT", NetworkDeviceRisk.INFO),
            9100 to NetworkServiceExposure(9100, "JETDIRECT", NetworkDeviceRisk.INFO),
        )
    }
}
