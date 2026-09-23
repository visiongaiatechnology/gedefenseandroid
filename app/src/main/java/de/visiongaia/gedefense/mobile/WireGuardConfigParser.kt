package de.visiongaia.gedefense.mobile

import android.net.InetAddresses
import android.util.Base64
import java.net.IDN
import java.net.Inet4Address
import java.net.InetAddress
import java.nio.charset.StandardCharsets

// STATUS: DIAMANT VGT SUPREME
internal object WireGuardConfigParser {
    private const val MAX_CONFIG_CHARS = 16 * 1024
    private const val MAX_CONFIG_BYTES = 16 * 1024
    private const val MAX_LINES = 128
    private const val KEY_BYTES = 32
    private const val MAX_INTERFACE_ADDRESSES = 8
    private const val MAX_DNS_SERVERS = 4
    private const val MAX_ALLOWED_IPS = 64

    fun parse(text: String): WireGuardProfile {
        require(text.length in 1..MAX_CONFIG_CHARS) { "wireguard_config_size_invalid" }
        require(text.toByteArray(StandardCharsets.UTF_8).size <= MAX_CONFIG_BYTES) { "wireguard_config_size_invalid" }
        var section = ""
        var privateKey: ByteArray? = null
        val addresses = mutableListOf<WireGuardInterfaceAddress>()
        val dns = mutableListOf<String>()
        var mtu = WireGuardProfileStore.DEFAULT_MTU
        var publicKey: ByteArray? = null
        var presharedKey: ByteArray? = null
        var endpointHost: String? = null
        var endpointPort = 0
        val allowed = mutableListOf<WireGuardAllowedIp>()
        var keepalive = 0
        var peers = 0
        var interfaceSeen = false
        var peerSeen = false
        var mtuSeen = false
        var keepaliveSeen = false
        var lines = 0

        try {
            text.lineSequence().forEach { rawLine ->
                lines++
                require(lines <= MAX_LINES) { "wireguard_config_line_limit" }
                val line = rawLine.substringBefore('#').trim()
                if (line.isEmpty()) return@forEach
                if (line.startsWith('[') && line.endsWith(']')) {
                    section = line.substring(1, line.length - 1).trim().lowercase()
                    require(section == "interface" || section == "peer") { "wireguard_section_invalid" }
                    when (section) {
                        "interface" -> {
                            require(!interfaceSeen && !peerSeen) { "wireguard_interface_section_order_invalid" }
                            interfaceSeen = true
                        }
                        "peer" -> {
                            require(interfaceSeen && !peerSeen) { "wireguard_peer_section_order_invalid" }
                            peerSeen = true
                            peers++
                        }
                    }
                    return@forEach
                }
                val split = line.indexOf('=')
                require(split in 1 until line.lastIndex) { "wireguard_line_invalid" }
                val key = line.substring(0, split).trim().lowercase()
                val value = line.substring(split + 1).trim()
                require(value.isNotEmpty()) { "wireguard_value_empty" }
                when (section) {
                    "interface" -> when (key) {
                        "privatekey" -> { require(privateKey == null) { "wireguard_private_key_duplicate" }; privateKey = decodeKey(value, false) }
                        "address" -> value.split(',').forEach { addresses += parseInterfaceAddress(it.trim()) }
                        "dns" -> value.split(',').forEach { dns += parseDns(it.trim()) }
                        "mtu" -> {
                            require(!mtuSeen) { "wireguard_mtu_duplicate" }
                            mtuSeen = true
                            mtu = value.toIntOrNull()?.takeIf { it in 1280..1420 }
                                ?: throw IllegalArgumentException("wireguard_mtu_invalid")
                        }
                        else -> throw IllegalArgumentException("wireguard_interface_key_unsupported")
                    }
                    "peer" -> when (key) {
                        "publickey" -> { require(publicKey == null) { "wireguard_public_key_duplicate" }; publicKey = decodeKey(value, false) }
                        "presharedkey" -> { require(presharedKey == null) { "wireguard_preshared_key_duplicate" }; presharedKey = decodeKey(value, true) }
                        "endpoint" -> { require(endpointHost == null) { "wireguard_endpoint_duplicate" }; parseEndpoint(value).also { endpointHost = it.first; endpointPort = it.second } }
                        "allowedips" -> value.split(',').forEach { allowed += parseAllowedIp(it.trim()) }
                        "persistentkeepalive" -> {
                            require(!keepaliveSeen) { "wireguard_keepalive_duplicate" }
                            keepaliveSeen = true
                            keepalive = value.toIntOrNull()?.takeIf { it in 0..65535 }
                                ?: throw IllegalArgumentException("wireguard_keepalive_invalid")
                        }
                        else -> throw IllegalArgumentException("wireguard_peer_key_unsupported")
                    }
                    else -> throw IllegalArgumentException("wireguard_section_missing")
                }
            }
            require(peers == 1) { "wireguard_single_peer_required" }
            require(addresses.size in 1..MAX_INTERFACE_ADDRESSES) { "wireguard_address_count_invalid" }
            require(dns.size in 1..MAX_DNS_SERVERS) { "wireguard_dns_count_invalid" }
            require(allowed.size in 1..MAX_ALLOWED_IPS) { "wireguard_allowed_ip_count_invalid" }
            require(addresses.any { isIpv4(it.address) }) { "wireguard_ipv4_interface_required" }
            require(allowed.any { it.network == "0.0.0.0" && it.prefixLength == 0 }) { "wireguard_full_tunnel_ipv4_required" }
            val hasIpv6Interface = addresses.any { !isIpv4(it.address) }
            val hasIpv6Default = allowed.any { !isIpv4(it.network) && it.prefixLength == 0 }
            val hasIpv6Dns = dns.any { !isIpv4(it) }
            require(!hasIpv6Dns || hasIpv6Interface) { "wireguard_ipv6_dns_requires_interface" }
            require(!hasIpv6Interface || hasIpv6Default) { "wireguard_full_tunnel_ipv6_required" }
            require(!hasIpv6Default || hasIpv6Interface) { "wireguard_ipv6_default_requires_interface" }
            val profile = WireGuardProfile(
                privateKey = privateKey ?: throw IllegalArgumentException("wireguard_private_key_missing"),
                interfaceAddresses = addresses.distinct(),
                dnsServers = dns.distinct(),
                mtu = mtu,
                peerPublicKey = publicKey ?: throw IllegalArgumentException("wireguard_public_key_missing"),
                presharedKey = presharedKey,
                endpointHost = endpointHost ?: throw IllegalArgumentException("wireguard_endpoint_missing"),
                endpointPort = endpointPort,
                allowedIps = allowed.distinct(),
                persistentKeepaliveSeconds = keepalive,
            )
            require(validateDecoded(profile)) { "wireguard_profile_invalid" }
            return profile
        } catch (error: Exception) {
            privateKey?.fill(0); publicKey?.fill(0); presharedKey?.fill(0)
            if (error is IllegalArgumentException) throw error
            throw IllegalArgumentException("wireguard_config_invalid")
        }
    }

    fun validateDecoded(profile: WireGuardProfile): Boolean {
        if (profile.privateKey.size != KEY_BYTES || profile.privateKey.all { it == 0.toByte() }) return false
        if (profile.peerPublicKey.size != KEY_BYTES || profile.peerPublicKey.all { it == 0.toByte() }) return false
        if (profile.privateKey.contentEquals(profile.peerPublicKey)) return false
        profile.presharedKey?.let { if (it.size != KEY_BYTES) return false }
        if (profile.interfaceAddresses.size !in 1..MAX_INTERFACE_ADDRESSES || profile.dnsServers.size !in 1..MAX_DNS_SERVERS) return false
        if (profile.allowedIps.size !in 1..MAX_ALLOWED_IPS || profile.allowedIps.none { it.network == "0.0.0.0" && it.prefixLength == 0 }) return false
        if (profile.interfaceAddresses.none { isIpv4(it.address) }) return false
        val hasIpv6Interface = profile.interfaceAddresses.any { !isIpv4(it.address) }
        val hasIpv6Default = profile.allowedIps.any { !isIpv4(it.network) && it.prefixLength == 0 }
        if (profile.dnsServers.any { !isIpv4(it) } && !hasIpv6Interface) return false
        if (hasIpv6Interface != hasIpv6Default) return false
        if (profile.mtu !in 1280..1420 || profile.persistentKeepaliveSeconds !in 0..65535 || profile.endpointPort !in 1..65535) return false
        if (!validHost(profile.endpointHost)) return false
        if (profile.interfaceAddresses.any { runCatching { parseInterfaceAddress("${it.address}/${it.prefixLength}") }.isFailure }) return false
        if (profile.dnsServers.any { runCatching { parseDns(it) }.isFailure }) return false
        if (profile.allowedIps.any { runCatching { parseAllowedIp("${it.network}/${it.prefixLength}") }.isFailure }) return false
        return true
    }

    private fun decodeKey(value: String, allowZero: Boolean): ByteArray {
        val decoded = try { Base64.decode(value, Base64.NO_WRAP) } catch (_: IllegalArgumentException) { throw IllegalArgumentException("wireguard_key_invalid") }
        require(decoded.size == KEY_BYTES && (allowZero || decoded.any { it != 0.toByte() })) { "wireguard_key_invalid" }
        return decoded
    }

    private fun parseInterfaceAddress(value: String): WireGuardInterfaceAddress {
        val split = value.lastIndexOf('/')
        require(split > 0 && split < value.lastIndex) { "wireguard_address_invalid" }
        val address = numeric(value.substring(0, split))
        val prefix = value.substring(split + 1).toIntOrNull() ?: throw IllegalArgumentException("wireguard_address_prefix_invalid")
        require(prefix in 0..if (address is Inet4Address) 32 else 128) { "wireguard_address_prefix_invalid" }
        require(
            !address.isAnyLocalAddress && !address.isMulticastAddress &&
                !address.isLoopbackAddress && !address.isLinkLocalAddress,
        ) { "wireguard_address_invalid" }
        return WireGuardInterfaceAddress(normalize(address), prefix)
    }

    private fun parseAllowedIp(value: String): WireGuardAllowedIp {
        val split = value.lastIndexOf('/')
        require(split > 0 && split < value.lastIndex) { "wireguard_allowed_ip_invalid" }
        val address = numeric(value.substring(0, split))
        val prefix = value.substring(split + 1).toIntOrNull() ?: throw IllegalArgumentException("wireguard_allowed_prefix_invalid")
        val max = if (address is Inet4Address) 32 else 128
        require(prefix in 0..max) { "wireguard_allowed_prefix_invalid" }
        val masked = maskAddress(address.address, prefix)
        val canonical = normalize(InetAddress.getByAddress(masked))
        require(canonical == normalize(address)) { "wireguard_allowed_ip_not_canonical" }
        return WireGuardAllowedIp(canonical, prefix)
    }

    private fun parseDns(value: String): String {
        val address = numeric(value)
        require(!address.isAnyLocalAddress && !address.isMulticastAddress && !address.isLoopbackAddress && !address.isLinkLocalAddress) {
            "wireguard_dns_invalid"
        }
        return normalize(address)
    }

    private fun parseEndpoint(value: String): Pair<String, Int> {
        val host: String
        val portText: String
        if (value.startsWith('[')) {
            val close = value.indexOf(']')
            require(close > 1 && close + 2 < value.length && value[close + 1] == ':') { "wireguard_endpoint_invalid" }
            host = value.substring(1, close)
            portText = value.substring(close + 2)
        } else {
            val split = value.lastIndexOf(':')
            require(split > 0 && split < value.lastIndex) { "wireguard_endpoint_invalid" }
            host = value.substring(0, split)
            portText = value.substring(split + 1)
        }
        val port = portText.toIntOrNull()?.takeIf { it in 1..65535 } ?: throw IllegalArgumentException("wireguard_endpoint_port_invalid")
        val normalizedHost = if (InetAddresses.isNumericAddress(host)) {
            val address = InetAddresses.parseNumericAddress(host)
            require(
                !address.isAnyLocalAddress && !address.isMulticastAddress &&
                    !address.isLoopbackAddress && !address.isLinkLocalAddress,
            ) { "wireguard_endpoint_host_invalid" }
            normalize(address)
        } else normalizeHost(host)
        require(validHost(normalizedHost)) { "wireguard_endpoint_host_invalid" }
        return normalizedHost to port
    }

    private fun isIpv4(value: String): Boolean = numeric(value) is Inet4Address

    private fun normalizeHost(host: String): String {
        val trimmed = host.trim().trimEnd('.')
        require(trimmed.length in 1..253) { "wireguard_endpoint_host_invalid" }
        return try { IDN.toASCII(trimmed, IDN.USE_STD3_ASCII_RULES).lowercase() }
        catch (_: IllegalArgumentException) { throw IllegalArgumentException("wireguard_endpoint_host_invalid") }
    }

    private fun validHost(host: String): Boolean {
        if (host.length !in 1..253) return false
        if (InetAddresses.isNumericAddress(host)) {
            val address = try { InetAddresses.parseNumericAddress(host) } catch (_: IllegalArgumentException) { return false }
            return !address.isAnyLocalAddress && !address.isMulticastAddress &&
                !address.isLoopbackAddress && !address.isLinkLocalAddress
        }
        return try { IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).equals(host, ignoreCase = true) } catch (_: IllegalArgumentException) { false }
    }

    private fun numeric(value: String): InetAddress = try { InetAddresses.parseNumericAddress(value.trim()) }
    catch (_: IllegalArgumentException) { throw IllegalArgumentException("wireguard_ip_invalid") }

    private fun normalize(address: InetAddress): String = requireNotNull(address.hostAddress) { "wireguard_ip_invalid" }.substringBefore('%').lowercase()

    private fun maskAddress(bytes: ByteArray, prefix: Int): ByteArray {
        val out = bytes.copyOf()
        var remaining = prefix
        for (i in out.indices) {
            val bits = remaining.coerceIn(0, 8)
            val mask = if (bits == 0) 0 else (0xff shl (8 - bits)) and 0xff
            out[i] = (out[i].toInt() and mask).toByte()
            remaining -= bits
        }
        return out
    }
}

