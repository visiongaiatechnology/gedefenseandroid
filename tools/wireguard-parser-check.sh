#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
command -v kotlinc >/dev/null 2>&1 || { echo 'WIREGUARD_PARSER_CHECK_FAIL kotlinc_unavailable' >&2; exit 1; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/android/net" "$TMP/android/util" "$TMP/de/visiongaia/gedefense/mobile"

cat > "$TMP/android/net/InetAddresses.kt" <<'KOTLIN'
package android.net

import java.net.Inet6Address
import java.net.InetAddress

object InetAddresses {
    fun isNumericAddress(value: String): Boolean = runCatching { parseNumericAddress(value); true }.getOrDefault(false)

    fun parseNumericAddress(value: String): InetAddress {
        val text = value.trim()
        require(text.isNotEmpty())
        if (':' in text) {
            val parsed = InetAddress.getByName(text)
            require(parsed is Inet6Address || text.startsWith("::ffff:", ignoreCase = true))
            return parsed
        }
        val parts = text.split('.')
        require(parts.size == 4)
        val bytes = ByteArray(4)
        parts.forEachIndexed { index, part ->
            require(part.isNotEmpty() && part.length <= 3 && part.all(Char::isDigit))
            val number = part.toInt()
            require(number in 0..255)
            bytes[index] = number.toByte()
        }
        return InetAddress.getByAddress(bytes)
    }
}
KOTLIN

cat > "$TMP/android/util/Base64.kt" <<'KOTLIN'
package android.util

object Base64 {
    const val NO_WRAP: Int = 2
    fun decode(value: String, flags: Int): ByteArray {
        @Suppress("UNUSED_VARIABLE") val ignored = flags
        return java.util.Base64.getDecoder().decode(value)
    }
}
KOTLIN

cat > "$TMP/de/visiongaia/gedefense/mobile/WireGuardModels.kt" <<'KOTLIN'
package de.visiongaia.gedefense.mobile

data class WireGuardInterfaceAddress(val address: String, val prefixLength: Int)
data class WireGuardAllowedIp(val network: String, val prefixLength: Int)
data class WireGuardProfile(
    val privateKey: ByteArray,
    val interfaceAddresses: List<WireGuardInterfaceAddress>,
    val dnsServers: List<String>,
    val mtu: Int,
    val peerPublicKey: ByteArray,
    val presharedKey: ByteArray?,
    val endpointHost: String,
    val endpointPort: Int,
    val allowedIps: List<WireGuardAllowedIp>,
    val persistentKeepaliveSeconds: Int,
)
object WireGuardProfileStore { const val DEFAULT_MTU = 1280 }
KOTLIN

cat > "$TMP/de/visiongaia/gedefense/mobile/WireGuardParserCheck.kt" <<'KOTLIN'
package de.visiongaia.gedefense.mobile

import java.util.Base64

private fun key(fill: Int): String = Base64.getEncoder().encodeToString(ByteArray(32) { fill.toByte() })

private fun validConfig(extraInterface: String = "", extraPeer: String = "", allowed: String = "0.0.0.0/0"): String = """
    [Interface]
    PrivateKey = ${key(1)}
    Address = 10.77.0.2/32
    DNS = 1.1.1.1
    MTU = 1380
    $extraInterface
    [Peer]
    PublicKey = ${key(2)}
    Endpoint = 198.51.100.7:51820
    AllowedIPs = $allowed
    PersistentKeepalive = 25
    $extraPeer
""".trimIndent()

private fun expectReject(name: String, config: String, expected: String) {
    val message = runCatching { WireGuardConfigParser.parse(config) }.exceptionOrNull()?.message
    check(message == expected) { "$name: expected=$expected actual=$message" }
}

fun main() {
    val parsed = WireGuardConfigParser.parse(validConfig())
    check(parsed.mtu == 1380)
    check(parsed.dnsServers == listOf("1.1.1.1"))
    check(parsed.allowedIps.single() == WireGuardAllowedIp("0.0.0.0", 0))
    parsed.privateKey.fill(0)
    parsed.peerPublicKey.fill(0)

    expectReject(
        "dns required",
        validConfig().lineSequence().filterNot { it.trim().startsWith("DNS") }.joinToString("\n"),
        "wireguard_dns_count_invalid",
    )
    expectReject(
        "duplicate interface",
        validConfig().replace("[Peer]", "[Interface]\n[Peer]"),
        "wireguard_interface_section_order_invalid",
    )
    expectReject(
        "duplicate mtu",
        validConfig(extraInterface = "MTU = 1300"),
        "wireguard_mtu_duplicate",
    )
    expectReject(
        "loopback endpoint",
        validConfig().replace("198.51.100.7:51820", "127.0.0.1:51820"),
        "wireguard_endpoint_host_invalid",
    )
    expectReject(
        "non canonical allowed ip",
        validConfig(allowed = "10.0.0.1/8, 0.0.0.0/0"),
        "wireguard_allowed_ip_not_canonical",
    )
    expectReject(
        "ipv6 interface requires default",
        validConfig(extraInterface = "Address = fd77::2/128"),
        "wireguard_full_tunnel_ipv6_required",
    )
    expectReject(
        "ipv6 dns requires interface",
        validConfig().replace("DNS = 1.1.1.1", "DNS = 2606:4700:4700::1111"),
        "wireguard_ipv6_dns_requires_interface",
    )

    val dual = WireGuardConfigParser.parse(
        validConfig(
            extraInterface = "Address = fd77::2/128\nDNS = 2606:4700:4700::1111",
            allowed = "0.0.0.0/0, ::/0",
        ),
    )
    check(dual.interfaceAddresses.size == 2)
    check(dual.allowedIps.size == 2)
    dual.privateKey.fill(0)
    dual.peerPublicKey.fill(0)

    val restoredBadEndpoint = WireGuardProfile(
        privateKey = ByteArray(32) { 1 },
        interfaceAddresses = listOf(WireGuardInterfaceAddress("10.77.0.2", 32)),
        dnsServers = listOf("1.1.1.1"),
        mtu = 1280,
        peerPublicKey = ByteArray(32) { 2 },
        presharedKey = null,
        endpointHost = "127.0.0.1",
        endpointPort = 51820,
        allowedIps = listOf(WireGuardAllowedIp("0.0.0.0", 0)),
        persistentKeepaliveSeconds = 25,
    )
    check(!WireGuardConfigParser.validateDecoded(restoredBadEndpoint))
    restoredBadEndpoint.privateKey.fill(0)
    restoredBadEndpoint.peerPublicKey.fill(0)

    println("WIREGUARD_PARSER_CHECK_PASS cases=9 mtu=true dns_fail_closed=true dual_stack=true restored_endpoint=true")
}
KOTLIN

OUT="$TMP/wireguard-parser-check.jar"
kotlinc -jvm-target 17 \
  "$TMP/android/net/InetAddresses.kt" \
  "$TMP/android/util/Base64.kt" \
  "$TMP/de/visiongaia/gedefense/mobile/WireGuardModels.kt" \
  "$ROOT/app/src/main/java/de/visiongaia/gedefense/mobile/WireGuardConfigParser.kt" \
  "$TMP/de/visiongaia/gedefense/mobile/WireGuardParserCheck.kt" \
  -include-runtime -d "$OUT"
java -jar "$OUT"
