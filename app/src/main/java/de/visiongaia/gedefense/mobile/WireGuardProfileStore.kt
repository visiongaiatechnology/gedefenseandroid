package de.visiongaia.gedefense.mobile

import android.net.InetAddresses
import android.net.Network
import de.visiongaia.gedefense.mobile.core.AuthenticatedSnapshotState
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.File
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicReference

// STATUS: DIAMANT VGT SUPREME
enum class WireGuardEgressMode { DIRECT, WIREGUARD, WIREGUARD_STRICT }

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
) {
    fun safeCopy(): WireGuardProfile = copy(
        privateKey = privateKey.copyOf(),
        interfaceAddresses = interfaceAddresses.toList(),
        dnsServers = dnsServers.toList(),
        peerPublicKey = peerPublicKey.copyOf(),
        presharedKey = presharedKey?.copyOf(),
        allowedIps = allowedIps.toList(),
    )

    fun destroySecrets() {
        privateKey.fill(0)
        peerPublicKey.fill(0)
        presharedKey?.fill(0)
    }
}

data class WireGuardProfileStatus(
    val initialized: Boolean,
    val integrityOk: Boolean,
    val configured: Boolean,
    val failureReason: String?,
    val endpoint: String?,
    val addressCount: Int,
    val allowedIpCount: Int,
    val mtu: Int,
)

data class WireGuardImportResult(val ok: Boolean, val reason: String? = null)

class WireGuardProfileStore(
    context: android.content.Context,
    private val runtimeState: RuntimeState,
) {
    private val appContext = context.applicationContext
    private val lock = Any()
    private val profile = AtomicReference<WireGuardProfile?>(null)
    private val snapshotStore = SecureSnapshotStore(
        file = File(appContext.noBackupFilesDir, "wireguard/profile.v1.bin"),
        hmacKey = null,
        domain = VaultDomain.WIREGUARD_PROFILE,
        schemaVersion = SCHEMA_VERSION,
        maxPlaintextBytes = MAX_SERIALIZED_BYTES,
        hmacKeyProvider = { SecureTelemetryVault.hotPathHmacKey(VaultDomain.WIREGUARD_PROFILE) },
        legacyHmacKeyProvider = { AndroidSecrets.hmacSha256OrNull(HMAC_ALIAS) },
    )

    @Volatile private var initialized = false
    @Volatile private var integrityOk = false
    @Volatile private var failureReason: String? = "wireguard_profile_initializing"

    fun initialize() = synchronized(lock) {
        if (initialized) return@synchronized
        val read = snapshotStore.read()
        when (read.state) {
            AuthenticatedSnapshotState.ABSENT -> {
                profile.set(null)
                integrityOk = true
                failureReason = null
            }
            AuthenticatedSnapshotState.VALID -> {
                val payload = read.payload ?: ByteArray(0)
                try {
                    if (payload.size == 1 && payload[0] == STORE_EMPTY) {
                        profile.getAndSet(null)?.destroySecrets()
                        integrityOk = true
                        failureReason = null
                    } else {
                        val decoded = decode(payload)
                        if (decoded == null) {
                            profile.set(null)
                            integrityOk = false
                            failureReason = "wireguard_profile_decode_failed"
                        } else {
                            profile.getAndSet(decoded)?.destroySecrets()
                            integrityOk = true
                            failureReason = null
                        }
                    }
                } finally {
                    payload.fill(0)
                }
            }
            AuthenticatedSnapshotState.INVALID -> {
                profile.set(null)
                integrityOk = false
                failureReason = "wireguard_profile_integrity_failed"
            }
        }
        initialized = true
    }

    fun status(): WireGuardProfileStatus {
        val current = profile.get()
        return WireGuardProfileStatus(
            initialized = initialized,
            integrityOk = integrityOk,
            configured = current != null,
            failureReason = failureReason,
            endpoint = current?.let { "${it.endpointHost}:${it.endpointPort}" },
            addressCount = current?.interfaceAddresses?.size ?: 0,
            allowedIpCount = current?.allowedIps?.size ?: 0,
            mtu = current?.mtu ?: DEFAULT_MTU,
        )
    }

    fun snapshot(): WireGuardProfile? = profile.get()?.safeCopy()

    fun importConfig(text: String): WireGuardImportResult = try {
        runtimeState.withMutableProtectionConfiguration { importConfigLocked(text) }
    } catch (_: IllegalArgumentException) {
        WireGuardImportResult(false, "wireguard_configuration_locked")
    }

    private fun importConfigLocked(text: String): WireGuardImportResult = synchronized(lock) {
        if (!initialized) return@synchronized WireGuardImportResult(false, "wireguard_profile_not_ready")
        val parsed = try {
            WireGuardConfigParser.parse(text)
        } catch (e: IllegalArgumentException) {
            return@synchronized WireGuardImportResult(false, e.message?.take(96) ?: "wireguard_config_invalid")
        }
        val encoded = try {
            encode(parsed)
        } catch (_: RuntimeException) {
            parsed.destroySecrets()
            return@synchronized WireGuardImportResult(false, "wireguard_profile_encode_failed")
        }
        val committed = try {
            snapshotStore.write(encoded)
            true
        } catch (_: Exception) {
            false
        } finally {
            encoded.fill(0)
        }
        if (!committed) {
            parsed.destroySecrets()
            integrityOk = false
            failureReason = "wireguard_profile_write_failed"
            return@synchronized WireGuardImportResult(false, failureReason)
        }
        profile.getAndSet(parsed)?.destroySecrets()
        integrityOk = true
        failureReason = null
        WireGuardImportResult(true)
    }

    fun clearProfile(): Boolean = try {
        runtimeState.withMutableProtectionConfiguration {
            val cleared = clearProfileLocked()
            if (cleared) runtimeState.setWireGuardEgressMode(WireGuardEgressMode.DIRECT)
            cleared
        }
    } catch (_: IllegalArgumentException) {
        false
    }

    private fun clearProfileLocked(): Boolean = synchronized(lock) {
        if (!initialized) return@synchronized false
        val empty = byteArrayOf(STORE_EMPTY)
        val ok = try {
            snapshotStore.write(empty)
            true
        } catch (_: Exception) {
            false
        } finally {
            empty.fill(0)
        }
        if (ok) {
            profile.getAndSet(null)?.destroySecrets()
            integrityOk = true
            failureReason = null
        }
        ok
    }

    fun resolveEndpoint(profile: WireGuardProfile, network: Network): InetAddress? {
        val host = profile.endpointHost
        val candidates = try {
            if (InetAddresses.isNumericAddress(host)) {
                arrayOf(InetAddresses.parseNumericAddress(host))
            } else {
                // Resolve peer hostnames on the exact physical underlay selected for the
                // subsequently protected WireGuard UDP sockets. Bound the blocking resolver so
                // a broken/OEM DNS stack cannot wedge the serialized VPN control plane forever.
                // A timeout is a hard startup failure; never fall back to the process resolver.
                BoundedAndroidCall.call(WIREGUARD_ENDPOINT_RESOLVE_TIMEOUT_MS) { network.getAllByName(host) }
            }
        } catch (_: Exception) {
            emptyArray()
        }
        return candidates.firstOrNull { address ->
            (address is Inet4Address || address is Inet6Address) &&
                !address.isAnyLocalAddress && !address.isMulticastAddress && !address.isLoopbackAddress && !address.isLinkLocalAddress
        }
    }

    fun buildUapi(profile: WireGuardProfile, endpoint: InetAddress): ByteArray {
        require(profile.endpointPort in 1..65535)
        val endpointHost = requireNotNull(endpoint.hostAddress) { "wireguard_endpoint_ip_invalid" }.substringBefore('%')
        val endpointText = if (endpoint is Inet6Address) "[$endpointHost]:${profile.endpointPort}"
        else "$endpointHost:${profile.endpointPort}"
        val out = SensitiveByteBuilder(MAX_UAPI_BYTES)
        return try {
            out.writeAscii("private_key=")
            out.writeHex(profile.privateKey)
            out.writeByte('\n'.code)
            out.writeAscii("replace_peers=true\npublic_key=")
            out.writeHex(profile.peerPublicKey)
            out.writeByte('\n'.code)
            profile.presharedKey?.let {
                out.writeAscii("preshared_key=")
                out.writeHex(it)
                out.writeByte('\n'.code)
            }
            out.writeAscii("endpoint=$endpointText\n")
            out.writeAscii("persistent_keepalive_interval=${profile.persistentKeepaliveSeconds}\n")
            out.writeAscii("replace_allowed_ips=true\n")
            profile.allowedIps.forEach { out.writeAscii("allowed_ip=${it.network}/${it.prefixLength}\n") }
            out.writeByte('\n'.code)
            out.finish()
        } finally {
            // UAPI contains the private key. Clear the fixed scratch buffer even when formatting
            // fails; the returned byte array has a single explicit owner and is cleared by caller.
            out.clear()
        }
    }

    private fun encode(value: WireGuardProfile): ByteArray {
        val out = SensitiveByteBuilder(MAX_SERIALIZED_BYTES)
        return try {
            out.writeInt(STORE_MAGIC)
            out.writeByte(STORE_VERSION)
            out.writeByte(STORE_PRESENT)
            out.writeShort(value.mtu)
            out.writeShort(value.persistentKeepaliveSeconds)
            out.writeByte(value.interfaceAddresses.size)
            out.writeByte(value.dnsServers.size)
            out.writeByte(value.allowedIps.size)
            out.writeByte(if (value.presharedKey != null) 1 else 0)
            out.writeBytes(value.privateKey)
            out.writeBytes(value.peerPublicKey)
            value.presharedKey?.let(out::writeBytes)
            out.writeString(value.endpointHost, MAX_HOST_BYTES)
            out.writeShort(value.endpointPort)
            value.interfaceAddresses.forEach {
                out.writeString(it.address, MAX_IP_TEXT_BYTES)
                out.writeByte(it.prefixLength)
            }
            value.dnsServers.forEach { out.writeString(it, MAX_IP_TEXT_BYTES) }
            value.allowedIps.forEach {
                out.writeString(it.network, MAX_IP_TEXT_BYTES)
                out.writeByte(it.prefixLength)
            }
            out.finish()
        } finally {
            // The serialized profile contains key material. Unlike ByteArrayOutputStream this
            // scratch storage is explicitly wipeable and never keeps a second hidden backing copy.
            out.clear()
        }
    }

    private fun decode(bytes: ByteArray): WireGuardProfile? {
        if (bytes.isEmpty() || bytes.size > MAX_SERIALIZED_BYTES) return null
        var privateKey: ByteArray? = null
        var publicKey: ByteArray? = null
        var psk: ByteArray? = null
        var keepSecrets = false
        return try {
            DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                if (input.readInt() != STORE_MAGIC || input.readUnsignedByte() != STORE_VERSION || input.readUnsignedByte() != STORE_PRESENT) return null
                val mtu = input.readUnsignedShort()
                val keepalive = input.readUnsignedShort()
                val addressCount = input.readUnsignedByte()
                val dnsCount = input.readUnsignedByte()
                val allowedCount = input.readUnsignedByte()
                val hasPsk = input.readUnsignedByte()
                if (mtu !in MIN_MTU..MAX_MTU || keepalive !in 0..65535 ||
                    addressCount !in 1..MAX_INTERFACE_ADDRESSES || dnsCount > MAX_DNS_SERVERS ||
                    allowedCount !in 1..MAX_ALLOWED_IPS || hasPsk !in 0..1) return null
                privateKey = ByteArray(KEY_BYTES).also { input.readFully(it) }
                publicKey = ByteArray(KEY_BYTES).also { input.readFully(it) }
                psk = if (hasPsk == 1) ByteArray(KEY_BYTES).also { input.readFully(it) } else null
                val endpointHost = readString(input, MAX_HOST_BYTES) ?: return null
                val endpointPort = input.readUnsignedShort()
                val addresses = ArrayList<WireGuardInterfaceAddress>(addressCount)
                repeat(addressCount) {
                    val address = readString(input, MAX_IP_TEXT_BYTES) ?: return null
                    addresses += WireGuardInterfaceAddress(address, input.readUnsignedByte())
                }
                val dns = ArrayList<String>(dnsCount)
                repeat(dnsCount) { dns += readString(input, MAX_IP_TEXT_BYTES) ?: return null }
                val allowed = ArrayList<WireGuardAllowedIp>(allowedCount)
                repeat(allowedCount) {
                    val network = readString(input, MAX_IP_TEXT_BYTES) ?: return null
                    allowed += WireGuardAllowedIp(network, input.readUnsignedByte())
                }
                val privateBytes = privateKey ?: return null
                val publicBytes = publicKey ?: return null
                if (input.read() != -1 || endpointPort !in 1..65535 || privateBytes.all { it == 0.toByte() } || publicBytes.all { it == 0.toByte() }) return null
                val candidate = WireGuardProfile(privateBytes, addresses, dns, mtu, publicBytes, psk, endpointHost, endpointPort, allowed, keepalive)
                if (!WireGuardConfigParser.validateDecoded(candidate)) return null
                keepSecrets = true
                candidate
            }
        } catch (_: Exception) {
            null
        } finally {
            if (!keepSecrets) {
                privateKey?.fill(0)
                publicKey?.fill(0)
                psk?.fill(0)
            }
        }
    }


    /** Fixed-capacity, explicitly wipeable encoder for WireGuard secret-bearing material. */
    private class SensitiveByteBuilder(private val limit: Int) {
        private val buffer = ByteArray(limit)
        private var size = 0

        init { require(limit > 0) }

        fun writeByte(value: Int) {
            ensure(1)
            buffer[size++] = value.toByte()
        }

        fun writeShort(value: Int) {
            require(value in 0..0xffff)
            ensure(2)
            buffer[size++] = (value ushr 8).toByte()
            buffer[size++] = value.toByte()
        }

        fun writeInt(value: Int) {
            ensure(4)
            buffer[size++] = (value ushr 24).toByte()
            buffer[size++] = (value ushr 16).toByte()
            buffer[size++] = (value ushr 8).toByte()
            buffer[size++] = value.toByte()
        }

        fun writeBytes(value: ByteArray) {
            ensure(value.size)
            value.copyInto(buffer, destinationOffset = size)
            size += value.size
        }

        fun writeAscii(value: String) {
            ensure(value.length)
            for (char in value) {
                require(char.code <= 0x7f)
                buffer[size++] = char.code.toByte()
            }
        }

        fun writeHex(value: ByteArray) {
            ensure(Math.multiplyExact(value.size, 2))
            for (byte in value) {
                val v = byte.toInt() and 0xff
                buffer[size++] = HEX[v ushr 4].code.toByte()
                buffer[size++] = HEX[v and 0x0f].code.toByte()
            }
        }

        fun writeString(value: String, maxBytes: Int) {
            val bytes = value.toByteArray(StandardCharsets.UTF_8)
            try {
                require(bytes.size in 1..maxBytes)
                writeShort(bytes.size)
                writeBytes(bytes)
            } finally {
                // These fields are not secret today, but wiping the temporary keeps this encoder's
                // ownership rule simple if the schema grows later.
                bytes.fill(0)
            }
        }

        fun finish(): ByteArray = buffer.copyOf(size)

        fun clear() {
            buffer.fill(0)
            size = 0
        }

        private fun ensure(count: Int) {
            require(count >= 0 && count <= limit - size) { "wireguard_buffer_limit" }
        }

        companion object {
            private const val HEX = "0123456789abcdef"
        }
    }

    private fun readString(input: DataInputStream, maxBytes: Int): String? {
        val size = input.readUnsignedShort()
        if (size !in 1..maxBytes) return null
        val bytes = ByteArray(size)
        input.readFully(bytes)
        return bytes.toString(StandardCharsets.UTF_8)
    }

    companion object {
        private const val SCHEMA_VERSION = 1
        private const val HMAC_ALIAS = "vgt.gedefense.mobile.wireguard-profile.hmac.v1"
        private const val STORE_MAGIC = 0x47575031 // GWP1
        private const val STORE_VERSION = 1
        private const val STORE_EMPTY: Byte = 0
        private const val STORE_PRESENT = 1
        private const val KEY_BYTES = 32
        private const val MAX_SERIALIZED_BYTES = 24 * 1024
        private const val MAX_UAPI_BYTES = 16 * 1024
        private const val MAX_HOST_BYTES = 253
        private const val MAX_IP_TEXT_BYTES = 64
        private const val MAX_INTERFACE_ADDRESSES = 8
        private const val MAX_DNS_SERVERS = 4
        private const val MAX_ALLOWED_IPS = 64
        private const val MIN_MTU = 1280
        private const val MAX_MTU = 1420
        private const val WIREGUARD_ENDPOINT_RESOLVE_TIMEOUT_MS = 5_000L
        const val DEFAULT_MTU = 1280
    }
}
