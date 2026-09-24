package de.visiongaia.gedefense.mobile

import android.content.Context
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.ErrnoException
import android.system.OsConstants
import de.visiongaia.gedefense.mobile.core.EnforcementClass
import de.visiongaia.gedefense.mobile.core.PrivacyAction
import de.visiongaia.gedefense.mobile.core.PrivacyIntelligenceRegistry
import de.visiongaia.gedefense.mobile.core.PrivacyProfile
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileDescriptor
import java.io.FileOutputStream
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Process-isolated bridge for GaiaNet v2.
 *
 * The Go transport is shipped as an ABI-specific executable in nativeLibraryDir. Android hands the
 * helper exactly five descriptors for direct egress, or six when the optional WireGuard egress
 * is active (TUN, telemetry writer, authenticated threat policy, immutable privacy policy,
 * package-egress gate socket, optional one-shot WireGuard config pipe).
 * No shell is involved and the control protocol is fixed-size.
 */
object NativeGaiaNet {
    private const val HELPER_NAME = "libgedefense_gaianet_v2.so"
    private const val PROTOCOL_VERSION: Byte = 5
    private const val TOKEN_BYTES = 32
    private const val HELPER_INIT_BYTES = 44
    private const val MIN_TUN_MTU = 1280
    private const val MAX_TUN_MTU = 1420
    private const val CONNECT_TIMEOUT_MS = 4_000
    private const val HANDSHAKE_TIMEOUT_MS = 7_000
    private const val CONNECT_RETRY_MS = 20L
    private const val HELPER_MIN_BYTES = 128 * 1024L
    private const val HELPER_MAX_BYTES = 16 * 1024 * 1024L
    private val secureRandom = SecureRandom()

    @Volatile private var helperExecutable: File? = null
    @Volatile private var activeSession: Session? = null
    @Volatile private var lastStartFailureCode: String? = null

    val lastStartFailure: String?
        get() = lastStartFailureCode

    fun initialize(context: Context) {
        val candidate = File(context.applicationInfo.nativeLibraryDir, HELPER_NAME)
        helperExecutable = candidate.takeIf {
            it.isFile && it.length() in HELPER_MIN_BYTES..HELPER_MAX_BYTES && it.canExecute() && hasElfMagic(it)
        }
    }

    val available: Boolean
        get() = helperExecutable?.let { it.isFile && it.canExecute() && hasElfMagic(it) } == true

    data class Session internal constructor(
        val telemetryRead: ParcelFileDescriptor,
        private val control: LocalSocket,
        private val process: Process,
        private val socketFile: File,
        private val tunnelAnchor: ParcelFileDescriptor,
        private val packageEgressGate: PackageEgressGateResponder,
    ) : AutoCloseable {
        private val closed = AtomicBoolean(false)
        private val writeLock = Any()

        fun setPowerConstrained(constrained: Boolean): Boolean = sendControl('P', constrained)

        fun setTelemetryDetailed(detailed: Boolean): Boolean = sendControl('V', detailed)

        fun syncPackageEgressQuarantine(packages: Set<String>): Boolean {
            if (closed.get()) return false
            packageEgressGate.updateQuarantine(packages)
            val ok = sendControl('Q', packageEgressGate.enabled())
            if (!ok) {
                // A policy update that cannot reach GaiaNet must not leave the old helper forwarding
                // with stale quarantine state. The Android-side TUN anchor survives this forced exit
                // and the normal recovery path rebuilds the helper from the persisted policy.
                try { process.destroyForcibly() } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("native-gaia-net", error) }
            }
            return ok
        }

        fun packageEgressGateEnabled(): Boolean = !closed.get() && process.isAlive && packageEgressGate.enabled()

        fun isProcessAlive(): Boolean = !closed.get() && process.isAlive

        fun terminateHelperForRecoveryTest(): Boolean {
            if (closed.get() || !process.isAlive) return false
            return try {
                // Deliberately kill only the helper process. The Session-owned TUN anchor remains
                // open so the production recovery path can be exercised without creating a direct
                // routing window during the self-test itself.
                process.destroyForcibly()
                true
            } catch (_: RuntimeException) {
                false
            }
        }

        private fun sendControl(kind: Char, enabled: Boolean): Boolean {
            if (closed.get()) return false
            return synchronized(writeLock) {
                if (closed.get()) return@synchronized false
                try {
                    control.outputStream.write(byteArrayOf(kind.code.toByte(), if (enabled) 1 else 0))
                    control.outputStream.flush()
                    true
                } catch (_: IOException) {
                    false
                }
            }
        }

        override fun close() {
            if (!closed.compareAndSet(false, true)) return
            synchronized(writeLock) {
                try {
                    control.outputStream.write(byteArrayOf('S'.code.toByte(), 0))
                    control.outputStream.flush()
                } catch (error: IOException) { RuntimeFailureLog.nonCritical("native-gaia-net", error) }
            }
            try { control.close() } catch (error: IOException) { RuntimeFailureLog.nonCritical("native-gaia-net", error) }
            try { telemetryRead.close() } catch (error: IOException) { RuntimeFailureLog.nonCritical("native-gaia-net", error) }
            try {
                if (!process.waitFor(350, TimeUnit.MILLISECONDS)) {
                    process.destroy()
                    if (!process.waitFor(250, TimeUnit.MILLISECONDS)) process.destroyForcibly()
                }
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                process.destroyForcibly()
            } catch (_: RuntimeException) {
                process.destroyForcibly()
            } finally {
                packageEgressGate.close()
                // Keep the Android VPN interface alive until the helper has fully stopped. If the
                // helper crashes, this descriptor remains open in the service process and therefore
                // preserves fail-closed routing until recovery replaces the tunnel or the operator
                // explicitly stops protection.
                tunnelAnchor.closeSafely()
            }
            socketFile.delete()
            clearSession(this)
        }
    }

    @Synchronized
    fun start(
        context: Context,
        tunnel: ParcelFileDescriptor,
        index: ThreatIndex,
        privacyRegistry: PrivacyIntelligenceRegistry,
        privacyProfile: PrivacyProfile,
        cacheDir: File,
        powerConstrained: Boolean,
        telemetryDetailed: Boolean,
        egressMode: WireGuardEgressMode = WireGuardEgressMode.DIRECT,
        tunnelMtu: Int = MIN_TUN_MTU,
        wireGuardConfig: ByteArray? = null,
        socketProtector: ((FileDescriptor) -> Boolean)? = null,
        quarantinedPackages: Set<String> = emptySet(),
    ): Session? {
        lastStartFailureCode = null
        if (activeSession != null) { lastStartFailureCode = "session_already_active"; return null }
        if (tunnelMtu !in MIN_TUN_MTU..MAX_TUN_MTU) {
            lastStartFailureCode = "tunnel_mtu_invalid"
            return null
        }
        if ((egressMode == WireGuardEgressMode.DIRECT) != (wireGuardConfig == null)) {
            lastStartFailureCode = "wireguard_config_mode_mismatch"
            return null
        }
        if ((egressMode == WireGuardEgressMode.DIRECT) != (socketProtector == null)) {
            lastStartFailureCode = "wireguard_socket_protector_mode_mismatch"
            return null
        }
        if (wireGuardConfig != null && wireGuardConfig.size !in 1..MAX_WIREGUARD_CONFIG_BYTES) {
            lastStartFailureCode = "wireguard_config_size_invalid"
            return null
        }
        val helper = helperExecutable?.takeIf { available } ?: run { lastStartFailureCode = "helper_unavailable"; return null }
        val policy = ThreatPolicyBinary.create(index, cacheDir) ?: run { lastStartFailureCode = "policy_serialize_failed"; return null }
        val privacyPolicy = PrivacyPolicyBinary.create(privacyRegistry, privacyProfile, cacheDir) ?: run {
            lastStartFailureCode = "privacy_policy_serialize_failed"
            policy.closeSafely()
            return null
        }
        val pipe = try { ParcelFileDescriptor.createPipe() } catch (_: IOException) {
            lastStartFailureCode = "telemetry_pipe_failed"; policy.closeSafely(); privacyPolicy.closeSafely(); return null
        }
        val wireGuardPipe = if (wireGuardConfig != null) {
            try { ParcelFileDescriptor.createPipe() } catch (_: IOException) {
                lastStartFailureCode = "wireguard_pipe_failed"
                policy.closeSafely(); privacyPolicy.closeSafely(); closePipe(pipe); return null
            }
        } else null
        if (wireGuardPipe != null) {
            try {
                ParcelFileDescriptor.AutoCloseOutputStream(wireGuardPipe[1]).use { output ->
                    output.write(wireGuardConfig ?: throw IOException("wireguard config missing"))
                    output.flush()
                }
            } catch (_: IOException) {
                lastStartFailureCode = "wireguard_pipe_write_failed"
                policy.closeSafely(); privacyPolicy.closeSafely(); closePipe(pipe); closePipe(wireGuardPipe); return null
            }
        }
        val packageGatePair = try { ParcelFileDescriptor.createSocketPair() } catch (_: IOException) {
            lastStartFailureCode = "package_egress_gate_socket_failed"
            policy.closeSafely(); privacyPolicy.closeSafely(); closePipe(pipe); wireGuardPipe?.let(::closePipe); return null
        }
        val packageGateResponder = try {
            PackageEgressGateResponder(context, packageGatePair[0], quarantinedPackages)
        } catch (_: RuntimeException) {
            lastStartFailureCode = "package_egress_gate_responder_failed"
            policy.closeSafely(); privacyPolicy.closeSafely(); closePipe(pipe); wireGuardPipe?.let(::closePipe); closePipe(packageGatePair); return null
        }
        val token = ByteArray(TOKEN_BYTES).also(secureRandom::nextBytes)
        val tokenHex = token.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        val socketFile = File(cacheDir, "gdv2-${tokenHex.take(16)}.sock")
        if (socketFile.absolutePath.length > 96) {
            lastStartFailureCode = "control_path_invalid"
            policy.closeSafely(); privacyPolicy.closeSafely(); closePipe(pipe); wireGuardPipe?.let(::closePipe); packageGateResponder.close(); packageGatePair[1].closeSafely(); return null
        }
        socketFile.delete()

        val process = try {
            ProcessBuilder(helper.absolutePath, "--control", socketFile.absolutePath, "--token", tokenHex)
                .redirectErrorStream(true)
                .start()
        } catch (_: IOException) {
            lastStartFailureCode = "helper_exec_failed"
            policy.closeSafely(); privacyPolicy.closeSafely(); closePipe(pipe); wireGuardPipe?.let(::closePipe); packageGateResponder.close(); packageGatePair[1].closeSafely(); return null
        } catch (_: SecurityException) {
            lastStartFailureCode = "helper_exec_denied"
            policy.closeSafely(); privacyPolicy.closeSafely(); closePipe(pipe); wireGuardPipe?.let(::closePipe); packageGateResponder.close(); packageGatePair[1].closeSafely(); return null
        }
        drainProcessOutput(process)

        val control = connectControl(socketFile, process) ?: run {
            lastStartFailureCode = "helper_connect_failed"
            process.destroyForcibly(); policy.closeSafely(); privacyPolicy.closeSafely(); closePipe(pipe); wireGuardPipe?.let(::closePipe); packageGateResponder.close(); packageGatePair[1].closeSafely(); socketFile.delete(); return null
        }
        return try {
            control.soTimeout = HANDSHAKE_TIMEOUT_MS
            val descriptors = if (wireGuardPipe == null) {
                arrayOf(
                    tunnel.fileDescriptor,
                    pipe[1].fileDescriptor,
                    policy.fileDescriptor,
                    privacyPolicy.fileDescriptor,
                    packageGatePair[1].fileDescriptor,
                )
            } else {
                arrayOf(
                    tunnel.fileDescriptor,
                    pipe[1].fileDescriptor,
                    policy.fileDescriptor,
                    privacyPolicy.fileDescriptor,
                    packageGatePair[1].fileDescriptor,
                    wireGuardPipe[0].fileDescriptor,
                )
            }
            control.setFileDescriptorsForSend(descriptors)
            val frame = ByteArray(HELPER_INIT_BYTES)
            frame[0] = 'G'.code.toByte(); frame[1] = 'D'.code.toByte(); frame[2] = 'V'.code.toByte(); frame[3] = '2'.code.toByte()
            frame[4] = PROTOCOL_VERSION
            frame[5] = if (powerConstrained) 1 else 0
            frame[6] = if (telemetryDetailed) 1 else 0
            frame[7] = when (egressMode) {
                WireGuardEgressMode.DIRECT -> 0
                WireGuardEgressMode.WIREGUARD -> 1
                WireGuardEgressMode.WIREGUARD_STRICT -> 2
            }
            token.copyInto(frame, destinationOffset = 8)
            frame[40] = (tunnelMtu ushr 8).toByte()
            frame[41] = tunnelMtu.toByte()
            frame[42] = if (packageGateResponder.enabled()) 1 else 0
            control.outputStream.write(frame)
            control.outputStream.flush()

            awaitStartupReady(control, egressMode, socketProtector)

            // SCM_RIGHTS duplicated the helper descriptors. Keep the original TUN descriptor as a
            // service-process liveness anchor: a helper crash must not tear down the Android VPN
            // interface and expose a direct-routing window before recovery runs. The Session owns
            // this descriptor after the ACK and closes it only during controlled replacement/stop.
            pipe[1].closeSafely()
            policy.closeSafely()
            privacyPolicy.closeSafely()
            wireGuardPipe?.get(0)?.closeSafely()
            packageGatePair[1].closeSafely()
            control.soTimeout = 0
            Session(pipe[0], control, process, socketFile, tunnel, packageGateResponder).also {
                lastStartFailureCode = null
                activeSession = it
            }
        } catch (_: Exception) {
            if (lastStartFailureCode == null) lastStartFailureCode = "helper_handshake_failed"
            try { control.close() } catch (error: IOException) { RuntimeFailureLog.nonCritical("native-gaia-net", error) }
            process.destroyForcibly()
            policy.closeSafely(); privacyPolicy.closeSafely(); closePipe(pipe); wireGuardPipe?.let(::closePipe); packageGateResponder.close(); packageGatePair[1].closeSafely(); socketFile.delete()
            null
        }
    }

    private data class HelperFrame(
        val bytes: ByteArray,
        val descriptors: Array<FileDescriptor>?,
    )

    private fun awaitStartupReady(
        control: LocalSocket,
        egressMode: WireGuardEgressMode,
        socketProtector: ((FileDescriptor) -> Boolean)?,
    ) {
        while (true) {
            val received = receiveHelperFrame(control)
            val frame = received.bytes
            when {
                hasMagic(frame, 'G', 'D', 'P', '2') -> {
                    if (egressMode == WireGuardEgressMode.DIRECT || socketProtector == null) {
                        closeAncillaryDescriptors(received.descriptors)
                        lastStartFailureCode = "unexpected_wireguard_socket_request"
                        sendSocketProtectionAck(control, SOCKET_PROTECT_REJECTED)
                        throw IOException("Unexpected WireGuard socket protection request")
                    }
                    handleSocketProtectionRequest(control, frame, received.descriptors, socketProtector)
                }
                hasMagic(frame, 'G', 'D', 'A', '2') -> {
                    if (!received.descriptors.isNullOrEmpty()) {
                        closeAncillaryDescriptors(received.descriptors)
                        lastStartFailureCode = "helper_ack_has_descriptors"
                        throw IOException("GaiaNet helper acknowledgement carried unexpected descriptors")
                    }
                    val status = decodeStatus(frame)
                    if (status != 0) {
                        lastStartFailureCode = when (status) {
                            74 -> "policy_rejected"
                            75 -> "engine_init_failed"
                            78 -> "wireguard_config_rejected"
                            79 -> "privacy_policy_rejected"
                            80 -> "package_egress_gate_rejected"
                            else -> "helper_status_$status"
                        }
                        throw IOException("GaiaNet helper rejected startup")
                    }
                    return
                }
                else -> {
                    closeAncillaryDescriptors(received.descriptors)
                    lastStartFailureCode = "helper_ack_invalid"
                    throw IOException("GaiaNet helper acknowledgement invalid")
                }
            }
        }
    }

    private fun receiveHelperFrame(control: LocalSocket): HelperFrame {
        val frame = ByteArray(HELPER_FRAME_BYTES)
        var offset = 0
        var descriptors: Array<FileDescriptor>? = null
        while (offset < frame.size) {
            val read = control.inputStream.read(frame, offset, frame.size - offset)
            if (read < 0) {
                closeAncillaryDescriptors(descriptors)
                throw IOException("GaiaNet helper control channel closed")
            }
            if (read == 0) continue
            val justReceived = try { control.ancillaryFileDescriptors } catch (_: IOException) { null }
            if (!justReceived.isNullOrEmpty()) {
                if (descriptors != null) {
                    closeAncillaryDescriptors(justReceived)
                    closeAncillaryDescriptors(descriptors)
                    throw IOException("Multiple ancillary descriptor batches in helper frame")
                }
                descriptors = justReceived
            }
            offset += read
        }
        return HelperFrame(frame, descriptors)
    }

    private fun handleSocketProtectionRequest(
        control: LocalSocket,
        frame: ByteArray,
        descriptors: Array<FileDescriptor>?,
        socketProtector: (FileDescriptor) -> Boolean,
    ) {
        val expected = frame[4].toInt() and 0xff
        val reservedValid = frame[5] == 0.toByte() && frame[6] == 0.toByte() && frame[7] == 0.toByte()
        if (!reservedValid || expected !in 1..MAX_WIREGUARD_SOCKET_FDS || descriptors == null || descriptors.size != expected) {
            closeAncillaryDescriptors(descriptors)
            lastStartFailureCode = "wireguard_socket_request_invalid"
            sendSocketProtectionAck(control, SOCKET_PROTECT_REJECTED)
            throw IOException("WireGuard socket protection request invalid")
        }

        var protected = true
        try {
            for (descriptor in descriptors) {
                if (!socketProtector(descriptor)) protected = false
            }
        } finally {
            closeAncillaryDescriptors(descriptors)
        }
        sendSocketProtectionAck(control, if (protected) 0 else SOCKET_PROTECT_REJECTED)
        if (!protected) {
            lastStartFailureCode = "wireguard_socket_protect_failed"
            throw IOException("WireGuard socket protection failed")
        }
    }

    private fun sendSocketProtectionAck(control: LocalSocket, status: Int) {
        val frame = byteArrayOf(
            'G'.code.toByte(), 'D'.code.toByte(), 'R'.code.toByte(), '2'.code.toByte(),
            (status ushr 24).toByte(), (status ushr 16).toByte(), (status ushr 8).toByte(), status.toByte(),
        )
        control.outputStream.write(frame)
        control.outputStream.flush()
    }

    private fun closeAncillaryDescriptors(descriptors: Array<FileDescriptor>?) {
        descriptors?.forEach { descriptor ->
            try { Os.close(descriptor) } catch (error: ErrnoException) { RuntimeFailureLog.nonCritical("native-gaia-net", error) }
        }
    }

    private fun hasMagic(frame: ByteArray, a: Char, b: Char, c: Char, d: Char): Boolean =
        frame.size == HELPER_FRAME_BYTES && frame[0] == a.code.toByte() && frame[1] == b.code.toByte() &&
            frame[2] == c.code.toByte() && frame[3] == d.code.toByte()

    private fun decodeStatus(frame: ByteArray): Int =
        ((frame[4].toInt() and 0xff) shl 24) or ((frame[5].toInt() and 0xff) shl 16) or
            ((frame[6].toInt() and 0xff) shl 8) or (frame[7].toInt() and 0xff)

    fun setPowerConstrained(constrained: Boolean): Boolean = activeSession?.setPowerConstrained(constrained) ?: false

    fun setTelemetryDetailed(detailed: Boolean): Boolean = activeSession?.setTelemetryDetailed(detailed) ?: false

    /**
     * Serializes the current immutable threat index through the exact policy writer used for
     * GaiaNet startup and validates its fixed header locally. No socket is opened and the active
     * transport/session is not mutated.
     */
    fun validateThreatPolicySnapshot(index: ThreatIndex, cacheDir: File): Boolean {
        if (index.count <= 0) return false
        val descriptor = ThreatPolicyBinary.create(index, cacheDir) ?: return false
        return try {
            ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { input ->
                val header = ByteArray(44)
                var offset = 0
                while (offset < header.size) {
                    val read = input.read(header, offset, header.size - offset)
                    if (read <= 0) return@use false
                    offset += read
                }
                if (header[0] != 'G'.code.toByte() || header[1] != 'D'.code.toByte() ||
                    header[2] != 'T'.code.toByte() || header[3] != 'I'.code.toByte() || header[4] != 2.toByte()) return@use false
                val count = ((header[8].toInt() and 0xff) shl 24) or
                    ((header[9].toInt() and 0xff) shl 16) or
                    ((header[10].toInt() and 0xff) shl 8) or (header[11].toInt() and 0xff)
                if (count != index.count) return@use false
                val fingerprint = header.copyOfRange(12, 44).joinToString("") { "%02x".format(it.toInt() and 0xff) }
                fingerprint == index.fullPolicySha256
            }
        } catch (_: IOException) {
            false
        }
    }

    fun stop() {
        activeSession?.close()
    }

    @Synchronized
    private fun clearSession(session: Session) {
        if (activeSession === session) activeSession = null
    }

    @Synchronized
    fun syncPackageEgressQuarantine(packages: Set<String>): Boolean =
        activeSession?.syncPackageEgressQuarantine(packages) ?: true

    @Synchronized
    fun packageEgressGateActive(): Boolean = activeSession?.packageEgressGateEnabled() == true

    private fun connectControl(socketFile: File, process: Process): LocalSocket? {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(CONNECT_TIMEOUT_MS.toLong())
        while (System.nanoTime() < deadline && process.isAlive) {
            val socket = LocalSocket()
            try {
                // Android LocalSocket intentionally does not implement the connect(endpoint, timeout)
                // overload; it throws UnsupportedOperationException even on current platform builds.
                // The outer monotonic deadline below remains the startup bound, while AF_UNIX connect
                // to a not-yet-created filesystem socket fails immediately and is retried.
                socket.connect(LocalSocketAddress(socketFile.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
                return socket
            } catch (_: IOException) {
                try { socket.close() } catch (error: IOException) { RuntimeFailureLog.nonCritical("native-gaia-net", error) }
                try { Thread.sleep(CONNECT_RETRY_MS) } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt(); return null
                }
            }
        }
        return null
    }

    private fun drainProcessOutput(process: Process) {
        Thread({
            try {
                process.inputStream.use { input ->
                    val buffer = ByteArray(1024)
                    while (input.read(buffer) >= 0) { /* bounded discard: helper emits no routine logs */ }
                }
            } catch (error: IOException) { RuntimeFailureLog.nonCritical("native-gaia-net", error) }
        }, "gedefense-gaianet-logdrain").apply { isDaemon = true; start() }
    }

    private fun hasElfMagic(file: File): Boolean = try {
        file.inputStream().use { input ->
            val magic = ByteArray(4)
            input.read(magic) == 4 && magic[0] == 0x7f.toByte() && magic[1] == 'E'.code.toByte() && magic[2] == 'L'.code.toByte() && magic[3] == 'F'.code.toByte()
        }
    } catch (_: IOException) {
        false
    }

    private fun closePipe(pipe: Array<ParcelFileDescriptor>) = pipe.forEach { it.closeSafely() }
    private fun ParcelFileDescriptor.closeSafely() { try { close() } catch (error: IOException) { RuntimeFailureLog.nonCritical("native-gaia-net", error) } }

    private const val HELPER_FRAME_BYTES = 8
    private const val MAX_WIREGUARD_SOCKET_FDS = 2
    private const val SOCKET_PROTECT_REJECTED = 1
    private const val MAX_WIREGUARD_CONFIG_BYTES = 16 * 1024
}

private object ThreatPolicyBinary {
    fun create(index: ThreatIndex, cacheDir: File): ParcelFileDescriptor? {
        if (!cacheDir.isDirectory && !cacheDir.mkdirs()) return null
        val file = try { File.createTempFile("gd-policy-", ".bin", cacheDir) } catch (_: IOException) { return null }
        return try {
            try { Os.chmod(file.absolutePath, OsConstants.S_IRUSR or OsConstants.S_IWUSR) } catch (error: Exception) { RuntimeFailureLog.nonCritical("native-gaia-net", error) }
            FileOutputStream(file).use { raw ->
                DataOutputStream(raw).use { out ->
                    out.write(byteArrayOf('G'.code.toByte(), 'D'.code.toByte(), 'T'.code.toByte(), 'I'.code.toByte()))
                    out.writeByte(2)
                    out.write(byteArrayOf(0, 0, 0))
                    out.writeInt(index.count)
                    out.write(hexToBytes(index.fullPolicySha256))
                    var written = 0
                    index.forEachPolicyRecord { prefix, bits, enforcement ->
                        out.writeByte(prefix.family)
                        out.writeByte(prefix.prefixLength)
                        out.writeByte(actionCode(enforcement))
                        out.writeByte(0)
                        out.writeLong(bits)
                        if (prefix.family == 4) {
                            out.writeInt(prefix.v4)
                        } else {
                            out.writeLong(prefix.v6Hi)
                            out.writeLong(prefix.v6Lo)
                        }
                        written++
                    }
                    if (written != index.count) throw IOException("threat policy record count mismatch")
                    out.flush()
                    raw.fd.sync()
                }
            }
            val pfd = ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
            file.delete()
            pfd
        } catch (_: Exception) {
            file.delete()
            null
        }
    }

    private fun actionCode(enforcement: EnforcementClass): Int = when (enforcement) {
        EnforcementClass.ANNOTATE_ONLY -> 1
        EnforcementClass.CORRELATE_ONLY -> 2
        EnforcementClass.ROUTE_BLOCK -> 3
    }

    private fun hexToBytes(value: String): ByteArray {
        if (!value.matches(Regex("[0-9a-f]{64}"))) throw IOException("threat policy fingerprint invalid")
        return ByteArray(32) { index -> value.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }
}

private object PrivacyPolicyBinary {
    private const val VERSION = 1
    private const val MAX_RULES = 8_192
    private const val MAX_ID_BYTES = 96
    private const val MAX_DOMAIN_BYTES = 253

    fun create(registry: PrivacyIntelligenceRegistry, profile: PrivacyProfile, cacheDir: File): ParcelFileDescriptor? {
        if (!cacheDir.isDirectory && !cacheDir.mkdirs()) return null
        val records = try { registry.policyRecords(profile) } catch (_: RuntimeException) { return null }
        if (records.size > MAX_RULES) return null
        val body = ByteArrayOutputStream((records.size * 80).coerceAtMost(4 * 1024 * 1024))
        return try {
            DataOutputStream(body).use { out ->
                for (record in records) {
                    val id = record.id.toByteArray(Charsets.US_ASCII)
                    val domain = record.domain.toByteArray(Charsets.US_ASCII)
                    if (id.size !in 3..MAX_ID_BYTES || domain.size !in 1..MAX_DOMAIN_BYTES) throw IOException("privacy policy record bound invalid")
                    var flags = 0
                    if (record.includeSubdomains) flags = flags or 0x01
                    if (record.essential) flags = flags or 0x02
                    out.writeByte(flags)
                    out.writeByte(record.confidence.ordinal)
                    out.writeByte(record.breakageRisk.ordinal)
                    out.writeByte(actionCode(record.action))
                    out.writeShort(id.size)
                    out.writeShort(domain.size)
                    out.write(id)
                    out.write(domain)
                }
            }
            val payload = body.toByteArray()
            val digest = MessageDigest.getInstance("SHA-256").digest(payload)
            val file = File.createTempFile("gd-privacy-", ".bin", cacheDir)
            try {
                try { Os.chmod(file.absolutePath, OsConstants.S_IRUSR or OsConstants.S_IWUSR) } catch (error: Exception) { RuntimeFailureLog.nonCritical("native-gaia-net", error) }
                FileOutputStream(file).use { raw ->
                    DataOutputStream(raw).use { out ->
                        out.write(byteArrayOf('G'.code.toByte(), 'D'.code.toByte(), 'P'.code.toByte(), 'I'.code.toByte()))
                        out.writeByte(VERSION)
                        out.writeByte(profile.ordinal)
                        out.write(byteArrayOf(0, 0))
                        out.writeInt(records.size)
                        out.write(digest)
                        out.write(payload)
                        out.flush()
                        raw.fd.sync()
                    }
                }
                val pfd = ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
                file.delete()
                pfd
            } catch (error: Exception) {
                file.delete()
                throw error
            } finally {
                payload.fill(0)
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun actionCode(action: PrivacyAction): Int = when (action) {
        PrivacyAction.ALLOW -> 0
        PrivacyAction.OBSERVE -> 1
        PrivacyAction.BLOCK -> 2
    }
}
