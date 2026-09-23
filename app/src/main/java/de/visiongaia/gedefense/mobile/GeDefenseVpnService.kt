package de.visiongaia.gedefense.mobile

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.drawable.Icon
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.os.SystemClock
import de.visiongaia.gedefense.mobile.core.EvidenceEvent
import de.visiongaia.gedefense.mobile.core.FlowTable
import de.visiongaia.gedefense.mobile.core.PacketParser
import de.visiongaia.gedefense.mobile.core.PolicyEngine
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import de.visiongaia.gedefense.mobile.core.ThreatVerdict
import java.io.FileInputStream
import java.io.IOException
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

class GeDefenseVpnService : VpnService() {
    private val running = AtomicBoolean(false)
    private val startupPending = AtomicBoolean(false)
    private val startupGeneration = AtomicLong(0L)
    private val recoveryAttempts = AtomicInteger(0)
    private val recoveryGeneration = AtomicLong(0L)
    private val recoveryPending = AtomicBoolean(false)
    private val fullFlowSessionGeneration = AtomicLong(0L)
    private val selfTestPending = AtomicBoolean(false)
    private val selfTestStartedElapsed = AtomicLong(0L)
    private val tunnel = AtomicReference<ParcelFileDescriptor?>(null)
    private val serviceDestroyed = AtomicBoolean(false)
    private val runtimeReady = AtomicBoolean(false)
    private val handoverGeneration = AtomicLong(0L)
    private val strictInvariantGeneration = AtomicLong(0L)
    private val strictWatchdogScheduled = AtomicBoolean(false)
    private val control = BoundedSerialScheduler("gedefense-control", CONTROL_QUEUE_CAPACITY)
    private val reader = BoundedExecutors.direct("gedefense-tun")
    private val flows = FlowTable(8192, 5 * 60_000L)
    private val dedupe = EventDedupe()
    private lateinit var owners: ConnectionOwnerResolver
    private lateinit var runtime: AppRuntime
    @Volatile private var nativeSession: NativeGaiaNet.Session? = null
    @Volatile private var fullFlowReader: FullFlowTelemetryReader? = null
    @Volatile private var fullFlowStartFailure = "full_flow_start_failed"
    @Volatile private var selectiveStartFailure = "selective_start_failed"
    private val lastEvidenceWriteFailure = AtomicReference("evidence_write_failure")
    private lateinit var connectivity: ConnectivityManager
    private lateinit var powerManager: PowerManager
    private lateinit var portSentinel: PortSentinel
    private val networkLock = Any()
    private val physicalNetworks = linkedMapOf<Network, NetworkCapabilities>()
    private val underlyingNetworks = AtomicReference<List<Network>>(emptyList())
    private val activeWireGuardUnderlay = AtomicReference<Network?>(null)
    private val activeWireGuardUnderlayGeneration = AtomicLong(-1L)
    private var underlyingFingerprint = ""
    @Volatile private var lastPowerConstrained: Boolean? = null
    private val physicalNetworkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            // getNetworkCapabilities() is a Binder call. The richer capabilities callback normally
            // follows immediately, but if we need the onAvailable fallback, resolve it on the VPN
            // control lane rather than blocking ConnectivityManager's callback thread.
            submitControl { updatePhysicalNetwork(network) }
        }
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) { updatePhysicalNetwork(network, caps) }
        override fun onLost(network: Network) {
            synchronized(networkLock) { physicalNetworks.remove(network) }
            applyPhysicalNetworks()
        }
    }
    private val powerStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            updateTransportPowerState()
        }
    }

    override fun onCreate() {
        super.onCreate()
        connectivity = getSystemService(ConnectivityManager::class.java)
        powerManager = getSystemService(PowerManager::class.java)
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == null || action == ACTION_START) {
            startForeground(NOTIFICATION_ID, notification(getString(R.string.vpn_starting)))
        }
        if (!submitControl {
            if (!ensureRuntimeReady()) {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf(startId)
                return@submitControl
            }
            handleReadyCommand(action, startId)
        }) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf(startId)
            return START_NOT_STICKY
        }
        return when (action) {
            null, ACTION_START, ACTION_RESILIENCE_PROBE -> START_STICKY
            else -> START_NOT_STICKY
        }
    }

    private fun ensureRuntimeReady(): Boolean {
        if (runtimeReady.get()) return true
        val initialized = AppRuntime.awaitInitialized(this, RUNTIME_INITIALIZATION_TIMEOUT_MS) ?: return false
        if (serviceDestroyed.get()) return false
        runtime = initialized
        owners = ConnectionOwnerResolver(this)
        registerPowerStateObserver()
        updateTransportPowerState(force = true)
        portSentinel = PortSentinel(
            this,
            isBlockedSource = { address -> runtime.portSentinelStore.isBlocked(address) },
            onHit = runtime::onPortSentinelHit,
            onState = runtime::onPortSentinelState,
        )
        registerPhysicalNetworkObserver()
        runtimeReady.set(true)
        return true
    }

    private fun handleReadyCommand(action: String?, startId: Int): Int = try {
        recordPlatformVpnPolicy()
        when (action) {
            ACTION_STOP -> {
                cancelPendingStart()
                stopProtection("OFF", "operator_stop")
                START_NOT_STICKY
            }
            ACTION_RESILIENCE_PROBE -> {
                runtime.notifyStateChanged()
                if (running.get() || startupPending.get()) START_STICKY else START_NOT_STICKY
            }
            ACTION_RECOVERY_SELF_TEST -> {
                runRecoverySelfTest()
                if (running.get()) START_STICKY else START_NOT_STICKY
            }
            ACTION_REFRESH -> {
                if (running.get()) refreshTunnel() else stopSelf(startId)
                if (running.get()) START_STICKY else START_NOT_STICKY
            }
            ACTION_REEVALUATE -> {
                reevaluateEvidenceAsync(startId)
                if (running.get()) START_STICKY else START_NOT_STICKY
            }
            ACTION_INTEGRITY_FAILURE -> {
                cancelPendingStart()
                stopProtection("DEGRADED_INTEGRITY", integrityFailureReason())
                START_NOT_STICKY
            }
            else -> {
                if (!runtime.awaitVpnDisclosureBootstrap(VPN_DISCLOSURE_BOOTSTRAP_TIMEOUT_MS)) {
                    cancelPendingStart()
                    runtime.state.setVpnActive(false)
                    runtime.state.setVpnStatus("START_FAILED", "vpn_disclosure_bootstrap_timeout")
                    runtime.notifyStateChanged()
                    stopSelf(startId)
                    START_NOT_STICKY
                } else if (!runtime.vpnDisclosure.isAccepted()) {
                    cancelPendingStart()
                    runtime.state.setVpnActive(false)
                    runtime.state.setVpnStatus("CONSENT_REQUIRED", "vpn_disclosure_not_accepted")
                    runtime.notifyStateChanged()
                    stopSelf(startId)
                    START_NOT_STICKY
                } else {
                    // Android requires the foreground notification promptly, but all expensive
                    // tunnel/policy/helper work is serialized off the app main thread.
                    startForeground(NOTIFICATION_ID, notification(getString(R.string.vpn_starting)))
                    if (!running.get() && !startupPending.get()) beginProtectionStart()
                    START_STICKY
                }
            }
        }
    } catch (t: RuntimeException) {
        val reason = "service_${t.javaClass.simpleName.ifBlank { "runtime_failure" }.lowercase()}"
        submitControl { failClosedFromStartup(reason) }
        START_NOT_STICKY
    }

    private fun submitControl(block: () -> Unit): Boolean {
        if (serviceDestroyed.get()) return false
        return control.execute {
            if (!serviceDestroyed.get()) block()
        }
    }

    private fun scheduleControl(delayMillis: Long, block: () -> Unit): Boolean {
        if (serviceDestroyed.get()) return false
        return control.schedule(delayMillis.coerceAtLeast(0L)) {
            if (!serviceDestroyed.get()) block()
        }
    }

    private fun submitReader(block: () -> Unit): Boolean = try {
        reader.execute(block)
        true
    } catch (_: RejectedExecutionException) {
        false
    }

    private fun beginProtectionStart() {
        if (running.get() || !startupPending.compareAndSet(false, true)) return
        val generation = startupGeneration.incrementAndGet()
        if (!runtime.state.beginProtectionStartTransition(PROTECTION_CONFIGURATION_FREEZE_TIMEOUT_MS)) {
            startupPending.set(false)
            failClosedFromStartup("protection_configuration_busy")
            return
        }
        runtime.notifyStateChanged()
        if (runtime.securityBootstrapComplete()) {
            startupPending.set(false)
            startProtection()
            return
        }
        if (!runtime.executeBackground("vpn-bootstrap-wait") {
            val ready = runtime.awaitSecurityBootstrap(SECURITY_BOOTSTRAP_TIMEOUT_MS)
            submitControl {
                if (generation != startupGeneration.get() || !startupPending.compareAndSet(true, false) || running.get()) return@submitControl
                if (!ready) failClosedFromStartup("security_bootstrap_timeout") else startProtection()
            }
        }) {
            if (startupPending.compareAndSet(true, false)) {
                failClosedFromStartup("runtime_worker_busy")
            }
        }
    }

    private fun cancelPendingStart() {
        startupGeneration.incrementAndGet()
        startupPending.set(false)
    }

    private fun startProtection() {
        invalidateRecovery(resetAttempts = true)
        if (!runtime.state.awaitDurableState(MODE_STORE_BOOTSTRAP_TIMEOUT_MS)) {
            refuseStart("STATE_UNAVAILABLE", "runtime_state_persistence_unhealthy")
            return
        }
        val index = runtime.threatIndex.get()
        var mode = runtime.state.protectionMode()
        if (platformLockdownEnabled() && mode == ProtectionMode.SELECTIVE) {
            mode = ProtectionMode.FULL_FLOW_BETA
            runtime.state.setProtectionModeForVpnStart(mode)
            appendEvidence("vpn.policy", "info", "local", "android lockdown forced full-flow mode")
        }
        if (!runtime.awaitProtectionStoreBootstrap(mode, MODE_STORE_BOOTSTRAP_TIMEOUT_MS)) {
            refuseStart("STORE_BOOTSTRAP_TIMEOUT", "protection_store_bootstrap_timeout")
            return
        }
        if (mode == ProtectionMode.FULL_FLOW_BETA && runtime.state.wireGuardEgressMode() != WireGuardEgressMode.DIRECT &&
            !runtime.awaitWireGuardBootstrap(MODE_STORE_BOOTSTRAP_TIMEOUT_MS)) {
            refuseStart("STORE_BOOTSTRAP_TIMEOUT", "wireguard_profile_bootstrap_timeout")
            return
        }
        if (mode == ProtectionMode.LOCKDOWN && !runtime.firewallPolicy.integrityOk()) {
            refuseStart("POLICY_UNAVAILABLE", "firewall_policy_integrity_unhealthy")
            return
        }
        if (mode == ProtectionMode.SELECTIVE && !runtime.portSentinelStore.integrityOk()) {
            refuseStart("POLICY_UNAVAILABLE", "port_sentinel_integrity_unhealthy")
            return
        }
        val readiness = readinessFailure(index, mode)
        if (readiness != null) { refuseStart(readiness.first, readiness.second); return }

        flows.clear(); owners.clear(); runtime.metrics.reset(); runtime.fullFlowAnalytics.reset(); runtime.behavior.beginSession()
        running.set(true)
        val installed = when (mode) {
            ProtectionMode.FULL_FLOW_BETA -> installFullFlow(index)
            ProtectionMode.LOCKDOWN -> installLockdown()
            ProtectionMode.SELECTIVE -> installSelective(index)
        }
        if (!installed) {
            val reason = when (mode) {
                ProtectionMode.FULL_FLOW_BETA -> fullFlowStartFailure
                ProtectionMode.LOCKDOWN -> "lockdown_start_failed"
                ProtectionMode.SELECTIVE -> selectiveStartFailure
            }
            if (mode == ProtectionMode.FULL_FLOW_BETA && runtime.state.wireGuardEgressMode() != WireGuardEgressMode.DIRECT &&
                hasFullFlowContinuity()) {
                // The VPN/TUN is already fail-closed even though the WireGuard helper/underlay is
                // not usable yet. Keep the foreground service alive and recover in place rather
                // than tearing down the last routing anchor and exposing normal app routing.
                runtime.state.setVpnActive(true)
                handleFullFlowFailure(reason)
                return
            }
            running.set(false); runtime.fullFlowAnalytics.stop()
            refuseStart("ESTABLISH_FAILED", reason)
            return
        }

        runtime.state.setVpnActive(true)
        val activeStatus = when (mode) {
            ProtectionMode.FULL_FLOW_BETA -> "FULL_GUARDED"
            ProtectionMode.LOCKDOWN -> "LOCKDOWN_GUARDED"
            ProtectionMode.SELECTIVE -> "GUARDED"
        }
        runtime.state.setVpnStatus(activeStatus, null)
        armStrictInvariantWatchdog()
        runtime.notifyStateChanged(); updateNotification()
        if (!appendEvidence(
                "vpn.state", "info", "local",
                when (mode) {
                    ProtectionMode.FULL_FLOW_BETA -> "full-flow beta active threat-prefixes=${index.count} fullPolicy=${index.fullPolicySha256} native_api=2 process_isolated=true egress=${runtime.state.wireGuardEgressMode().name.lowercase()}"
                    ProtectionMode.LOCKDOWN -> "default-deny lockdown active allowed_apps=${runtime.firewallPolicy.allowedPackages().size}"
                    ProtectionMode.SELECTIVE -> "guarded selective-route protection active routes=${index.routePrefixes.size} candidates=${index.routeCandidateCount} policy=${index.routePolicySha256}"
                },
            )
        ) {
            degradeEvidenceAndStop(lastEvidenceWriteFailure.get())
        }
    }

    private fun platformLockdownEnabled(): Boolean =
        try { isLockdownEnabled } catch (_: RuntimeException) { false }

    private fun recordPlatformVpnPolicy() {
        val alwaysOn = try { isAlwaysOn } catch (_: RuntimeException) { false }
        val lockdown = platformLockdownEnabled()
        runtime.state.recordPlatformVpnPolicy(alwaysOn, lockdown)
        if (alwaysOn) runtime.state.setResilienceDesired(true)
    }

    private fun readinessFailure(index: ThreatIndex, mode: ProtectionMode): Pair<String, String>? {
        if (!runtime.evidenceHealth.ok) {
            val reason = runtime.evidenceHealth.reason?.trim()?.lowercase()
                ?.replace(Regex("[^a-z0-9_]+"), "_")?.trim('_')?.take(96)
                ?.ifBlank { null } ?: "evidence_integrity_unhealthy"
            return "DEGRADED_EVIDENCE" to reason
        }
        if (!runtime.integritySnapshot.get().ok) return "DEGRADED_INTEGRITY" to integrityFailureReason()
        if (mode == ProtectionMode.LOCKDOWN) return null
        if (index.count <= 0) return "NO_THREAT_INDEX" to "no_fresh_threat_intelligence"
        if (mode == ProtectionMode.FULL_FLOW_BETA) {
            if (!NativeGaiaNet.available) return "NETSTACK_UNAVAILABLE" to "native_gaianet_missing"
            val egress = runtime.state.wireGuardEgressMode()
            if (egress != WireGuardEgressMode.DIRECT) {
                val wireGuard = runtime.wireGuard.status()
                if (!wireGuard.initialized) return "WIREGUARD_UNAVAILABLE" to "wireguard_profile_initializing"
                if (!wireGuard.integrityOk) return "WIREGUARD_UNAVAILABLE" to (wireGuard.failureReason ?: "wireguard_profile_integrity_failed")
                if (!wireGuard.configured) return "WIREGUARD_UNAVAILABLE" to "wireguard_profile_missing"
                if (egress == WireGuardEgressMode.WIREGUARD_STRICT) {
                    if (!platformLockdownEnabled()) return "KILL_SWITCH_REQUIRED" to "wireguard_strict_requires_android_lockdown"
                }
            }
            return null
        }
        if (index.routeOverflow) return "ROUTE_OVERFLOW" to "selective_route_policy_overflow"
        if (index.routePrefixes.size > SELECTIVE_PLATFORM_ROUTE_BUDGET) {
            return "ROUTE_OVERFLOW" to "selective_platform_route_budget_exceeded"
        }
        if (index.routePrefixes.isEmpty()) return "NO_THREAT_ROUTES" to "no_fresh_high_confidence_routes"
        return null
    }

    private fun refuseStart(status: String, reason: String) {
        runtime.state.setVpnActive(false); runtime.state.setVpnStatus(status, reason); runtime.notifyStateChanged()
        stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
    }

    private fun integrityFailureReason(): String {
        val snapshot = runtime.integritySnapshot.get()
        return snapshot.issues.firstOrNull { it.severity == IntegritySeverity.CRITICAL }?.code
            ?: snapshot.issues.firstOrNull()?.code
            ?: if (snapshot.state == "PENDING") "integrity_scan_pending" else "application_integrity_unhealthy"
    }

    private fun failClosedFromStartup(reason: String) {
        cancelPendingStart()
        running.set(false)
        try { closeTransports() } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
        try { runtime.metrics.setActiveFlows(0) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
        try { runtime.fullFlowAnalytics.stop() } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
        runtime.state.setVpnActive(false)
        runtime.state.setVpnStatus("START_FAILED", reason.take(160))
        appendEvidence("vpn.failure", "high", "local", "startup failure=$reason")
        runtime.notifyStateChanged()
        try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
        stopSelf()
    }

    private fun baseBuilder(
        mtu: Int,
        wireGuardAddresses: List<WireGuardInterfaceAddress>? = null,
        preferredUnderlay: Network? = null,
    ): Builder {
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(mtu)
            .setBlocking(true)
            .setMetered(false)
            .setConfigureIntent(PendingIntent.getActivity(
                this, 0, Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            ))
        if (wireGuardAddresses == null) {
            builder.addAddress("10.253.0.2", 32)
            builder.addAddress("fd7a:4744::2", 128)
        } else {
            require(wireGuardAddresses.isNotEmpty())
            wireGuardAddresses.forEach { builder.addAddress(it.address, it.prefixLength) }
        }
        val physical = underlyingNetworks.get().ifEmpty { listOfNotNull(preferredUnderlay) }
        if (physical.isNotEmpty()) try { builder.setUnderlyingNetworks(physical.toTypedArray()) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
        return builder
    }

    private fun registerPowerStateObserver() {
        val filter = IntentFilter().apply {
            addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
            addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED)
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        }
        try {
            if (Build.VERSION.SDK_INT >= 33) registerReceiver(powerStateReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
            else @Suppress("DEPRECATION") registerReceiver(powerStateReceiver, filter)
        } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
    }

    private fun isTransportPowerConstrained(): Boolean =
        powerManager.isDeviceIdleMode || powerManager.isPowerSaveMode || !powerManager.isInteractive

    private fun updateTransportPowerState(force: Boolean = false) {
        val constrained = isTransportPowerConstrained()
        if (!force && lastPowerConstrained == constrained) return
        lastPowerConstrained = constrained
        runtime.state.setTransportPowerConstrained(constrained)
        NativeGaiaNet.setPowerConstrained(constrained)
    }

    private fun registerPhysicalNetworkObserver() {
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        try { connectivity.registerNetworkCallback(request, physicalNetworkCallback) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
    }

    private fun updatePhysicalNetwork(network: Network, provided: NetworkCapabilities? = null) {
        val caps = provided ?: connectivity.getNetworkCapabilities(network) ?: return
        if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return
        synchronized(networkLock) {
            if (physicalNetworks.size >= MAX_PHYSICAL_NETWORKS && network !in physicalNetworks) {
                physicalNetworks.entries.firstOrNull()?.let { physicalNetworks.remove(it.key) }
            }
            physicalNetworks[network] = caps
        }
        applyPhysicalNetworks()
    }

    private fun applyPhysicalNetworks() {
        val snapshot = synchronized(networkLock) { physicalNetworks.toMap() }
        val internet = snapshot.entries.asSequence()
            .filter { (_, caps) -> caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) }
            .sortedByDescending { (_, caps) -> physicalNetworkScore(caps) }
            .map { it.key }.take(MAX_PHYSICAL_NETWORKS).toList()
        val previousUnderlying = underlyingNetworks.getAndSet(internet)
        val preferredUnderlay = internet.firstOrNull()
        if (previousUnderlying != internet) {
            // Both calls may cross Binder or rebind many sockets. NetworkCallback delivery is not a
            // transport-mutation lane, so coalesce unchanged capability callbacks and serialize the
            // actual platform/network work with every other VPN control mutation.
            submitControl {
                if (underlyingNetworks.get() != internet) return@submitControl
                try { setUnderlyingNetworks(internet.takeIf { it.isNotEmpty() }?.toTypedArray()) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
                portSentinel.rebind(preferredUnderlay)
            }
        }

        // Direct GaiaNet sockets follow Android's default route and need no helper rebuild here.
        // WireGuard sockets are bound to one exact physical Network, so a preferred-underlay change
        // requires a controlled replacement. Crucially, loss of all underlays does NOT tear down the
        // current TUN anchor: traffic remains captured/fail-closed until a usable underlay returns.
        val fingerprint = preferredUnderlay?.toString().orEmpty()
        if (fingerprint != underlyingFingerprint) {
            underlyingFingerprint = fingerprint
            val generation = handoverGeneration.incrementAndGet()
            if (running.get() && runtime.state.protectionMode() == ProtectionMode.FULL_FLOW_BETA &&
                runtime.state.wireGuardEgressMode() != WireGuardEgressMode.DIRECT) {
                if (preferredUnderlay == null) {
                    submitControl {
                        if (generation != handoverGeneration.get() || !running.get() ||
                            runtime.state.protectionMode() != ProtectionMode.FULL_FLOW_BETA ||
                            runtime.state.wireGuardEgressMode() == WireGuardEgressMode.DIRECT) return@submitControl
                        invalidateRecovery(resetAttempts = false)
                        completeSelfTest(false)
                        runtime.state.setVpnStatus("RECOVERING", "wireguard_underlay_unavailable")
                        runtime.notifyStateChanged()
                        updateNotification()
                        appendEvidence("vpn.handover", "warning", "local", "wireguard underlay unavailable; preserving fail-closed tunnel anchor")
                    }
                } else {
                    scheduleControl(HANDOVER_DEBOUNCE_MS) {
                        if (generation != handoverGeneration.get() || !running.get() ||
                            runtime.state.protectionMode() != ProtectionMode.FULL_FLOW_BETA ||
                            runtime.state.wireGuardEgressMode() == WireGuardEgressMode.DIRECT) return@scheduleControl
                        // A recovery may already have rebuilt WireGuard on exactly this underlay
                        // after the callback scheduled us. Skip that redundant second rebuild, but
                        // only if the successful transport captured this callback generation (or a
                        // newer one). A later network event therefore can never be hidden by an
                        // older recovery finishing concurrently.
                        if (nativeSession?.isProcessAlive() == true &&
                            activeWireGuardUnderlay.get() == preferredUnderlay &&
                            activeWireGuardUnderlayGeneration.get() >= generation) return@scheduleControl
                        appendEvidence("vpn.handover", "info", "local", "wireguard underlay changed; replacing full-flow transport")
                        refreshTunnel()
                    }
                }
            }
        }
    }

    private fun physicalNetworkScore(caps: NetworkCapabilities): Int =
        (if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) 100 else 0) +
            (if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) 30 else 0) +
            (if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) 20 else 0) +
            (if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) 10 else 0)

    private fun preferredPhysicalNetwork(): Network? {
        underlyingNetworks.get().firstOrNull()?.let { return it }
        val active = try { connectivity.activeNetwork } catch (_: RuntimeException) { null } ?: return null
        val caps = try { connectivity.getNetworkCapabilities(active) } catch (_: RuntimeException) { null } ?: return null
        return active.takeIf {
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }
    }

    private fun protectWireGuardSocket(descriptor: java.io.FileDescriptor, underlay: Network): Boolean = try {
        BoundedAndroidCall.call(WIREGUARD_SOCKET_PROTECT_TIMEOUT_MS) {
            ParcelFileDescriptor.dup(descriptor).use { duplicate ->
                // Pin first, then mark the same kernel socket as VPN-exempt. If either platform
                // operation blocks or fails, GaiaNet rejects startup before the bind is released.
                underlay.bindSocket(duplicate.fileDescriptor)
                protect(duplicate.fd)
            }
        }
    } catch (_: IOException) {
        false
    } catch (_: SecurityException) {
        false
    } catch (_: PlatformCallUnavailableException) {
        false
    } catch (_: RuntimeException) {
        false
    }

    private fun configureSelfBypass(builder: Builder): Boolean = try {
        // Native Go upstream sockets share GeDefense's UID and therefore bypass the VPN without a
        // privileged raw-socket path. This prevents recursive full-tunnel capture.
        builder.addDisallowedApplication(packageName); true
    } catch (_: Exception) { false }


    private fun configureLockdownBypass(builder: Builder): Boolean {
        if (!configureSelfBypass(builder)) return false
        runtime.firewallPolicy.pruneMissingPackages()
        for (allowedPackage in runtime.firewallPolicy.allowedPackages().sorted()) {
            if (allowedPackage == packageName) continue
            try {
                builder.addDisallowedApplication(allowedPackage)
            } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
                // Stale package state is pruned at the next policy read; never fail open globally.
            } catch (_: Exception) {
                return false
            }
        }
        return true
    }

    private fun installLockdown(): Boolean {
        tearDownFullFlow()
        val builder = baseBuilder(FULL_FLOW_MTU)
        if (!configureLockdownBypass(builder)) return false
        try {
            builder.addRoute("0.0.0.0", 0)
            builder.addRoute("::", 0)
        } catch (_: IllegalArgumentException) { return false }
        val descriptor = try { builder.establish() } catch (_: Exception) { null } ?: return false
        val old = tunnel.getAndSet(descriptor)
        try { old?.close() } catch (error: IOException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
        if (!submitReader { readLockdownLoop(descriptor) }) {
            tunnel.compareAndSet(descriptor, null)
            try { descriptor.close() } catch (error: IOException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
            return false
        }
        return true
    }

    private fun installSelective(index: ThreatIndex): Boolean {
        selectiveStartFailure = "selective_start_failed"
        if (index.routeOverflow) {
            selectiveStartFailure = "selective_route_policy_overflow"
            return false
        }
        if (index.routePrefixes.isEmpty()) {
            selectiveStartFailure = "selective_no_routes"
            return false
        }
        if (!runtime.portSentinelStore.integrityOk()) {
            selectiveStartFailure = "selective_sentinel_integrity_unhealthy"
            return false
        }
        val blockedLan = runtime.portSentinelStore.blockedSources().sorted()
        val exactRouteCount = index.routePrefixes.size + blockedLan.size
        if (exactRouteCount > SELECTIVE_PLATFORM_ROUTE_BUDGET) {
            selectiveStartFailure = "selective_platform_route_budget_exceeded"
            return false
        }
        val builder = baseBuilder(SELECTIVE_MTU)
        if (!configureSelfBypass(builder)) {
            selectiveStartFailure = "selective_self_bypass_failed"
            return false
        }
        var installedRoutes = 0
        for (address in blockedLan) {
            val prefix = de.visiongaia.gedefense.mobile.core.IpPrefix.parse(address) ?: run {
                selectiveStartFailure = "selective_blocked_source_invalid"
                return false
            }
            val hostPrefix = if (prefix.family == 4) 32 else 128
            try {
                builder.addRoute(prefix.toInetAddress(), hostPrefix)
                installedRoutes++
            } catch (_: IllegalArgumentException) {
                selectiveStartFailure = "selective_route_config_failed"
                return false
            }
        }
        for (prefix in index.routePrefixes) {
            try {
                builder.addRoute(prefix.toInetAddress(), prefix.prefixLength)
                installedRoutes++
            } catch (_: IllegalArgumentException) {
                selectiveStartFailure = "selective_route_config_failed"
                return false
            }
        }
        if (installedRoutes != exactRouteCount || installedRoutes == 0 || installedRoutes > SELECTIVE_PLATFORM_ROUTE_BUDGET) {
            selectiveStartFailure = "selective_route_count_invariant_failed"
            return false
        }
        val descriptor = try {
            builder.establish()
        } catch (_: Exception) {
            null
        } ?: run {
            selectiveStartFailure = "selective_vpn_establish_failed"
            return false
        }
        val old = tunnel.getAndSet(descriptor)
        try { old?.close() } catch (error: IOException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
        if (!submitReader { readSelectiveLoop(descriptor, index) }) {
            tunnel.compareAndSet(descriptor, null)
            try { descriptor.close() } catch (error: IOException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
            selectiveStartFailure = "selective_reader_busy"
            return false
        }
        return true
    }

    private fun installFullFlow(index: ThreatIndex): Boolean {
        fullFlowStartFailure = "full_flow_start_failed"
        val egressMode = runtime.state.wireGuardEgressMode()
        // Capture the network-event generation together with the selected underlay. If a newer
        // callback arrives while this potentially slow build is in flight, the completed session
        // remains tagged with the older generation and the newer handover is still allowed to run.
        val selectedUnderlayGeneration = handoverGeneration.get()
        val selectedUnderlay = if (egressMode == WireGuardEgressMode.DIRECT) null else preferredPhysicalNetwork()
        var profile: WireGuardProfile? = null
        var wireGuardConfig: ByteArray? = null
        fun clearWireGuardMaterial() {
            wireGuardConfig?.fill(0)
            wireGuardConfig = null
            profile?.destroySecrets()
            profile = null
        }
        val builder = if (egressMode == WireGuardEgressMode.DIRECT) {
            baseBuilder(FULL_FLOW_MTU)
        } else {
            val underlay = selectedUnderlay ?: run {
                fullFlowStartFailure = "wireguard_underlay_unavailable"
                ensureWireGuardFailClosedAnchor("wireguard_underlay_unavailable")
                return false
            }
            profile = runtime.wireGuard.snapshot() ?: run {
                fullFlowStartFailure = "wireguard_profile_missing"
                return false
            }
            val current = profile ?: return false
            val endpoint = runtime.wireGuard.resolveEndpoint(current, underlay) ?: run {
                current.destroySecrets()
                fullFlowStartFailure = "wireguard_endpoint_resolution_failed"
                return false
            }
            wireGuardConfig = try { runtime.wireGuard.buildUapi(current, endpoint) } catch (_: RuntimeException) {
                current.destroySecrets()
                fullFlowStartFailure = "wireguard_config_build_failed"
                return false
            }
            try {
                baseBuilder(current.mtu, current.interfaceAddresses, underlay).also { configured ->
                    current.dnsServers.forEach { configured.addDnsServer(it) }
                }
            } catch (_: Exception) {
                clearWireGuardMaterial()
                fullFlowStartFailure = "wireguard_interface_config_failed"
                return false
            }
        }
        if (egressMode == WireGuardEgressMode.DIRECT && !configureSelfBypass(builder)) {
            clearWireGuardMaterial()
            fullFlowStartFailure = "full_flow_self_bypass_failed"
            return false
        }
        try {
            builder.addRoute("0.0.0.0", 0)
            builder.addRoute("::", 0)
        } catch (_: IllegalArgumentException) {
            clearWireGuardMaterial()
            fullFlowStartFailure = "full_flow_route_config_failed"
            return false
        }
        val descriptor = try { builder.establish() } catch (_: Exception) { null } ?: run {
            clearWireGuardMaterial()
            fullFlowStartFailure = "full_flow_vpn_establish_failed"
            return false
        }

        // A replacement VPN interface is established BEFORE the previous helper/session anchor is
        // closed. This converts handover/recovery from "tear down, then hope rebuild is fast" into a
        // fail-closed swap. Any previous emergency anchor is likewise closed only after this new TUN
        // exists, so there is no intentional direct-routing window between generations.
        val previousAnchor = tunnel.getAndSet(null)
        try { previousAnchor?.close() } catch (error: IOException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
        tearDownFullFlow()

        val constrained = isTransportPowerConstrained()
        val session = try {
            NativeGaiaNet.start(
                context = this,
                tunnel = descriptor,
                index = index,
                privacyRegistry = runtime.privacyIntelligence.registry(),
                privacyProfile = runtime.state.privacyProfile(),
                cacheDir = cacheDir,
                powerConstrained = constrained,
                telemetryDetailed = runtime.hasStateListeners(),
                egressMode = egressMode,
                tunnelMtu = profile?.mtu ?: FULL_FLOW_MTU,
                wireGuardConfig = wireGuardConfig,
                socketProtector = selectedUnderlay?.let { underlay ->
                    { socket -> protectWireGuardSocket(socket, underlay) }
                },
                quarantinedPackages = runtime.firewallPolicy.quarantinedPackages(),
            )
        } finally {
            clearWireGuardMaterial()
        } ?: run {
            fullFlowStartFailure = "full_flow_${NativeGaiaNet.lastStartFailure ?: "gaianet_start_failed"}"
            if (egressMode != WireGuardEgressMode.DIRECT) {
                // NativeGaiaNet leaves the caller-owned TUN open on startup failure. Retain it as a
                // bounded fail-closed anchor while recovery retries the helper/underlay. No reader is
                // attached intentionally: kernel TUN backpressure drops/blocks traffic instead of
                // permitting a direct fallback.
                val replaced = tunnel.getAndSet(descriptor)
                try { replaced?.close() } catch (error: IOException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
            } else {
                try { descriptor.close() } catch (error: IOException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
            }
            return false
        }
        val sessionGeneration = fullFlowSessionGeneration.incrementAndGet()
        val telemetry = FullFlowTelemetryReader(this, runtime, session.telemetryRead) { reason ->
            // Fatal telemetry delivery crosses reader -> main -> control threads. A callback from a
            // session that was replaced in between must never recycle its healthy successor. Check
            // the transport generation on both sides of the control-queue handoff.
            if (running.get() && sessionGeneration == fullFlowSessionGeneration.get()) {
                submitControl {
                    if (running.get() && sessionGeneration == fullFlowSessionGeneration.get()) {
                        handleFullFlowFailure(reason)
                    }
                }
            }
        }
        nativeSession = session; fullFlowReader = telemetry
        activeWireGuardUnderlay.set(selectedUnderlay)
        activeWireGuardUnderlayGeneration.set(
            if (egressMode == WireGuardEgressMode.DIRECT) -1L else selectedUnderlayGeneration,
        )
        lastPowerConstrained = constrained
        return true
    }

    private fun ensureWireGuardFailClosedAnchor(reason: String): Boolean {
        if (tunnel.get() != null || nativeSession != null) return true
        val builder = try {
            baseBuilder(FULL_FLOW_MTU).also {
                it.addRoute("0.0.0.0", 0)
                it.addRoute("::", 0)
            }
        } catch (_: Exception) {
            return false
        }
        val descriptor = try { builder.establish() } catch (_: Exception) { null } ?: return false
        val previous = tunnel.getAndSet(descriptor)
        try { previous?.close() } catch (error: IOException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
        appendEvidence("vpn.fail_closed", "warning", "local", "wireguard fail-closed anchor active reason=${reason.take(96)}")
        return true
    }

    private fun hasFullFlowContinuity(): Boolean = tunnel.get() != null || nativeSession != null


    private fun runRecoverySelfTest() {
        if (!running.get() || !platformLockdownEnabled() || runtime.state.protectionMode() != ProtectionMode.FULL_FLOW_BETA || recoveryPending.get()) {
            appendEvidence("vpn.resilience_test", "warning", "local", "self-test rejected status=${runtime.state.lastVpnStatus()}")
            return
        }
        val session = nativeSession ?: run {
            handleFullFlowFailure("self_test_missing_session")
            return
        }
        if (!selfTestPending.compareAndSet(false, true)) return
        selfTestStartedElapsed.set(SystemClock.elapsedRealtime())
        runtime.state.recordResilienceSelfTestStarted()
        runtime.notifyStateChanged()
        appendEvidence("vpn.resilience_test", "info", "local", "controlled GaiaNet transport recycle requested")
        // Kill only the helper process. The Session-owned TUN liveness anchor intentionally remains
        // open; the telemetry reader observes the resulting EOF and therefore exercises the exact
        // production recovery path without weakening routing while the self-test is in flight.
        if (!session.terminateHelperForRecoveryTest()) {
            completeSelfTest(false)
            handleFullFlowFailure("self_test_helper_termination_failed")
        }
    }

    private fun handleFullFlowFailure(reason: String) {
        if (!running.get() || runtime.state.protectionMode() != ProtectionMode.FULL_FLOW_BETA) return
        if (!recoveryPending.compareAndSet(false, true)) return
        handoverGeneration.incrementAndGet()
        val generation = recoveryGeneration.get()

        val egressMode = runtime.state.wireGuardEgressMode()
        if (egressMode == WireGuardEgressMode.WIREGUARD_STRICT && !platformLockdownEnabled()) {
            recoveryPending.set(false)
            completeSelfTest(false)
            ensureWireGuardFailClosedAnchor("wireguard_strict_android_lockdown_lost")
            runtime.state.setVpnStatus("RECOVERING", "wireguard_strict_android_lockdown_lost")
            runtime.notifyStateChanged()
            updateNotification()
            appendEvidence("vpn.kill_switch", "high", "local", "strict WireGuard waiting for Android lockdown restoration")
            armStrictInvariantWatchdog()
            return
        }
        if (egressMode != WireGuardEgressMode.DIRECT && preferredPhysicalNetwork() == null) {
            recoveryPending.set(false)
            completeSelfTest(false)
            ensureWireGuardFailClosedAnchor("wireguard_underlay_unavailable")
            runtime.state.setVpnStatus("RECOVERING", "wireguard_underlay_unavailable")
            runtime.notifyStateChanged()
            updateNotification()
            appendEvidence("vpn.recovery", "warning", "local", "wireguard recovery paused until physical underlay returns")
            return
        }

        val attempt = recoveryAttempts.incrementAndGet()
        if (attempt > MAX_FULL_FLOW_RECOVERY_ATTEMPTS) {
            recoveryPending.set(false)
            completeSelfTest(false)
            appendEvidence("vpn.recovery", "high", "local", "full-flow recovery exhausted reason=${reason.take(96)}")
            stopProtection("FULL_FLOW_FAILED", reason.take(160))
            return
        }
        runtime.state.setVpnStatus("RECOVERING", reason.take(160))
        runtime.notifyStateChanged()
        appendEvidence("vpn.recovery", "warning", "local", "full-flow recovery attempt=$attempt reason=${reason.take(96)}")
        val delay = FULL_FLOW_RECOVERY_DELAYS_MS[(attempt - 1).coerceIn(0, FULL_FLOW_RECOVERY_DELAYS_MS.lastIndex)]
        val scheduled = scheduleControl(delay) {
            if (generation != recoveryGeneration.get() || !running.get() || runtime.state.protectionMode() != ProtectionMode.FULL_FLOW_BETA) {
                recoveryPending.set(false)
                return@scheduleControl
            }
            recoveryPending.set(false)
            val index = runtime.threatIndex.get()
            val readiness = readinessFailure(index, ProtectionMode.FULL_FLOW_BETA)
            if (readiness != null) {
                if (!retainStrictFailClosedOnLockdownLoss(readiness.second)) {
                    stopProtection(readiness.first, readiness.second)
                }
                return@scheduleControl
            }
            if (installFullFlow(index)) {
                invalidateRecovery(resetAttempts = true)
                runtime.state.recordVpnRecovery("full_flow:$attempt")
                runtime.state.setVpnStatus("FULL_GUARDED", null)
                armStrictInvariantWatchdog()
                completeSelfTest(true)
                updateNotification()
                runtime.notifyStateChanged()
                appendEvidence("vpn.recovery", "info", "local", "full-flow transport recovered attempt=$attempt")
            } else {
                handleFullFlowFailure("recovery_establish_failed")
            }
        }
        if (!scheduled) {
            recoveryPending.set(false)
            completeSelfTest(false)
            appendEvidence("vpn.recovery", "high", "local", "full-flow recovery scheduler saturated")
            if (egressMode == WireGuardEgressMode.WIREGUARD_STRICT) {
                ensureWireGuardFailClosedAnchor("recovery_scheduler_busy")
                runtime.state.setVpnStatus("RECOVERING", "recovery_scheduler_busy")
                runtime.notifyStateChanged()
                updateNotification()
                armStrictInvariantWatchdog()
            } else {
                stopProtection("FULL_FLOW_FAILED", "recovery_scheduler_busy")
            }
        }
    }

    private fun completeSelfTest(success: Boolean) {
        if (!selfTestPending.compareAndSet(true, false)) return
        val started = selfTestStartedElapsed.getAndSet(0L)
        val duration = if (started > 0L) (SystemClock.elapsedRealtime() - started).coerceAtLeast(0L) else 0L
        runtime.state.recordResilienceSelfTestResult(success, duration)
    }

    private fun invalidateRecovery(resetAttempts: Boolean) {
        recoveryGeneration.incrementAndGet()
        recoveryPending.set(false)
        if (resetAttempts) recoveryAttempts.set(0)
    }

    private fun armStrictInvariantWatchdog() {
        if (!running.get() || runtime.state.protectionMode() != ProtectionMode.FULL_FLOW_BETA ||
            runtime.state.wireGuardEgressMode() != WireGuardEgressMode.WIREGUARD_STRICT) return
        if (!strictWatchdogScheduled.compareAndSet(false, true)) return
        scheduleStrictInvariantCheck(strictInvariantGeneration.get())
    }

    private fun scheduleStrictInvariantCheck(generation: Long) {
        if (!scheduleControl(STRICT_KILL_SWITCH_WATCHDOG_MS) {
            if (generation != strictInvariantGeneration.get()) return@scheduleControl
            strictWatchdogScheduled.set(false)
            if (!running.get() ||
                runtime.state.protectionMode() != ProtectionMode.FULL_FLOW_BETA ||
                runtime.state.wireGuardEgressMode() != WireGuardEgressMode.WIREGUARD_STRICT) return@scheduleControl

            if (!platformLockdownEnabled()) {
                val firstObservation = runtime.state.lastVpnReason() != "wireguard_strict_android_lockdown_lost"
                runtime.state.setVpnStatus("RECOVERING", "wireguard_strict_android_lockdown_lost")
                runtime.notifyStateChanged()
                updateNotification()
                if (firstObservation) {
                    appendEvidence("vpn.kill_switch", "high", "local", "Android lockdown disabled while strict WireGuard is active; retaining VPN anchor")
                }
            } else {
                when (runtime.state.lastVpnReason()) {
                    "wireguard_strict_android_lockdown_lost" -> {
                        val sessionAlive = nativeSession?.isProcessAlive() == true
                        if (sessionAlive) {
                            runtime.state.setVpnStatus("FULL_GUARDED", null)
                            runtime.notifyStateChanged()
                            updateNotification()
                            appendEvidence("vpn.kill_switch", "info", "local", "Android lockdown restored; strict WireGuard invariant healthy")
                        } else {
                            refreshTunnel()
                            return@scheduleControl
                        }
                    }
                    "recovery_scheduler_busy" -> {
                        // The bounded control queue has drained enough for this watchdog to execute.
                        // Retry the retained fail-closed transport rather than waiting indefinitely.
                        refreshTunnel()
                        return@scheduleControl
                    }
                    "wireguard_underlay_unavailable" -> {
                        if (preferredPhysicalNetwork() != null) {
                            refreshTunnel()
                            return@scheduleControl
                        }
                    }
                }
            }
            armStrictInvariantWatchdog()
        }) {
            if (generation != strictInvariantGeneration.get()) return
            strictWatchdogScheduled.set(false)
            if (serviceDestroyed.get() || !running.get() ||
                runtime.state.protectionMode() != ProtectionMode.FULL_FLOW_BETA ||
                runtime.state.wireGuardEgressMode() != WireGuardEgressMode.WIREGUARD_STRICT) return
            completeSelfTest(false)
            appendEvidence("vpn.kill_switch", "high", "local", "strict invariant watchdog could not be scheduled")
            if (platformLockdownEnabled()) {
                // With Android lockdown still active, hand fail-closed ownership back to the OS. A
                // wedged internal scheduler must never leave a Strict session falsely reported healthy.
                stopProtection("FULL_FLOW_FAILED", "strict_watchdog_scheduler_busy")
            } else {
                // If lockdown disappeared at the same time, closing our last TUN would be the unsafe
                // action. Keep the anchor and surface the already-known kill-switch loss instead.
                ensureWireGuardFailClosedAnchor("wireguard_strict_android_lockdown_lost")
                runtime.state.setVpnStatus("RECOVERING", "wireguard_strict_android_lockdown_lost")
                runtime.notifyStateChanged()
                updateNotification()
            }
        }
    }

    private fun retainStrictFailClosedOnLockdownLoss(reason: String): Boolean {
        if (!running.get() || runtime.state.protectionMode() != ProtectionMode.FULL_FLOW_BETA ||
            runtime.state.wireGuardEgressMode() != WireGuardEgressMode.WIREGUARD_STRICT ||
            reason != "wireguard_strict_requires_android_lockdown" || !hasFullFlowContinuity()) return false
        recoveryPending.set(false)
        runtime.state.setVpnStatus("RECOVERING", "wireguard_strict_android_lockdown_lost")
        runtime.notifyStateChanged()
        updateNotification()
        appendEvidence("vpn.kill_switch", "high", "local", "strict WireGuard remains fail-closed while Android lockdown is unavailable")
        armStrictInvariantWatchdog()
        return true
    }

    private fun readLockdownLoop(descriptor: ParcelFileDescriptor) {
        val input = FileInputStream(descriptor.fileDescriptor)
        val buffer = ByteArray(MAX_PACKET_BYTES)
        var unexpectedFailure: String? = null
        try {
            while (running.get() && tunnel.get() === descriptor) {
                val read = input.read(buffer)
                if (read < 0) { if (running.get() && tunnel.get() === descriptor) unexpectedFailure = "tun_eof"; break }
                val packet = PacketParser.parse(buffer, read) ?: continue
                // Intentionally do not forward. Apps not excluded by the allowlist are fully denied.
                flows.observe(packet); runtime.metrics.setActiveFlows(flows.size())
                val owner = owners.resolve(packet) ?: "uid-unresolved"
                runtime.metrics.recordBlocked(packet, owner)
                if (dedupe.shouldEmit("lockdown|${packet.destination}|${packet.protocol}|$owner")) {
                    if (!appendEvidence(
                            "firewall.block", "info", packet.destination.toString(),
                            "app=$owner protocol=${packet.protocol} dport=${packet.destinationPort ?: 0} mode=lockdown",
                        )
                    ) {
                        requestEvidenceDegrade(lastEvidenceWriteFailure.get()); break
                    }
                    runtime.notifyStateChanged()
                }
            }
        } catch (_: IOException) {
            if (running.get() && tunnel.get() === descriptor) unexpectedFailure = "tun_io_failure"
        } catch (_: RuntimeException) {
            if (running.get() && tunnel.get() === descriptor) unexpectedFailure = "tun_runtime_failure"
        } finally { try { input.close() } catch (error: IOException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) } }

        if (unexpectedFailure != null && running.get() && tunnel.compareAndSet(descriptor, null)) {
            try { descriptor.close() } catch (error: IOException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
            val failure = unexpectedFailure
            submitControl { handleTunFailure("TUN_FAILED", failure) }
        }
    }

    private fun readSelectiveLoop(descriptor: ParcelFileDescriptor, policyIndex: ThreatIndex) {
        val input = FileInputStream(descriptor.fileDescriptor)
        val buffer = ByteArray(MAX_PACKET_BYTES)
        val policy = PolicyEngine(policyIndex)
        var unexpectedFailure: String? = null
        try {
            while (running.get() && tunnel.get() === descriptor) {
                val read = input.read(buffer)
                if (read < 0) { if (running.get() && tunnel.get() === descriptor) unexpectedFailure = "tun_eof"; break }
                val packet = PacketParser.parse(buffer, read) ?: continue
                // Private /32 routes are installed only for the authenticated Sentinel denylist.
                // Other local kernel-control traffic is ignored and never treated as public threat intelligence.
                if (!packet.destination.isPublic()) {
                    val destination = packet.destination.toString()
                    if (runtime.portSentinelStore.isBlocked(destination)) {
                        flows.observe(packet); runtime.metrics.setActiveFlows(flows.size())
                        val owner = owners.resolve(packet) ?: "uid-unresolved"
                        runtime.metrics.recordBlocked(packet, owner)
                        if (dedupe.shouldEmit("sentinel-deny|$destination|${packet.protocol}|$owner")) {
                            if (!appendEvidence("sentinel.block", "high", destination, "app=$owner protocol=${packet.protocol} dport=${packet.destinationPort ?: 0} mode=selective")) {
                                requestEvidenceDegrade(lastEvidenceWriteFailure.get()); break
                            }
                            runtime.notifyStateChanged()
                        }
                    }
                    continue
                }
                flows.observe(packet); runtime.metrics.setActiveFlows(flows.size())
                val decision = policy.evaluate(packet.destination)
                if (decision.verdict != ThreatVerdict.BLOCK) { unexpectedFailure = "policy_invariant_failure"; break }
                val owner = owners.resolve(packet) ?: "uid-unresolved"
                runtime.metrics.recordBlocked(packet, owner)
                val feeds = decision.blockingFeeds.joinToString(",") { it.id }
                if (dedupe.shouldEmit("${packet.destination}|${packet.protocol}|$owner")) {
                    if (!appendEvidence("threat.block", "high", packet.destination.toString(), "app=$owner protocol=${packet.protocol} dport=${packet.destinationPort ?: 0} feeds=$feeds mode=selective")) {
                        requestEvidenceDegrade(lastEvidenceWriteFailure.get()); break
                    }
                    try { runtime.xdr.recordThreatBlock(owner, packet.destination.toString(), packet.protocol, packet.destinationPort ?: 0) } catch (error: Throwable) { runtime.recordXdrFailure("threat_block", error) }
                    runtime.notifyStateChanged()
                }
            }
        } catch (_: IOException) {
            if (running.get() && tunnel.get() === descriptor) unexpectedFailure = "tun_io_failure"
        } catch (_: RuntimeException) {
            if (running.get() && tunnel.get() === descriptor) unexpectedFailure = "tun_runtime_failure"
        } finally { try { input.close() } catch (error: IOException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) } }

        if (unexpectedFailure != null && running.get() && tunnel.compareAndSet(descriptor, null)) {
            try { descriptor.close() } catch (error: IOException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
            val failure = unexpectedFailure
            val status = if (failure == "policy_invariant_failure") "POLICY_INVARIANT_FAILED" else "TUN_FAILED"
            submitControl { handleTunFailure(status, failure) }
        }
    }

    private fun refreshTunnel() {
        val index = runtime.threatIndex.get(); val mode = runtime.state.protectionMode()
        if (mode == ProtectionMode.FULL_FLOW_BETA) invalidateRecovery(resetAttempts = true)
        readinessFailure(index, mode)?.let {
            if (mode == ProtectionMode.FULL_FLOW_BETA && retainStrictFailClosedOnLockdownLoss(it.second)) return
            stopProtection(it.first, it.second)
            return
        }
        val ok = when (mode) {
            ProtectionMode.FULL_FLOW_BETA -> installFullFlow(index)
            ProtectionMode.LOCKDOWN -> installLockdown()
            ProtectionMode.SELECTIVE -> installSelective(index)
        }
        if (!ok) {
            if (mode == ProtectionMode.FULL_FLOW_BETA && hasFullFlowContinuity()) {
                handleFullFlowFailure("refresh_${fullFlowStartFailure.take(120)}")
            } else {
                stopProtection("ESTABLISH_FAILED", "policy_refresh_failed")
            }
            return
        }
        val activeStatus = when (mode) {
            ProtectionMode.FULL_FLOW_BETA -> "FULL_GUARDED"
            ProtectionMode.LOCKDOWN -> "LOCKDOWN_GUARDED"
            ProtectionMode.SELECTIVE -> "GUARDED"
        }
        runtime.state.setVpnStatus(activeStatus, null)
        armStrictInvariantWatchdog()
        updateNotification(); runtime.notifyStateChanged()
        val fingerprint = when (mode) {
            ProtectionMode.FULL_FLOW_BETA -> index.fullPolicySha256
            ProtectionMode.LOCKDOWN -> "allowlist:${runtime.firewallPolicy.allowedPackages().size}"
            ProtectionMode.SELECTIVE -> index.routePolicySha256
        }
        if (!appendEvidence("vpn.routes", "info", "local", "policy refreshed mode=${mode.name} routes=${index.routePrefixes.size} prefixes=${index.count} policy=$fingerprint")) {
            degradeEvidenceAndStop(lastEvidenceWriteFailure.get())
        }
    }

    private fun reevaluateEvidenceAsync(startId: Int) {
        runtime.verifyEvidenceAsync { health ->
            submitControl {
                if (!health.ok && running.get()) degradeEvidenceAndStop("evidence_integrity_unhealthy")
                else if (running.get()) {
                    val status = when (runtime.state.protectionMode()) {
                        ProtectionMode.FULL_FLOW_BETA -> "FULL_GUARDED"
                        ProtectionMode.LOCKDOWN -> "LOCKDOWN_GUARDED"
                        ProtectionMode.SELECTIVE -> "GUARDED"
                    }
                    runtime.state.setVpnStatus(status, null); updateNotification(); runtime.notifyStateChanged()
                } else {
                    runtime.state.setVpnActive(false)
                    runtime.state.setVpnStatus(if (health.ok) "OFF" else "DEGRADED_EVIDENCE", if (health.ok) null else "evidence_integrity_unhealthy")
                    runtime.notifyStateChanged()
                    stopSelf(startId)
                }
            }
        }
    }

    private fun commitBehaviorSession() {
        if (runtime.state.protectionMode() != ProtectionMode.FULL_FLOW_BETA) return
        try { runtime.behavior.commitSession(runtime.fullFlowAnalytics.snapshot()) } catch (error: Throwable) { runtime.recordXdrFailure("behavior_commit", error) }
    }

    private fun requestEvidenceDegrade(reason: String) {
        submitControl {
            if (running.get()) degradeEvidenceAndStop(reason)
        }
    }

    private fun handleTunFailure(status: String, reason: String) {
        if (!running.get()) return
        appendEvidence("vpn.failure", "high", "local", reason)
        stopProtection(status, reason)
    }

    private fun degradeEvidenceAndStop(reason: String) {
        cancelPendingStart()
        completeSelfTest(false)
        invalidateRecovery(resetAttempts = true)
        handoverGeneration.incrementAndGet()
        strictInvariantGeneration.incrementAndGet()
        strictWatchdogScheduled.set(false)
        commitBehaviorSession()
        running.set(false); closeTransports(); runtime.metrics.setActiveFlows(0); runtime.fullFlowAnalytics.stop()
        runtime.state.setVpnActive(false); runtime.state.setVpnStatus("DEGRADED_EVIDENCE", reason)
        runtime.verifyEvidenceAsync(); runtime.notifyStateChanged(); stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
    }

    private fun stopProtection(finalStatus: String, reason: String) {
        cancelPendingStart()
        completeSelfTest(false)
        invalidateRecovery(resetAttempts = true)
        handoverGeneration.incrementAndGet()
        strictInvariantGeneration.incrementAndGet()
        strictWatchdogScheduled.set(false)
        if (running.getAndSet(false)) appendEvidence("vpn.state", "info", "local", "stopped reason=$reason")
        commitBehaviorSession()
        closeTransports(); runtime.metrics.setActiveFlows(0); runtime.fullFlowAnalytics.stop()
        runtime.state.setVpnActive(false); runtime.state.setVpnStatus(finalStatus, if (finalStatus == "OFF") null else reason)
        runtime.notifyStateChanged(); stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
    }

    private fun closeTransports() {
        try { tunnel.getAndSet(null)?.close() } catch (error: IOException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
        tearDownFullFlow()
    }

    private fun tearDownFullFlow() {
        // Invalidate any fatal callback already posted by the old telemetry reader before closing
        // its descriptors. This is independent from handover/recovery generations because it owns
        // one concrete helper/TUN transport instance.
        fullFlowSessionGeneration.incrementAndGet()
        activeWireGuardUnderlay.set(null)
        activeWireGuardUnderlayGeneration.set(-1L)
        val telemetry = fullFlowReader; fullFlowReader = null
        try { telemetry?.close() } catch (error: Throwable) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
        val session = nativeSession; nativeSession = null
        try { session?.close() } catch (error: Throwable) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
        NativeGaiaNet.stop()
    }

    private fun appendEvidence(type: String, severity: String, subject: String, detail: String): Boolean = try {
        runtime.evidence.append(EvidenceEvent(type, severity, subject, detail))
        lastEvidenceWriteFailure.set("evidence_write_failure")
        true
    } catch (error: Throwable) {
        val code = EvidenceWriteFailureClassifier.code(error)
        lastEvidenceWriteFailure.set(code)
        runtime.state.recordEvidencePersistenceFailure(code)
        false
    }

    override fun onRevoke() {
        if (runtimeReady.get()) {
            runtime.state.recordPlatformVpnPolicy(alwaysOn = false, lockdown = false)
            cancelPendingStart()
            submitControl { stopProtection("OFF", "system_revoke") }
        }
        super.onRevoke()
    }

    override fun onDestroy() {
        serviceDestroyed.set(true)
        strictInvariantGeneration.incrementAndGet()
        strictWatchdogScheduled.set(false)
        val hadRuntime = runtimeReady.get()
        val behaviorWasRunning = hadRuntime && running.get()
        if (hadRuntime) {
            cancelPendingStart()
            invalidateRecovery(resetAttempts = true)
            handoverGeneration.incrementAndGet()
            running.set(false)
        }

        // Close only the local TUN descriptor synchronously so blocked readers wake immediately.
        // Process waits, Binder cleanup and authenticated persistence are never executed on Android's
        // main Service lifecycle thread.
        val descriptor = tunnel.getAndSet(null)
        try { descriptor?.close() } catch (error: IOException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
        control.shutdownNow()
        reader.shutdownNow()

        if (hadRuntime) {
            try {
                DESTROY_CLEANUP_EXECUTOR.execute { destroyCleanup(behaviorWasRunning) }
            } catch (_: RejectedExecutionException) {
                // The TUN descriptor is already closed and Android owns the remaining process
                // resources. Never fall back to blocking cleanup on the lifecycle thread.
            }
        }
        super.onDestroy()
    }

    private fun destroyCleanup(commitBehavior: Boolean) {
        completeSelfTest(false)
        if (commitBehavior) commitBehaviorSession()
        closeTransports()
        runtime.fullFlowAnalytics.stop()
        try { connectivity.unregisterNetworkCallback(physicalNetworkCallback) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
        try { unregisterReceiver(powerStateReceiver) } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
        try { portSentinel.close() } catch (error: Exception) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
        try { runtime.portSentinelStore.flush() } catch (error: RuntimeException) { RuntimeFailureLog.nonCritical("ge-defense-vpn-service", error) }
        runtime.state.setVpnActive(false)
        runtime.state.setTransportPowerConstrained(false)
        if (runtime.state.lastVpnStatus() in setOf("GUARDED", "FULL_GUARDED", "LOCKDOWN_GUARDED", "STARTING", "RECOVERING")) {
            runtime.state.setVpnStatus("OFF", null)
        }
    }
    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    private fun createChannel() {
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL_ID, getString(R.string.notification_channel), NotificationManager.IMPORTANCE_LOW).apply {
                description = getString(R.string.notification_channel_detail); setShowBadge(false)
            },
        )
    }

    private fun notification(text: String): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val stop = PendingIntent.getService(this, 1, Intent(this, GeDefenseVpnService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return Notification.Builder(this, CHANNEL_ID).setSmallIcon(android.R.drawable.ic_lock_lock).setContentTitle(getString(R.string.app_name))
            .setContentText(text).setContentIntent(open).addAction(
                Notification.Action.Builder(Icon.createWithResource(this, android.R.drawable.ic_delete), getString(R.string.notification_stop), stop).build(),
            )
            .setOngoing(true).setCategory(Notification.CATEGORY_SERVICE).build()
    }

    private fun updateNotification() {
        val text = when (runtime.state.lastVpnStatus()) {
            "FULL_GUARDED" -> getString(R.string.vpn_full_guarded)
            "LOCKDOWN_GUARDED" -> getString(R.string.vpn_lockdown_guarded)
            "GUARDED" -> getString(R.string.vpn_guarded)
            else -> getString(R.string.vpn_degraded)
        }
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(text))
    }

    companion object {
        const val ACTION_START = "de.visiongaia.gedefense.mobile.START"
        const val ACTION_STOP = "de.visiongaia.gedefense.mobile.STOP"
        const val ACTION_REFRESH = "de.visiongaia.gedefense.mobile.REFRESH"
        const val ACTION_REEVALUATE = "de.visiongaia.gedefense.mobile.REEVALUATE"
        const val ACTION_INTEGRITY_FAILURE = "de.visiongaia.gedefense.mobile.INTEGRITY_FAILURE"
        const val ACTION_RESILIENCE_PROBE = "de.visiongaia.gedefense.mobile.RESILIENCE_PROBE"
        const val ACTION_RECOVERY_SELF_TEST = "de.visiongaia.gedefense.mobile.RECOVERY_SELF_TEST"
        private const val CHANNEL_ID = "gedefense_protection"
        private const val NOTIFICATION_ID = 4701
        private const val RUNTIME_INITIALIZATION_TIMEOUT_MS = 15_000L
        private const val VPN_DISCLOSURE_BOOTSTRAP_TIMEOUT_MS = 10_000L
        private const val MODE_STORE_BOOTSTRAP_TIMEOUT_MS = 10_000L
        private const val PROTECTION_CONFIGURATION_FREEZE_TIMEOUT_MS = 2_000L
        private const val CONTROL_QUEUE_CAPACITY = 32
        private const val SELECTIVE_MTU = 1500
        private const val SELECTIVE_PLATFORM_ROUTE_BUDGET = 1_024
        private const val FULL_FLOW_MTU = 1280
        private const val WIREGUARD_SOCKET_PROTECT_TIMEOUT_MS = 2_000L
        private const val MAX_PACKET_BYTES = 65_535
        private const val MAX_PHYSICAL_NETWORKS = 4
        private const val HANDOVER_DEBOUNCE_MS = 2_000L
        private const val STRICT_KILL_SWITCH_WATCHDOG_MS = 5_000L
        private const val SECURITY_BOOTSTRAP_TIMEOUT_MS = 30_000L
        private const val MAX_FULL_FLOW_RECOVERY_ATTEMPTS = 3
        private val FULL_FLOW_RECOVERY_DELAYS_MS = longArrayOf(500L, 1_500L, 4_000L)
        private val DESTROY_CLEANUP_EXECUTOR = BoundedExecutors.fixed(
            name = "gedefense-destroy-cleanup",
            threads = 1,
            queueCapacity = 2,
        )
    }
}
