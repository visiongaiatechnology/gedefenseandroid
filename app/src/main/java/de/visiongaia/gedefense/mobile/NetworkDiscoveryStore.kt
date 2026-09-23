package de.visiongaia.gedefense.mobile

import android.content.Context
import de.visiongaia.gedefense.mobile.core.AuthenticatedSnapshotState
import de.visiongaia.gedefense.mobile.core.LanBehaviorEvaluator
import de.visiongaia.gedefense.mobile.core.LanDeviceBehaviorInput
import de.visiongaia.gedefense.mobile.core.LanNetworkBehaviorInput
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.charset.StandardCharsets

// STATUS: DIAMANT VGT SUPREME
data class NetworkDiscoveryDelta(
    val newDeviceIds: Set<String>,
    val newlyExposedPorts: Map<String, Set<Int>>,
    val newlyAdvertisedServices: Map<String, Set<String>>,
    val changedAttributes: Map<String, Set<String>>,
    val deviceBehaviorSignals: Map<String, Set<String>> = emptyMap(),
    val deviceBaselineObservations: Map<String, Int> = emptyMap(),
    val deviceHistoricalRiskScore: Map<String, Int> = emptyMap(),
    val networkBehaviorSignals: Set<String> = emptySet(),
    val networkBaselineObservations: Int = 0,
    val historicalDeviceCount: Int = 0,
    val historicalElevatedCount: Int = 0,
)

/**
 * Authenticated local-network baseline with delayed promotion of newly observed services.
 * One anomalous scan cannot silently redefine normal exposure; candidates must be observed twice.
 */
class NetworkDiscoveryStore(context: Context) {
    private data class DeviceRecord(
        val stableId: String,
        val identitySource: NetworkIdentitySource,
        val firstSeenMillis: Long,
        val lastSeenMillis: Long,
        val lastIp: String,
        val macAddress: String?,
        val hostname: String?,
        val role: String,
        val openPorts: Set<Int>,
        val advertisedServiceTypes: Set<String>,
        val pendingPorts: Map<Int, Int>,
        val pendingServices: Map<String, Int>,
        val observations: Int,
        val riskEwma: Int,
    )

    private data class NetworkRecord(
        val networkId: String,
        val lastSeenMillis: Long,
        val devices: MutableMap<String, DeviceRecord>,
        val observations: Int,
        val deviceCountEwma: Int,
        val elevatedCountEwma: Int,
    )

    private val lock = Any()
    private val recoveryDir = File(context.noBackupFilesDir, "vault-recovery")
    private val betaRecoveryBoundaryMillis: Long? by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        BetaVaultMigrationPolicy.updateBoundaryMillis(context)
    }
    private val store = SecureSnapshotStore(
        File(context.noBackupFilesDir, "xdr/network-discovery.v1.bin"),
        hmacKey = null,
        domain = VaultDomain.NETWORK_DISCOVERY,
        schemaVersion = 1,
        maxPlaintextBytes = MAX_PAYLOAD_BYTES,
        hmacKeyProvider = { SecureTelemetryVault.hotPathHmacKey(VaultDomain.NETWORK_DISCOVERY) },
        legacyHmacKeyProvider = { AndroidSecrets.hmacSha256OrNull("vgt.gedefense.mobile.network.discovery.hmac.v1") },
    )
    private var networks = linkedMapOf<String, NetworkRecord>()
    @Volatile private var integrityOk = false
    @Volatile private var integrityReason: String? = "network_discovery_initializing"

    fun initialize() = load()

    fun integrityOk(): Boolean = integrityOk
    fun integrityFailureReason(): String? = integrityReason

    fun applyScan(networkId: String, devices: List<NetworkDevice>, now: Long): NetworkDiscoveryDelta = synchronized(lock) {
        if (!integrityOk || networkId.isBlank()) {
            return@synchronized NetworkDiscoveryDelta(emptySet(), emptyMap(), emptyMap(), emptyMap())
        }
        val boundedDevices = devices.take(MAX_DEVICES_PER_NETWORK)
        val previousNetworks = deepCopy(networks)
        val oldNetwork = networks[networkId]
        val initializingNetwork = oldNetwork == null
        val oldDevices = oldNetwork?.devices.orEmpty()
        val newIds = linkedSetOf<String>()
        val newPorts = linkedMapOf<String, Set<Int>>()
        val newServices = linkedMapOf<String, Set<String>>()
        val changedAttributes = linkedMapOf<String, Set<String>>()
        val behaviorSignals = linkedMapOf<String, Set<String>>()
        val observationsByDevice = linkedMapOf<String, Int>()
        val historicalRiskByDevice = linkedMapOf<String, Int>()
        val merged = LinkedHashMap(oldDevices)

        val currentElevated = boundedDevices.count { it.risk == NetworkDeviceRisk.HIGH || it.risk == NetworkDeviceRisk.CRITICAL }
        val oldNetworkObservations = oldNetwork?.observations ?: 0
        val historicalDeviceCount = oldNetwork?.deviceCountEwma ?: boundedDevices.size
        val historicalElevatedCount = oldNetwork?.elevatedCountEwma ?: currentElevated
        val networkSignals = if (initializingNetwork) emptySet() else LanBehaviorEvaluator.networkSignals(
            LanNetworkBehaviorInput(
                observations = oldNetworkObservations,
                historicalDeviceCount = historicalDeviceCount,
                currentDeviceCount = boundedDevices.size,
                historicalElevatedCount = historicalElevatedCount,
                currentElevatedCount = currentElevated,
            )
        )

        boundedDevices.forEach { device ->
            val direct = oldDevices[device.stableId]
            val strongerIdentityAlias = if (direct == null && device.identitySource != NetworkIdentitySource.IP) {
                oldDevices.values.firstOrNull { old -> old.identitySource == NetworkIdentitySource.IP && old.lastIp == device.ipAddress }
            } else null
            val old = direct ?: strongerIdentityAlias
            if (!initializingNetwork && old == null) newIds += device.stableId

            val observedPorts = device.openServices.asSequence().map { it.port }.filter { it in 1..65535 }.toSortedSet()
            val observedServices = device.advertisedServices.asSequence()
                .map { it.baselineKey }
                .filter(::isSafeServiceType)
                .take(MAX_SERVICES_PER_DEVICE)
                .toSortedSet()
            val appearedPorts = if (initializingNetwork) emptySet() else observedPorts - old?.openPorts.orEmpty()
            val appearedServices = if (initializingNetwork) emptySet() else observedServices - old?.advertisedServiceTypes.orEmpty()
            if (appearedPorts.isNotEmpty()) newPorts[device.stableId] = appearedPorts
            if (appearedServices.isNotEmpty()) newServices[device.stableId] = appearedServices

            if (!initializingNetwork && old != null && direct != null) {
                val changes = linkedSetOf<String>()
                if (!old.hostname.isNullOrBlank() && !device.hostname.isNullOrBlank() && old.hostname != device.hostname) changes += "hostname"
                if (old.role != "NETWORK_DEVICE" && device.role != "NETWORK_DEVICE" && old.role != device.role) changes += "role"
                if (changes.isNotEmpty()) changedAttributes[device.stableId] = changes
            }

            val oldObservations = old?.observations ?: 0
            val historicalRisk = old?.riskEwma ?: device.riskScore
            val signals = if (initializingNetwork || old == null) emptySet() else LanBehaviorEvaluator.deviceSignals(
                LanDeviceBehaviorInput(
                    observations = oldObservations,
                    historicalRiskScore = historicalRisk,
                    currentRiskScore = device.riskScore,
                    newlyExposedPorts = appearedPorts.size,
                    newlyAdvertisedServices = appearedServices.size,
                    lastSeenMillis = old.lastSeenMillis,
                    nowMillis = now,
                )
            )
            if (signals.isNotEmpty()) behaviorSignals[device.stableId] = signals

            val stablePorts: Set<Int>
            val pendingPorts: Map<Int, Int>
            val stableServices: Set<String>
            val pendingServices: Map<String, Int>
            if (initializingNetwork || old == null) {
                stablePorts = observedPorts.take(MAX_PORTS_PER_DEVICE).toSet()
                pendingPorts = emptyMap()
                stableServices = observedServices
                pendingServices = emptyMap()
            } else {
                val promotedPorts = old.openPorts.toMutableSet()
                val nextPendingPorts = linkedMapOf<Int, Int>()
                (observedPorts - old.openPorts).take(MAX_PENDING_PORTS).forEach { port ->
                    val count = (old.pendingPorts[port] ?: 0) + 1
                    if (count >= PROMOTION_OBSERVATIONS) promotedPorts += port else nextPendingPorts[port] = count
                }
                stablePorts = promotedPorts.take(MAX_PORTS_PER_DEVICE).toSet()
                pendingPorts = nextPendingPorts

                val promotedServices = old.advertisedServiceTypes.toMutableSet()
                val nextPendingServices = linkedMapOf<String, Int>()
                (observedServices - old.advertisedServiceTypes).take(MAX_PENDING_SERVICES).forEach { service ->
                    val count = (old.pendingServices[service] ?: 0) + 1
                    if (count >= PROMOTION_OBSERVATIONS) promotedServices += service else nextPendingServices[service] = count
                }
                stableServices = promotedServices.take(MAX_SERVICES_PER_DEVICE).toSet()
                pendingServices = nextPendingServices
            }

            val newObservationCount = (oldObservations + 1).coerceAtMost(MAX_OBSERVATIONS)
            val nextRiskEwma = when {
                old == null || oldObservations == 0 -> device.riskScore.coerceIn(0, 100)
                signals.isNotEmpty() -> historicalRisk.coerceIn(0, 100)
                else -> (((historicalRisk * 3L) + device.riskScore.toLong()) / 4L).toInt().coerceIn(0, 100)
            }
            observationsByDevice[device.stableId] = newObservationCount
            historicalRiskByDevice[device.stableId] = historicalRisk.coerceIn(0, 100)

            if (strongerIdentityAlias != null && strongerIdentityAlias.stableId != device.stableId) merged.remove(strongerIdentityAlias.stableId)
            merged[device.stableId] = DeviceRecord(
                stableId = device.stableId.take(MAX_ID_CHARS),
                identitySource = device.identitySource,
                firstSeenMillis = old?.firstSeenMillis ?: now,
                lastSeenMillis = now,
                lastIp = device.ipAddress.take(64),
                macAddress = device.macAddress?.take(32),
                hostname = device.hostname?.take(MAX_HOST_CHARS),
                role = device.role.take(80),
                openPorts = stablePorts,
                advertisedServiceTypes = stableServices,
                pendingPorts = pendingPorts,
                pendingServices = pendingServices,
                observations = newObservationCount,
                riskEwma = nextRiskEwma,
            )
        }

        val trimmedDevices = merged.values.sortedByDescending { it.lastSeenMillis }.take(MAX_DEVICES_PER_NETWORK)
            .associateByTo(linkedMapOf()) { it.stableId }
        val nextNetworkObservations = (oldNetworkObservations + 1).coerceAtMost(MAX_OBSERVATIONS)
        val nextDeviceCountEwma = when {
            oldNetwork == null || oldNetworkObservations == 0 -> boundedDevices.size
            networkSignals.isNotEmpty() -> historicalDeviceCount
            else -> (((historicalDeviceCount * 3L) + boundedDevices.size.toLong()) / 4L).toInt()
        }.coerceIn(0, MAX_DEVICES_PER_NETWORK)
        val nextElevatedEwma = when {
            oldNetwork == null || oldNetworkObservations == 0 -> currentElevated
            networkSignals.isNotEmpty() -> historicalElevatedCount
            else -> (((historicalElevatedCount * 3L) + currentElevated.toLong()) / 4L).toInt()
        }.coerceIn(0, MAX_DEVICES_PER_NETWORK)

        networks[networkId] = NetworkRecord(
            networkId = networkId,
            lastSeenMillis = now,
            devices = trimmedDevices,
            observations = nextNetworkObservations,
            deviceCountEwma = nextDeviceCountEwma,
            elevatedCountEwma = nextElevatedEwma,
        )
        networks = networks.values.sortedByDescending { it.lastSeenMillis }.take(MAX_NETWORKS)
            .associateByTo(linkedMapOf()) { it.networkId }

        if (!persist()) {
            networks = previousNetworks
            degrade("network discovery baseline persist failed")
            return@synchronized NetworkDiscoveryDelta(emptySet(), emptyMap(), emptyMap(), emptyMap())
        }
        NetworkDiscoveryDelta(
            newDeviceIds = newIds,
            newlyExposedPorts = newPorts,
            newlyAdvertisedServices = newServices,
            changedAttributes = changedAttributes,
            deviceBehaviorSignals = behaviorSignals,
            deviceBaselineObservations = observationsByDevice,
            deviceHistoricalRiskScore = historicalRiskByDevice,
            networkBehaviorSignals = networkSignals,
            networkBaselineObservations = nextNetworkObservations,
            historicalDeviceCount = historicalDeviceCount,
            historicalElevatedCount = historicalElevatedCount,
        )
    }

    fun markSnapshot(snapshot: NetworkDiscoverySnapshot, delta: NetworkDiscoveryDelta): NetworkDiscoverySnapshot {
        if (!integrityOk) return snapshot.copy(baselineIntegrityOk = false, baselineFailureReason = integrityReason)
        val marked = snapshot.devices.map { device ->
            val signals = delta.deviceBehaviorSignals[device.stableId].orEmpty()
            val observations = delta.deviceBaselineObservations[device.stableId] ?: 0
            device.copy(
                newToBaseline = device.stableId in delta.newDeviceIds,
                newlyExposedPorts = delta.newlyExposedPorts[device.stableId].orEmpty(),
                newlyAdvertisedServiceTypes = delta.newlyAdvertisedServices[device.stableId].orEmpty(),
                changedBaselineAttributes = delta.changedAttributes[device.stableId].orEmpty(),
                behaviorState = when {
                    signals.isNotEmpty() -> NetworkBehaviorState.ANOMALOUS
                    observations < LanBehaviorEvaluator.MIN_DEVICE_OBSERVATIONS -> NetworkBehaviorState.LEARNING
                    else -> NetworkBehaviorState.NORMAL
                },
                behaviorSignals = signals,
                baselineObservations = observations,
                historicalRiskScore = delta.deviceHistoricalRiskScore[device.stableId] ?: device.riskScore,
            )
        }
        return snapshot.copy(
            devices = marked,
            baselineIntegrityOk = true,
            baselineFailureReason = null,
            networkBehaviorSignals = delta.networkBehaviorSignals,
            networkBaselineObservations = delta.networkBaselineObservations,
            historicalDeviceCount = delta.historicalDeviceCount,
            historicalElevatedCount = delta.historicalElevatedCount,
        )
    }

    fun reset(): Boolean = synchronized(lock) {
        val previous = networks
        networks = linkedMapOf()
        integrityOk = true
        integrityReason = null
        if (persist()) true else {
            networks = previous
            degrade("network discovery baseline reset persist failed")
            false
        }
    }

    private fun load() = synchronized(lock) {
        val read = store.read()
        when (read.state) {
            AuthenticatedSnapshotState.ABSENT -> {
                networks = linkedMapOf()
                integrityOk = true
                integrityReason = null
                if (!persist()) degrade("network discovery baseline initialization failed")
            }
            AuthenticatedSnapshotState.INVALID -> {
                if (store.archiveAndClearReconstructibleStartupFailure(recoveryDir, betaRecoveryBoundaryMillis) != null) {
                    networks = linkedMapOf()
                    integrityOk = true
                    integrityReason = null
                    if (!persist()) degrade("network discovery continuity recovery initialization failed")
                } else degrade(read.reason ?: "network discovery baseline authentication failed")
            }
            AuthenticatedSnapshotState.VALID -> {
                val decoded = decode(read.payload ?: ByteArray(0))
                if (decoded == null) degrade("network discovery baseline payload invalid")
                else {
                    networks = decoded
                    integrityOk = true
                    integrityReason = null
                }
            }
        }
    }

    private fun persist(): Boolean = try {
        val payload = encode().toByteArray(StandardCharsets.UTF_8)
        if (payload.size > MAX_PAYLOAD_BYTES) false else {
            store.write(payload)
            true
        }
    } catch (_: Exception) {
        false
    }

    private fun encode(): String {
        val root = JSONObject().put("schema", PAYLOAD_SCHEMA)
        val networkArray = JSONArray()
        networks.values.sortedByDescending { it.lastSeenMillis }.take(MAX_NETWORKS).forEach { network ->
            val devices = JSONArray()
            network.devices.values.sortedByDescending { it.lastSeenMillis }.take(MAX_DEVICES_PER_NETWORK).forEach { device ->
                val pendingPorts = JSONObject()
                device.pendingPorts.toSortedMap().entries.take(MAX_PENDING_PORTS).forEach { (port, count) -> pendingPorts.put(port.toString(), count) }
                val pendingServices = JSONObject()
                device.pendingServices.toSortedMap().entries.take(MAX_PENDING_SERVICES).forEach { (service, count) -> pendingServices.put(service, count) }
                devices.put(JSONObject()
                    .put("id", device.stableId)
                    .put("identity", device.identitySource.name)
                    .put("first", device.firstSeenMillis)
                    .put("last", device.lastSeenMillis)
                    .put("ip", device.lastIp)
                    .put("mac", device.macAddress ?: JSONObject.NULL)
                    .put("host", device.hostname ?: JSONObject.NULL)
                    .put("role", device.role)
                    .put("ports", JSONArray(device.openPorts.sorted()))
                    .put("dnsSd", JSONArray(device.advertisedServiceTypes.sorted()))
                    .put("pendingPorts", pendingPorts)
                    .put("pendingDnsSd", pendingServices)
                    .put("observations", device.observations)
                    .put("riskEwma", device.riskEwma))
            }
            networkArray.put(JSONObject()
                .put("id", network.networkId)
                .put("last", network.lastSeenMillis)
                .put("observations", network.observations)
                .put("deviceCountEwma", network.deviceCountEwma)
                .put("elevatedCountEwma", network.elevatedCountEwma)
                .put("devices", devices))
        }
        root.put("networks", networkArray)
        return root.toString()
    }

    private fun decode(payload: ByteArray): LinkedHashMap<String, NetworkRecord>? = try {
        if (payload.isEmpty() || payload.size > MAX_PAYLOAD_BYTES) null else {
            val root = JSONObject(String(payload, StandardCharsets.UTF_8))
            val schema = root.optInt("schema", -1)
            if (schema !in 1..PAYLOAD_SCHEMA) null else {
                val out = linkedMapOf<String, NetworkRecord>()
                val nets = root.optJSONArray("networks") ?: JSONArray()
                val netCount = minOf(nets.length(), MAX_NETWORKS)
                for (i in 0 until netCount) {
                    val n = nets.optJSONObject(i) ?: continue
                    val id = n.optString("id").take(MAX_ID_CHARS)
                    if (id.isBlank()) continue
                    val devs = linkedMapOf<String, DeviceRecord>()
                    val array = n.optJSONArray("devices") ?: JSONArray()
                    val deviceCount = minOf(array.length(), MAX_DEVICES_PER_NETWORK)
                    for (j in 0 until deviceCount) {
                        val d = array.optJSONObject(j) ?: continue
                        val stableId = d.optString("id").take(MAX_ID_CHARS)
                        val ip = d.optString("ip").take(64)
                        if (stableId.isBlank() || ip.isBlank()) continue
                        val ports = linkedSetOf<Int>()
                        val pa = d.optJSONArray("ports") ?: JSONArray()
                        for (k in 0 until minOf(pa.length(), MAX_PORTS_PER_DEVICE)) pa.optInt(k, -1).takeIf { it in 1..65535 }?.let(ports::add)
                        val services = linkedSetOf<String>()
                        val sa = d.optJSONArray("dnsSd") ?: JSONArray()
                        for (k in 0 until minOf(sa.length(), MAX_SERVICES_PER_DEVICE)) sa.optString(k).lowercase().takeIf(::isSafeServiceType)?.let(services::add)
                        val pendingPorts = linkedMapOf<Int, Int>()
                        if (schema >= 3) {
                            val po = d.optJSONObject("pendingPorts") ?: JSONObject()
                            val keys = po.keys()
                            while (keys.hasNext() && pendingPorts.size < MAX_PENDING_PORTS) {
                                val key = keys.next()
                                val port = key.toIntOrNull() ?: continue
                                val count = po.optInt(key, 0)
                                if (port in 1..65535 && count in 1 until PROMOTION_OBSERVATIONS) pendingPorts[port] = count
                            }
                        }
                        val pendingServices = linkedMapOf<String, Int>()
                        if (schema >= 3) {
                            val so = d.optJSONObject("pendingDnsSd") ?: JSONObject()
                            val keys = so.keys()
                            while (keys.hasNext() && pendingServices.size < MAX_PENDING_SERVICES) {
                                val service = keys.next().lowercase()
                                val count = so.optInt(service, 0)
                                if (isSafeServiceType(service) && count in 1 until PROMOTION_OBSERVATIONS) pendingServices[service] = count
                            }
                        }
                        val identity = if (schema >= 2) {
                            try { NetworkIdentitySource.valueOf(d.optString("identity", "IP")) } catch (_: IllegalArgumentException) { NetworkIdentitySource.IP }
                        } else if (d.optString("mac").takeIf { it.isNotBlank() && it != "null" } != null) NetworkIdentitySource.MAC else NetworkIdentitySource.IP
                        devs[stableId] = DeviceRecord(
                            stableId = stableId,
                            identitySource = identity,
                            firstSeenMillis = d.optLong("first", 0L).coerceAtLeast(0L),
                            lastSeenMillis = d.optLong("last", 0L).coerceAtLeast(0L),
                            lastIp = ip,
                            macAddress = d.optString("mac").takeIf { it.isNotBlank() && it != "null" }?.take(32),
                            hostname = d.optString("host").takeIf { it.isNotBlank() && it != "null" }?.take(MAX_HOST_CHARS),
                            role = d.optString("role", "NETWORK_DEVICE").take(80),
                            openPorts = ports,
                            advertisedServiceTypes = services,
                            pendingPorts = pendingPorts,
                            pendingServices = pendingServices,
                            observations = if (schema >= 3) d.optInt("observations", 0).coerceIn(0, MAX_OBSERVATIONS) else 1,
                            riskEwma = if (schema >= 3) d.optInt("riskEwma", 0).coerceIn(0, 100) else 0,
                        )
                    }
                    val observations = if (schema >= 3) n.optInt("observations", 0).coerceIn(0, MAX_OBSERVATIONS) else 1
                    out[id] = NetworkRecord(
                        networkId = id,
                        lastSeenMillis = n.optLong("last", 0L).coerceAtLeast(0L),
                        devices = devs,
                        observations = observations,
                        deviceCountEwma = if (schema >= 3) n.optInt("deviceCountEwma", devs.size).coerceIn(0, MAX_DEVICES_PER_NETWORK) else devs.size,
                        elevatedCountEwma = if (schema >= 3) n.optInt("elevatedCountEwma", 0).coerceIn(0, MAX_DEVICES_PER_NETWORK) else 0,
                    )
                }
                out
            }
        }
    } catch (_: Exception) {
        null
    }

    private fun deepCopy(input: LinkedHashMap<String, NetworkRecord>): LinkedHashMap<String, NetworkRecord> =
        input.values.associateByTo(linkedMapOf()) { network -> network.networkId }
            .mapValuesTo(linkedMapOf()) { (_, network) -> network.copy(devices = LinkedHashMap(network.devices)) }

    private fun degrade(reason: String) {
        integrityOk = false
        integrityReason = reason.take(180)
    }

    private fun isSafeServiceType(value: String): Boolean = value.length in 7..160 && SERVICE_TYPE.matches(value)

    companion object {
        private const val PAYLOAD_SCHEMA = 3
        private const val MAX_PAYLOAD_BYTES = 640 * 1024
        private const val MAX_NETWORKS = 8
        private const val MAX_DEVICES_PER_NETWORK = 512
        private const val MAX_PORTS_PER_DEVICE = 32
        private const val MAX_SERVICES_PER_DEVICE = 32
        private const val MAX_PENDING_PORTS = 24
        private const val MAX_PENDING_SERVICES = 24
        private const val MAX_ID_CHARS = 160
        private const val MAX_HOST_CHARS = 160
        private const val MAX_OBSERVATIONS = 10_000
        private const val PROMOTION_OBSERVATIONS = 2
        private val SERVICE_TYPE = Regex("^_[a-z0-9-]{1,32}\\._(?:tcp|udp)\\.local$")
    }
}
