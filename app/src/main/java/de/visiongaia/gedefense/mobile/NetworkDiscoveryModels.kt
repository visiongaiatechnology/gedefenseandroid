package de.visiongaia.gedefense.mobile

enum class NetworkDeviceRisk { INFO, REVIEW, HIGH, CRITICAL }
enum class NetworkIdentitySource { MAC, MDNS_HOST, IP }
enum class NetworkBehaviorState { LEARNING, NORMAL, ANOMALOUS }

data class NetworkServiceExposure(
    val port: Int,
    val name: String,
    val risk: NetworkDeviceRisk,
)

data class NetworkDnsSdService(
    val serviceType: String,
    val instanceName: String,
    val targetHost: String?,
    val port: Int?,
    val txtKeys: Set<String> = emptySet(),
) {
    val baselineKey: String
        get() = serviceType.lowercase()
}

data class NetworkDevice(
    val stableId: String,
    val identitySource: NetworkIdentitySource,
    val ipAddress: String,
    val macAddress: String?,
    val hostname: String?,
    val role: String,
    val openServices: List<NetworkServiceExposure>,
    val advertisedServices: List<NetworkDnsSdService>,
    val riskScore: Int,
    val risk: NetworkDeviceRisk,
    val isGateway: Boolean,
    val isThisDevice: Boolean,
    val newToBaseline: Boolean = false,
    val newlyExposedPorts: Set<Int> = emptySet(),
    val newlyAdvertisedServiceTypes: Set<String> = emptySet(),
    val changedBaselineAttributes: Set<String> = emptySet(),
    val behaviorState: NetworkBehaviorState = NetworkBehaviorState.LEARNING,
    val behaviorSignals: Set<String> = emptySet(),
    val baselineObservations: Int = 0,
    val historicalRiskScore: Int = 0,
)

data class NetworkDiscoveryProgress(
    val scannedHosts: Int,
    val totalHosts: Int,
    val discoveredDevices: Int,
    val currentAddress: String,
) {
    val fraction: Float get() = if (totalHosts <= 0) 0f else (scannedHosts.toFloat() / totalHosts.toFloat()).coerceIn(0f, 1f)
}

data class NetworkDiscoverySnapshot(
    val state: String,
    val startedAtMillis: Long,
    val completedAtMillis: Long,
    val networkId: String,
    val transport: String,
    val interfaceName: String,
    val localAddress: String,
    val prefixLength: Int,
    val effectivePrefixLength: Int,
    val gatewayAddress: String?,
    val scopeClamped: Boolean,
    val scannedHosts: Int,
    val totalHosts: Int,
    val devices: List<NetworkDevice>,
    val baselineIntegrityOk: Boolean,
    val baselineFailureReason: String?,
    val errorReason: String?,
    val networkBehaviorSignals: Set<String> = emptySet(),
    val networkBaselineObservations: Int = 0,
    val historicalDeviceCount: Int = 0,
    val historicalElevatedCount: Int = 0,
) {
    val newDevices: Int get() = devices.count { it.newToBaseline }
    val elevatedDevices: Int get() = devices.count { it.risk == NetworkDeviceRisk.HIGH || it.risk == NetworkDeviceRisk.CRITICAL }
    val dnsSdServices: Int get() = devices.sumOf { it.advertisedServices.size }
    val anomalousDevices: Int get() = devices.count { it.behaviorState == NetworkBehaviorState.ANOMALOUS }

    companion object {
        fun idle() = NetworkDiscoverySnapshot(
            state = "IDLE",
            startedAtMillis = 0L,
            completedAtMillis = 0L,
            networkId = "",
            transport = "",
            interfaceName = "",
            localAddress = "",
            prefixLength = 0,
            effectivePrefixLength = 0,
            gatewayAddress = null,
            scopeClamped = false,
            scannedHosts = 0,
            totalHosts = 0,
            devices = emptyList(),
            baselineIntegrityOk = true,
            baselineFailureReason = null,
            errorReason = null,
        )
    }
}
