package de.visiongaia.gedefense.mobile

import de.visiongaia.gedefense.mobile.core.EnforcementClass

data class FeedUiSnapshot(
    val id: String,
    val name: String,
    val enforcement: EnforcementClass,
    val available: Boolean,
    val fresh: Boolean,
    val records: Int,
    val fetchedAtMillis: Long,
)

data class UiSnapshot(
    val vpnStatus: String,
    val vpnReason: String?,
    val vpnActive: Boolean,
    val indexedPrefixes: Int,
    val routeCandidates: Int,
    val compactedRoutes: Int,
    val routeOverflow: Boolean,
    val routePolicySha256: String,
    val fullPolicySha256: String,
    val lastFeedSync: Long,
    val blockedPackets: Long,
    val blockedBytes: Long,
    val uniqueDestinations: Int,
    val attributedApps: Int,
    val activeFlows: Int,
    val lastBlockedAtMillis: Long,
    val evidenceOk: Boolean,
    val evidenceRecords: Long,
    val evidenceReason: String?,
    val evidenceInvalidLine: Long?,
    val feeds: List<FeedUiSnapshot>,
    val integrity: IntegritySnapshot,
    val appScan: AppScanSnapshot,
    val deviceScan: DeviceScanSnapshot,
    val traffic: TrafficUsageSnapshot,
    val usageAccessGranted: Boolean,
    val protectionMode: ProtectionMode,
    val wireGuardEgressMode: WireGuardEgressMode,
    val wireGuard: WireGuardProfileStatus,
    val nativeFullFlowAvailable: Boolean,
    val fullFlow: FullFlowAnalyticsSnapshot,
    val geoCountry: GeoCountryState,
    val originLocation: OriginLocationSnapshot,
    val hardening: HardeningSnapshot,
    val titan: TitanSnapshot,
    val setup: DeviceSetupSnapshot,
    val xdr: XdrSnapshot,
    val resilienceDesired: Boolean,
    val platformAlwaysOn: Boolean,
    val platformLockdown: Boolean,
    val platformPolicyObservedAtMillis: Long,
    val transportPowerConstrained: Boolean,
    val vpnRecoveryCount: Long,
    val lastVpnRecoveryAtMillis: Long,
    val lastVpnRecoveryReason: String?,
    val resilienceSelfTestStatus: String?,
    val resilienceSelfTestAtMillis: Long,
    val resilienceSelfTestDurationMillis: Long,
) {
    val healthyFeeds: Int get() = feeds.count { it.available && it.fresh }
    val routeBlockFeeds: Int get() = feeds.count { it.enforcement == EnforcementClass.ROUTE_BLOCK }
    val alwaysOnConfigured: Boolean get() = titan.alwaysOnVpn || platformAlwaysOn
    val killSwitchConfigured: Boolean get() = titan.alwaysOnLockdown || platformLockdown
}

interface UiActions {
    fun activateProtection()
    fun deactivateProtection()
    fun synchronizeFeeds()
    fun verifyEvidence()
    fun recoverEvidence()
    fun verifyIntegrity()
    fun scanInstalledApps()
    fun openMalwareScanner()
    fun openSetupWizard()
    fun openNetworkFirewall()
    fun openWireGuard()
    fun openXdrCenter()
    fun openXdrForPackage(packageName: String)
    fun openHardeningCenter()
    fun openNetworkDiscovery()
    fun openPortSentinel()
    fun openTitan()
    fun openBehaviorCenter()
    fun configureAlwaysOnProtection()
    fun runResilienceSelfTest()
    fun refreshTrafficUsage()
    fun openUsageAccessSettings()
    fun requestTrafficMapLocation()
    fun setProtectionMode(mode: ProtectionMode)
    fun navigateTo(index: Int)
}
