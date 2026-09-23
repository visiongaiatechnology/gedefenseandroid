package de.visiongaia.gedefense.mobile

import android.content.Context
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

// STATUS: DIAMANT VGT SUPREME
/**
 * Privacy-bounded diagnostic export.
 *
 * Deliberately exports aggregate state only. Package names, domains, IP addresses, file paths,
 * certificate hashes, APK hashes, evidence payloads and incident detail strings are excluded.
 */
class DiagnosticBundleBuilder(
    context: Context,
    private val runtime: AppRuntime,
) {
    private val appContext = context.applicationContext

    fun writeTo(output: OutputStream) {
        val summary = buildSummary().toString(2).toByteArray(Charsets.UTF_8)
        val summarySha256 = sha256(summary)
        val manifest = JSONObject()
            .put("schema", SCHEMA_VERSION)
            .put("created_at", System.currentTimeMillis())
            .put("summary_sha256", summarySha256)
            .put("privacy_profile", "aggregate-only-v1")
            .toString(2)
            .toByteArray(Charsets.UTF_8)

        ZipOutputStream(output.buffered()).use { zip ->
            zip.setLevel(6)
            putEntry(zip, "summary.json", summary)
            putEntry(zip, "manifest.json", manifest)
            putEntry(zip, "README.txt", README.toByteArray(Charsets.UTF_8))
        }
    }

    fun buildSummary(): JSONObject {
        val state = runtime.state
        val integrity = runtime.integritySnapshot.get()
        val appScan = runtime.appScanSnapshot.get()
        val metrics = runtime.metrics.snapshot()
        val fullFlow = runtime.fullFlowAnalytics.snapshot()
        val xdr = runtime.xdr.snapshot()
        val hardening = runtime.hardeningSnapshot.get()
        val titan = runtime.titan.snapshot()
        val setup = runtime.setup.snapshot()
        val feeds = runtime.feedHealth.get()
        val sentinel = runtime.portSentinelSnapshot()
        val analysisIntegrityOk = runtime.malwareAnalysisStore.integrityOk()
        val vaultStatuses = SecureTelemetryVault.activeStatuses()
        val initializedVaultKeys = vaultStatuses.filter { it.initialized }
        val selfHealing = runtime.resilienceSupervisor.latestReport()

        val appVersion = runCatching {
            @Suppress("DEPRECATION")
            appContext.packageManager.getPackageInfo(appContext.packageName, 0).versionName ?: "unknown"
        }.getOrDefault("unknown")
        val versionCode = runCatching {
            @Suppress("DEPRECATION")
            appContext.packageManager.getPackageInfo(appContext.packageName, 0).longVersionCode
        }.getOrDefault(0L)

        val severityCounts = JSONObject()
        XdrSeverity.entries.forEach { severity ->
            severityCounts.put(severity.name.lowercase(), xdr.incidents.count { it.severity == severity })
        }
        val categoryCounts = JSONObject()
        XdrCategory.entries.forEach { category ->
            categoryCounts.put(category.name.lowercase(), xdr.events.count { it.category == category })
        }
        val vpnDisclosure = runtime.vpnDisclosure.snapshot()

        return JSONObject()
            .put("schema", SCHEMA_VERSION)
            .put("created_at", System.currentTimeMillis())
            .put("app", JSONObject()
                .put("version_name", appVersion.take(64))
                .put("version_code", versionCode)
                .put("build_type", if (isDebuggable()) "debug" else "release"))
            .put("platform", JSONObject()
                .put("android_sdk", Build.VERSION.SDK_INT)
                .put("android_release", Build.VERSION.RELEASE.take(32))
                .put("manufacturer", Build.MANUFACTURER.take(64)))
            .put("vpn", JSONObject()
                .put("active", state.isVpnActive())
                .put("status", safeCode(state.lastVpnStatus()))
                .put("reason", safeCode(state.lastVpnReason()))
                .put("mode", state.protectionMode().name)
                .put("resilience_desired", state.resilienceDesired())
                .put("platform_always_on", state.platformAlwaysOn())
                .put("platform_lockdown", state.platformLockdown())
                .put("power_constrained", state.transportPowerConstrained())
                .put("recovery_count", state.vpnRecoveryCount())
                .put("last_recovery_at", state.lastVpnRecoveryAtMillis())
                .put("last_recovery_reason", safeCode(state.lastVpnRecoveryReason()))
                .put("self_test_status", safeCode(state.lastResilienceSelfTestStatus()))
                .put("self_test_at", state.lastResilienceSelfTestAtMillis())
                .put("self_test_duration_ms", state.lastResilienceSelfTestDurationMillis())
                .put("disclosure_accepted", vpnDisclosure.accepted)
                .put("disclosure_integrity_ok", vpnDisclosure.integrityOk)
                .put("disclosure_failure", safeCode(vpnDisclosure.failureReason))
                .put("evidence_health_ok", runtime.evidenceHealth.ok)
                .put("evidence_health_records", runtime.evidenceHealth.records)
                .put("evidence_health_reason", safeCode(runtime.evidenceHealth.reason))
                .put("evidence_persistence_failures", state.evidencePersistenceFailureCount())
                .put("evidence_persistence_last_failure", safeCode(state.lastEvidencePersistenceFailure()))
                .put("evidence_persistence_last_failure_at", state.lastEvidencePersistenceFailureAtMillis())
                .put("xdr_persistence_failures", state.xdrPersistenceFailureCount())
                .put("xdr_persistence_last_failure", safeCode(state.lastXdrPersistenceFailure()))
                .put("xdr_persistence_last_failure_at", state.lastXdrPersistenceFailureAtMillis()))
            .put("gaianet", JSONObject()
                .put("available", NativeGaiaNet.available)
                .put("last_start_failure", safeCode(NativeGaiaNet.lastStartFailure))
                .put("analytics_state", safeCode(fullFlow.state))
                .put("active_flows", fullFlow.activeFlows)
                .put("transport_errors", fullFlow.transportErrors)
                .put("blocked_flows", fullFlow.blockedFlows)
                .put("correlated_flows", fullFlow.correlatedFlows)
                .put("annotated_flows", fullFlow.annotatedFlows)
                .put("tx_bytes", fullFlow.txBytes)
                .put("rx_bytes", fullFlow.rxBytes))
            .put("self_healing", JSONObject()
                .put("available", selfHealing != null)
                .put("last_run_at", selfHealing?.atMillis ?: 0L)
                .put("trigger", safeCode(selfHealing?.trigger))
                .put("healthy", selfHealing?.healthy ?: false)
                .put("repairs", selfHealing?.repairs ?: 0)
                .put("unresolved", selfHealing?.unresolved ?: 0)
                .put("skipped", selfHealing?.skipped ?: false)
                .put("findings", JSONArray(selfHealing?.findings?.take(16)?.map { finding ->
                    JSONObject()
                        .put("component", safeCode(finding.component))
                        .put("state", safeCode(finding.state))
                        .put("action", safeCode(finding.action))
                        .put("disposition", finding.disposition.name.lowercase())
                        .put("repaired", finding.repaired)
                } ?: emptyList<JSONObject>())))
            .put("protection_metrics", JSONObject()
                .put("blocked_packets", metrics.blockedPackets)
                .put("blocked_bytes", metrics.blockedBytes)
                .put("unique_destinations", metrics.uniqueDestinations)
                .put("attributed_apps", metrics.attributedApps)
                .put("unresolved_owners", metrics.unresolvedOwners)
                .put("active_flows", metrics.activeFlows))
            .put("integrity", JSONObject()
                .put("state", safeCode(integrity.state))
                .put("checked_at", integrity.checkedAtMillis)
                .put("files_checked", integrity.filesChecked)
                .put("issue_codes", JSONArray(integrity.issues.map { safeCode(it.code) }.distinct().take(32))))
            .put("scanner", JSONObject()
                .put("state", safeCode(appScan.state))
                .put("scanned_at", appScan.scannedAtMillis)
                .put("packages", appScan.scannedPackages)
                .put("user_packages", appScan.userPackages)
                .put("deep_scanned", appScan.deepScannedPackages)
                .put("review_or_higher", appScan.highRiskPackages)
                .put("threat_matched", appScan.threatMatchedPackages)
                .put("analysis_store_integrity_ok", analysisIntegrityOk)
                .put("analysis_store_failure", safeCode(runtime.malwareAnalysisStore.integrityFailureReason()))
                .put("timings", JSONObject()
                    .put("elapsed_ms", appScan.metrics.elapsedMs)
                    .put("package_query_ms", appScan.metrics.packageQueryMs)
                    .put("metadata_ms", appScan.metrics.metadataMs)
                    .put("static_ms", appScan.metrics.staticAnalysisMs)
                    .put("hashing_ms", appScan.metrics.hashingMs)
                    .put("correlation_ms", appScan.metrics.correlationMs)
                    .put("cache_hits", appScan.metrics.cacheHits)
                    .put("cache_misses", appScan.metrics.cacheMisses)
                    .put("bytes_static", appScan.metrics.bytesStaticScanned)
                    .put("bytes_hashed", appScan.metrics.bytesHashed)))
            .put("secure_telemetry_vault", JSONObject()
                .put("cipher", "AES-256-GCM")
                .put("independent_integrity", "HMAC-SHA-256")
                .put("domain_keys_total", vaultStatuses.size)
                .put("initialized_domain_keys", initializedVaultKeys.size)
                .put("strongbox_keys", initializedVaultKeys.count { it.securityLevel == AndroidSecrets.KeySecurityLevel.STRONGBOX })
                .put("tee_keys", initializedVaultKeys.count { it.securityLevel == AndroidSecrets.KeySecurityLevel.TRUSTED_ENVIRONMENT })
                .put("other_hardware_keys", initializedVaultKeys.count { it.securityLevel == AndroidSecrets.KeySecurityLevel.HARDWARE })
                .put("software_keys", initializedVaultKeys.count { it.securityLevel == AndroidSecrets.KeySecurityLevel.SOFTWARE })
                .put("unknown_key_security", initializedVaultKeys.count { it.securityLevel == AndroidSecrets.KeySecurityLevel.UNKNOWN })
                .put("evidence_records", "encrypted-v3")
                .put("rotation", "versioned-reencrypt-on-read")
                .put("backup", "disabled")
                .put("ml_dsa_87_hardware_available", HybridArtifactSigner.hardwareMlDsaAvailable(appContext)))
            .put("threat_intelligence", JSONObject()
                .put("indexed_prefixes", runtime.threatIndex.get().count)
                .put("feeds_total", feeds.size)
                .put("feeds_available", feeds.count { it.available })
                .put("feeds_fresh", feeds.count { it.available && it.fresh })
                .put("last_sync", state.lastFeedSync()))
            .put("xdr", JSONObject()
                .put("events", xdr.events.size)
                .put("incidents", xdr.incidents.size)
                .put("severity_counts", severityCounts)
                .put("category_counts", categoryCounts)
                .put("quarantined_packages", xdr.quarantinedPackages.size)
                .put("event_store_integrity_ok", xdr.eventStoreIntegrityOk)
                .put("package_baseline_integrity_ok", xdr.packageBaselineIntegrityOk)
                .put("firewall_policy_integrity_ok", xdr.firewallPolicyIntegrityOk)
                .put("network_discovery_integrity_ok", xdr.networkDiscoveryIntegrityOk)
                .put("port_sentinel_integrity_ok", xdr.portSentinelIntegrityOk)
                .put("titan_policy_integrity_ok", xdr.titanPolicyIntegrityOk)
                .put("trust_stores_healthy", xdr.trustStoresHealthy))
            .put("hardening", JSONObject()
                .put("checked_at", hardening.checkedAtMillis)
                .put("score", hardening.score)
                .put("passed", hardening.passed)
                .put("review", hardening.review)
                .put("failed", hardening.failed)
                .put("critical", hardening.critical))
            .put("titan", JSONObject()
                .put("tier", titan.tier.name)
                .put("admin_active", titan.adminActive)
                .put("device_owner", titan.isDeviceOwner)
                .put("policy_store_integrity_ok", titan.policyStoreIntegrityOk)
                .put("always_on_vpn", titan.alwaysOnVpn)
                .put("lockdown", titan.alwaysOnLockdown))
            .put("setup", JSONObject()
                .put("battery_exempt", setup.batteryExempt)
                .put("background_restricted", setup.batteryBackgroundRestricted)
                .put("battery_ready", setup.batteryReady)
                .put("notifications", setup.notificationsAllowed)
                .put("usage_access", setup.usageAccess)
                .put("all_files_access", setup.allFilesAccess)
                .put("device_admin", setup.deviceAdminActive)
                .put("device_owner", setup.deviceOwnerActive))
            .put("network_sentinel", JSONObject()
                .put("active", sentinel.runtime.active)
                .put("transport", safeCode(sentinel.runtime.transport))
                .put("listeners", sentinel.runtime.listenerCount)
                .put("hits", sentinel.hits.size)
                .put("critical_hits", sentinel.criticalHits)
                .put("unique_sources", sentinel.uniqueSources)
                .put("blocked_sources", sentinel.blockedSources.size)
                .put("integrity_ok", sentinel.integrityOk)
                .put("last_error", safeCode(sentinel.runtime.lastError)))
    }

    private fun isDebuggable(): Boolean = (appContext.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0

    private fun safeCode(value: String?): String? {
        val normalized = value?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: return null
        return if (SAFE_CODE.matches(normalized)) normalized.take(120) else "redacted"
    }

    private fun putEntry(zip: ZipOutputStream, name: String, bytes: ByteArray) {
        require(name in ALLOWED_ENTRIES)
        val entry = ZipEntry(name).apply { time = 0L }
        zip.putNextEntry(entry)
        zip.write(bytes)
        zip.closeEntry()
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    companion object {
        private const val SCHEMA_VERSION = 1
        private val SAFE_CODE = Regex("[a-z][a-z0-9_-]{0,119}")
        private val ALLOWED_ENTRIES = setOf("summary.json", "manifest.json", "README.txt")
        private const val README = """GeDefense Mobile diagnostic bundle

This export uses the aggregate-only-v1 privacy profile.
It intentionally excludes package names, application labels, IP addresses, domains, file paths,
certificate/APK hashes, evidence payloads and XDR incident details.

The bundle is created only after an explicit user export action and is never uploaded automatically.
"""
    }
}
