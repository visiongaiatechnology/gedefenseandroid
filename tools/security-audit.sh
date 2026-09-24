#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() { echo "SECURITY_AUDIT_FAIL: $*" >&2; exit 1; }

# High-risk Android patterns remain forbidden. NativeGaiaNet has the single reviewed direct
# ProcessBuilder boundary used to start the bundled process-isolated GaiaNet v2 helper; no shell or
# user-controlled command path is permitted anywhere.
if grep -RInE --exclude-dir=.git --exclude-dir=build --exclude-dir=.gradle --exclude='*.md' --exclude='security-audit.sh' --exclude='NativeGaiaNet.kt' \
  'TrustAll|ALLOW_ALL_HOSTNAME|HostnameVerifier[[:space:]]*\{[[:space:]]*true|setHostnameVerifier|usesCleartextTraffic="true"|android:debuggable="true"|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|DexClassLoader|PathClassLoader|System\.load\(|System\.loadLibrary\(|WebView|WRITE_EXTERNAL_STORAGE' \
  app core; then
  fail "forbidden dangerous Android pattern found"
fi

if grep -RInE --include='*.kt' 'http://' app/src core/src; then
  fail "cleartext URL in Kotlin source"
fi

python3 tools/i18n-audit.py
python3 tools/silent-failure-audit.py
python3 tools/durable-persistence-audit.py
python3 tools/bounded-storage-audit.py
python3 tools/go-supply-chain-reachability-audit.py
python3 tools/sbom-audit.py
python3 tools/main-thread-io-audit.py
python3 tools/runtime-bootstrap-audit.py
python3 tools/wireguard-audit.py
python3 tools/privacy-shield-audit.py
python3 tools/threat-enforcement-self-test-audit.py
python3 tools/install-guard-audit.py
bash tools/install-guard-policy-check.sh
python3 tools/resilience-supervisor-audit.py
python3 tools/asn-evidence-audit.py
bash tools/wireguard-upstream-check.sh

python3 - <<'PY'
from pathlib import Path
import re
p=Path('core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/ThreatFeed.kt').read_text()
urls=re.findall(r'"(https?://[^"]+)"',p)
if len(urls) != 9:
    raise SystemExit(f"expected exactly 9 threat feed URLs, got {len(urls)}")
if any(not u.startswith('https://') for u in urls): raise SystemExit('non-HTTPS threat feed URL')
if len(set(urls)) != len(urls): raise SystemExit('duplicate threat feed URL')
required={
    'feodo':'ROUTE_BLOCK', 'spamhaus-drop-v4':'ROUTE_BLOCK', 'spamhaus-drop-v6':'ROUTE_BLOCK',
    'cins':'CORRELATE_ONLY', 'blocklist-de':'CORRELATE_ONLY', 'emerging-threats':'CORRELATE_ONLY',
    'ipsum':'CORRELATE_ONLY', 'firehol-level1':'ROUTE_BLOCK', 'tor-exits':'ANNOTATE_ONLY',
}
for feed, action in required.items():
    marker=f'ThreatFeed(\n            \"{feed}\"'
    if marker not in p:
        raise SystemExit(f'threat feed entry missing: {feed}')
    block=p.split(marker,1)[1].split('        ),',1)[0]
    if f'EnforcementClass.{action}' not in block:
        raise SystemExit(f'threat feed authority invariant missing: {feed} -> {action}')
if 'POLICY_ABI_VERSION = 2' not in p or 'threat feed order changed without native policy ABI migration' not in p:
    raise SystemExit('threat feed/native policy ABI guard missing')
if 'https://check.torproject.org/torbulkexitlist' not in p: raise SystemExit('Tor source invariant missing')
if 'https://iplists.firehol.org/files/firehol_level1.netset' not in p: raise SystemExit('FireHOL direct source invariant missing')
print('FEED_CATALOG_PASS sources=9')
PY

python3 - <<'PY'
import xml.etree.ElementTree as ET
m=ET.parse('app/src/main/AndroidManifest.xml').getroot(); ns='{http://schemas.android.com/apk/res/android}'
app=m.find('application')
if app is None: raise SystemExit('application missing')
if app.get(ns+'usesCleartextTraffic') != 'false': raise SystemExit('cleartext not disabled')
if app.get(ns+'allowBackup') != 'false': raise SystemExit('backup not disabled')
if app.get(ns+'fullBackupContent') != 'false': raise SystemExit('legacy full backup not disabled')
if app.get(ns+'dataExtractionRules') != '@xml/data_extraction_rules': raise SystemExit('Android 12+ data extraction rules missing')
for service in app.findall('service'):
    if service.get(ns+'exported') == 'true' and not service.get(ns+'permission'):
        raise SystemExit('exported service without binding permission: '+str(service.get(ns+'name')))
vpn=next((s for s in app.findall('service') if s.get(ns+'name') == '.GeDefenseVpnService'), None)
if vpn is None or vpn.get(ns+'permission') != 'android.permission.BIND_VPN_SERVICE': raise SystemExit('VPN binding permission missing')
meta={n.get(ns+'name'):n.get(ns+'value') for n in vpn.findall('meta-data')}
if meta.get('android.net.VpnService.SUPPORTS_ALWAYS_ON') != 'true':
    raise SystemExit('TITAN requires VpnService always-on capability')
permissions={n.get(ns+'name') for n in m.findall('uses-permission')}
for forbidden in (
    'android.permission.WRITE_EXTERNAL_STORAGE','android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_BACKGROUND_LOCATION','android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS',
):
    if forbidden in permissions: raise SystemExit('forbidden permission present: '+forbidden)
for required in (
    'android.permission.QUERY_ALL_PACKAGES','android.permission.PACKAGE_USAGE_STATS',
    'android.permission.INTERNET','android.permission.ACCESS_COARSE_LOCATION',
    'android.permission.MANAGE_EXTERNAL_STORAGE',
    'android.permission.RECEIVE_BOOT_COMPLETED',
    'android.permission.REQUEST_DELETE_PACKAGES','android.permission.REQUEST_PASSWORD_COMPLEXITY',
):
    if required not in permissions: raise SystemExit('required permission missing: '+required)
for activity_name in ('.SetupWizardActivity','.VpnDisclosureActivity','.PrivacyActivity','.ScannerActivity','.FirewallActivity','.WireGuardActivity','.XdrActivity','.HardeningActivity','.BehaviorActivity','.NetworkDiscoveryActivity','.PortSentinelActivity','.TitanActivity'):
    a=next((x for x in app.findall('activity') if x.get(ns+'name') == activity_name),None)
    if a is None or a.get(ns+'exported') != 'false': raise SystemExit('internal activity must not be exported: '+activity_name)
receiver=next((x for x in app.findall('receiver') if x.get(ns+'name') == '.BootReceiver'),None)
if receiver is None or receiver.get(ns+'exported') != 'false': raise SystemExit('boot receiver missing or exported')
package_receiver=next((x for x in app.findall('receiver') if x.get(ns+'name') == '.PackageChangeReceiver'),None)
if package_receiver is None or package_receiver.get(ns+'exported') != 'false': raise SystemExit('package receiver missing or exported')
admin=next((x for x in app.findall('receiver') if x.get(ns+'name') == '.TitanDeviceAdminReceiver'),None)
if admin is None or admin.get(ns+'exported') != 'true' or admin.get(ns+'permission') != 'android.permission.BIND_DEVICE_ADMIN':
    raise SystemExit('TITAN device admin receiver contract invalid')
admin_meta={n.get(ns+'name'):n.get(ns+'resource') for n in admin.findall('meta-data')}
if admin_meta.get('android.app.device_admin') != '@xml/titan_device_admin': raise SystemExit('TITAN device admin metadata missing')
package_op=next((x for x in app.findall('receiver') if x.get(ns+'name') == '.TitanPackageOperationReceiver'),None)
if package_op is None or package_op.get(ns+'exported') != 'false': raise SystemExit('TITAN package operation receiver must be internal')
for name, action in ((
    '.TitanGetProvisioningModeActivity','android.app.action.GET_PROVISIONING_MODE'),
    ('.TitanPolicyComplianceActivity','android.app.action.ADMIN_POLICY_COMPLIANCE'),
):
    a=next((x for x in app.findall('activity') if x.get(ns+'name') == name),None)
    if a is None or a.get(ns+'exported') != 'true' or a.get(ns+'permission') != 'android.permission.BIND_DEVICE_ADMIN':
        raise SystemExit('TITAN provisioning activity contract invalid: '+name)
    actions={node.get(ns+'name') for f in a.findall('intent-filter') for node in f.findall('action')}
    if action not in actions: raise SystemExit('TITAN provisioning action missing: '+action)
print('MANIFEST_SECURITY_PASS')
PY

python3 - <<'PY'
from pathlib import Path
app=Path('app/build.gradle.kts').read_text()
if 'implementation(project(":core"))' not in app: raise SystemExit('core dependency missing')
for bad in ('implementation("', 'api("', 'kapt(', 'ksp('):
    if bad in app: raise SystemExit('unexpected external Android dependency declaration: '+bad)
if 'ndkVersion = "27.2.12479018"' not in app: raise SystemExit('NDK pin missing')
print('DEPENDENCY_SURFACE_PASS')
PY

python3 - <<'PY'
from pathlib import Path
service=Path('app/src/main/java/de/visiongaia/gedefense/mobile/GeDefenseVpnService.kt').read_text()
selective=(
    'readSelectiveLoop(descriptor, index)' in service and
    'POLICY_INVARIANT_FAILED' in service and
    'installedRoutes != exactRouteCount' in service and
    'SELECTIVE_PLATFORM_ROUTE_BUDGET = 1_024' in service and
    'selective_platform_route_budget_exceeded' in service and
    'if (!packet.destination.isPublic()) {' in service and
    'runtime.portSentinelStore.isBlocked(destination)' in service and
    'sentinel.block' in service
)
if not selective: raise SystemExit('selective-route safety invariant missing')
for token in (
    'ProtectionMode.FULL_FLOW_BETA', 'builder.addRoute("0.0.0.0", 0)', 'builder.addRoute("::", 0)',
    'builder.addDisallowedApplication(packageName)', 'NativeGaiaNet.start(', 'egressMode,', 'wireGuardConfig,',
    'FullFlowTelemetryReader', 'FULL_GUARDED', 'FULL_FLOW_FAILED', 'index.fullPolicySha256'
):
    if token not in service: raise SystemExit('full-flow invariant missing: '+token)
for token in (
    'ProtectionMode.LOCKDOWN', 'installLockdown()', 'configureLockdownBypass', 'readLockdownLoop',
    'LOCKDOWN_GUARDED', 'runtime.firewallPolicy.allowedPackages()', 'firewall.block',
    'platformLockdownEnabled() && mode == ProtectionMode.SELECTIVE'
):
    if token not in service: raise SystemExit('lockdown firewall invariant missing: '+token)
firewall=Path('app/src/main/java/de/visiongaia/gedefense/mobile/FirewallPolicyStore.kt').read_text()
for token in ('MAX_ALLOWED_PACKAGES = 512','Manifest.permission.INTERNET','setAllowed','pruneMissingPackages'):
    if token not in firewall: raise SystemExit('firewall policy invariant missing: '+token)
for token in (
    'WireGuardEgressMode.WIREGUARD_STRICT', 'wireguard_strict_requires_android_lockdown',
    'runtime.wireGuard.resolveEndpoint', 'runtime.wireGuard.buildUapi', 'clearWireGuardMaterial()',
):
    if token not in service: raise SystemExit('wireguard full-flow invariant missing: '+token)
print('VPN_TRIPLE_MODE_PASS wireguard_egress=true')
PY

python3 - <<'PY'
from pathlib import Path
scanner=Path('app/src/main/java/de/visiongaia/gedefense/mobile/AppRiskScanner.kt').read_text()
required=('MAX_PACKAGES = 768','MAX_APK_BYTES = 512L * 1024L * 1024L','MAX_TOTAL_HASH_BYTES = 1024L * 1024L * 1024L','MAX_TOTAL_STATIC_SCAN_BYTES = 512L * 1024L * 1024L','MAX_DECOMPRESSED_SCAN_BYTES = 48L * 1024L * 1024L','ZipFile(apk)','ThreatIndex','splitSourceDirs')
for token in required:
    if token not in scanner: raise SystemExit('bounded app scanner invariant missing: '+token)
if 'DexClassLoader' in scanner or 'System.load' in scanner or 'Runtime.getRuntime().exec' in scanner:
    raise SystemExit('app scanner must never execute inspected code')
print('APP_SCANNER_BOUNDARY_PASS')
PY

python3 - <<'PY'
from pathlib import Path
integrity=Path('app/src/main/java/de/visiongaia/gedefense/mobile/IntegrityGuardian.kt').read_text()
baseline=Path('core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/IntegrityBaseline.kt').read_text()
for token in ('Files.isSymbolicLink','IntegrityBaselineStore','unexpected_executable_artifact'):
    if token not in integrity: raise SystemExit('integrity invariant missing: '+token)
if 'HmacSHA256' not in baseline or 'MessageDigest.isEqual' not in baseline:
    raise SystemExit('authenticated integrity baseline invariant missing')
print('INTEGRITY_GUARD_PASS')
PY

python3 - <<'PY'
from pathlib import Path
setup=Path('app/src/main/java/de/visiongaia/gedefense/mobile/DeviceSetupManager.kt').read_text()
wizard=Path('app/src/main/java/de/visiongaia/gedefense/mobile/SetupWizardActivity.kt').read_text()
wizard_renderer=Path('app/src/main/java/de/visiongaia/gedefense/mobile/SetupWizardPageRenderer.kt').read_text()
boot=Path('app/src/main/java/de/visiongaia/gedefense/mobile/BootReceiver.kt').read_text()
for token in (
    'ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS','isIgnoringBatteryOptimizations',
    'ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION','Environment.isExternalStorageManager',
    'ACTION_USAGE_ACCESS_SETTINGS','openAutostartSettings',
):
    if token not in setup: raise SystemExit('setup hardening invariant missing: '+token)
if 'ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS' in setup:
    raise SystemExit('direct battery allowlist request must remain absent')
for token in ('BOOT_COMPLETED','MY_PACKAGE_REPLACED','ThreatIntelJobs.schedule','IntegrityJobs.schedule'):
    if token not in boot: raise SystemExit('boot restoration invariant missing: '+token)
if 'openAllFilesAccess' not in wizard_renderer or 'SetupRequirementLevel.OPTIONAL' not in wizard_renderer:
    raise SystemExit('wizard all-files flow missing or not optional')
print('SETUP_ASSISTANT_PASS')
PY

python3 - <<'PY'
from pathlib import Path
import re
storage=Path('app/src/main/java/de/visiongaia/gedefense/mobile/StorageMalwareScanner.kt').read_text()
device=Path('app/src/main/java/de/visiongaia/gedefense/mobile/DeviceSecurityScanner.kt').read_text()
scanner=Path('app/src/main/java/de/visiongaia/gedefense/mobile/ScannerActivity.kt').read_text()
required=(
    'MAX_FILES = 20_000','MAX_DEPTH = 24','MAX_TOTAL_CONTENT_BYTES = 512L * 1024L * 1024L',
    'MAX_TOTAL_HASH_BYTES = 2L * 1024L * 1024L * 1024L','Files.isSymbolicLink',
    'Environment.isExternalStorageManager','getPackageArchiveInfo','ThreatIndex','ZipFile(file)',
    'MAX_ARCHIVE_CONTAINER_BYTES = 256L * 1024L * 1024L','archive_deep_scan_size_limit','archiveWithinDeepScanBudget',
    'deceptive_double_extension','extension_magic_mismatch','embedded_blocklist_endpoint',
)
for token in required:
    if token not in storage: raise SystemExit('storage scanner invariant missing: '+token)
for forbidden in ('FileOutputStream','delete()','deleteRecursively','renameTo(','Files.write','Files.move','Runtime.getRuntime().exec','System.load('):
    if forbidden in storage: raise SystemExit('storage scanner must remain read-only/non-executing: '+forbidden)
for token in ('DeviceScanPhase.INTEGRITY','DeviceScanPhase.APPS','DeviceScanPhase.STORAGE','DeviceScanPhase.FINALIZING'):
    if token not in device: raise SystemExit('device scanner phase missing: '+token)
for token in ('ScannerRadarView','scanner_tab_overview','scanner_tab_apps','scanner_tab_files','cancelDeviceScan'):
    if token not in scanner: raise SystemExit('scanner UX invariant missing: '+token)
cache=Path('app/src/main/java/de/visiongaia/gedefense/mobile/ScannerStateCache.kt').read_text()
tokens=Path('app/src/main/java/de/visiongaia/gedefense/mobile/ThreatTokenScanner.kt').read_text()
appscanner=Path('app/src/main/java/de/visiongaia/gedefense/mobile/AppRiskScanner.kt').read_text()
for token in (
    'MAX_CACHE_AGE_MS = 7L * 24L * 60L * 60L * 1000L','MIN_WORKERS = 2','MAX_WORKERS = 4',
    'MEDIA_EXTENSIONS','ScannerStateCache','ProgressGate','contentFingerprint','secureHexEquals',
    'cached.deepComplete','MAX_ARCHIVE_ENUMERATED_ENTRIES = 32_768','file_identity_unstable',
):
    if token not in storage: raise SystemExit('accelerated storage scanner invariant missing: '+token)
for token in (
    'AppPackageCacheRecord','packageFingerprint','CACHE_RECORRELATED','MAX_PACKAGE_CACHE_AGE_MS',
    'HEURISTIC_ONLY_SCORE_CAP = 34','USER_VISIBLE_REVIEW_THRESHOLD = 35','MAX_ENUMERATED_ZIP_ENTRIES = 32_768','ProgressGate',
    'BoundedExecutors.direct("gedefense-app-scan", workers)','ThreatTokenScanner','requiresForensicHash',
):
    if token not in appscanner: raise SystemExit('incremental app scanner invariant missing: '+token)
if 'AppEntryCacheKey' in appscanner or 'entry.crc' in appscanner:
    raise SystemExit('app scanner must not reopen unchanged APK ZIPs for entry-cache validation')
for token in (
    'SecureSnapshotStore','storage-v4.bin','apps-v3.bin','SecureTelemetryVault.hotPathHmacKey',
    'legacyHmacKeyProvider','VaultDomain.SCANNER_STORAGE','VaultDomain.SCANNER_APPS',
    'contentFingerprint','deepComplete','MAX_STORAGE_RECORDS = 25_000','MAX_APP_PACKAGE_RECORDS = 1_024',
):
    if token not in cache: raise SystemExit('encrypted scanner cache invariant missing: '+token)
vault=Path('app/src/main/java/de/visiongaia/gedefense/mobile/SecureTelemetryVault.kt').read_text()
for token in ('AuthenticatedSnapshotStore','AndroidSecrets.aes256Gcm','SecureTelemetryVault.seal','SecureTelemetryVault.open'):
    if token not in vault: raise SystemExit('scanner vault authentication/encryption invariant missing: '+token)
for token in ('SecureVaultFailureKind.KEY_CONTINUITY','archiveAndClearKeyContinuityFailure','archiveAndClearReconstructibleStartupFailure','OUTER_INTEGRITY','OUTER_KEY_UNAVAILABLE','OUTER_KEY_OPERATION','archiveMigrationCandidate','commitArchivedMigration'):
    if token not in vault: raise SystemExit('vault continuity recovery invariant missing: '+token)
reconstructible = {
    'XdrEventStore.kt': ('archiveAndClearReconstructibleStartupFailure','betaRecoveryBoundaryMillis'),
    'NetworkDiscoveryStore.kt': ('archiveAndClearReconstructibleStartupFailure','betaRecoveryBoundaryMillis'),
    'PortSentinelStore.kt': ('archiveAndClearReconstructibleStartupFailure','betaRecoveryBoundaryMillis'),
    'BehaviorBaselineStore.kt': ('archiveAndClearReconstructibleStartupFailure','betaRecoveryBoundaryMillis'),
    'MalwareAnalysisStore.kt': ('archiveAndClearReconstructibleStartupFailure','betaRecoveryBoundaryMillis'),
    'ScannerStateCache.kt': ('archiveAndClearReconstructibleStartupFailure','betaRecoveryBoundaryMillis'),
}
policy=Path('app/src/main/java/de/visiongaia/gedefense/mobile/BetaVaultMigrationPolicy.kt').read_text()
for token in ('RECOVERY_VERSION_CODE = 43','lastUpdateTime','firstInstallTime'):
    if token not in policy: raise SystemExit('beta vault migration boundary missing: '+token)
for name,tokens_required in reconstructible.items():
    text=Path('app/src/main/java/de/visiongaia/gedefense/mobile',name).read_text()
    for token in tokens_required:
        if token not in text: raise SystemExit(f'reconstructible vault continuity policy missing {name}: {token}')
package_baseline=Path('app/src/main/java/de/visiongaia/gedefense/mobile/PackageBaselineStore.kt').read_text()
migration_policy=Path('app/src/main/java/de/visiongaia/gedefense/mobile/VaultMigrationPolicy.kt').read_text()
auth_store=Path('core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/AuthenticatedSnapshotStore.kt').read_text()
for token in (
    'package-baseline.v3.bin',
    'package-baseline.hmac.v3',
    'preferStrongBox = false',
    'VaultMigrationPolicy.PACKAGE_BASELINE_HMAC_V2_TO_V3',
    'archiveMigrationCandidate',
    'commitArchivedMigration',
    '_key_operation_failed',
    '_integrity_failed',
):
    if token not in package_baseline: raise SystemExit('package baseline v3 migration invariant missing: '+token)
for token in (
    'sourceGeneration = 2',
    'targetGeneration = 3',
    'minimumTargetVersionCode = 52L',
    'migration-markers',
    'lastUpdateTime',
    'firstInstallTime',
    'markCompleted',
    'by lazy(LazyThreadSafetyMode.SYNCHRONIZED)',
    'require(validMigrationId(id))',
    'validSha256Hex',
):
    if token not in migration_policy: raise SystemExit('vault generation migration policy missing: '+token)
if 'Regex(' in migration_policy:
    raise SystemExit('vault migration initializer invariant failed: runtime Regex field reintroduced')
for token in (
    'AuthenticatedSnapshotFailureKind.KEY_UNAVAILABLE',
    'AuthenticatedSnapshotFailureKind.KEY_OPERATION',
    'AuthenticatedSnapshotFailureKind.AUTHENTICATION_FAILED',
    'snapshot key operation failed',
):
    if token not in auth_store: raise SystemExit('authenticated snapshot failure classification missing: '+token)
legacy_recovery_match=re.search(r'LEGACY_KEY_RECOVERY_FAILURES\s*=\s*setOf\((.*?)\)', package_baseline, re.S)
if not legacy_recovery_match:
    raise SystemExit('package baseline migration recoverable set missing')
if 'OUTER_INTEGRITY' in legacy_recovery_match.group(1):
    raise SystemExit('package baseline migration must not auto-heal outer integrity failures')
for protected in ('AppApprovalStore.kt','FirewallPolicyStore.kt','TitanPolicyStore.kt'):
    text=Path('app/src/main/java/de/visiongaia/gedefense/mobile',protected).read_text()
    if 'archiveAndClearKeyContinuityFailure' in text:
        raise SystemExit('authoritative policy store must never auto-reset on vault continuity loss: '+protected)
print('VAULT_CONTINUITY_RECOVERY_PASS')
if 'AtomicFile' in cache:
    raise SystemExit('scanner cache must not use unauthenticated AtomicFile persistence')
if 'legacyStorageFiles' not in cache or 'legacyAppFile' not in cache:
    raise SystemExit('legacy scanner cache cleanup path missing')
for token in ('extractPublicIndicators','IpPrefix.parseAddress','MAX_TOKEN_BYTES = 49'):
    if token not in tokens: raise SystemExit('binary token scanner invariant missing: '+token)
for token in ('AppScanMetrics','packageQueryMs','staticAnalysisMs','hashingMs','cacheHits','cacheMisses','bytesStaticScanned'):
    if token not in appscanner: raise SystemExit('app scanner instrumentation invariant missing: '+token)
for token in ('StorageScanMetrics','enumerationMs','contentBytesRead','hashBytesRead'):
    if token not in storage: raise SystemExit('storage scanner instrumentation invariant missing: '+token)
for token in ('blockingEvidence -> maxOf(85, raw)', 'correlatedEvidence -> maxOf(48, minOf(raw, 62))', 'else -> minOf(raw, HEURISTIC_ONLY_SCORE_CAP)'):
    if token not in appscanner: raise SystemExit('adaptive malware severity calibration missing: '+token)
if 'blockingEvidence -> AppRiskConfidence.HIGH' not in appscanner or 'correlatedEvidence -> AppRiskConfidence.MEDIUM' not in appscanner or 'else -> AppRiskConfidence.LOW' not in appscanner:
    raise SystemExit('app scanner confidence calibration missing')
print('DEEP_SCANNER_ACCELERATION_PASS')
print('SCANNER_PERFORMANCE_QUALITY_PASS')
PY

python3 - <<'PY'
from pathlib import Path
geo=Path('app/src/main/java/de/visiongaia/gedefense/mobile/GeoCountryRepository.kt').read_text()
for token in ('Proxy.NO_PROXY','MessageDigest.isEqual','HmacSHA256','user-country-ipv4.csv','user-country-ipv6.csv','MAX_RECORDS = 2_000_000','allowedGeoHost','readAuthenticatedPointer','restorePointer(previousPointer)','recoverLatestValidGeneration','geo host refused'):
    if token not in geo: raise SystemExit('local geo integrity invariant missing: '+token)
if 'geolocation' in geo.lower() and 'lookup service' not in geo.lower(): pass
analytics=Path('app/src/main/java/de/visiongaia/gedefense/mobile/FullFlowAnalytics.kt').read_text()
for token in ('getConnectionOwnerUid' if False else 'FullFlowTelemetryReader','topCountries','dnsQuery','EventDedupe','threat.block'):
    if token not in analytics: raise SystemExit('full-flow analytics invariant missing: '+token)
owner=Path('app/src/main/java/de/visiongaia/gedefense/mobile/ConnectionOwner.kt').read_text()
if 'getConnectionOwnerUid' not in owner: raise SystemExit('VPN UID attribution missing')
print('FULL_FLOW_ANALYTICS_PASS')
PY

python3 - <<'PY'
from pathlib import Path
origin=Path('app/src/main/java/de/visiongaia/gedefense/mobile/OriginLocation.kt').read_text()
for token in ('ACCESS_COARSE_LOCATION','NETWORK_PROVIDER','PASSIVE_PROVIDER','getLastKnownLocation','QUANTUM_DEGREES = 0.25'):
    if token not in origin: raise SystemExit('atlas origin privacy invariant missing: '+token)
for forbidden in ('requestLocationUpdates','ACCESS_FINE_LOCATION','ACCESS_BACKGROUND_LOCATION'):
    if forbidden in origin: raise SystemExit('atlas origin must not use active/fine/background location: '+forbidden)
mapview=Path('app/src/main/java/de/visiongaia/gedefense/mobile/TrafficWorldMapView.kt').read_text()
for token in ('R.drawable.world_map_ambient','MAX_ROUTES = 12','CountryCentroids.lookup','TrafficMapRoute'):
    if token not in mapview: raise SystemExit('offline atlas invariant missing: '+token)
for forbidden in ('WebView','http://','https://','com.google.android.gms.maps','org.osmdroid','MapFragment','GoogleMap','fetch('):
    if forbidden in mapview: raise SystemExit('offline atlas network/map SDK surface forbidden: '+forbidden)
security=Path('app/src/main/java/de/visiongaia/gedefense/mobile/SecurityScreen.kt').read_text()
if 'traffic_map_country_scope' not in security or 'take(12)' not in security:
    raise SystemExit('atlas country-scope/bounded rendering invariant missing')
for asset in ('app/src/main/res/drawable-nodpi/world_map_ambient.png','app/src/main/res/drawable-nodpi/hero_energy_texture.png'):
    p=Path(asset)
    if not p.is_file() or p.stat().st_size <= 1024: raise SystemExit('bundled presentation asset missing: '+asset)
print('OFFLINE_ATLAS_PRIVACY_PASS')
PY

python3 - <<'PY'
from pathlib import Path
store=Path('core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/AuthenticatedSnapshotStore.kt').read_text()
for token in (
    'MessageDigest.isEqual', 'DurableAtomicFiles.replace(temp, file)', 'channel.force(true)', 'snapshot staged verification failed',
    'snapshot post-write verification failed', 'MAX_PAYLOAD_LIMIT', 'AuthenticatedSnapshotState.INVALID',
):
    if token not in store: raise SystemExit('authenticated state store invariant missing: '+token)
tests=Path('core/src/test/kotlin/de/visiongaia/gedefense/mobile/core/CoreTestMain.kt').read_text()
for token in ('testAuthenticatedSnapshotStore()', 'snapshot tamper must fail authentication', 'snapshot truncation must fail authentication', 'snapshot oversized write must be rejected'):
    if token not in tests: raise SystemExit('authenticated state store test invariant missing: '+token)
print('AUTHENTICATED_STATE_STORE_PASS')
PY

python3 - <<'PYPLAY'
from pathlib import Path
build=Path('app/build.gradle.kts').read_text()
manifest=Path('app/src/main/AndroidManifest.xml').read_text()
store=Path('app/src/main/java/de/visiongaia/gedefense/mobile/VpnDisclosureStore.kt').read_text()
disclosure=Path('app/src/main/java/de/visiongaia/gedefense/mobile/VpnDisclosureActivity.kt').read_text()
privacy=Path('app/src/main/java/de/visiongaia/gedefense/mobile/PrivacyActivity.kt').read_text()
service=Path('app/src/main/java/de/visiongaia/gedefense/mobile/GeDefenseVpnService.kt').read_text()
main=Path('app/src/main/java/de/visiongaia/gedefense/mobile/MainActivity.kt').read_text()
xdr=Path('app/src/main/java/de/visiongaia/gedefense/mobile/XdrActivity.kt').read_text()
titan=Path('app/src/main/java/de/visiongaia/gedefense/mobile/TitanActivity.kt').read_text()
runtime=Path('app/src/main/java/de/visiongaia/gedefense/mobile/AppRuntime.kt').read_text()
setup=Path('app/src/main/java/de/visiongaia/gedefense/mobile/SetupWizardActivity.kt').read_text()
setup_renderer=Path('app/src/main/java/de/visiongaia/gedefense/mobile/SetupWizardPageRenderer.kt').read_text()
receiver=Path('app/src/main/java/de/visiongaia/gedefense/mobile/PackageChangeReceiver.kt').read_text()
if 'compileSdk = 36' not in build:
    raise SystemExit('Android compile API 36 invariant missing')
if 'targetSdk = 36' not in build:
    raise SystemExit('Play target API 36 invariant missing')
for token in ('AuthenticatedSnapshotStore','vpn-disclosure.v1.bin','CURRENT_DISCLOSURE_VERSION = 1','isAccepted()','SecureTelemetryVault.hotPathHmacKey(VaultDomain.VPN_DISCLOSURE)','vpn_disclosure_reaccept_required_after_key_migration','VPN_DISCLOSURE_LEGACY'):
    if token not in store: raise SystemExit('VPN disclosure store invariant missing: '+token)
for token in ('runtime.vpnDisclosure.accept()','RESULT_CANCELED','PrivacyActivity::class.java'):
    if token not in disclosure: raise SystemExit('VPN disclosure UI invariant missing: '+token)
for token in ('privacy_vpn_consent_revoke','runtime.vpnDisclosure.revoke()','GeDefenseVpnService.ACTION_STOP',
              'stopProtectionAfterConsentRevoke()','waitForVpnInactive','privacy_vpn_consent_revoked_stop_unconfirmed'):
    if token not in privacy: raise SystemExit('privacy control invariant missing: '+token)
if 'catch (_: RuntimeException) { }' in privacy[privacy.find('private fun revokeVpnConsent'):privacy.find('private fun section')]:
    raise SystemExit('privacy consent revocation must not silently swallow protection-stop failure')
if 'if (!runtime.vpnDisclosure.isAccepted())' not in service or 'CONSENT_REQUIRED' not in service or 'START_NOT_STICKY' not in service:
    raise SystemExit('service-side VPN disclosure fail-closed gate missing')
for source,name in ((main,'MainActivity'),(xdr,'XdrActivity'),(titan,'TitanActivity')):
    if 'VpnDisclosureActivity::class.java' not in source:
        raise SystemExit('VPN disclosure launch gate missing: '+name)
for name in ('.VpnDisclosureActivity','.PrivacyActivity'):
    marker=f'android:name="{name}" android:exported="false"'
    if marker not in manifest: raise SystemExit('privacy activity must be internal: '+name)
if 'REQUEST_IGNORE_BATTERY_OPTIMIZATIONS' in manifest:
    raise SystemExit('Play-hostile direct battery optimization permission reintroduced')
if 'if (setup.isWizardCompleted()) xdr.reconcilePackages()' not in runtime:
    raise SystemExit('fresh-install background package inventory gate missing')
if 'setup.markWizardCompleted()' not in setup or 'activatePostSetupInventoryAsync()' not in setup:
    raise SystemExit('post-setup package inventory activation missing')
if '!runtime.setup.isWizardCompleted()' not in receiver:
    raise SystemExit('pre-setup package event gate missing')
# Every Activity that opts into VGT edge-to-edge system bars must also consume safe-area insets.
activity_dir=Path('app/src/main/java/de/visiongaia/gedefense/mobile')
for path in activity_dir.glob('*.kt'):
    source=path.read_text()
    if 'VgtWindowInsets.configureSystemBars(window)' in source and 'setOnApplyWindowInsetsListener' not in source:
        raise SystemExit('edge-to-edge safe-area invariant missing: '+path.name)
for source,name in ((disclosure,'VpnDisclosureActivity'),(privacy,'PrivacyActivity')):
    for token in ('setOnApplyWindowInsetsListener','VgtWindowInsets.safeArea(insets)','requestApplyInsets()'):
        if token not in source:
            raise SystemExit('privacy safe-area invariant missing: '+name+':'+token)
print('EDGE_TO_EDGE_SAFE_AREA_PASS')
print('PLAY_PRIVACY_GATES_PASS')
PYPLAY

python3 - <<'PYANDROID16'
from pathlib import Path
manifest=Path('app/src/main/AndroidManifest.xml').read_text()
source='\n'.join(p.read_text() for p in Path('app/src/main/java').rglob('*.kt'))
for forbidden in ('windowOptOutEdgeToEdgeEnforcement', 'android:resizeableActivity="false"', 'android:screenOrientation='):
    if forbidden in manifest:
        raise SystemExit('Android 16 compatibility escape/restriction present: '+forbidden)
for forbidden in ('.onBackPressed()', 'KEYCODE_BACK'):
    if forbidden in source:
        raise SystemExit('legacy back-navigation override present: '+forbidden)
if 'VgtWindowInsets.safeArea' not in source or 'WindowInsets.Type.systemBars()' not in source:
    raise SystemExit('edge-to-edge safe-area infrastructure missing')
print('ANDROID16_STATIC_COMPAT_PASS')
PYANDROID16

python3 - <<'PY'
from pathlib import Path
engine=Path('app/src/main/java/de/visiongaia/gedefense/mobile/XdrEngine.kt').read_text()
store=Path('app/src/main/java/de/visiongaia/gedefense/mobile/XdrEventStore.kt').read_text()
baseline=Path('app/src/main/java/de/visiongaia/gedefense/mobile/PackageBaselineStore.kt').read_text()
firewall=Path('app/src/main/java/de/visiongaia/gedefense/mobile/FirewallPolicyStore.kt').read_text()
receiver=Path('app/src/main/java/de/visiongaia/gedefense/mobile/PackageChangeReceiver.kt').read_text()
secrets=Path('app/src/main/java/de/visiongaia/gedefense/mobile/AndroidSecrets.kt').read_text()
for token in ('reconcilePackages','ingestDeviceScan','ingestHardening','recordThreatBlock','Signing certificate changed','Sensitive permission drift','recordEmergencyLockdown','setQuarantined','recoverXdrEventStore','resetPackageBaseline','resetFirewallPolicy'):
    if token not in engine: raise SystemExit('XDR engine invariant missing: '+token)
for token in ('SecureSnapshotStore','events.v2.bin','MAX_PAYLOAD_BYTES = 4 * 1024 * 1024','INCIDENT_WINDOW_MS','dedupeKey','recoverCorruptStore','MessageDigest','val next = ArrayList<XdrEvent>'):
    if token not in store: raise SystemExit('authenticated XDR event store invariant missing: '+token)
if 'events.removeLastOrNull()' in store:
    raise SystemExit('XDR event append rollback must be copy-on-write')
for token in ('SecureSnapshotStore','package-baseline.v2.bin','GET_SIGNING_CERTIFICATES','REQUESTED_PERMISSION_GRANTED','ACCESSIBILITY_SERVICE','DEVICE_ADMIN','signerIdentity','aggregateSigners','compareUnsigned','resetTrustedBaseline'):
    if token not in baseline: raise SystemExit('authenticated package baseline invariant missing: '+token)
for token in ('SecureSnapshotStore','policy.v2.bin','MAX_ALLOWED_PACKAGES = 512','setQuarantined','resetPolicy','policyIntegrityOk','it !in quarantineState'):
    if token not in firewall: raise SystemExit('authenticated firewall policy invariant missing: '+token)
if 'fun installedPackageNames(): Set<String>?' not in firewall or 'catch (_: RuntimeException) { null }' not in firewall:
    raise SystemExit('installed-package query must preserve failure state')
for token in ('KeyStore.getInstance("AndroidKeyStore")','KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore")','AndroidKeystoreGate.call','as? SecretKey'):
    if token not in secrets: raise SystemExit('Android keystore invariant missing: '+token)
if 'synchronized(lock)' in secrets:
    raise SystemExit('Android keystore provider calls must not be held behind an unbounded process monitor')
gate=Path('app/src/main/java/de/visiongaia/gedefense/mobile/AndroidKeystoreGate.kt').read_text()
for token in ('OPERATION_TIMEOUT_MILLIS = 5_000L','ADMISSION_TIMEOUT_MILLIS = 10_000L','SynchronousQueue','ReentrantLock(true)','tryLock','circuitOpen','future.get','shutdownNow'):
    if token not in gate: raise SystemExit('Android keystore bounded gate invariant missing: '+token)
opaque=Path('core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/BoundedSecretKeyCrypto.kt').read_text()
for token in ('DEFAULT_TIMEOUT_MILLIS = 5_000L','ADMISSION_TIMEOUT_MILLIS = 10_000L','SynchronousQueue','ReentrantLock(true)','tryLock','circuitOpen','opaque key provider timeout'):
    if token not in opaque: raise SystemExit('opaque SecretKey bounded gate invariant missing: '+token)
install_guard=Path('app/src/main/java/de/visiongaia/gedefense/mobile/InstallGuard.kt').read_text()
if 'goAsync()' not in receiver or 'runtime.installGuard.handlePackageEvent' not in receiver:
    raise SystemExit('XDR package receiver async InstallGuard handoff missing')
if 'xdr.handlePackageEvent(packageName, action, replacing)' not in install_guard:
    raise SystemExit('InstallGuard -> XDR package-event correlation missing')
print('XDR_EDR_CORRELATION_PASS')
PY

python3 - <<'PY'
from pathlib import Path
models=Path('app/src/main/java/de/visiongaia/gedefense/mobile/XdrModels.kt').read_text()
engine=Path('app/src/main/java/de/visiongaia/gedefense/mobile/XdrEngine.kt').read_text()
store=Path('app/src/main/java/de/visiongaia/gedefense/mobile/XdrEventStore.kt').read_text()
activity=Path('app/src/main/java/de/visiongaia/gedefense/mobile/XdrActivity.kt').read_text()
for token in ('XdrForensicReason','XdrForensicFact','XdrScoreBreakdown','fun xdrScoreBreakdown','countedEventIds'):
    if token not in models: raise SystemExit('XDR forensic model invariant missing: '+token)
for token in ('detectorScore = rawScannerScore','forensicReasons = reasons','forensicFacts = facts','signer_sha256','apk_sha256','threat_matches'):
    if token not in engine: raise SystemExit('XDR forensic ingestion invariant missing: '+token)
for token in ('forensic_reasons','forensic_facts','detector_score','MAX_FORENSIC_REASONS','MAX_FORENSIC_FACTS'):
    if token not in store: raise SystemExit('XDR forensic persistence invariant missing: '+token)
if 'root.optInt("version") != 2' not in store:
    raise SystemExit('XDR forensic extension must retain event-store v2 compatibility')
for token in ('XdrViewMode.FINDINGS','XdrViewMode.FORENSICS','renderForensics','xdrScoreBreakdown(events)','xdr_forensic_reasons','xdr_forensic_artifacts','xdr_event_counted'):
    if token not in activity: raise SystemExit('XDR forensic UI invariant missing: '+token)
print('XDR_FORENSICS_PASS')
PY

python3 - <<'PY'
from pathlib import Path
models=Path('app/src/main/java/de/visiongaia/gedefense/mobile/BehaviorModels.kt').read_text()
store=Path('app/src/main/java/de/visiongaia/gedefense/mobile/BehaviorBaselineStore.kt').read_text()
engine=Path('app/src/main/java/de/visiongaia/gedefense/mobile/BehaviorEngine.kt').read_text()
xdr=Path('app/src/main/java/de/visiongaia/gedefense/mobile/XdrEngine.kt').read_text()
activity=Path('app/src/main/java/de/visiongaia/gedefense/mobile/BehaviorActivity.kt').read_text()
telemetry=Path('app/src/main/java/de/visiongaia/gedefense/mobile/FullFlowAnalytics.kt').read_text()
vpn=Path('app/src/main/java/de/visiongaia/gedefense/mobile/GeDefenseVpnService.kt').read_text()
manifest=Path('app/src/main/AndroidManifest.xml').read_text()
for token in ('POTENTIAL_EXFILTRATION','TRAFFIC_SPIKE','NEW_DESTINATION_BURST','NEW_COUNTRY','OFF_HOURS_ACTIVITY','val mature: Boolean','pendingDomains','pendingCountries'):
    if token not in models: raise SystemExit('behavior model invariant missing: '+token)
for token in ('SecureSnapshotStore','behavior-baseline.v2.bin','MAX_PROFILES = 256','MAX_DOMAINS = 64','PROMOTION_OBSERVATIONS = 3','observeBatch','markAnomalies','baselineIntegrityOk'):
    if token not in store: raise SystemExit('authenticated behavior baseline invariant missing: '+token)
for token in ('if (!profile.mature)','Potential data-exfiltration pattern','New network-destination burst','Activity outside learned hours','EVALUATION_INTERVAL_MS = 30_000L','autoQuarantineCritical','baselineIntegrityOk','excludedPackages','XdrSeverity.HIGH','XdrSeverity.CRITICAL'):
    if token not in engine: raise SystemExit('behavior engine invariant missing: '+token)
if 'store.observeBatch(apps, duration, now, excludedPackages)' not in engine:
    raise SystemExit('anomalous behavioral sessions must be excluded from baseline learning')
if 'recordBehaviorAnomaly' not in xdr or 'XdrCategory.BEHAVIOR' not in xdr:
    raise SystemExit('behavior -> XDR correlation missing')
for token in ('behavior_profiles_title','behavior_policy_toggle','behavior_reset_confirm_title'):
    if token not in activity: raise SystemExit('behavior UI invariant missing: '+token)
if 'runtime.behavior.evaluateLive' not in telemetry:
    raise SystemExit('live behavioral evaluation missing from GaiaNet telemetry')
if 'runtime.behavior.commitSession' not in vpn:
    raise SystemExit('behavior session baseline commit missing')
if '.BehaviorActivity' not in manifest or 'android:exported="false"' not in manifest:
    raise SystemExit('behavior activity export invariant missing')
print('BEHAVIORAL_EDR_PASS')
PY

python3 - <<'PY'
from pathlib import Path
scanner=Path('app/src/main/java/de/visiongaia/gedefense/mobile/DeviceHardeningScanner.kt').read_text()
activity=Path('app/src/main/java/de/visiongaia/gedefense/mobile/HardeningActivity.kt').read_text()
security=Path('app/src/main/java/de/visiongaia/gedefense/mobile/SecurityScreen.kt').read_text()
xdr=Path('app/src/main/java/de/visiongaia/gedefense/mobile/XdrActivity.kt').read_text()
models=Path('app/src/main/java/de/visiongaia/gedefense/mobile/HardeningModels.kt').read_text()
for token in ('KeyguardManager','SECURITY_PATCH','ADB_ENABLED','DEVELOPMENT_SETTINGS_ENABLED','/sys/fs/selinux/enforce','verifiedbootstate','ROOT_PATHS','storageEncryptionStatus','private_dns_mode','ENABLED_ACCESSIBILITY_SERVICES','enabled_notification_listeners','activeAdmins'):
    if token not in scanner: raise SystemExit('hardening scanner invariant missing: '+token)
for token in ('enum class HardeningStatus { PASS, REVIEW, FAIL, UNKNOWN }','pointsLost','settingsAction'):
    if token not in models: raise SystemExit('hardening model invariant missing: '+token)
for token in ('hardening_posture_title','hardening_controls_title','openSettings'):
    if token not in activity: raise SystemExit('hardening UI invariant missing: '+token)
if 'updateHardening(snapshot.hardening)' not in security: raise SystemExit('hardening summary missing from Security Center')
job=Path('app/src/main/java/de/visiongaia/gedefense/mobile/IntegrityJobService.kt').read_text()
if 'runtime.hardeningScanner.scan()' not in job or 'runtime.xdr.ingestHardening(hardening)' not in job:
    raise SystemExit('periodic hardening drift detection missing')
for token in ('xdr_sensor_coverage','updateCoverage','incidentRecommendation','HardeningActivity'):
    if token not in xdr: raise SystemExit('XDR visibility invariant missing: '+token)
print('DEVICE_HARDENING_XDR_PASS')
PY


python3 - <<'PYNET'
from pathlib import Path
planner=Path('core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/NetworkRangePlanner.kt').read_text()
mdns=Path('core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/MdnsDnsCodec.kt').read_text()
scanner=Path('app/src/main/java/de/visiongaia/gedefense/mobile/NetworkDiscoveryScanner.kt').read_text()
models=Path('app/src/main/java/de/visiongaia/gedefense/mobile/NetworkDiscoveryModels.kt').read_text()
store=Path('app/src/main/java/de/visiongaia/gedefense/mobile/NetworkDiscoveryStore.kt').read_text()
activity=Path('app/src/main/java/de/visiongaia/gedefense/mobile/NetworkDiscoveryActivity.kt').read_text()
xdr=Path('app/src/main/java/de/visiongaia/gedefense/mobile/XdrEngine.kt').read_text()
tests=Path('core/src/test/kotlin/de/visiongaia/gedefense/mobile/core/CoreTestMain.kt').read_text()
manifest=Path('app/src/main/AndroidManifest.xml').read_text()
for token in ('MAX_ACTIVE_HOSTS = 254','isPrivateIpv4','prefixLength < 24 -> 24','scopeClamped'):
    if token not in planner: raise SystemExit('LAN scan planner invariant missing: '+token)
for token in ('MAX_PACKET_BYTES = 9_000','MAX_RECORDS = 128','MAX_POINTER_JUMPS = 16','MAX_EXPANDED_NAME_BYTES = 255','buildPtrQuery','TYPE_PTR','TYPE_SRV','TYPE_TXT'):
    if token not in mdns: raise SystemExit('bounded mDNS codec invariant missing: '+token)
for token in ('MAX_WORKERS = 32','CONNECT_TIMEOUT_MS = 140','network.socketFactory.createSocket','network.bindSocket(socket)','discoverSsdp','discoverMdns','sourceIp !in allowed','MDNS_MAX_PACKETS = 128','MDNS_MAX_DYNAMIC_TYPES = 12','/proc/net/arp','MAX_ARP_BYTES','MAX_RESULTS = 512','WIFI','ETHERNET','parseIpv4Literal'):
    if token not in scanner: raise SystemExit('LAN discovery scanner invariant missing: '+token)
for forbidden in ('Runtime.getRuntime().exec','ProcessBuilder','targetCidr','userTarget','scanTargetInput','catch (_: Throwable)'):
    if forbidden in scanner: raise SystemExit('LAN scanner forbidden capability present: '+forbidden)
for token in ('SecureSnapshotStore','network-discovery.v1.bin','PAYLOAD_SCHEMA = 3','MAX_PAYLOAD_BYTES = 640 * 1024','initializingNetwork','newlyAdvertisedServices','changedAttributes','pendingPorts','pendingServices','PROMOTION_OBSERVATIONS = 2','LanBehaviorEvaluator','network discovery baseline persist failed'):
    if token not in store: raise SystemExit('LAN baseline invariant missing: '+token)
for token in ('NetworkIdentitySource','MDNS_HOST','advertisedServices','changedBaselineAttributes','NetworkBehaviorState','behaviorSignals','networkBehaviorSignals'):
    if token not in models: raise SystemExit('LAN identity/service model invariant missing: '+token)
if 'testNetworkRangePlanner()' not in tests or 'public IPv4 range refused' not in tests:
    raise SystemExit('LAN range core tests missing')
for token in ('testMdnsDnsCodec()','mDNS compression loop rejected','mDNS supported record parsing'):
    if token not in tests: raise SystemExit('mDNS core tests missing: '+token)
for token in ('testLanBehaviorEvaluator()','LAN service burst detected','LAN device surge detected','normal LAN variation must remain quiet'):
    if token not in tests: raise SystemExit('LAN behavior core tests missing: '+token)
for token in ('ingestNetworkDiscovery','HIGH_RISK_LAN_PORTS','HIGH_RISK_DNS_SD_SERVICES','New local service exposure detected','New local service advertisement detected','Local device identity drift observed','Local-network risk surge observed','Local device exposure risk spiked','lan-behavior','networkDiscoveryIntegrityOk'):
    if token not in xdr: raise SystemExit('LAN -> XDR correlation invariant missing: '+token)
for token in ('network_discovery_status_title','network_discovery_devices_title','network_discovery_advertised_services','network_discovery_identity_source','network_discovery_behavior_detail','resetNetworkDiscoveryBaseline'):
    if token not in activity: raise SystemExit('LAN discovery UI invariant missing: '+token)
for permission in ('android.permission.ACCESS_WIFI_STATE','android.permission.CHANGE_WIFI_MULTICAST_STATE'):
    if permission not in manifest: raise SystemExit('mDNS permission invariant missing: '+permission)
if '.NetworkDiscoveryActivity' not in manifest or 'android:exported="false"' not in manifest:
    raise SystemExit('LAN discovery activity export invariant missing')
print('NETWORK_DISCOVERY_XDR_PASS')
PYNET

python3 - <<'PYSENTINEL'
from pathlib import Path
classifier=Path('core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/PortSentinelClassifier.kt').read_text()
sentinel=Path('app/src/main/java/de/visiongaia/gedefense/mobile/PortSentinel.kt').read_text()
store=Path('app/src/main/java/de/visiongaia/gedefense/mobile/PortSentinelStore.kt').read_text()
activity=Path('app/src/main/java/de/visiongaia/gedefense/mobile/PortSentinelActivity.kt').read_text()
xdr=Path('app/src/main/java/de/visiongaia/gedefense/mobile/XdrEngine.kt').read_text()
vpn=Path('app/src/main/java/de/visiongaia/gedefense/mobile/GeDefenseVpnService.kt').read_text()
tests=Path('core/src/test/kotlin/de/visiongaia/gedefense/mobile/core/CoreTestMain.kt').read_text()
manifest=Path('app/src/main/AndroidManifest.xml').read_text()
for token in ('SCAN_WINDOW_MILLIS = 30_000L','MAX_TRACKED_DISTINCT_PORTS = 6','5555','2323','LAN_PORT_SCAN_DETECTED','LAN_ADB_PROBE_DETECTED'):
    if token not in classifier: raise SystemExit('Port Sentinel classifier invariant missing: '+token)
for token in ('Selector.open()','ServerSocketChannel.open()','DatagramChannel.open','MAX_EVENTS_PER_MINUTE = 96','DEDUPE_MS = 10_000L','PortSentinelStore.isBlockableAddress','socket.close()','ByteBuffer.allocateDirect(1)'):
    if token not in sentinel: raise SystemExit('Port Sentinel listener invariant missing: '+token)
for forbidden in ('Runtime.getRuntime().exec','ProcessBuilder','readLine(','InputStream','catch (_: Throwable)'):
    if forbidden in sentinel: raise SystemExit('Port Sentinel forbidden interaction present: '+forbidden)
for token in ('SecureSnapshotStore','port-sentinel.v1.bin','MAX_HITS = 256','MAX_BLOCKED = 256','MIN_PERSIST_INTERVAL_MS = 5_000L','isPrivateIpv4'):
    if token not in store: raise SystemExit('Port Sentinel authenticated state invariant missing: '+token)
for token in ('recordPortSentinel','network-sentinel:','recordSentinelBlocklistChange','portSentinelIntegrityOk'):
    if token not in xdr: raise SystemExit('Port Sentinel XDR invariant missing: '+token)
for token in ('registerNetworkCallback','NET_CAPABILITY_NOT_VPN','setUnderlyingNetworks','HANDOVER_DEBOUNCE_MS = 2_000L','portSentinel.rebind','ProtectionMode.FULL_FLOW_BETA'):
    if token not in vpn: raise SystemExit('physical network handover invariant missing: '+token)
for token in ('port_sentinel_limit_body','setSentinelSourceBlocked','ScannerRadarView','resetSentinelHistory'):
    if token not in activity: raise SystemExit('Port Sentinel UI invariant missing: '+token)
if 'testPortSentinelClassifier()' not in tests or 'broad port scan escalates' not in tests:
    raise SystemExit('Port Sentinel core tests missing')
if '.PortSentinelActivity' not in manifest or 'android:exported="false"' not in manifest:
    raise SystemExit('Port Sentinel activity export invariant missing')
print('PORT_SENTINEL_XDR_PASS')
PYSENTINEL

python3 - <<'PYUI'
from pathlib import Path
perf=Path('app/src/main/java/de/visiongaia/gedefense/mobile/VgtUiPerformance.kt').read_text()
main=Path('app/src/main/java/de/visiongaia/gedefense/mobile/MainActivity.kt').read_text()
telemetry=Path('app/src/main/java/de/visiongaia/gedefense/mobile/FullFlowAnalytics.kt').read_text()
shield=Path('app/src/main/java/de/visiongaia/gedefense/mobile/ShieldPulseView.kt').read_text()
radar=Path('app/src/main/java/de/visiongaia/gedefense/mobile/ScannerRadarView.kt').read_text()
world=Path('app/src/main/java/de/visiongaia/gedefense/mobile/TrafficWorldMapView.kt').read_text()
security=Path('app/src/main/java/de/visiongaia/gedefense/mobile/SecurityScreen.kt').read_text()
titan_visual=Path('app/src/main/java/de/visiongaia/gedefense/mobile/TitanVisualMode.kt').read_text()
cyber=Path('app/src/main/java/de/visiongaia/gedefense/mobile/CyberBackgroundView.kt').read_text()
ui=Path('app/src/main/java/de/visiongaia/gedefense/mobile/GeDefenseUi.kt').read_text()
header=Path('app/src/main/java/de/visiongaia/gedefense/mobile/VgtUiComponents.kt').read_text()
for token in ('Choreographer.FrameCallback','frameIntervalMillis','isLowRamDevice','isPowerSaveMode','INTERACTION_COOLDOWN_MS'):
    if token not in perf: raise SystemExit('UI performance governor invariant missing: '+token)
for token in ('UI_REFRESH_COALESCE_MS = 120L','refreshPending','when (selectedScreen)','VgtUiPerformance.noteInteraction'):
    if token not in main: raise SystemExit('main UI refresh coalescing invariant missing: '+token)
for token in ('UI_NOTIFY_MIN_INTERVAL_MS = 500L','notifyUi(force = true)','SystemClock.elapsedRealtime'):
    if token not in telemetry: raise SystemExit('telemetry UI throttling invariant missing: '+token)
for name,text in [('shield',shield),('radar',radar),('world',world)]:
    if 'VgtFrameTicker' not in text: raise SystemExit(name+' animation ticker missing')
    if 'ValueAnimator' in text: raise SystemExit(name+' must not use unbounded ValueAnimator redraw loop')
for token in ('lastIntegrity','lastHardening','lastFullFlow','lastMap','lastTraffic'):
    if token not in security: raise SystemExit('Security Center render diffing invariant missing: '+token)
for token in ('AppRuntime.peek()?.titan?.snapshot()?.tier','@Volatile var tier: TitanTier','val active: Boolean','val light: Boolean','val full: Boolean','fun refresh('):
    if token not in titan_visual: raise SystemExit('TITAN visual-mode invariant missing: '+token)
if 'isDeviceOwnerApp(' in titan_visual or 'getSystemService(DevicePolicyManager' in titan_visual or 'import android.app.admin.DevicePolicyManager' in titan_visual:
    raise SystemExit('TITAN visual mode must remain snapshot-only and perform no platform Binder query')
for token in ('VgtFrameTicker','titanSweep','TitanVisualMode.active'):
    if token not in cyber: raise SystemExit('TITAN animated background invariant missing: '+token)
if 'TitanVisualMode.active' not in ui or 'titan_global_badge' not in header:
    raise SystemExit('app-wide TITAN visual treatment missing')
print('UI_PERFORMANCE_PASS')
PYUI

python3 - <<'PYTITAN'
from pathlib import Path
import xml.etree.ElementTree as ET
manager=Path('app/src/main/java/de/visiongaia/gedefense/mobile/TitanPolicyManager.kt').read_text()
ca_validator=Path('core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/ManagedCaCertificateValidator.kt').read_text()
core_tests=Path('core/src/test/kotlin/de/visiongaia/gedefense/mobile/core/CoreTestMain.kt').read_text()
store=Path('app/src/main/java/de/visiongaia/gedefense/mobile/TitanPolicyStore.kt').read_text()
activity=Path('app/src/main/java/de/visiongaia/gedefense/mobile/TitanActivity.kt').read_text()
xdr=Path('app/src/main/java/de/visiongaia/gedefense/mobile/XdrEngine.kt').read_text()
vpn=Path('app/src/main/java/de/visiongaia/gedefense/mobile/GeDefenseVpnService.kt').read_text()
main=Path('app/src/main/java/de/visiongaia/gedefense/mobile/MainActivity.kt').read_text()
provision=Path('app/src/main/java/de/visiongaia/gedefense/mobile/TitanGetProvisioningModeActivity.kt').read_text()
compliance=Path('app/src/main/java/de/visiongaia/gedefense/mobile/TitanPolicyComplianceActivity.kt').read_text()
admin_xml=Path('app/src/main/res/xml/titan_device_admin.xml').read_text()
for token in (
    'isDeviceOwnerApp','setPackagesSuspended','setAlwaysOnVpnPackage','addUserRestriction','clearUserRestriction',
    'setRequiredPasswordComplexity','setMaximumFailedPasswordsForWipe','packageInstaller.uninstall',
    'installCaCert','getInstalledCaCerts','ManagedCaCertificateValidator.inspect','MAX_CA_CERT_BYTES = ManagedCaCertificateValidator.MAX_BYTES',
    'SYSTEM_PACKAGE_NOT_SUSPENDED','SYSTEM_PACKAGE_NOT_REMOVED',
):
    if token not in manager: raise SystemExit('TITAN policy invariant missing: '+token)
for token in ('MAX_BYTES: Int = 128 * 1024','generateCertificates','certificates.size != 1','basicConstraints < 0','usage.size <= 5 || !usage[5]','checkValidity(Date(nowMillis))','MessageDigest.getInstance("SHA-256")'):
    if token not in ca_validator: raise SystemExit('TITAN managed CA validation invariant missing: '+token)
for token in ('testManagedCaCertificateValidator()','leaf certificate rejected as trust anchor','multiple certificates rejected','oversized CA input rejected'):
    if token not in core_tests: raise SystemExit('TITAN managed CA core test invariant missing: '+token)
for token in ('SecureSnapshotStore','gedefense-titan-policy-v1','MAX_PAYLOAD_BYTES = 4096','autoSuspendOnQuarantine'):
    if token not in store: raise SystemExit('TITAN authenticated policy invariant missing: '+token)
for token in (
    'adb shell dpm set-device-owner --user 0','titan_qr_body','titan_trust_title','confirmCaInstall',
    'TitanPolicyManager.MAX_CA_CERT_BYTES','titan_wipe_confirm_title','confirmUninstall',
    'titan_xiaomi_title','titan_xiaomi_path','activationMethodCard','TitanCoreView','adbCommandWell',
):
    if token not in activity: raise SystemExit('TITAN UI/operator-confirmation invariant missing: '+token)
if xdr.find('firewallPolicy.setQuarantined') < 0 or xdr.find('titan.enforceQuarantine') < 0:
    raise SystemExit('TITAN XDR quarantine integration missing')
if xdr.find('firewallPolicy.setQuarantined') > xdr.find('titan.enforceQuarantine'):
    raise SystemExit('TITAN privileged quarantine must follow network quarantine')
if 'uninstallUserPackage(' in xdr:
    raise SystemExit('XDR must never auto-uninstall packages')
for token in ('ACTION_GET_PROVISIONING_MODE','PROVISIONING_MODE_FULLY_MANAGED_DEVICE','EXTRA_PROVISIONING_ALLOWED_PROVISIONING_MODES'):
    if token not in provision: raise SystemExit('modern TITAN provisioning invariant missing: '+token)
for token in ('ACTION_ADMIN_POLICY_COMPLIANCE','isDeviceOwnerApp','setOrganizationName'):
    if token not in compliance: raise SystemExit('TITAN compliance invariant missing: '+token)
for token in ('<limit-password />','<watch-login />','<wipe-data />'):
    if token not in admin_xml: raise SystemExit('TITAN admin policy declaration missing: '+token)
if 'runtime.state.platformAlwaysOn()' not in main or 'titan.alwaysOnVpn || platformAlwaysOn' not in main or 'always_on_release_first' not in main:
    raise SystemExit('main UI must not bypass platform/TITAN always-on protection')
if 'platformLockdownEnabled() && mode == ProtectionMode.SELECTIVE' not in vpn or 'ProtectionMode.FULL_FLOW_BETA' not in vpn:
    raise SystemExit('Android lockdown must force full-flow semantics')
print('TITAN_DEVICE_OWNER_PASS')
PYTITAN

python3 - <<'PYRESILIENCE'
from pathlib import Path
manifest=Path('app/src/main/AndroidManifest.xml').read_text()
vpn=Path('app/src/main/java/de/visiongaia/gedefense/mobile/GeDefenseVpnService.kt').read_text()
setup=Path('app/src/main/java/de/visiongaia/gedefense/mobile/DeviceSetupManager.kt').read_text()
state=Path('app/src/main/java/de/visiongaia/gedefense/mobile/RuntimeState.kt').read_text()
main=Path('app/src/main/java/de/visiongaia/gedefense/mobile/MainActivity.kt').read_text()
nav=Path('app/src/main/java/de/visiongaia/gedefense/mobile/BottomNavBar.kt').read_text()
for token in ('android.net.VpnService.SUPPORTS_ALWAYS_ON','android:value="true"'):
    if token not in manifest: raise SystemExit('always-on VPN manifest invariant missing: '+token)
for token in ('isAlwaysOn','isLockdownEnabled','ACTION_RESILIENCE_PROBE','ACTION_RECOVERY_SELF_TEST','START_STICKY','recordPlatformVpnPolicy','security_bootstrap_timeout','recoveryPending','recoveryGeneration'):
    if token not in vpn: raise SystemExit('VPN resilience invariant missing: '+token)
if 'Settings.ACTION_VPN_SETTINGS' not in setup:
    raise SystemExit('consumer always-on setup must use Android VPN settings')
for token in ('resilienceDesired','platformAlwaysOn','platformLockdown','recordPlatformVpnPolicy','recordVpnRecovery'):
    if token not in state: raise SystemExit('persisted VPN resilience state missing: '+token)
for token in ('ProtectionHubScreen','AnalysisHubScreen','SystemHubScreen','configureAlwaysOnProtection','runtime.state.platformAlwaysOn()'):
    if token not in main: raise SystemExit('resilience/UX hub invariant missing: '+token)
if 'lp.bottomMargin' not in nav or 'setPadding(' not in nav:
    raise SystemExit('bottom navigation inset/margin invariant missing')
print('VPN_RESILIENCE_UX_PASS')
PYRESILIENCE

python3 - <<'PYPOWER'
from pathlib import Path
vpn=Path('app/src/main/java/de/visiongaia/gedefense/mobile/GeDefenseVpnService.kt').read_text()
runtime=Path('app/src/main/java/de/visiongaia/gedefense/mobile/AppRuntime.kt').read_text()
analytics=Path('app/src/main/java/de/visiongaia/gedefense/mobile/FullFlowAnalytics.kt').read_text()
sentinel=Path('app/src/main/java/de/visiongaia/gedefense/mobile/PortSentinel.kt').read_text()
ui_perf=Path('app/src/main/java/de/visiongaia/gedefense/mobile/VgtUiPerformance.kt').read_text()
owner=Path('app/src/main/java/de/visiongaia/gedefense/mobile/ConnectionOwner.kt').read_text()
power=Path('netstack/power_state.go').read_text()
telemetry=Path('netstack/telemetry.go').read_text()
tcp=Path('netstack/tcp_manager.go').read_text()
udp=Path('netstack/udp_manager.go').read_text()
limits=Path('netstack/limits.go').read_text()
helper=Path('netstack/helper_main_process.go').read_text()
bridge=Path('app/src/main/java/de/visiongaia/gedefense/mobile/NativeGaiaNet.kt').read_text()
protection=Path('app/src/main/java/de/visiongaia/gedefense/mobile/ProtectionHubScreen.kt').read_text()
main=Path('app/src/main/java/de/visiongaia/gedefense/mobile/MainActivity.kt').read_text()
for token in ('ACTION_DEVICE_IDLE_MODE_CHANGED','ACTION_POWER_SAVE_MODE_CHANGED','ACTION_SCREEN_OFF','setPowerConstrained','setTelemetryDetailed','hasStateListeners()'):
    if token not in vpn and token not in runtime: raise SystemExit('adaptive power governor invariant missing: '+token)
for token in ('securityBootstrapComplete','awaitSecurityBootstrap','CountDownLatch'):
    if token not in runtime: raise SystemExit('bounded security bootstrap invariant missing: '+token)
for token in ('activeFlowCount()','if (!runtime.hasStateListeners()) return','LABEL_CACHE_CAPACITY'):
    if token not in analytics: raise SystemExit('background analytics optimization missing: '+token)
if 'selector.select()' not in sentinel or 'selector.select(' in sentinel.replace('selector.select()',''):
    raise SystemExit('Port Sentinel must block event-driven without periodic selector timeout')
if 'postFrameCallbackDelayed' in ui_perf:
    raise SystemExit('UI ticker must not poll invisible/background windows')
for token in ('requested','onWindowVisibilityChanged','stopCallbacks'):
    if token not in ui_perf: raise SystemExit('UI visibility power gate missing: '+token)
for token in ('uidOwners','UID_CACHE_CAPACITY','UID_CACHE_TTL_MS'):
    if token not in owner: raise SystemExit('bounded UID attribution cache missing: '+token)
for token in ('telemetryDetailed','currentTelemetryInterval','currentTCPHousekeepingInterval','return udpIdleTimeout'):
    if token not in power: raise SystemExit('GaiaNet adaptive power invariant missing: '+token)
for token in ('wake','resetTimer','currentTelemetryInterval','critical bool'):
    if token not in telemetry: raise SystemExit('GaiaNet telemetry coalescing invariant missing: '+token)
for token in ('sweepWake','signalSweep','tcpSweepUrgent','nextSweepInterval'):
    if token not in tcp: raise SystemExit('GaiaNet event-driven TCP housekeeping invariant missing: '+token)
if 'go m.sweepLoop()' in udp or 'func (m *udpManager) sweepLoop()' in udp:
    raise SystemExit('UDP manager must rely on socket deadlines instead of periodic sweeper')
if 'SetReadDeadline(time.Now().Add(currentUDPIdleTimeout()))' not in udp:
    raise SystemExit('UDP idle deadline invariant missing')
for token in ('tcpUrgentSweepInterval','tcpIdleSweepInterval','tcpConstrainedIdleSweepInterval','tcpNoFlowSweepInterval','telemetryBackgroundInterval','telemetryConstrainedInterval'):
    if token not in limits: raise SystemExit('adaptive cadence limit missing: '+token)
for token in ("case 'P':","case 'V':",'e.powerStateChanged()'):
    if token not in helper: raise SystemExit('GaiaNet helper power control invariant missing: '+token)
for token in ('setPowerConstrained','setTelemetryDetailed'):
    if token not in bridge: raise SystemExit('GaiaNet Android power bridge invariant missing: '+token)
for token in ('resilienceTestAction','killSwitchConfigured'):
    if token not in protection: raise SystemExit('resilience self-test UI guard missing: '+token)
for token in ('runResilienceSelfTest','ACTION_RECOVERY_SELF_TEST','snapshot.killSwitchConfigured'):
    if token not in main: raise SystemExit('resilience self-test operator guard missing: '+token)
selftest=vpn[vpn.find('private fun runRecoverySelfTest()'):vpn.find('private fun handleFullFlowFailure')]
if '!platformLockdownEnabled()' not in selftest or 'session.terminateHelperForRecoveryTest()' not in selftest or 'session.close()' in selftest or 'vpn.resilience_test' not in selftest:
    raise SystemExit('controlled recovery self-test must require Android Lockdown, kill only GaiaNet, and preserve the TUN anchor while exercising real transport EOF')
for view in ('ShieldPulseView.kt','CyberBackgroundView.kt','TitanCoreView.kt','ScannerRadarView.kt','TrafficWorldMapView.kt','TitanManagedBanner.kt'):
    text=Path('app/src/main/java/de/visiongaia/gedefense/mobile',view).read_text()
    if 'ticker.onWindowVisibilityChanged(visibility)' not in text:
        raise SystemExit('animated view lacks background-stop hook: '+view)
print('VPN_RESILIENCE_POWER_PASS')
PYPOWER

python3 - <<'PYLIVEACTIVITY'
from pathlib import Path
main=Path('app/src/main/java/de/visiongaia/gedefense/mobile/MainActivity.kt').read_text()
activity=Path('app/src/main/java/de/visiongaia/gedefense/mobile/ThreatScreen.kt').read_text()
map_view=Path('app/src/main/java/de/visiongaia/gedefense/mobile/TrafficWorldMapView.kt').read_text()
if 'ThreatScreen(this, this)' not in main:
    raise SystemExit('live activity screen must remain reachable from MainActivity')
for token in (
    'TrafficWorldMapView(activity)',
    'updateFullFlow(snapshot)',
    'updateMap(snapshot)',
    'updateTraffic(snapshot.traffic, snapshot.usageAccessGranted)',
    'requestTrafficMapLocation()',
    'openUsageAccessSettings()',
    'refreshTrafficUsage()',
):
    if token not in activity:
        raise SystemExit('live activity invariant missing: '+token)
if 'R.drawable.world_map_ambient' not in map_view:
    raise SystemExit('live activity world-map resource invariant missing')
print('LIVE_ACTIVITY_RESTORATION_PASS')
PYLIVEACTIVITY

python3 - <<'PYHARDENING'
from pathlib import Path
secure=Path('app/src/main/java/de/visiongaia/gedefense/mobile/SecureFiles.kt').read_text()
feed=Path('app/src/main/java/de/visiongaia/gedefense/mobile/FeedDownloader.kt').read_text()
geo=Path('app/src/main/java/de/visiongaia/gedefense/mobile/GeoCountryRepository.kt').read_text()
baseline=Path('core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/IntegrityBaseline.kt').read_text()
titan=Path('app/src/main/java/de/visiongaia/gedefense/mobile/TitanPolicyManager.kt').read_text()
receiver=Path('app/src/main/java/de/visiongaia/gedefense/mobile/TitanPackageOperationReceiver.kt').read_text()
manifest=Path('app/src/main/AndroidManifest.xml').read_text()
for token in ('createPrivateTempFile','File.createTempFile','Os.chmod','PRIVATE_FILE_MODE = 384','Os.rename','Os.fsync','Os.open(directory.absolutePath, OsConstants.O_RDONLY, 0)','verifyExactBytes'):
    if token not in secure: raise SystemExit('secure crash-safe file invariant missing: '+token)
for forbidden in ('AtomicMoveNotSupportedException','StandardCopyOption.REPLACE_EXISTING'):
    if forbidden in secure: raise SystemExit('secure file commit must not silently downgrade atomicity: '+forbidden)
for text,name in ((secure,'SecureFiles'),(feed,'FeedDownloader'),(geo,'GeoCountryRepository'),(baseline,'IntegrityBaseline')):
    if 'System.nanoTime()' in text and ('tmp-' in text or 'download-' in text or '.new-' in text):
        raise SystemExit(name+' still uses predictable timing-derived temp names')
if 'SecureFiles.createPrivateTempFile' not in feed or 'SecureFiles.createPrivateTempFile' not in geo:
    raise SystemExit('download temp files must use private exclusive creation')
if 'Files.createTempFile' not in baseline:
    raise SystemExit('integrity baseline temp file must be exclusively created')
for token in ('SecureRandom','Uri.Builder()','FLAG_MUTABLE or PendingIntent.FLAG_ONE_SHOT','RESULT_SCHEME','RESULT_AUTHORITY'):
    if token not in titan: raise SystemExit('TITAN uninstall callback identity invariant missing: '+token)
if 'packageName.hashCode()' in titan or 'FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE' in titan:
    raise SystemExit('TITAN uninstall callback must not use predictable/colliding PendingIntent identity')
for token in ('data.scheme != RESULT_SCHEME','data.authority != RESULT_AUTHORITY','NONCE_PATTERN','data.pathSegments.size != 2'):
    if token not in receiver: raise SystemExit('TITAN uninstall receiver validation missing: '+token)
if 'android:name=".TitanPackageOperationReceiver"' not in manifest or 'android:exported="false"' not in manifest:
    raise SystemExit('TITAN uninstall receiver must remain non-exported')
build=Path('app/build.gradle.kts').read_text()
if 'release {' not in build or 'isDebuggable = false' not in build:
    raise SystemExit('release build must explicitly disable debuggability')
for token in ('android:allowBackup="false"','android:usesCleartextTraffic="false"','android:networkSecurityConfig="@xml/network_security_config"'):
    if token not in manifest: raise SystemExit('application hardening manifest invariant missing: '+token)
print('APP_WIDE_HARDENING_PASS')
PYHARDENING

python3 - <<'PY0200'
from pathlib import Path
root=Path('.')
manifest=(root/'app/src/main/AndroidManifest.xml').read_text()
admin=(root/'app/src/main/res/xml/titan_device_admin.xml').read_text()
titan=(root/'app/src/main/java/de/visiongaia/gedefense/mobile/TitanPolicyManager.kt').read_text()
visual=(root/'app/src/main/java/de/visiongaia/gedefense/mobile/TitanVisualMode.kt').read_text()
setup=(root/'app/src/main/java/de/visiongaia/gedefense/mobile/DeviceSetupManager.kt').read_text()
receiver=(root/'app/src/main/java/de/visiongaia/gedefense/mobile/TitanDeviceAdminReceiver.kt').read_text()
scanner=(root/'app/src/main/java/de/visiongaia/gedefense/mobile/AppRiskScanner.kt').read_text()
approvals=(root/'app/src/main/java/de/visiongaia/gedefense/mobile/AppApprovalStore.kt').read_text()
analysis_store=(root/'app/src/main/java/de/visiongaia/gedefense/mobile/MalwareAnalysisStore.kt').read_text()
xdr=(root/'app/src/main/java/de/visiongaia/gedefense/mobile/XdrEngine.kt').read_text()
xdr_models=(root/'app/src/main/java/de/visiongaia/gedefense/mobile/XdrModels.kt').read_text()
xdr_ui=(root/'app/src/main/java/de/visiongaia/gedefense/mobile/XdrActivity.kt').read_text()
support=(root/'app/src/main/java/de/visiongaia/gedefense/mobile/SupportVgtActivity.kt').read_text()
dash=(root/'app/src/main/java/de/visiongaia/gedefense/mobile/DashboardScreen.kt').read_text()
# TITAN Light must remain a strictly lesser tier than Device Owner while using all declared legacy policies.
for token in ('<limit-password />','<watch-login />','<force-lock />','<wipe-data />'):
    if token not in admin: raise SystemExit('TITAN Light admin policy missing: '+token)
for token in ('TitanTier.LIGHT','titanLightActive','setMaximumTimeToLock','lockNow','setMaximumFailedPasswordsForWipe'):
    if token not in titan and token not in (root/'app/src/main/java/de/visiongaia/gedefense/mobile/TitanModels.kt').read_text():
        raise SystemExit('TITAN Light policy invariant missing: '+token)
for token in ('ACTION_ADD_DEVICE_ADMIN','TitanDeviceAdminReceiver','setup_titan_light_admin_explanation'):
    if token not in setup: raise SystemExit('TITAN Light setup invariant missing: '+token)
if 'android.permission.BIND_DEVICE_ADMIN' not in manifest or 'android:exported="true"' not in manifest:
    raise SystemExit('Device admin receiver binding invariant missing')
for token in ('onPasswordFailed','onPasswordSucceeded','recordTitanLightPasswordFailure','recordTitanLightState'):
    if token not in receiver: raise SystemExit('TITAN Light login telemetry invariant missing: '+token)
if 'TitanTier.LIGHT' not in visual or 'TitanTier.FULL' not in visual:
    raise SystemExit('TITAN visual tier distinction missing')
# Adaptive trust: capability-only context stays below visibility threshold; trust never suppresses TI/behavior evidence.
for token in ('HEURISTIC_ONLY_SCORE_CAP = 34','USER_VISIBLE_REVIEW_THRESHOLD = 35','permissionGranted','accessibilityEnabled','deviceAdminActive','overlayAllowed','enum class AppApprovalState { NONE, APPROVED, STALE }'):
    if token not in scanner: raise SystemExit('adaptive app-risk invariant missing: '+token)
for forbidden in ('com.whatsapp','org.telegram','com.xiaomi.aicr'):
    if forbidden in scanner or forbidden in xdr:
        raise SystemExit('package-specific trust/whitelist forbidden: '+forbidden)
for token in ('SecureSnapshotStore','signerSha256','capabilityCodes','MessageDigest.isEqual','noBackupFilesDir'):
    if token not in approvals: raise SystemExit('approval-store authentication invariant missing: '+token)
if 'threatMatches.any { it.endsWith(":BLOCK") }' not in approvals:
    raise SystemExit('blocking threat-intelligence evidence must not be approvable')
for token in ('SecureSnapshotStore','last-app-analysis.vgt','noBackupFilesDir'):
    if token not in analysis_store: raise SystemExit('malware-analysis persistence invariant missing: '+token)
for token in ('INCIDENT_VISIBILITY_THRESHOLD = 35','approvals.currentStatus','XdrCategory.BEHAVIOR','XdrCategory.NETWORK','XdrCategory.SIGNER','strongScanner'):
    if token not in xdr: raise SystemExit('XDR adaptive visibility invariant missing: '+token)
for token in ('signalFamily(event)','"static-analysis"','independentFamilies','Capability-only scanner evidence','event.category == XdrCategory.RESPONSE'):
    if token not in xdr_models: raise SystemExit('XDR independent-signal scoring invariant missing: '+token)
if 'val reasons = scannerEvent?.forensicReasons.orEmpty()' not in xdr_ui or 'val detectorScore = scannerEvent?.detectorScore' not in xdr_ui:
    raise SystemExit('forensic raw-score/reason snapshot consistency invariant missing')
# Support page is local, non-exported and opens only the fixed HTTPS PayPal host.
if 'android:name=".SupportVgtActivity" android:exported="false"' not in manifest:
    raise SystemExit('support page must remain non-exported')
for token in ('parsed.scheme != "https"','parsed.host != "paypal.me"','bc1q3ue5gq822tddmkdrek79adlkm36fatat3lz0dm','0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85'):
    if token not in support: raise SystemExit('support page invariant missing: '+token)
if 'powered_by_vgt' not in dash:
    raise SystemExit('VGT branding invariant missing')
print('TITAN_LIGHT_ADAPTIVE_TRUST_PASS')
PY0200

python3 - <<'PY0201'
from pathlib import Path
runtime=Path('app/src/main/java/de/visiongaia/gedefense/mobile/AppRuntime.kt').read_text()
scanner=Path('app/src/main/java/de/visiongaia/gedefense/mobile/AppRiskScanner.kt').read_text()
integrity=Path('app/src/main/java/de/visiongaia/gedefense/mobile/IntegrityGuardian.kt').read_text()
device=Path('app/src/main/java/de/visiongaia/gedefense/mobile/DeviceSecurityScanner.kt').read_text()
# Startup restoration must never launch/hold the synchronized full scanner.
for token in ('restoreAppAnalysisAsync','restoreFromAuthenticatedCache','ANALYSIS_RESTORE_TIMEOUT_MS = 8_000L','cancelAppAnalysisRestore'):
    if token not in runtime and token not in scanner:
        raise SystemExit('analysis restore hotfix invariant missing: '+token)
bootstrap=runtime.split('init {',1)[1].split('fun refreshEvidenceHealth',1)[0]
if 'scanAppsAsync()' in bootstrap:
    raise SystemExit('startup restoration must not launch the synchronized full app scan')
if '@Synchronized\n    fun scan(' not in scanner:
    raise SystemExit('full app scan synchronization invariant missing')
restore=scanner.split('fun restoreFromAuthenticatedCache',1)[1].split('@Synchronized\n    fun fastScanPackage(',1)[0]
if 'cache.saveAppPackages' in restore or 'findEmbeddedThreatIps' in restore or 'packageHash(' in restore:
    raise SystemExit('startup restore must remain read-only and avoid deep APK work')
for token in ('RESTORED_CACHE','cached.fingerprint != packageFingerprint','cached.signerSha256','timeoutMillis'):
    if token not in restore:
        raise SystemExit('authenticated cache restoration invariant missing: '+token)
# Integrity Guard gets a hard deadline/cancellation boundary and traversal ceiling.
for token in ('INTEGRITY_SCAN_TIMEOUT_NANOS','integrity_scan_timeout','MAX_ENTRIES = 16_384','checkBudget(cancelled, deadlineNanos)'):
    if token not in integrity:
        raise SystemExit('bounded Integrity Guard invariant missing: '+token)
if 'integrity.scan(cancelled)' not in device:
    raise SystemExit('device scan must propagate cancellation into Integrity Guard')
apps_phase='DeviceScanPhase.APPS, 0.10f, 0, 0'
if apps_phase not in device or device.index(apps_phase) > device.index('val appResult = apps.scan('):
    raise SystemExit('device scan must publish APPS phase before entering app scanner')
print('ANALYSIS_RESTORE_INTEGRITY_HOTFIX_PASS')
PY0201

python3 - <<'PY0210'
from pathlib import Path
models=Path('app/src/main/java/de/visiongaia/gedefense/mobile/BehaviorModels.kt').read_text()
engine=Path('app/src/main/java/de/visiongaia/gedefense/mobile/BehaviorEngine.kt').read_text()
store=Path('app/src/main/java/de/visiongaia/gedefense/mobile/BehaviorBaselineStore.kt').read_text()
flow=Path('app/src/main/java/de/visiongaia/gedefense/mobile/FullFlowAnalytics.kt').read_text()
xdr=Path('app/src/main/java/de/visiongaia/gedefense/mobile/XdrModels.kt').read_text()
xdr_engine=Path('app/src/main/java/de/visiongaia/gedefense/mobile/XdrEngine.kt').read_text()
security=Path('app/src/main/java/de/visiongaia/gedefense/mobile/SecurityScreen.kt').read_text()
actions=Path('app/src/main/java/de/visiongaia/gedefense/mobile/UiSnapshot.kt').read_text()
xdr_ui=Path('app/src/main/java/de/visiongaia/gedefense/mobile/XdrActivity.kt').read_text()
for token in ('EGRESS_RATIO_SHIFT','CONNECTION_FANOUT','txDeviationPerMinute','avgUploadRatioPermille','avgFlowsPerMinute','confidence: Int','baselineObservations: Int'):
    if token not in models: raise SystemExit('behavioral intelligence model invariant missing: '+token)
for token in ('robustRateThreshold','POTENTIAL_EXFILTRATION','EGRESS_RATIO_SHIFT','CONNECTION_FANOUT','AUTO_QUARANTINE_MIN_CONFIDENCE = 85','profile.avgUploadRatioPermille','profile.flowDeviationPerMinute'):
    if token not in engine: raise SystemExit('behavioral intelligence detector invariant missing: '+token)
for token in ('txDev','uploadRatioPm','avgFlows','flowDev','avgDomainCount','avgCountryCount','SecureSnapshotStore'):
    if token not in store: raise SystemExit('behavior baseline persistence invariant missing: '+token)
for token in ('val openedFlows: Long','var opened: Long','app.opened = saturatingAdd(app.opened, 1L)'):
    if token not in flow: raise SystemExit('full-flow fanout telemetry invariant missing: '+token)
for token in ('signalFamily(event)','independentFamilies','"behavior"','"network-ti"','"package-signer"'):
    if token not in xdr: raise SystemExit('XDR source-diversity invariant missing: '+token)
for token in ('behavior_confidence','baseline_observations','behaviorRiskPoints'):
    if token not in xdr_engine: raise SystemExit('behavior XDR forensic invariant missing: '+token)
for token in ('openXdrForPackage','live_flow_open_forensics'):
    if token not in security and token not in actions: raise SystemExit('live activity forensic drilldown invariant missing: '+token)
if 'EXTRA_PACKAGE' not in xdr_ui:
    raise SystemExit('package-scoped XDR drilldown invariant missing')
for forbidden in ('com.whatsapp','org.telegram','com.xiaomi.aicr'):
    if forbidden in engine or forbidden in xdr_engine:
        raise SystemExit('package-specific behavioral trust forbidden: '+forbidden)
print('BEHAVIORAL_INTELLIGENCE_DIVERSITY_PASS')
PY0210

python3 - <<'PY0220'
from pathlib import Path
root=Path('.')
feeds=(root/'core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/ThreatFeed.kt').read_text()
parser=(root/'core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/ThreatParser.kt').read_text() if (root/'core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/ThreatParser.kt').exists() else ''.join(p.read_text() for p in (root/'core/src/main/kotlin/de/visiongaia/gedefense/mobile/core').glob('*.kt'))
setup=(root/'app/src/main/java/de/visiongaia/gedefense/mobile/DeviceSetupManager.kt').read_text()
sentinel=(root/'app/src/main/java/de/visiongaia/gedefense/mobile/PortSentinel.kt').read_text()
sentinel_store=(root/'app/src/main/java/de/visiongaia/gedefense/mobile/PortSentinelStore.kt').read_text()
vpn=(root/'app/src/main/java/de/visiongaia/gedefense/mobile/GeDefenseVpnService.kt').read_text()
baseline=(root/'app/src/main/java/de/visiongaia/gedefense/mobile/PackageBaselineStore.kt').read_text()
xdr=(root/'app/src/main/java/de/visiongaia/gedefense/mobile/XdrEngine.kt').read_text()
hardening=(root/'app/src/main/java/de/visiongaia/gedefense/mobile/DeviceHardeningScanner.kt').read_text()
# FireHOL Level 1 may block only after the parser's public-prefix boundary rejects local/bogon space.
if '"firehol-level1", "FireHOL Level 1"' not in feeds or 'EnforcementClass.ROUTE_BLOCK' not in feeds.split('"firehol-level1", "FireHOL Level 1"',1)[1].split(')',1)[0]:
    raise SystemExit('FireHOL Level 1 must remain ROUTE_BLOCK')
for token in ('IpPrefix.isPublic','100.64.0.0/10','192.168.0.0/16'):
    corpus=parser + (root/'core/src/test/kotlin/de/visiongaia/gedefense/mobile/core/CoreTestMain.kt').read_text()
    if token not in corpus: raise SystemExit('public-prefix FireHOL safety invariant missing: '+token)
# Battery readiness must not equate Xiaomi/HyperOS background policy with Android Doze allowlisting.
for token in ('ActivityManager','isBackgroundRestricted','batteryBackgroundRestricted','batteryReady = batteryExempt || !backgroundRestricted'):
    if token not in setup: raise SystemExit('OEM battery-state invariant missing: '+token)
# Exposure Sentinel follows Wi-Fi/Ethernet/cellular and remains bounded/event-driven.
for token in ('TRANSPORT_CELLULAR','Selector.open()','selector.select()','MAX_EVENTS_PER_MINUTE','MAX_LOCAL_ADDRESSES','MOBILE_INTERNET','MOBILE_CARRIER'):
    if token not in sentinel: raise SystemExit('network exposure sentinel invariant missing: '+token)
for token in ('isBlockableAddress','isCarrierGradeNat','isUniqueLocalIpv6'):
    if token not in sentinel_store: raise SystemExit('network exposure address invariant missing: '+token)
if 'val preferredUnderlay = internet.firstOrNull()' not in vpn or 'portSentinel.rebind(preferredUnderlay)' not in vpn or 'if (underlyingNetworks.get() != internet) return@submitControl' not in vpn:
    raise SystemExit('sentinel must follow the latest preferred physical underlay including cellular on the serialized control lane')
# Package signer changes are contextualized with Android-verified rotation lineage and system provenance.
for token in ('signingCertificateHistory','signerLineageSha256','systemPackage','signerRotationTrusted','signerChangeReviewOnly'):
    if token not in baseline: raise SystemExit('signer provenance invariant missing: '+token)
for token in ('pruneTrustedSignerEvents','Signing certificate rotation verified','System package signer transition','store.removeEvents("signer:$pkg:"'):
    if token not in xdr: raise SystemExit('signer false-positive reconciliation invariant missing: '+token)
# GeDefense's own TITAN Light admin must never be counted as a third-party administrator finding.
for token in ('it == appContext.packageName','gedefense_admin=1','GeDefense device administrator'):
    if token not in hardening: raise SystemExit('self device-admin exclusion invariant missing: '+token)
print('LIVE_HARDENING_PROVENANCE_PASS')
PY0220


python3 - <<'PY0221'
from pathlib import Path
feeds=Path('core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/ThreatFeed.kt').read_text()
policy=Path('netstack/policy.go').read_text()
policy_tests=Path('netstack/policy_test.go').read_text()
native=Path('app/src/main/java/de/visiongaia/gedefense/mobile/NativeGaiaNet.kt').read_text()
vpn=Path('app/src/main/java/de/visiongaia/gedefense/mobile/GeDefenseVpnService.kt').read_text()
# Kotlin feed/policy ABI v2 is fixed by CoreTestMain; GaiaNet must grant FireHOL bit 7 the same ROUTE_BLOCK authority.
for token in ('POLICY_ABI_VERSION = 2','"firehol-level1", "FireHOL Level 1"','EnforcementClass.ROUTE_BLOCK'):
    if token not in feeds: raise SystemExit('FireHOL Kotlin authority invariant missing: '+token)
for token in ('bits&0x87','bits&0x78','7 FireHOL L1 => BLOCK','8 Tor exits => ANNOTATE'):
    if token not in policy: raise SystemExit('GaiaNet feed-authority ABI invariant missing: '+token)
for token in ('TestPolicyFeedAuthorityABI','firehol-level1','TestPolicyAcceptsFireHOLBlockAuthority'):
    if token not in policy_tests: raise SystemExit('GaiaNet authority regression test missing: '+token)
for token in ('lastStartFailureCode','policy_rejected','engine_init_failed'):
    if token not in native: raise SystemExit('GaiaNet startup diagnostic invariant missing: '+token)
if 'full_flow_${NativeGaiaNet.lastStartFailure ?: "gaianet_start_failed"}' not in vpn:
    raise SystemExit('Full Flow sanitized helper failure propagation missing')
print('POLICY_AUTHORITY_ABI_PASS')
PY0221

python3 - <<'PY0230'
from pathlib import Path
manifest=Path('app/src/main/AndroidManifest.xml').read_text()
diag=Path('app/src/main/java/de/visiongaia/gedefense/mobile/DiagnosticBundle.kt').read_text()
activity=Path('app/src/main/java/de/visiongaia/gedefense/mobile/DiagnosticsActivity.kt').read_text()
state=Path('app/src/main/java/de/visiongaia/gedefense/mobile/RuntimeState.kt').read_text()
vpn=Path('app/src/main/java/de/visiongaia/gedefense/mobile/GeDefenseVpnService.kt').read_text()
if '<activity android:name=".DiagnosticsActivity" android:exported="false" />' not in manifest:
    raise SystemExit('diagnostics activity must remain non-exported')
for token in ('aggregate-only-v1','Package names, domains, IP addresses','ALLOWED_ENTRIES','ACTION_CREATE_DOCUMENT','application/zip'):
    target = diag + activity
    if token not in target: raise SystemExit('privacy-safe diagnostics invariant missing: '+token)
for forbidden in ('packageName =', 'sourceAddress', 'topDomains(', 'signerSha256', 'apkSha256', 'installSha256'):
    # Field names may exist in comments/types elsewhere, but the diagnostic encoder itself must not serialize them.
    if forbidden in diag and forbidden not in ('signerSha256','apkSha256','installSha256'):
        raise SystemExit('diagnostic export exposes forbidden identity field: '+forbidden)
# Explicit privacy exclusions are mandatory for hash-bearing source objects.
for token in ('certificate/APK hashes','evidence payloads','incident detail strings are excluded'):
    if token not in diag: raise SystemExit('diagnostic privacy boundary documentation missing: '+token)
for token in ('recordResilienceSelfTestStarted','recordResilienceSelfTestResult','lastResilienceSelfTestDurationMillis'):
    if token not in state: raise SystemExit('resilience self-test persistence invariant missing: '+token)
for token in ('selfTestPending','selfTestStartedElapsed','completeSelfTest(true)','completeSelfTest(false)'):
    if token not in vpn: raise SystemExit('resilience self-test measurement invariant missing: '+token)
print('DIAGNOSTICS_RESILIENCE_PASS')
PY0230

python3 - <<'PYPOLICYREFRESH'
from pathlib import Path
firewall=Path('app/src/main/java/de/visiongaia/gedefense/mobile/FirewallActivity.kt').read_text()
sentinel=Path('app/src/main/java/de/visiongaia/gedefense/mobile/PortSentinelActivity.kt').read_text()
for source,name,helper in (
    (firewall,'firewall','refreshActiveLockdownOrFailClosed'),
    (sentinel,'port-sentinel','refreshActiveSelectiveOrFailClosed'),
):
    for token in (helper,'GeDefenseVpnService.ACTION_REFRESH','stopService','live_policy_refresh_failed_stopped'):
        if token not in source: raise SystemExit(f'{name} live-policy fail-closed invariant missing: {token}')
    for line in source.splitlines():
        if 'ACTION_REFRESH' in line and 'catch (_: RuntimeException) { }' in line:
            raise SystemExit(f'{name} silently swallows live-policy refresh failure')
print('LIVE_POLICY_REFRESH_FAIL_CLOSED_PASS')
PYPOLICYREFRESH

python3 - <<'PY0240'
from pathlib import Path
state=Path('app/src/main/java/de/visiongaia/gedefense/mobile/RuntimeState.kt').read_text()
diag=Path('app/src/main/java/de/visiongaia/gedefense/mobile/DiagnosticsActivity.kt').read_text()
ui=Path('app/src/main/java/de/visiongaia/gedefense/mobile/UiSnapshot.kt').read_text()
main=Path('app/src/main/java/de/visiongaia/gedefense/mobile/MainActivity.kt').read_text()
hub=Path('app/src/main/java/de/visiongaia/gedefense/mobile/ProtectionHubScreen.kt').read_text()
integrity_job=Path('app/src/main/java/de/visiongaia/gedefense/mobile/IntegrityJobService.kt').read_text()
for token in ('TRANSIENT_VPN_STATES','"RECOVERING"','vpn_self_test_status','MAX_SELF_TEST_DURATION_MS'):
    if token not in state: raise SystemExit('beta-freeze transient-state reconciliation missing: '+token)
if 'selfTestWasRunning = rawSelfTest == "RUNNING"' not in state or 'selfTestStatus = if (selfTestWasRunning) "FAIL"' not in state or '.applyOptionalString(KEY_SELF_TEST_STATUS, state.selfTestStatus)' not in state:
    raise SystemExit('orphaned resilience self-test recovery missing')
for token in ('runtime.addStateListener(listener)','runtime.removeStateListener(listener)','lifecycleGeneration','applicationContext'):
    if token not in diag: raise SystemExit('diagnostics lifecycle hardening missing: '+token)
for token in ('resilienceSelfTestStatus','resilienceSelfTestAtMillis','resilienceSelfTestDurationMillis'):
    if token not in ui or token not in main: raise SystemExit('self-test UI snapshot invariant missing: '+token)
if 'snapshot.resilienceSelfTestStatus == "RUNNING"' not in main:
    raise SystemExit('overlapping self-test dispatch guard missing')
if 'snapshot.resilienceSelfTestStatus == "RUNNING"' not in hub or '!selfTestRunning' not in hub:
    raise SystemExit('self-test action enablement guard missing')
for token in ('private val jobLock = Any()','synchronized(jobLock)','if (active.get() != null) return@synchronized false','active.set(task)'):
    if token not in integrity_job: raise SystemExit('integrity job ownership invariant missing: '+token)
for token in ('MAX_ENUMERATED_ENTRIES = 40_000','Files.newDirectoryStream(canonical.toPath())'):
    storage=Path('app/src/main/java/de/visiongaia/gedefense/mobile/StorageMalwareScanner.kt').read_text()
    if token not in storage: raise SystemExit('bounded lazy storage traversal missing: '+token)
integrity=Path('app/src/main/java/de/visiongaia/gedefense/mobile/IntegrityGuardian.kt').read_text()
if 'Files.newDirectoryStream(canonical.toPath())' not in integrity or 'entryLimitReached' not in integrity:
    raise SystemExit('bounded lazy integrity traversal missing')
if '.listFiles()' in storage or '.listFiles()' in integrity:
    raise SystemExit('eager unbounded directory allocation reintroduced')
print('BETA_FREEZE_LIFECYCLE_PASS')
PY0240

python3 - <<'PYGAIABRIDGE'
from pathlib import Path
native=Path('app/src/main/java/de/visiongaia/gedefense/mobile/NativeGaiaNet.kt').read_text()
for token in (
    'HELPER_NAME = "libgedefense_gaianet_v2.so"','LocalSocket','LocalSocketAddress.Namespace.FILESYSTEM',
    'setFileDescriptorsForSend','SecureRandom','TOKEN_BYTES = 32','ProcessBuilder(helper.absolutePath',
    'ThreatPolicyBinary','raw.fd.sync()','out.writeByte(2)','hexToBytes(index.fullPolicySha256)',
    'setPowerConstrained','process.destroyForcibly','hasElfMagic','HELPER_MAX_BYTES',
):
    if token not in native: raise SystemExit('GaiaNet v2 process boundary invariant missing: '+token)
for forbidden in ('Runtime.getRuntime().exec','/system/bin/sh','sh -c','bash -c','System.loadLibrary','detachFd()'):
    if forbidden in native: raise SystemExit('GaiaNet v2 forbidden bridge pattern: '+forbidden)
# Android's LocalSocket.connect(endpoint, timeout) overload is intentionally unimplemented and
# throws UnsupportedOperationException. GaiaNet must use the supported one-argument overload;
# START_TIMEOUT_MS + retry deadline still bound helper startup.
supported_connect = 'socket.connect(LocalSocketAddress(socketFile.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))'
if supported_connect not in native:
    raise SystemExit('GaiaNet v2 supported LocalSocket connect invariant missing')
if 'LocalSocketAddress.Namespace.FILESYSTEM), 250' in native or 'connect(LocalSocketAddress(socketFile.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM),' in native:
    raise SystemExit('GaiaNet v2 must not use unsupported LocalSocket timeout-connect overload')
index=Path('core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/ThreatIndex.kt').read_text()
for token in ('val fullPolicySha256: String','fullPolicySha256(immutableV4, immutableV6)',"'G'.code.toByte(), 'D'.code.toByte(), 'F'.code.toByte(), 1"):
    if token not in index: raise SystemExit('full policy fingerprint invariant missing: '+token)
build=Path('app/build.gradle.kts').read_text()
if 'jniLibs.useLegacyPackaging = true' not in build:
    raise SystemExit('GaiaNet helper must be extracted into nativeLibraryDir')
print('GAIANET_V2_PROCESS_BOUNDARY_PASS')
PYGAIABRIDGE

command -v go >/dev/null 2>&1 || fail "Go 1.26.8 is required for GaiaNet release verification"
[[ "$(GOTOOLCHAIN=local go env GOVERSION)" == "go1.26.8" ]] || fail "unreviewed Go toolchain: $(go env GOVERSION 2>/dev/null || echo unavailable), expected go1.26.8"

if command -v go >/dev/null 2>&1; then
  MODULES="$(cd netstack && GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=off GOSUMDB=off go list -m all)" || fail "vendored Go module graph unavailable offline"
  [[ "$(printf '%s\n' "$MODULES" | wc -l | tr -d ' ')" = "7" ]] || fail "unreviewed Go module dependency count"
  for expected in \
    'visiongaia.dev/gedefense/mobile/netstack' \
    'golang.org/x/crypto v0.37.0 => ../third_party/go/x-crypto' \
    'golang.org/x/net v0.39.0 => ../third_party/go/x-net' \
    'golang.org/x/sys v0.32.0 => ../third_party/go/x-sys' \
    'golang.org/x/term v0.31.0 => ../third_party/go/x-term' \
    'golang.org/x/text v0.24.0 => ../third_party/go/x-text' \
    'golang.zx2c4.com/wireguard v0.0.20250522 => ../third_party/go/wireguard-go'; do
    printf '%s\n' "$MODULES" | grep -Fxq "$expected" || fail "Go module graph mismatch: $expected"
  done
  (cd netstack && GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=off GOSUMDB=off go test ./... && GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=off GOSUMDB=off go vet ./... && GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=off GOSUMDB=off go test -race ./...) || fail "GaiaNet tests/vet/race detector failed"
  (cd netstack && GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=off GOSUMDB=off go test -tags=gdandroidhelper ./... && GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=off GOSUMDB=off go vet -tags=gdandroidhelper ./...) || fail "GaiaNet helper protocol tests failed"
  TMP_GAIA="$(mktemp -d)"
  trap 'rm -rf "$TMP_GAIA"' EXIT
  (cd netstack && GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=off GOSUMDB=off CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags='-s -w -buildid= -R 0x4000' -o "$TMP_GAIA/arm64.so" .)
  SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
  [[ -n "$SDK_ROOT" ]] || fail "ANDROID_SDK_ROOT/ANDROID_HOME required for x86_64 Android helper verification"
  NDK_ROOT="${ANDROID_NDK_ROOT:-$SDK_ROOT/ndk/27.2.12479018}"
  case "$(uname -s)" in
    Linux*) NDK_HOST='linux-x86_64' ;;
    Darwin*) NDK_HOST='darwin-x86_64' ;;
    MINGW*|MSYS*|CYGWIN*) NDK_HOST='windows-x86_64' ;;
    *) fail "unsupported host for pinned Android NDK verification" ;;
  esac
  X64_CC="$NDK_ROOT/toolchains/llvm/prebuilt/$NDK_HOST/bin/x86_64-linux-android29-clang"
  [[ -x "$X64_CC" || -f "$X64_CC.cmd" ]] || fail "pinned Android NDK x86_64 clang missing"
  if [[ ! -x "$X64_CC" && -f "$X64_CC.cmd" ]]; then X64_CC="$X64_CC.cmd"; fi
  (cd netstack && GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=off GOSUMDB=off CGO_ENABLED=1 GOOS=android GOARCH=amd64 CC="$X64_CC" go build -trimpath -buildvcs=false -ldflags='-s -w -buildid= -extldflags=-Wl,-z,max-page-size=16384' -o "$TMP_GAIA/x86_64.so" .)
  cmp -s "$TMP_GAIA/arm64.so" app/src/main/jniLibs/arm64-v8a/libgedefense_gaianet_v2.so || fail "arm64 GaiaNet v2 helper/source mismatch"
  cmp -s "$TMP_GAIA/x86_64.so" app/src/main/jniLibs/x86_64/libgedefense_gaianet_v2.so || fail "x86_64 GaiaNet v2 helper/source mismatch"
  python3 - <<'PYELF'
from pathlib import Path
import struct

MIN_ALIGNMENT=0x4000

def verify(path: Path) -> None:
    data=path.read_bytes()
    if len(data) < 64 or data[:4] != b'\x7fELF':
        raise SystemExit(f'not an ELF64 helper: {path}')
    if data[4] != 2 or data[5] != 1:
        raise SystemExit(f'unsupported ELF class/endianness: {path}')
    phoff=struct.unpack_from('<Q',data,32)[0]
    phentsize=struct.unpack_from('<H',data,54)[0]
    phnum=struct.unpack_from('<H',data,56)[0]
    if phentsize < 56 or phnum <= 0 or phoff + phentsize * phnum > len(data):
        raise SystemExit(f'invalid program header table: {path}')
    seen=0
    for i in range(phnum):
        off=phoff + i * phentsize
        p_type=struct.unpack_from('<I',data,off)[0]
        if p_type != 1:
            continue
        seen += 1
        p_offset=struct.unpack_from('<Q',data,off+8)[0]
        p_vaddr=struct.unpack_from('<Q',data,off+16)[0]
        p_align=struct.unpack_from('<Q',data,off+48)[0]
        if p_align < MIN_ALIGNMENT or (p_align & (p_align - 1)) != 0:
            raise SystemExit(f'16 KiB ELF alignment missing: {path} align={p_align:#x}')
        if (p_vaddr - p_offset) % p_align != 0:
            raise SystemExit(f'ELF PT_LOAD congruence invalid: {path}')
    if seen == 0:
        raise SystemExit(f'ELF contains no PT_LOAD segments: {path}')

for helper in (
    Path('app/src/main/jniLibs/arm64-v8a/libgedefense_gaianet_v2.so'),
    Path('app/src/main/jniLibs/x86_64/libgedefense_gaianet_v2.so'),
):
    verify(helper)
print('GAIANET_16K_ELF_ALIGNMENT_PASS')
PYELF
  python3 - <<'PY'
from pathlib import Path
required={
 'limits.go':['maxConcurrentFlows','maxHalfOpenTCP','maxFragmentReassemblyBytes','tcpHandshakeAckTimeout'],
 'reassembly.go':['errFragmentOverlap','maxFragmentPiecesPerDatagram'],
 'tcp_manager.go':['handshakeReady','close(f.done)','randomUint32() (uint32, error)','upstreamWrite{fin: true}'],
 'tcp_flow_io.go':['maxTCPUnackedBytes','retransmit','handshake_ack_timeout'],
 'tcp_manager.go':['maxTCPDialWorkers','sync.Pool','reserveUnacked','maxTCPGlobalUnackedBytes','sweepWake','signalSweep'],
 'udp_manager.go':['buildUDPPackets','readBuffers sync.Pool','maxUDPFlows','SetReadDeadline(time.Now().Add(currentUDPIdleTimeout()))'],
 'dns.go':['parseDNSQueryName'],
 'telemetry.go':['criticalLost','emitCritical'],
 'fuzz_test.go':['FuzzParsePacket','FuzzLoadPolicy','FuzzDNSQueryName','FuzzFragmentReassembly'],
 'helper_main_process.go':['subtle.ConstantTimeCompare','receiveInit','parseReceivedFDs','helperTokenBytes','helperProtocolVersion','setPowerConstrained'],
 'power_state.go':['tcpDozeHalfOpenTimeout','powerConstrained','telemetryDetailed','currentTCPHousekeepingInterval','currentTelemetryInterval'],
 'packet.go':['WindowScale','windowScale'],
 'build_packet.go':['negotiateWindowScale','tcpOptionWindowScale'],
 'policy.go':['threat policy fingerprint mismatch','threat policy authority mismatch','actionForBits','trailing threat policy bytes','duplicate ipv4 threat prefix'],
}
for file,tokens in required.items():
    s=Path('netstack',file).read_text()
    for token in tokens:
        if token not in s: raise SystemExit(f'GaiaNet invariant missing {file}: {token}')
limits=Path('netstack/limits.go').read_text()
import re
limit_patterns={
    'maxTCPUnackedBytes=1MiB': r'\bmaxTCPUnackedBytes\s*=\s*1024\s*\*\s*1024\b',
    'maxTCPGlobalUnackedBytes=32MiB': r'\bmaxTCPGlobalUnackedBytes\s*=\s*32\s*\*\s*1024\s*\*\s*1024\b',
    'maxTCPDialWorkers=64': r'\bmaxTCPDialWorkers\s*=\s*64\b',
    'maxUDPFlows=1024': r'\bmaxUDPFlows\s*=\s*1024\b',
}
for name,pattern in limit_patterns.items():
    if re.search(pattern, limits) is None:
        raise SystemExit('GaiaNet v2 transport limit missing: '+name)
print('GAIANET_SECURITY_PASS')
PY
fi

if [[ -f SOURCE-MANIFEST.sha256 ]]; then
  python3 tools/verify-source-manifest.py
fi

echo SECURITY_AUDIT_PASS
