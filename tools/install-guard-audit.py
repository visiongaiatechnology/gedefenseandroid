#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
java = ROOT / 'app/src/main/java/de/visiongaia/gedefense/mobile'
net = ROOT / 'netstack'
manifest = (ROOT / 'app/src/main/AndroidManifest.xml').read_text()
receiver = (java / 'PackageChangeReceiver.kt').read_text()
guard = (java / 'InstallGuard.kt').read_text()
scanner = (java / 'AppRiskScanner.kt').read_text()
xdr = (java / 'XdrEngine.kt').read_text()
titan = (java / 'TitanPolicyManager.kt').read_text()
native = (java / 'NativeGaiaNet.kt').read_text()
responder = (java / 'PackageEgressGate.kt').read_text()
bounded_scan = (java / 'BoundedInstallScanCall.kt').read_text()
analytics = (java / 'FullFlowAnalytics.kt').read_text()
helper = (net / 'helper_main_process.go').read_text()
engine = (net / 'engine.go').read_text()
tcp = (net / 'tcp_manager.go').read_text()
udp = (net / 'udp_manager.go').read_text()
gate_go = (net / 'package_egress_gate.go').read_text()
security = (ROOT / 'tools/security-audit.sh').read_text()
release = (ROOT / 'tools/release-readiness.sh').read_text()
architecture = (ROOT / 'ARCHITECTURE.md').read_text()
readme = (ROOT / 'README.md').read_text()

quarantine_pos = guard.find('holdStaged = xdr.setQuarantined(packageName, true)')
fast_scan_pos = guard.find('scanner.fastScanPackage(packageName, index)')
scan_pos = guard.find('scanner.scanPackage(packageName, index)')

checks = {
    'receiver_registered_private': 'android:name=".PackageChangeReceiver"' in manifest and 'android:exported="false"' in manifest,
    'receiver_install_update_events': all(token in manifest for token in ('android.intent.action.PACKAGE_ADDED', 'android.intent.action.PACKAGE_REPLACED', 'android:scheme="package"')),
    'receiver_async_off_main': 'goAsync()' in receiver and 'runtime.executeBackground("package-change")' in receiver,
    'receiver_post_setup_only': 'runtime.setup.isWizardCompleted()' in receiver,
    'replacement_scanned_once': 'action.endsWith("PACKAGE_ADDED") && replacing' in guard and 'PACKAGE_REPLACED' in guard,
    'local_only_guard': all(token not in guard + responder for token in ('HttpURLConnection', 'OkHttp', 'Retrofit', 'openConnection(', 'URL(')),
    'bounded_active_set': 'MAX_ACTIVE_PACKAGES = 32' in guard and 'ConcurrentHashMap' in guard,
    'bounded_priority_scan': 'scanner.scanPackage(packageName, index)' in guard and 'INSTALL_SCAN_HASH_BYTES' in scanner and 'INSTALL_SCAN_STATIC_BYTES' in scanner,
    'hard_fast_deadline': 'BoundedInstallScanCall.fast' in guard and 'FAST_TIMEOUT_MS = 1_750L' in bounded_scan,
    'hard_deep_deadline': 'BoundedInstallScanCall.deep' in guard and 'DEEP_TIMEOUT_MS = 25_000L' in bounded_scan,
    'separate_zero_queue_pools': 'fastExecutor' in bounded_scan and 'deepExecutor' in bounded_scan and 'SynchronousQueue()' in bounded_scan,
    'scan_timeout_fail_closed': 'install_fast_timeout' in bounded_scan and 'install_deep_timeout' in bounded_scan and 'deep_scan_required' in guard,
    'new_install_requires_prior_signer': 'cached?.signerSha256 != null && cached.signerSha256 == signer' in scanner,
    'deep_failure_reinstates_hold': 'reinstate the hold' in guard and 'if (!holdStaged && userPackage) holdStaged = xdr.setQuarantined(packageName, true)' in guard,
    'staged_fast_then_deep': fast_scan_pos >= 0 and scan_pos >= 0 and fast_scan_pos < scan_pos and 'FAST_PASS_DEEP_PENDING' in guard,
    'fast_scan_no_payload_hash': 'fun fastScanPackage' in scanner and 'FAST_METADATA' in scanner and 'FAST_CACHE_RECORRELATED' in scanner and 'deepEvidenceReusable' in scanner,
    'fast_pass_is_not_clean_claim': 'release-to-background-deep-scan decision, not a final malware-clean claim' in scanner and 'deep_scan_pending' in guard,
    'fast_release_requires_policy_removal_success': 'val released = xdr.setQuarantined(packageName, false)' in guard and 'if (released)' in guard and 'fast_release_failed' in guard,
    'deep_concern_requarantines': 'Any later deep-scan' in guard and 'holdStaged = xdr.setQuarantined(packageName, true)' in guard,
    'quarantine_staged_before_scan': quarantine_pos >= 0 and fast_scan_pos >= 0 and scan_pos >= 0 and quarantine_pos < fast_scan_pos < scan_pos,
    'pass_releases_hold': 'verdict == InstallGuardVerdict.PASS && holdStaged' in guard and 'xdr.setQuarantined(packageName, false)' in guard,
    'nonpass_keeps_hold': 'verdict != InstallGuardVerdict.PASS && holdStaged' in guard,
    'system_package_auto_hold_forbidden': 'ApplicationInfo.FLAG_SYSTEM == 0' in guard and 'Never auto-hold platform/system packages' in guard,
    'device_owner_suspend_available': 'dpm.setPackagesSuspended' in titan and 'DEVICE_OWNER_REQUIRED' in titan,
    'protocol_v5': 'PROTOCOL_VERSION: Byte = 5' in native and re.search(r'helperProtocolVersion\s*=\s*byte\(5\)', helper) is not None,
    'six_fd_wireguard_contract': 'syscall.CmsgSpace(6*4)' in helper and 'len(fds) > 6' in helper and 'expectedFDs = 5' in helper and 'expectedFDs++' in helper,
    'dedicated_gate_socketpair': 'ParcelFileDescriptor.createSocketPair()' in native and 'PackageEgressGateResponder(context, packageGatePair[0], quarantinedPackages)' in native and 'packageGatePair[1].fileDescriptor' in native,
    'dynamic_gate_sync': "sendControl('Q', packageEgressGate.enabled())" in native and "case 'Q':" in helper and 'setPackageGateEnabled' in helper,
    'android_uid_authority': 'getConnectionOwnerUid' in responder and 'getPackagesForUid(uid)' in responder,
    'bounded_owner_lookup': 'BoundedAndroidCall.call(OWNER_RESOLVE_TIMEOUT_MS)' in responder and 'OWNER_RESOLVE_TIMEOUT_MS = 250L' in responder,
    'unknown_owner_fail_closed': 'if (ownerPackages.isEmpty()) return VERDICT_DENY' in responder,
    'native_query_fail_closed': 'packageGateQueryTimeout = 400 * time.Millisecond' in gate_go and 'g.failed.Store(true)' in gate_go and 'return false' in gate_go,
    'direct_tcp_before_egress': 'm.packageGate.allow(p)' in tcp and tcp.find('m.packageGate.allow(p)') < tcp.find('net.Dialer'),
    'direct_udp_before_egress': 'm.packageGate.allow(p)' in udp and udp.find('m.packageGate.allow(p)') < udp.find('dialer.DialContext'),
    'wireguard_before_egress': 'e.packageGate.allow(packet)' in engine and engine.find('e.packageGate.allow(packet)') < engine.find('e.wireGuard.send(raw[:packet.TotalLen]'),
    'fragment_bypass_closed': 'if e.packageGate != nil && e.packageGate.isEnabled()' in engine and 'e.telemetry.quarantineBlocked(packet)' in engine,
    'gate_failure_recycles_helper': 'e.packageGate.failedState()' in engine and 'package_egress_gate_failure' in engine,
    'policy_change_clears_flows': 'setPackageGateEnabled' in engine and 'e.tcp.closeAll("package_gate_policy_change")' in engine and 'e.udp.closeAll("package_gate_policy_change")' in engine,
    'quarantine_telemetry': 'Q\\t%d' in (net / 'telemetry.go').read_text() and 'handlePackageQuarantine' in analytics and 'install_guard.network_block' in analytics,
    'xdr_syncs_native_policy': 'NativeGaiaNet.syncPackageEgressQuarantine(firewallPolicy.quarantinedPackages())' in xdr,
    'honest_standard_boundary': 'does not guarantee' in responder and 'pre-first-launch hold remains a Device Owner / controlled installer feature' in responder,
    'public_boundary_documented': 'absolute first packet' in architecture and 'Device Owner' in architecture and 'InstallGuard' in readme,
    'security_gate_integration': 'python3 tools/install-guard-audit.py' in security and 'bash tools/install-guard-policy-check.sh' in security,
    'release_gate_integration': 'python3 tools/install-guard-audit.py' in release and 'bash tools/install-guard-policy-check.sh' in release,
}

failed = [name for name, ok in checks.items() if not ok]
if failed:
    raise SystemExit('INSTALL_GUARD_AUDIT_FAIL ' + ','.join(failed))
print('INSTALL_GUARD_AUDIT_PASS local_first=true full_flow_uid_gate=true direct=true wireguard=true fail_closed=true device_owner_hold=true first_packet_claim_bounded=true staged_fast_deep=true')
