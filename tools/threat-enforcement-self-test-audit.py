#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[1]

def read(path: str) -> str:
    return (root / path).read_text(encoding='utf-8')

def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)

runtime = read('app/src/main/java/de/visiongaia/gedefense/mobile/AppRuntime.kt')
native = read('app/src/main/java/de/visiongaia/gedefense/mobile/NativeGaiaNet.kt')
diag = read('app/src/main/java/de/visiongaia/gedefense/mobile/DiagnosticsActivity.kt')
snapshot = read('app/src/main/java/de/visiongaia/gedefense/mobile/ThreatEnforcementSelfTest.kt')
strings = read('app/src/main/res/values/strings.xml')

require('runThreatEnforcementSelfTest()' in runtime, 'Threat Policy Self-Test entry point missing')
require('state.protectionMode() != ProtectionMode.FULL_FLOW_BETA' in runtime and 'state.lastVpnStatus() != "FULL_GUARDED"' in runtime,
        'self-test is not gated on guarded Full Flow')
require('index.routePrefixes.first()' in runtime and 'index.match(address)' in runtime,
        'self-test does not exercise loaded ThreatIndex matcher')
require('match.hasBlockingSignal' in runtime and 'blockingFeeds' in runtime,
        'self-test does not verify block authority')
require('index.routePrefixes.any { it.contains(match.address) }' in runtime,
        'self-test does not verify route coverage')
require('NativeGaiaNet.validateThreatPolicySnapshot(index, application.cacheDir)' in runtime,
        'self-test does not exercise production GDTI serializer')
require('ThreatPolicyBinary.create(index, cacheDir)' in native and 'header[4] != 2.toByte()' in native,
        'GDTI serializer/header validation missing')
require('count != index.count' in native and 'fingerprint == index.fullPolicySha256' in native,
        'GDTI count/fingerprint validation missing')
require('No socket is opened' in native or 'No socket is opened' in snapshot,
        'no-egress contract not documented in source')
require('recordBlockedFlow' not in runtime[runtime.index('private fun executeThreatPolicySelfTest'):runtime.index('private fun recordThreatSelfTestImmediateFailure')],
        'self-test pollutes production block metrics')
block = runtime[runtime.index('private fun executeThreatPolicySelfTest'):runtime.index('private fun recordThreatSelfTestImmediateFailure')]
require('evidence.append' not in block and 'recordThreatBlock' not in block,
        'self-test pollutes production Evidence/XDR')
require('java.net.Socket' not in block and 'URL(' not in block,
        'self-test unexpectedly opens network traffic')
require('runThreatEnforcementSelfTest()' in diag and 'diagnostics_threat_self_test_action' in diag,
        'Diagnostics self-test UI missing')
require('Threat policy self-test' in strings and 'TUN capture is outside this self-test' in strings,
        'UI does not state truthful self-test scope')
require('third-party app/TUN capture' in snapshot or 'third-party-app/TUN capture' in snapshot,
        'self-test source does not preserve TUN-capture boundary')

# The no-egress policy test must not require a new GaiaNet control command or native telemetry frame.
for path in ('netstack/helper_main_process.go', 'netstack/engine.go', 'netstack/telemetry.go', 'netstack/policy.go'):
    content = read(path)
    require('threatSelfTest' not in content and 'runThreatPolicySelfTest' not in content,
            f'native transport unexpectedly contains synthetic self-test path: {path}')

print('THREAT_SELF_TEST_AUDIT_PASS no_egress=true loaded_index=true route_authority=true gdti_serializer=true production_metrics_untouched=true tun_capture_claimed=false')
