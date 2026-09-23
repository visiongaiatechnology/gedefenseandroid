#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "app/src/main/java/de/visiongaia/gedefense/mobile"

runtime = (JAVA / "RuntimeState.kt").read_text()
vpn = (JAVA / "GeDefenseVpnService.kt").read_text()
analytics = (JAVA / "FullFlowAnalytics.kt").read_text()
diagnostics = (JAVA / "DiagnosticBundle.kt").read_text()
vault = (JAVA / "SecureTelemetryVault.kt").read_text()
evidence = (JAVA / "AndroidEvidence.kt").read_text()
xdr = (JAVA / "XdrEventStore.kt").read_text()

# Fresh installs must default to Full Flow. Persisted malformed security modes are corruption and
# must not silently downgrade: RuntimeState.readPersistedEnum throws at that boundary.
full_flow_default = re.search(
    r'readPersistedEnum\(\s*preferences,\s*KEY_PROTECTION_MODE,\s*ProtectionMode\.FULL_FLOW_BETA,',
    runtime,
    re.S,
)
if full_flow_default is None:
    raise SystemExit('FULL_FLOW_AVAILABILITY_FAIL fresh_default_not_full_flow')
if 'persisted security mode invalid' not in runtime or 'persisted security mode missing' not in runtime:
    raise SystemExit('FULL_FLOW_AVAILABILITY_FAIL malformed_mode_not_fail_closed')
if re.search(r'KEY_PROTECTION_MODE[\s\S]{0,220}ProtectionMode\.SELECTIVE', runtime):
    raise SystemExit('FULL_FLOW_AVAILABILITY_FAIL legacy_selective_default_reintroduced')
for token in (
    'SELECTIVE_PLATFORM_ROUTE_BUDGET = 1_024',
    'selective_platform_route_budget_exceeded',
    'selective_route_count_invariant_failed',
    'selective_vpn_establish_failed',
    'selectiveStartFailure',
):
    if token not in vpn:
        raise SystemExit(f'FULL_FLOW_AVAILABILITY_FAIL selective_route_gate={token}')
if '"route_install_failed"' in vpn:
    raise SystemExit('FULL_FLOW_AVAILABILITY_FAIL generic_selective_route_failure_reintroduced')

# Threat-block Evidence is fail-closed; XDR enrichment is explicitly non-fatal after the block has
# already been enforced and journalled. Other telemetry handlers (Privacy/InstallGuard) may also
# append Evidence, so scope this invariant to handleBlocked rather than relying on first-match order.
blocked_start = analytics.find('private fun handleBlocked(')
blocked_end = analytics.find('private fun notifyUi(', blocked_start)
if blocked_start < 0 or blocked_end < 0:
    raise SystemExit('FULL_FLOW_AVAILABILITY_FAIL telemetry_split_handler_missing')
blocked = analytics[blocked_start:blocked_end]
evidence_pos = blocked.find('runtime.evidence.append(')
fatal_pos = blocked.find('main.post { onFatal(code) }')
xdr_pos = blocked.find('runtime.xdr.recordThreatBlock(')
xdr_failure_pos = blocked.find('recordXdrPersistenceFailure("write_failed")')
if min(evidence_pos, xdr_pos, fatal_pos, xdr_failure_pos) < 0:
    raise SystemExit('FULL_FLOW_AVAILABILITY_FAIL telemetry_split_missing')
if not (evidence_pos < fatal_pos < xdr_pos < xdr_failure_pos):
    raise SystemExit('FULL_FLOW_AVAILABILITY_FAIL telemetry_split_order')
segment = blocked[xdr_pos:xdr_failure_pos + 200]
if 'onFatal(' in segment:
    raise SystemExit('FULL_FLOW_AVAILABILITY_FAIL xdr_failure_is_fatal')

for token in (
    'EvidenceWriteFailureClassifier.code(error)',
    'recordEvidencePersistenceFailure(code)',
    'recordXdrPersistenceFailure("write_failed")',
):
    if token not in analytics:
        raise SystemExit(f'FULL_FLOW_AVAILABILITY_FAIL failure_counter={token}')
for token in (
    'evidence_persistence_failures',
    'xdr_persistence_failures',
    'evidence_persistence_last_failure',
    'xdr_persistence_last_failure',
):
    if token not in diagnostics:
        raise SystemExit(f'FULL_FLOW_AVAILABILITY_FAIL diagnostics={token}')


# All transport mutations that may block on Binder, filesystem policy serialization, socket binding,
# helper process startup or control-socket handshakes must stay off Android's main Service thread.
for token in (
    'BoundedSerialScheduler("gedefense-control", CONTROL_QUEUE_CAPACITY)',
    'BoundedExecutors.direct("gedefense-tun")',
    'if (!submitControl {',
    'if (!runtime.executeBackground("vpn-bootstrap-wait")',
    'handleFullFlowFailure(reason)',
    'portSentinel.rebind(preferredUnderlay)',
    'scheduleControl(HANDOVER_DEBOUNCE_MS)',
    'scheduleControl(delay)',
):
    if token not in vpn:
        raise SystemExit(f'FULL_FLOW_AVAILABILITY_FAIL control_plane={token}')
if 'if (underlyingNetworks.get() != internet) return@submitControl' not in vpn:
    raise SystemExit('FULL_FLOW_AVAILABILITY_FAIL stale_underlay_callback_not_coalesced')
if vpn.count('sessionGeneration == fullFlowSessionGeneration.get()') < 2:
    raise SystemExit('FULL_FLOW_AVAILABILITY_FAIL stale_fullflow_callback_guard_missing')
if 'handoverHandler' in vpn:
    raise SystemExit('FULL_FLOW_AVAILABILITY_FAIL main_looper_transport_reintroduced')
on_start = vpn[vpn.find('override fun onStartCommand'):vpn.find('private fun submitControl')]
if 'if (!running.get()) beginProtectionStart()' in on_start or 'if (!running.get()) refreshTunnel()' in on_start:
    raise SystemExit('FULL_FLOW_AVAILABILITY_FAIL synchronous_service_transport_start')

for token in (
    'XDR_EVENTS("xdr-events", activeKeyVersion = 5',
    'EVIDENCE("evidence", activeKeyVersion = 5',
    'fun hotPathHmacKey(domain: VaultDomain)',
):
    if token not in vault:
        raise SystemExit(f'FULL_FLOW_AVAILABILITY_FAIL hot_path_profile={token}')
if 'SecureTelemetryVault.hotPathHmacKey(VaultDomain.EVIDENCE)' not in evidence:
    raise SystemExit('FULL_FLOW_AVAILABILITY_FAIL evidence_hmac_hot_path')
if 'SecureTelemetryVault.hotPathHmacKey(VaultDomain.XDR_EVENTS)' not in xdr:
    raise SystemExit('FULL_FLOW_AVAILABILITY_FAIL xdr_hmac_hot_path')
persistent = (JAVA / 'PersistentVaultKeys.kt').read_text()
for token in ('AndroidSecrets.hmacSha256(ROOT_PRF_ALIAS, preferStrongBox = false)', 'VisionGaiaTechnology/PersistentVaultRootWrapMaterial/v1', 'SecretKeySpec(aesBytes, "AES")', 'SecretKeySpec(hmacBytes, "HmacSHA256")'):
    if token not in persistent:
        raise SystemExit(f'FULL_FLOW_AVAILABILITY_FAIL hot_path_key={token}')

print('FULL_FLOW_AVAILABILITY_PASS selective_budget=1024 evidence_fail_closed=true xdr_nonfatal=true hot_path=persistent-root-prf control_plane=off-main')
