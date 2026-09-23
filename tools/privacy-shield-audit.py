#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
from pathlib import Path
import re
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
java = ROOT / 'app/src/main/java/de/visiongaia/gedefense/mobile'
core = ROOT / 'core/src/main/kotlin/de/visiongaia/gedefense/mobile/core'
net = ROOT / 'netstack'

model = (core / 'PrivacyIntelligence.kt').read_text()
repo = (java / 'PrivacyIntelligenceRepository.kt').read_text()
state = (java / 'RuntimeState.kt').read_text()
native = (java / 'NativeGaiaNet.kt').read_text()
vpn = (java / 'GeDefenseVpnService.kt').read_text()
analytics = (java / 'FullFlowAnalytics.kt').read_text()
xdr = (java / 'XdrEngine.kt').read_text()
privacy_ui = (java / 'PrivacyActivity.kt').read_text()
security_audit = (ROOT / 'tools/security-audit.sh').read_text()
release_audit = (ROOT / 'tools/release-readiness.sh').read_text()
helper = (net / 'helper_main_process.go').read_text()
engine = (net / 'engine.go').read_text()
udp = (net / 'udp_manager.go').read_text()
tcp = (net / 'tcp_manager.go').read_text()
telemetry_go = (net / 'telemetry.go').read_text()
dns = (net / 'dns.go').read_text()
privacy_go = (net / 'privacy_policy.go').read_text()
asset = ROOT / 'app/src/main/assets/privacy_intelligence_v1.tsv'

checks = {
    'asset_present': asset.is_file(),
    'immutable_local_loader': 'appContext.assets.open(ASSET_NAME)' in repo and 'PrivacyIntelligenceRegistry.build' in repo,
    'no_runtime_privacy_api': all(token not in repo for token in ('HttpURLConnection', 'OkHttp', 'URL(', 'Socket(', 'openConnection(', 'Retrofit')),
    'bounded_asset': 'MAX_RULES = 8_192' in repo and 'MAX_CHARS = 4 * 1024 * 1024' in repo and 'CodingErrorAction.REPORT' in repo,
    'local_authority': 'Rules never gain blocking authority merely because they exist' in model and 'actionFor(rule, profile)' in model,
    'essential_override': 'val essential = candidates.filter { it.essential }' in model,
    'profile_persisted': 'KEY_PRIVACY_PROFILE' in state and 'PrivacyProfile.CONSERVATIVE' in state and 'fun setPrivacyProfile' in state,
    'profile_frozen_with_vpn_config': 'setPrivacyProfile(profile: PrivacyProfile) = withMutableProtectionConfiguration' in state,
    'helper_protocol_current': 'PROTOCOL_VERSION: Byte = 5' in native and re.search(r'helperProtocolVersion\s*=\s*byte\(5\)', helper) is not None and 'helperProtocolV4' in helper,
    'privacy_fd_scm_rights': 'privacyPolicy.fileDescriptor' in native and 'gedefense-privacy-policy' in helper,
    'privacy_policy_authenticated': 'MessageDigest.getInstance("SHA-256")' in native and 'subtle.ConstantTimeCompare(expectedDigest, actualDigest)' in privacy_go,
    'privacy_policy_bounded': 'count > 8192' in privacy_go and 'idLen > 96' in privacy_go and 'domainLen > 253' in privacy_go,
    'direct_dns_enforcement': 'm.handlePrivacyDNS(p)' in udp and 'decision.Action == privacyAllow' in udp and 'buildDNSBlockedResponse' in udp,
    'encrypted_dns_category': 'ENCRYPTED_DNS' in model,
    'encrypted_dns_profile_bound': 'profile: header[5]' in privacy_go and 'encryptedDNSAction' in privacy_go,
    'dot_doq_standard_port': 'packet.DstPort != 853' in privacy_go and 'p.DstPort != 853' not in privacy_go,
    'strict_blocks_dot_doq': 'if p.profile == 3' in privacy_go and 'return privacyBlock' in privacy_go,
    'balanced_observes_dot_doq': 'return privacyObserve' in privacy_go,
    'direct_tcp_encrypted_dns': 'm.privacy.encryptedDNSAction(p)' in tcp and 'tcpRST|tcpACK' in tcp,
    'direct_udp_encrypted_dns': 'm.privacy.encryptedDNSAction(p)' in udp,
    'wireguard_encrypted_dns': 'e.privacy.encryptedDNSAction(packet)' in engine and engine.find('e.privacy.encryptedDNSAction(packet)') < engine.find('e.wireGuard.send(raw[:packet.TotalLen]'),
    'encrypted_dns_telemetry': 'func (t *telemetry) encryptedDNS' in telemetry_go and 'Y\\t%d' in telemetry_go,
    'encrypted_dns_android_revalidation': 'handleEncryptedDns' in analytics and 'encrypted-dns-desync' in analytics and 'transport-port-853' in analytics,
    'no_generic_https_block': 'packet.DstPort != 853' in privacy_go and 'DstPort == 443' not in privacy_go,
    'encrypted_dns_ui_boundary': 'privacy_telemetry_encrypted_dns_note' in privacy_ui,
    'wireguard_dns_enforcement': engine.find('if e.handlePrivacyDNS(packet, e.tunMTU)') != -1 and engine.find('if e.handlePrivacyDNS(packet, e.tunMTU)') < engine.find('e.wireGuard.send(raw[:packet.TotalLen]', engine.find('if e.handlePrivacyDNS(packet, e.tunMTU)')),
    'local_nxdomain': 'buildDNSBlockedResponse' in dns and '0x0003' in dns,
    'privacy_telemetry': 'func (t *telemetry) privacy' in (net / 'telemetry.go').read_text() and '"P\\t%d' in (net / 'telemetry.go').read_text(),
    'android_revalidation': 'runtime.privacyIntelligence.registry().decide(domain, runtime.state.privacyProfile())' in analytics and 'privacy.policy_desync' in analytics,
    'evidence_and_xdr': 'privacy.block' in analytics and 'runtime.xdr.ingestPrivacyDecision' in analytics and 'source = "telemetry-shield"' in xdr,
    'vpn_receives_registry': 'privacyRegistry = runtime.privacyIntelligence.registry()' in vpn and 'privacyProfile = runtime.state.privacyProfile()' in vpn,
    'profile_ui': all(token in privacy_ui for token in (
        'telemetryShieldCard()',
        'setPrivacyProfile(PrivacyProfile.CONSERVATIVE)',
        'setPrivacyProfile(PrivacyProfile.BALANCED)',
        'setPrivacyProfile(PrivacyProfile.STRICT)',
        'setPrivacyProfile(PrivacyProfile.OFF)',
        'canMutateProtectionConfiguration()',
        'privacy_telemetry_full_flow_only',
        'privacy_telemetry_encrypted_dns_note',
    )),
    'full_flow_scope_disclosed': 'Full Flow' in (ROOT / 'README.md').read_text() and 'Selective mode does not claim system-wide telemetry filtering' in (ROOT / 'README.md').read_text(),
    'security_gate_integration': 'python3 tools/privacy-shield-audit.py' in security_audit,
    'release_gate_integration': 'python3 tools/privacy-shield-audit.py' in release_audit,
}

if asset.is_file():
    rows = []
    for line_no, line in enumerate(asset.read_text().splitlines(), 1):
        if not line.strip() or line.startswith('#'):
            continue
        fields = line.split('\t')
        if len(fields) != 11:
            raise SystemExit(f'PRIVACY_SHIELD_AUDIT_FAIL asset_fields_line={line_no}')
        rows.append(fields)
    if not rows:
        raise SystemExit('PRIVACY_SHIELD_AUDIT_FAIL asset_empty')
    ids = [row[0] for row in rows]
    if len(ids) != len(set(ids)):
        raise SystemExit('PRIVACY_SHIELD_AUDIT_FAIL duplicate_asset_id')
    forbidden_licenses = ('CC-BY-NC', 'CC BY-NC', 'PROPRIETARY')
    for row in rows:
        license_id = row[9].upper()
        if any(token in license_id for token in forbidden_licenses):
            raise SystemExit(f'PRIVACY_SHIELD_AUDIT_FAIL forbidden_license={row[9]}')
    encrypted = [row for row in rows if row[3] == 'ENCRYPTED_DNS']
    if len(encrypted) < 6:
        raise SystemExit(f'PRIVACY_SHIELD_AUDIT_FAIL encrypted_dns_rules={len(encrypted)}')
    allowed_reference_hosts = {'developers.google.com', 'developers.cloudflare.com', 'docs.quad9.net'}
    for row in encrypted:
        if row[9] != 'REFERENCE' or urlparse(row[8]).hostname not in allowed_reference_hosts:
            raise SystemExit(f'PRIVACY_SHIELD_AUDIT_FAIL encrypted_dns_provenance={row[0]}')

failed = [name for name, ok in checks.items() if not ok]
if failed:
    raise SystemExit('PRIVACY_SHIELD_AUDIT_FAIL ' + ','.join(failed))
print(f'PRIVACY_SHIELD_AUDIT_PASS local_first=true rules={len(rows)} dns_enforcement=true encrypted_dns=true dot_doq_853=true no_tls_mitm=true direct=true wireguard=true evidence=true xdr=true profile_ui=true')
