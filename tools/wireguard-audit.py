#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
java = ROOT / 'app/src/main/java/de/visiongaia/gedefense/mobile'
net = ROOT / 'netstack'

native = (java/'NativeGaiaNet.kt').read_text()
vpn = (java/'GeDefenseVpnService.kt').read_text()
profile = (java/'WireGuardProfileStore.kt').read_text()
parser = (java/'WireGuardConfigParser.kt').read_text()
activity = (java/'WireGuardActivity.kt').read_text()
qr_activity = (java/'WireGuardQrScannerActivity.kt').read_text()
build_ps1 = (ROOT/'tools/build-go-netstack.ps1').read_text()
vault = (java/'SecureTelemetryVault.kt').read_text()
state = (java/'RuntimeState.kt').read_text()
app_runtime = (java/'AppRuntime.kt').read_text()
helper = (net/'helper_main_process.go').read_text()
transport = (net/'wireguard_transport.go').read_text()
tun = (net/'wireguard_tun.go').read_text()
protected_bind = (net/'wireguard_protected_bind.go').read_text()
tracker = (net/'wireguard_flow_tracker.go').read_text()
engine = (net/'engine.go').read_text()
mod = (net/'go.mod').read_text()
manifest = (ROOT/'app/src/main/AndroidManifest.xml').read_text()
wg_constants = (ROOT/'third_party/go/wireguard-go/device/constants.go').read_text()
wg_send = (ROOT/'third_party/go/wireguard-go/device/send.go').read_text()
wg_timers = (ROOT/'third_party/go/wireguard-go/device/timers.go').read_text()

checks = {
    'single_android_vpn_service': manifest.count('android.permission.BIND_VPN_SERVICE') == 1,
    'helper_protocol_v5': re.search(r'helperProtocolVersion\s*=\s*byte\(5\)', helper) is not None and 'helperProtocolV4' in helper,
    'six_fd_oob_capacity': 'syscall.CmsgSpace(6*4)' in helper and 'len(fds) > 6' in helper,
    'mode_fd_contract': 'expectedFDs := 3' in helper and 'case helperProtocolVersion:' in helper and 'expectedFDs = 5' in helper and 'expectedFDs++' in helper,
    'official_wireguard_device': 'golang.zx2c4.com/wireguard/device' in transport and 'wgdevice.NewDevice' in transport,
    'upstream_rekey_engine': 'RekeyAfterTime          = time.Second * 120' in wg_constants and 'RekeyTimeout            = time.Second * 5' in wg_constants and 'time.Since(keypair.created) > RekeyAfterTime' in wg_send and 'peer.timers.retransmitHandshake.Mod(RekeyTimeout' in wg_timers,
    'wireguard_vendored_replace': 'replace golang.zx2c4.com/wireguard => ../third_party/go/wireguard-go' in mod,
    'policy_before_wireguard': 'match := e.policy.match(packet.Dst)' in engine and 'e.wireGuard.send' in engine,
    'no_direct_fallback': 'if e.egressMode != egressDirect' in engine and 'wireguard_egress_backpressure' in engine,
    'stateful_peer_ingress': 'if !t.tracker.handleInbound(packet)' in tun and 'tracked == nil' in tracker and 'return false' in tracker,
    'stateful_related_icmp': 'handleInboundICMP' in tracker and 'parseQuotedFlowKey' in tracker and 'parseQuotedICMPEchoKey' in tracker and 'icmpEchoIdleTimeout' in (net/'limits.go').read_text() and 'TestPacketFlowTrackerAllowsRelatedICMPv6PacketTooBig' in (net/'wireguard_icmp_test.go').read_text(),
    'stateful_fragments': 'handleInboundFragment' in tracker and 'handleOutboundFragment' in tracker and 'outboundFragments' in tracker and 'inboundFragments' in tracker and 'TestPacketFlowTrackerAdmitsOnlyRelatedInboundFragments' in (net/'wireguard_icmp_test.go').read_text() and 'TestPacketFlowTrackerAdmitsOnlyRelatedIPv6Fragments' in (net/'wireguard_icmp_test.go').read_text(),
    'full_tunnel_required_go': 'fullV4' in transport and 'wireguard config incomplete or not full-tunnel' in transport,
    'uapi_defense_in_depth': 'validWireGuardEndpoint' in transport and 'wireguard keepalive duplicated' in transport and 'wireguard private/public key collision' in transport,
    'uapi_secret_scratch_wiped': 'validWireGuardHexKeyBytes' in transport and 'scanner.Text()' not in transport and 'clear(privateKey[:])' in transport and 'clear(publicKey[:])' in transport and 'clear(out.Bytes())' in transport,
    'full_tunnel_required_android': 'wireguard_full_tunnel_ipv4_required' in parser and 'wireguard_full_tunnel_ipv6_required' in parser,
    'strict_android_lockdown': 'wireguard_strict_requires_android_lockdown' in vpn and 'isLockdownEnabled' in vpn,
    'wireguard_no_uid_bypass': 'egressMode == WireGuardEgressMode.DIRECT && !configureSelfBypass(builder)' in vpn,
    'per_socket_vpn_protect': 'protectWireGuardSocket' in vpn and 'protect(duplicate.fd)' in vpn,
    'single_family_bind_support': 'wireGuardSocketFDs(receivers, peeker)' in protected_bind and 'TestProtectedWireGuardBindProtectsSingleAvailableFamily' in (net/'wireguard_transport_test.go').read_text(),
    'socket_fd_scm_rights': 'helperProtectMagic' in helper and 'syscall.UnixRights(fds...)' in helper and 'requestAndroidSocketProtection' in helper,
    'protect_before_bind_open_returns': 'wireGuardSocketFDs(receivers, peeker)' in protected_bind and 'b.protector(fds)' in protected_bind and 'wireguard protected bind reopen rejected' in protected_bind,
    'android_socket_ack': "hasMagic(frame, 'G', 'D', 'P', '2')" in native and "'R'.code.toByte()" in native and 'receiveHelperFrame' in native and 'ancillaryFileDescriptors' in native,
    'secret_config_pipe': 'ParcelFileDescriptor.createPipe()' in native and 'wireGuardPipe' in native and 'File.createTempFile("wireguard' not in native,
    'secret_vault_domain': 'WIREGUARD_PROFILE("wireguard-profile"' in vault and 'VaultDomain.WIREGUARD_PROFILE' in profile,
    'secret_zeroization': 'wireGuardConfig?.fill(0)' in vpn and 'destroySecrets()' in profile and 'payload.fill(0)' in profile,
    'no_private_key_string_hex': 'privateKey.toHex()' not in profile,
    'wipeable_secret_encoders': 'SensitiveByteBuilder' in profile and 'import java.io.ByteArrayOutputStream' not in profile and 'import java.io.DataOutputStream' not in profile,
    'profile_mode_persistence': 'KEY_WIREGUARD_EGRESS_MODE' in state,
    'durable_mode_rehydration': 'awaitDurableState(MODE_STORE_BOOTSTRAP_TIMEOUT_MS)' in vpn and vpn.find('awaitDurableState(MODE_STORE_BOOTSTRAP_TIMEOUT_MS)') < vpn.find('runtime.state.wireGuardEgressMode()', vpn.find('private fun startProtection()')),
    'runtime_persistence_fail_closed': 'persistenceLoadHealthy' in state and 'persistenceWriteHealthy' in state and 'if (!persistenceLoadHealthy.get() || !persistenceWriteHealthy.get()) return false' in state,
    'configuration_transition_lock': 'ReentrantLock()' in state and 'beginProtectionStartTransition' in state and 'CONFIGURATION_LOCKED_VPN_STATES = setOf("STARTING", "RECOVERING")' in state and 'beginProtectionStartTransition(PROTECTION_CONFIGURATION_FREEZE_TIMEOUT_MS)' in vpn,
    'wireguard_profile_mutation_serialized': 'runtimeState.withMutableProtectionConfiguration { importConfigLocked(text) }' in profile and 'runtimeState.withMutableProtectionConfiguration {' in profile and 'WireGuardProfileStore(application, state)' in app_runtime,
    'wireguard_ui_transition_guard': activity.count('canMutateProtectionConfiguration()') >= 5 and 'runtime.state.isVpnActive() || !importRunning.compareAndSet' not in activity,
    'endpoint_resolved_before_helper': (
        'resolveEndpoint(current, underlay)' in vpn
        and vpn.find('resolveEndpoint(current, underlay)', vpn.find('private fun installFullFlow'))
            < vpn.find('builder.establish()', vpn.find('private fun installFullFlow'))
    ),
    'endpoint_resolution_bound_to_underlay': 'fun resolveEndpoint(profile: WireGuardProfile, network: Network)' in profile and 'network.getAllByName(host)' in profile and 'InetAddress.getAllByName(host)' not in profile,
    'endpoint_resolution_time_bounded': 'BoundedAndroidCall.call(WIREGUARD_ENDPOINT_RESOLVE_TIMEOUT_MS)' in profile and 'WIREGUARD_ENDPOINT_RESOLVE_TIMEOUT_MS = 5_000L' in profile,
    'socket_protection_time_bounded': 'BoundedAndroidCall.call(WIREGUARD_SOCKET_PROTECT_TIMEOUT_MS)' in vpn and 'WIREGUARD_SOCKET_PROTECT_TIMEOUT_MS = 2_000L' in vpn and 'PlatformCallUnavailableException' in vpn,
    'config_bounds_aligned': 'MAX_WIREGUARD_CONFIG_BYTES = 16 * 1024' in native and 'MAX_CONFIG_BYTES = 16 * 1024' in parser and 'MAX_UAPI_BYTES = 16 * 1024' in profile,
    'mtu_end_to_end': 'frame[40] = (tunnelMtu ushr 8).toByte()' in native and 'tunMTU' in helper and 'wireGuardMTU' in engine and 'tunnelMtu = profile?.mtu ?: FULL_FLOW_MTU' in vpn,
    'explicit_wireguard_dns': 'dns.size in 1..MAX_DNS_SERVERS' in parser and 'configured.addDnsServer(it)' in vpn,
    'conf_picker_mime_tolerant': 'type = "*/*"' in activity and 'FLAG_GRANT_READ_URI_PERMISSION' in activity,
    'local_qr_import': 'ScanOptions.QR_CODE' in activity and 'WireGuardQrScannerActivity::class.java' in activity and 'SCAN_RESULT' in activity and 'FLAG_SECURE' in qr_activity,
    'qr_parser_reuse': 'importConfigText(text, "wireguard-import-qr", clearInputOnSuccess = false)' in activity and 'runtime.wireGuard.importConfig(text)' in activity,
    'physical_underlay_socket_binding': 'underlay.bindSocket(duplicate.fileDescriptor)' in vpn and 'wireguard_underlay_unavailable' in vpn,
    'secret_entry_screen_secure': 'FLAG_SECURE' in activity and 'IMPORTANT_FOR_AUTOFILL_NO' in activity and 'IME_FLAG_NO_PERSONALIZED_LEARNING' in activity,
    'strict_utf8_import': 'CodingErrorAction.REPORT' in activity and 'bytes.fill(0)' in activity,
    'android_both_abis': "$env:GOOS = 'android'" in build_ps1 and build_ps1.count("$env:GOOS = 'android'") >= 2 and "$env:CGO_ENABLED = '1'" in build_ps1 and '27.2.12479018' in build_ps1,
    'encrypted_roundtrip_test': 'TestWireGuardTransportEncryptedUDPRoundTrip' in (net/'wireguard_transport_test.go').read_text(),
    'tun_liveness_anchor': 'private val tunnelAnchor: ParcelFileDescriptor' in native and 'tunnelAnchor.closeSafely()' in native and 'Session(pipe[0], control, process, socketFile, tunnel, packageGateResponder)' in native,
    'recovery_selftest_preserves_anchor': 'terminateHelperForRecoveryTest' in native and 'session.terminateHelperForRecoveryTest()' in vpn and 'session.close()' not in vpn[vpn.find('private fun runRecoverySelfTest()'):vpn.find('private fun handleFullFlowFailure')],
    'fail_closed_replacement_order': vpn.find('val descriptor = try { builder.establish()', vpn.find('private fun installFullFlow')) < vpn.find('tearDownFullFlow()', vpn.find('private fun installFullFlow')),
    'wireguard_emergency_anchor': 'ensureWireGuardFailClosedAnchor' in vpn and 'wireguard fail-closed anchor active' in vpn and 'No reader is' in vpn,
    'underlay_loss_preserves_anchor': 'wireguard underlay unavailable; preserving fail-closed tunnel anchor' in vpn and 'wireguard recovery paused until physical underlay returns' in vpn,
    'strict_runtime_watchdog': 'STRICT_KILL_SWITCH_WATCHDOG_MS = 5_000L' in vpn and 'armStrictInvariantWatchdog' in vpn and 'wireguard_strict_android_lockdown_lost' in vpn and 'retainStrictFailClosedOnLockdownLoss' in vpn,
    'strict_watchdog_bounded': 'strictWatchdogScheduled.compareAndSet(false, true)' in vpn and 'strictWatchdogScheduled.set(false)' in vpn and 'BoundedSerialScheduler("gedefense-control", CONTROL_QUEUE_CAPACITY)' in vpn and 'strict_watchdog_scheduler_busy' in vpn and 'stopProtection("FULL_FLOW_FAILED", "strict_watchdog_scheduler_busy")' in vpn,
    'underlay_generation_safe': 'activeWireGuardUnderlayGeneration' in vpn and 'selectedUnderlayGeneration = handoverGeneration.get()' in vpn and 'activeWireGuardUnderlayGeneration.get() >= generation' in vpn,
    'stale_transport_callback_rejected': 'fullFlowSessionGeneration' in vpn and 'sessionGeneration == fullFlowSessionGeneration.get()' in vpn and vpn.count('sessionGeneration == fullFlowSessionGeneration.get()') >= 2 and 'fullFlowSessionGeneration.incrementAndGet()' in vpn[vpn.find('private fun tearDownFullFlow()'):],
    'network_callback_io_serialized': 'override fun onAvailable(network: Network) {' in vpn and 'submitControl { updatePhysicalNetwork(network) }' in vpn and 'if (underlyingNetworks.get() != internet) return@submitControl' in vpn and 'setUnderlyingNetworks(internet.takeIf { it.isNotEmpty() }?.toTypedArray())' in vpn,
    'recovery_schedule_fail_closed': 'full-flow recovery scheduler saturated' in vpn and 'ensureWireGuardFailClosedAnchor("recovery_scheduler_busy")' in vpn,
}
# The Android controller must have enough time to protect both possible WireGuard sockets
# serially, while still timing out before the helper's own 8-second startup deadline.
def int_const(text: str, name: str) -> int:
    match = re.search(rf'{re.escape(name)}\s*=\s*([0-9_]+)', text)
    if not match:
        raise SystemExit(f'WIREGUARD_AUDIT_FAIL missing_timeout_constant={name}')
    return int(match.group(1).replace('_', ''))

connect_timeout = int_const(native, 'CONNECT_TIMEOUT_MS')
handshake_timeout = int_const(native, 'HANDSHAKE_TIMEOUT_MS')
protect_timeout = int_const(vpn, 'WIREGUARD_SOCKET_PROTECT_TIMEOUT_MS')
max_protect_fds = int_const(native, 'MAX_WIREGUARD_SOCKET_FDS')
if connect_timeout > 5_000 or connect_timeout < 1_000:
    raise SystemExit('WIREGUARD_AUDIT_FAIL helper_connect_timeout_budget')
if handshake_timeout < protect_timeout * max_protect_fds + 2_000:
    raise SystemExit('WIREGUARD_AUDIT_FAIL helper_handshake_timeout_too_short')
if 'helperStartupTimeout         = 10 * time.Second' not in helper:
    raise SystemExit('WIREGUARD_AUDIT_FAIL helper_startup_timeout_missing')
if 'helperProtectResponseTimeout = 5 * time.Second' not in helper or 'SetReadDeadline(time.Now().Add(helperProtectResponseTimeout))' not in helper:
    raise SystemExit('WIREGUARD_AUDIT_FAIL protect_response_deadline_rearm_missing')
if 'TestWireGuardSocketProtectionRearmsStaleReadDeadline' not in (net/'helper_process_test.go').read_text():
    raise SystemExit('WIREGUARD_AUDIT_FAIL protect_response_deadline_regression_missing')
if handshake_timeout >= 9_000:
    raise SystemExit('WIREGUARD_AUDIT_FAIL helper_handshake_timeout_not_inside_helper_deadline')

failed=[name for name, ok in checks.items() if not ok]
if failed:
    raise SystemExit('WIREGUARD_AUDIT_FAIL ' + ','.join(failed))

# No application-level WireGuard implementation or ad-hoc crypto is allowed. The protocol engine
# must remain upstream wireguard-go, vendored and pinned.
for path in java.rglob('*.kt'):
    text=path.read_text()
    if re.search(r'(?i)chacha20|poly1305|curve25519|noise[_ -]?ik', text):
        raise SystemExit(f'WIREGUARD_AUDIT_FAIL custom_crypto={path.name}')

print('WIREGUARD_AUDIT_PASS single_vpn=true full_tunnel=true fail_closed=true stateful_ingress=true related_icmp=true stateful_fragments=true per_socket_protect=true protect_timeout=true timeout_budget=true helper_deadline=true protect_deadline_rearm=true underlay_bound=true mtu_propagated=true explicit_dns=true conf_picker_wildcard=true local_qr=true qr_parser_reuse=true underlay_dns_resolution=true dns_timeout=true secret_buffers_wipeable=true go_secret_scratch_wiped=true secret_pipe=true uapi_hardened=true durable_mode=true config_freeze=true encrypted_roundtrip=true tun_anchor=true fail_closed_swap=true recovery_selftest_anchor=true underlay_wait=true strict_watchdog=true bounded_watchdog=true underlay_generation=true stale_transport_callbacks=true callback_io_serialized=true recovery_queue_fail_closed=true upstream_rekey=true')
