# GeDefense Mobile 0.24.0-beta.1 — Real-Device Test Plan

A Gradle/Go build is necessary, not sufficient. Full Flow promotion requires the following on real Android hardware.

## A. Build / package

1. `windows-build-beta.ps1` completes.
2. Both `lib/arm64-v8a/libgedefense_gaianet_v2.so` and `lib/x86_64/libgedefense_gaianet_v2.so` are present in the APK and byte-identical to the source-tree helper artifacts.
3. APK SHA-256 recorded.
4. Clean install and upgrade from `0.5.0-alpha.1` both succeed.

## B. UI / device geometry

5. centered hole-punch
6. left/right hole-punch
7. notch
8. gesture navigation and three-button navigation
9. landscape side cutout
10. 320-360dp narrow display
11. font scale 1.0 / 1.3 / 1.5
12. no interactive content under status/camera/navigation areas

## C. Selective Shield regression

13. Feodo/Spamhaus block routes install.
14. public route-policy mismatch still fails `POLICY_INVARIANT_FAILED`.
15. IPv6 DAD/MLD/RS, multicast, link-local, ULA/interface-local packets do not trigger the invariant.
16. CINS/blocklist.de/ET/IPsum remain correlation-only; FireHOL Level 1 blocks only after non-public prefixes have been rejected by the public-prefix boundary.
17. Tor remains annotation-only.
18. route overflow refuses partial protection.

## D. Full Flow core connectivity

19. IPv4 web browsing over TCP.
20. IPv6 web browsing over TCP.
21. HTTP/3/QUIC-capable app over UDP.
22. DNS through normal system resolver.
23. Private DNS/DoT path remains usable where configured.
24. long-lived streaming TCP (>= 30 min).
25. long-lived UDP/QUIC (>= 30 min).
26. repeated connect/close storm without leak/crash.
27. device sleep/wake.
28. Wi-Fi -> cellular handover.
29. cellular -> Wi-Fi handover.
30. airplane mode off/on recovery.
31. captive portal login behavior.
32. local LAN TCP/UDP access where expected.
33. common multicast/local-discovery apps documented as pass/fail rather than silently assumed.

## E. Full Flow policy

34. Feodo destination produces local block and Evidence.
35. Spamhaus v4/v6 destination produces block.
36. correlation-only destination remains forwarded and increments correlation telemetry.
37. Tor destination remains forwarded and annotated.
38. self-owned GeDefense feed/Geo requests do not recurse into TUN.
39. critical telemetry pipe failure terminates Full Flow.
40. Evidence failure terminates protection.
41. Integrity failure prevents/terminates protection.

## F. App attribution / analytics

42. TCP owner UID/package is correct for multiple apps.
43. UDP owner UID/package is correct for multiple apps.
44. shared UID presentation does not falsely claim a unique package.
45. per-app TX/RX grows monotonically.
46. Top-3 country values correspond to observed test endpoints.
47. `ZZ` is used when no local country mapping exists.
48. visible UDP/53 DNS names appear; encrypted DNS is not falsely decoded.
49. top domains/countries remain bounded under high-cardinality traffic.

## G. Geo generation safety

50. first Geo sync downloads/checksums/compiles both families.
51. corrupted active pointer recovers newest valid authenticated generation.
52. corrupted manifest/data is rejected.
53. failed refresh retains prior active generation.
54. interruption during stage leaves no partially active generation.
55. source redirect outside allowed GitHub asset hosts is rejected.

## G2. ASN evidence generation / evidence-only safety

1. First ASN sync downloads and checksum-verifies both `IPtoASN` IPv4 and IPv6 snapshots, then publishes one authenticated generation containing both indexes and the organization dictionary.
2. Verify a known IPv4 and IPv6 endpoint resolve locally to the expected AS number/organization while private/link-local/multicast destinations produce no ASN evidence.
3. Corrupt the ASN active pointer, manifest and each compiled index independently; startup must reject damage and recover the newest valid authenticated generation where available.
4. Interrupt refresh after source download, during compilation and before/after pointer publication; the previous authenticated generation must remain usable.
5. Force source SHA mismatch, oversized input, malformed CSV, overlap/out-of-order ranges and disallowed redirect hosts; refresh must fail without replacing the active generation.
6. Capture network traffic during lookup and confirm no destination address is sent to an ASN service; only periodic whole-dataset refresh traffic is allowed.
7. Inspect `network.asn` Evidence and confirm it contains AS/app/family/provenance/hash context but no raw destination IP.
8. Generate ASN matches under benign and hostile test flows and confirm ASN alone never enters XDR scoring or changes allow/block policy.

## H. Resource/adversarial

56. SYN storm respects half-open/global limits.
57. UDP-flow storm respects limits.
58. overlapping IP fragments are rejected.
59. fragment-memory ceiling remains bounded.
60. malformed packet corpus cannot crash native core.
61. telemetry/TUN backpressure fails predictably.
62. 2+ hour mixed browsing/streaming session shows no unbounded memory/thread growth.
63. battery/CPU/throughput measured against VPN-off baseline.

## I. Stable-release blockers

Do not call Always-on/lockdown or TITAN stable until the OEM/network and Device Owner matrices below have passed and remaining compatibility failures are explicitly resolved or bounded.

## J. Data-Flow Atlas / privacy

64. Atlas renders with no map/network connection while offline.
65. Without location permission, origin uses a country-level fallback and the map remains useful.
66. Granting coarse location moves only the local origin marker; no fine/background permission is requested.
67. Atlas origin is visibly labeled coarse/approximate and destination points are disclosed as country-level anchors.
68. App legend and route colors remain stable while live telemetry updates.
69. More than 12 app/country candidates remain bounded to 12 visual routes.
70. Tapping a destination persists the selected app/country/byte summary without affecting enforcement.
71. 320-360dp devices show the map, legend and location action without horizontal clipping.


## K. Setup assistant / privilege boundaries

72. Fresh install opens the setup assistant once and can be skipped/completed without breaking VPN protection.
73. Battery-optimization action opens an Android-controlled exemption surface; denial leaves GeDefense functional but visibly not optimized.
74. OEM autostart action either opens a known OEM settings surface or safely falls back to application details.
75. Android 11+ all-files action opens the app-specific all-files settings surface and status updates after returning.
76. Denying all-files access does not prevent Selective Shield or Full Flow protection.
77. Usage-access and notification states refresh correctly after returning from system settings.
78. Reboot/package replacement restores scheduled Threat Intelligence/Integrity jobs and does not silently start the VPN.

## L. Device Security Scanner

79. Scanner screen shows live Integrity -> Apps -> Storage -> Finalizing phases with cancellable progress.
80. Cancelling a scan terminates bounded work and leaves a coherent `CANCELLED` snapshot.
81. Without all-files access, the scanner reports the limitation and provides a settings action rather than claiming full coverage.
82. Symlinks and canonical paths escaping the selected shared-storage root are rejected.
83. Archive/file-count/depth/content/hash budgets stop adversarial corpus expansion without OOM or ANR.
84. Extension/magic mismatch and deceptive double extensions produce review findings.
85. APK inspection never executes or dynamically loads DEX/native content.
86. Embedded public IP indicators preserve BLOCK/CORRELATE/ANNOTATE authority when correlated.
87. Scanner never deletes, quarantines, renames or modifies scanned content.
88. A critical GeDefense self-integrity failure still suspends active protection.
89. Scanner results remain local and Evidence records contain bounded summary data, not private file paths.

## Lockdown firewall and scanner acceleration gates

- Activate **Lockdown** with an empty allowlist and verify normal user apps cannot reach IPv4, IPv6, DNS or local-LAN endpoints while GeDefense remains controllable.
- Allow one user app, refresh the active policy and verify only that app regains connectivity; repeat with selected system software and then revoke it again.
- Reboot and verify the allowlist persists but the VPN does not falsely report itself active before Android actually starts it.
- Run two identical deep scans back-to-back and confirm the second scan reuses unchanged file/app state while still producing the same findings and current Threat Intelligence correlation.
- Update an app with split APKs and verify unchanged DEX/native/asset ZIP entries are reused while changed entries are rescanned.
- Change Threat Intelligence between two scans without changing test files and verify cached public indicators are re-correlated to the new policy without requiring a full reread.
- Cancel a scan during parallel storage inspection and verify workers terminate without corrupting the persistent scanner state.
- Tamper with the private scanner cache and verify authentication failure causes cache rejection/rescan rather than reuse or a clean verdict.
- Force a storage scan to exhaust its content budget, rerun the same corpus and verify the incomplete record is not treated as a deep cache hit.
- Run a warm identical app scan and verify unchanged packages avoid reopening APK ZIPs while current Threat Intelligence correlation still changes when the policy generation changes.
- Verify scanner progress update rate remains bounded during a large storage corpus and does not produce UI-thread starvation.
## M. Network Discovery / LAN XDR

90. On Wi-Fi with a /24 private LAN, discovery never targets an address outside the planned subnet and scans no more than 254 hosts.
91. On a broader private /16 or /20 LAN, active discovery is clamped to the device-local /24 window and the UI discloses the clamp.
92. A public/non-private IPv4 interface cannot produce an active scan plan.
93. With GeDefense Full Flow active, discovery traffic remains bound to the underlying Wi-Fi/Ethernet network rather than recursively entering the VPN.
94. The first complete scan initializes the LAN baseline without flagging every pre-existing device as new.
95. Adding a test device after baseline creation produces a bounded LAN XDR event; removing and re-adding it does not create an unbounded event storm.
96. Opening ADB TCP/5555 on a lab device produces a CRITICAL local-service exposure event; Telnet/RDP/VNC produce HIGH exposure events.
97. Cancelling mid-scan never persists partial results as trusted baseline state.
98. Corrupting the authenticated network-discovery snapshot produces an integrity failure and no silent baseline replacement.
99. SSDP responses whose source IP is outside the approved local target set are ignored.
100. Systems with unreadable `/proc/net/arp` still complete without claiming MAC-address coverage.
101. A device with no monitored TCP port and no SSDP/ARP visibility may be absent; the UI/docs must not claim raw ARP/ICMP discovery coverage.
102. Repeated scans on the same LAN remain bounded in CPU, memory and thread count and do not leak sockets.



### Network Discovery 0.11 additions

103. On a Wi-Fi LAN with mDNS-capable devices, DNS-SD advertisements are discovered without leaving the planner-approved local address set.
104. A DNS-SD service is shown as advertised and is not mislabeled as a TCP-confirmed open service unless the active TCP probe independently succeeds.
105. Android Wireless Debugging advertising `_adb-tls-connect._tcp.local` or `_adb-tls-pairing._tcp.local` creates an elevated LAN-XDR signal.
106. A known MAC-backed device changing `.local` hostname after baseline creation produces bounded identity-drift telemetry; an IP-only identity later upgraded to mDNS/MAC identity does not create a synthetic new-device incident.
107. Corrupt/truncated network-discovery baseline fails closed and does not learn new LAN state until explicitly reset.
108. mDNS packet fuzz/malformed compression-pointer cases cannot crash discovery, grow unbounded state or escape the local-network source filter.


## UI performance / animation stress

1. Run Full Flow for >= 20 minutes on a 60 Hz device while repeatedly scrolling Dashboard, Security, XDR, Scanner and Network Discovery; verify no sustained input starvation or ANR.
2. Repeat on a 90/120 Hz device; verify shield/radar/map animations remain visually continuous while security events continue updating.
3. Enable Android battery saver during an active animated screen; verify decorative cadence reduces without pausing VPN, scanner, XDR or evidence processing.
4. Test a low-RAM Android 10/11 device or emulator profile; verify animation degradation is graceful and navigation remains responsive.
5. Generate high Full Flow telemetry while remaining on Dashboard; verify hidden primary screens are not repeatedly rebuilt.
6. Scroll during live telemetry bursts; verify recent interaction temporarily lowers decorative cadence rather than dropping touch events.
7. Background/foreground the app repeatedly; verify `Choreographer` callbacks stop while views are detached and resume without duplicated tickers.

## LAN behavioral NDR

1. First complete scan of a previously unseen LAN initializes baseline and produces no synthetic new-device/behavior surge incident.
2. Repeat unchanged complete scans until behavioral maturity; verify LEARNING transitions to ACTIVE/NORMAL without false anomalies.
3. Expose one new low-risk service for a single scan and remove it; verify it remains a candidate and is not promoted to stable normal.
4. Expose the same service across the required repeated observations; verify bounded candidate promotion.
5. Add >=3 new services to a mature known device; verify service-burst correlation without mutating normal risk on the anomalous scan.
6. Increase a mature device exposure score by the configured threshold; verify `exposure_risk_spike` and XDR correlation.
7. Add enough devices/elevated hosts to cross network-surge thresholds; verify network-level XDR events.
8. Cancel a scan mid-run; verify no baseline observations, candidate counters or EWMA values are committed.
9. Upgrade from schema-v1/v2 LAN state; verify migration preserves known devices/services and does not emit synthetic drift.
10. Tamper/truncate/oversize the LAN state; verify authenticated state failure is surfaced and not interpreted as an empty safe network.
## TITAN Device Owner / DPC real-device gates

1. On a factory-reset test device, provision the signed GeDefense release as fully managed Device Owner through a supported Android Enterprise QR flow; verify `GET_PROVISIONING_MODE` and `ADMIN_POLICY_COMPLIANCE` complete without setup-loop failure.
2. On a separate eligible controlled device, install the same signed release and verify the displayed `adb shell dpm set-device-owner --user 0 de.visiongaia.gedefense.mobile/.TitanDeviceAdminReceiver` command succeeds only in an allowed provisioning state.
3. Verify Standard Mode remains fully functional when GeDefense is not Device Owner and no privileged toggle claims enforcement.
4. Enable Always-on + lockdown from TITAN; reboot, upgrade GeDefense in place and verify Android restores the VPN and blocks app traffic while the tunnel is unavailable.
5. While Android lockdown is active, verify GeDefense never runs Selective semantics and the ordinary Stop action cannot silently disable the administrator-enforced tunnel.
6. Quarantine a non-system lab app with auto-suspend enabled; verify network quarantine commits first, Android suspension follows, launch/UI/notification behavior matches platform semantics, and clearing quarantine restores the app.
7. Verify GeDefense, active admins, launcher/installer/verifier/system packages cannot be accidentally suspended/removed by TITAN UI.
8. Request operator-confirmed uninstall of a quarantined lab app; verify asynchronous PackageInstaller status is recorded in XDR/Evidence and no uninstall occurs automatically from a detection event.
9. Enable and disable each restriction independently: debugging features, unknown sources, Safe Boot, USB file transfer and Verify Apps. Verify Android readback matches the TITAN UI after process restart.
10. Enable high password complexity and confirm Android enforces the platform policy; disable and confirm release.
11. On a disposable test device only, enable the failed-unlock wipe threshold after the destructive confirmation and verify the policy value readback. Do not exercise an actual wipe on a device containing required data.
12. Import a known test X.509 CA: verify leaf certificates, multiple certificates, expired/not-yet-valid certificates and >128 KiB inputs are rejected before DevicePolicyManager. Verify subject/issuer/expiry/SHA-256 confirmation appears for a valid CA.
13. Verify a valid confirmed CA is reported by Android after installation. Confirm apps that do not trust user-added CAs remain unaffected; do not interpret CA installation as universal TLS interception.
14. Tamper/truncate TITAN's authenticated local policy snapshot and verify automatic privileged response is disabled until explicit reset while Android-effective policies remain accurately read back.
15. Upgrade from Standard Mode to Device Owner on a controlled provisioning path and verify existing XDR/Evidence history remains intact.

## Port Sentinel / handover real-device gates

1. On a private lab LAN, connect to Sentinel TCP ports 1080/2222/2323/5555/8080/8443 from a second owned device and verify metadata-only events with immediate close and no banner/credential exchange.
2. Send bounded UDP probes and verify source metadata without payload retention.
3. Probe several monitored ports inside 30 seconds and verify bounded `LAN_PORT_SCAN_DETECTED` correlation; verify ADB/5555 receives CRITICAL classification.
4. Add/remove a private source from the Sentinel denylist and verify authenticated persistence across process restart.
5. In Selective mode, verify a denylisted source receives a `/32` sink route and outbound traffic to that source is dropped while unrelated private LAN traffic is unaffected.
6. Tamper/truncate the Sentinel snapshot and verify the protected selective route set fails closed instead of silently treating the denylist as empty.
7. Switch Wi-Fi → cellular → Wi-Fi during Full Flow and verify underlying-network telemetry updates, the debounced restart closes stale flows, and protection recovers without recursive VPN routing.
8. Verify Sentinel unbinds from the departed LAN and rebinds only to the current private Wi-Fi/Ethernet network.


## GaiaNet V2 transport

- Validate arm64 real-device and x86_64 emulator helper execution, sustained throughput, process death, Wi-Fi/cellular handover and Doze cleanup.

## TITAN UI / Xiaomi-HyperOS validation

1. Standard mode: verify TITAN content remains readable at font scales 1.0, 1.3 and 1.5 with no clipped provisioning text or horizontal overflow.
2. Device Owner mode: verify the app-wide TITAN managed banner appears on every primary screen and disappears after Device Owner is no longer effective.
3. Verify command-deck DPC/VPN/XDR states are Android readback, not optimistic UI state.
4. On Xiaomi/Redmi/POCO HyperOS, verify the assistant labels `Settings -> Additional settings -> Enterprise mode` as Xiaomi OEM enterprise management and explicitly states that it does not itself grant GeDefense Device Owner.
5. Validate Android managed-device QR/setup provisioning independently from Xiaomi Enterprise Mode.
6. Validate the displayed ADB command only on an eligible disposable device; do not imply that an already normally provisioned personal device can always become Device Owner without reset/account cleanup.

## 0.19 resilience / power real-device matrix

1. With Android Always-on + "Block connections without VPN" enabled, start Full Flow and run Recovery Self-Test. Verify VPN status enters RECOVERING, returns to FULL_GUARDED, recovery count increments exactly once, and no traffic escapes during the recycle.
2. Repeat Recovery Self-Test rapidly; verify the UI disables/rejects overlapping tests and only one generation-guarded recovery chain runs.
3. Kill the GeDefense app process while Android Always-on is configured. Verify the service is recreated, waits for the bounded security bootstrap and returns to guarded state without an `integrity_scan_pending` false start.
4. Reboot with Android Always-on/Lockdown configured and verify the same startup invariant.
5. Switch Wi-Fi → cellular → Wi-Fi repeatedly during Full Flow; verify stale handover callbacks cannot recycle a newer recovered tunnel and the recovery counter remains semantically correct.
6. Turn the display off for 30 minutes with representative TCP, QUIC/UDP and push traffic. Verify established sessions are not artificially reaped at 30/90 seconds and no reconnect storm appears.
7. Compare Battery Historian / Android battery statistics for VPN-off, 0.18 Full Flow and 0.19 Full Flow across identical idle and mixed-traffic windows. Record CPU time, wakeups, mobile-radio active time and foreground-service consumption.
8. With GeDefense in background but screen on, verify detailed byte-update cadence drops while block/open/close events remain immediate. Repeat under Battery Saver and Doze.
9. Leave Port Sentinel bound to an idle Wi-Fi LAN for 30 minutes; verify no one-second selector polling wakeups occur and an inbound monitored-port event still wakes immediately.
10. Background GeDefense while animated screens were visible; verify Choreographer callbacks stop until the window becomes visible again.
11. Stress 512+ Full Flow connections and confirm telemetry cadence scales with load without exceeding bounded queues; any critical telemetry overflow must still terminate Full Flow fail-closed.
12. Exercise long-lived QUIC/UDP and TCP push connections across screen-off/on transitions and verify the power governor does not alter enforcement or healthy established-flow lifetime.


## 0.22 live-device hardening matrix

1. On HyperOS, set GeDefense to Battery → No restrictions and verify setup/protection no longer claims a background restriction even when Android Doze allowlisting remains false; then switch to an explicitly restricted state and verify the warning returns.
2. Refresh Threat Intelligence and verify FireHOL Level 1 is shown as BLOCK while private/CGNAT/fullbogon prefixes never appear as threat routes. Confirm Selective mode stays below the route budget.
3. Run Network Port Sentinel on Wi-Fi and Ethernet, then cellular. Verify it follows only the preferred physical underlay, immediately closes TCP probes, retains no payload and labels local/carrier/public source zones correctly. On CGNAT/carrier-firewalled service, STANDBY/no hits is an acceptable network result if no inbound path exists.
4. With a lab SIM/public IPv6 path, send probes only from owned infrastructure to monitored ports and verify XDR records bounded mobile-exposure events.
5. Upgrade a package through an APK Signature Scheme v3 proof-of-rotation test lineage and verify the previous signer is accepted as verified lineage rather than CRITICAL drift.
6. Verify an unprovable signer change on a non-system test package still produces CRITICAL signer evidence. Verify a system/updated-system package transition is review context unless independent integrity/behavior/network evidence corroborates it.
7. After upgrading from 0.21, verify stale signer-only incidents for current system packages/verified rotation lineage are pruned without clearing unrelated XDR history.
8. Enable TITAN Light and verify Device Hardening reports GeDefense as first-party admin with zero third-party-admin penalty; add a separate lab Device Admin and verify that external admin is still flagged.


## 0.23 Diagnostics / resilience

1. Open System → Diagnostics and verify runtime/resilience cards update without enabling new permissions.
2. Export a support bundle, unzip it, and confirm it contains only `summary.json`, `manifest.json`, and `README.txt`.
3. Search the bundle for installed package names, local/public IPs and known domains; none may appear.
4. With Full Flow + Android Lockdown active, run the existing resilience self-test and verify PASS/FAIL plus duration is retained in Diagnostics after leaving/reopening the screen.


## 0.24 beta-freeze lifecycle / recovery gates

1. Kill the app process while Full Flow is in `RECOVERING`; on the next process start, the UI must begin from `OFF` until Android actually recreates the VPN service.
2. Kill the app process while a resilience self-test is `RUNNING`; the next process must reconcile the orphaned test to bounded `FAIL`, never leave it permanently running.
3. Keep Diagnostics visible while VPN/recovery state changes and verify runtime/resilience cards update live without leaving/re-entering the activity.
4. Start a Diagnostics export and leave/finish the activity before it completes; the export may finish, but no stale Activity view mutation or lifecycle crash may occur.
5. Trigger a recovery self-test and immediately try again; the Protection Hub action must be disabled/rejected while the first test remains `RUNNING` or the VPN is `RECOVERING`.
6. Force/retrigger the scheduled Integrity job while one execution is active; duplicate starts must not invalidate the active generation, strand `active`, or suppress the original `jobFinished` completion.
7. Present a synthetic shared-storage tree with far more than 40,000 directory entries and verify enumeration truncates without allocating an unbounded child array or hanging cancellation.
8. Present an oversized private-filesystem directory in a test sandbox and verify Integrity Guard fails closed at its entry ceiling without eager whole-directory allocation.

## 0.27.8 beta.6 WireGuard release matrix

1. Import a valid one-peer full-tunnel profile from paste and from SAF file import. Verify the stored profile survives process death and reboot, while the import screen remains `FLAG_SECURE` and never restores plaintext configuration text.
2. Reject malformed UTF-8, >16 KiB input, >128 lines, multiple Interface/Peer sections, duplicate keys, non-canonical AllowedIPs, missing `0.0.0.0/0`, unsafe endpoint addresses, invalid MTU and private/public key collision without replacing the last valid stored profile.
3. Start Full Flow in WireGuard mode and verify the helper requests only its one/two upstream UDP socket descriptors; Android binds each to the selected physical `Network`, protects each exact socket and acknowledges before `wireguard-go` becomes usable. Confirm the GeDefense UID itself is not globally excluded from the VPN.
4. Force `VpnService.protect()` refusal/timeout and underlay bind failure. Startup must fail closed with no Direct fallback and no unprotected WireGuard datagram leaving the device.
5. Configure WireGuard Strict without Android Always-on + Block connections without VPN. Protection start must be refused with the explicit kill-switch-required state. Enable Android lockdown and verify Strict starts normally.
6. With Strict active, kill the GaiaNet helper, kill the app process and make the peer unreachable. Android lockdown must prevent physical-network escape throughout failure and service recovery.
7. Resolve a hostname endpoint and verify resolution occurs on the selected physical underlay before TUN establishment. Break/timeout underlay DNS and verify startup fails without falling back to the process/default resolver.
8. Use a profile with explicit IPv4 DNS. Confirm DNS queries traverse GeDefense -> WireGuard and no ordinary Android DNS server receives the inner query. Repeat with a coherent IPv6 profile/DNS pair.
9. Use an IPv4-only WireGuard profile while generating IPv6 traffic. Because Android still routes `::/0` into GeDefense, unsupported IPv6 must fail inside the VPN rather than escape to the physical network.
10. Use a dual-stack profile containing an IPv6 interface address and `::/0`. Verify IPv4 and IPv6 Internet traffic, DNS, ICMPv4/v6 error handling and PMTU behavior through the peer.
11. Exercise MTU 1280, a representative middle value and 1420 with large TCP, UDP/QUIC and ICMP traffic. Oversized decrypted peer packets must be rejected before Android TUN reinjection; no fragmentation/state bypass may appear.
12. Send unsolicited TCP/UDP, ICMP echo replies, ICMP errors with unrelated quoted packets and non-initial fragments from the peer. GaiaNet must reject them. Then exercise matching outbound flows and verify only related return traffic is admitted.
13. Switch Wi-Fi -> cellular -> Wi-Fi while transferring traffic. Verify the preferred-underlay change generation/debounce closes stale WireGuard sockets, re-resolves the endpoint on the new underlay and completes a fresh per-socket protection handshake before traffic resumes.
14. Repeat handover under Battery Saver, screen-off and Doze. Verify bounded recovery, no main-thread ANR path, no stale helper generation taking ownership and no silent Direct fallback.
15. Force helper control-channel failure during the SCM_RIGHTS protection handshake, malformed descriptor count, duplicate ancillary batch and protection ACK timeout. Every case must close the bind/helper and report a bounded startup/recovery failure.
16. Verify automatic WireGuard rekey/keepalive behavior comes from pinned upstream `wireguard-go`; GeDefense must not log private/preshared keys or place them in process arguments, temporary plaintext files, diagnostics or Evidence.
17. Capture release traffic on a controlled lab network. Outside the tunnel, only the configured peer endpoint plus explicitly documented GeDefense egress may appear; inner destinations and configured WireGuard DNS must not bypass the tunnel.
18. Run Recovery Self-Test in Direct, WireGuard and WireGuard Strict modes. WireGuard recovery must rebuild the helper instead of reopening an already-protected bind in place, and Strict must remain leak-blocked by Android lockdown throughout.
19. During WireGuard recovery, remove every physical underlay for longer than the normal retry window. Verify the Android VPN interface remains present, app traffic remains captured, the recovery-attempt counter does not advance while no underlay exists, and recovery resumes only after a usable underlay returns.
20. Disable Android "Block connections without VPN" while an already-running WireGuard Strict session is active. Within the bounded invariant-watch interval GeDefense must enter the explicit recovering/lockdown-lost state while retaining the TUN anchor. Re-enable lockdown and verify the live helper is retained when healthy or rebuilt when dead, with no Direct-mode transition.
21. Race helper death against Wi-Fi -> cellular handover repeatedly. A recovery built on the new underlay may satisfy the pending handover, but a newer network generation must never be cancelled by an older recovery completion. Verify no duplicate long-lived helper, stale protected UDP socket or direct-routing interval.
22. Saturate/force rejection of the bounded VPN control queue in an instrumented build. WireGuard Strict must retain a fail-closed anchor and expose `recovery_scheduler_busy`; non-Strict modes may terminate according to policy but must never silently switch to Direct.

23. Saturate the bounded control queue specifically while a WireGuard Strict watchdog re-arm is due. If Android lockdown remains enabled, GeDefense must stop the affected Strict session and rely on the OS lockdown rather than falsely reporting it healthy; if lockdown is already absent, the existing TUN anchor must remain captured and the explicit lockdown-lost state must be visible.
24. Delay delivery of an old helper telemetry EOF until after a successful handover/recovery has installed a newer helper. The stale fatal callback must be discarded by transport generation and must not recycle the newer healthy session.


## Telemetry Shield v1 real-device gates

1. With VPN stopped, switch among OFF, Conservative, Balanced and Strict; restart the app and verify the selected profile persists. While VPN is STARTING/active/RECOVERING, profile mutation must be refused.
2. In Direct Full Flow, query a known high-confidence low-breakage telemetry test domain from the packaged registry and verify GaiaNet returns local NXDOMAIN with no upstream DNS flow.
3. Repeat the same policy decision in WireGuard mode; Direct and WireGuard must produce the same rule/action and no Direct fallback.
4. Query a documented essential connectivity/push/update rule that overlaps a broader telemetry suffix and verify essential ALLOW wins.
5. Verify OFF performs no privacy blocking while Threat Intelligence enforcement remains unchanged.
6. Verify Conservative blocks only high-confidence/low-breakage advertising, analytics and attribution rules; Balanced additionally permits local authority for eligible device telemetry; Strict still preserves essential-service precedence.
7. Tamper with the native privacy-policy descriptor/digest in an instrumented build and verify helper startup rejects it rather than running with a partial policy.
8. Generate repeated requests to one observed/blocked domain and verify Evidence/XDR dedupe prevents event floods while counters/enforcement remain correct.
9. Exercise private DNS / DoT / DoH and confirm GeDefense makes no false claim that encrypted DNS payloads were classified; no TLS interception is introduced.
10. Verify no runtime request to VGT, Sophos or a tracker API occurs when Telemetry Shield is enabled; all decisions come from the signed local snapshot.
11. Select Selective mode with a non-OFF Telemetry Shield profile and verify UI/documentation explicitly states that system-wide telemetry filtering requires Full Flow; no Selective-mode protection claim may be shown.


## InstallGuard v1 real-device gates

1. With Full Flow active, install a benign non-system test APK and verify quarantine is staged before the priority scan, network egress is denied while the verdict is pending, PASS releases quarantine, and the app then obtains normal connectivity.
2. Repeat with an update (`PACKAGE_REPLACED`) while the app has active Direct TCP/UDP traffic; verify policy synchronization closes stale Direct flows and subsequent flows are attributed again before egress.
3. Repeat tests 1-2 in WireGuard mode and verify quarantined packets never bypass into the WireGuard egress.
4. Force Android owner resolution to timeout/return unknown in an instrumented build while quarantine is active; the queried flow must be denied and no upstream socket/datagram may be opened.
5. Break/malformed-close the package-gate IPC channel while quarantine is active; GaiaNet must fail closed, terminate/recover through the retained TUN anchor and never silently switch to Direct.
6. Generate fragmented traffic from a quarantined app; Direct reassembly must still reach the gate and WireGuard fragmented traffic must be denied while quarantine is active.
7. Produce REVIEW, BLOCK and INCOMPLETE verdicts and verify quarantine remains persisted across process/service recovery; only an explicit PASS/operator action may release it according to policy.
8. Install/update a system/updated-system package in a disposable OEM test environment and verify it is scanned/reported but not automatically suspended or package-quarantined by InstallGuard.
9. On a Device Owner test device with auto-suspend enabled, install a user test app and verify Android suspension prevents launch until PASS; REVIEW/BLOCK/INCOMPLETE remain suspended/quarantined.
10. On Standard/TITAN Light, verify UI/docs do not claim an absolute pre-first-packet/pre-launch guarantee; enforcement starts once the package event has staged quarantine.
11. Stress concurrent install/update events beyond the bounded active set and verify excess work records INCOMPLETE while still staging containment for eligible user packages.
12. Install a brand-new benign APK with no previous authenticated signer evidence and verify Fast Verdict does not release it; containment remains until the bounded Deep Scan completes.
13. Update the same benign app with signer continuity and low-risk metadata; verify Fast Verdict may release it quickly while Deep Scan continues, and Scanner UI shows the stage transition.
14. Force Fast Verdict timeout/capacity exhaustion and verify the app remains quarantined with INCOMPLETE rather than being treated as clean.
15. Force Deep Scan timeout after a known update was fast-released and verify quarantine is reinstated before INCOMPLETE is published.
16. Confirm InstallGuard performs no Sophos/VGT/third-party runtime verdict API requests; scanner, Threat Intelligence, signer state and XDR evidence remain local.


## Resilience Supervisor v1 real-device gates

1. Trigger the persisted resilience job on a healthy device and verify it performs no destructive mutation, records a bounded healthy report and causes no VPN interruption.
2. Start the job while secondary trust stores are still initializing after process recreation; verify the supervisor reports bounded `RETRY_LATER` rather than a false integrity failure and succeeds on a later run.
3. Corrupt a disposable signed-asset test fixture and verify only signed-snapshot reload is attempted; repeated failure exhausts the component retry budget and never downloads repair material.
4. Simulate transient Evidence verification failure followed by recovery; verify no ledger reset occurs, recovery is recorded once, and a persistent authentication failure remains `OPERATOR_REQUIRED`.
5. Stage stale firewall package entries and verify bounded pruning removes only packages proven absent by one package inventory snapshot; transient PackageManager failure must prune nothing.
6. With a package quarantined in Full Flow, force the GaiaNet package-egress gate inactive and verify the supervisor reasserts quarantine or reports `FAIL_CLOSED`; no Direct fallback is permitted.
7. On Device Owner with auto-suspend enabled, unsuspend a still-quarantined test package out of band and verify the supervisor re-suspends it after Android readback.
8. Break cached Threat Intelligence while a last-known-good snapshot remains and verify local reload restores it. With no usable local snapshot, verify `SYNC_REQUIRED` without an automatic cloud/API verdict call.
9. Force packaged GaiaNet availability revalidation failure while Full Flow is active and verify the result is `FAIL_CLOSED`; when VPN is inactive the same condition remains bounded/retryable.
10. Present a self-integrity mismatch and verify the supervisor may re-scan the signed install but never advances/replaces the same-version integrity baseline to make the mismatch disappear.
11. Corrupt the reconstructible malware-analysis cache and verify it becomes `SCAN_REQUIRED`; it must not be silently reset into a trusted clean verdict.
12. Stress repeated repair triggers and overlapping Integrity/Resilience jobs; verify single-flight behavior, per-run repair ceiling, cooldown/window exhaustion and no unbounded thread/queue growth.
13. Reboot and upgrade the app, then verify the persisted two-hour resilience job is restored alongside existing jobs without requiring network access.
14. Inspect Diagnostics export and confirm self-healing data is aggregate-only: no package names, IPs, domains, file paths or raw Evidence/XDR details.
15. Measure idle battery/wakeup behavior across a representative 24-hour period and verify the supervisor does not create a restart/recovery storm or materially alter packet-enforcement latency.


## Telemetry Shield encrypted DNS / non-MITM gates

1. In Full Flow + Conservative, generate owned/lab TCP/853 DoT and UDP/853 traffic; verify GeDefense records `ENCRYPTED_DNS` observation but does not block solely because of port 853.
2. Repeat in Strict Direct mode; verify TCP/853 receives no upstream connection and UDP/853 receives no upstream datagram, with Evidence/XDR block records tied to the owning app when attribution succeeds.
3. Repeat test 2 through WireGuard egress; encrypted-DNS traffic must be blocked before the WireGuard send path.
4. Resolve/connect to documented Google Public DNS, Cloudflare and Quad9 bootstrap domains. In Strict, visible ordinary-DNS bootstrap queries must match the signed `ENCRYPTED_DNS` rules and be locally blocked.
5. Browse normal HTTPS sites on TCP/443 in Strict and verify they are not blocked merely because HTTPS can carry DoH.
6. Use an owned custom DoH endpoint on HTTPS/443 with a hard-coded IP or ECH-capable test path and confirm GeDefense does not falsely claim universal detection; the UI/docs must preserve the explicit non-MITM visibility limitation.
7. With Android/OEM Private DNS configured, validate actual device behavior separately because Android may place system resolver traffic differently across versions/OEMs; GeDefense only claims enforcement for traffic captured by its TUN.

## Update-stable cryptographic continuity

1. Seed every durable vault domain on the prior signed build, including Evidence and XDR.
2. Update in place without clearing application data and verify the application starts without reinstall/reset.
3. Confirm the installed APK hash changes are accepted only as a forward signed integrity update and do not alter encryption custody.
4. Verify Evidence/XDR v4 HMAC state rotates to persistent v5 and remains valid across at least three process restarts.
5. Verify low-frequency domains migrate from derived v2 to persistent v3 and WireGuard from derived v1 to persistent v2 only after successful decrypt + durable rewrite.
6. Inject a migration write failure on a disposable device and verify plaintext is not released, historical state remains intact, and retry succeeds after the fault is removed.
7. On the Xiaomi/HyperOS device that reproduced `package_baseline_key_operation_failed` / `snapshot key operation failed`, install the fixed build in place without clearing data. Verify encrypted package-baseline, network-discovery and Port Sentinel snapshots recover through inner AEAD, are durably re-HMACed under the stable domain key, and no longer emit `Authenticated security state degraded` after a reboot.
8. If the historical VPN-disclosure HMAC is unusable, verify protection remains fail-closed until the user explicitly re-accepts the disclosure once; after acceptance, reboot and a subsequent in-place update must preserve the receipt.
9. Exercise a disposable encrypted snapshot with a corrupted outer HMAC but intact inner AEAD and confirm recovery succeeds; then corrupt the inner ciphertext/tag and confirm recovery fails closed. Repeat with a plaintext legacy snapshot and confirm unauthenticated recovery is refused.
