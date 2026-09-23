# Embedded WireGuard — Integration Status

GeDefense Mobile now contains the first production WireGuard egress implementation for the release following `0.27.8-beta.5`. The source version intentionally remains **VC54 / 0.27.8-beta.5** until the Android build, packaged native helpers and physical-device gates pass on the exact frozen tree.

## Implemented architecture

```text
Android App Traffic
       |
       v
GeDefense VpnService / Android TUN       <-- only Android VPN owner
       |
       v
GaiaNet packet parser + threat policy
       |
       +---- BLOCK
       |
       `---- ALLOW
               |
               v
      in-process wireguard-go TUN
               |
               v
       upstream wireguard-go
               |
       protected + underlay-bound UDP sockets
               |
               v
       configured WireGuard peer
```

WireGuard is a Layer-3 egress behind GaiaNet. It is not modeled as a SOCKS/TCP proxy and never owns a second Android `VpnService`.

## Implemented security boundary

- Upstream `wireguard-go 0.0.20250522` is vendored and pinned; GeDefense implements no WireGuard cryptographic primitives.
- Direct, WireGuard and WireGuard Strict are explicit egress modes. WireGuard startup never silently falls back to Direct.
- Strict mode requires Android Always-on VPN lockdown before protection can start. Android lockdown remains the authoritative kill switch during helper failure, process death and network handover.
- WireGuard mode does **not** exclude the whole GeDefense UID from the VPN. GaiaNet transfers only the upstream WireGuard UDP socket descriptors to Android with `SCM_RIGHTS`; Android binds each socket to the selected physical `Network`, calls `VpnService.protect()` on that socket, and acknowledges success before the WireGuard bind is allowed to return.
- A preferred `NET_CAPABILITY_NOT_VPN` underlay is selected before endpoint resolution, TUN establishment and socket protection. Underlay **loss** keeps the Android TUN anchored and pauses recovery without burning the bounded retry budget; a usable replacement underlay triggers a debounced helper rebuild. Network callbacks carry a generation so a stale handover can neither recycle a newer recovered session nor suppress a genuinely newer underlay event.
- Imported configurations are bounded to 16 KiB / 128 lines, strict UTF-8 on file import, exactly one Interface and one Peer, bounded address/DNS/AllowedIPs counts, one mandatory IPv4 default route, coherent optional IPv6 full-tunnel state and MTU `1280..1420`.
- DNS servers are explicit numeric addresses. WireGuard mode does not accept an empty DNS set and does not intentionally inherit Android's ordinary resolver into the tunnel configuration.
- Numeric endpoints reject unspecified, multicast, loopback and link-local addresses. Hostname endpoints are resolved on the selected physical underlay before the Android VPN is established; only the resolved numeric endpoint enters GaiaNet.
- WireGuard profile secrets are kept in the dedicated authenticated/encrypted WireGuard vault domain. One-shot UAPI config is passed to the helper through a pipe, never a temporary plaintext config file, and mutable key/config byte arrays are cleared when ownership ends.
- Secret-bearing profile/UAPI serialization uses fixed-capacity explicitly wipeable scratch storage rather than non-wipeable byte-stream backing buffers.
- Build repository configuration contains no checkpoint-machine path; an optional controlled Maven mirror is injected with `VGT_LOCAL_MAVEN`, and release readiness rejects host-specific Gradle paths.
- Helper protocol v3 propagates the selected WireGuard MTU end-to-end and rejects invalid/reserved fields. v2 remains read-compatible with the conservative 1280 default for checkpoint compatibility.
- Decrypted peer traffic is stateful. Unsolicited TCP/UDP is rejected. ICMP echo replies require matching request state; ICMPv4/v6 errors are admitted only when the quoted packet belongs to active state. Fragmented TCP/UDP/ICMP uses bounded short-lived fragment state and continuation fragments are not admitted before a related initial fragment.
- WireGuard ingress cannot change GeDefense threat policy. GaiaNet evaluates the immutable local threat policy before packets enter WireGuard.
- The service retains an Android-side TUN liveness anchor after GaiaNet startup. A helper crash therefore cannot destroy the VPN interface by becoming the last TUN-FD owner. Recovery establishes the replacement VPN interface before closing the prior session/anchor, and a failed WireGuard helper start retains the newly established TUN as a no-reader fail-closed emergency anchor.
- WireGuard Strict continuously re-checks the Android lockdown invariant with a single bounded 5-second watchdog task. Runtime lockdown loss leaves the VPN/TUN anchor active and reports `wireguard_strict_android_lockdown_lost`; restoration either resumes the live helper or rebuilds from the retained anchor. Failure to schedule the watchdog is itself fail-closed: when Android lockdown is still present the session is stopped so the OS kill switch remains authoritative; when lockdown is already gone the TUN anchor is retained rather than deliberately opened.
- Full-Flow telemetry callbacks are transport-generation scoped. `tearDownFullFlow()` invalidates the old generation before closing it, and fatal reader callbacks re-check generation after crossing the main/control queue boundary, preventing a stale EOF from an old helper from tearing down a newer healthy handover/recovery session.
- Rekey, handshake retransmission and keepalive behavior remain upstream `wireguard-go`. `tools/wireguard-upstream-check.sh` executes the vendored `device`, `replay` and `ratelimiter` packages fully offline, while `wireguard-audit.py` pins the upstream rekey constants/path (`RekeyAfterTime`, `RekeyTimeout`, send and retransmit timer logic).

## Current verification

Verified in the current workspace after the integration changes:

```text
GOFMT_PASS
go vet ./... PASS
go test ./... PASS
go test -race ./... PASS
go test -shuffle=on -count=10 ./... PASS
go test -tags=gdandroidhelper ./... PASS
go vet -tags=gdandroidhelper ./... PASS
WIREGUARD_AUDIT_PASS
WIREGUARD_PARSER_CHECK_PASS
WIREGUARD_UPSTREAM_CHECK_PASS offline=true packages=device,replay,ratelimiter
WIREGUARD_ADVERSARIAL_GO_PASS repeat=10 race_repeat=3 shuffle=10
MAIN_THREAD_IO_AUDIT_PASS
STARTUP_ANR_AUDIT_PASS
CORE_TESTS_PASS
I18N_PASS
NETWORK_EGRESS_PASS
ONBOARDING_AUDIT_PASS
SECURE_TELEMETRY_VAULT_PASS
FULL_FLOW_AVAILABILITY_PASS
RUNTIME_BOOTSTRAP_AUDIT_PASS
```

`tools/security-audit.sh` also reaches the native Android helper verification stage in the current container. It cannot complete here because this environment does not provide `ANDROID_SDK_ROOT` / `ANDROID_HOME` and the pinned NDK. `lint-zero-audit.py` likewise cannot pass until a current Android lint report exists.

## Remaining release gates

The WireGuard implementation is **not yet release-frozen**. Before changing to VC55 / beta.6, the exact final tree still needs:

1. JDK 17 + Android SDK 36 + pinned NDK `27.2.12479018` build of both helper ABIs.
2. `compileReleaseKotlin`, release assemble/bundle and `lintRelease` on the modified Kotlin sources.
3. Full `SECURITY_AUDIT_PASS`, source-manifest freeze and `RELEASE_READINESS_PASS`.
4. APK/AAB artifact, signing, 16 KiB native alignment and version-metadata audits.
5. Real-device tests on the Xiaomi/HyperOS target: import, Direct -> WireGuard -> Strict transitions, protection start/stop, DNS, IPv4, optional IPv6, large UDP/fragment handling, Wi-Fi/cellular handover, Doze, endpoint failure, peer failure, helper crash/recovery and Android Always-on lockdown behavior.

Until those gates pass, `VERSION` and `VERSION_CODE` stay at `0.27.8-beta.5` / `54` by design.
