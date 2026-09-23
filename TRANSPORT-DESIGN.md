# GaiaNet V2 Full Flow Transport — 0.27.8-beta.5 integration checkpoint

## Security boundary

Android `VpnService` remains the **only** Android VPN owner. Kotlin owns lifecycle, Android VPN policy, Keystore-backed state, package attribution, physical-network selection and UI. GaiaNet V2 owns the packet hot path in a separate, packaged in-tree Go helper process.

Two egress modes intentionally use different recursion-avoidance rules:

```text
DIRECT
App socket
   -> Android VPN TUN
   -> GaiaNet V2 helper
        -> parse / threat policy / TCP+UDP state
        -> BLOCK or kernel TCP/UDP upstream socket
   -> GeDefense app UID is excluded from the Android VPN
   -> physical Android network

WIREGUARD / WIREGUARD_STRICT
App socket
   -> Android VPN TUN
   -> GaiaNet V2 helper
        -> parse / threat policy / bounded state
        -> BLOCK or embedded wireguard-go Layer-3 egress
   -> only the WireGuard UDP transport sockets are bound to the selected
      physical Network and exempted with VpnService.protect()
   -> WireGuard peer
   -> Internet
```

The whole GeDefense UID is **not** excluded in WireGuard mode. Doing so would create an unnecessarily broad VPN bypass. The only recursion exception is the exact WireGuard UDP socket set required to reach the peer.

`WIREGUARD_STRICT` additionally requires Android Always-on VPN lockdown. A missing/failed tunnel never falls back to Direct mode. Non-strict WireGuard still fails tunnel establishment closed, but only Android lockdown can guarantee that other apps cannot use the physical network during a temporary Android VPN teardown/re-establish window.

## Helper startup and descriptor protocol

`NativeGaiaNet` starts only the packaged ABI-specific `libgedefense_gaianet_v2.so` after size, ELF and executable checks. `ProcessBuilder` receives no shell command. A private filesystem Unix-domain control socket authenticates the child with a 32-byte random token.

Helper protocol v4 uses the fixed 44-byte initialization frame. The MTU is authenticated inside that frame and is constrained to `1280..1420`; its reserved bytes must be zero. v4 Direct transfers four descriptors (TUN, telemetry, threat policy, privacy policy) and v4 WireGuard transfers five by adding the one-shot WireGuard config pipe. Older v1/v2 40-byte frames and v3 44-byte frames remain parser-compatible for bounded migration/testing, but the current Android runtime emits v4.

Direct mode transfers exactly three startup descriptors with `SCM_RIGHTS`:

1. Android VPN TUN
2. telemetry writer
3. immutable GDTI-v2 policy

WireGuard mode transfers a fourth one-shot descriptor containing the canonical WireGuard device configuration. The helper consumes the configuration through the pipe and does not place private-key material in process arguments or ordinary files.

There is no per-packet JNI/Kotlin callback.

## WireGuard socket-protection handshake

WireGuard transport sockets are created inside the GaiaNet helper. Before `wireguard-go` is allowed to complete `Bind.Open()`, GaiaNet sends the exact UDP socket descriptors to the authenticated Android control endpoint with `SCM_RIGHTS`.

Android then, for every received descriptor:

1. duplicates the descriptor into a managed `ParcelFileDescriptor`;
2. binds it to the same selected physical `Network` used as the VPN underlay;
3. calls `VpnService.protect(fd)`;
4. closes the received/duplicated descriptor after processing; and
5. acknowledges success only if the complete required socket set was protected.

The Go side does not return a usable WireGuard bind before the acknowledgement arrives. Missing descriptors, malformed frames, Android refusal, an upstream FD lookup failure, timeout or control-channel failure closes the bind and fails startup. The helper never silently substitutes an unprotected socket. The initial helper startup read uses a bounded absolute deadline, and the later Android socket-protection acknowledgement explicitly re-arms a fresh 5-second read window so policy/config parsing time cannot consume the IPC response budget. If the Android peer dies, the control channel fails closed on the next read/syscall via the kernel-managed Unix-domain socket EOF/error; there is no keepalive or polling-delay claim.

The Android FD receiver tolerates partial stream reads while collecting ancillary descriptors and closes unexpected descriptors rather than leaking them.

## Toolchain and native artifacts

The `.so` suffix is an Android extraction convention; GaiaNet is an executable helper, not a JNI library.

- `arm64-v8a`: Go 1.26.8, `CGO_ENABLED=0`, Android/arm64.
- `x86_64`: Go 1.26.8, Android/amd64 with the pinned Android NDK `27.2.12479018` Clang as the external linker. Go 1.26.8 does not support this Android target as a completely internal `CGO_ENABLED=0` link.
- The real helper main is selected for Android independent of cgo; cgo must never cause selection of a no-op helper stub.
- Embedded WireGuard and its Go dependencies are pinned and fully vendored. Release verification runs with `GOPROXY=off`/`GOSUMDB=off` and must not fetch modules.

## Threat policy

The policy FD carries the deterministic full-policy SHA-256. GaiaNet verifies the fingerprint, canonical prefix encoding, unique records, exact EOF and the fixed nine-feed authority mapping before publishing the policy. Serialized evidence cannot promote correlate/annotate feeds into block authority.

Policy evaluation happens **before** either Direct upstream sockets or WireGuard egress. WireGuard therefore does not bypass GaiaNet threat policy.

## Transport and state limits

- TCP Window Scale is parsed/negotiated and the client scale is applied to the synthetic downstream send window.
- Downstream unacknowledged data: 1 MiB maximum per flow, 32 MiB global reservation ceiling.
- Upstream dialing: bounded queue with at most 64 dial workers.
- TCP/UDP hot-path buffers use ownership-safe `sync.Pool` reuse.
- UDP flow ceiling: 1024.
- Normal TCP idle: 10 min; power-constrained TCP idle: 90 s.
- Normal half-open: 20 s; power-constrained half-open: 8 s.
- Normal UDP idle: 90 s; power-constrained UDP idle: 30 s.
- WireGuard ICMP echo state is short-lived and bounded.
- WireGuard fragment state is bounded to a small number of short-lived datagrams; continuation fragments are not admitted before a related initial fragment establishes state.
- Fragment, flow, TUN, telemetry and retransmission memory remain explicitly bounded.

For Direct mode, the real upstream connection is an Android/Linux kernel TCP socket and therefore receives the kernel's TCP congestion/window behavior. The userspace Window Scale work applies to the synthetic app↔GaiaNet TCP leg and does not replace the kernel upstream TCP implementation.

## WireGuard ingress policy

A WireGuard peer is not treated as a trusted source of arbitrary packets. GaiaNet maintains state before writing decrypted peer traffic back to the Android TUN:

- TCP/UDP responses must correspond to an active outbound flow.
- ICMPv4/ICMPv6 echo replies must match a previously observed echo request and are consumed to prevent replay through stale state.
- ICMP errors are accepted only when the quoted original packet maps to an active outbound TCP/UDP/ICMP context. This includes ICMPv6 Packet Too Big, required for Path-MTU Discovery.
- First IP fragments must establish a related transport/control context. Continuation fragments are accepted only against short-lived fragment state created by the related first fragment.
- Unsolicited, malformed, unsupported or stale peer traffic is dropped.

GaiaNet intentionally does not perform complete application-layer inspection of encrypted traffic inside the tunnel.

## MTU and IPv4/IPv6 behavior

WireGuard profiles may specify MTU `1280..1420`. The selected MTU is carried through Android, authenticated helper protocol v4 and the in-process WireGuard TUN. Invalid or contradictory values reject the profile/startup rather than being silently clamped.

Android routes both `0.0.0.0/0` and `::/0` into GeDefense. A profile must contain `0.0.0.0/0`; IPv6 configuration is coherent and requires `::/0` when an IPv6 interface address or IPv6 DNS server is configured. An IPv4-only WireGuard profile therefore blackholes unsupported IPv6 inside the VPN instead of leaking it to the physical network.

Related ICMPv6 Packet Too Big messages are admitted through stateful ingress so IPv6 Path-MTU Discovery can function.

## Physical-network handover

The Android service observes physical `NET_CAPABILITY_NOT_VPN` networks and updates `VpnService.setUnderlyingNetworks()`. WireGuard endpoint resolution is performed against the selected physical `Network` before VPN establishment.

A preferred-network change debounces a controlled Full Flow helper rebuild. Existing WireGuard sockets are closed; the replacement helper resolves/binds/protects its new UDP transport sockets against the newly selected physical network and must complete the protection handshake before traffic resumes.

Direct mode continues to rebuild its kernel upstream sockets on handover. Power-constrained state is sent over the authenticated control channel so GaiaNet can shorten dead-flow retention.

## WireGuard configuration boundary

Imported WireGuard configuration is deliberately narrow:

- maximum 16 KiB / 128 lines;
- strict UTF-8 import;
- exactly one `[Interface]` and one `[Peer]`, with no section re-entry;
- duplicate MTU and keepalive fields rejected;
- canonical full-tunnel AllowedIPs;
- numeric DNS only, 1..4 servers;
- unsafe unspecified, multicast, loopback and link-local interface/DNS/endpoint addresses rejected;
- IPv4 interface address required;
- IPv6 address/DNS/full-route coherence enforced;
- helper-side UAPI validation repeats security-critical endpoint/keepalive/key constraints as defense in depth.

The import screen uses `FLAG_SECURE`, disables autofill/personalized learning, and zeroes the raw imported byte buffer after strict decoding. JVM `String` lifetime cannot be explicitly zeroized, so WireGuard secrets are not represented as process arguments and are handed to the helper through the one-shot pipe as soon as practical.

## Verification

The source-level release matrix includes:

- `gofmt`, `go vet`, normal tests, race detector, shuffle/repetition tests and Android-helper-tag tests;
- encrypted end-to-end `wireguard-go` roundtrip coverage;
- protected-socket fail-closed tests;
- stateful TCP/UDP, ICMP/ICMPv6, PMTU and fragmented-flow tests;
- `tools/wireguard-audit.py` for architecture invariants;
- `tools/wireguard-parser-check.sh` as an SDK-independent adversarial compile/test of the production Kotlin parser when host `kotlinc` is available;
- reproducible arm64/x86_64 Android helper rebuilds and byte comparison with packaged artifacts;
- 16 KiB ELF PT_LOAD alignment verification.

Full Android Gradle compilation, Lint, packaged-artifact comparison, OEM behavior, Always-on lockdown, mobile/Wi-Fi handover, sleep/Doze, sustained TCP/UDP/QUIC/ICMP, DNS, local-LAN behavior and battery/performance remain real-device/release-toolchain gates. No source-only test is a substitute for those checks.


### Privacy policy descriptor

Telemetry Shield is transported as a distinct immutable descriptor rather than being mixed into Threat Intelligence authority. The binary begins with `GDPI`, format version 1, selected profile and bounded record count, followed by a SHA-256 digest over the record payload. GaiaNet rejects malformed flags/enums, duplicate identifiers, non-canonical domains, oversized fields, essential rules carrying non-ALLOW actions, digest mismatch and trailing bytes before packet processing begins.

Direct and WireGuard paths share the same native decision engine. Only visible classic DNS/UDP queries are classified in v1; GeDefense does not claim visibility into encrypted DNS payloads or TLS/QUIC application content and performs no interception.
