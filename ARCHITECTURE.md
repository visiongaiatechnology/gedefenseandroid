# GeDefense Mobile Architecture — 0.27.8-beta.6

## Secure Telemetry Vault

`SecureTelemetryVault` is the Android key-custody adapter; `core/AeadVaultEnvelope` is the single persistent AEAD codec and is pure JVM code so the binary format/AAD contract can be regression-tested without Android. The Android layer never exports persistent root material. Active vault generations use an installation-stable Android-Keystore HMAC root only as a PRF boundary; independent random per-domain keysets are wrapped at rest and expanded in process into separate AES-GCM and HMAC-SHA-256 subkeys. `SecureSnapshotStore` composes the vault envelope underneath the existing authenticated crash-safe snapshot, so confidentiality and independent structural authentication use separate keys.

Security-state publication uses a shared crash-safety contract: same-directory staging, file-data fsync, candidate authentication/read-back verification, atomic replace without non-atomic fallback, then parent-directory fsync. `core/DurableAtomicFiles` owns JVM/core publication while Android filesystem publication uses `SecureFiles`; unsupported atomic replacement fails closed instead of silently reducing durability. Directory enumeration on recovery paths is bounded and uses no-follow semantics so corrupted/private state cannot induce unbounded allocations or symlink traversal.

Persistent AEAD uses AES-256-GCM with a fresh 96-bit nonce and 128-bit tag. AAD binds format, domain, logical binding, schema, key generation and exact lengths. Legacy authenticated plaintext snapshots are encrypted and committed before release to callers. A versioned key-generation field enables fail-closed re-encryption-on-read. Evidence implements the same domain through `EvidencePayloadProtector`, retaining its record-chain HMAC while encrypting canonical event payloads.

Android Keystore availability is isolated from process availability. Evidence performs its wrapped-key encrypt/decrypt preflight before ledger construction and exposes an explicit fail-closed `UnavailableEvidenceStore` if key custody, unwrap, migration or private-storage I/O is unavailable. That store rejects every append and recovery operation and can never report a healthy empty ledger. XDR uses the same startup boundary internally: its event store remains constructible but reports degraded integrity and refuses mutation when wrapped-key bootstrap fails. Neither path deletes continuity-sensitive key or ciphertext files automatically, and VPN readiness remains blocked while Evidence is unhealthy.

The same availability boundary applies to every HMAC-authenticated runtime store. `AuthenticatedSnapshotStore` accepts explicit unavailable key custody as a first-class fail-closed state: reads return `INVALID`, writes throw a bounded storage failure, and clear/recovery is refused so continuity evidence cannot be destroyed while authentication is unavailable. Threat Intelligence publishes an empty policy, Integrity remains untrusted, and Geo-country remains unavailable when their keys cannot be acquired. Non-critical domains remain inspectable in degraded state, allowing `AppRuntime` construction and UI routing to complete without granting protection readiness.

Encrypted snapshot stores use the update-stable per-domain HMAC subkey for the active outer authentication layer. Historical direct AndroidKeyStore HMAC aliases are retained only as read-only migration material. If an OEM makes such a historical HMAC unusable after an app update, `SecureSnapshotStore` may recover the outer layer only when the payload is already a valid inner AES-GCM vault envelope: it parses the bounded outer framing as untrusted bytes, authenticates/decrypts the inner AEAD, and atomically re-seals the snapshot under the active outer HMAC before releasing plaintext. Plaintext legacy snapshots never receive this recovery bypass. The VPN disclosure receipt contains no inner AEAD, so an unusable historical HMAC deliberately requires one fresh explicit acceptance rather than trusting unauthenticated authorization state.

`HybridArtifactSigner` is a separate authenticity plane for durable/exportable security artifacts. It uses Android-Keystore ECDSA P-256/SHA-256 and conditionally adds platform-native ML-DSA-87 on Android 17+ hardware exposing KeyMint 5. Neither signature mechanism participates in data encryption.

The vault is an at-rest boundary. It is not claimed to conceal plaintext from a fully compromised live process that can legitimately ask Android Keystore to perform operations or observe post-decryption memory. Full-device replay of an earlier valid state is also outside the claimed anti-rollback boundary because the design has no universal hardware monotonic counter.

## 1. System invariant

GeDefense Mobile transfers GeDefense security semantics to Android without pretending Android is Linux:

```text
identity -> observation -> normalized evidence -> immutable policy -> local decision -> evidence
```

Android trust boundaries are `VpnService`, app UID ownership, PackageManager identity, app-private storage and Android Keystore.


## XDR / EDR correlation plane

The XDR plane is local-first and intentionally does not require a remote SOC or cloud account. `PackageBaselineStore` snapshots package version, signer identity, requested/granted permissions and privileged Android component capabilities. `PackageChangeReceiver` and startup reconciliation feed drift into `XdrEngine`.

`XdrEngine` receives bounded evidence from package drift, integrity checks, app/storage scanners and GaiaNet threat blocks. `XdrEventStore` persists a bounded local timeline and correlates recent events by package/artifact identity into incidents. Scores are correlation/routing signals, not standalone malware verdicts. Every accepted XDR event is also mirrored into the authenticated Evidence ledger.

`0.16.0-beta.1` adds structured local forensics without changing the trust boundary: detector raw scores, per-finding weights and bounded artifact facts are stored as optional authenticated XDR-event fields. The UI derives the XDR correlation recipe from the exact same pure scoring function used by the store, so the displayed score explanation cannot silently drift from the scoring implementation. Existing schema-v2 stores remain readable because all forensic fields are optional.

Response authority is deliberately narrow on ordinary non-root Android: GeDefense can quarantine network access by binding package state to the Lockdown allowlist, and it can activate Emergency Lockdown. It does not claim the ability to silently uninstall, disable or mutate other applications without platform/device-owner authority.

## TITAN Device Owner policy plane

TITAN is an optional privileged response adapter over the existing detection/XDR plane. `TitanPolicyManager` is the sole `DevicePolicyManager` authority; `TitanPolicyStore` persists only GeDefense-owned response preferences in an HMAC-authenticated snapshot, while effective OS policy is always read back from Android. `TitanDeviceAdminReceiver` declares the minimal admin policies required for credential/wipe enforcement. Android 12+ managed-device provisioning is handled through dedicated `GET_PROVISIONING_MODE` and `ADMIN_POLICY_COMPLIANCE` activities protected by `BIND_DEVICE_ADMIN`; the ordinary TITAN settings activity remains non-exported.

Response ordering is intentional: `XdrEngine` commits normal GeDefense network quarantine first and only then asks TITAN to suspend a package when the operator has enabled that policy. Automatic uninstall is not an XDR action. Operator-confirmed removal uses `PackageInstaller` with an explicit, internal one-shot result receiver. System/updated-system packages and GeDefense itself are protected from suspension/removal by local policy. Always-on VPN policy is enabled only after Full Flow, Threat Intelligence, Evidence and Integrity prerequisites are healthy; Android lockdown cannot be represented by Selective mode.

Managed CA installation is a separate explicit operator flow. Certificate parsing/validation lives in the dependency-free core and accepts exactly one current X.509 CA with bounded input and CA/key-usage checks; the Android layer displays the SHA-256 identity before invoking `DevicePolicyManager.installCaCert`. Certificate bytes are not persisted by GeDefense.

`TitanVisualMode` is a presentation-only projection of Android's effective Device Owner state. When active, `MainActivity` adds `TitanManagedBanner`, common VGT panels/navigation switch to the managed gold/cyan treatment, and TITAN surfaces show a compact command deck. The visual mode never grants privilege and cannot substitute for `DevicePolicyManager` readback. Xiaomi/HyperOS guidance is an OEM-specific provisioning aid only; Xiaomi Enterprise Mode is never treated as Device Owner evidence.

## Local Network Discovery sensor

`NetworkRangePlanner` lives in the dependency-free core and is the authority for active IPv4 scan scope. Public IPv4 ranges are refused, no more than 254 active hosts are emitted, and prefixes broader than /24 are clamped to the device-local /24 window. The Android sensor selects only an underlying Wi-Fi/Ethernet `Network`; active TCP sockets and SSDP are bound to that network so an active GeDefense VPN cannot redirect discovery into the TUN.

`NetworkDiscoveryScanner` uses fixed service probes with bounded workers/connect deadlines, bounded SSDP collection, bounded `/proc/net/arp` enrichment where Android exposes neighbor data, plus bounded mDNS/DNS-SD discovery. DNS decoding lives in the dependency-free core (`MdnsDnsCodec`) with hard packet/record/name/compression limits and explicit malformed-packet rejection. mDNS source addresses must be inside the planner-approved LAN scope, multicast is bound to the selected interface/network, and advertised services remain distinct from TCP-confirmed exposures. There is no shell execution, arbitrary target entry or raw-packet privilege.

`NetworkDiscoveryStore` persists a bounded AES-256-GCM-encrypted and independently HMAC-authenticated schema-v3 baseline with migration from earlier device/port and DNS-SD models. The first successful scan initializes the baseline; later device, port, DNS-SD service and stable-device identity drift enter `XdrEngine` under LAN incident identities. New ports/services on mature devices first enter bounded probationary candidate maps and require repeated complete observations before promotion into the stable baseline. Per-device observation count and exposure-risk EWMA plus network-wide device/elevated-host history feed the dependency-free `LanBehaviorEvaluator`, which emits only after minimum maturity and never treats a partial scan as training evidence. Behavioral anomalies are correlated under the same LAN incident identity but do not silently retrain the risk baseline. `MAC`, `MDNS_HOST` and `IP` are explicitly tagged as different confidence sources. Cancelled or incomplete scans are never committed.

## Network Port Sentinel plane

`PortSentinel` is a bounded non-interactive network listener using Java NIO selectors. Listener scope follows the preferred physical non-VPN Wi-Fi, Ethernet or cellular underlay and binds only the device's currently assigned unicast IPv4/IPv6 addresses for a fixed defensive TCP/UDP port set. TCP connections are accepted only long enough to obtain peer metadata and are then closed; UDP reads are deliberately minimal. Source context distinguishes local LAN, carrier/CGNAT/private mobile space and public Internet. Carrier routing or CGNAT may make mobile listeners unreachable, which is treated as a network property rather than a sensor failure. `PortSentinelClassifier` in the dependency-free core performs bounded multi-port correlation. `PortSentinelStore` authenticates local history and source denylist state. Sentinel events enter the network-sentinel XDR incident namespace.

In Selective Shield, authenticated denylist entries become `/32` sink routes evaluated by the TUN reader before public threat-policy evaluation. Full Flow handover watches `NET_CAPABILITY_NOT_VPN`, updates `setUnderlyingNetworks`, and debounces a controlled GaiaNet V2 helper restart when the preferred physical network changes. Direct-mode upstream sockets are recreated with the helper. In WireGuard mode the endpoint is resolved on the selected physical `Network`, and only the upstream WireGuard UDP sockets are bound to that same underlay and exempted from VPN recursion with per-socket `VpnService.protect()` before the WireGuard bind becomes usable.

## UI render plane

Animated security visuals are presentation-only and never gate protection. `VgtUiPerformance` provides an adaptive `Choreographer`-based ticker for decorative views; cached geometry/shaders keep per-frame allocation bounded. Full Flow telemetry coalesces presentation notifications while policy/evidence processing remains immediate. `MainActivity` renders only the selected primary screen during high-rate state changes, and heavy security/network surfaces use snapshot keys before rebuilding child views. Power-save, low-RAM and recent touch/scroll activity may lower decorative cadence but cannot lower sensor cadence or suppress security events.

## 2. Protection plane

`GeDefenseVpnService` is the sole VPN owner and provides Selective Shield, Full Flow and default-deny Lockdown modes.

### Selective Shield

Only compacted `ROUTE_BLOCK` prefixes are installed. A TUN reader is bound to the exact immutable `ThreatIndex` that produced those routes. Public packets reaching TUN must evaluate to `BLOCK`; disagreement produces `POLICY_INVARIANT_FAILED` and protection stops.

Kernel-generated non-public TUN control traffic is filtered before flow/policy evaluation. DAD, MLD, RS, multicast, link-local, ULA/interface-local and similar packets are not security-policy violations.

### Full Flow Beta

`0.0.0.0/0` and `::/0` are installed so traffic cannot bypass the Android TUN by address family. Direct egress excludes the GeDefense package because its native TCP/UDP proxy sockets otherwise recurse into its own VPN. WireGuard egress deliberately does **not** exclude the whole GeDefense UID: GaiaNet opens the upstream WireGuard sockets, sends only those socket descriptors to Android over the authenticated control channel, and waits until Android has bound and protected them individually. WireGuard Strict additionally requires Android Always-on VPN lockdown and never falls back to Direct.

`NativeGaiaNet` launches the ABI-specific process-isolated GaiaNet V2 helper from `nativeLibraryDir` using `ProcessBuilder` without a shell. A private filesystem Unix-domain control socket authenticates startup with a random 32-byte token. Direct mode transfers TUN, telemetry, immutable threat-policy and immutable privacy-policy descriptors with `SCM_RIGHTS`; WireGuard mode adds a fifth one-shot config-pipe descriptor. Helper protocol v4 carries the bounded TUN MTU and authenticates the local Privacy Intelligence policy as a separate immutable descriptor. The binary policy carries the deterministic full-policy SHA-256 fingerprint; GaiaNet recomputes it before accepting the snapshot, rejects trailing/non-canonical/duplicate records, and independently derives enforcement authority from the fixed nine-feed bit ABI (ABI v2; catalog order and authority mapping are runtime-gated and must be migrated explicitly) so serialized data cannot escalate `ANNOTATE_ONLY` or `CORRELATE_ONLY` into blocking. The startup control socket uses bounded absolute deadlines; the separate Android WireGuard socket-protection response re-arms its own 5-second read deadline after policy/config initialization. Android-helper death is observed fail-closed on the next control-channel syscall through kernel Unix-socket EOF/error, not through an asserted zero-millisecond userspace detector. No per-packet Kotlin policy callback exists.

## 3. GaiaNet native plane

GaiaNet V2 is built reproducibly from `netstack/` into ABI-specific executable helpers packaged as `libgedefense_gaianet_v2.so`. The `.so` suffix is an Android packaging/extraction convention; the artifact is executed as an isolated helper process, not dynamically loaded as a JNI library. Runtime transport logic remains Go code. arm64 is built with `CGO_ENABLED=0`; Go 1.26.8 requires the x86_64 Android target to use the pinned NDK linker, but GeDefense does not use that as a JNI bridge or as a custom WireGuard crypto implementation.

All Go dependencies are vendored/pinned in-tree, including upstream `wireguard-go 0.0.20250522` and its pinned `x/*` modules. Major components:

- bounded IPv4/IPv6 parser
- extension-header parsing with explicit bounds
- bounded IPv4/IPv6 fragment reassembly
- overlap rejection
- TCP proxy/state engine
- UDP forwarding, including QUIC payload transport as ordinary UDP
- DNS query-name observation for visible UDP/53 DNS
- immutable threat-policy matcher
- bounded telemetry channel
- bounded TUN writer
- global flow limiter
- optional in-process upstream WireGuard Layer-3 transport behind GaiaNet policy
- per-socket WireGuard underlay protection handshake
- stateful WireGuard peer ingress for TCP/UDP, related ICMP/ICMPv6 and bounded fragment state

### TCP safety constraints

- cryptographic random ISN only; entropy failure rejects the flow
- bounded half-open connections
- bounded upstream queue
- bounded unacknowledged downstream bytes
- finite retransmission count
- client handshake ACK gate before server-originated payload injection
- idle/half-open/handshake deadlines
- flow-local shutdown channel to prevent orphan goroutines
- no dynamic memory growth from unbounded out-of-order/fragment state

### UDP safety constraints

- bounded UDP-flow count
- finite idle lifetime
- write/read deadlines
- bounded response fragmentation to configured TUN MTU

## 4. Threat Intelligence plane

`ThreatFeedCatalog` defines source URLs and immutable authority classes. Downloaded content can supply IP/CIDR evidence only.

Authority precedence:

```text
ROUTE_BLOCK > CORRELATE_ONLY > ANNOTATE_ONLY > ALLOW
```

A single destination may retain evidence from several feeds while the effective action is the maximum compiled authority.

Threat cache generations are bounded, HMAC-authenticated and freshness-gated. A malformed, stale, suspiciously small or interrupted update never publishes a partially built runtime index.

## 5. App identity and traffic analytics

GaiaNet emits bounded line-framed telemetry for flow open/update/close, blocked packets, DNS observations and transport errors.

`FullFlowTelemetryReader` validates every frame before use and resolves flow ownership using `ConnectivityManager.getConnectionOwnerUid()` while the original app connection is live. The result is mapped to bounded package identity/labels.

Session analytics track:

- TX/RX bytes
- active flows
- block/correlation/annotation counts
- top domains
- Top-3 countries
- per-app equivalents

Critical telemetry loss fails Full Flow closed because GeDefense refuses to continue a security mode whose enforcement events cannot be reconciled locally.

## 6. Local country database

`GeoCountryRepository` downloads only fixed HTTPS `sapics/ip-location-db` assets and matching SHA-256 files. It compiles ranges into memory-mappable binary tables and performs local binary search.

The local publication protocol is generation based:

```text
download -> checksum verify -> compile -> fsync -> HMAC manifest -> verify stage
        -> atomic generation move -> authenticated active-pointer swap -> re-open/verify
```

If post-publish verification fails, the previous authenticated pointer is restored. Startup can recover the newest valid HMAC-authenticated generation if the active pointer is missing/corrupt. Only validated generation directories inside the app-private storage jail may be recovered or deleted.

## 6A. Local ASN evidence database

`AsnEvidenceRepository` applies the same generation-safety model to the PDDL/Public-Domain `IPtoASN` IPv4/IPv6 snapshot distributed by `sapics/ip-location-db`. Published source SHA-256 files are verified before compilation. The accepted source is transformed locally into `asn-v4.bin`, `asn-v6.bin` and a deduplicated `asn-org.bin`; the manifest records upstream/distributor identity, license, fetch time, source hashes, compiled hashes and the fixed `evidence_only` classification.

`AsnLiteIndex` memory-maps the authenticated binaries and performs O(log n) range search for both address families. ASN 0 (unannounced/unattributed space) is intentionally omitted. A flow-open match may append local `network.asn` Evidence containing AS number, organization, app attribution, address family and snapshot provenance/hash. It does not include the raw destination address, invoke XDR scoring, or expose block/allow authority. No per-destination ASN network lookup exists.

ASN generations use a dedicated Keystore HMAC alias and independent authenticated active pointer. A corrupt or interrupted refresh therefore retains the previous valid ASN generation without weakening Geo, Threat Intelligence or Evidence state.

## 7. Integrity and malware-risk plane

`IntegrityGuardian` protects GeDefense's own installation/private security state. It does not claim access to other apps' private sandboxes.

`AppRiskScanner` uses package visibility to inspect installed package metadata and bounded APK/split files without execution. Threat-Intel literals and capability heuristics enrich risk evidence but do not create automatic app-remediation authority.

## 8. Evidence plane

The Evidence Ledger is local and HMAC-SHA-256 chained using a dedicated non-exported Android-Keystore key. Evidence failure is a protection-health failure, not a logging inconvenience.

Threat cache, Geo-country state, ASN-evidence state, integrity baseline and Evidence use distinct key aliases.

## 9. UI plane

Native Android Views only. Decorative content may render edge-to-edge; interactive content lives in a `WindowInsets` / `DisplayCutout` safe-area shell. No fixed device-specific top offsets are used.

## 10. Deliberate boundaries

The beta does not perform TLS MITM, dynamic code loading, remote packet inspection, cloud telemetry, automatic app deletion or kernel exploit mitigation.

The post-beta.5 source tree contains an optional embedded WireGuard egress behind GaiaNet. GeDefense remains the only Android `VpnService`; WireGuard is subordinate to the local policy plane and cannot modify threat policy or silently replace a failed strict tunnel with Direct egress.

## 11. Offline Data-Flow Atlas

`TrafficWorldMapView` consumes only already-normalized `FullFlowAnalyticsSnapshot` data. It never receives raw packet payloads and never opens a network connection. The bundled map bitmap and generated country-centroid table are static presentation resources.

`LocalOriginLocator` is deliberately one-way and local-only: without permission it resolves an approximate country anchor from mobile-network/locale metadata; with `ACCESS_COARSE_LOCATION` it reads only last-known NETWORK/PASSIVE locations and quantizes latitude/longitude to 0.25°. It registers no location listener. `ACCESS_FINE_LOCATION` and background location are forbidden by the source security gate.

Route visualization is bounded to 12 app/country arcs. Destination points are country centroids derived from local country attribution, not exact infrastructure coordinates. The atlas has zero enforcement authority.


## Guided setup and scanner privilege plane

`SetupWizardActivity` and `DeviceSetupManager` isolate Android/OEM special-access flows from protection logic. They can surface battery-optimization exemption, OEM autostart/application settings, all-files scanner access, usage access and notifications, but never silently grant them. `BootReceiver` only restores scheduled Threat Intelligence and Integrity jobs after boot/package replacement.

The deep scanner is deliberately separate from GaiaNet enforcement:

```text
DeviceSecurityScanner
    +-- IntegrityGuardian
    +-- AppRiskScanner
    +-- StorageMalwareScanner (optional all-files access, read-only)
    `-- bounded Evidence summary
```

`StorageMalwareScanner` traverses only canonical shared-storage roots, rejects symlinks/escapes, enforces hard file/archive/content/hash budgets and never executes, loads, deletes, renames or quarantines user files. File/app findings remain advisory evidence. Threat Intelligence correlation preserves compiled feed authority and cannot convert scanner evidence into a destructive response.

`ScannerStateCache` persists only bounded authenticated acceleration state under an Android-Keystore-backed HMAC identity. App cache eligibility is gated by package/version/update-time plus APK/split metadata and a completed deep-analysis marker; storage cache eligibility additionally requires a completed content inspection and a private content-sampling fingerprint. Cache corruption, legacy unauthenticated state and incomplete analysis fail back to scanning. `AppRiskScanner` uses bounded worker parallelism, delayed full APK hashing and current-policy re-correlation; UI progress is rate-limited independently from security work.


## Behavioral EDR

Full Flow telemetry is summarized locally per application into authenticated behavioral baselines. The detector learns bounded upload/download rates, observed DNS destinations, country codes and activity-hour histograms. Live sessions are compared only after a minimum learning period. Detected deviations are emitted into XDR using the same per-app incident key as package, permission, signer, malware and network-threat signals. Payload contents are never inspected for behavioral learning. Automatic quarantine is disabled by default and can only be explicitly enabled for CRITICAL behavioral anomalies.


## 0.17 Primary UX domains and VPN resilience

The persistent navigation is intentionally limited to five stable domains: **Start**, **Activity**, **Protection**, **Analysis**, and **System**. Specialist controls remain separate activities and are launched from the domain that owns their operational meaning. This prevents security capabilities from accumulating in a single monolithic screen while preserving direct access.

Always-on behavior is layered. Android's `VpnService` remains the authoritative data-plane boundary. In consumer mode GeDefense exposes observed `isAlwaysOn` / `isLockdownEnabled` state and sends the operator to `Settings.ACTION_VPN_SETTINGS`; only Android can provide a kill switch that survives GeDefense process failure. In TITAN Device Owner mode `DevicePolicyManager.setAlwaysOnVpnPackage(..., lockdownEnabled=true)` can enforce the same platform guarantee programmatically. While protection is active the service returns `START_STICKY` and records platform policy state, but this process-restart behavior is never represented as equivalent to Android lockdown.

### Resilience and power plane

`GeDefenseVpnService` separates protection readiness from non-critical runtime enrichment. A process/Always-on restart blocks tunnel activation on a bounded Stage-1 bootstrap (integrity, authenticated Evidence health and cached Threat Intelligence) while Stage-2 geo/XDR/hardening enrichment continues asynchronously. Full Flow transport failures use generation-guarded bounded self-healing so stale delayed callbacks cannot recycle a newer healthy tunnel. The optional recovery self-test is reachable only behind Android Lockdown and closes the real helper session to exercise the production telemetry-EOF recovery path.

GaiaNet's power governor changes only housekeeping and non-critical statistics cadence. It never reduces threat matching or critical event delivery. TCP housekeeping is event-driven and urgent only while half-open or unacknowledged data exists; idle established flows use long scans and an empty table sleeps until signalled. UDP flow expiry is enforced by socket deadlines refreshed on activity, eliminating a periodic manager sweep. Android UI visibility controls detailed statistics cadence, and hidden animated views stop callbacks rather than polling in the background.



## 0.20 TITAN Light and adaptive trust

TITAN is now a three-tier state machine: STANDARD, LIGHT and FULL. LIGHT is classic Device Administrator and never impersonates Device Owner. App-risk static capability evidence is retained as correlation context; XDR visibility requires threshold plus independent evidence unless direct threat intelligence is present. App approvals are authenticated and signer/capability-bound. The last completed app-malware scan is also authenticated and persistent across app upgrades.

## 0.20.1 bounded analysis restoration

Startup malware-analysis restoration is a read-only authenticated cache reconstruction path and is deliberately isolated from the synchronized deep scanner. Explicit user scans cancel restoration immediately. Integrity Guard itself is bounded by a monotonic 15-second deadline and private-tree entry ceiling; timeout remains fail-closed and produces explicit evidence.


## Diagnostics boundary

`DiagnosticBundleBuilder` is an explicit export boundary above runtime state. It serializes aggregate health and performance metadata only and cannot read packet payloads or emit package/domain/IP identity lists. `DiagnosticsActivity` writes only to a user-selected SAF document and is `exported=false`.

## 0.27.8-beta.5 audit — runtime publication and bounded Android service boundary

The Beta-5 audit separates **runtime publication** from **security readiness**. This is a corrective architecture change after encrypted/authenticated persistence introduced too many synchronous AndroidKeyStore, crypto, Binder and storage dependencies into `AppRuntime` construction.

The process now follows this ownership model:

```text
process start
  -> bounded runtime constructor worker
  -> quickly constructible AppRuntime shell
  -> critical readiness bootstrap
       +-- Evidence
       +-- Integrity
       `-- cached Threat Intelligence
  -> secondary encrypted/authenticated stores initialize independently
  -> protection can activate only when required security domains are healthy
```

AndroidKeyStore and opaque hardware-key operations are treated as potentially blocking OEM service calls, not ordinary in-process function calls. `AndroidKeystoreGate` and core `BoundedSecretKeyCrypto` isolate them behind hard deadlines and circuit-breaker semantics. A timed-out provider operation cannot be allowed to serialize every authenticated store behind one global lock. Timeout/unavailability remains fail-closed and cannot be interpreted as an absent or healthy store.

Persistent stores acquire authentication/encryption material lazily where possible. Constructors must not perform Keystore work, migration I/O, PackageManager queries or SharedPreferences reads as an incidental side effect. Critical and secondary bootstraps own their I/O explicitly.

Android lifecycle/UI code is a separate trust/performance boundary. `RuntimeActivityEntry` prevents restored Activities from assuming `AppRuntime` already exists. `RuntimeState` is in-memory first with background/coalesced persistence. TITAN and setup UI consume cached state; actual `DevicePolicyManager`, PackageManager and other Binder operations execute through bounded background/IPC gates. Receivers must use asynchronous completion for persistent/Binder work rather than block Android's receiver main thread.

Executor ownership is explicit. Runtime/control-plane queues are bounded; unbounded convenience executor factories are forbidden in security/startup paths. Full-flow telemetry uses a clearly owned reader lifecycle rather than an unbounded work queue.

The permanent regression layer includes `runtime-bootstrap-audit.py`, `main-thread-io-audit.py`, `startup-anr-audit.py`, the JVM class-initialization probe and strengthened vault/security/release-readiness gates. A successful build alone does not establish release readiness; the final Beta-5 artifact must still pass all source/security/native/lint/signing/artifact gates and the affected Xiaomi/HyperOS physical-device startup/update path.

## Beta-6 setup orchestration and WireGuard staging

The setup wizard is presentation over cached/event-driven setup state. Android/OEM access checks refresh asynchronously when the wizard resumes or regains focus; UI rendering does not synchronously query Binder services. The first Threat-Intelligence synchronization is an explicit runtime-owned state machine and a mandatory setup gate before first protection activation.

WireGuard sources are vendored and pinned and the GaiaNet egress integration is now implemented in the working tree. GaiaNet remains the local inspection/policy plane; allowed Layer-3 packets enter an in-process `wireguard-go` TUN and decrypted peer traffic returns through bounded stateful ingress checks. WireGuard uses per-socket Android protection rather than a whole-UID VPN bypass, propagates the imported MTU through the current helper protocol, requires explicit DNS configuration and rebuilds on preferred-underlay handover. Strict WireGuard mode requires Android lockdown and never silently uses Direct Internet. VC55 / 0.27.8-beta.6 is the current signed beta baseline; public promotion remains blocked on the remaining real-device gates and the new pre-public-release privacy/install/self-healing work.


## Telemetry Shield / local Privacy Intelligence

Telemetry Shield is a local-only GaiaNet policy plane and is enforced only while Full Flow owns the complete app traffic path; Selective mode does not claim system-wide telemetry filtering. `privacy_intelligence_v1.tsv` is packaged inside the signed APK and every rule carries source, license, observation date, confidence and breakage-risk metadata. `PrivacyIntelligenceRegistry` derives action authority locally from the selected `OFF`, `CONSERVATIVE`, `BALANCED` or `STRICT` profile; imported/community evidence cannot directly grant blocking authority. Essential connectivity, push and update rules override overlapping telemetry rules.

At Full Flow startup Android serializes the selected immutable policy into a bounded SHA-256-authenticated descriptor. Helper protocol v5 transfers it independently from Threat Intelligence and also carries a dedicated package-egress gate channel. Both Direct and WireGuard egress inspect ordinary UDP/53 queries before upstream forwarding. A blocked query receives a local bounded NXDOMAIN response; observed/blocked matches emit bounded metadata telemetry which Android revalidates against the same registry before Evidence/XDR ingestion. No TLS interception, runtime cloud lookup or third-party telemetry API is used.

Encrypted-DNS visibility is deliberately non-MITM. The signed Privacy Intelligence snapshot contains an `ENCRYPTED_DNS` category for documented resolver bootstrap domains. Conservative/Balanced observe captured TCP/UDP flows to standard encrypted-DNS port 853; Strict blocks captured DoT (TCP/853) and DoQ-style UDP/853 before Direct or WireGuard egress. Strict also blocks known resolver bootstrap domains when they are visible through ordinary DNS. Generic HTTPS/443 is never blocked merely because it could carry DoH. Custom DoH using hard-coded IP addresses, shared HTTPS/443, ECH or unlisted resolver infrastructure remains an explicit visibility limit until a future non-MITM classifier can prove the endpoint safely.


## InstallGuard / package egress quarantine

InstallGuard is local-first and reacts to Android package-added/package-replaced events only after setup has completed. A bounded priority scan is started off the main thread. For non-system applications, authenticated quarantine is staged **before** the scanner is invoked. In Full Flow, helper protocol v5 carries a dedicated fixed-size Unix socket channel between GaiaNet and Android. While the quarantine set is non-empty, GaiaNet asks Android to attribute each new TCP/UDP five-tuple with `ConnectivityManager.getConnectionOwnerUid()` before opening a Direct upstream socket or handing the packet to WireGuard. Android maps the UID to package names and denies flows owned by a quarantined package. Unknown ownership, IPC timeout, malformed framing or gate protocol failure fails closed while the gate is active; a broken gate causes the helper to exit so the existing TUN anchor/recovery path preserves containment. Policy changes clear the native attribution cache and close existing Direct flows so a newly quarantined package cannot keep an already-open Direct flow. WireGuard rechecks the gate before egress, and fragmented WireGuard traffic is denied while package quarantine is active rather than bypassing UID attribution.

InstallGuard uses a two-stage local verdict pipeline. Stage 1 is a hard-bounded fast verdict with a 1.75-second wall-clock budget and a dedicated zero-queue worker pool. It evaluates parsed package metadata, active capabilities, installer identity, signer identity and only exact authenticated cached evidence. A brand-new package is never considered signer-continuous merely because Android can read its signer, so new installs remain contained until deep inspection completes. Low-risk updates may be released after the fast verdict only when their signer matches previously authenticated local evidence and no review/block signal is present. Stage 2 performs bounded deep static inspection in a separate two-worker zero-queue pool with a 25-second wall-clock budget. If deep inspection times out, saturates or fails after a fast release, InstallGuard reinstates quarantine before publishing an INCOMPLETE verdict. This prevents a temporary fast release from becoming an unbounded unverified state.

On a fully managed Device Owner device, TITAN can additionally suspend the package so it cannot be launched while the scan verdict is pending. Standard/TITAN Light devices do not receive a false hard-preinstall claim: Android does not guarantee that a third-party `PACKAGE_ADDED` receiver runs before the absolute first packet an installed application could emit. GeDefense therefore guarantees Full-Flow egress quarantine from the point the package policy has been staged; an absolute pre-first-launch/first-packet hold requires Device Owner suspension or a future controlled GeDefense installation pipeline. System packages are scanned and reported but are not automatically suspended/quarantined during OEM/OTA replacement.


## Resilience Supervisor / local self-healing

The Resilience Supervisor is a local-only reconciliation plane. Immediate GaiaNet/WireGuard failure recovery remains event-driven inside `GeDefenseVpnService`; the supervisor handles slower integrity drift across signed local policy, authenticated stores, package quarantine, TITAN enforcement and derived runtime state. It performs no repair download and calls no VGT, Sophos or third-party verdict API. A persisted JobScheduler task runs every two hours without requiring network access, while the existing Integrity job also invokes the same single-flight supervisor after its scan.

Automatic repairs are deliberately narrow: re-read the signed Privacy Intelligence asset, re-verify Evidence, reinitialize an authenticated store from its existing durable bytes, reload cached Threat Intelligence, revalidate the packaged GaiaNet helper, reconcile package baselines, reassert Full-Flow InstallGuard quarantine and re-suspend already-quarantined apps when Device Owner policy requires it. The supervisor may re-run self-integrity validation but never advances a same-version integrity baseline after a mismatch. Malware-analysis corruption is marked `SCAN_REQUIRED`; it is not silently treated as a clean result.

Every repair is single-flight, bounded by a fixed worker pool, per-component cooldown/window budget and a per-run repair ceiling. Secondary-store bootstrap latches prevent normal startup initialization from being misclassified as corruption. Persistent trust failures escalate to `OPERATOR_REQUIRED` or `FAIL_CLOSED`; the supervisor never calls destructive reset/recovery APIs, clears Evidence/XDR history, disables lockdown, or downloads replacement trust material. Every completed repair and critical unresolved finding is written to Evidence and summarized into XDR. Diagnostics expose aggregate self-healing state only.
