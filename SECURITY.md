# Security

## Project invariants

1. Protection requires no VGT cloud account.
2. Threat data is evidence; authority is compiled into GeDefense.
3. `ROUTE_BLOCK`, `CORRELATE_ONLY` and `ANNOTATE_ONLY` are never conflated.
4. No threat/Geo dataset can supply executable code or policy directives.
5. GeDefense performs no TLS interception. TITAN may install an operator-selected managed X.509 CA only after bounded validation and explicit fingerprint confirmation; installation is never an XDR/automatic action.
6. No WebView, shell execution or dynamic class loading. Broad external-storage access is scanner-only, user-granted, read-only in GeDefense code, and never part of VPN protection/enforcement.
7. Threat cache, Geo-country state and Integrity retain distinct bounded Android-Keystore HMAC identities; vault-backed Evidence/XDR/scanner/state domains use distinct HMAC subkeys derived from independently wrapped persistent domain keysets.
8. Selective mode binds TUN evaluation to the immutable route-producing ThreatIndex.
9. Full Flow uses bounded memory/state for packets, fragments, flows and telemetry.
10. Critical Full Flow telemetry loss is fail-closed.
11. TCP sequence entropy failure is fail-closed; no time-based fallback.
12. Local generation updates are staged, verified, atomically published and recoverable to last-known-good state.
13. Direct/Selective transport may exclude GeDefense's own package to prevent recursive upstream capture, but WireGuard modes forbid a whole-UID bypass: only the exact WireGuard upstream UDP sockets are bound to the selected physical network and exempted with `VpnService.protect()` after the authenticated descriptor handoff succeeds.
14. App-risk findings never independently authorize destructive remediation.
15. Device Owner privilege is an optional response plane; network quarantine precedes privileged suspension and automatic package uninstall is forbidden.
16. Effective TITAN state is read from Android DevicePolicyManager; authenticated local preferences are not treated as proof of OS enforcement.
17. Application backup/export is disabled both through `allowBackup=false` / legacy full-backup controls and Android 12+ data-extraction rules.
18. Product-level VPN disclosure is explicit, independently HMAC-authenticated in `noBackupFilesDir`, and enforced again inside `GeDefenseVpnService`; absent/tampered consent fails closed. Its active HMAC is derived from the installation-stable vault key hierarchy, while the historical direct AndroidKeyStore HMAC is migration-only. Because the receipt contains no inner AEAD, an unusable historical HMAC requires fresh explicit acceptance rather than unauthenticated recovery.
19. Fresh-install XDR package enumeration is deferred until explicit setup completion; background package events are ignored before that point.
20. Packaged 64-bit GaiaNet helpers require >=16 KiB PT_LOAD alignment and remain byte-reproducible from in-tree source.

## Secure Telemetry Vault boundary

Durable security telemetry is not stored as application-readable plaintext. Active snapshot domains use independent AES-256-GCM and HMAC-SHA-256 subkeys derived from independent random per-domain roots. Those roots are persisted only as authenticated wrapped keysets under an installation-stable, non-exportable Android-Keystore HMAC root PRF; APK hash, signer digest, source-manifest hash and application version are not encryption-root inputs. AES-GCM associated data binds each ciphertext to its vault domain, store binding, schema version and key generation; moving a valid ciphertext to another store/domain therefore fails authentication. Fresh 96-bit nonces are generated for every write. Legacy HMAC-authenticated plaintext snapshots are migrated atomically and fail closed if the encrypted replacement cannot be made durable before plaintext is returned.

The Evidence ledger uses encrypted v3 per-record payloads while retaining its independent HMAC chain. Recovery manifests receive a persistent Android-Keystore ECDSA P-256 detached signature; Android 17+ devices with KeyMint 5 hardware add ML-DSA-87 as a second signature when the platform actually exposes that primitive. ML-DSA is never used as an encryption algorithm.

The active vault path touches Android Keystore only for the bounded root-PRF operation needed to recover process-local wrapping custody; per-store reads/writes use the derived domain subkeys rather than repeated OEM hardware-HMAC calls. Historical direct AndroidKeyStore HMAC/AES generations remain read-only migration material. Hardware-provider operations are off the main thread, admission-bounded and use a 5 s provider deadline with fail-closed circuit behavior. This is an at-rest/offline-exfiltration boundary, not a claim that cryptography can hide data from a process that is already executing legitimately on a fully compromised live device. A root/process attacker able to control GeDefense while it is running may be able to request legitimate Keystore operations or observe plaintext after decryption.

Vault data remains excluded from Android backup/device-transfer extraction. Key versions are explicit and readers re-encrypt old generations before releasing plaintext. GeDefense does not claim hardware monotonic anti-rollback for replay of an entire previously valid filesystem state because Android does not expose a universal trusted monotonic counter for this application design.

See `SECURE-TELEMETRY-VAULT.md` for the exact format and key-separation model.

## Native-code boundary

GaiaNet V2 is built reproducibly from in-tree Go source as a stripped pure-Go helper for each supported ABI; no opaque third-party transport binary is accepted. The helper is executed from Android `nativeLibraryDir` as a separate process. `NativeGaiaNet` creates a private filesystem Unix-domain control socket, authenticates startup with a 32-byte random token and transfers exactly the TUN, telemetry and immutable-policy file descriptors via `SCM_RIGHTS`. The helper validates descriptor count/type and protocol framing before entering the forwarding loop. The threat-policy wire format is versioned and fingerprint-bound: GaiaNet recomputes `ThreatIndex.fullPolicySha256`, rejects duplicate/non-canonical records and trailing bytes, and re-derives action authority from the compiled feed-bit ABI v2 before any packet is evaluated. ABI v2 grants block authority only to Feodo, Spamhaus DROP v4/v6 and the public-prefix-filtered FireHOL Level 1 feed; CINS/blocklist.de/Emerging Threats/IPsum remain correlation-only and Tor exits annotation-only.

GaiaNet V2 is built reproducibly per ABI from the same in-tree Go source. `arm64-v8a` remains a pure-Go Android build with `CGO_ENABLED=0`. Go 1.26.8 requires Android/amd64 to use external linking, so `x86_64` is linked with the pinned Android NDK `27.2.12479018` Clang; this is a build-time linker requirement, not a JNI transport or crypto backend. Physical-network handover is controlled by the Android VPN service. In WireGuard modes, GaiaNet transfers only the upstream UDP socket descriptors through the authenticated control channel; Android binds/protects those exact sockets before acknowledging bind activation. The optional `gdnetworkbinder` cgo source remains non-default and is not part of the production WireGuard path.

## Reporting

**Security contact:** [security@visiongaia.de](mailto:security@visiongaia.de)

Use GitHub private vulnerability reporting when available. For sensitive reports that cannot be submitted there, contact the security address above. Do not send private keys, unredacted packet captures or personal device data unless explicitly requested through a secure follow-up channel.

Security reports should include affected version, Android/OEM version, protection mode, reproduction steps, whether root/custom ROM is involved, and relevant GeDefense reason codes. Do not attach real packet payloads unless strictly necessary and sanitized.


## Scanner privilege boundary

`MANAGE_EXTERNAL_STORAGE` is optional special access used only by the local on-demand malware scanner on Android 11+. It is never required to activate VPN/Threat Intelligence protection, never changes Threat Intelligence authority, and does not bypass Android application-private sandboxes. The storage scanner is read-only: it does not delete, quarantine, rename, execute or load scanned artifacts. Every traversal, archive and content-inspection path is bounded and symlinks are rejected.

Incremental scanner state is encrypted with separate AES-256-GCM vault domains and independently authenticated before reuse. A missing/invalid HMAC, stale record, incomplete deep inspection, changed package/file fingerprint or malformed bounded record causes a normal rescan rather than a trusted cache hit. Cache reuse never freezes Threat Intelligence decisions: extracted indicators are correlated against the current ThreatIndex on every scan. Scanner caches are acceleration hints, not allow/block authority.

Battery and OEM autostart settings are explicit operator choices surfaced by the setup assistant. GeDefense does not request Android's direct battery-optimization exemption permission; it opens the system settings surface and reads back observable state. GeDefense restores scheduled feed/integrity jobs after boot or package replacement but does not silently start the VPN from `BOOT_COMPLETED`.

## Local Network Discovery Boundary

Network Discovery is intentionally limited to the currently attached private IPv4 Wi-Fi/Ethernet LAN. It does not accept arbitrary target hosts or Internet CIDRs. Active sweeps are capped at 254 targets, use bounded worker concurrency and short connect deadlines, and bind sockets to the selected underlying LAN network. Broad LAN prefixes are reduced to the device-local /24 window. SSDP and mDNS responses are accepted only from planner-approved local addresses. mDNS/DNS-SD decoding uses an in-tree bounded parser with packet/record/name/compression limits; advertised services are evidence, not proof of an open TCP socket. Device identity remains best-effort and explicitly records whether it came from MAC, mDNS hostname or IP. Discovery history is stored only on-device in a domain-separated AES-256-GCM vault snapshot with an independent HMAC-SHA-256 envelope. Partial or cancelled scans are never committed as a trusted baseline. Mature LAN behavioral baselines use bounded candidate promotion for newly observed services/ports, minimum observation counts and saturating/core-tested thresholds. A single anomalous scan cannot immediately redefine normal service exposure, and behavioral anomalies are not used to update normal-risk EWMA state.


## UI Performance Boundary

Animation throttling is presentation-only. The adaptive UI governor may reduce decorative frame cadence during touch/scroll interaction, battery saver or low-memory operation, but it does not throttle packet processing, policy evaluation, malware inspection, XDR ingestion, hardening checks or Evidence writes. Full Flow presentation notifications are coalesced independently from security processing.
## TITAN Device Owner boundary

TITAN is disabled unless Android reports GeDefense as both active admin and Device Owner. Provisioning components are system-facing and protected with `BIND_DEVICE_ADMIN`; ordinary TITAN UI and package-operation callbacks are not exported. The consumer XDR/EDR plane continues to operate without Device Owner. Privileged operations use explicit allowlists and reject GeDefense itself and system/updated-system packages for suspension/removal. XDR can optionally escalate an already-committed network quarantine to package suspension, but it cannot automatically invoke managed uninstall or destructive wipe.

Always-on VPN is declared as supported so Android/Device Owner can persist it. TITAN enables lockdown only after Full Flow/native availability, threat policy, Evidence and self-integrity are healthy. If Android starts the service in lockdown while local mode is Selective, the service upgrades to Full Flow semantics rather than exposing partial routing. The ordinary Stop action refuses to pretend that an administrator-enforced Always-on policy has been disabled.

Managed trust-anchor installation accepts at most 128 KiB, exactly one X.509 certificate, current validity, CA `basicConstraints` and `keyCertSign` when KeyUsage is present. The UI shows subject, issuer, expiration and SHA-256 fingerprint and requires an explicit second confirmation. GeDefense does not persist selected CA bytes. Android's user-CA trust behavior remains application-dependent on Android 7+.

The failed-unlock wipe threshold is disabled by default and requires explicit destructive confirmation. Device Owner restrictions close Android-managed interfaces such as debugging or USB file transfer; they are not claimed to defeat bootloader/baseband/firmware exploits or dedicated forensic attacks outside Android's policy plane.


## Resilience / battery security invariant

Power optimization is not an enforcement mode. GeDefense may coalesce byte counters, slow decorative rendering and reduce idle housekeeping wakeups, but it may not defer policy matching, block decisions, critical telemetry, integrity failure handling or Evidence writes. Established TCP/UDP/QUIC lifetimes are not shortened merely because the screen is off; forced reconnect churn is both a reliability and power regression. Intentional transport recovery testing requires Android Lockdown so the test remains fail-closed. Full Flow recovery is bounded and stale recovery callbacks are invalidated by generation state.



## 0.20 trust invariants

TITAN Light is least-privilege by construction: destructive wipe policy is opt-in, enterprise-only DPC operations still require Device Owner, and admin callbacks feed XDR evidence. App approval cannot authorize a blocking threat-intelligence match and does not suppress signer drift, behavior, network or integrity events. No package-name whitelist exists. Support VGT is non-exported and uses no payment or wallet SDK.

## 0.22 live-device provenance and exposure invariants

FireHOL Level 1 is permitted to enforce blocking only after `IpPrefix.isPublic()` filtering. Private RFC1918 space, CGNAT, link-local, multicast, documentation and reserved ranges never become blocking threat routes even when an upstream aggregate list contains them.

Battery state is multi-source. Android's Doze allowlist and `ActivityManager.isBackgroundRestricted()` represent different policy planes; GeDefense reports them separately and considers the background path ready when either a Doze exemption is active or Android/OEM reports the app as not background-restricted. This status does not weaken VPN fail-closed enforcement.

Network Port Sentinel is a bounded metadata-only decoy sensor, not a claim of kernel-firewall visibility. It follows only the preferred non-VPN physical underlay, immediately closes TCP probes, retains no payload, caps listeners/events/windows and can observe cellular probes only when carrier routing actually delivers them to the handset.

Signer drift is never trusted from a package name. GeDefense uses Android's verified signing-certificate history for rotation lineage and treats current system/updated-system package provenance as review context when a legacy baseline cannot prove the transition. Device-integrity and independent XDR signals remain responsible for escalation. GeDefense's own legacy Device Administrator is explicitly classified as first-party TITAN Light state rather than third-party posture risk.


## Aggregate-only diagnostics boundary

The 0.23 diagnostic export is user-initiated through Android SAF. `DiagnosticsActivity` is not exported. The bundle contains bounded aggregate counters, states, timings and sanitized reason codes only. It excludes application/package identities, IP addresses, domains, file paths, certificate/APK hashes, traffic payloads, evidence payloads and XDR incident details.


### Go dependency reachability

GaiaNet release verification is pinned to Go 1.26.8 and offline local module replacements. The compiled `gdandroidhelper` external package surface is frozen by `tools/go-supply-chain-reachability-audit.py`; importing a package covered by the reviewed 2026 advisories fails the release gate. `SBOM.cdx.json` provides the deterministic CycloneDX inventory and is regenerated/verified during Security Audit.

### Crash-safe authenticated state

Security-critical file publication never falls back from atomic replacement to a weaker normal move. Candidate bytes are flushed, authenticated/read-back verified, atomically replaced in the same directory, and the parent directory is fsynced. Failure to provide that contract is treated as a storage/security failure, not as permission to continue with ambiguous state. Recovery scans are entry-bounded and no-follow.
