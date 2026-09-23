## 0.27.8-beta.6 — embedded WireGuard / release hardening

- Added optional WireGuard Layer-3 egress behind GaiaNet while GeDefense remains the sole Android `VpnService`; Strict mode requires Android Always-on lockdown and never falls back to Direct.
- Replaced whole-UID VPN bypass in WireGuard modes with exact per-socket `VpnService.protect()` using authenticated `SCM_RIGHTS` descriptor transfer before the upstream bind becomes usable.
- Added bounded endpoint resolution on the selected physical underlay, explicit DNS handling, IPv4/IPv6 full-tunnel validation, MTU propagation `1280..1420`, stateful peer ingress and encrypted upstream round-trip coverage.
- Hardened helper crash recovery, TUN liveness anchoring, stale telemetry generation rejection, underlay handover, queue saturation and the Strict lockdown watchdog to remain fail-closed.
- Vendored and pinned `wireguard-go 0.0.20250522` plus required Go modules; upstream rekey/replay/rate-limiter tests run offline and GeDefense implements no parallel WireGuard cryptographic primitive.
- Added mandatory first-run Threat Intelligence synchronization with runtime-owned progress/retry state and live Setup permission refresh.
- Pinned Android NDK r27c `27.2.12479018`; x86_64 external LLD linking now enforces 16 KiB PT_LOAD alignment alongside arm64.
- GitHub verification pins JDK 17, Go 1.26.8, SDK 36 and NDK r27c and runs release compile/APK/AAB/lint/readiness gates without release signing in PR workflows.
- Final pre-promotion VC54 gates passed: zero-warning `lintRelease`, `SECURITY_AUDIT_PASS`, `RELEASE_READINESS_PASS`, signed APK/AAB artifact audit and both GaiaNet ABIs at 16 KiB PT_LOAD alignment.
- Added authenticated offline ASN Evidence from the PDDL/Public-Domain `IPtoASN` snapshot: SHA-256 verified IPv4/IPv6 sources, compact O(log n) binary indexes, explicit upstream/distributor provenance, family-specific source/index hashes, HMAC generation rollback/recovery and a strict `evidence_only` authority boundary with no ASN-to-XDR scoring.
- Hardened Privacy Intelligence provenance to reject cleartext HTTP and refreshed stale security-audit assertions for the current InstallGuard/XDR and startup-cache architecture.
- Reworked vault key lifecycle before public release: a single installation-stable non-exportable AndroidKeyStore HMAC root now derives a process-local wrapping KEK; each sensitive vault domain/key generation owns an independent random wrapped keyset in `noBackupFilesDir`.
- Encryption custody is explicitly independent of APK hash, source-manifest hash, signer digest, `versionCode` and `versionName`; those values remain integrity evidence only and cannot rotate persistent data keys during a normal update.
- Active vault generations advance to the first persistent-keyset generation while retaining historical AES, wrapped-DEK and hardware-PRF generations for fail-closed one-way migration. Snapshot migration remains atomic: old ciphertext/key generations are retained unless the new generation is durably written.
- Evidence and XDR explicitly authenticate the existing v4 hardware-PRF HMAC generation before rotating their outer authentication to persistent v5, preventing a normal update from misclassifying intact local state as tampered.
- Version: `0.27.8-beta.6` / version code `55`.

## 0.27.8-beta.5 — bounded runtime / crypto bootstrap hardening

- Separates runtime publication from cryptographic and persistent-store readiness so Android Keystore, provider, Binder or storage latency cannot indefinitely prevent `AppRuntime` from becoming available.
- Adds `AndroidKeystoreGate` and core `BoundedSecretKeyCrypto` with hard deadlines and process-local circuit breakers for AndroidKeyStore and opaque `SecretKey` operations; timeout never becomes healthy/empty state.
- Moves authenticated-store key acquisition to lazy providers and isolates Evidence, Integrity and cached Threat Intelligence as explicit critical readiness domains; secondary encrypted stores bootstrap independently and remain fail-closed until ready.
- Removes synchronous SharedPreferences/PackageManager/DevicePolicyManager work from runtime construction, Activity/Receiver render paths and other Android lifecycle callbacks; UI consumes cached snapshots while bounded workers own Binder/storage mutations.
- Adds bounded executor/scheduler ownership, non-blocking Activity restore through `RuntimeActivityEntry`, explicit runtime Evidence capability, and hardened receiver/service bootstrap paths.
- Adds permanent `RUNTIME_BOOTSTRAP_AUDIT`, `MAIN_THREAD_IO_AUDIT` and expanded startup/class-init regression gates so eager Keystore/persistence/Binder regressions block release.
- Keeps GaiaNet V2 and the current direct egress transport unchanged; embedded WireGuard remains a separately gated follow-up so transport-engine integration cannot destabilize the startup-hardening release.
- Version: `0.27.8-beta.5` / version code `54`.

## 0.27.8-beta.4 — migration-policy initializer hardening

- Fixes an Android/JVM class-initialization crash in `VaultMigrationPolicy` that could surface as `runtime_exceptionininitializererror` before `AppRuntime` construction.
- Removes initialization-order-dependent `Regex` fields from migration-spec validation and SHA-256 validation.
- Makes the package-baseline v2→v3 migration spec lazy, so constructing the policy object cannot recursively depend on later object fields.
- Keeps the beta.3 fail-closed baseline migration semantics unchanged: only key-unavailable/key-operation/key-continuity failures are reconstructible inside a verified update window; authentication/integrity failures remain non-recoverable.
- Version: `0.27.8-beta.4` / version code `53`.

## 0.27.8-beta.3 — package-baseline Keystore recovery hardening

- Separates authenticated snapshot integrity failures from Android Keystore/provider availability failures with typed failure classes; OEM HMAC provider exceptions no longer masquerade as `snapshot decode failed` or outer-integrity tampering.
- Rotates the package-baseline outer authentication generation from v2 to v3 using a fresh non-StrongBox-preferred HMAC key while retaining the encrypted vault payload model.
- Adds a one-way, update-gated v2→v3 migration: valid v2 state migrates intact; only key-unavailable/key-operation/key-continuity failures may be archived and reconstructed from the installed package inventory. Format/authentication failures remain fail-closed and are never auto-healed.
- Adds generation-scoped migration metadata, an atomic one-time completion marker, pre-update mtime gating, SHA-256 verified recovery archives and source deletion only after the replacement generation is durably written.
- Package-baseline diagnostics now expose bounded machine reason codes such as `package_baseline_key_operation_failed` instead of raw provider/decode text.
- Version: `0.27.8-beta.3` / version code `52`.

## 0.27.8-beta.2 — complete fail-closed Keystore bootstrap

- Extends unavailable-key handling from Evidence/XDR to every authenticated runtime domain, including Threat Intelligence, Integrity, Geo, Firewall, Disclosure, Scanner, TITAN, package baselines and app approvals.
- Makes the common authenticated snapshot boundary explicitly reject reads, writes and clearing when key custody is unavailable instead of throwing through `AppRuntime` construction.
- Keeps missing Threat Intelligence keys empty, Integrity keys untrusted and Geo-country state unavailable so protection remains fail-closed without trapping the UI on the startup screen.
- Adds hostile core coverage for absent persistence keys and a static release invariant against throwable direct HMAC acquisition in runtime constructors.
- Version: `0.27.8-beta.2` / version code `51`.

## 0.27.8-beta.1 — non-blocking process and consent bootstrap

- Moves Android Keystore, wrapped-domain-root, Evidence/XDR, authenticated-store, and cached-snapshot construction from `Application.onCreate()` to a single process-scoped initializer thread.
- Renders the startup surface before waiting for runtime readiness and keeps direct activity, JobScheduler, receiver, and Always-on VPN process entry points behind an explicit asynchronous readiness gate.
- Verifies the VPN disclosure receipt once during background bootstrap, serves authorization checks from an atomic cache, and persists explicit acceptance on a worker instead of the UI thread.
- Promotes the VPN foreground notification immediately, then performs runtime acquisition and all service-bound initialization on the serialized control executor.
- Removes the host-specific Linux AAPT2 override so Windows and controlled Linux builders resolve their own verified toolchain executable.
- Version: `0.27.8-beta.1` / version code `50`.

## 0.27.7-beta.1 — ANR-safe VPN control plane

- Moves VPN establish/rebuild/recovery, GaiaNet helper startup/handshake and Port Sentinel rebinds onto a dedicated serialized `gedefense-control` executor instead of Android's main Service thread.
- Keeps foreground-service promotion immediate while expensive policy serialization, `VpnService.Builder.establish()` and GaiaNet control-socket startup run off-main.
- Uses the same off-main control plane for route refresh, physical-network handover, recovery and controlled stop paths.
- Makes the activation click use a bounded readiness snapshot instead of constructing the complete XDR/UI snapshot before requesting Android VPN consent.
- Adds a release invariant that rejects reintroduction of main-looper transport mutation.
- Version: `0.27.7-beta.1` / version code `49`.

## 0.27.6-beta.1 — OEM-safe hardware-root vault

- Replaced active AndroidKeyStore AES-GCM data operations with per-domain non-exportable HMAC-SHA-256 hardware roots plus HKDF-derived in-process AES/HMAC subkeys.
- Retained historical AES and wrapped-DEK generations strictly for backward-compatible reads and one-way migration.
- Added explicit Evidence health/reason fields to aggregate-only diagnostics and surfaced Evidence readiness reasons in the Protection UI.
- Bumped active vault generations to v2 (low-frequency domains) and v4 (Evidence/XDR) so ciphertexts can never be interpreted under the wrong key backend.

## 0.27.5-beta.2 — Fail-closed vault startup availability

- Fixed an immediate process crash when OEM Android Keystore, wrapped-key continuity, or private-storage I/O failed during `Application.onCreate()`. Evidence now preflights before ledger construction and degrades to an explicit non-writable unhealthy store; XDR independently degrades its event store without terminating the process.
- Added bounded opaque startup diagnostics containing only domain, failure code and exception class chain. Provider messages, aliases, paths and key material are excluded.
- Added regression gates proving that the unavailable Evidence capability cannot report healthy state, append records or enter recovery, and that future refactors cannot move the preflight behind ledger construction.

## 0.27.5-beta.1 — Evidence hot-path envelope encryption

- Fixed persistent `evidence_write_failure` on OEM Android 16 devices by removing per-record AndroidKeyStore operations from the Evidence/XDR hot path.
- Evidence and XDR now use a random 256-bit domain root wrapped at rest by a non-exportable TEE-backed Android Keystore KEK; HKDF-SHA-256 derives independent AES-256-GCM and HMAC-SHA-256 subkeys in process memory.
- Existing Evidence HMAC v1/v2 and XDR HMAC v2/v3 stores migrate one-way to the wrapped hot-path key generation; historical AES envelope versions remain readable for continuity.
- Added hot-path crypto preflight before Evidence is considered healthy and precise `evidence_crypto_failure`, `evidence_io_failure`, `evidence_state_race`, and validation failure codes.
- Full Flow remains fail-closed on durable Evidence failure; XDR enrichment remains non-fatal after packet enforcement.

# Changelog

## 0.27.4-beta.1 — Full Flow evidence/XDR availability hardening

- Split Full Flow durable Evidence writes from XDR enrichment. An XDR correlation/store failure can no longer be misreported as `evidence_write_failure` or tear down an otherwise healthy, already-enforcing Full Flow tunnel.
- Added bounded aggregate-only failure telemetry that records only sanitized failure classes/counters for Evidence and XDR persistence; provider exception messages and internal paths are never exported.
- Re-profiled the two high-frequency encrypted domains, Evidence and XDR Events, to use non-exportable Android-Keystore TEE keys instead of preferring StrongBox for every record. Low-frequency authoritative stores continue to prefer StrongBox. This preserves hardware-backed key custody while avoiding StrongBox operation-slot/latency availability failures under sustained Full Flow telemetry.
- Rotated Evidence and XDR event AES domains to key generation v2. Existing v1 encrypted records remain readable with their historical Keystore key and are rotated lazily; missing historical keys fail closed instead of silently generating replacement keys.
- Rotated the high-frequency Evidence HMAC chain to `evidence.hmac.v2` and the XDR outer snapshot HMAC to `xdr-events.hmac.v3`, both using the normal Android-Keystore/TEE profile. Existing StrongBox-backed beta data is verified with the historical key once and atomically re-authenticated under the new key before normal writes continue.
- Preserves the 0.27.3 route-scaling fix: GaiaNet Full Flow remains the fresh-install default and Selective Shield refuses exact route sets above the conservative Android platform budget instead of attempting thousands of `VpnService.Builder.addRoute()` calls.


## 0.27.3-beta.1 — Android VPN route-scaling hardening

- Fresh installations now default to GaiaNet Full Flow instead of Selective Shield. Full Flow installs only the two default IPv4/IPv6 routes and scales independently of the size of the threat-prefix policy.
- Selective Shield is now explicitly bounded to 1,024 Android VPN routes. GeDefense refuses partial enforcement when the exact route set exceeds that platform-safety budget and reports `selective_platform_route_budget_exceeded`.
- Replaced the generic `route_install_failed` bucket with sanitized stage-specific Selective startup reasons for self-bypass, route validation, route-count invariants and `VpnService.Builder.establish()` failures.
- Added release-audit coverage so a future change cannot silently restore Selective as the fresh-install default or remove the platform route budget.

## 0.27.2-beta.1 — authenticated beta-vault recovery hardening

- Fixed a persisted `XDR-Speicher DEGRADIERT` state seen on beta upgrades after the 0.27 Secure Telemetry Vault rollout. Diagnostics from the affected Xiaomi/Android 16 device showed healthy Evidence integrity while legacy XDR event, Port Sentinel and persisted malware-analysis stores remained invalid.
- Added explicit vault failure classification so outer HMAC/integrity failures are never confused with an authenticated ciphertext whose AES key continuity was lost. Normal tampering remains fail-closed.
- Added archive-before-reset recovery for reconstructible stores. Key-continuity failures can self-heal after the raw encrypted/authenticated snapshot is copied, SHA-256 verified and retained in no-backup recovery storage.
- Added a one-release VC43 beta-compatibility gate for historical outer-snapshot failures: recovery is permitted only on a real app update, only when the invalid file predates that update, and only for reconstructible XDR/scanner/baseline state. Fresh installs and post-update tampering cannot enter this path.
- Firewall policy, explicit app approvals and TITAN policy remain authoritative stores and are never automatically reset by vault recovery.
- Recovery actions are journaled into the independent encrypted Evidence ledger with domain, failure class and archive SHA-256.
- Analysis UI now names the degraded XDR component (`EVENT`, `PACKAGE`, `FIREWALL`, `LAN`, `SENTINEL`, `TITAN`) instead of showing only a generic degraded label. Diagnostics now exports the individual aggregate trust-store health booleans.

## 0.27.1-beta.1 — VPN consent receipt availability hardening

- Fixed a protection-start regression where the product VPN disclosure could remain `CONSENT_REQUIRED` after the Secure Telemetry Vault rollout. The disclosure decision is authorization metadata, not sensitive telemetry, so it now uses a dedicated Android-Keystore HMAC-SHA-256 authenticated receipt instead of requiring AES-GCM/StrongBox on the start path.
- Added compatibility migration for the encrypted 0.27.0 disclosure receipt. A successfully authenticated legacy receipt is migrated one-way to the HMAC receipt; if the historical AEAD key is unavailable, a new explicit user acceptance safely overwrites the invalid legacy state.
- Added aggregate-only diagnostics for disclosure acceptance, receipt integrity and sanitized failure code.
- Secure Telemetry Vault remains enabled for twelve sensitive telemetry/evidence domains; no behavioral/XDR/scanner/Evidence confidentiality protection was reduced.

## 0.27.0-beta.1 — Secure Telemetry Vault / cryptographic compartmentalization

- Added the **Secure Telemetry Vault** for durable sensitive GeDefense state. Thirteen independent storage domains use versioned AES-256-GCM keys held by Android Keystore; StrongBox is preferred when the device can satisfy the key profile.
- Kept independent HMAC-SHA-256 authentication as a second layer around snapshot/Evidence structures instead of replacing integrity with encryption and pretending those are the same thing.
- Added a pure-JVM `AeadVaultEnvelope` codec with fresh 96-bit nonces, 128-bit GCM tags and AAD binding to domain, logical store/record binding, schema, key generation and exact lengths. Wrong-domain, wrong-binding, wrong-schema, future-generation and ciphertext-tamper regression tests are mandatory.
- Legacy HMAC-authenticated plaintext beta snapshots now migrate atomically to encrypted form before plaintext is released. Rotation is similarly fail-closed and temporary encrypted buffers are explicitly wiped after durable persistence.
- Upgraded Evidence to encrypted v3 per-record payloads while retaining the independent HMAC chain. Legacy healthy Evidence is migrated before normal use and the legacy file is moved into no-backup storage with a durable copy+digest fallback when atomic rename is unavailable.
- Added hybrid detached signatures for durable recovery/security artifacts: Android-Keystore ECDSA P-256/SHA-256 on supported devices plus ML-DSA-87 on Android 17+ / KeyMint 5 hardware when the platform natively exposes it. ML-DSA is not misused as an encryption primitive.
- Added aggregate-only diagnostics for vault key initialization/security levels without exposing aliases, plaintext, package identities or key material.
- Added `SECURE-TELEMETRY-VAULT.md` and `SECURE_TELEMETRY_VAULT_PASS`; release readiness now fails if vault architecture, store mapping, backup exclusion, hybrid-signature gates or the single-AEAD-implementation invariant regress.
- Added a launch-time GeDefense secure-boot experience with a cached, allocation-free animated security core, real AppRuntime bootstrap readiness, local-first/Vault/GaiaNet/XDR/Integrity phases and a bounded fail-closed handoff instead of a cosmetic fixed-delay splash.
- Reduced launcher exposure by moving the MAIN/LAUNCHER intent filter to the dedicated `StartupActivity` and making `MainActivity` internal-only. Android 12+ receives a matching dark native splash theme before the in-app secure-boot surface.

## 0.26.1-beta.1 — public-beta onboarding and release-readiness hardening

- Fixed edge-to-edge safe-area handling in the local VPN disclosure and Privacy Center so status bars, display cutouts and hole-punch cameras cannot cover security/privacy content. Added a release audit that rejects any Activity opting into VGT system bars without a matching inset consumer.
- Raised compileSdk to Android API 36 using the verified Android SDK Platform 36 revision 2 package while retaining targetSdk 36.
- Rebuilt first-run setup into a ten-stage guided security onboarding that explains GeDefense's protection model, local VPN architecture, XDR/Threat Intelligence, reliability controls, scanner scope, optional visibility signals, TITAN, privacy boundaries and final readiness state before activation.
- Classified setup capabilities as CORE, RECOMMENDED, OPTIONAL or ENTERPRISE so optional Android permissions are never presented as mandatory for baseline VPN protection.
- Added an explicit local-VPN education path covering Android's VPN indicator, no remote consumer VPN endpoint, no TLS interception and no traffic-history upload, with the existing authenticated disclosure remaining the fail-closed service gate.
- Added local-first privacy education and direct access to the Privacy Center from onboarding.
- Added coarse-location education using only ACCESS_COARSE_LOCATION; fine/background/continuous location is neither requested nor claimed.
- Versioned the setup-completion contract so existing beta installations receive the expanded public-release onboarding once. Fresh-install package inventory and package-change processing remain gated until setup is consciously completed.
- Added release-oriented onboarding, source-manifest and artifact verification gates plus Play declaration, Data Safety, review-video and public-beta release documentation.
- Retains targetSdk 36, 16 KiB-aligned reproducible GaiaNet helpers, release signing, zero-error release lint and the public-release privacy/permission hardening introduced during the 0.25 freeze.
- Cleared the Android release lint baseline to **0 errors / 0 warnings**; removed dead resources and global lint disables, fixed custom-view constructors, Application lifetime typing, obsolete SDK branches and deprecated DeviceAdmin callbacks, with only narrow manifest/resource suppressions for intentional policy/telemetry heuristics.
- Added a self-contained web-ready privacy page under `docs/privacy.html` for GitHub Pages or another static HTTPS host.


## 0.24.0-beta.1 — beta-freeze lifecycle/recovery hardening

- Reconciles stale transient VPN state after hard process death, including `RECOVERING`, so a fresh process never presents historical tunnel state as live protection.
- Converts an orphaned resilience self-test `RUNNING` record into bounded `FAIL` on process restart when Android could not deliver normal service teardown callbacks.
- Diagnostics now subscribes to live runtime state while visible and removes the listener on stop; runtime/resilience cards no longer require an activity resume or export to refresh.
- Diagnostic export completion is lifecycle-generation guarded and builds from application context, preventing a completed background export from mutating a destroyed Activity.
- The Protection Hub now exposes self-test execution state to its enablement logic and rejects overlapping recovery self-tests before dispatch.
- Added beta-freeze regression gates for transient-state recovery, Diagnostics lifecycle wiring and overlapping self-test prevention.
- Serialized `IntegrityJobService` start/stop ownership so a duplicate scheduler callback cannot invalidate the live generation and strand the active task without `jobFinished`.
- Replaced eager `listFiles()` traversal in both shared-storage malware scanning and private self-integrity scanning with lazy `DirectoryStream` walks and explicit entry budgets, preventing giant-directory allocation spikes from bypassing scan limits.

## 0.23.0-beta.1

- Added a non-exported Diagnostics & Support center with an explicit SAF export flow.
- Diagnostic bundles use the `aggregate-only-v1` privacy profile and exclude package names, IPs, domains, paths, signer/APK hashes, packet/evidence payloads and incident details.
- Added aggregate runtime, scanner timing, XDR, TITAN, setup, Network Port Sentinel, GaiaNet and protection-state diagnostics.
- Resilience self-tests now persist PASS/FAIL plus bounded duration so recovery quality is visible after the test.
- Added `DIAGNOSTICS_RESILIENCE_PASS` to prevent accidental identity/telemetry leakage and self-test regression.


## 0.22.1-beta.1 — FireHOL/GaiaNet policy-ABI startup hotfix

- Fixed a fail-closed Full Flow startup regression introduced when FireHOL Level 1 moved to `ROUTE_BLOCK`: Android/Core correctly granted FireHOL feed bit 7 block authority, while the process-isolated GaiaNet policy ABI still classified bit 7 as correlation-only and therefore rejected the immutable policy with an authority mismatch.
- Updated GaiaNet's shipped feed-authority ABI to match the nine-feed catalog exactly: Feodo + Spamhaus v4/v6 + FireHOL L1 block, CINS/blocklist.de/Emerging Threats/IPsum correlate, and Tor exits annotate. Block authority dominates mixed matches.
- Added exhaustive Go feed-bit authority tests plus a release audit that checks the Kotlin catalog and GaiaNet authority mapping together so future policy changes cannot silently diverge across the process boundary.
- Added sanitized Full Flow startup reason codes and explicit helper failure acknowledgements for policy rejection / engine initialization, replacing the previous single `full_flow_start_failed` bucket for these paths.

## 0.22.0-beta.1 — live-device hardening, network exposure & signer provenance

- Promoted the public-prefix portion of FireHOL Level 1 from correlation-only to route/full-flow blocking. GeDefense still rejects private, CGNAT, link-local, multicast, documentation and other non-public prefixes before they enter the threat index, so FireHOL fullbogon entries cannot sinkhole the local LAN or carrier-private space.
- Reworked battery-readiness detection to distinguish Android Doze allowlisting from `ActivityManager.isBackgroundRestricted()`. HyperOS/OEM "No restrictions" can therefore satisfy the background-readiness check even when the package is not on Android's Doze allowlist, while a real OS background restriction remains visible.
- Expanded LAN Port Sentinel into **Network Port Sentinel**. The bounded passive decoy listeners now follow the preferred physical Wi-Fi, Ethernet or cellular underlay, support IPv4/IPv6 addresses and classify carrier/private versus public source zones. Carriers using CGNAT or inbound filtering may naturally expose no reachable mobile listener.
- Added generic signer provenance. Package baselines persist the Android-verified signing-certificate lineage and system/updated-system provenance; verified key rotation no longer becomes a critical signer alert, and an unprovable transition on a system package becomes low-weight review context rather than independent 100/100 evidence. No Google/package-name whitelist is used.
- Added reconciliation that removes stale signer-only XDR events when current Android provenance proves a verified rotation lineage or system-package context.
- Excluded GeDefense's own Device Administrator from third-party-admin hardening findings. TITAN Light remains visible as first-party protection state instead of inflating device-posture risk.
- Added `LIVE_HARDENING_PROVENANCE_PASS` to lock these live-device invariants into release auditing.

## 0.21.0-beta.1 — behavioral intelligence & independent XDR signal families

- Extended Behavioral EDR with robust per-app baselines for egress ratio, flow fanout, destination/country cardinality, activity hours and variance-aware traffic thresholds.
- Added explicit behavioral confidence and observation counts; automatic behavioral quarantine requires CRITICAL severity plus at least 85% confidence.
- XDR now counts independent detector families rather than treating multiple emitters from the same subsystem as independent corroboration.
- Added direct Live Activity app-to-forensics drill-down while keeping presentation paths separate from enforcement.

## 0.20.1-beta.1 — analysis-restore / Integrity Guard hotfix

- Fixed a startup migration race where 0.20.0 restored the previous malware baseline by launching a full synchronized `AppRiskScanner.scan()` in the background. A user-triggered device scan could then finish Integrity Guard but block before the first app-scan progress event, making the UI appear stuck on “Prüfe Integrity Guard”.
- Replaced startup deep-scan migration with a read-only, authenticated cache restoration path. It revalidates current package fingerprints, signer identity, dynamic permission/AppOps/admin/accessibility state and current Threat Intelligence without opening APK ZIPs or taking the full-scan monitor.
- Restore is bounded to eight seconds, cancelable by any explicit user scan and falls back to IDLE/fresh scan rather than remaining indefinitely in `RESTORING`.
- Added a bounded 15-second Integrity Guard deadline with cancellation propagation and a private-filesystem entry ceiling. A genuine I/O/traversal stall now becomes explicit fail-closed `integrity_scan_timeout` evidence instead of an endless scanner phase.
- Device scan now publishes the APPS phase before entering the app scanner, preventing a downstream scanner wait from being misreported as an Integrity Guard hang.
- Added `ANALYSIS_RESTORE_INTEGRITY_HOTFIX_PASS` to lock these invariants into the release audit.

## 0.20.0-beta.1 — TITAN Light, adaptive XDR trust & persistent analysis

- Added **TITAN Light** for classic Android Device Administrator deployments. It is automatically recognized and visually distinguished from both Standard and full Device Owner TITAN.
- Setup Wizard can request Device Administrator without factory reset; full Device Owner provisioning remains the upgrade path for enterprise-only policy controls.
- TITAN Light uses supported legacy admin controls: force-lock, password policy, failed-login monitoring, maximum-time-to-lock and opt-in failed-password wipe threshold.
- Reworked app-risk scoring so declared capabilities are context, active/granted privileges carry more weight, and capability-only static evidence cannot create a user-facing incident without independent evidence.
- XDR now deduplicates static scanner evidence into one signal family and surfaces low static context only after behavior/network/signer/integrity corroboration.
- Added authenticated signer/capability-bound **App Approval**. Approval never suppresses TI, signer drift, network/behavior anomalies or integrity evidence and becomes stale when reviewed capabilities change.
- Fixed forensics raw-score/reason mismatch by deriving the displayed scanner score and reasons from the same scanner event snapshot.
- Persisted the last completed malware analysis in an authenticated no-backup snapshot across application updates.
- Added “powered by VisionGaiaTechnology” branding and a non-exported local **Support VGT** page for PayPal, Bitcoin and ETH/USDT addresses.


## 0.19.0-beta.1 — Always-on resilience & security-preserving power governor

- Added a bounded two-stage security bootstrap gate so Android Always-on/process recovery waits only for integrity, authenticated evidence health and cached Threat Intelligence required for fail-closed tunnel readiness; non-critical UI/XDR enrichment remains asynchronous.
- Added Full Flow self-healing with bounded 0.5/1.5/4 second recovery attempts, persisted recovery counters and generation/pending guards that prevent stale or duplicate recovery jobs from churning the tunnel.
- Added an operator-confirmed Recovery Self-Test. It is enabled only while Full Flow is guarded behind Android Lockdown/Kill Switch and deliberately recycles the real GaiaNet transport so the production EOF/recovery path is exercised.
- Added an adaptive GaiaNet power governor. Policy matching, block decisions, flow open/close and critical telemetry remain immediate; byte/statistics snapshots are coalesced according to UI visibility, active-flow load, screen state, Doze and Battery Saver.
- Replaced fixed TCP housekeeping polling with event-driven wakeups: retransmission/half-open work retains 1-second urgency, established idle flows use 15/30-second housekeeping, and an empty flow table can sleep for minutes until a new flow wakes it.
- Removed the periodic UDP manager sweeper. Per-socket read deadlines are refreshed by both outbound and inbound activity, preserving UDP/QUIC lifetimes without a background polling loop.
- Preserved established TCP and UDP/QUIC idle lifetimes during Doze to avoid battery-expensive reconnect storms; only incomplete TCP handshakes retain a tighter constrained timeout.
- Converted LAN Port Sentinel to a blocking selector with explicit wakeup/rebind semantics so an idle LAN no longer produces a one-second polling wakeup.
- Stopped decorative `Choreographer` tickers completely while their window is hidden/backgrounded instead of polling invisible views, while retaining adaptive foreground animation cadence.
- Added bounded UID-to-package attribution caching and O(1) active-flow counting to remove repeated PackageManager work and full analytics snapshots from high-rate Full Flow telemetry.
- Added `VPN_RESILIENCE_POWER_PASS` to lock the battery/resilience invariants into the release gate.


## 0.18.0-beta.1 — Scanner performance, detection quality & app-wide hardening

- Reworked installed-app scanning around authenticated whole-package incremental state. Unchanged package/version/update-time/APK-split fingerprints reuse bounded static evidence without reopening APK ZIPs, while Threat Intelligence is re-correlated on every scan.
- Added bounded parallel app analysis, deferred forensic APK hashing, throttled progress delivery and explicit scanner timing/byte/cache metrics so performance bottlenecks are measurable on-device.
- Added confidence and heuristic-score separation to app-risk results so generic capability heuristics cannot masquerade as high-confidence malware evidence.
- Hardened scanner caches with Android-Keystore-backed HMAC authentication, bounded records and fail-closed cache rejection. Legacy unauthenticated cache state is not trusted or promoted.
- Fixed a storage-scanner cache weakness where an incomplete budget-limited content inspection could be reused as if it were complete. Only fully completed deep analysis is now cache-eligible.
- Strengthened shared-storage cache identity with private content sampling in addition to metadata, while avoiding a mandatory full-file hash on every unchanged file.
- Added archive/ZIP work ceilings, cancellation propagation and bounded worker shutdown so hostile corpora cannot silently convert scanner acceleration into unbounded CPU or stale trusted state.
- Hardened temporary security-file creation with exclusive private files and tightened atomic-replacement fallback behavior.
- Explicitly disabled legacy full-backup and Android 12+ cloud/device-transfer extraction paths in the manifest, with a release gate enforcing the backup boundary.
- Hardened TITAN managed-uninstall result routing with cryptographically random one-shot PendingIntent identity and strict callback validation.
- Added `SCANNER_PERFORMANCE_QUALITY_PASS` and `APP_WIDE_HARDENING_PASS` release gates.

## 0.17.1-beta.1 — Live activity restoration hotfix

- Restored the complete live Full-Flow activity surface after the 0.17.0 information-architecture refactor.
- Activity now owns live per-app traffic, destination world map, country analytics, traffic usage and threat-feed state.
- `TrafficWorldMapView` is again a reachable release path, preventing R8/resource shrinking from stripping `world_map_ambient.png`.
- Added a release regression gate that fails if the live map path becomes unreachable again.

## 0.17.0-beta.1 — Resilience & information architecture

- Added Android Always-on VPN / lockdown visibility and guided setup. TITAN Device Owner can enforce Always-on VPN with lockdown directly; consumer mode opens the authoritative Android VPN settings instead of pretending an app-level toggle can provide a platform kill switch.
- Added persisted resilience intent and live observation of `VpnService.isAlwaysOn` / `isLockdownEnabled`; the VPN service remains `START_STICKY` while active and exposes a bounded resilience probe.
- Reorganized the five primary domains to Start, Activity, Protection, Analysis and System. Existing specialist activities remain intact behind the relevant hubs.
- Added a compact Current Analysis block to the dashboard with live malware-scan progress, recent findings and direct navigation to Scanner / Analysis.
- Reduced the bottom dock height and moved gesture-navigation inset handling to the dock margin so the glass bar floats above the system gesture area instead of becoming visually oversized.
- Added static resilience / UX regression gates and retained local-first, fail-closed behavior.

# 0.16.0-beta.1

- Split the XDR Security Center into **Findings** and **Forensics** views so operational response and diagnostic analysis no longer compete in one endless incident feed.
- Added incident drill-down with the exact XDR correlation recipe: counted event points, cross-category bonus, critical-event bonus, volume bonus, unclamped score and final bounded score.
- Added structured detector evidence to XDR events: scanner raw score, individual finding codes and weights, package/version/installer, signer SHA-256, APK SHA-256 and threat-intelligence matches.
- Kept the detector raw score separate from the XDR correlation score. This exposes the previous 80/100 pattern where a severe app-scan event contributed 70 XDR points plus the 10-point critical-event correlation bonus.
- Added evidence-timeline marking that shows which events currently contribute to the incident score and which are retained only as forensic context.
- Kept XDR event-store schema compatibility: new forensic fields are optional and older authenticated event stores remain readable.

# 0.15.2-beta.1

- Hotfix: GaiaNet V2 now uses Android's supported `LocalSocket.connect(endpoint)` API for the authenticated helper control channel. The `connect(endpoint, timeout)` overload is intentionally unimplemented by Android and caused `UnsupportedOperationException` on protection activation.
- Kept the existing bounded 4-second helper startup deadline/retry loop and post-connect socket I/O timeout; fail-closed semantics remain unchanged.
- Added a static regression gate that forbids the unsupported LocalSocket timeout-connect overload from returning to the GaiaNet V2 bridge.

# 0.15.1-beta.1

- Hotfix: VPN activation is now fail-closed at the UI/service boundary instead of allowing OEM/runtime start exceptions to terminate GeDefense.
- Hotfix: integrity activation failures expose the concrete integrity issue code rather than only `application_integrity_unhealthy`.
- Hotfix: versionCode advanced to 24 so an authenticated forward update can legitimately advance the local install-integrity baseline.
- UI: TITAN and LAN Port Sentinel cards now apply glass backgrounds before explicit content padding, preventing drawable padding from collapsing text against card edges.
- UI: additional internal spacing for TITAN command/cards and LAN Port Sentinel status, scope, and hit cards.

# GeDefense Mobile 0.15.0-beta.1

- Promoted Full Flow to the process-isolated GaiaNet V2 helper and packaged reproducible arm64-v8a/x86_64 helper artifacts from in-tree pure-Go source.
- Added authenticated Unix-domain helper startup with random token and `SCM_RIGHTS` transfer of exactly the TUN, telemetry and immutable threat-policy descriptors.
- Added TCP Window Scale handling, 1 MiB per-flow / 32 MiB global downstream unacknowledged budgets, bounded 64-worker dial concurrency, ownership-safe buffer pools, 1024 UDP-flow ceiling and power-constrained flow deadlines.
- Added Android physical-network tracking and controlled V2 helper restart on Wi-Fi/cellular handover; optional cgo `android_setsocknetwork()` binder remains future-only and is not claimed active.
- Rebuilt TITAN into a spacious managed-device console with status hero, three-tile command deck, separated capability cards and four-step provisioning guidance.
- Added Xiaomi/Redmi/POCO HyperOS assistant that distinguishes Xiaomi Enterprise Mode from Android Device Owner provisioning.
- Added an app-wide TITAN MDM visual mode with managed banner, gold/cyan panel/navigation treatment and bounded animated background accents whenever Android confirms GeDefense as Device Owner.
- Added visible GaiaNet V2 readiness state under More and extended i18n parity across all four shipped locales.

# GeDefense Mobile 0.14.0-beta.1

- Added optional **TITAN** Device Policy Controller / Device Owner mode while retaining the full Standard Mode for non-managed consumer devices.
- Added modern Android managed-device provisioning components (`GET_PROVISIONING_MODE` / `ADMIN_POLICY_COMPLIANCE`) plus an in-app ADB provisioning command and QR/factory-reset guidance.
- Added OS-level user-app suspension as an opt-in escalation after GeDefense network quarantine; system packages and GeDefense itself are protected from suspension/removal.
- Added Device Owner Always-on GeDefense VPN with Android lockdown. Lockdown requires healthy Full Flow prerequisites and cannot silently fall back to Selective semantics.
- Added Device Owner hardware/interface restrictions for debugging features, unknown-source installation, Safe Boot, USB file transfer and app verification.
- Added high password-complexity enforcement and an explicitly confirmed, disabled-by-default failed-unlock wipe threshold.
- Added operator-confirmed managed package removal through `PackageInstaller`; automatic XDR uninstall remains forbidden.
- Added explicit managed X.509 CA installation with dependency-free bounded CA validation, SHA-256 fingerprint confirmation and no persistent copy of selected certificate bytes.
- Added HMAC-authenticated TITAN local policy preferences while treating Android `DevicePolicyManager` readback as the authority for effective state.
- Added passive TCP/UDP LAN Port Sentinel telemetry, bounded port-scan/ADB/Telnet correlation, authenticated source denylist, and Selective-mode private `/32` sink routes.
- Added physical `NOT_VPN` network handover tracking, underlying-network updates and debounced Full Flow restart to retire stale upstream sockets on Wi-Fi/cellular transitions.
- Extended XDR sensor coverage, trust-state recovery, Security Center and More/TITAN UI for the new privileged policy plane.

# GeDefense Mobile 0.12.0-beta.1

- Added adaptive UI performance governance using `Choreographer`: animations remain enabled while decorative cadence adapts to recent interaction, high-refresh displays, power-save mode and low-RAM devices.
- Reworked shield, scanner-radar and traffic-map renderers to cache static shaders/geometry and avoid per-frame gradient/path allocation while preserving the existing animated visual language.
- Coalesced high-rate Full Flow telemetry UI notifications and limited primary-screen refreshes to the visible destination; detection, policy evaluation and XDR ingestion remain real-time.
- Added snapshot-diff rendering to heavy Security and Network Discovery surfaces to avoid rebuilding unchanged lists during live telemetry.
- Added schema-v3 authenticated LAN behavioral baselines with per-device observations, exposure-risk EWMA, network device/elevated-count history and bounded candidate promotion for newly observed ports/services.
- Added dependency-free `LanBehaviorEvaluator` decisions for mature service bursts, exposure-risk spikes, returning-device surface drift, device-count surges and elevated-risk surges.
- Added LAN behavioral signals to the shared XDR incident plane and surfaced LEARNING/NORMAL/ANOMALOUS state in Network Discovery and XDR sensor coverage.
- Prevented one-off LAN anomalies from immediately becoming normal by requiring repeated observation before new service/port promotion and excluding behavioral anomalies from normal-risk EWMA training.

# GeDefense Mobile 0.11.0-beta.1

- Added bounded mDNS/DNS-SD discovery using a new dependency-free core DNS codec with compression-loop, truncation, record-count and size guards.
- Added DNS-SD service inventory for common local protocols plus bounded dynamic service-type discovery. Advertisements are kept separate from TCP-confirmed service exposure.
- Added Wireless Android Debugging (`_adb-tls-*`) and other elevated DNS-SD service correlation into LAN XDR.
- Added explicit device identity-source classification (`MAC`, `MDNS_HOST`, `IP`) and stronger-identity migration without synthetic new-device alerts.
- Added authenticated schema-v2 LAN baselines tracking advertised service types and stable-device hostname/role drift while retaining schema-v1 compatibility.
- Added XDR events for newly advertised local services and device identity drift, plus richer Network Discovery UI metadata.
- Added Wi-Fi multicast-state permissions only for local mDNS discovery; no arbitrary target input, shell scanner or Internet-scope discovery was introduced.

# GeDefense Mobile 0.10.0-beta.1

- Added bounded local Wi-Fi/Ethernet Network Discovery with private-IPv4-only scope.
- Added authenticated LAN device/service baseline and XDR correlation for new devices and service exposure drift.
- Added high-risk local service detections including ADB/5555, Telnet, RDP and VNC.
- Added SSDP-assisted discovery and ARP enrichment when the Android platform exposes neighbor data.
- Hardened SSDP source admission to the planner-approved local target set, made IPv4 parsing strict, and replaced broad Throwable swallowing with explicit interruption/exception handling.
- Centralized system-bar/inset compatibility across security activities to remove duplicated Android version branches.
- Hardened behavioral, XDR, package-baseline and firewall state with authenticated atomic persistence from the 0.9.1 hardening pass.

# Changelog

## 0.9.0-beta.1

- Added local Behavioral EDR baselines for per-app Full Flow telemetry.
- Baselines track bounded traffic rates, observed DNS destinations, network geographies and activity-hour history without storing payload content.
- Added anomaly detectors for potential exfiltration patterns, unusual traffic-volume spikes, new-destination bursts, new network geographies and activity outside learned hours.
- Behavioral signals correlate into the existing XDR incident key for the affected package, allowing signer, permission, malware and network signals to compound the same incident.
- Added HMAC-SHA-256 authentication for mutable behavioral baseline state with fail-closed reset on integrity failure.
- Added Behavioral EDR UI with learning maturity, per-app baseline metrics, recent anomalies and a reset workflow.
- Added opt-in automatic network quarantine for CRITICAL behavioral anomalies; default policy remains alert-and-correlate only.
- Behavioral evaluation is live-throttled to avoid per-packet disk/CPU overhead and session baselines are committed only at Full Flow session boundaries.


## 0.8.1-beta.1

### Device hardening, XDR visibility and posture correlation

- Added a dedicated Device Hardening Center with a local 0-100 posture score derived only from observable Android controls; inaccessible state is reported as UNKNOWN and never silently converted into PASS.
- Added checks for secure credential lock screen, Android security-patch age, ADB, Developer Options, SELinux enforcement, Verified Boot/bootloader metadata where exposed, common root indicators, storage encryption, Private DNS, third-party Accessibility services, notification listeners and legacy device administrators.
- Added per-control evidence, severity, remediation guidance and direct links into relevant Android settings without attempting to mutate privileged state.
- Added hardening posture directly to the Device Security screen and Control Center so the feature is visible without navigating through the XDR internals.
- Added Hardening -> XDR correlation. Failed/high-review controls become bounded SYSTEM signals in the authenticated local event plane and participate in incident scoring.
- Extended the periodic integrity job to reassess hardening every six hours, allowing posture drift to surface even without manually opening the Hardening Center.
- Expanded the XDR Security Center with active-risk + hardening posture, live sensor-coverage status across package monitoring, malware scanning, GaiaNet, Integrity Guardian and hardening, plus severity-aware response guidance on incident cards.
- Added static security gates for hardening observability, UNKNOWN-state semantics, internal-activity export state, Security Center visibility and XDR integration.

## 0.8.0-beta.1

### XDR / EDR correlation and response foundation

- Added a persistent local XDR event plane that correlates PackageManager drift, sensitive permission changes, signing-certificate changes, malware-scan findings, integrity failures and GaiaNet threat blocks into per-subject incidents.
- Added package baselining across versionCode, current signing certificate, requested/granted permissions and privileged component capabilities including Accessibility, Device Admin, Notification Listener, VPN, overlay, package-install and boot-persistence surfaces.
- Added package-change monitoring for install, update, removal and changed-package broadcasts plus reconciliation on app startup to recover changes missed while GeDefense was not running.
- Added bounded incident scoring using category diversity and strongest recent evidence rather than treating any single heuristic as a malware verdict. XDR events remain local and are mirrored into the authenticated Evidence ledger.
- Added a dedicated XDR Security Center with incident cards, security timeline, risk score, source/category context and per-package network-quarantine actions.
- Added network quarantine state to the firewall policy. Quarantined packages are forcibly removed from the Lockdown allowlist and cannot be re-allowed until quarantine is explicitly cleared.
- Added Emergency Lockdown from the XDR Security Center to switch into default-deny VPN enforcement, including the Android VPN consent path where required.
- Added GaiaNet Selective and Full Flow threat-block ingestion into the XDR correlation plane with bounded deduplication.
- Added XDR ingestion of high/severe installed-app and shared-storage findings plus self-integrity failures.
- Added static security gates for XDR receiver export state, event-store bounds, package baseline primitives, correlation inputs and quarantine integration.

## 0.7.1-beta.1

### Default-deny app firewall and accelerated malware scanning

- Added a third VPN protection mode, **Lockdown**, that routes all non-allowlisted IPv4/IPv6 traffic into a local drop-only TUN while explicitly permitted apps and selected system packages bypass the VPN. GeDefense excludes only its own package as an operational invariant.
- Added a dedicated local Network Firewall surface with user/system/allowed filters and persistent package allowlisting. Policy changes can refresh an active Lockdown tunnel without disabling protection.
- Added persistent private scanner state with a seven-day forced deep-rescan ceiling. Unchanged shared-storage files reuse static findings and extracted public network indicators while Threat Intelligence correlation is recalculated against the current policy on every scan.
- Added 2-4 bounded storage-inspection workers, a deliberate 64-byte media fast path, and an allocation-light binary token scanner that avoids converting full binary chunks into Java/Kotlin strings.
- Added per-APK-entry delta scanning for installed apps. Unchanged DEX, native-library and selected asset entries are identified by ZIP entry name/CRC/size and reused across app updates; only changed entries are decompressed and rescanned.
- Added cached APK artifact hashing for unchanged installed package files while retaining bounded total hash/static-scan budgets.
- Scanner cache data remains private, bounded and non-authoritative: it cannot itself grant malware or firewall verdicts, and stale/invalid cache data fails back to normal scanning.

## 0.7.0-beta.1

### Guided setup and deep local scanner

- Added a first-run setup assistant that checks battery-optimization exemption, OEM autostart settings, all-files scanner access, usage access and notification permission without silently granting privileged state.
- Added safe OEM-autostart deep links with platform application-details fallback; reboot/package replacement restores scheduled Threat Intelligence and Integrity jobs without silently starting the VPN.
- Added optional Android 11+ `MANAGE_EXTERNAL_STORAGE` support for the on-demand scanner, isolated from the VPN protection path. Pre-Android-11 devices use the bounded legacy read permission path where applicable.
- Added a dedicated Device Security Scanner surface with animated radar/progress state, cancel support and Overview / Apps / Files result tabs.
- Added a bounded read-only shared-storage malware scanner with canonical-root jail checks, symlink rejection, file-magic/type mismatch detection, deceptive double-extension detection, executable-artifact signals, APK metadata/signing/permission review, bounded APK/ZIP inspection and Threat Intelligence correlation against embedded public IP indicators.
- Added explicit scan resource ceilings for file count, traversal depth, archive entries, bytes inspected and bytes hashed to prevent scanner-driven resource exhaustion.
- Extended the installed-app risk scanner with live progress/cancellation callbacks and integrated Integrity -> Apps -> Storage -> Evidence orchestration.
- Critical self-integrity failure during a deep scan still suspends active protection; heuristic file/app findings never independently authorize destructive remediation.
- Added localized setup/scanner UI copy with German, English, Russian and Simplified Chinese parity.
- Expanded static security gates for privileged-access isolation, setup activity/receiver export rules, bounded deep scanning and read-only storage semantics.

## 0.6.3-beta.1

- Increased adaptive screen gutters and vertical section spacing across Home, Activity, Device Security, Evidence and Control surfaces to remove edge crowding on 350-430dp phones while preserving narrow-device reflow.
- Added an in-app offline 2.5D Data-Flow Atlas to Device Security. It renders bounded app-to-country routes from GaiaNet live telemetry with app-colored arcs, animated flow particles, tappable destinations and a local app legend.
- Added a bundled dark GeDefense world-map graphic and a richer hero energy texture; both are local APK resources with no runtime image/map dependency.
- Added privacy-tiered origin positioning: country-centroid fallback by default, optional coarse Android location using last-known NETWORK/PASSIVE fixes quantized to 0.25 degrees. Fine/background location and active location subscriptions remain forbidden.
- Added country-level destination disclosure so the UI never implies that GeoIP country anchors are exact server coordinates.
- Added a generated ISO country-centroid table used only for the offline atlas.
- Extended source/security gates for map privacy, bounded route count, location-permission constraints and bundled-map invariants.
- No Threat Intelligence authority, GaiaNet forwarding, Evidence, Integrity or scanner enforcement semantics changed in this release.

## 0.6.2-beta.1

- Rebuilt the visual system around restrained glass panels, neutral borders and localized accent energy instead of full-card neon outlines.
- Added state-aware protection hero rendering: active Full Flow/Selective protection receives animated cyan/gold energy rings and particles behind the transparent GeDefense shield; inactive protection remains intentionally calm.
- Redesigned Home metrics, Quick Actions and Session XDR hierarchy for denser, more premium information composition.
- Redesigned Threat Intelligence rows with neutral glass cards, narrow action accents, compact modern icon wells and chevrons while preserving BLOCK/CORRELATE/ANNOTATE authority semantics.
- Redesigned Device Security cards with accent rules, quieter surfaces and compact action controls.
- Reworked bottom navigation into a lighter glass dock with a gold focus rail instead of a large selected-tab block.
- Refined typography to system sans-serif-medium/sans-serif roles, reduced background grid prominence and added subtle atmospheric light streaks.
- No networking, policy, evidence, scanner, integrity or threat-enforcement semantics changed in this UI release.

## 0.6.1-beta.1

### VGT premium UI refinement

- Reworked all five navigation surfaces around a shared dependency-free glassmorphism design system with denser cards, controlled cyan/gold depth, consistent status pills and custom-drawn security icons.
- Replaced font-dependent symbol/emoji navigation and security glyphs with the in-repository `VgtIconView` vector renderer.
- Refined the protection hero with a compact mode badge, animated energy arcs, mode-aware threat-vector labels and stronger visual hierarchy.
- Replaced the dashboard XDR summary sentence with a responsive 2x2 session-metric grid for active flows, blocks, threat destinations and attributed apps.
- Redesigned Threat Intelligence feed cards with explicit BLOCK / CORRELATE / ANNOTATE iconography while preserving enforcement authority semantics.
- Redesigned Device Security with integrity status matrix, app-risk result cards, per-app live traffic cards, local country progress bars, DNS summaries and 24-hour traffic bars.
- Refined Evidence & Policy and Control Center surfaces to the same component language.
- Reduced grid/background visual noise while keeping safe-area and display-cutout isolation unchanged.
- Added full German, English, Russian and Simplified Chinese string parity for the new UI states.

## 0.6.0-beta.1

### GaiaNet Full Flow

- Added an in-repository Go userspace network core with zero external Go modules.
- Added optional Full Flow beta routes (`0.0.0.0/0`, `::/0`) while retaining Selective Shield mode.
- Added bounded IPv4/IPv6 parsing, fragment reassembly, TCP proxy/state handling, UDP forwarding, DNS observation, global flow quotas, telemetry backpressure handling and finite timeouts/retransmission.
- Added fragment-overlap rejection, cryptographic TCP ISNs with fail-closed entropy failure, client SYN-ACK acknowledgement gating and flow-local goroutine shutdown.
- Added narrow JNI start/stop/API-version bridge and reproducible arm64-v8a/x86_64 Go/NDK build path.
- Bound the JNI policy snapshot to the deterministic full-policy SHA-256; GaiaNet recomputes it and rejects tampering, trailing data, duplicate/non-canonical prefixes and feed-authority escalation.
- Hardened client FIN handling so backpressure can never acknowledge a half-close that was not accepted by the bounded upstream queue.

### Live XDR-style network analytics

- Added per-flow UID/package attribution through Android's VPN connection-owner API.
- Added live per-app bytes, active flows, block/correlation/annotation counters, visible DNS names and Top-3 country summaries.
- Added bounded native telemetry framing and fail-closed behavior for critical-event loss.

### Local Geo-country plane

- Added local PDDL user-country IPv4/IPv6 dataset ingestion with upstream SHA-256 verification and compact binary range lookup.
- Added Android-Keystore-HMAC authenticated manifests and active generation pointers.
- Added transactional active-pointer publication/rollback, last-known-good retention and startup recovery of the newest valid authenticated generation.
- Added fixed allowed download hosts, no-proxy HTTPS path and bounded file/line/record sizes.
- Added periodic Geo refresh to the existing background security-data job.

### Verification

- Added hostile-input Go fuzz targets for packet parsing, policy decoding, DNS parsing and fragment reassembly.
- Expanded source security gates for GaiaNet, Geo generation transactionality and Full Flow JNI/analytics boundaries.
- Promoted version line from alpha to first Full Flow beta.

## 0.5.0-alpha.1

### TUN policy invariant correction

- Filter non-public local OS/kernel traffic (IPv6 DAD, MLD, router solicitation, multicast, link-local, ULA/interface-local and IPv4 local/multicast traffic) before flow accounting and selective-route policy evaluation.
- Keep `POLICY_INVARIANT_FAILED` intact for public destinations, where a route/evaluator disagreement remains a real security invariant violation.
- Added direct `IpAddress.isPublic()` coverage for TUN-local IPv4/IPv6 control traffic.

### Integrity Guard

- Added a Keystore-HMAC authenticated installation baseline binding package identity, version, installed APK-set SHA-256 and signing identity.
- Same-version APK changes, signing-identity changes, version rollback, baseline MAC tampering, private-filesystem symlinks/jail escape and unexpected executable artifacts fail integrity.
- Valid forward app updates may advance the baseline only under the same signing identity.
- Added six-hour JobScheduler verification and fail-closed VPN shutdown when integrity becomes unhealthy.

### Malware & App Risk Scanner

- Added local installed-app inventory using the security-product package-visibility permission.
- Added bounded metadata risk rules, APK SHA-256, signing fingerprints and install-source context.
- Added bounded base/split-APK ZIP/DEX/native/static-asset scanning without loading or executing inspected code, including IPv4/IPv6 Threat-Intel literal correlation and global scan budgets.
- Embedded public IP literals are correlated against the current nine-feed ThreatIndex; block-authority and correlate-only hits remain distinct evidence.
- Scanner results stay runtime-local and never authorize automatic app deletion or process termination.

### Traffic Insights

- Added user-granted Android Usage Access integration and bounded `NetworkStatsManager.querySummary` passes (Wi-Fi + mobile + Ethernet) for previous-24-hour per-UID RX/TX totals.
- Added a Device Security screen with integrity, app-risk and per-app traffic summaries.
- Country ranking intentionally remains disabled until Full-Flow exists because Android usage accounting does not expose destination IPs.


## 0.4.0-alpha.1

### GeDefense mobile interface

- Replaced the single long diagnostic screen with a production-style four-tab interface: Dashboard, Live Threat Intelligence, Evidence & Policy, and Control Center.
- Added a dependency-free GeDefense design system with obsidian/graphite surfaces, metallic-gold accents, electric-blue/cyan status lighting, translucent glass panels, responsive cards and branded shield presentation.
- Added an atmospheric custom-drawn cyber background and shield pulse treatment without adding AndroidX, Compose, image libraries or third-party UI dependencies.
- Preserved all existing protection, threat-feed synchronization, evidence verification and evidence-recovery controls inside the new UI.
- Threat-feed cards preserve enforcement semantics: route-block, correlate-only and annotate-only are visually distinct rather than being presented as equivalent blocking sources.

### Responsive / display-cutout safety

- Added explicit edge-to-edge system-bar handling with `WindowInsets` and `DisplayCutout` safe insets.
- App content now stays below centered/offset hole-punch cameras and notches, clear of the status bar, above gesture/navigation insets, and inside landscape side-cutout safe areas.
- Only the decorative background renders behind system bars; interactive content lives inside the safe-area host.
- Replaced brittle fixed-width layouts with weighted responsive grids and a narrow-screen fallback that stacks metric cards vertically.
- Added a UI design/test specification covering cutouts, small displays, font scaling and rotation.

## 0.3.0-alpha.1

### Protection / policy integrity

- Added a pure local `PolicyEngine` separating feed evidence from enforcement authority.
- TUN readers are now bound to the exact immutable `ThreatIndex` snapshot used to install their route set.
- Removed a route-refresh race where a packet entering an older TUN could be evaluated against a newer global threat index and be silently dropped despite no longer matching that policy.
- Route installation is now all-or-nothing; one rejected route refuses the entire protection activation/refresh.
- Added `POLICY_INVARIANT_FAILED`: any disagreement between the installed selective-sinkhole route policy and local evaluator suspends protection rather than silently broadening blocking.
- Added deterministic SHA-256 fingerprints for exact installed blocking route policies and records them in local Evidence events.
- Added bounded persisted reason codes for degraded/offline VPN states; normal states clear stale reasons.

### Threat intelligence

- Background feed synchronization is cancellation-aware and JobScheduler cancellation no longer intentionally leaves untracked work running.
- Interrupted syncs never publish a partially built threat index.
- Switched Tor annotation data to the Tor Project bulk exit list rather than a third-party mirror.
- Switched FireHOL Level 1 to FireHOL's direct upstream list endpoint.
- Added static release gates that enforce those source choices, the Tor annotation-only invariant and immutable TUN-policy snapshots.

### Evidence

- Unexpected Evidence verification failures now produce fail-closed degraded health instead of escaping the verification worker.
- Recovery manifests are now HMAC-SHA-256 authenticated and bind archive filename, SHA-256, size, timestamp, reason and invalid record.
- Recovery verifies the archive+manifest pair before resetting the active ledger.
- The fresh post-recovery ledger is re-read from disk and must verify empty before recovery succeeds.
- Added recovery-manifest tamper regression coverage.

### Verification / operations

- Expanded real-device beta gates for route compaction, partial-route refusal, immutable policy snapshots, JobScheduler cancellation, process death and Evidence failure.
- Added explicit Windows/Android Studio build instructions and debug APK path.
- Expanded security audit with `VPN_POLICY_SNAPSHOT_PASS`.

## 0.2.0-alpha.1

- Added exact CIDR route compaction for `ROUTE_BLOCK` intelligence.
- Added hard route-candidate and compacted-route budgets; overflow refuses partial enforcement.
- Added per-feed freshness/record health state to the UI.
- Added bounded session XDR metrics for blocked packets, bytes, destinations, apps and active flows.
- Added bounded UID/package attribution caching to reduce per-packet Android framework calls.
- Evidence degradation now suspends active blocking rather than continuing unaudited enforcement.
- Added explicit operator-triggered Evidence re-verification.
- Added notification action to stop protection.
- Disabled Android Always-on capability until full-flow forwarding exists.
- Threat-index loading is now incremental across feed generations instead of retaining an aggregate record list.
- Added upstream-informed single-VPN WireGuard transport design.

## 0.1.0-alpha.1

Initial Android source alpha.

### Protection

- native Android `VpnService` selective threat-route sinkhole
- IPv4/IPv6/TCP/UDP packet metadata parser
- bounded flow tracking and event deduplication
- best-effort UID/package attribution

### Threat intelligence

- nine-source VGT threat-intelligence catalog
- Feodo and Spamhaus DROP/DROPv6 high-confidence route enforcement
- CINS, blocklist.de, Emerging Threats, IPsum and FireHOL correlation sources
- Tor exits annotation only
- modernized Spamhaus eDROP handling to current DROP v4/v6 datasets
- bounded HTTPS downloader with no proxy and same-host redirect policy
- authenticated, generation-based, crash-tolerant feed cache
- freshness/staleness budgets and anomalous-shrink refusal

### Evidence

- Android-Keystore-backed HMAC-SHA-256 chained local Evidence Ledger
- explicit forensic archive recovery path

### UI

- native dark GeDefense UI
- English, German, Russian and Simplified Chinese resources

### Explicitly not included

- full-flow forwarding
- WireGuard transport
- TLS MITM
- cloud account/telemetry

### Supreme pre-release audit (VC55, no version bump)

- Telemetry Shield is now a prominent Privacy step in the setup assistant with explicit Full-Flow/non-MITM boundaries.
- GaiaNet release toolchain moved from unsupported Go 1.23.x to pinned Go 1.26.8; both Android helper ABIs rebuilt reproducibly.
- WireGuard Android socket-protection IPC re-arms a fresh 5-second read deadline before its second control-channel read; regression coverage proves a stale startup deadline cannot poison the ACK phase.
- Security-critical file publication is staged, fsynced, verified, atomically replaced without downgrade, and directory-fsynced; recovery enumerations are bounded/no-follow.
- Empty catch blocks were removed; non-critical failures use bounded privacy-safe reporting and critical Evidence/XDR/Integrity failures propagate.
- Added exact Go dependency reachability gate and deterministic CycloneDX 1.6 SBOM gate.
