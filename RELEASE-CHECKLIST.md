# Public Release Checklist

A release is not declared ready because an APK exists. Every applicable gate below must have evidence.

## Source and supply chain

- [ ] `bash tools/release-readiness.sh` passes from a clean tree.
- [ ] `SOURCE-MANIFEST.sha256` was regenerated only after all source changes and verifies cleanly.
- [ ] `python3 tools/onboarding-audit.py` passes and the versioned first-run education path remains intact.
- [ ] Gradle wrapper checksum matches `TOOLCHAINS.lock`.
- [ ] No signing material, tokens, service-account files, private captures or local build secrets are present.
- [ ] GaiaNet packaged helpers byte-match reproducible source builds.
- [ ] All GaiaNet PT_LOAD segments are >=16 KiB aligned.

## Android artifacts

- [ ] Release APK builds and signature verifies.
- [ ] Release AAB builds from the same source state.
- [ ] `tools/artifact-audit.sh` verifies archive integrity, release signatures and both packaged GaiaNet ABIs.
- [ ] Release lint contains zero errors **and zero warnings**; `python3 tools/lint-zero-audit.py` passes.
- [ ] `targetSdk=36`, `minSdk=29`; compile SDK/toolchain state is documented.
- [ ] Version code/name match `VERSION` and release notes.

## Privacy and permissions

- [ ] VPN prominent disclosure cannot be bypassed by UI, Always-on or lifecycle start.
- [ ] Privacy Center accurately describes local processing and network egress.
- [ ] All-files access remains scanner-only and read-only.
- [ ] Package inventory is not background-enumerated before completed setup on fresh install.
- [ ] No direct battery-optimization exemption permission is present.
- [ ] Play declarations for VPN, package visibility and all-files access are prepared.
- [ ] Data Safety draft is reconciled against the final binary and `NETWORK-EGRESS.md`.
- [ ] VpnService review video is recorded from the exact release build using `VPN-REVIEW-VIDEO-SCRIPT.md`.
- [ ] Public privacy-policy URL is live before Play submission.

## Real-device beta gates

- [ ] Android 10 baseline device.
- [ ] Android 14/15 device.
- [ ] Android 16/API 36 device.
- [ ] Pixel/AOSP-class device.
- [ ] Samsung-class device.
- [ ] Xiaomi/HyperOS device.
- [ ] 16 KiB page-size runtime where available.
- [ ] Sustained Full Flow traffic, handover, Doze, reboot, Always-on/Lockdown and recovery exercised.

## Community release

- [ ] README accurately states beta scope and non-claims.
- [ ] `SECURITY.md`, `PRIVACY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`, `NETWORK-EGRESS.md` published.
- [ ] Issue templates and CI verification enabled.
- [ ] GitHub private vulnerability reporting enabled.
- [ ] Release notes include known limitations and compatibility-report request.
- [ ] Store listing avoids absolute security claims and accurately distinguishes local VPN protection from a consumer location-changing VPN.

### Android 16 / safe-area closure

- [x] `compileSdk=36` and `targetSdk=36` are both present in the release build.
- [x] `VpnDisclosureActivity` consumes system-bar + display-cutout safe-area insets.
- [x] `PrivacyActivity` consumes system-bar + display-cutout safe-area insets.
- [x] Release audit rejects VGT edge-to-edge activities that do not consume insets.
- [x] Release lint is zero errors / zero warnings against the API 36 platform.

## Secure Telemetry Vault

- [x] Sensitive durable telemetry and security metadata are mapped to explicit versioned `VaultDomain` identities; legacy-only domains are never active write targets.
- [x] AES-256-GCM persistent codec exists only once in the pure JVM core and has adversarial AAD/tamper tests.
- [x] Independent HMAC authentication retained for snapshot/Evidence structures; active vault-backed snapshots use update-stable per-domain HMAC subkeys, with direct OEM Keystore HMACs migration-only.
- [x] Legacy authenticated plaintext migration is fail-closed and durable-before-release.
- [x] Evidence v3 payloads are encrypted and remain HMAC-chained.
- [x] Android backup/device-transfer extraction remains disabled for vault state.
- [x] Key-generation field and re-encrypt-on-read rotation path are release-audited.
- [x] ECDSA detached artifact signing is present; ML-DSA-87 is conditional on native Android 17+/KeyMint 5 hardware support.
- [x] `python3 tools/secure-vault-audit.py` returns `SECURE_TELEMETRY_VAULT_PASS`.
- [x] Encrypted snapshot recovery from an unusable historical outer OEM HMAC requires successful inner AES-GCM authentication plus durable re-HMAC before plaintext release; plaintext legacy state has no bypass.
- [x] VPN disclosure uses update-stable active HMAC; unusable historical plaintext-HMAC receipt requires explicit re-acceptance.
- [x] Keystore/opaque-key provider operations are off-main-thread, admission-bounded and use a 5 s provider deadline.
- [ ] Real-device in-place retest on Xiaomi/HyperOS confirms package-baseline, network-discovery, Port Sentinel and VPN disclosure recover/reauthorize correctly after update and reboot.
- [ ] Real-device Keystore/StrongBox latency and background Evidence-write behavior exercised during OEM beta matrix.

## Embedded WireGuard beta.6 gate

- [x] Upstream `wireguard-go` and required Go modules are pinned, vendored and referenced through local `replace` directives; GeDefense implements no WireGuard cryptographic primitive.
- [x] GeDefense remains the single Android `VpnService`; WireGuard is an in-process GaiaNet Layer-3 egress.
- [x] WireGuard startup has no Direct fallback; Strict additionally requires Android Always-on lockdown.
- [x] Whole-UID VPN bypass is forbidden in WireGuard modes; only the exact upstream UDP socket FDs may be underlay-bound and `VpnService.protect()`-ed.
- [x] WireGuard endpoint resolution and socket protection have explicit bounded platform-call deadlines and fail closed.
- [x] MTU `1280..1420` propagates Android -> helper -> GaiaNet -> in-process WireGuard TUN; oversized peer plaintext is rejected before Android reinjection.
- [x] WireGuard UAPI/profile secret-bearing scratch encoders are explicitly wipeable; one-shot UAPI crosses the process boundary by pipe, not plaintext file or process argument.
- [x] Build repository configuration is relocatable; optional local Maven mirror is supplied through `VGT_LOCAL_MAVEN`, not a host-specific source path.
- [x] Helper crash/recovery retains an Android-side TUN liveness anchor; replacement establishes the new VPN interface before the old session is closed, and WireGuard startup failure retains a no-reader fail-closed anchor.
- [x] Underlay handover is generation-safe and callback I/O is serialized off the network callback thread; underlay absence pauses recovery without consuming the bounded retry budget.
- [x] Strict runtime lockdown loss is monitored by one bounded watchdog task and retains the fail-closed VPN anchor instead of silently degrading to Direct; watchdog scheduling failure is itself handled fail-closed.
- [x] Full-Flow fatal telemetry callbacks are helper-generation scoped on both sides of the reader/main/control handoff, so stale EOF from a replaced helper cannot recycle its healthy successor.
- [x] Vendored upstream WireGuard rekey/replay/rate-limiter tests run fully offline via `tools/wireguard-upstream-check.sh`; GeDefense does not implement a parallel rekey engine.
- [x] GitHub verification pins JDK 17 / Go 1.26.8 / NDK `27.2.12479018`, verifies the installed NDK revision, and runs release compile/APK/AAB/lint before full release-readiness.
- [ ] Re-run JDK 17 + SDK 36 + NDK `27.2.12479018` clean build on the exact VC55 ASN tree. The current sandbox lacks SDK/NDK, and the inherited packaged GaiaNet helpers require regeneration/byte-match against the newer `netstack/` source before this gate can be re-closed.
- [ ] Exact VC55 ASN tree passes `compileReleaseKotlin`, `assembleRelease`, `bundleRelease`, `lintRelease` and zero-warning lint audit; current sandbox lacks the cached Android/Gradle toolchain required to re-run these gates.
- [ ] Exact frozen VC55 ASN tree passes full security audit, release readiness and artifact/signing/alignment gates. Source/static gates are re-run locally; native/Android artifact gates remain blocked until the pinned SDK/NDK/Gradle toolchain is restored.
- [ ] The complete `BETA-TEST-PLAN.md` WireGuard release matrix passes on real Xiaomi/HyperOS hardware, including Strict kill-switch, DNS, dual-stack, MTU, handover, Doze and forced-failure tests.

## ASN evidence pre-public gate

- [x] ASN source is `IPtoASN`-derived PDDL/Public-Domain data distributed through the pinned `sapics/ip-location-db` release paths; DB-IP ASN data is not used.
- [x] IPv4 and IPv6 source files require published SHA-256 verification before compilation; accepted generations persist source and compiled-index hashes plus source/license provenance.
- [x] Local binary indexes are bounded, ordered/non-overlapping and queried with O(log n) binary search; ASN 0 is omitted as non-evidence.
- [x] ASN generations and active pointer are HMAC-authenticated under a dedicated key domain with last-known-good rollback/recovery.
- [x] ASN lookup is local-only and `evidence_only`: no destination-IP lookup API, block/allow path or XDR-score ingest exists.
- [x] `python3 tools/asn-evidence-audit.py` is chained into the security/release gate.
- [ ] Real-device first sync and cached restart validate actual IPv4+IPv6 snapshot download/compile/load under representative OEM storage/network conditions.

## Telemetry Shield pre-public gate

- [x] Privacy Intelligence is an APK-vendored, bounded, provenance/license-bearing snapshot; no runtime tracker API is required.
- [x] Blocking authority is derived locally from profile/confidence/breakage risk and essential connectivity/push/update rules override telemetry rules.
- [x] Helper protocol v5 carries an independently authenticated privacy-policy FD; Direct and WireGuard enforce the same policy.
- [x] Blocked classic DNS queries receive local bounded NXDOMAIN responses and matching events are revalidated before Evidence/XDR ingestion.
- [x] Privacy Center exposes OFF / Conservative / Balanced / Strict and freezes profile mutation while VPN protection is active.
- [x] UI and public documentation explicitly state that Telemetry Shield system-wide enforcement requires Full Flow; Selective mode makes no equivalent claim.
- [x] Encrypted DNS remains non-MITM: Conservative/Balanced observe captured port 853; Strict blocks captured DoT/DoQ port 853 plus known signed resolver bootstrap domains. Generic HTTPS/443 is never blanket-blocked.
- [x] Google Public DNS, Cloudflare and Quad9 bootstrap records use official documentation as local `REFERENCE` provenance; no runtime resolver API is used.
- [x] Custom DoH over shared HTTPS/443, hard-coded resolver IPs and ECH remain explicitly documented visibility limits rather than being misrepresented as blocked.
- [x] `python3 tools/privacy-shield-audit.py` is part of both security and release-readiness gates.
- [ ] Xiaomi real-device validation confirms profile switching while stopped, DNS blocking/allow precedence, WireGuard parity and no breakage of connectivity/push/update essentials.



## InstallGuard pre-public gate

- [x] Package-added/package-replaced handling runs off-main after setup completion and uses no runtime cloud verdict API.
- [x] Non-system application quarantine is staged before the bounded priority scan and PASS explicitly releases it; REVIEW/BLOCK/INCOMPLETE retain containment.
- [x] Helper protocol v5 carries a dedicated package-egress gate FD; Direct TCP, Direct UDP and WireGuard consult the Android UID authority before new egress while quarantine is active.
- [x] Unknown ownership, IPC timeout/malformed response and gate failure are fail-closed; helper gate failure enters the existing TUN-anchor recovery path.
- [x] Quarantine policy changes clear native flow-attribution cache and close existing Direct flows; WireGuard evaluates the gate before egress and denies fragmented traffic while the gate is active.
- [x] Device Owner may additionally suspend quarantined user apps; Standard/TITAN Light documentation explicitly avoids an absolute pre-first-packet guarantee.
- [x] Fast verdict and deep scan use independent zero-queue worker pools with hard 1.75 s / 25 s wall-clock budgets; timeout/capacity exhaustion never becomes PASS.
- [x] Brand-new apps require deep inspection before release; fast release is limited to low-risk updates with signer continuity against authenticated local evidence.
- [x] Deep timeout/failure after a fast release reinstates quarantine before INCOMPLETE is published.
- [x] Scanner UI exposes FAST VERDICT vs DEEP SCAN and accurately describes Full-Flow package egress blocking without claiming an absolute Android pre-first-packet guarantee.
- [x] `python3 tools/install-guard-audit.py` is part of security and release-readiness gates.
- [ ] Xiaomi real-device validation confirms install/update PASS release, REVIEW/BLOCK retention, Full-Flow Direct/WireGuard egress denial, gate recovery and Device Owner suspension behavior.


## Resilience Supervisor pre-public gate

- [x] Self-healing is local-only, single-flight and bounded by a zero-capacity recovery executor, per-component cooldown/window budget and per-run repair ceiling.
- [x] Automatic repair is trust-preserving only: signed asset reload, authenticated-state re-read, cached Threat Intelligence reload, helper revalidation, package reconciliation and enforcement reassertion.
- [x] Evidence/XDR history, integrity baselines and authenticated policy stores are never automatically reset or cleared by the supervisor.
- [x] Persistent trust failures escalate to `FAIL_CLOSED`, `OPERATOR_REQUIRED`, `SCAN_REQUIRED` or `SYNC_REQUIRED` instead of being relabeled healthy.
- [x] Secondary trust/behavior/malware bootstrap completion is bounded before health classification so startup initialization cannot masquerade as corruption.
- [x] A persisted network-free JobScheduler task runs every two hours; immediate VPN/WireGuard recovery remains event-driven and independent.
- [x] InstallGuard quarantine drift is reasserted in GaiaNet and TITAN Device Owner suspension is reconciled without relaxing policy.
- [x] Aggregate self-healing state is available in Diagnostics; repair/critical findings are journaled to Evidence/XDR.
- [x] `python3 tools/resilience-supervisor-audit.py` is part of both security and release-readiness gates.
- [ ] Xiaomi real-device validation confirms scheduled reconciliation, process restart, trust-store transient failure, quarantine drift repair and no battery/restart storm.

## Update-stable vault acceptance

- [ ] Install the previous signed VC55 build, create representative Evidence/XDR/policy/scanner/WireGuard state, then install the new signed VC55 test build over it without clearing app data.
- [ ] Verify cold start preserves and opens all existing stores, Evidence chain and XDR history, and that each migrated snapshot is rewritten under the persistent key generation only after successful authentication.
- [ ] Restart the process repeatedly and verify the persistent domain keysets are reused rather than regenerated.
- [ ] Verify a changed APK/install hash advances Integrity Guardian independently and does not alter the vault root or make encrypted data unreadable.
- [ ] Force an interrupted/failed migration on a disposable device and verify the old ciphertext/key generation remains recoverable and no automatic destructive reset occurs.


## Supreme pre-release hardening (2026-09-23)

- [x] Go supply-chain reachability gate: Go 1.26.8, reviewed module graph, known-advisory packages unreachable (`GO_SUPPLY_CHAIN_REACHABILITY_PASS`).
- [x] Deterministic CycloneDX 1.6 SBOM regenerated and license/toolchain inventory verified (`SBOM_AUDIT_PASS`).
- [x] Crash-safe authenticated persistence rejects non-atomic fallback and fsyncs parent directories (`DURABLE_PERSISTENCE_AUDIT_PASS`).
- [x] Recovery/state directory scans are bounded and no-follow (`BOUNDED_STORAGE_AUDIT_PASS`).
