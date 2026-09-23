# GeDefense Mobile 0.27.8-beta.6 — Public Beta Release Notes

`0.27.8-beta.6` adds embedded WireGuard egress behind GaiaNet and completes the corresponding fail-closed recovery, handover, Strict kill-switch and release-toolchain hardening. It retains the beta.5 bounded runtime/crypto bootstrap architecture while adding per-socket Android VPN protection, pinned upstream WireGuard, dual-stack/MTU/DNS validation and a mandatory initial Threat Intelligence sync during Setup.

The package-baseline v2→v3 migration and beta.4 class-initializer fix remain intact. GaiaNet V2 transport behavior is unchanged in this release; integrated WireGuard is intentionally gated as a follow-up transport feature rather than mixed into the startup stabilization patch.

## New first-run experience

The setup assistant is now a ten-stage guided security onboarding. It explains what GeDefense is, how the local VPN boundary works, what XDR and threat intelligence do, why reliability settings matter, what the optional scanner can access, what optional visibility signals add, where TITAN fits, and what remains local on the device.

Capabilities are labeled **Core**, **Recommended**, **Optional** or **Enterprise**. Optional Android privileges are not treated as mandatory for baseline VPN protection.

## Full Flow persistence hardening

Full Flow now defaults on fresh installs and installs only the IPv4/IPv6 default routes; the large threat policy remains inside GaiaNet instead of being mirrored into thousands of Android VPN routes. Selective Shield remains available but refuses route sets above the conservative platform budget rather than silently reducing enforcement.

Evidence and XDR persistence are now isolated failure domains. A durable Evidence failure remains fail-closed and stops/recoveries the affected protection session; an XDR enrichment/store failure is surfaced separately without falsely labeling Evidence as broken or disabling an already-enforcing Full Flow tunnel.

The high-frequency Evidence and XDR-event cryptographic domains use non-exportable TEE-backed Android Keystore keys rather than StrongBox-per-record operations. Authoritative low-frequency policy stores still prefer StrongBox. This is an availability hardening decision: confidentiality and non-exportability remain intact while the hot path avoids OEM StrongBox throughput/operation-slot limitations.

## Secure Telemetry Vault

Sensitive durable GeDefense state is encrypted at rest in twelve compartmentalized vault domains. XDR/behavior/package baselines, malware-analysis state, app approvals, firewall policy, LAN/Port Sentinel state, TITAN policy, scanner caches and Evidence no longer rely on private-directory plaintext as their final security boundary. The VPN disclosure is intentionally stored as an independent HMAC-authenticated authorization receipt rather than encrypted telemetry, eliminating an unnecessary Keystore/AEAD availability dependency from the protection-start path.

Each vault domain uses versioned AES-256-GCM with Android Keystore key custody and retains independent HMAC authentication where the store format supports it. Earlier authenticated beta snapshots are upgraded locally and fail closed if encryption cannot be persisted before use. Evidence uses encrypted v3 records.

Durable recovery artifacts are signed with Android-Keystore ECDSA. Android 17+ / KeyMint 5 devices can add ML-DSA-87 as a second hardware-backed signature. Post-quantum signature support is intentionally conditional; GeDefense does not ship a home-grown ML-DSA implementation or misuse a signature primitive as encryption.

## Privacy and Play-readiness hardening

- Versioned, authenticated prominent VPN disclosure with service-level fail-closed enforcement.
- Privacy Center with revocation that stops VPN protection.
- Fresh-install package inventory delayed until setup completion.
- No direct battery-optimization exemption permission.
- Optional coarse location only; no fine/background location request.
- Documented runtime network egress and release gate for new hard-coded HTTPS hosts.
- Play declaration, Data Safety and VpnService review-video drafts included with the source.

## Native and release integrity

- GaiaNet arm64-v8a and x86_64 helpers are reproducibly rebuilt during security auditing.
- Packaged GaiaNet ELF PT_LOAD segments are checked for at least 16 KiB alignment.
- APK and AAB artifact auditing verifies archive integrity, expected native ABIs and release signatures.
- Source-manifest verification binds the public source snapshot to the audited tree.
- Release lint is held to **0 errors / 0 warnings** by `tools/lint-zero-audit.py`; CI fails if a lint issue returns.
- A self-contained `docs/privacy.html` is included for public HTTPS publication of the Play privacy policy.

## Beta scope

This is not a claim of perfect protection. The public beta is intended to collect compatibility and usability evidence across Android/OEM variants while keeping security boundaries explicit. Reports should include Android version, device/OEM, protection mode and sanitized reproduction steps. Do not publish sensitive diagnostic material in public issues.