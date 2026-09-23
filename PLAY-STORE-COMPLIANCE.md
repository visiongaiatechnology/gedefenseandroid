# Google Play Release Compliance — 0.27.6-beta.1

This document separates code-complete controls from actions that can only be completed in Play Console or on real devices.

## Code-complete controls

- `targetSdk = 36`; Android 16 targeted behavior is therefore active on supported devices.
- `VpnService` has a dedicated prominent disclosure and explicit affirmative decision before Android VPN consent.
- VPN disclosure state is authenticated in `noBackupFilesDir`; invalid/tampered state fails closed.
- `GeDefenseVpnService` independently refuses protection startup without accepted product disclosure, including lifecycle/Always-on starts.
- VPN consent can be revoked from the in-app Privacy Center and revocation stops protection.
- No `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` permission and no direct exemption-request intent. GeDefense only opens Android battery settings.
- `QUERY_ALL_PACKAGES` is limited to antivirus/XDR/firewall functions; initial background package reconciliation waits for explicit setup completion.
- `MANAGE_EXTERNAL_STORAGE` is scanner-only, read-only in GeDefense code, optional for VPN protection and requested through Android special-access UI.
- Privacy Center documents VPN metadata, package inventory, file scanning, usage access, optional coarse location, diagnostics, external dataset requests and retention.
- GaiaNet packaged 64-bit ELF helpers use >=16 KiB PT_LOAD alignment.
- Application backup is disabled.
- No ad, analytics or third-party crash-reporting SDK exists.

## Play Console declarations still required

### VpnService

Declare the Device Security / Antivirus / Firewall core purpose. The store listing must describe local VPN use. Prepare the required short review video showing: open GeDefense -> prominent local-VPN disclosure -> affirmative action -> Android VPN consent -> protection enabled. If Play asks for a second sensitive-data disclosure video, show the same disclosure before VPN access.

### QUERY_ALL_PACKAGES

Declare antivirus/security as the core function requiring broad installed-app visibility. Explain signer/permission/package-drift analysis, local XDR correlation and firewall policy presentation. State that package inventory is processed locally and is not uploaded to VGT.

### MANAGE_EXTERNAL_STORAGE

Declare antivirus as the core function. Explain that recursive malware inspection of user/shared storage cannot be implemented with equivalent coverage through media-only APIs or one-off SAF selections. State that access is optional for VPN protection and the scanner is read-only.

### Data Safety

Complete the form from the final release binary and this repository's egress inventory. Local-only processing is not treated as off-device collection by the Play definition, but do not mechanically answer “no data collected” without validating every final network path. Dataset servers necessarily receive ordinary connection metadata such as source IP at the transport layer.

### Privacy Policy

Publish `PRIVACY.md` at a stable public HTTPS URL, enter that URL in Play Console, and use the exact official VisionGaiaTechnology developer/legal contact data from the Play developer account. The policy must remain reachable without login or geofencing.

## Release artifacts

Play: signed `.aab` generated from the same commit as the public source release.  
GitHub: signed `.apk`, source archive, checksums, release notes and provenance/build information.

## External verification gates before production

- Android 16/API 36 real device or official emulator: VPN start/stop, disclosure, predictive-back/edge-to-edge UI, notifications, jobs and package visibility.
- 16 KiB page-size runtime: install and execute both packaged-helper paths where applicable; verify no linker/execution fault.
- OEM matrix: Pixel/AOSP, Samsung One UI and Xiaomi/HyperOS at minimum.
- Full Flow: sustained TCP/UDP/QUIC, DNS, Wi-Fi/cellular handover, sleep/Doze, Always-on and Lockdown recovery.
- TITAN: provisioning/readback, suspension, restrictions, Always-on lockdown and destructive controls only on disposable managed hardware.

## Closed testing

If the Play developer account is subject to Google's personal-account closed-test requirement, complete the required tester count/duration before applying for production access. This is an account-level requirement and cannot be satisfied by source code.
