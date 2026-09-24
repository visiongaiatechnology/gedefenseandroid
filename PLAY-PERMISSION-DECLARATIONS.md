# Google Play Permission Declaration Drafts

**Release:** `0.27.4-beta.1`

These drafts describe the shipped implementation. They must be checked against the final Play Console wording and final binary before submission.

## VpnService

**Core purpose:** device security, antivirus/XDR and firewall enforcement.

GeDefense creates a local Android `VpnService` tunnel on the device so it can inspect network metadata and apply local threat-intelligence and firewall policy. It is not a consumer location-changing VPN service. GeDefense does not terminate TLS to inspect encrypted application payloads and does not upload a browsing/traffic history to VisionGaiaTechnology.

Before Android's VPN permission dialog is reached, GeDefense presents an in-app prominent disclosure explaining the local VPN architecture, data categories, Android VPN indicator and user controls. Acceptance is versioned and authenticated locally. The VPN service itself refuses startup without valid acceptance, including lifecycle and Always-on starts. Acceptance can be revoked in the Privacy Center.

## QUERY_ALL_PACKAGES

**Core purpose:** antivirus/XDR package-risk analysis and firewall/security context.

GeDefense needs broad installed-package visibility to detect package additions/removals, signer and permission drift, risky application posture and to correlate local app identity with observed security events. Package inventory is processed locally. Fresh installations do not perform the initial background package inventory until the user completes the setup assistant.

GeDefense does not use package visibility for advertising, profiling or sale of data.

## MANAGE_EXTERNAL_STORAGE

**Core purpose:** optional antivirus/malware scanning of user-accessible shared storage.

The optional Device Security Scanner can recursively inspect user/shared storage for suspicious executable artifacts, APKs, deceptive file types and bounded archive contents. The scanner is read-only in GeDefense application logic and is bounded by file-count, recursion, archive-entry, content and hashing budgets.

This permission is not required for local VPN protection. GeDefense does not claim or attempt to bypass Android private application sandboxes.

## PACKAGE_USAGE_STATS

**Purpose:** optional local security context.

Usage access is optional. When enabled, GeDefense may use Android-provided app-usage state as one local signal for security correlation. The application remains usable without granting usage access.

## ACCESS_COARSE_LOCATION

**Purpose:** optional coarse network/environment security context where Android exposes it.

GeDefense requests only coarse location, not fine or background location. The signal is optional, is not required for VPN protection and is not used for continuous location tracking.

## Foreground service / special use

The foreground VPN service exists to keep user-enabled device network protection visible and operating under Android's service lifecycle rules. GeDefense shows a persistent protection notification while the relevant foreground protection service is active.


## CAMERA

**Purpose:** user-initiated local WireGuard QR profile import.

Camera access is requested only when the user explicitly starts the WireGuard QR scanner. QR decoding runs locally inside the GeDefense application using pinned vendored scanner code. Captured frames, decoded QR payloads and WireGuard keys are not uploaded to VisionGaiaTechnology, Google Play Services or an external scanner application. The scanner activity uses `FLAG_SECURE` and the decoded text is immediately passed to the same bounded WireGuard parser used by paste/file import.
