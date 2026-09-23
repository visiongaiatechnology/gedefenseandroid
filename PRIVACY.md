# GeDefense Mobile Privacy Policy

**Product:** VGT GeDefense Mobile  
**Publisher:** VisionGaiaTechnology (VGT)  
**Applies to:** `0.27.4-beta.1` and later releases that reference this policy

## Privacy model

GeDefense Mobile is designed as a local-first Android security product. It does not require a VGT account and does not include advertising, analytics, profiling or third-party crash-reporting SDKs.

Security findings, policy state, package inventory, signer/permission observations, traffic analytics, scanner results, XDR events and evidence state are processed and stored on the device unless the user explicitly exports a bounded diagnostic bundle through Android's document picker.

## Local VPN processing

GeDefense uses Android `VpnService` to create an on-device security tunnel. The tunnel is used for firewall, threat-intelligence and XDR enforcement. It is not a remote consumer VPN service and does not forward traffic to a VisionGaiaTechnology VPN server.

For local enforcement GeDefense may process destination IP addresses, DNS domain names when visible, protocol/port metadata, flow counters and Android app/UID attribution. GeDefense does not perform TLS or QUIC interception and does not decrypt application payloads.

Observed destination IPs, DNS queries, package inventory and traffic history are not uploaded to VisionGaiaTechnology.

## Telemetry Shield

Telemetry Shield is enforced only in Full Flow, where GaiaNet owns the complete app traffic path. Selective mode does not claim system-wide telemetry filtering. Telemetry Shield uses a versioned Privacy Intelligence snapshot packaged inside the signed application. It does not query a VGT or third-party tracker API at runtime. Rules contain provenance and license metadata, while the actual `ALLOW` / `OBSERVE` / `BLOCK` authority is derived locally from the selected privacy profile, confidence and estimated breakage risk. Essential connectivity, push and update services take precedence over blocking rules.

When classic DNS is visible inside Full Flow, GaiaNet may classify the requested domain and locally answer a blocked query with NXDOMAIN. Matching metadata can be written to the local Evidence/XDR stores. GeDefense does not decrypt DNS-over-TLS/HTTPS, TLS or QUIC traffic in order to force visibility.

## Installed applications and permissions

GeDefense may inspect installed-application metadata, version/signing information, declared and granted permissions and security-relevant package changes for local antivirus/XDR analysis. Initial background package reconciliation is not performed on a fresh installation until the setup flow has been explicitly completed.

GeDefense does not upload the installed-app inventory to VisionGaiaTechnology.

## File scanning

When the user grants Android all-files access, GeDefense may inspect shared-storage files for local malware analysis. The scanner is read-only. It does not execute, upload, rename, delete or quarantine scanned files. Android application-private sandboxes remain outside this access.

## Usage access and optional location

Usage access is used locally to improve app/traffic attribution. Optional coarse location is used only where Android network/passive last-known information is available and is not implemented as continuous background location tracking.

## Device administration / TITAN

Device Administrator and Device Owner capabilities are used only when the user or managed-device operator explicitly provisions TITAN capabilities. Destructive actions are not automatic. Managed uninstall, wipe-related settings and managed trust-anchor installation require separate explicit operator actions in the product.

## Threat-intelligence, geographic and ASN datasets

GeDefense downloads public security, geolocation and ASN datasets from configured upstream providers. These HTTPS requests fetch whole public datasets and do not append observed destination IPs, DNS history, package names or scanner findings. ASN lookup itself is offline: the IPtoASN-derived PDDL snapshot is checksum-verified, compiled and queried locally, and ASN matches remain `evidence_only` with no XDR/enforcement authority. As with any Internet connection, the upstream server and intervening network may observe ordinary connection metadata such as the requesting public IP address.

The current endpoint inventory is documented in [`NETWORK-EGRESS.md`](NETWORK-EGRESS.md).

## Diagnostics

Diagnostics export is explicit and uses Android's Storage Access Framework. The `aggregate-only-v1` support bundle excludes package names/app labels, IP addresses, domains, file paths, signer/APK/install hashes, packet contents, Evidence payloads and XDR incident-detail text. It contains only bounded aggregate states, counters, durations and sanitized reason codes.

GeDefense does not automatically upload a diagnostic bundle.

## Secure local storage

Sensitive durable GeDefense state is protected by the **Secure Telemetry Vault**. XDR event state, behavioral/package baselines, malware-analysis state, app approvals, firewall policy, LAN discovery, Port Sentinel, TITAN policy, scanner caches and Evidence use separate AES-256-GCM cryptographic domains with independent HMAC-SHA-256 authentication where the store format uses an authenticated outer snapshot. Keys are generated and held by Android Keystore; StrongBox is preferred when the device supports the requested key profile.

The VPN disclosure decision contains no telemetry and is therefore not confidentiality-encrypted. It is stored as a dedicated HMAC-authenticated receipt in `noBackupFilesDir`; tampering fails closed while VPN availability does not depend on an unnecessary AEAD key operation.

Existing authenticated plaintext beta snapshots are migrated locally to encrypted form before their plaintext is returned to the application. The Evidence ledger uses encrypted per-record payloads. Vault material is excluded from Android backup/device-transfer extraction. No vault key is uploaded to VisionGaiaTechnology.

ML-DSA is used only as an optional additional hardware-backed **signature** for durable/exportable security artifacts on Android versions that natively support it. It is not used to encrypt local data.

## Retention and deletion

Local security state remains on the device until it is replaced by bounded newer state, reset through a product control where available, or removed with the app. GeDefense does not maintain a VGT cloud account containing a copy of local traffic/scanner history.

Revoking the product VPN disclosure stops VPN protection and removes the authenticated local disclosure decision. Uninstalling GeDefense removes ordinary application-local state according to Android platform behavior; application backup is disabled.

## External links

The optional Support VGT screen only opens its fixed external destination after an explicit user action. Once the user leaves GeDefense, the destination service's own privacy terms apply.

## Security and privacy reports

Do not place sensitive device information, packet payloads, private keys or personal files in a public issue. Use GitHub private vulnerability reporting when it is enabled for the repository. Non-sensitive privacy questions may be raised through the repository's normal support channel.

## Policy publication requirement

For Google Play distribution, this exact policy must also be published at a stable, publicly accessible HTTPS URL with no login or geofencing and the URL must be entered in Play Console. The official developer-account contact/legal details should be used there without inventing substitute identities in the source tree.


### Encrypted DNS visibility

Telemetry Shield does not decrypt TLS. In Full Flow, GeDefense can observe or block captured traffic using the standard encrypted-DNS destination port 853 and can classify documented resolver bootstrap domains from the signed local Privacy Intelligence snapshot. Strict blocks captured TCP/UDP port 853 and known resolver bootstrap domains. It does not generically block HTTPS/443. Custom DoH over shared HTTPS infrastructure, hard-coded resolver IPs, ECH and unlisted resolver endpoints can therefore remain outside domain visibility. No resolver query or verdict is sent to VGT or a third-party API.
