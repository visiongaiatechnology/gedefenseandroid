# Google Play Data Safety Draft

**Release:** `0.27.4-beta.1`

This is an engineering mapping, not a substitute for the final Play Console questionnaire. The final answers must be reviewed against the exact shipped binary, network-egress inventory and any website/service added after this release candidate.

## Local processing

The following categories are designed for on-device processing and are not intentionally uploaded to VisionGaiaTechnology by the application:

Sensitive durable state in these categories is protected at rest by the local Secure Telemetry Vault (domain-separated AES-256-GCM plus independent authentication). The vault keys remain in Android Keystore and are not uploaded.

- installed package inventory, package metadata, permissions and signer evidence;
- local XDR/EDR events and evidence ledger;
- observed flow metadata and local firewall decisions;
- scanner findings, file paths and file hashes;
- TITAN/device-hardening posture;
- optional usage-access context;
- optional coarse-location context;
- diagnostic details that remain on device unless the user explicitly exports a privacy-bounded diagnostic bundle.

## External network activity

GeDefense downloads threat-intelligence/security datasets from the endpoints documented in `NETWORK-EGRESS.md`. Those remote operators necessarily observe ordinary transport-layer connection metadata such as the public source IP used for the HTTPS request. GeDefense does not append the device's observed traffic history, package inventory, scanner findings or XDR incident data to those dataset requests.

## Diagnostics

Diagnostics are not automatically uploaded. User-initiated diagnostic export uses the `aggregate-only-v1` profile and intentionally excludes package names/app labels, IP addresses, domains, file paths, signer/APK/install hashes, packet/evidence payloads and detailed XDR incident text.

## Advertising and analytics

The release contains no advertising SDK and no third-party analytics/crash-reporting SDK.

## Final submission gate

Before Play submission:

1. run `python3 tools/network-egress-audit.py`;
2. compare the final manifest and dependency tree with this document;
3. review every Play Data Safety question using the exact current definitions in Play Console;
4. publish the public privacy policy at a stable HTTPS URL;
5. do not answer a field based solely on an earlier beta's behavior.
