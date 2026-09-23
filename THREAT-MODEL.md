# Threat Model — GeDefense Mobile 0.7.1-beta.1

## Assets

- device network availability
- Full Flow/Selective policy integrity
- threat-intelligence cache integrity
- Geo-country generation integrity
- local Evidence integrity
- Android-Keystore keys
- application/package identity
- user network privacy

## Adversaries considered

- hostile network destinations and botnet/C2 infrastructure
- malformed/hostile TUN packets
- packet/flow/fragment resource exhaustion
- malformed or substituted threat/geo downloads
- captive portals and HTML/error substitution
- stale intelligence
- local app-private-file tampering after broader compromise
- crashes/interruption during generation updates
- forged/malformed native telemetry frames
- accidental operator recovery actions

## Explicit non-goals

- defeating root/kernel compromise
- decrypting TLS/QUIC application content
- behavioral sandbox execution of foreign APK code
- guaranteed classification of all malware
- automatic malware deletion/process killing
- forwarding every exotic L4 protocol
- remote SOC/cloud collection

## Failure behavior

### Threat feed unavailable/malformed

The previous authenticated generation remains. Once older than its configured maximum active age it leaves the runtime index. A new malformed, suspiciously small, oversized or interrupted generation is never partially published.

### Geo-country update failure

The active authenticated generation remains in memory/on disk. Active-pointer publication is transactional and rolls back on post-publish verification failure. Startup may recover the newest valid HMAC-authenticated generation.

### Evidence failure

Protection is suspended rather than continuing unaudited. Recovery archives the damaged ledger and authenticates the recovery manifest before a fresh chain can be accepted.

### Selective route-policy mismatch

For public destinations, a packet reaching a threat-only TUN route that does not evaluate to `BLOCK` is `POLICY_INVARIANT_FAILED`. Non-public kernel/interface control traffic is filtered before this invariant.

### Full Flow telemetry loss

Loss of a security-critical native event marks the native telemetry path unhealthy and Full Flow terminates. Best-effort periodic byte snapshots may be dropped without changing enforcement authority.

### Flow exhaustion

New flows are refused when global/per-protocol/half-open bounds are exhausted. Existing bounded flows remain. Fragment overlap or reassembly-capacity violations are dropped.

### TCP entropy failure

No predictable fallback ISN is used. Flow creation fails closed.

### Unsupported traffic

Current GaiaNet forwards TCP and UDP. Unsupported L4 protocols are ignored, not classified as threats. This is a beta compatibility limitation, not an enforcement claim.

## Privacy boundary

No observed destination IP, package inventory, APK hash, DNS query, traffic summary or atlas origin is uploaded to VGT. Country mapping and map rendering are local. The optional atlas location path requests coarse permission only, reads last-known NETWORK/PASSIVE fixes, quantizes them to 0.25° and starts no active/background location subscription. Threat/Geo upstream requests are only dataset retrieval and do not contain observed destination IPs.

## Local telemetry theft / vault compromise

**Threat:** an attacker obtains app-private files, a filesystem image, an unintended backup, or one valid ciphertext and attempts to read, transplant, modify or replay GeDefense telemetry.

**Controls:** sensitive durable stores use domain-separated AES-256-GCM with non-exportable Android-Keystore keys, independent HMAC authentication, no-backup storage, schema/store/domain-bound AAD and bounded parsers. Copying a ciphertext between domains or stores fails AEAD authentication. Healthy legacy beta plaintext is migrated before normal use. Evidence encrypts records while retaining a separate chained HMAC.

**Compartmentalization:** XDR, behavior, package baseline, malware analysis, approvals, firewall, discovery, Port Sentinel, TITAN, scanner storage/apps and Evidence use distinct AES aliases. Compromise/oracle access to one domain key is not treated as authority over another. The VPN-disclosure decision is authorization metadata rather than telemetry and uses a separate HMAC-authenticated receipt so an unnecessary AEAD dependency cannot block protection startup.

**Residual boundary:** a fully compromised live Android process may observe plaintext after legitimate decryption or request legitimate Keystore operations. The vault therefore claims resistance to offline/file-level disclosure and cross-domain tampering, not magical secrecy from code already executing with GeDefense's process authority. Replaying an entire old but internally valid application/device state is not universally preventable without an independent trusted monotonic counter.

**Post-quantum use:** ML-DSA-87 is optional additional artifact-signing protection on Android 17+/KeyMint 5 hardware. It is not an encryption mechanism. AES-256-GCM remains the confidentiality primitive.
