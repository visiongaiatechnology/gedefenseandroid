# GeDefense Secure Telemetry Vault

**Release:** `0.27.8-beta.6`  
**Status:** Public-beta cryptographic storage contract

## Purpose

GeDefense processes security telemetry that can itself be sensitive: installed-app baselines, behavioral observations, incident state, scanner fingerprints, local network discovery and Evidence. Android application sandboxing and file-based encryption remain the first storage boundary; the Secure Telemetry Vault adds an independent application cryptographic boundary for durable sensitive state.

## Cryptographic composition

The persistent vault uses only platform/JCA primitives:

- **AES-256-GCM** for confidentiality and authenticated encryption;
- a fresh **96-bit CSPRNG nonce** for every AEAD write;
- a **128-bit GCM authentication tag**;
- **HMAC-SHA-256** as an independent outer snapshot/ledger integrity layer where applicable;
- non-exportable key custody through **Android Keystore**;
- **StrongBox preferred** for low-frequency authoritative domains when the requested key profile is supported; high-frequency Evidence/XDR use a wrapped-domain-key profile so the Android Keystore/TEE is touched only to unwrap the process-local domain root, not for every telemetry record;
- **ECDSA P-256 / SHA-256** for detached signing of durable security/recovery artifacts;
- optional **ML-DSA-87** as a second artifact signature only on Android 17+ devices that expose KeyMint 5 hardware support.

ML-DSA is a signature primitive. It is intentionally not used for data encryption. ML-KEM is intentionally absent because the local at-rest vault has no remote peer/key-establishment problem to solve.

## Domain separation

Active key custody is domain-separated across XDR events, behavioral/package baselines, malware analysis, app approvals, firewall policy, network discovery, Port Sentinel, TITAN policy, scanner state, WireGuard profile, Evidence and the VPN-disclosure receipt. The historical `VPN_DISCLOSURE_LEGACY` domain exists only to read the short-lived 0.27.0 encrypted receipt format and is never an active write target.

The VPN-disclosure decision is deliberately **not confidentiality-encrypted** because it contains no telemetry; it is authorization metadata. Its active outer HMAC is nevertheless derived from the same installation-stable per-domain key hierarchy as the sensitive snapshot stores. The historical direct AndroidKeyStore HMAC remains read-only migration material. If that historical OEM key cannot be used after an update, GeDefense fails closed and requires one fresh explicit acceptance; plaintext authorization state is never recovered without authentication.

Each active domain has independent versioned cryptographic material. The active public-release architecture uses one installation-stable, non-exportable Android-Keystore HMAC-SHA-256 root (`vgt.gedefense.mobile.vault.root-prf.v1`). One bounded hardware PRF operation derives a process-local wrapping KEK. Each vault domain/key generation owns an independent random 256-bit root persisted only as an AES-256-GCM-wrapped keyset in `noBackupFilesDir`; HKDF-SHA-256 then derives separate AES-256-GCM and HMAC-SHA-256 subkeys. Compromise of one domain keyset does not authenticate or decrypt another domain.

The root alias and wrapping derivation deliberately contain no APK hash, source-manifest hash, signing digest, package version or runtime-integrity measurement. Those signals remain inputs to Integrity Guardian only. A normal same-app Android update therefore changes integrity measurements without changing encryption custody.

Historical direct-AES, wrapped-DEK and hardware-HMAC-PRF generations remain read-only continuity material. Existing snapshots first attempt normal historical authentication. If a historical outer AndroidKeyStore HMAC has become unusable on an OEM after update, recovery is permitted **only** for snapshots that already contain a valid inner AES-GCM vault envelope: outer framing is parsed as untrusted bounded bytes, the inner AEAD must authenticate/decrypt successfully, and the exact recovered state is atomically rewritten under the active update-stable outer HMAC before plaintext is returned. Plaintext legacy snapshots never receive this bypass. Evidence and XDR retain their explicit generation migrations, and old key generations are never deleted merely because one object migrated.

## Envelope binding

The binary `VGTVLT01` envelope is versioned. AES-GCM Additional Authenticated Data binds ciphertext to:

- format version;
- vault-domain identifier;
- logical store/record binding;
- schema version;
- encryption-key generation;
- plaintext/ciphertext lengths.

A valid encrypted payload copied to another domain, store, schema or key generation does not authenticate.

## Migration

Earlier GeDefense beta snapshots were HMAC-authenticated but could contain plaintext payloads inside the private app directory. On first successful read after upgrade:

1. the legacy outer HMAC is verified;
2. the bounded plaintext is encrypted into the correct vault domain;
3. the encrypted snapshot is atomically persisted;
4. temporary ciphertext buffers are wiped from managed byte arrays;
5. only after durable migration succeeds is plaintext released to the caller.

Migration failure is fail-closed and produces an invalid store state rather than silently continuing with plaintext.

For already-encrypted snapshots, an outer-HMAC provider failure may enter the bounded inner-AEAD recovery path described above. A valid AES-GCM tag is mandatory and the snapshot must be durably re-HMACed with the active key before plaintext is released. This path cannot authenticate legacy plaintext.

The Evidence ledger similarly upgrades healthy legacy records to encrypted v3 records before normal use.

## Key rotation

Every vault domain has an explicit active cryptographic generation independent of the application release number. Envelopes store their key generation. Readers open older supported generations and persist the active generation before returning plaintext. App upgrades do not themselves rotate keys.

Migration is transactional: existing ciphertext remains authoritative until the new envelope/keyset is durably written and authenticated. A failed migration leaves the historical generation available for retry. Old keys are not automatically deleted merely because a single record migrated; safe key retirement requires evidence that no durable object still references that generation.

## Evidence and hybrid signatures

Evidence v3 encrypts each canonical event payload independently and retains the separate HMAC chain across records. Recovery artifacts receive an Android-Keystore ECDSA signature. On platforms that natively support hardware ML-DSA-87, GeDefense adds ML-DSA-87 as a second signature rather than replacing the classical signature.

The detached signature JSON contains the public key and public-key fingerprint so a verifier can preserve/pin that identity when artifacts are collected over time. A signature whose public key is replaced together with the artifact is not by itself an external identity oracle; consumers requiring provenance must preserve the expected fingerprint or establish trust through an independent channel.

## Backup and Direct Boot

Sensitive vault state lives in credential-encrypted application storage / `noBackupFilesDir`. Android cloud backup and device-to-device extraction are disabled and release-audited. GeDefense does not duplicate behavioral/Evidence plaintext into Device Protected Storage for Direct Boot convenience.

## Threat-model boundary

The vault materially raises the cost of offline file theft, backup leakage, filesystem snapshots and casual privileged file reads. It also compartmentalizes durable state by domain.

It does **not** claim to make live plaintext unknowable to a fully compromised process/device. If an attacker controls GeDefense while Android has legitimately made the relevant user storage available, that attacker may be able to request legitimate Keystore operations or observe plaintext after decryption. No application-layer cryptography can honestly erase that execution-boundary fact.

Likewise, authenticated encryption and HMAC detect modification but do not provide a universal hardware monotonic counter. Replaying an entire previously valid device/application state is therefore outside the claimed anti-rollback boundary unless Android supplies an independently trusted monotonic state source.

## Verification

Release gates include:

- pure-JVM AEAD round-trip and adversarial AAD/tamper tests;
- store-to-domain mapping audit;
- prohibition of duplicate persistent AEAD implementations;
- Android-Keystore key-profile audit;
- encrypted Evidence migration/tamper tests;
- backup-exclusion audit;
- hybrid-signature capability audit;
- release lint and full GeDefense security gate.

Run:

```bash
python3 tools/secure-vault-audit.py
bash tools/release-readiness.sh
```
