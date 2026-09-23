#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "app/src/main/java/de/visiongaia/gedefense/mobile"

vault = (JAVA / "SecureTelemetryVault.kt").read_text()
secrets = (JAVA / "AndroidSecrets.kt").read_text()
evidence = (JAVA / "AndroidEvidence.kt").read_text()
CORE = ROOT / "core/src/main/kotlin/de/visiongaia/gedefense/mobile/core"
ledger = (CORE / "EvidenceLedger.kt").read_text()
envelope = (CORE / "AeadVaultEnvelope.kt").read_text()
manifest = (ROOT / "app/src/main/AndroidManifest.xml").read_text()
backup = (ROOT / "app/src/main/res/xml/data_extraction_rules.xml").read_text()
signer = (JAVA / "HybridArtifactSigner.kt").read_text()

required_android_vault = [
    'AndroidSecrets.aes256Gcm',
    'AeadVaultEnvelope.seal',
    'AeadVaultEnvelope.open',
    'storedKeyVersion < domain.activeKeyVersion',
    'legacy vault migration failed',
    'encrypted.fill(0)',
    'replacement.fill(0)',
]
for token in required_android_vault:
    if token not in vault:
        raise SystemExit(f'SECURE_VAULT_FAIL android_vault={token}')

required_envelope = [
    'Cipher.getInstance("AES/GCM/NoPadding")',
    'GCMParameterSpec(GCM_TAG_BITS, nonce)',
    'private const val GCM_TAG_BITS = 128',
    'ByteArray(NONCE_BYTES).also(random::nextBytes)',
    'cipher.updateAAD(aad)',
    'MessageDigest.isEqual(readMagic, magic)',
    'maxKeyVersion',
]
for token in required_envelope:
    if token not in envelope:
        raise SystemExit(f'SECURE_VAULT_FAIL envelope={token}')

for forbidden in ('AES/ECB', 'AES/CBC', 'DES/', 'DESede', 'PBEWithMD5'):
    if forbidden in vault or forbidden in envelope or forbidden in secrets:
        raise SystemExit(f'SECURE_VAULT_FAIL forbidden_crypto={forbidden}')
if re.search(r'(?<!Secure)Random\(\)', vault + envelope + secrets):
    raise SystemExit('SECURE_VAULT_FAIL forbidden_crypto=java.util.Random')

for token in (
    '.setKeySize(256)',
    'KeyProperties.BLOCK_MODE_GCM',
    '.setRandomizedEncryptionRequired(true)',
    '.setIsStrongBoxBacked(true)',
    'StrongBoxUnavailableException',
    'KeySecurityLevel.STRONGBOX',
):
    if token not in secrets:
        raise SystemExit(f'SECURE_VAULT_FAIL keystore_invariant={token}')

sensitive = {
    'XdrEventStore.kt': 'VaultDomain.XDR_EVENTS',
    'BehaviorBaselineStore.kt': 'VaultDomain.BEHAVIOR_BASELINE',
    'PackageBaselineStore.kt': 'VaultDomain.PACKAGE_BASELINE',
    'MalwareAnalysisStore.kt': 'VaultDomain.MALWARE_ANALYSIS',
    'AppApprovalStore.kt': 'VaultDomain.APP_APPROVALS',
    'FirewallPolicyStore.kt': 'VaultDomain.FIREWALL_POLICY',
    'NetworkDiscoveryStore.kt': 'VaultDomain.NETWORK_DISCOVERY',
    'PortSentinelStore.kt': 'VaultDomain.PORT_SENTINEL',
    'TitanPolicyStore.kt': 'VaultDomain.TITAN_POLICY',
    'ScannerStateCache.kt': 'VaultDomain.SCANNER_STORAGE',
}
for name, domain in sensitive.items():
    text = (JAVA / name).read_text()
    if 'SecureSnapshotStore(' not in text or domain not in text:
        raise SystemExit(f'SECURE_VAULT_FAIL store_not_encrypted={name}')
    if 'core.AuthenticatedSnapshotStore' in text:
        raise SystemExit(f'SECURE_VAULT_FAIL raw_authenticated_store={name}')
    # XDR owns its explicit multi-generation HMAC rotation path. Every other active encrypted
    # snapshot must use the installation-stable domain HMAC and retain the historical direct
    # AndroidKeyStore provider only as migration material.
    if name != 'XdrEventStore.kt':
        active = f'SecureTelemetryVault.hotPathHmacKey({domain})'
        if active not in text:
            raise SystemExit(f'SECURE_VAULT_FAIL unstable_outer_hmac={name}')
        if 'legacyHmacKeyProvider' not in text and name != 'PackageBaselineStore.kt':
            raise SystemExit(f'SECURE_VAULT_FAIL missing_outer_hmac_migration={name}')

# VPN disclosure is authorization metadata, not sensitive telemetry. It remains plaintext but the
# active authentication key is now update-stable. The historical direct AndroidKeyStore HMAC is
# read-only migration material; if that OEM key is unusable, explicit re-acceptance is required.
disclosure = (JAVA / 'VpnDisclosureStore.kt').read_text()
for token in (
    'AuthenticatedSnapshotStore(',
    'VaultDomain.VPN_DISCLOSURE',
    'VPN_DISCLOSURE_LEGACY',
    'SecureTelemetryVault.hotPathHmacKey(VaultDomain.VPN_DISCLOSURE)',
    'LEGACY_HMAC_ALIAS',
    'vpn_disclosure_reaccept_required_after_key_migration',
    'legacy_vault_authentication_failed',
):
    if token not in disclosure:
        raise SystemExit(f'SECURE_VAULT_FAIL disclosure_receipt={token}')
if 'SecureSnapshotStore(' in disclosure:
    raise SystemExit('SECURE_VAULT_FAIL disclosure_receipt_coupled_to_sensitive_vault')

snapshot_store = (CORE / 'AuthenticatedSnapshotStore.kt').read_text()
for token in (
    'readPayloadWithoutAuthenticationForAeadRecovery',
    'Returned bytes are UNTRUSTED',
    'payloadLength !in 0..maxPayloadBytes',
    'length != expectedLength',
):
    if token not in snapshot_store:
        raise SystemExit(f'SECURE_VAULT_FAIL bounded_inner_aead_recovery={token}')
for token in (
    'legacyHmacKeyProvider',
    'OUTER_AEAD_RECOVERABLE_FAILURES',
    'readPayloadWithoutAuthenticationForAeadRecovery()',
    'SecureTelemetryVault.isEncryptedEnvelope(candidate)',
    'rewriteOuterAuthentication = true',
    'legacy plaintext requires authenticated outer snapshot',
):
    if token not in vault:
        raise SystemExit(f'SECURE_VAULT_FAIL outer_hmac_recovery={token}')
raw_recovery_pos = vault.find('readPayloadWithoutAuthenticationForAeadRecovery()')
legacy_hmac_pos = vault.find('legacyAuthenticatedStore?.let')
if raw_recovery_pos < 0 or legacy_hmac_pos < 0 or raw_recovery_pos > legacy_hmac_pos:
    raise SystemExit('SECURE_VAULT_FAIL encrypted_recovery_must_precede_legacy_oem_hmac')

scanner = (JAVA / 'ScannerStateCache.kt').read_text()
if 'VaultDomain.SCANNER_APPS' not in scanner:
    raise SystemExit('SECURE_VAULT_FAIL scanner_app_domain_missing')

for token in (
    'protector = object : EvidencePayloadProtector',
    'VaultDomain.EVIDENCE',
    'context.noBackupFilesDir',
):
    if token not in evidence:
        raise SystemExit(f'SECURE_VAULT_FAIL evidence_android={token}')
for token in (
    'RECORD_VERSION_V3 = "3"',
    'migrateLegacyLedger()',
    'mixed ledger formats',
    'activeProtector.unprotect',
    'evidence encryption migration failed',
):
    if token not in ledger:
        raise SystemExit(f'SECURE_VAULT_FAIL evidence_core={token}')

if 'android:allowBackup="false"' not in manifest or 'android:fullBackupContent="false"' not in manifest:
    raise SystemExit('SECURE_VAULT_FAIL backup_manifest')
for domain in ('root', 'file', 'database', 'sharedpref', 'external', 'device_root', 'device_file', 'device_database', 'device_sharedpref'):
    if f'<exclude domain="{domain}" path="." />' not in backup:
        raise SystemExit(f'SECURE_VAULT_FAIL backup_exclusion={domain}')

for token in (
    'ML_DSA_87 = "ML-DSA-87"',
    'KEYMINT_5_FEATURE_VERSION = 500',
    'PackageManager.FEATURE_HARDWARE_KEYSTORE',
    'SHA256withECDSA',
    'Build.VERSION.SDK_INT < ANDROID_17_API',
):
    if token not in signer:
        raise SystemExit(f'SECURE_VAULT_FAIL hybrid_signature={token}')

# Persistent telemetry AEAD has exactly one codec in the pure JVM core. The Android-side
# Active vault generations deliberately avoid AndroidKeyStore AES cipher operations. A non-exportable
# AndroidKeyStore HMAC root performs one hardware PRF operation per domain/process; HKDF then
# expands independent in-memory AES/HMAC subkeys. Historical AES/wrapped-DEK code remains only
# for backward-compatible reads/migration.
for path in JAVA.glob('*.kt'):
    if path.name in {'WrappedHotPathKeys.kt', 'PersistentVaultKeys.kt'}:
        continue
    if 'AES/GCM/NoPadding' in path.read_text() and path.name not in {'HardwareDerivedVaultKeys.kt'}:
        raise SystemExit(f'SECURE_VAULT_FAIL android_aead_implementation={path.name}')
for path in CORE.glob('*.kt'):
    if path.name == 'AeadVaultEnvelope.kt':
        continue
    if 'AES/GCM/NoPadding' in path.read_text():
        raise SystemExit(f'SECURE_VAULT_FAIL duplicate_aead_implementation={path.name}')

derived = (JAVA / 'HardwareDerivedVaultKeys.kt').read_text()
for token in (
    'VisionGaiaTechnology/VaultRootMaterial/v1',
    'VisionGaiaTechnology/VaultDomainKdf/v1',
    'AndroidSecrets.hmacSha256(alias, preferStrongBox = false)',
    'Mac.getInstance("HmacSHA256")',
    'SecretKeySpec(aesBytes, "AES")',
    'SecretKeySpec(hmacBytes, "HmacSHA256")',
    'rootSecurityLevel',
):
    if token not in derived:
        raise SystemExit(f'SECURE_VAULT_FAIL hardware_prf_profile={token}')

persistent = (JAVA / 'PersistentVaultKeys.kt').read_text()
for token in (
    'ROOT_PRF_ALIAS = "vgt.gedefense.mobile.vault.root-prf.v1"',
    'AndroidSecrets.hmacSha256(ROOT_PRF_ALIAS, preferStrongBox = false)',
    'VisionGaiaTechnology/PersistentVaultDomainKdf/v1',
    'VisionGaiaTechnology/PersistentVaultRootWrapMaterial/v1',
    'VisionGaiaTechnology/PersistentVaultRootWrapKey/v1',
    'VisionGaiaTechnology/PersistentVaultWrap/v1/',
    'secure-vault-keysets',
    'SecureFiles.atomicReplace(temp, file)',
    'MessageDigest.isEqual(root, verified)',
    'SecretKeySpec(aesBytes, "AES")',
    'SecretKeySpec(hmacBytes, "HmacSHA256")',
):
    if token not in persistent:
        raise SystemExit(f'SECURE_VAULT_FAIL persistent_key_lifecycle={token}')
persistent_code = re.sub(r'/\*.*?\*/', '', persistent, flags=re.S)
persistent_code = re.sub(r'//.*', '', persistent_code)
if 'AndroidSecrets.aes256Gcm(ROOT_PRF_ALIAS' in persistent or 'ROOT_KEK_ALIAS' in persistent:
    raise SystemExit('SECURE_VAULT_FAIL persistent_root_must_use_hmac_prf')

for forbidden in (
    'BuildConfig', 'versionCode', 'versionName', 'installSha256', 'signerSha256',
    'SOURCE-MANIFEST', 'source-manifest', 'PackageManager', 'packageManager',
):
    if forbidden in persistent_code:
        raise SystemExit(f'SECURE_VAULT_FAIL update_coupled_key_material={forbidden}')

for token in (
    'XDR_EVENTS("xdr-events", activeKeyVersion = 5',
    'EVIDENCE("evidence", activeKeyVersion = 5',
    'VPN_DISCLOSURE("vpn-disclosure-receipt", activeKeyVersion = 1, persistentKeyVersion = 1)',
    'BEHAVIOR_BASELINE("behavior-baseline", activeKeyVersion = 3, derivedKeyVersion = 2, persistentKeyVersion = 3)',
    'WIREGUARD_PROFILE("wireguard-profile", activeKeyVersion = 2, derivedKeyVersion = 1, persistentKeyVersion = 2)',
    'version >= domain.persistentKeyVersion -> PersistentVaultKeys.keys(domain, version, create = true).aes',
    'version >= domain.persistentKeyVersion -> PersistentVaultKeys.keys(domain, version, create = false).aes',
    'fun historicalHotPathHmacKey(domain: VaultDomain, version: Int)',
    'fun hotPathHmacKey(domain: VaultDomain)',
    'fun preflightHotPath(domain: VaultDomain)',
):
    if token not in vault:
        raise SystemExit(f'SECURE_VAULT_FAIL active_persistent_profile={token}')
if 'SecureTelemetryVault.hotPathHmacKey(VaultDomain.EVIDENCE)' not in evidence:
    raise SystemExit('SECURE_VAULT_FAIL evidence_hot_path_hmac_profile')
for alias in ('vgt.gedefense.mobile.evidence.hmac.v2', 'vgt.gedefense.mobile.evidence.hmac.v1'):
    if alias not in evidence:
        raise SystemExit(f'SECURE_VAULT_FAIL evidence_legacy_hmac={alias}')
xdr_store = (JAVA / 'XdrEventStore.kt').read_text()
if 'SecureTelemetryVault.hotPathHmacKey(VaultDomain.XDR_EVENTS)' not in xdr_store:
    raise SystemExit('SECURE_VAULT_FAIL xdr_hot_path_hmac_profile')
for alias in ('vgt.gedefense.mobile.xdr-events.hmac.v3', 'vgt.gedefense.mobile.xdr-events.hmac.v2'):
    if alias not in xdr_store:
        raise SystemExit(f'SECURE_VAULT_FAIL xdr_legacy_hmac={alias}')
if 'rotateAuthenticationKey(activeKey)' not in evidence:
    raise SystemExit('SECURE_VAULT_FAIL evidence_hmac_rotation_missing')

# The first persistent generation must migrate the current v4 hot-path HMAC generations before
# falling back to historical direct AndroidKeyStore aliases. Otherwise a normal update would make
# an intact Evidence/XDR store appear unauthenticated.
for token in (
    'for (version in (VaultDomain.EVIDENCE.activeKeyVersion - 1) downTo VaultDomain.EVIDENCE.wrappedKeyVersion)',
    'SecureTelemetryVault.historicalHotPathHmacKey(VaultDomain.EVIDENCE, version)',
):
    if token not in evidence:
        raise SystemExit(f'SECURE_VAULT_FAIL evidence_persistent_hmac_migration={token}')
for token in (
    'for (version in (VaultDomain.XDR_EVENTS.activeKeyVersion - 1) downTo VaultDomain.XDR_EVENTS.wrappedKeyVersion)',
    'SecureTelemetryVault.historicalHotPathHmacKey(VaultDomain.XDR_EVENTS, version)',
):
    if token not in xdr_store:
        raise SystemExit(f'SECURE_VAULT_FAIL xdr_persistent_hmac_migration={token}')

# Keystore and wrapped-key availability is not process availability. Evidence must preflight before
# constructing the ledger, and both Evidence/XDR must retain explicit fail-closed degraded stores
# instead of throwing through Application.onCreate().
for token in (
    'data class BootstrapResult(',
    'UnavailableEvidenceStore(code)',
    'VaultStartupFailure.report("evidence", code',
):
    if token not in evidence:
        raise SystemExit(f'SECURE_VAULT_FAIL evidence_startup_boundary={token}')
preflight_index = evidence.find('SecureTelemetryVault.preflightHotPath(VaultDomain.EVIDENCE)')
create_index = evidence.find('BootstrapResult(create(context), null)')
if preflight_index < 0 or create_index < 0 or preflight_index >= create_index:
    raise SystemExit('SECURE_VAULT_FAIL evidence_preflight_order')
for token in (
    'interface EvidenceStore',
    'class UnavailableEvidenceStore',
    'class EvidenceStoreUnavailableException',
    'override fun append(event: EvidenceEvent): Nothing',
    'LedgerHealth(ok = false, records = 0L, reason = reason)',
):
    if token not in ledger:
        raise SystemExit(f'SECURE_VAULT_FAIL unavailable_evidence_store={token}')
runtime = (JAVA / 'AppRuntime.kt').read_text()
for token in (
    'MAX_RECORDS = 128',
    'ArrayDeque<VaultRecoveryRecord>(MAX_RECORDS)',
    'if (records.size >= MAX_RECORDS)',
    'droppedRecords',
):
    if token not in vault:
        raise SystemExit(f'SECURE_VAULT_FAIL bounded_recovery_journal={token}')
if 'ConcurrentLinkedQueue' in vault:
    raise SystemExit('SECURE_VAULT_FAIL unbounded_recovery_journal')
for token in (
    'if (!evidenceHealth.ok) return',
    'journal_overflow_dropped=${recoveryBatch.droppedRecords}',
):
    if token not in runtime:
        raise SystemExit(f'SECURE_VAULT_FAIL recovery_journal_reporting={token}')

for token in (
    '@Volatile private var authenticatedStore: SecureSnapshotStore? = null',
    '@Volatile private var initializationAttempted = false',
    'fun initialize() = synchronized(lock)',
    'VaultStartupFailure.report("xdr", code, error)',
    'integrityOk = false',
    'val store = authenticatedStore ?: return false',
):
    if token not in xdr_store:
        raise SystemExit(f'SECURE_VAULT_FAIL xdr_startup_boundary={token}')

# Ten snapshot-store domains + scanner-app cache + Evidence = twelve sensitive encryption domains.
# VPN disclosure is deliberately excluded because it is an authorization receipt, not telemetry.
active_domain_count = len(sensitive) + 2
if active_domain_count != 12:
    raise SystemExit(f'SECURE_VAULT_FAIL domain_count={active_domain_count}')
if 'VPN_DISCLOSURE_LEGACY("vpn-disclosure", legacyOnly = true)' not in vault:
    raise SystemExit('SECURE_VAULT_FAIL legacy_disclosure_migration_domain_missing')
if 'filterNot { it.legacyOnly }' not in vault:
    raise SystemExit('SECURE_VAULT_FAIL legacy_domain_exposed_as_active')
print(f'SECURE_TELEMETRY_VAULT_PASS domains={active_domain_count} active_keys=persistent-kek-wrapped-domain-keysets evidence=encrypted-v3 pqc=ml-dsa-87-conditional consent=update-stable-hmac-receipt')
