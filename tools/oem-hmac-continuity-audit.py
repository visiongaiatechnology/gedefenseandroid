#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JAVA = ROOT / "app/src/main/java/de/visiongaia/gedefense/mobile"
RUNTIME = (JAVA / "AppRuntime.kt").read_text(encoding="utf-8")
STABLE = (JAVA / "StableSecurityKeys.kt").read_text(encoding="utf-8")
VAULT = (JAVA / "SecureTelemetryVault.kt").read_text(encoding="utf-8")
POLICY = (JAVA / "IntegrityKeyMigrationPolicy.kt").read_text(encoding="utf-8")
INTEGRITY = (ROOT / "core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/IntegrityBaseline.kt").read_text(encoding="utf-8")
GUARDIAN = (JAVA / "IntegrityGuardian.kt").read_text(encoding="utf-8")

for token in (
    'SECURITY_ROOT("security-root"',
    'persistentKeyVersion = 1',
    'infrastructureOnly = true',
    'filterNot { it.legacyOnly || it.infrastructureOnly }',
):
    if token not in VAULT:
        raise SystemExit(f"OEM_HMAC_CONTINUITY_FAIL vault_root={token}")

for token in (
    'PersistentVaultKeys.keys(',
    'VaultDomain.SECURITY_ROOT',
    'Mac.getInstance("HmacSHA256")',
    'SecretKeySpec(derived, "HmacSHA256")',
):
    if token not in STABLE:
        raise SystemExit(f"OEM_HMAC_CONTINUITY_FAIL stable_key={token}")

for purpose in ('threat-intel', 'integrity-baseline', 'geo-country', 'asn-evidence'):
    if f'StableSecurityKeys.hmacOrNull("{purpose}")' not in RUNTIME:
        raise SystemExit(f"OEM_HMAC_CONTINUITY_FAIL runtime_purpose={purpose}")

for forbidden in (
    'vgt.gedefense.mobile.threatintel.hmac.v1',
    'vgt.gedefense.mobile.integrity.hmac.v1',
    'vgt.gedefense.mobile.geo-country.hmac.v1',
    'vgt.gedefense.mobile.asn-evidence.hmac.v1',
):
    if forbidden in RUNTIME:
        raise SystemExit(f"OEM_HMAC_CONTINUITY_FAIL active_direct_alias={forbidden}")

for token in (
    'RECOVERY_VERSION_CODE = 57L',
    'updated <= first',
    'return updated',
):
    if token not in POLICY:
        raise SystemExit(f"OEM_HMAC_CONTINUITY_FAIL recovery_policy={token}")
for token in (
    'recoveryBoundaryMillis',
    'modified in 1..boundary',
    'integrity_update_key_recovered',
):
    if token not in INTEGRITY:
        raise SystemExit(f"OEM_HMAC_CONTINUITY_FAIL integrity_recovery={token}")
if 'IntegrityKeyMigrationPolicy.updateBoundaryMillis(appContext)' not in GUARDIAN:
    raise SystemExit('OEM_HMAC_CONTINUITY_FAIL guardian_boundary_missing')

print('OEM_HMAC_CONTINUITY_PASS active_direct_oem_hmac=0 stable_root=persistent-security-root integrity_recovery=update-bounded')
