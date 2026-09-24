#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
MODEL = (ROOT / 'app/src/main/java/de/visiongaia/gedefense/mobile/SetupWizardModel.kt').read_text(encoding='utf-8')
ACTIVITY = (ROOT / 'app/src/main/java/de/visiongaia/gedefense/mobile/SetupWizardActivity.kt').read_text(encoding='utf-8')
RENDERER = (ROOT / 'app/src/main/java/de/visiongaia/gedefense/mobile/SetupWizardPageRenderer.kt').read_text(encoding='utf-8')
SETUP = (ROOT / 'app/src/main/java/de/visiongaia/gedefense/mobile/DeviceSetupManager.kt').read_text(encoding='utf-8')

expected = [
    'WELCOME', 'PROTECTION_MODEL', 'LOCAL_VPN', 'XDR_INTELLIGENCE', 'RELIABILITY',
    'STORAGE_SCANNER', 'VISIBILITY', 'TITAN', 'PRIVACY', 'INITIAL_SYNC', 'SUMMARY',
]
missing = [name for name in expected if not re.search(rf'^\s*{name}\(', MODEL, re.M)]
if missing:
    raise SystemExit(f'ONBOARDING_AUDIT_FAIL missing_steps={missing}')
if 'completedMarker || legacyWizardVersion > 0' not in SETUP or 'SETUP_SCHEMA_VERSION = 2' not in SETUP:
    raise SystemExit('ONBOARDING_AUDIT_FAIL monotonic_completion')
required = {
    'vpn_disclosure': 'VpnDisclosureActivity::class.java',
    'privacy_center': 'PrivacyActivity::class.java',
    'coarse_location': 'Manifest.permission.ACCESS_COARSE_LOCATION',
    'core_label': 'SetupRequirementLevel.CORE',
    'optional_label': 'SetupRequirementLevel.OPTIONAL',
    'enterprise_label': 'SetupRequirementLevel.ENTERPRISE',
    'vpn_no_mitm': 'setup_vpn_not_mitm',
    'vpn_no_history_upload': 'setup_vpn_not_history_upload',
    'storage_readonly': 'setup_storage_scope_readonly',
    'telemetry_shield': 'setup_privacy_telemetry_title',
    'telemetry_fullflow_boundary': 'setup_privacy_telemetry_boundary_fullflow',
    'telemetry_no_mitm_boundary': 'setup_privacy_telemetry_boundary_no_mitm',
    'telemetry_profile_control': 'setup_privacy_telemetry_boundary_control',
}
for name, token in required.items():
    if token not in RENDERER:
        raise SystemExit(f'ONBOARDING_AUDIT_FAIL {name}')
for forbidden in ('Manifest.permission.ACCESS_FINE_LOCATION', 'Manifest.permission.ACCESS_BACKGROUND_LOCATION'):
    if forbidden in RENDERER:
        raise SystemExit(f'ONBOARDING_AUDIT_FAIL forbidden_permission={forbidden}')
if 'setup.markWizardCompleted()' not in ACTIVITY or 'activatePostSetupInventoryAsync()' not in ACTIVITY:
    raise SystemExit('ONBOARDING_AUDIT_FAIL completion_activation')
if ACTIVITY.index('setup.markWizardCompleted()') > ACTIVITY.index('activatePostSetupInventoryAsync()'):
    raise SystemExit('ONBOARDING_AUDIT_FAIL inventory_before_consent')
print(f'ONBOARDING_AUDIT_PASS steps={len(expected)} setup_schema=2 monotonic_completion=true telemetry_shield=true')
