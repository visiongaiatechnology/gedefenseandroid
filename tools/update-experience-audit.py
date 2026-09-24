#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SETUP = (ROOT / "app/src/main/java/de/visiongaia/gedefense/mobile/DeviceSetupManager.kt").read_text(encoding="utf-8")
UPDATE = (ROOT / "app/src/main/java/de/visiongaia/gedefense/mobile/UpdateExperienceActivity.kt").read_text(encoding="utf-8")
MAIN = (ROOT / "app/src/main/java/de/visiongaia/gedefense/mobile/MainActivity.kt").read_text(encoding="utf-8")
STARTUP = (ROOT / "app/src/main/java/de/visiongaia/gedefense/mobile/StartupActivity.kt").read_text(encoding="utf-8")
VPN = (ROOT / "app/src/main/java/de/visiongaia/gedefense/mobile/GeDefenseVpnService.kt").read_text(encoding="utf-8")
MANIFEST = (ROOT / "app/src/main/AndroidManifest.xml").read_text(encoding="utf-8")

required_setup = [
    "completedMarker || legacyWizardVersion > 0",
    "shouldShowUpdateExperience()",
    "KEY_LAST_ACK_VERSION_CODE",
    "KEY_UPDATE_SYNCED_VERSION_CODE",
    "KEY_PENDING_UPDATE_ACTIVATION_VERSION_CODE",
    "markUpdateThreatSyncCompleted",
    "markUpdateActivationPending",
    "completePendingUpdateAfterProtection",
]
for token in required_setup:
    if token not in SETUP:
        raise SystemExit(f"UPDATE_EXPERIENCE_AUDIT_FAIL setup_missing={token}")
if "legacyWizardVersion > 0" not in SETUP or ">= CURRENT_WIZARD_VERSION" in SETUP:
    raise SystemExit("UPDATE_EXPERIENCE_AUDIT_FAIL wizard_completion_not_monotonic")
if "putInt(KEY_LAST_ACK_VERSION_CODE, versionCode)" not in SETUP:
    raise SystemExit("UPDATE_EXPERIENCE_AUDIT_FAIL fresh_install_ack_missing")
required_update = [
    "startInitialSetupFeedSync()",
    "markUpdateThreatSyncCompleted()",
    "markUpdateActivationPending()",
    "markUpdateExperienceAcknowledged()",
    "GeDefenseVpnService.ACTION_REFRESH",
    "EXTRA_REQUEST_PROTECTION_ACTIVATION",
]
for token in required_update:
    if token not in UPDATE:
        raise SystemExit(f"UPDATE_EXPERIENCE_AUDIT_FAIL activity_missing={token}")
if UPDATE.find("markUpdateThreatSyncCompleted()") > UPDATE.find("markUpdateActivationPending()"):
    raise SystemExit("UPDATE_EXPERIENCE_AUDIT_FAIL activation_pending_before_sync")
if "UpdateExperienceActivity::class.java" not in MAIN or "UPDATE_REQUEST" not in MAIN:
    raise SystemExit("UPDATE_EXPERIENCE_AUDIT_FAIL main_routing")
if "SetupWizardActivity::class.java" in STARTUP:
    raise SystemExit("UPDATE_EXPERIENCE_AUDIT_FAIL startup_duplicate_wizard_route")
if "runtime.setup.completePendingUpdateAfterProtection()" not in VPN:
    raise SystemExit("UPDATE_EXPERIENCE_AUDIT_FAIL guarded_activation_ack")
if '.UpdateExperienceActivity' not in MANIFEST:
    raise SystemExit("UPDATE_EXPERIENCE_AUDIT_FAIL manifest_activity")
print("UPDATE_EXPERIENCE_AUDIT_PASS monotonic_onboarding=true preference_race_gated=true per_version_notice=true threat_sync_gate=true guarded_activation_ack=true")
