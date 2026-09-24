#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
set -euo pipefail
cd "$(dirname "$0")/.."

required=(README.md SECURITY.md PRIVACY.md CONTRIBUTING.md CODE_OF_CONDUCT.md SUPPORT.md NETWORK-EGRESS.md ASN-EVIDENCE.md PLAY-STORE-COMPLIANCE.md PLAY-PERMISSION-DECLARATIONS.md DATA-SAFETY-DRAFT.md VPN-REVIEW-VIDEO-SCRIPT.md PLAY-STORE-LISTING.md PUBLIC-BETA-RELEASE-NOTES.md COMMUNITY-RELEASE.md RELEASE-CHECKLIST.md SUPPLY-CHAIN.md SECURE-TELEMETRY-VAULT.md VERSION_CODE)
for f in "${required[@]}"; do
  [[ -s "$f" ]] || { echo "RELEASE_GATE_FAIL missing=$f" >&2; exit 1; }
done

python3 - <<'PY'
from pathlib import Path
import re, sys
build=Path('app/build.gradle.kts').read_text()
version=Path('VERSION').read_text().strip()
version_code=Path('VERSION_CODE').read_text().strip()
if not version_code.isdigit() or int(version_code) <= 0:
    raise SystemExit('RELEASE_GATE_FAIL invalid_version_code')
checks={
    'compileSdk36': r'compileSdk\s*=\s*36',
    'targetSdk36': r'targetSdk\s*=\s*36',
    'versionCode': rf'versionCode\s*=\s*{re.escape(version_code)}(?:\s|$)',
    'versionName': re.escape(f'versionName = "{version}"'),
}
if f'## {version} ' not in Path('CHANGELOG.md').read_text():
    raise SystemExit('RELEASE_GATE_FAIL changelog_version')
for name, pattern in checks.items():
    if not re.search(pattern, build):
        raise SystemExit(f'RELEASE_GATE_FAIL {name}')
props=Path('gradle/wrapper/gradle-wrapper.properties').read_text()
lock=Path('TOOLCHAINS.lock').read_text()
expected_lock = {
    'compile_sdk': '36',
    'target_sdk': '36',
    'min_sdk': '29',
    'java_target': '17',
    'android_ndk': '27.2.12479018',
    'native_abis': 'arm64-v8a,x86_64',
    'go': '1.26.8',
}
for key, expected in expected_lock.items():
    match = re.search(rf'(?m)^{re.escape(key)}=([^\r\n]+)$', lock)
    if not match or match.group(1).strip() != expected:
        raise SystemExit(f'RELEASE_GATE_FAIL toolchain_lock_{key}')
if 'ndkVersion = "27.2.12479018"' not in build:
    raise SystemExit('RELEASE_GATE_FAIL ndk_version')
if 'minSdk = 29' not in build:
    raise SystemExit('RELEASE_GATE_FAIL minSdk29')
if 'jvmTarget = "17"' not in build or 'JavaVersion.VERSION_17' not in build:
    raise SystemExit('RELEASE_GATE_FAIL java_target17')
if 'abiFilters += listOf("arm64-v8a", "x86_64")' not in build:
    raise SystemExit('RELEASE_GATE_FAIL native_abis')
sha=re.search(r'gradle_8_7_bin_sha256=([0-9a-f]{64})', lock)
if not sha or f'distributionSha256Sum={sha.group(1)}' not in props:
    raise SystemExit('RELEASE_GATE_FAIL gradle_wrapper_sha')
print('RELEASE_METADATA_PASS')
PY

python3 - <<'PY'
from pathlib import Path
import re

# Release metadata must remain relocatable. Host-specific build paths make a
# source checkpoint silently depend on the machine that produced it.
checked = [
    Path('settings.gradle.kts'),
    Path('app/build.gradle.kts'),
    Path('core/build.gradle.kts'),
    Path('gradle.properties'),
]
patterns = [
    re.compile(r'/mnt/data(?:/|$)'),
    re.compile(r'/home/[^/\s]+(?:/|$)'),
    re.compile(r'/root(?:/|$)'),
    re.compile(r'(?i)(?<![A-Za-z0-9_])[A-Z]:[\\/]'),
]
for path in checked:
    if not path.exists():
        continue
    text = path.read_text(errors='replace')
    if any(pattern.search(text) for pattern in patterns):
        raise SystemExit(f'RELEASE_GATE_FAIL host_specific_path file={path}')

settings = Path('settings.gradle.kts').read_text()
if 'VGT_LOCAL_MAVEN' not in settings:
    raise SystemExit('RELEASE_GATE_FAIL portable_local_maven_hook')
archive_hashes = Path('third_party/go/UPSTREAM-ARCHIVES.sha256').read_text()
for line in archive_hashes.splitlines():
    line=line.strip()
    if not line or line.startswith('#'):
        continue
    parts=line.split(None, 1)
    if len(parts) != 2:
        raise SystemExit('RELEASE_GATE_FAIL upstream_archive_hash_format')
    filename=parts[1].lstrip('*')
    if '/' in filename or '\\' in filename:
        raise SystemExit('RELEASE_GATE_FAIL upstream_archive_hash_absolute_path')
print('RELEASE_PORTABILITY_PASS')
PY

python3 - <<'PYCI'
from pathlib import Path
workflow = Path('.github/workflows/verify.yml').read_text()
required = {
    'ci_jdk17': "java-version: '17'",
    'ci_go1268': "go-version: '1.26.8'",
    'ci_ndk_pin': 'GEDEFENSE_NDK_VERSION: "27.2.12479018"',
    'ci_ndk_install': '"ndk;${GEDEFENSE_NDK_VERSION}"',
    'ci_ndk_revision_check': "Pkg\\.Revision = 27\\.2\\.12479018",
    'ci_release_compile': ':app:compileReleaseKotlin',
    'ci_release_apk': ':app:assembleRelease',
    'ci_release_aab': ':app:bundleRelease',
    'ci_release_lint': ':app:lintRelease',
    'ci_release_readiness': 'bash tools/release-readiness.sh',
}
for name, token in required.items():
    if token not in workflow:
        raise SystemExit(f'RELEASE_GATE_FAIL {name}')
if workflow.find(':app:lintRelease') > workflow.find('bash tools/release-readiness.sh'):
    raise SystemExit('RELEASE_GATE_FAIL ci_lint_must_precede_release_readiness')
print('RELEASE_CI_TOOLCHAIN_PASS')
PYCI

command -v go >/dev/null 2>&1 || { echo 'RELEASE_GATE_FAIL go_1_26_8_missing' >&2; exit 1; }
[[ "$(GOTOOLCHAIN=local go env GOVERSION)" == "go1.26.8" ]] || { echo "RELEASE_GATE_FAIL go_toolchain_expected_1_26_8_actual_$(go env GOVERSION 2>/dev/null || echo unavailable)" >&2; exit 1; }
echo 'RELEASE_GO_TOOLCHAIN_PASS version=go1.26.8'

python3 - <<'PYGAIAALIGN'
from pathlib import Path
security = Path('tools/security-audit.sh').read_text()
build_ps1 = Path('tools/build-go-netstack.ps1').read_text()
required = '-extldflags=-Wl,-z,max-page-size=16384'
if required not in security:
    raise SystemExit('RELEASE_GATE_FAIL security_x86_64_16k_extlink')
if required not in build_ps1:
    raise SystemExit('RELEASE_GATE_FAIL powershell_x86_64_16k_extlink')
print('RELEASE_GAIANET_X86_64_16K_LINK_PASS')
PYGAIAALIGN

if find . -path './.git' -prune -o -type f \( -iname '*.jks' -o -iname '*.keystore' -o -iname '*.p12' -o -iname '*.pfx' -o -iname '*.pem' -o -iname '*.key' -o -name 'google-services.json' -o -iname '*service-account*.json' \) -print | grep -q .; then
  echo 'RELEASE_GATE_FAIL signing_or_secret_material_present' >&2
  exit 1
fi

grep -q 'android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS' app/src/main/AndroidManifest.xml && {
  echo 'RELEASE_GATE_FAIL direct_battery_exemption_permission' >&2; exit 1;
}

grep -q 'ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS' app/src/main/java/de/visiongaia/gedefense/mobile/DeviceSetupManager.kt && {
  echo 'RELEASE_GATE_FAIL direct_battery_exemption_intent' >&2; exit 1;
}

bash tools/core-check.sh
python3 tools/i18n-audit.py
python3 tools/network-egress-audit.py
python3 tools/onboarding-audit.py
python3 tools/update-experience-audit.py
python3 tools/secure-vault-audit.py
python3 tools/oem-hmac-continuity-audit.py
python3 tools/full-flow-availability-audit.py
python3 tools/wireguard-audit.py
bash tools/wireguard-parser-check.sh
python3 tools/wireguard-import-surface-audit.py
python3 tools/sbom-audit.py
python3 tools/asn-evidence-audit.py
python3 tools/privacy-shield-audit.py
python3 tools/install-guard-audit.py
bash tools/install-guard-policy-check.sh
python3 tools/resilience-supervisor-audit.py
bash tools/wireguard-upstream-check.sh
python3 tools/startup-anr-audit.py
python3 tools/main-thread-io-audit.py
python3 tools/lint-zero-audit.py
bash tools/security-audit.sh
bash tools/jvm-class-init-probe.sh

echo 'RELEASE_READINESS_PASS'
