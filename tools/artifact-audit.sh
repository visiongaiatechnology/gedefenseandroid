#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
set -euo pipefail
cd "$(dirname "$0")/.."
APK="${1:-app/build/outputs/apk/release/app-release.apk}"
AAB="${2:-app/build/outputs/bundle/release/app-release.aab}"
[[ -s "$APK" ]] || { echo "ARTIFACT_AUDIT_FAIL missing_apk=$APK" >&2; exit 1; }
[[ -s "$AAB" ]] || { echo "ARTIFACT_AUDIT_FAIL missing_aab=$AAB" >&2; exit 1; }
unzip -tq "$APK" >/dev/null
unzip -tq "$AAB" >/dev/null
EXPECTED_VERSION="$(cat VERSION)"
EXPECTED_VERSION_CODE="$(cat VERSION_CODE)"
AAPT="${AAPT:-${ANDROID_HOME:-}/build-tools/34.0.0/aapt}"
ZIPALIGN="${ZIPALIGN:-${ANDROID_HOME:-}/build-tools/34.0.0/zipalign}"
[[ -x "$AAPT" ]] || { echo 'ARTIFACT_AUDIT_FAIL aapt_unavailable' >&2; exit 1; }
BADGING="$($AAPT dump badging "$APK")"
grep -q "package: name='de.visiongaia.gedefense.mobile' versionCode='$EXPECTED_VERSION_CODE' versionName='$EXPECTED_VERSION'" <<<"$BADGING" || { echo 'ARTIFACT_AUDIT_FAIL apk_version_metadata' >&2; exit 1; }
grep -q "sdkVersion:'29'" <<<"$BADGING" || { echo 'ARTIFACT_AUDIT_FAIL apk_min_sdk' >&2; exit 1; }
grep -q "targetSdkVersion:'36'" <<<"$BADGING" || { echo 'ARTIFACT_AUDIT_FAIL apk_target_sdk' >&2; exit 1; }
grep -q "compileSdkVersion='36'" <<<"$BADGING" || { echo 'ARTIFACT_AUDIT_FAIL apk_compile_sdk' >&2; exit 1; }
[[ -x "$ZIPALIGN" ]] || { echo 'ARTIFACT_AUDIT_FAIL zipalign_unavailable' >&2; exit 1; }
# AGP 8.5.x is retained for this reproducible beta toolchain. Android's documented fallback for
# AGP <= 8.5 is compressed JNI libraries (`useLegacyPackaging = true`), which are extracted before
# mmap and therefore do not require 16 KiB ZIP entry alignment. The ELF PT_LOAD alignment is checked
# separately by the source security gate. If packaging ever switches to uncompressed JNI libraries,
# this audit requires a modern zipalign with explicit -P 16 support instead of silently accepting 4 KiB.
NATIVE_ROWS="$(unzip -lv "$APK" | grep 'libgedefense_gaianet_v2.so' || true)"
[[ "$(printf '%s\n' "$NATIVE_ROWS" | grep -c 'Defl:')" -eq 2 ]] || {
  if "$ZIPALIGN" -h 2>&1 | grep -q -- '-P <pagesize_kb>'; then
    "$ZIPALIGN" -c -P 16 -v 4 "$APK" >/dev/null || { echo 'ARTIFACT_AUDIT_FAIL apk_zipalign_16k' >&2; exit 1; }
  else
    echo 'ARTIFACT_AUDIT_FAIL uncompressed_native_lib_requires_modern_zipalign' >&2
    exit 1
  fi
}
"$ZIPALIGN" -c -p -v 4 "$APK" >/dev/null || { echo 'ARTIFACT_AUDIT_FAIL apk_zipalign_general' >&2; exit 1; }
for abi in arm64-v8a x86_64; do
  unzip -Z1 "$APK" | grep -qx "lib/$abi/libgedefense_gaianet_v2.so" || { echo "ARTIFACT_AUDIT_FAIL apk_missing_gaianet_$abi" >&2; exit 1; }
  unzip -Z1 "$AAB" | grep -qx "base/lib/$abi/libgedefense_gaianet_v2.so" || { echo "ARTIFACT_AUDIT_FAIL aab_missing_gaianet_$abi" >&2; exit 1; }
done
APKSIGNER="${APKSIGNER:-${ANDROID_HOME:-}/build-tools/34.0.0/apksigner}"
if [[ -x "$APKSIGNER" ]]; then
  "$APKSIGNER" verify --verbose --print-certs "$APK" >/tmp/gedefense-apksigner.txt
  grep -q 'Verified using v2 scheme (APK Signature Scheme v2): true' /tmp/gedefense-apksigner.txt || { echo 'ARTIFACT_AUDIT_FAIL apk_v2_signature' >&2; exit 1; }
else
  echo 'ARTIFACT_AUDIT_FAIL apksigner_unavailable' >&2; exit 1
fi
JARSIGNER="${JARSIGNER:-${JAVA_HOME:-}/bin/jarsigner}"
if [[ -x "$JARSIGNER" ]]; then
  "$JARSIGNER" -verify "$AAB" >/tmp/gedefense-jarsigner.txt 2>&1 || { cat /tmp/gedefense-jarsigner.txt >&2; echo 'ARTIFACT_AUDIT_FAIL aab_signature' >&2; exit 1; }
  grep -q 'jar verified.' /tmp/gedefense-jarsigner.txt || { echo 'ARTIFACT_AUDIT_FAIL aab_not_verified' >&2; exit 1; }
else
  echo 'ARTIFACT_AUDIT_FAIL jarsigner_unavailable' >&2; exit 1
fi
EXPECTED_CERT_SHA256="0A:60:3C:4D:60:C8:75:BF:12:88:99:8F:7B:D3:D9:88:93:7D:BA:C6:AE:F0:EA:48:7C:F2:B4:6D:FE:70:DD:8C"
APK_CERT="$(sed -n 's/^Signer #1 certificate SHA-256 digest: //p' /tmp/gedefense-apksigner.txt | head -1 | tr '[:lower:]' '[:upper:]')"
[[ "${APK_CERT//:/}" == "${EXPECTED_CERT_SHA256//:/}" ]] || { echo "ARTIFACT_AUDIT_FAIL apk_cert_fingerprint=$APK_CERT" >&2; exit 1; }
KEYTOOL="${KEYTOOL:-${JAVA_HOME:-}/bin/keytool}"
[[ -x "$KEYTOOL" ]] || { echo 'ARTIFACT_AUDIT_FAIL keytool_unavailable' >&2; exit 1; }
AAB_CERT="$("$KEYTOOL" -printcert -jarfile "$AAB" 2>/dev/null | sed -n 's/^[[:space:]]*SHA256: //p' | head -1 | tr '[:lower:]' '[:upper:]')"
[[ "${AAB_CERT//:/}" == "${EXPECTED_CERT_SHA256//:/}" ]] || { echo "ARTIFACT_AUDIT_FAIL aab_cert_fingerprint=$AAB_CERT" >&2; exit 1; }
printf 'ARTIFACT_AUDIT_PASS apk_sha256=%s aab_sha256=%s\n' "$(sha256sum "$APK" | cut -d' ' -f1)" "$(sha256sum "$AAB" | cut -d' ' -f1)"
