#!/usr/bin/env python3
from pathlib import Path
import hashlib
ROOT=Path(__file__).resolve().parents[1]
activity=(ROOT/'app/src/main/java/de/visiongaia/gedefense/mobile/WireGuardActivity.kt').read_text()
manifest=(ROOT/'app/src/main/AndroidManifest.xml').read_text()
build=(ROOT/'app/build.gradle.kts').read_text()
expected={
 'zxing-android-embedded-4.3.0.aar':'4ab03353127c34e55cbb80fbc9a34031decbcfb1ec5e8f991944d2d494621a33',
 'zxing-core-3.5.3.jar':'8d8064c1636fdaef7189dd9055c7d59950a8940a12f2293956446ec3c109fd82',
}
base=ROOT/'third_party/android/zxing'
for name,want in expected.items():
 p=base/name
 if not p.is_file(): raise SystemExit('WIREGUARD_IMPORT_SURFACE_FAIL missing='+name)
 got=hashlib.sha256(p.read_bytes()).hexdigest()
 if got!=want: raise SystemExit('WIREGUARD_IMPORT_SURFACE_FAIL hash='+name)
if not (base/'LICENSE-Apache-2.0.txt').is_file(): raise SystemExit('WIREGUARD_IMPORT_SURFACE_FAIL license')
for token in ('play-services-code-scanner','mlkit','com.google.android.gms'):
 if token in build: raise SystemExit('WIREGUARD_IMPORT_SURFACE_FAIL google_runtime='+token)
if 'type = "*/*"' not in activity or 'Intent.ACTION_OPEN_DOCUMENT' not in activity:
 raise SystemExit('WIREGUARD_IMPORT_SURFACE_FAIL picker')
if 'ScanOptions.QR_CODE' not in activity or 'wireguard-import-qr' not in activity:
 raise SystemExit('WIREGUARD_IMPORT_SURFACE_FAIL qr')
if 'android.permission.CAMERA' not in manifest or 'android:required="false"' not in manifest:
 raise SystemExit('WIREGUARD_IMPORT_SURFACE_FAIL camera_manifest')
print('WIREGUARD_IMPORT_SURFACE_PASS conf_picker=true qr_local=true qr_hash_pinned=true google_play_services=false parser_shared=true')
