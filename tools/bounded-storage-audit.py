#!/usr/bin/env python3
from pathlib import Path

root=Path(__file__).resolve().parents[1]

def load(path): return (root/path).read_text()

def need(path,*tokens):
    text=load(path)
    for token in tokens:
        if token not in text:
            raise SystemExit(f"BOUNDED_STORAGE_AUDIT_FAIL: {path} missing {token}")
    return text

helper=need('app/src/main/java/de/visiongaia/gedefense/mobile/BoundedDirectoryFiles.kt',
            'Files.newDirectoryStream','maxEntries','result.size >= maxEntries','LinkOption.NOFOLLOW_LINKS')
for path in (
    'app/src/main/java/de/visiongaia/gedefense/mobile/AsnEvidenceRepository.kt',
    'app/src/main/java/de/visiongaia/gedefense/mobile/GeoCountryRepository.kt',
    'app/src/main/java/de/visiongaia/gedefense/mobile/XdrEventStore.kt',
):
    text=load(path)
    if '.listFiles(' in text or '.listFiles()' in text:
        raise SystemExit(f"BOUNDED_STORAGE_AUDIT_FAIL: eager listFiles reintroduced in {path}")
    if 'BoundedDirectoryFiles.list' not in text:
        raise SystemExit(f"BOUNDED_STORAGE_AUDIT_FAIL: bounded enumeration missing in {path}")

geo=need('app/src/main/java/de/visiongaia/gedefense/mobile/GeoCountryRepository.kt',
         'MAX_MANIFEST_BYTES','manifest.length() !in 1..MAX_MANIFEST_BYTES')
asn=need('app/src/main/java/de/visiongaia/gedefense/mobile/AsnEvidenceRepository.kt',
         'MAX_GENERATION_DIRECTORY_ENTRIES = 64')
threat=need('core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/ThreatCacheStore.kt',
            'Files.newDirectoryStream','MAX_DIRECTORY_SCAN_ENTRIES = 256','LinkOption.NOFOLLOW_LINKS','isRegularFileNoFollow')
if '.listFiles(' in threat or '.listFiles()' in threat:
    raise SystemExit('BOUNDED_STORAGE_AUDIT_FAIL: eager listFiles reintroduced in ThreatCacheStore')
print('BOUNDED_STORAGE_AUDIT_PASS directory_enumeration=bounded nofollow=true manifest_caps=true')
