#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import os

ROOT=Path(__file__).resolve().parents[1]
BOM=ROOT/'SBOM.cdx.json'
if not BOM.is_file(): raise SystemExit('SBOM missing')
obj=json.loads(BOM.read_text(encoding='utf-8'))
if obj.get('bomFormat')!='CycloneDX' or obj.get('specVersion')!='1.6': raise SystemExit('SBOM format/version mismatch')
version=(ROOT/'VERSION').read_text().strip()
meta=obj.get('metadata',{})
if meta.get('component',{}).get('version')!=version: raise SystemExit('SBOM application version mismatch')
components=[meta.get('component',{})]+obj.get('components',[])
by_name={c.get('name'):c for c in components}
expected={
 'VGT GeDefense Mobile':version,
 'GeDefense Core':version,
 'GaiaNet V2 Android Helper':version,
 'Kotlin Standard Library':'1.9.24',
 'wireguard-go':'0.0.20250522',
 'golang.org/x/crypto':'v0.37.0',
 'golang.org/x/net':'v0.39.0',
 'golang.org/x/sys':'v0.32.0',
 'golang.org/x/term':'v0.31.0',
 'golang.org/x/text':'v0.24.0',
}
if set(by_name)!=set(expected): raise SystemExit(f'SBOM component surface mismatch: {sorted(by_name)}')
for name,v in expected.items():
 if by_name[name].get('version')!=v: raise SystemExit(f'SBOM component version mismatch: {name}')
for d in ('wireguard-go','x-crypto','x-net','x-sys','x-term','x-text'):
 if not (ROOT/'third_party/go'/d/'LICENSE').is_file(): raise SystemExit('vendored license missing: '+d)
# Recompute the SBOM deterministically and require byte identity.
before=BOM.read_bytes()
proc=subprocess.run(['python3',str(ROOT/'tools/generate-sbom.py')],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
if proc.returncode: raise SystemExit('SBOM regeneration failed: '+proc.stderr.decode(errors='replace'))
if BOM.read_bytes()!=before: raise SystemExit('SBOM was stale or non-deterministic')
print(f'SBOM_AUDIT_PASS components={len(components)} licenses=vendored toolchains=pinned deterministic=true')
