#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
from __future__ import annotations
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / 'SOURCE-MANIFEST.sha256'
EXCLUDE = {'SOURCE-MANIFEST.sha256', 'local.properties', '.lint-run.log', '.lint-run.exit', '.release-readiness-final.log', '.release-readiness-final.exit'}

def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def files() -> list[Path]:
    out=[]
    for path in ROOT.rglob('*'):
        if not path.is_file():
            continue
        rel=path.relative_to(ROOT).as_posix()
        if rel in EXCLUDE or '/build/' in f'/{rel}/' or rel.startswith('.git/') or rel.startswith('.gradle/') or '/__pycache__/' in f'/{rel}/' or rel.endswith('.pyc'):
            continue
        out.append(path)
    return sorted(out, key=lambda p:p.relative_to(ROOT).as_posix())

rows=[]
for path in files():
    rows.append(f'{digest(path)}  {path.relative_to(ROOT).as_posix()}')
MANIFEST.write_text('\n'.join(rows)+'\n', encoding='utf-8')
print(f'SOURCE_MANIFEST_GENERATED files={len(rows)}')
