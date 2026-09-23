#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
from __future__ import annotations
from pathlib import Path
import zipfile

ROOT=Path(__file__).resolve().parent.parent
VERSION=(ROOT/'VERSION').read_text(encoding='utf-8').strip()
OUT=ROOT.parent / f'VGT_GeDefense_Mobile_{VERSION}_Source.zip'
EXCLUDE={'local.properties'}

def included(path: Path) -> bool:
    rel=path.relative_to(ROOT).as_posix()
    return not (
        rel in EXCLUDE or rel.startswith('.git/') or rel.startswith('.gradle/') or
        '/build/' in f'/{rel}/' or rel.endswith('.jks') or rel.endswith('.keystore') or
        rel.endswith('.p12') or rel.endswith('.pfx') or rel.endswith('.pem') or rel.endswith('.key')
    )

files=sorted((p for p in ROOT.rglob('*') if p.is_file() and included(p)), key=lambda p:p.relative_to(ROOT).as_posix())
with zipfile.ZipFile(OUT,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as zf:
    for path in files:
        rel=path.relative_to(ROOT).as_posix()
        info=zipfile.ZipInfo(rel, date_time=(2026,9,21,0,0,0))
        info.compress_type=zipfile.ZIP_DEFLATED
        info.external_attr=(0o755 if path.stat().st_mode & 0o111 else 0o644) << 16
        zf.writestr(info,path.read_bytes(),compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
print(f'SOURCE_PACKAGE_PASS files={len(files)} output={OUT}')
