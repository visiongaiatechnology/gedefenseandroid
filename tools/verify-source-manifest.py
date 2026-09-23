#!/usr/bin/env python3
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "SOURCE-MANIFEST.sha256"
EXCLUDE = {"SOURCE-MANIFEST.sha256", "local.properties", ".lint-run.log", ".lint-run.exit", ".release-readiness-final.log", ".release-readiness-final.exit"}


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def files() -> list[Path]:
    result: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        if rel in EXCLUDE or "/build/" in f"/{rel}/" or rel.startswith(".git/") or rel.startswith(".gradle/") or "/__pycache__/" in f"/{rel}/" or rel.endswith(".pyc"):
            continue
        result.append(path)
    return sorted(result, key=lambda p: p.relative_to(ROOT).as_posix())


def main() -> int:
    if not MANIFEST.is_file():
        print("SOURCE_MANIFEST_FAIL: manifest missing", file=sys.stderr)
        return 1
    expected: dict[str, str] = {}
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        try:
            sha, rel = line.split("  ", 1)
        except ValueError:
            print("SOURCE_MANIFEST_FAIL: malformed line", file=sys.stderr)
            return 1
        if rel in expected or len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            print(f"SOURCE_MANIFEST_FAIL: invalid entry {rel!r}", file=sys.stderr)
            return 1
        expected[rel] = sha

    actual_files = files()
    actual_names = {p.relative_to(ROOT).as_posix() for p in actual_files}
    if set(expected) != actual_names:
        missing = sorted(actual_names - set(expected))
        extra = sorted(set(expected) - actual_names)
        print(f"SOURCE_MANIFEST_FAIL: set mismatch missing={missing} extra={extra}", file=sys.stderr)
        return 1

    for path in actual_files:
        rel = path.relative_to(ROOT).as_posix()
        if digest(path) != expected[rel]:
            print(f"SOURCE_MANIFEST_FAIL: hash mismatch {rel}", file=sys.stderr)
            return 1

    print(f"SOURCE_MANIFEST_PASS files={len(actual_files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
