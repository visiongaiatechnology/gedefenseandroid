#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
from __future__ import annotations
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / 'app/build/reports/lint-results-release.xml'
if not REPORT.is_file():
    raise SystemExit('LINT_ZERO_FAIL report_missing')
try:
    root = ET.parse(REPORT).getroot()
except (ET.ParseError, OSError) as exc:
    raise SystemExit(f'LINT_ZERO_FAIL report_invalid={type(exc).__name__}') from exc
issues = list(root.findall('issue'))
if issues:
    summary: dict[str, int] = {}
    for issue in issues:
        severity = issue.get('severity', 'Unknown')
        issue_id = issue.get('id', 'Unknown')
        key = f'{severity}:{issue_id}'
        summary[key] = summary.get(key, 0) + 1
    details = ','.join(f'{key}={count}' for key, count in sorted(summary.items()))
    raise SystemExit(f'LINT_ZERO_FAIL issues={len(issues)} {details}')
print('LINT_ZERO_PASS issues=0')
