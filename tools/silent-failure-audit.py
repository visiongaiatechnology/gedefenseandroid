#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "app/src/main/java/de/visiongaia/gedefense/mobile"

violations: list[str] = []
empty_catch = re.compile(r"catch\s*\([^)]*\)\s*\{\s*\}", re.S)
critical_runcatching = re.compile(
    r"runCatching\s*\{\s*(?:runtime\.)?(?:xdr|evidence)\b|runCatching\s*\{\s*store\.write\b",
    re.S,
)

for path in SRC.rglob("*.kt"):
    text = path.read_text(encoding="utf-8")
    if empty_catch.search(text):
        violations.append(f"empty catch block: {path.relative_to(ROOT)}")
    if critical_runcatching.search(text):
        violations.append(f"silent critical runCatching: {path.relative_to(ROOT)}")

required = {
    "app/src/main/java/de/visiongaia/gedefense/mobile/AppRuntime.kt": [
        'recordXdrPersistenceFailure("xdr_${safeOperation}_failed")',
        'recordEvidencePersistenceFailure(code)',
        'requestIntegrityFailClosed(reason: String)',
        'stopService(android.content.Intent(application, GeDefenseVpnService::class.java))',
    ],
    "app/src/main/java/de/visiongaia/gedefense/mobile/XdrEngine.kt": [
        'reportXdrPersistenceFailure("event_write_failed", error)',
        'reportEvidencePersistenceFailure(error)',
        'runtimeState.recordXdrPersistenceFailure(code)',
        'runtimeState.recordEvidencePersistenceFailure(EvidenceWriteFailureClassifier.code(error))',
    ],
    "app/src/main/java/de/visiongaia/gedefense/mobile/IntegrityJobService.kt": [
        'runtime.recordXdrFailure("integrity_job_ingest", error)',
        'runtime.recordEvidenceFailure("integrity_job", error)',
        'runtime.requestIntegrityFailClosed("integrity_job")',
    ],
    "app/src/main/java/de/visiongaia/gedefense/mobile/ThreatIntelJobService.kt": [
        'runtime.recordEvidenceFailure("geo_sync_failure", error)',
        'runtime.recordEvidenceFailure("asn_sync_failure", error)',
        'needsReschedule = true',
    ],
    "app/src/main/java/de/visiongaia/gedefense/mobile/GeDefenseVpnService.kt": [
        'runtime.recordXdrFailure("threat_block", error)',
        'runtime.recordXdrFailure("behavior_commit", error)',
    ],
    "app/src/main/java/de/visiongaia/gedefense/mobile/RuntimeFailureLog.kt": [
        'MAX_SCOPES = 64',
        'error.javaClass.simpleName',
        'count == 1L || count and (count - 1L) == 0L',
    ],
}
for rel, tokens in required.items():
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    for token in tokens:
        if token not in text:
            violations.append(f"critical failure-handling invariant missing {rel}: {token}")

reporter = (SRC / "RuntimeFailureLog.kt").read_text(encoding="utf-8")
for forbidden in ("error.message", "stackTraceToString", "Log.getStackTraceString"):
    if forbidden in reporter:
        violations.append(f"RuntimeFailureLog may expose sensitive failure details: {forbidden}")

if violations:
    raise SystemExit("SILENT_FAILURE_AUDIT_FAIL\n" + "\n".join(violations))

print("SILENT_FAILURE_AUDIT_PASS empty_catches=0 critical_failures=propagated bounded_logging=true")
