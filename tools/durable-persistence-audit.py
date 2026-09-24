#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[1]

def require(path: str, *tokens: str) -> str:
    text = (root / path).read_text()
    for token in tokens:
        if token not in text:
            raise SystemExit(f"DURABLE_PERSISTENCE_AUDIT_FAIL: {path} missing {token}")
    return text

atomic = require(
    "core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/DurableAtomicFiles.kt",
    "StandardCopyOption.ATOMIC_MOVE",
    "throw IOException(\"atomic replace unsupported\"",
    "channel.force(true)",
    "Files.isSymbolicLink",
    "LinkOption.NOFOLLOW_LINKS",
)
if "Files.move(tempPath, targetPath, StandardCopyOption.REPLACE_EXISTING)" in atomic:
    raise SystemExit("DURABLE_PERSISTENCE_AUDIT_FAIL: non-atomic fallback reintroduced")

snapshot = require(
    "core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/AuthenticatedSnapshotStore.kt",
    "snapshot staged verification failed",
    "DurableAtomicFiles.replace(temp, file)",
    "snapshot post-write verification failed",
)
integrity = require(
    "core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/IntegrityBaseline.kt",
    "readState(temp, activeKey)",
    "integrity baseline staged verification failed",
    "DurableAtomicFiles.replace(temp, file)",
)
evidence = require(
    "core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/EvidenceLedger.kt",
    "evidence rekey verification failed",
    "fresh evidence candidate verification failed",
    "encrypted evidence migration verification failed",
    "DurableAtomicFiles.replace(temp, file)",
)
threat = require(
    "core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/ThreatCacheStore.kt",
    "staged feed metadata failed verification",
    "staged feed metadata mismatch",
    "DurableAtomicFiles.replace(dataTemp, finalData)",
    "DurableAtomicFiles.replace(metaTemp, finalMeta)",
)
secure = require(
    "app/src/main/java/de/visiongaia/gedefense/mobile/SecureFiles.kt",
    "Os.rename",
    "Os.fsync",
    "verifyExactBytes",
)
migration = require(
    "app/src/main/java/de/visiongaia/gedefense/mobile/VaultMigrationPolicy.kt",
    "SecureFiles.writeAtomic(marker, body)",
    "isCompleted(app, window.spec)",
)
android_evidence = require(
    "app/src/main/java/de/visiongaia/gedefense/mobile/AndroidEvidence.kt",
    "SecureFiles.atomicReplace(temp, target)",
    "source.parentFile?.let(SecureFiles::fsyncDirectory)",
    "evidence migration digest mismatch",
)

for path, text in (
    ("AuthenticatedSnapshotStore.kt", snapshot),
    ("IntegrityBaseline.kt", integrity),
    ("EvidenceLedger.kt", evidence),
    ("ThreatCacheStore.kt", threat),
    ("VaultMigrationPolicy.kt", migration),
    ("AndroidEvidence.kt", android_evidence),
):
    if "catch (_: AtomicMoveNotSupportedException)" in text:
        raise SystemExit(f"DURABLE_PERSISTENCE_AUDIT_FAIL: silent atomic downgrade in {path}")

print("DURABLE_PERSISTENCE_AUDIT_PASS staged_verify=true atomic_fail_closed=true directory_fsync=true")
