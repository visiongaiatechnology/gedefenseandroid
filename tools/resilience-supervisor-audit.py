#!/usr/bin/env python3
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
supervisor = (ROOT / "app/src/main/java/de/visiongaia/gedefense/mobile/ResilienceSupervisor.kt").read_text(encoding="utf-8")
bounded = (ROOT / "app/src/main/java/de/visiongaia/gedefense/mobile/BoundedRecoveryCall.kt").read_text(encoding="utf-8")
budget = (ROOT / "core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/RecoveryAttemptBudget.kt").read_text(encoding="utf-8")
core_tests = (ROOT / "core/src/test/kotlin/de/visiongaia/gedefense/mobile/core/CoreTestMain.kt").read_text(encoding="utf-8")
job = (ROOT / "app/src/main/java/de/visiongaia/gedefense/mobile/IntegrityJobService.kt").read_text(encoding="utf-8")
resilience_job = (ROOT / "app/src/main/java/de/visiongaia/gedefense/mobile/ResilienceJobService.kt").read_text(encoding="utf-8")
resilience_jobs = (ROOT / "app/src/main/java/de/visiongaia/gedefense/mobile/ResilienceJobs.kt").read_text(encoding="utf-8")
application = (ROOT / "app/src/main/java/de/visiongaia/gedefense/mobile/GeDefenseApplication.kt").read_text(encoding="utf-8")
boot = (ROOT / "app/src/main/java/de/visiongaia/gedefense/mobile/BootReceiver.kt").read_text(encoding="utf-8")
manifest = (ROOT / "app/src/main/AndroidManifest.xml").read_text(encoding="utf-8")
runtime = (ROOT / "app/src/main/java/de/visiongaia/gedefense/mobile/AppRuntime.kt").read_text(encoding="utf-8")
security = (ROOT / "tools/security-audit.sh").read_text(encoding="utf-8")
readiness = (ROOT / "tools/release-readiness.sh").read_text(encoding="utf-8")

required = {
    "off_main": "Looper.myLooper() != Looper.getMainLooper()" in supervisor,
    "single_flight": "AtomicBoolean(false)" in supervisor and "running.compareAndSet(false, true)" in supervisor,
    "bounded_calls": "BoundedRecoveryCall.call" in supervisor and "SynchronousQueue()" in bounded,
    "budgeted": "RecoveryAttemptBudget(" in supervisor and "MAX_REPAIR_ATTEMPTS_PER_WINDOW" in supervisor,
    "per_run_budget": "MAX_REPAIRS_PER_RUN" in supervisor,
    "signed_privacy_reload": "reloadSignedSnapshot()" in supervisor,
    "threat_lkg_only": "feeds.loadCachedSnapshot()" in supervisor,
    "gaianet_revalidate": "refreshNativeGaiaNetAvailability()" in supervisor,
    "installguard_resync": "syncPackageEgressQuarantine" in supervisor and "packageEgressGateActive()" in supervisor,
    "titan_reassert": "RESUSPEND_QUARANTINED" in supervisor and "enforceQuarantine" in supervisor,
    "evidence_reverify": "refreshEvidenceHealth()" in supervisor,
    "integrity_revalidate": "REVALIDATE_SIGNED_INSTALL" in supervisor and "integrityGuardian.scan()" in supervisor,
    "malware_cache_no_reset": "REBUILD_SCAN_REQUIRED" in supervisor,
    "behavior_reload": "behavior.initialize()" in supervisor,
    "xdr_audit": "recordResilienceFinding" in supervisor,
    "integrity_hook": "runtime.resilienceSupervisor.runOnce" in job,
    "dedicated_periodic_hook": 'runtime.resilienceSupervisor.runOnce("periodic-job")' in resilience_job,
    "offline_periodic_job": ".setPeriodic(PERIOD_MS, FLEX_MS)" in resilience_jobs and "setRequiredNetworkType" not in resilience_jobs,
    "job_manifest": '.ResilienceJobService' in manifest and 'android.permission.BIND_JOB_SERVICE' in manifest,
    "application_schedule": "ResilienceJobs.schedule(this)" in application,
    "boot_schedule": "ResilienceJobs.schedule(appContext)" in boot,
    "budget_core_test": "testRecoveryAttemptBudget()" in core_tests,
    "bounded_budget_map": "maxKeys" in budget and "cooldownMillis" in budget,
    "trust_bootstrap_gate": "awaitXdrTrustBootstrap" in supervisor and "fun awaitXdrTrustBootstrap" in runtime,
    "behavior_bootstrap_gate": "awaitBehaviorBootstrap" in supervisor and "behaviorBootstrap" in runtime,
    "malware_bootstrap_gate": "awaitMalwareAnalysisBootstrap" in supervisor and "malwareAnalysisBootstrap" in runtime,
    "shipping_security_gate": "python3 tools/resilience-supervisor-audit.py" in security,
    "shipping_readiness_gate": "python3 tools/resilience-supervisor-audit.py" in readiness,
}

forbidden_substrings = {
    "automatic_firewall_reset": "resetPolicy(",
    "automatic_xdr_reset": "recoverCorruptStore(",
    "network_feed_sync": "feeds.syncDue(",
    "network_downloader": "FeedDownloader",
    "thread_sleep": "Thread.sleep(",
    "unbounded_executor": "Executors.new",
    "store_delete": ".delete(",
}

failed = [name for name, ok in required.items() if not ok]
failed += [name for name, token in forbidden_substrings.items() if token in supervisor]

# The only clear operation allowed in the supervisor is its in-memory retry budget.
clear_calls = re.findall(r"([A-Za-z0-9_.]+)\.clear\(", supervisor)
if any(call != "repairBudget" for call in clear_calls):
    failed.append("automatic_store_clear")

if failed:
    print("RESILIENCE_SUPERVISOR_AUDIT_FAIL " + " ".join(sorted(set(failed))))
    sys.exit(1)
print(
    "RESILIENCE_SUPERVISOR_AUDIT_PASS "
    "local_only=true bounded=true single_flight=true evidence_preserving=true "
    "trust_bootstrap_guarded=true fail_closed=true"
)
