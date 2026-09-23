#!/usr/bin/env python3
# STATUS: PLATIN
"""Static release gate for process-start/runtime construction purity.

The gate is deliberately narrow: it protects the invariants that were violated by the 0.27.8
startup regressions. It does not pretend to prove Android/OEM runtime behavior by source scanning.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "app/src/main/java/de/visiongaia/gedefense/mobile"


def read(name: str) -> str:
    path = JAVA / name
    if not path.is_file():
        raise SystemExit(f"RUNTIME_BOOTSTRAP_AUDIT_FAIL missing={name}")
    return path.read_text(encoding="utf-8")


sources = {p.name: p.read_text(encoding="utf-8") for p in JAVA.glob("*.kt")}
runtime = read("AppRuntime.kt")
state = read("RuntimeState.kt")
setup = read("DeviceSetupManager.kt")
vault = read("SecureTelemetryVault.kt")
wrapped = read("WrappedHotPathKeys.kt")
persistent = read("PersistentVaultKeys.kt")
keystore = read("AndroidKeystoreGate.kt")

# SharedPreferences handles are not acquired as object-field initializers. Even a seemingly cheap
# getSharedPreferences() can couple later reads to SharedPreferencesImpl disk loading. Acquisition
# therefore occurs only inside the dedicated persistence/migration worker.
eager_prefs = []
for name, source in sources.items():
    for match in re.finditer(r"private\s+(?:val|var)\s+\w+[^\n=]*=\s*[^\n]*getSharedPreferences\(", source):
        eager_prefs.append(f"{name}:{source.count(chr(10), 0, match.start()) + 1}")
if eager_prefs:
    raise SystemExit("RUNTIME_BOOTSTRAP_AUDIT_FAIL eager_preferences=" + ",".join(sorted(eager_prefs)))

checks = {
    "runtime_shell_async": 'fun initializeAsync(context: Context)' in runtime and '"gedefense-runtime-constructor"' in runtime,
    "runtime_constructor_deadline": 'RUNTIME_BOOTSTRAP_DEADLINE_MS = 12_000L' in runtime and 'future.get(RUNTIME_BOOTSTRAP_DEADLINE_MS' in runtime,
    "native_helper_deferred": 'launchEnrichment("gaianet-helper", nativeGaiaNetBootstrap)' in runtime and 'NativeGaiaNet.initialize(app)' not in runtime,
    "native_helper_readiness": 'ProtectionMode.FULL_FLOW_BETA -> awaitLatch(nativeGaiaNetBootstrap, timeoutMillis)' in runtime,
    "critical_stages_bounded": 'CRITICAL_BOOTSTRAP_STAGE_TIMEOUT_MS = 6_000L' in runtime and runtime.count('ArrayBlockingQueue(CRITICAL_BOOTSTRAP_STAGES)') >= 2,
    "runtime_worker_bounded": 'ArrayBlockingQueue(WORKER_QUEUE_CAPACITY)' in runtime and 'AbortPolicy()' in runtime,
    "secondary_bootstrap_independent": all(token in runtime for token in (
        'launchEnrichment("vpn-disclosure"',
        'launchTrustStoreBootstrap("firewall-policy"',
        'launchTrustStoreBootstrap("network-discovery-store"',
        'launchTrustStoreBootstrap("port-sentinel-store"',
        'launchTrustStoreBootstrap("titan-policy"',
        'launchTrustStoreBootstrap("app-approvals"',
        'launchTrustStoreBootstrap("xdr-persistence"',
    )),
    "trust_latch_rejection_safe": 'if (!accepted) xdrTrustBootstrap.countDown()' in runtime,
    "runtime_state_async_preferences": 'scheduleInitialLoad()' in state and 'appContext.getSharedPreferences(PREFERENCES_NAME' in state and 'private val preferences =' not in state,
    "runtime_state_durable_start_gate": 'fun awaitDurableState(timeoutMillis: Long): Boolean' in state and 'persistenceLoadHealthy' in state and 'persistenceWriteHealthy' in state,
    "runtime_state_security_modes_fail_closed": all(token in state for token in (
        'private fun <T : Enum<T>> readPersistedEnum(',
        'if (!preferences.contains(key)) return defaultValue',
        'throw IllegalStateException("persisted security mode invalid", error)',
    )) and '.getOrDefault(WireGuardEgressMode.DIRECT)' not in state and '.getOrDefault(PrivacyProfile.CONSERVATIVE)' not in state,
    "runtime_state_configuration_freeze": 'ReentrantLock()' in state and 'beginProtectionStartTransition(timeoutMillis: Long)' in state and 'CONFIGURATION_LOCKED_VPN_STATES = setOf("STARTING", "RECOVERING")' in state,
    "setup_async_preferences": 'appContext.getSharedPreferences(PREFS' in setup and 'private val prefs =' not in setup and 'private val cached = AtomicReference' in setup,
    "vault_initialize_context_only": 'fun initialize(context: android.content.Context) {\n        WrappedHotPathKeys.initialize(context)\n        PersistentVaultKeys.initialize(context)\n    }' in vault,
    "wrapped_initialize_context_only": 'fun initialize(context: Context) {\n        appContext = context.applicationContext\n    }' in wrapped,
    "persistent_initialize_context_only": 'fun initialize(context: Context) {\n        appContext = context.applicationContext\n    }' in persistent,
    "keystore_deadline_circuit": all(token in keystore for token in ('OPERATION_TIMEOUT_MILLIS = 5_000L','SynchronousQueue()','ReentrantLock(true)','circuitOpen','future.get')),
}

failed = [name for name, ok in checks.items() if not ok]
if failed:
    raise SystemExit("RUNTIME_BOOTSTRAP_AUDIT_FAIL " + ",".join(failed))

print(f"RUNTIME_BOOTSTRAP_AUDIT_PASS kotlin_files={len(sources)} eager_preferences=0")
