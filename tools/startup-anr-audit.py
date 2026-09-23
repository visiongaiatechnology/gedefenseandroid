# STATUS: DIAMANT VGT SUPREME
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def source(relative: str) -> str:
    path = ROOT / relative
    if not path.is_file():
        raise SystemExit(f"STARTUP_ANR_AUDIT_FAIL missing={relative}")
    return path.read_text(encoding="utf-8")


application = source("app/src/main/java/de/visiongaia/gedefense/mobile/GeDefenseApplication.kt")
runtime = source("app/src/main/java/de/visiongaia/gedefense/mobile/AppRuntime.kt")
startup = source("app/src/main/java/de/visiongaia/gedefense/mobile/StartupActivity.kt")
service = source("app/src/main/java/de/visiongaia/gedefense/mobile/GeDefenseVpnService.kt")
disclosure_store = source("app/src/main/java/de/visiongaia/gedefense/mobile/VpnDisclosureStore.kt")
disclosure_activity = source("app/src/main/java/de/visiongaia/gedefense/mobile/VpnDisclosureActivity.kt")
runtime_state = source("app/src/main/java/de/visiongaia/gedefense/mobile/RuntimeState.kt")
setup = source("app/src/main/java/de/visiongaia/gedefense/mobile/DeviceSetupManager.kt")
bounded_executors = source("app/src/main/java/de/visiongaia/gedefense/mobile/BoundedExecutors.kt")
bounded_scheduler = source("app/src/main/java/de/visiongaia/gedefense/mobile/BoundedSerialScheduler.kt")
authenticated_store = source("core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/AuthenticatedSnapshotStore.kt")
opaque_crypto = source("core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/BoundedSecretKeyCrypto.kt")
keystore_gate = source("app/src/main/java/de/visiongaia/gedefense/mobile/AndroidKeystoreGate.kt")
secrets = source("app/src/main/java/de/visiongaia/gedefense/mobile/AndroidSecrets.kt")
derived_keys = source("app/src/main/java/de/visiongaia/gedefense/mobile/HardwareDerivedVaultKeys.kt")
wrapped_keys = source("app/src/main/java/de/visiongaia/gedefense/mobile/WrappedHotPathKeys.kt")
persistent_keys = source("app/src/main/java/de/visiongaia/gedefense/mobile/PersistentVaultKeys.kt")
storage_scanner = source("app/src/main/java/de/visiongaia/gedefense/mobile/StorageMalwareScanner.kt")

app_source_root = ROOT / "app/src/main/java/de/visiongaia/gedefense/mobile"
all_kotlin = {p.name: p.read_text(encoding="utf-8") for p in app_source_root.glob("*.kt")}
allowed_direct_hmac = {"AndroidSecrets.kt", "HardwareDerivedVaultKeys.kt", "PersistentVaultKeys.kt"}
unsafe_constructor_hmac = [
    name for name, text in all_kotlin.items()
    if name not in allowed_direct_hmac and "AndroidSecrets.hmacSha256(" in text
]
unbounded_executor_factories = [
    name for name, text in all_kotlin.items()
    if re.search(r"Executors\.new(?:FixedThreadPool|SingleThreadExecutor|CachedThreadPool|SingleThreadScheduledExecutor|ScheduledThreadPool)", text)
]

# Lifecycle teardown must not perform authenticated persistence/process waits synchronously.
on_destroy_match = re.search(r"override fun onDestroy\(\) \{(?P<body>.*?)\n    \}\n\n    private fun destroyCleanup", service, re.S)
on_destroy = on_destroy_match.group("body") if on_destroy_match else ""

lazy_runtime_components = [
    "geoCountry", "fullFlowAnalytics", "originLocator", "setup", "vpnDisclosure",
    "firewallPolicy", "networkDiscoveryStore", "portSentinelStore", "titan",
    "appApprovals", "xdr", "behavior", "hardeningScanner", "malwareAnalysisStore",
    "appRiskScanner", "storageMalwareScanner", "deviceSecurityScanner", "trafficUsage",
]

checks = {
    "application_async_runtime": "AppRuntime.initializeAsync(this)" in application,
    "application_jobs_off_main": "processBootstrap.execute" in application and "ThreatIntelJobs.schedule(this)" in application,
    "application_no_sync_vault": "SecureTelemetryVault.initialize(this)" not in application,
    "runtime_dedicated_initializer": '"gedefense-runtime-init"' in runtime and '"gedefense-runtime-constructor"' in runtime,
    "runtime_main_thread_guard": "AppRuntime is not ready on the Android main thread" in runtime,
    "runtime_worker_bounded": "ArrayBlockingQueue(WORKER_QUEUE_CAPACITY)" in runtime,
    "runtime_critical_bootstrap_bounded": runtime.count("ArrayBlockingQueue(CRITICAL_BOOTSTRAP_STAGES)") >= 2,
    "runtime_noncritical_components_lazy": all(f"val {name} by lazy(LazyThreadSafetyMode.SYNCHRONIZED)" in runtime for name in lazy_runtime_components),
    "runtime_store_readiness_latches": all(token in runtime for token in ["nativeGaiaNetBootstrap", "vpnDisclosureBootstrap", "firewallPolicyBootstrap", "portSentinelBootstrap", "awaitProtectionStoreBootstrap"]),
    "runtime_native_helper_off_constructor": 'launchEnrichment("gaianet-helper", nativeGaiaNetBootstrap)' in runtime and "NativeGaiaNet.initialize(app)" not in runtime,
    "startup_renders_before_wait": startup.find("setContentView(buildUi())") < startup.find("AppRuntime.awaitInitialized"),
    "startup_dedicated_gate_thread": '"gedefense-startup-gate"' in startup,
    "startup_no_blocking_get": "AppRuntime.get(this)" not in startup,
    "service_no_blocking_get": "AppRuntime.get(this)" not in service,
    "service_off_main_gate": "submitControl" in service and "ensureRuntimeReady()" in service,
    "service_bounded_control_queue": "BoundedSerialScheduler" in service and "CONTROL_QUEUE_CAPACITY" in service,
    "service_zero_backlog_reader": "BoundedExecutors.direct(\"gedefense-tun\")" in service,
    "service_destroy_main_thread_clean": bool(on_destroy) and all(token not in on_destroy for token in ["closeTransports()", "commitBehaviorSession()", "portSentinelStore.flush()", "portSentinel.close()"]),
    "disclosure_cached_initial_state": "vpn_disclosure_initializing" in disclosure_store and "AtomicReference(" in disclosure_store,
    "disclosure_explicit_initialize": "fun initialize(): VpnDisclosureSnapshot" in disclosure_store,
    "disclosure_ui_async_write": 'executeBackground("vpn-disclosure-accept")' in disclosure_activity,
    "runtime_state_async_persistence": "scheduleInitialLoad()" in runtime_state and "requestFlush()" in runtime_state and "ArrayBlockingQueue(2)" in runtime_state,
    "setup_cached_platform_state": "private val cached = AtomicReference" in setup and "fun snapshot(): DeviceSetupSnapshot = cached.get()" in setup,
    "bounded_executor_library": "ArrayBlockingQueue(queueCapacity)" in bounded_executors and "SynchronousQueue()" in bounded_executors,
    "bounded_delayed_scheduler": "queue.size >= capacity" in bounded_scheduler and "PriorityQueue<Task>()" in bounded_scheduler,
    "no_unbounded_executor_factories": not unbounded_executor_factories,
    "nullable_authenticated_key": "private val key: SecretKey?" in authenticated_store,
    "unavailable_key_invalid": "AuthenticatedSnapshotFailureKind.KEY_UNAVAILABLE" in authenticated_store,
    "key_operation_classified": "AuthenticatedSnapshotFailureKind.KEY_OPERATION" in authenticated_store and "snapshot key operation failed" in authenticated_store,
    "keystore_provider_deadline": "OPERATION_TIMEOUT_MILLIS = 5_000L" in keystore_gate and "circuitOpen" in keystore_gate and "future.get" in keystore_gate,
    "secrets_routed_through_gate": "AndroidKeystoreGate.call" in secrets and "synchronized(lock)" not in secrets,
    "opaque_key_deadline": "BoundedSecretKeyCrypto.execute" in authenticated_store and "opaque key provider timeout" in opaque_crypto,
    "derived_prf_bounded": "AndroidKeystoreGate.call" in derived_keys and "hardwarePrf" in derived_keys,
    "persistent_prf_bounded": "AndroidKeystoreGate.call" in persistent_keys and "rootWrapKey(create: Boolean)" in persistent_keys and "AndroidSecrets.hmacSha256(ROOT_PRF_ALIAS" in persistent_keys,
    "wrapped_aes_bounded": wrapped_keys.count("AndroidKeystoreGate.call") >= 2,
    "runtime_constructor_deadline": "RUNTIME_BOOTSTRAP_DEADLINE_MS = 12_000L" in runtime and "future.get(RUNTIME_BOOTSTRAP_DEADLINE_MS" in runtime,
    "runtime_no_eager_malware_snapshot": "AtomicReference(malwareAnalysisStore.load()" not in runtime,
    "storage_fingerprint_seed_lazy": "fingerprintSeed: ByteArray? by lazy" in storage_scanner and "VaultDomain.SCANNER_STORAGE" in storage_scanner,
    "no_throwable_constructor_hmac": not unsafe_constructor_hmac,
}

failed = [name for name, passed in checks.items() if not passed]
if failed:
    details = []
    if unbounded_executor_factories:
        details.append("unbounded=" + ",".join(sorted(unbounded_executor_factories)))
    if unsafe_constructor_hmac:
        details.append("direct_hmac=" + ",".join(sorted(unsafe_constructor_hmac)))
    suffix = (" " + " ".join(details)) if details else ""
    raise SystemExit("STARTUP_ANR_AUDIT_FAIL " + ",".join(failed) + suffix)

print("STARTUP_ANR_AUDIT_PASS")
