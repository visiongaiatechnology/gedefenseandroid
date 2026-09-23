#!/usr/bin/env python3
# STATUS: PLATIN
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / 'app/src/main/java/de/visiongaia/gedefense/mobile'


def text(name: str) -> str:
    p = JAVA / name
    if not p.is_file():
        raise SystemExit(f'MAIN_THREAD_IO_AUDIT_FAIL missing={name}')
    return p.read_text(encoding='utf-8')

sources = {p.name: p.read_text(encoding='utf-8') for p in JAVA.glob('*.kt')}
lifecycle_names = [
    name for name in sources
    if name.endswith('Activity.kt') or name.endswith('Receiver.kt') or name in {'GeDefenseApplication.kt', 'GeDefenseVpnService.kt'}
]
lifecycle = {name: sources[name] for name in lifecycle_names}

# AppRuntime.get() can synchronously initialize off-main and intentionally rejects the Android main
# thread when the runtime is not ready. Lifecycle/UI code must therefore use cached runtime state or
# RuntimeActivityEntry/executeWhenReady rather than racing process startup.
direct_runtime_get = [name for name, src in sources.items() if name != 'AppRuntime.kt' and 'AppRuntime.get(' in src]
if direct_runtime_get:
    raise SystemExit('MAIN_THREAD_IO_AUDIT_FAIL direct_runtime_get=' + ','.join(sorted(direct_runtime_get)))

# No cryptographic provider or authenticated-store construction belongs in Android lifecycle code.
crypto_patterns = (
    'AndroidSecrets.', 'AndroidKeystoreGate.', 'SecureTelemetryVault.', 'SecureSnapshotStore(',
    'KeyStore.getInstance(', 'Mac.getInstance(', 'Cipher.getInstance(',
)
crypto_hits = [
    f'{name}:{token}' for name, src in lifecycle.items() for token in crypto_patterns if token in src
]
if crypto_hits:
    raise SystemExit('MAIN_THREAD_IO_AUDIT_FAIL lifecycle_crypto=' + ','.join(sorted(crypto_hits)))

# Lifecycle paths must not synchronously hit SharedPreferences. RuntimeState/DeviceSetupManager own
# cached snapshots and bounded background persistence instead.
pref_hits = [
    name for name, src in lifecycle.items()
    if 'getSharedPreferences(' in src or re.search(r'\.edit\(\)\s*(?:\.|\n)', src)
]
if pref_hits:
    raise SystemExit('MAIN_THREAD_IO_AUDIT_FAIL lifecycle_preferences=' + ','.join(sorted(pref_hits)))

boot = text('BootReceiver.kt')
for token in ('goAsync()', 'BOOT_EXECUTOR.execute', 'BoundedExecutors.fixed', 'ThreatIntelJobs.schedule', 'IntegrityJobs.schedule', 'pending.finish()'):
    if token not in boot:
        raise SystemExit(f'MAIN_THREAD_IO_AUDIT_FAIL boot_receiver={token}')

titan_admin = text('TitanDeviceAdminReceiver.kt')
for token in ('goAsync()', 'runtime.executeBackground("titan-admin-event")', 'BoundedAndroidCall.call', 'pending.finish()'):
    if token not in titan_admin:
        raise SystemExit(f'MAIN_THREAD_IO_AUDIT_FAIL titan_admin={token}')

compliance = text('TitanPolicyComplianceActivity.kt')
for token in ('COMPLIANCE_EXECUTOR.execute', 'BoundedExecutors.direct', 'BoundedAndroidCall.call', 'runOnUiThread'):
    if token not in compliance:
        raise SystemExit(f'MAIN_THREAD_IO_AUDIT_FAIL titan_compliance={token}')

application = text('GeDefenseApplication.kt')
if 'processBootstrap.execute' not in application or 'ThreatIntelJobs.schedule(this)' not in application:
    raise SystemExit('MAIN_THREAD_IO_AUDIT_FAIL application_job_scheduler')

runtime_entry = text('RuntimeActivityEntry.kt')
for token in ('AppRuntime.peek()', 'AppRuntime.initializeAsync', 'StartupActivity::class.java', 'activity.finish()'):
    if token not in runtime_entry:
        raise SystemExit(f'MAIN_THREAD_IO_AUDIT_FAIL activity_entry={token}')

# Every internal specialist Activity that owns an AppRuntime field must go through the non-blocking
# Activity boundary. MainActivity already has an equivalent explicit peek/redirect path.
for name, src in sources.items():
    if not name.endswith('Activity.kt') or 'private lateinit var runtime: AppRuntime' not in src:
        continue
    if name in {'MainActivity.kt', 'StartupActivity.kt'}:
        continue
    if 'RuntimeActivityEntry.requireReady(this) ?: return' not in src:
        raise SystemExit(f'MAIN_THREAD_IO_AUDIT_FAIL activity_runtime_gate={name}')

# JDK convenience executors hide unbounded queues; all app workers must state capacity explicitly.
unbounded = [
    name for name, src in sources.items()
    if re.search(r'Executors\.new(?:FixedThreadPool|SingleThreadExecutor|CachedThreadPool|SingleThreadScheduledExecutor|ScheduledThreadPool)', src)
]
if unbounded:
    raise SystemExit('MAIN_THREAD_IO_AUDIT_FAIL unbounded_executor=' + ','.join(sorted(unbounded)))

print(f'MAIN_THREAD_IO_AUDIT_PASS lifecycle_files={len(lifecycle)}')
