# Contributing to GeDefense Mobile

GeDefense is an endpoint-security project. Correctness, containment and auditability have priority over feature count.

## Before opening a change

1. Keep changes scoped and modular. Do not merge unrelated refactors into security fixes.
2. Do not add analytics, advertising, dynamic code loading, WebView, remote-control backends or broad third-party runtime dependencies.
3. Treat packet/file/package/network input as hostile and keep allocations, queues, traversal and parser work bounded.
4. Do not weaken fail-closed paths to improve UI success rates.
5. Do not commit signing keys, secrets, private captures, real device identifiers or unsanitized diagnostics.

## Required local checks

Run:

```bash
bash tools/release-readiness.sh
```

For Android changes also run the pinned Gradle build/lint commands in [`BUILD-RUNBOOK.md`](BUILD-RUNBOOK.md). Changes to `netstack/` must pass Go race tests and the reproducible packaged-helper comparison.

## Pull requests

Describe the threat model, blast radius, user-visible behavior, tests performed and any Android/OEM behavior that still requires real-device verification. Security-impacting changes should include a regression test or an explicit machine-verifiable audit invariant.

## Security reports

**Security contact:** [security@visiongaia.de](mailto:security@visiongaia.de)

Do not publish exploitable vulnerabilities before a fix is available. Use private vulnerability reporting when enabled. See [`SECURITY.md`](SECURITY.md).
