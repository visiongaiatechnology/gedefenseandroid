# Build Runbook — 0.27.8-beta.5

## Required toolchain

- JDK 17
- Android SDK Platform 36 (revision 2, verified package) for compileSdk/targetSdk 36
- Android Build Tools 34.0.0+
- Gradle 8.7
- Go 1.26.8
- Git Bash on Windows for mandatory shell security gates

Android NDK `27.2.12479018` is required for the x86_64 Android GaiaNet helper with Go 1.26.8 because `android/amd64` requires external linking. arm64 remains `CGO_ENABLED=0`. The NDK is a build-time linker requirement for x86_64, not a JNI WireGuard backend and not a runtime dependency injection point.

Install the exact side-by-side NDK revision through the Android SDK manager; do not substitute a newer NDK during a release freeze:

```bash
sdkmanager "ndk;27.2.12479018"
grep -E '^Pkg\.Revision = 27\.2\.12479018$' "$ANDROID_SDK_ROOT/ndk/27.2.12479018/source.properties"
```

The corresponding upstream release is NDK r27c. For reproducible CI, `.github/workflows/verify.yml` installs this exact revision and checks `source.properties` before any Android release gate runs.

For controlled or air-gapped builds, an optional Maven mirror can be supplied with `VGT_LOCAL_MAVEN`. The repository configuration contains no machine-specific absolute path; when the variable is unset, Gradle uses the pinned public repositories declared in `settings.gradle.kts`. Example:

```powershell
$env:VGT_LOCAL_MAVEN = "C:\vgt-build-cache\maven"
```

The mirror is build infrastructure only. It must contain byte-identical pinned artifacts and does not change runtime dependencies.

## Pinned Gradle distribution

`gradle-8.7-bin.zip` SHA-256:

```text
544c35d6bd849ae8a5ed0bcea39ba677dc40f49df7d1835561582da2009b961d
```

## Source/security gates

```bash
bash tools/release-readiness.sh
bash tools/wireguard-parser-check.sh
python3 tools/wireguard-audit.py
bash tools/wireguard-upstream-check.sh
cd netstack
go mod verify
go vet ./...
go test -race ./...
go test -tags=gdandroidhelper ./...
```

The security audit rebuilds both GaiaNet V2 helpers from source and byte-compares them with the packaged ABI artifacts. It also enforces `DIAGNOSTICS_RESILIENCE_PASS` for aggregate-only support exports and persisted resilience self-test results. It also validates the process/Fd-transfer boundary, transport budgets, feed authority, VPN/Lockdown semantics, authenticated state, XDR/EDR/NDR, Port Sentinel, UI performance invariants and TITAN Device Owner contracts.

## Build GaiaNet V2

```powershell
PowerShell -ExecutionPolicy Bypass -File .\tools\build-go-netstack.ps1
```

The script requires Go 1.26.8, the pinned in-tree Go dependency snapshot and NDK `27.2.12479018` for x86_64. It builds:

```text
app\src\main\jniLibs\arm64-v8a\libgedefense_gaianet_v2.so
app\src\main\jniLibs\x86_64\libgedefense_gaianet_v2.so
```

These files are stripped executable helpers. The transport implementation is Go; arm64 is linked pure-Go and x86_64 uses the pinned Android NDK only for the Go toolchain's required external link. The `.so` suffix is used so Android extracts them into `nativeLibraryDir`; `NativeGaiaNet` executes them as child processes and does not `System.loadLibrary` them.

## Android build

```powershell
gradlew.bat --no-daemon clean :core:coreCheck :app:assembleDebug
gradlew.bat --no-daemon :app:lintDebug
```

For a distributable release, provide the four release-signing environment variables consumed by `app/build.gradle.kts`, then run `:app:assembleRelease :app:bundleRelease :app:lintRelease`. Never distribute a debug-signed Device Owner build as the production identity.

## Controlled Windows beta build

```powershell
PowerShell -ExecutionPolicy Bypass -File .\tools\windows-build-beta.ps1
```

The controlled script performs source/security gates, reproducible GaiaNet V2 helper builds, Android compile/lint, packaged-helper audit and APK hashing.

## Real-device gates

TITAN and Full Flow cannot be proven by JVM/Gradle gates alone. Before stable promotion, validate the release-signed APK on disposable real hardware across helper execution, sustained throughput, Wi-Fi/cellular handover, Doze, OEM VPN behavior, Device Owner provisioning, package suspension, Always-on lockdown, restrictions, managed uninstall callback, password policy and managed CA installation. Never test destructive wipe policy on a device containing required data.
