# Supply-Chain Model

GeDefense minimizes runtime dependencies and treats build tooling as an explicit trust input.

## Runtime

- Android platform APIs and Kotlin standard library.
- In-tree `:core` module.
- In-tree GaiaNet V2 helper plus pinned, vendored upstream `wireguard-go 0.0.20250522`.
- Pinned vendored Go support modules: `golang.org/x/crypto v0.37.0`, `x/net v0.39.0`, `x/sys v0.32.0`, `x/term v0.31.0`, `x/text v0.24.0`. Release builds resolve them only through local `replace` directives with `GOPROXY=off` / `GOSUMDB=off`.
- No analytics, advertising, remote configuration, WebView runtime, Retrofit/OkHttp/Room or third-party Android VPN/tun2socks SDK. WireGuard cryptographic primitives are upstream `wireguard-go`/Go crypto code, not a GeDefense reimplementation.

`tools/go-supply-chain-reachability-audit.py` freezes the exact external Go package surface compiled into the Android helper. The 2026 advisory review found known issues in older vendored module versions only in packages that are not reachable from the helper (`x/crypto/ssh`, `x/net/html`, `x/net/dns/dnsmessage`, `x/net/http2`, `x/net/idna`, `x/text/unicode/norm`, `x/sys/windows`). The gate fails if any reviewed advisory package becomes reachable. Go itself is pinned to 1.26.8, which contains the standard-library fixes relevant to this build.

## Pinned build inputs

The authoritative versions and hashes live in `TOOLCHAINS.lock`. Gradle 8.7's distribution SHA-256 is embedded in `gradle-wrapper.properties` so wrapper downloads are integrity checked.

## Native provenance

`tools/security-audit.sh` rebuilds arm64 and x86_64 GaiaNet helpers with deterministic flags and byte-compares them to the packaged APK inputs. It additionally parses ELF program headers and rejects PT_LOAD alignment below 16 KiB.

## Release keys

Release signing material is never committed. Builds consume signing values from the controlled release environment. Public source releases must remain buildable without access to the private release key.

## GitHub automation

CI is verification-only and receives read-only repository contents permission. Release signing must not be performed in pull-request workflows. GitHub Actions pins the Java and Go setup actions by immutable commit SHA, selects JDK 17 and Go 1.26.8 explicitly, installs Android Platform 36 / Build Tools 36.0.0 plus side-by-side NDK `27.2.12479018`, verifies the installed NDK revision from `source.properties`, and only then runs Android release/lint plus the full release-readiness chain.

## SBOM

`SBOM.cdx.json` is a deterministic CycloneDX 1.6 inventory of GeDefense Mobile, Core, GaiaNet, Kotlin runtime, vendored Go modules and the pinned release toolchains. `tools/sbom-audit.py` regenerates it and requires byte identity plus the expected vendored license files.
