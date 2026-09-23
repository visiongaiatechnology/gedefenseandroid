# Dependencies

## Android runtime

GeDefense Mobile intentionally has no third-party Android runtime libraries.

Application runtime stack:

- Android platform APIs
- Kotlin standard library
- GeDefense `:core`
- in-tree process-isolated GaiaNet V2 helper compiled reproducibly from `netstack/`

Not used:

- AndroidX / Jetpack Compose
- Retrofit / OkHttp
- Room
- analytics/ad/crash-reporting SDKs
- third-party VPN/tun2socks stacks
- third-party cryptographic libraries

## Go runtime

GaiaNet Direct mode remains predominantly standard-library code. Embedded WireGuard uses the official pinned `wireguard-go 0.0.20250522` source plus its pinned `golang.org/x/*` dependencies. All required Go modules are stored under `third_party/go/` and resolved through local `replace` directives; release verification uses `GOPROXY=off` and `GOSUMDB=off` so a release build cannot fetch Go source from the network. Go `1.26.8` is pinned for the beta build.

## Local Geo dataset

GeDefense downloads `user-country-ipv4.csv` and `user-country-ipv6.csv` from `sapics/ip-location-db` at runtime and does not bundle them in the source release. The selected `user-country` data is published under PDDL. Matching upstream SHA-256 assets are verified before local compilation.


## Local ASN evidence dataset

GeDefense downloads the `iptoasn-asn-ipv4.csv` and `iptoasn-asn-ipv6.csv` snapshots distributed by `sapics/ip-location-db`; upstream identity is retained as `IPtoASN`. The ASN data is published under PDDL/Public Domain. Matching release SHA-256 assets are verified before the source is compiled into local IPv4/IPv6 binary indexes and a deduplicated organization table. The dataset is not bundled as an Android runtime dependency, and no per-destination ASN API is used.

## Build-time geographic presentation assets

The APK includes `world_map_ambient.png` and a generated ISO country-centroid table for the offline Data-Flow Atlas. They were generated during development from `countryinfo 0.1.2` (MIT) country geometry/metadata. `countryinfo` is **not** an Android/Go runtime dependency and no Python code ships in the APK. The rendered atlas performs no remote tile/geocoding request.

## Build supply chain

- Android Gradle Plugin `8.5.2`
- Kotlin Gradle Plugin `1.9.24`
- Gradle `8.7`
- JDK 17
- Android NDK `27.2.12479018` — required for the `x86_64` Android helper external link under Go 1.26.8; `arm64-v8a` remains pure Go
- Go `1.26.8`

Build-time plugins/toolchains are supply-chain inputs even when they are not application runtime dependencies.

## Embedded WireGuard

WireGuard egress is integrated behind GaiaNet using vendored upstream `wireguard-go 0.0.20250522`. GeDefense does not implement WireGuard cryptographic primitives. The transport remains subordinate to GeDefense's single-`VpnService` architecture, uses per-socket Android protection rather than a whole-UID bypass, and is not considered release-frozen until the Android/native/artifact/device gates for VC55 pass. Provenance and archive hashes are recorded under `third_party/go/`.
