# GeDefense Mobile vendored Go transport provenance

These sources are vendored to make the Android GaiaNet/WireGuard build reproducible and offline.

- wireguard-go: upstream tag `0.0.20250522`, module `golang.zx2c4.com/wireguard`
- golang.org/x/crypto: `v0.37.0`
- golang.org/x/net: `v0.39.0`
- golang.org/x/sys: `v0.32.0`
- golang.org/x/text: `v0.24.0`
- golang.org/x/term: `v0.31.0`

WireGuard cryptography is upstream code. GeDefense does not reimplement WireGuard cryptographic primitives.
