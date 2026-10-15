#!/usr/bin/env bash
# STATUS: PLATIN
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
command -v go >/dev/null 2>&1 || { echo 'WIREGUARD_UPSTREAM_CHECK_FAIL go_unavailable' >&2; exit 1; }

for module in wireguard-go x-crypto x-net x-sys x-term x-text; do
  [[ -f "$ROOT/third_party/go/$module/go.mod" ]] || {
    echo "WIREGUARD_UPSTREAM_CHECK_FAIL missing_vendor_module=$module" >&2
    exit 1
  }
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/go.mod" <<EOF
module visiongaia.dev/gedefense/mobile/wireguard-upstream-check

go 1.26.0

require (
    golang.zx2c4.com/wireguard v0.0.20250522
    golang.org/x/crypto v0.37.0
    golang.org/x/net v0.39.0
    golang.org/x/sys v0.32.0
    golang.org/x/term v0.31.0
    golang.org/x/text v0.24.0
)

replace golang.zx2c4.com/wireguard => $ROOT/third_party/go/wireguard-go
replace golang.org/x/crypto => $ROOT/third_party/go/x-crypto
replace golang.org/x/net => $ROOT/third_party/go/x-net
replace golang.org/x/sys => $ROOT/third_party/go/x-sys
replace golang.org/x/term => $ROOT/third_party/go/x-term
replace golang.org/x/text => $ROOT/third_party/go/x-text
EOF

cd "$TMP"
# This must be a genuinely offline gate: if a dependency escapes the vendored set, fail rather
# than quietly making the release depend on whatever the network happens to serve that day.
GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test \
  golang.zx2c4.com/wireguard/device \
  golang.zx2c4.com/wireguard/replay \
  golang.zx2c4.com/wireguard/ratelimiter

echo 'WIREGUARD_UPSTREAM_CHECK_PASS offline=true packages=device,replay,ratelimiter'
