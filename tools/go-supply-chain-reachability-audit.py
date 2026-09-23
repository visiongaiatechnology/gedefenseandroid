#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
NETSTACK = ROOT / "netstack"
EXPECTED_GO = "go1.26.8"
EXPECTED_TOOLCHAIN_DIRECTIVE = "toolchain go1.26.8"
EXPECTED_MODULES = {
    "golang.org/x/crypto v0.37.0 => ../third_party/go/x-crypto",
    "golang.org/x/net v0.39.0 => ../third_party/go/x-net",
    "golang.org/x/sys v0.32.0 => ../third_party/go/x-sys",
    "golang.org/x/term v0.31.0 => ../third_party/go/x-term",
    "golang.org/x/text v0.24.0 => ../third_party/go/x-text",
    "golang.zx2c4.com/wireguard v0.0.20250522 => ../third_party/go/wireguard-go",
}

# Exact external package surface compiled into the gdandroidhelper target at VC55.
EXPECTED_EXTERNAL_PACKAGES = {
    "golang.org/x/crypto/blake2s",
    "golang.org/x/crypto/chacha20",
    "golang.org/x/crypto/chacha20poly1305",
    "golang.org/x/crypto/curve25519",
    "golang.org/x/crypto/internal/alias",
    "golang.org/x/crypto/internal/poly1305",
    "golang.org/x/crypto/poly1305",
    "golang.org/x/net/bpf",
    "golang.org/x/net/internal/iana",
    "golang.org/x/net/internal/socket",
    "golang.org/x/net/ipv4",
    "golang.org/x/net/ipv6",
    "golang.org/x/sys/cpu",
    "golang.org/x/sys/unix",
}

# Packages with known advisories relevant to the pinned older module versions as reviewed
# on 2026-09-23. None may become reachable in the Android helper without an explicit
# dependency upgrade/review. Standard-library vendored internals are intentionally not
# matched by these module-path prefixes; Go 1.26.8 supplies the patched stdlib.
FORBIDDEN_REACHABLE = {
    "golang.org/x/crypto/ssh": "GO-2026-5014/15/16/17/18/19/20/5023/6303/6354/6355",
    "golang.org/x/crypto/ssh/agent": "GO-2026-5005",
    "golang.org/x/net/dns/dnsmessage": "GO-2026-5942",
    "golang.org/x/net/html": "GO-2026-4440/4441/5025/5027/5028/5029/5030",
    "golang.org/x/net/http2": "GO-2026-4918 and related 2026 HTTP/2 advisories",
    "golang.org/x/net/idna": "GO-2026-5026",
    "golang.org/x/text/unicode/norm": "GO-2026-5970",
    "golang.org/x/sys/windows": "GO-2026-5024",
}

def run(*args: str) -> str:
    env = os.environ.copy()
    env.update({"GOTOOLCHAIN": "local", "GOFLAGS": "-mod=readonly", "GOPROXY": "off", "GOSUMDB": "off"})
    proc = subprocess.run(args, cwd=NETSTACK, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode:
        raise SystemExit(f"command failed ({' '.join(args)}): {proc.stderr.strip()}")
    return proc.stdout

version = run("go", "env", "GOVERSION").strip()
if version != EXPECTED_GO:
    raise SystemExit(f"unexpected Go toolchain: {version}; expected {EXPECTED_GO}")

go_mod = (NETSTACK / "go.mod").read_text(encoding="utf-8")
if EXPECTED_TOOLCHAIN_DIRECTIVE not in go_mod:
    raise SystemExit("go.mod toolchain directive is not pinned to go1.26.8")
if not re.search(r"(?m)^go\s+1\.26\.0\s*$", go_mod):
    raise SystemExit("go.mod language version drifted from reviewed 1.26.0 baseline")

modules = set(run("go", "list", "-m", "all").splitlines())
missing_modules = sorted(EXPECTED_MODULES - modules)
if missing_modules:
    raise SystemExit("reviewed Go module graph mismatch: " + "; ".join(missing_modules))
if len(modules) != 7:
    raise SystemExit(f"unreviewed Go module count: {len(modules)} (expected 7)")

packages = set(run("go", "list", "-deps", "-tags=gdandroidhelper", ".").splitlines())
external = {p for p in packages if p.startswith("golang.org/x/")}
if external != EXPECTED_EXTERNAL_PACKAGES:
    added = sorted(external - EXPECTED_EXTERNAL_PACKAGES)
    removed = sorted(EXPECTED_EXTERNAL_PACKAGES - external)
    raise SystemExit(f"compiled external package surface changed; added={added} removed={removed}")

for package, advisories in FORBIDDEN_REACHABLE.items():
    if package in packages or any(p.startswith(package + "/") for p in packages):
        raise SystemExit(f"known-advisory package became reachable: {package} ({advisories})")

print(
    "GO_SUPPLY_CHAIN_REACHABILITY_PASS "
    f"go={version} modules={len(modules)} external_packages={len(external)} "
    "known_2026_advisory_packages=unreachable offline=true"
)
