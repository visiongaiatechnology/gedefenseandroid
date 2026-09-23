#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import uuid

ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
TOOLCHAINS = {}
for raw in (ROOT / "TOOLCHAINS.lock").read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, v = line.split("=", 1)
    TOOLCHAINS[k.strip()] = v.strip()

serial = uuid.uuid5(uuid.NAMESPACE_URL, f"https://visiongaia.dev/gedefense/mobile/{VERSION}/vc55/sbom")

def comp(ref: str, typ: str, name: str, version: str, purl: str | None = None, licenses: list[str] | None = None):
    out = {"type": typ, "bom-ref": ref, "name": name, "version": version}
    if purl:
        out["purl"] = purl
    if licenses:
        out["licenses"] = [{"license": {"id": x}} for x in licenses]
    return out

components = [
    comp("pkg:generic/visiongaia/gedefense-mobile@" + VERSION, "application", "VGT GeDefense Mobile", VERSION, "pkg:generic/visiongaia/gedefense-mobile@" + VERSION),
    comp("pkg:generic/visiongaia/gedefense-core@" + VERSION, "library", "GeDefense Core", VERSION, "pkg:generic/visiongaia/gedefense-core@" + VERSION),
    comp("pkg:golang/visiongaia.dev/gedefense/mobile/netstack@" + VERSION, "application", "GaiaNet V2 Android Helper", VERSION, "pkg:golang/visiongaia.dev/gedefense/mobile/netstack@" + VERSION),
    comp("pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@1.9.24", "library", "Kotlin Standard Library", "1.9.24", "pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@1.9.24", ["Apache-2.0"]),
    comp("pkg:golang/golang.zx2c4.com/wireguard@0.0.20250522", "library", "wireguard-go", "0.0.20250522", "pkg:golang/golang.zx2c4.com/wireguard@0.0.20250522", ["MIT"]),
    comp("pkg:golang/golang.org/x/crypto@v0.37.0", "library", "golang.org/x/crypto", "v0.37.0", "pkg:golang/golang.org/x/crypto@v0.37.0", ["BSD-3-Clause"]),
    comp("pkg:golang/golang.org/x/net@v0.39.0", "library", "golang.org/x/net", "v0.39.0", "pkg:golang/golang.org/x/net@v0.39.0", ["BSD-3-Clause"]),
    comp("pkg:golang/golang.org/x/sys@v0.32.0", "library", "golang.org/x/sys", "v0.32.0", "pkg:golang/golang.org/x/sys@v0.32.0", ["BSD-3-Clause"]),
    comp("pkg:golang/golang.org/x/term@v0.31.0", "library", "golang.org/x/term", "v0.31.0", "pkg:golang/golang.org/x/term@v0.31.0", ["BSD-3-Clause"]),
    comp("pkg:golang/golang.org/x/text@v0.24.0", "library", "golang.org/x/text", "v0.24.0", "pkg:golang/golang.org/x/text@v0.24.0", ["BSD-3-Clause"]),
]

tools = [
    comp("tool:gradle", "application", "Gradle", TOOLCHAINS["gradle"]),
    comp("tool:agp", "application", "Android Gradle Plugin", TOOLCHAINS["android_gradle_plugin"]),
    comp("tool:kotlin-gradle", "application", "Kotlin Gradle Plugin", TOOLCHAINS["kotlin_gradle_plugin"]),
    comp("tool:go", "application", "Go", TOOLCHAINS["go"]),
    comp("tool:android-ndk", "application", "Android NDK", TOOLCHAINS["android_ndk"]),
    comp("tool:android-platform", "framework", "Android Platform", TOOLCHAINS["compile_sdk"]),
    comp("tool:jdk", "application", "JDK target", TOOLCHAINS["java_target"]),
]

deps = [
    {"ref": components[0]["bom-ref"], "dependsOn": [components[1]["bom-ref"], components[2]["bom-ref"], components[3]["bom-ref"]]},
    {"ref": components[1]["bom-ref"], "dependsOn": []},
    {"ref": components[2]["bom-ref"], "dependsOn": [c["bom-ref"] for c in components[4:]]},
]
for c in components[3:]:
    deps.append({"ref": c["bom-ref"], "dependsOn": []})

bom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": f"urn:uuid:{serial}",
    "version": 1,
    "metadata": {
        "component": components[0],
        "tools": {"components": tools},
        "properties": [
            {"name": "visiongaia:versionCode", "value": "55"},
            {"name": "visiongaia:compileSdk", "value": TOOLCHAINS["compile_sdk"]},
            {"name": "visiongaia:targetSdk", "value": TOOLCHAINS["target_sdk"]},
            {"name": "visiongaia:minSdk", "value": TOOLCHAINS["min_sdk"]},
            {"name": "visiongaia:goDependencyMode", "value": "offline-local-replace"},
        ],
    },
    "components": components[1:],
    "dependencies": deps,
}

out = ROOT / "SBOM.cdx.json"
out.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"SBOM_GENERATED components={len(components)} tools={len(tools)} path={out.name}")
