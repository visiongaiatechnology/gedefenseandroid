#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
command -v kotlinc >/dev/null 2>&1 || { echo 'INSTALL_GUARD_POLICY_CHECK_FAIL kotlinc_unavailable' >&2; exit 1; }
command -v java >/dev/null 2>&1 || { echo 'INSTALL_GUARD_POLICY_CHECK_FAIL java_unavailable' >&2; exit 1; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/TestMain.kt" <<'KT'
package de.visiongaia.gedefense.mobile

fun main() {
    fun checkVerdict(name: String, input: InstallFastPolicyInput, expected: InstallFastVerdict) {
        check(InstallGuardPolicy.fastVerdict(input) == expected) { name }
    }
    checkVerdict("new_install_hold", InstallFastPolicyInput(true,false,false,true,false,false,InstallFastRisk.LOW), InstallFastVerdict.HOLD_FOR_DEEP)
    checkVerdict("known_update_release", InstallFastPolicyInput(true,false,false,true,true,false,InstallFastRisk.LOW), InstallFastVerdict.RELEASE_PENDING_DEEP)
    checkVerdict("block_threat", InstallFastPolicyInput(true,true,false,true,true,false,InstallFastRisk.LOW), InstallFastVerdict.BLOCK)
    checkVerdict("review_hold", InstallFastPolicyInput(true,false,false,true,true,false,InstallFastRisk.REVIEW), InstallFastVerdict.HOLD_FOR_DEEP)
    checkVerdict("correlate_hold", InstallFastPolicyInput(true,false,true,true,true,false,InstallFastRisk.LOW), InstallFastVerdict.HOLD_FOR_DEEP)
    checkVerdict("stale_hold", InstallFastPolicyInput(true,false,false,true,true,true,InstallFastRisk.LOW), InstallFastVerdict.HOLD_FOR_DEEP)
    check(BoundedInstallScanCall.fast { 42 } == 42)
    val started = System.nanoTime()
    val reason = try {
        BoundedInstallScanCall.fast { Thread.sleep(4_000); 1 }
        "missing"
    } catch (e: InstallScanUnavailableException) { e.reasonCode }
    check(reason == "install_fast_timeout") { reason }
    val elapsedMs = (System.nanoTime() - started) / 1_000_000
    check(elapsedMs in 1_500..3_000) { "fast_timeout_elapsed=$elapsedMs" }
    println("INSTALL_GUARD_POLICY_CHECK_PASS fast_timeout_ms=$elapsedMs")
}
KT
kotlinc -jvm-target 17 \
  "$ROOT/app/src/main/java/de/visiongaia/gedefense/mobile/InstallGuardPolicy.kt" \
  "$ROOT/app/src/main/java/de/visiongaia/gedefense/mobile/BoundedInstallScanCall.kt" \
  "$TMP/TestMain.kt" -include-runtime -d "$TMP/install-guard-policy.jar"
java -jar "$TMP/install-guard-policy.jar"
