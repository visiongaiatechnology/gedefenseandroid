#!/usr/bin/env bash
# STATUS: PLATIN
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
JAVA_BIN="${JAVA_BIN:-${JAVA_HOME:+$JAVA_HOME/bin/java}}"
JAVA_BIN="${JAVA_BIN:-$(command -v java 2>/dev/null || true)}"
JAVAC_BIN="${JAVAC_BIN:-${JAVA_HOME:+$JAVA_HOME/bin/javac}}"
JAVAC_BIN="${JAVAC_BIN:-$(command -v javac 2>/dev/null || true)}"
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
: "${ANDROID_SDK_ROOT:?ANDROID_SDK_ROOT is required}"
[[ -x "$JAVA_BIN" && -x "$JAVAC_BIN" ]] || { echo 'CLASS_INIT_PROBE_FAIL jdk17_missing' >&2; exit 1; }
ANDROID_JAR="$ANDROID_SDK_ROOT/platforms/android-36/android.jar"
[[ -f "$ANDROID_JAR" ]] || { echo 'CLASS_INIT_PROBE_FAIL android36_missing' >&2; exit 1; }
APP_CLASSES="$ROOT/app/build/tmp/kotlin-classes/release"
CORE_CLASSES="$ROOT/core/build/classes/kotlin/main"
[[ -d "$APP_CLASSES" && -d "$CORE_CLASSES" ]] || { echo 'CLASS_INIT_PROBE_FAIL release_classes_missing' >&2; exit 1; }
KOTLIN_CACHE_DIR="${GRADLE_USER_HOME:-$HOME/.gradle}/caches/modules-2/files-2.1/org.jetbrains.kotlin/kotlin-stdlib/1.9.24"
if [[ -d "$KOTLIN_CACHE_DIR" ]]; then
  KOTLIN_STDLIB="$(find "$KOTLIN_CACHE_DIR" -type f -name 'kotlin-stdlib-1.9.24.jar' -print -quit 2>/dev/null || true)"
else
  KOTLIN_STDLIB="$(find "${GRADLE_USER_HOME:-$HOME/.gradle}/caches" -type f -name 'kotlin-stdlib-1.9.24.jar' -print -quit 2>/dev/null || true)"
fi
[[ -f "$KOTLIN_STDLIB" ]] || { echo 'CLASS_INIT_PROBE_FAIL kotlin_stdlib_missing' >&2; exit 1; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/ClassInitProbe.java" <<'JAVA'
public final class ClassInitProbe {
  public static void main(String[] args) throws Exception {
    String[] names = {
      "de.visiongaia.gedefense.mobile.VaultMigrationPolicy",
      "de.visiongaia.gedefense.mobile.BetaVaultMigrationPolicy",
      "de.visiongaia.gedefense.mobile.AndroidSecrets",
      "de.visiongaia.gedefense.mobile.AndroidKeystoreGate",
      "de.visiongaia.gedefense.mobile.SecureTelemetryVault",
      "de.visiongaia.gedefense.mobile.WrappedHotPathKeys",
      "de.visiongaia.gedefense.mobile.HardwareDerivedVaultKeys",
      "de.visiongaia.gedefense.mobile.AppRuntime",
      "de.visiongaia.gedefense.mobile.core.BoundedSecretKeyCrypto",
      "de.visiongaia.gedefense.mobile.core.AuthenticatedSnapshotStore"
    };
    for (String name : names) {
      Class.forName(name, true, ClassInitProbe.class.getClassLoader());
      System.out.println("CLASS_INIT_PASS " + name);
    }
  }
}
JAVA
CP="$APP_CLASSES:$CORE_CLASSES:$ANDROID_JAR:$KOTLIN_STDLIB"
"$JAVAC_BIN" -cp "$CP" -d "$TMP" "$TMP/ClassInitProbe.java"
"$JAVA_BIN" -cp "$TMP:$CP" ClassInitProbe
printf '%s\n' 'JVM_CLASS_INIT_PROBE_PASS classes=10'
