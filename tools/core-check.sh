#!/usr/bin/env bash
# STATUS: DIAMANT VGT SUPREME
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${TMPDIR:-/tmp}/gedefense-mobile-core-tests.jar"
rm -f "$OUT"

if command -v kotlinc >/dev/null 2>&1; then
  kotlinc -jvm-target 17 \
    $(find "$ROOT/core/src/main/kotlin" -name '*.kt' -print) \
    $(find "$ROOT/core/src/test/kotlin" -name '*.kt' -print) \
    -include-runtime -d "$OUT"
  java -jar "$OUT"
  rm -f "$OUT"
elif command -v gradle >/dev/null 2>&1; then
  (
    cd "$ROOT"
    gradle --offline --no-daemon :core:coreCheck
  )
elif [[ -x "$ROOT/gradlew" ]]; then
  (
    cd "$ROOT"
    "$ROOT/gradlew" --offline --no-daemon :core:coreCheck
  )
else
  echo "CORE_CHECK_FAIL no Kotlin compiler or Gradle runtime available" >&2
  exit 1
fi
