#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPECTED_BUN="1.3.14"
EXPECTED_BUN_SHA256="e0c90ec15d33363e6b70713d56bc3b2c7585c17f40a0fe0f8fd9305901d4e233"
EXPECTED_UI_SHA256="af4c787730e125b98535e50cc1ac818410083a529411006c2ef29af305c15fd2"

[[ -x "$ROOT/.cache/tools/bun-$EXPECTED_BUN/bun" ]] || {
  printf 'FAIL sunaba-ui - missing project-local Bun %s at .cache/tools/bun-%s/bun\n' "$EXPECTED_BUN" "$EXPECTED_BUN" >&2
  exit 1
}
BUN="$ROOT/.cache/tools/bun-$EXPECTED_BUN/bun"
[[ "$($BUN --version)" == "$EXPECTED_BUN" ]] || {
  printf 'FAIL sunaba-ui - project-local Bun version mismatch\n' >&2
  exit 1
}
[[ "$(shasum -a 256 "$BUN" | awk '{print $1}')" == "$EXPECTED_BUN_SHA256" ]] || {
  printf 'FAIL sunaba-ui - project-local Bun digest mismatch\n' >&2
  exit 1
}

cd "$ROOT/ui"
"$BUN" install --frozen-lockfile --os='*' --cpu='*'
"$BUN" test
"$BUN" run typecheck
mkdir -p "$ROOT/.cache/build-ui/check"
"$BUN" run check
mkdir -p "$ROOT/bin"
"$BUN" run build
chmod 0700 "$ROOT/bin/sunaba-ui"
ACTUAL_UI_SHA256="$(shasum -a 256 "$ROOT/bin/sunaba-ui" | awk '{print $1}')"
[[ "$ACTUAL_UI_SHA256" == "$EXPECTED_UI_SHA256" ]] || {
  printf 'FAIL sunaba-ui - standalone artifact digest mismatch: %s\n' "$ACTUAL_UI_SHA256" >&2
  exit 1
}
printf 'PASS sunaba-ui %s\n' "$ACTUAL_UI_SHA256"
mkdir -p "$ROOT/.cache/build-ui/gocache"
GOCACHE="$ROOT/.cache/build-ui/gocache" SUNABA_UI_ARTIFACT="$ROOT/bin/sunaba-ui" go test sunaba/internal/tui -run '^TestBuiltStandaloneArtifactMatchesActiveLock$' -count=1
