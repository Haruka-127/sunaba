#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUN_VERSION="1.3.14"
BUN_ARCHIVE_SHA256="d8b96221828ad6f97ac7ac0ab7e95872341af763001e8803e8267652c2652620"
BUN_EXECUTABLE_SHA256="e0c90ec15d33363e6b70713d56bc3b2c7585c17f40a0fe0f8fd9305901d4e233"
BUN_URL="https://github.com/oven-sh/bun/releases/download/bun-v$BUN_VERSION/bun-darwin-aarch64.zip"
DESTINATION="$ROOT/.cache/tools/bun-$BUN_VERSION/bun"

digest() { shasum -a 256 "$1" | awk '{print $1}'; }

if [[ -x "$DESTINATION" ]]; then
  [[ "$(digest "$DESTINATION")" == "$BUN_EXECUTABLE_SHA256" && "$($DESTINATION --version)" == "$BUN_VERSION" ]] || {
    printf 'FAIL sunaba-ui toolchain - existing project-local Bun is not the pinned artifact\n' >&2
    exit 1
  }
  printf 'PASS project-local Bun %s\n' "$BUN_VERSION"
  exit 0
fi

mkdir -p "$ROOT/.cache/tools"
STAGING="$(mktemp -d "$ROOT/.cache/tools/.bun-$BUN_VERSION.XXXXXX")"
trap 'rm -rf "$STAGING"' EXIT
curl -fL "$BUN_URL" -o "$STAGING/bun.zip"
[[ "$(digest "$STAGING/bun.zip")" == "$BUN_ARCHIVE_SHA256" ]] || {
  printf 'FAIL sunaba-ui toolchain - Bun archive digest mismatch\n' >&2
  exit 1
}
unzip -q "$STAGING/bun.zip" -d "$STAGING/extracted"
[[ "$(digest "$STAGING/extracted/bun-darwin-aarch64/bun")" == "$BUN_EXECUTABLE_SHA256" ]] || {
  printf 'FAIL sunaba-ui toolchain - Bun executable digest mismatch\n' >&2
  exit 1
}
mkdir "$ROOT/.cache/tools/bun-$BUN_VERSION"
install -m 0700 "$STAGING/extracted/bun-darwin-aarch64/bun" "$DESTINATION"
printf 'PASS project-local Bun %s\n' "$BUN_VERSION"
