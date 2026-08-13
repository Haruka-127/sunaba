#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFY_TMP="$(mktemp -d "${TMPDIR:-/tmp}/sunaba-verify.XXXXXX")"
export GOPATH="$VERIFY_TMP/gopath"
export GOMODCACHE="$VERIFY_TMP/gomodcache"
export GOCACHE="$VERIFY_TMP/gocache"
export SUNABA_VERIFY_CACHE_ROOT="$VERIFY_TMP"

cleanup() {
	chmod -R u+w "$VERIFY_TMP" 2>/dev/null || true
	rm -rf "$VERIFY_TMP"
}
trap cleanup EXIT

"$ROOT/scripts/verify.sh"
"$ROOT/scripts/verify-race.sh"
