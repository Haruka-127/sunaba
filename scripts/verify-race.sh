#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE_KEY="$(go env GOVERSION)-$(git -C "$ROOT" hash-object go.sum)"
CACHE_ROOT="${SUNABA_VERIFY_CACHE_ROOT:-$ROOT/.cache/verify/$CACHE_KEY}"
export GOPATH="$CACHE_ROOT/gopath"
export GOMODCACHE="$CACHE_ROOT/gomodcache"
export GOCACHE="$CACHE_ROOT/gocache"
cd "$ROOT"

go test -race ./...
printf 'PASS race\n'
