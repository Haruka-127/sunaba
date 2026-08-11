#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFY_TMP="$(mktemp -d /tmp/sunaba-verify.XXXXXX)"
export GOPATH="$VERIFY_TMP/gopath"
export GOMODCACHE="$VERIFY_TMP/gomodcache"
export GOCACHE="$VERIFY_TMP/gocache"

cleanup() {
	chmod -R u+w "$VERIFY_TMP" 2>/dev/null || true
	rm -rf "$VERIFY_TMP"
}
trap cleanup EXIT

pass() { printf 'PASS %s\n' "$1"; }
skip() { printf 'SKIP %s - %s\n' "$1" "$2"; }
fail() { printf 'FAIL %s - %s\n' "$1" "$2" >&2; exit 1; }

cd "$ROOT"

UNFORMATTED="$(gofmt -l -- $(rg --files -g '*.go' -g '!bin/**'))"
[[ -z "$UNFORMATTED" ]] || fail format "$UNFORMATTED"
git diff --check
go test ./...
go test -race ./...
go vet ./...
mkdir -p bin
go build -trimpath -o bin/sunaba ./cmd/sunaba
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o bin/sunaba-guest-relay ./cmd/sunaba-guest-relay
go build -trimpath -o bin/sunaba-git-hook ./cmd/sunaba-git-hook
GUEST_RELAY_FILE="$(file bin/sunaba-guest-relay)"
grep -Fq 'ELF 64-bit' <<<"$GUEST_RELAY_FILE" || fail guest-relay 'not a Linux ELF binary'
grep -Eq 'ARM aarch64|ARM64' <<<"$GUEST_RELAY_FILE" || fail guest-relay 'not an AArch64 binary'
pass "unit/race/vet/build"

HELP="$(./bin/sunaba help)"
for REQUIRED in 'credentials openai' 'project init' 'agent' 'git remote add' 'changes export' 'changes apply' 'secure|dev' 'never bind-mounted'; do
  grep -Fq "$REQUIRED" <<<"$HELP" || fail cli-help "missing $REQUIRED"
done
for OBSOLETE in '--no-firewall' 'env set' 'git set' 'reset --full' 'automatic approval'; do
  if grep -Fq -- "$OBSOLETE" <<<"$HELP"; then
    fail cli-help "retained obsolete prototype behavior: $OBSOLETE"
  fi
done
if rg -n --glob '*.go' --glob '*.sh' --glob '!*_test.go' --glob '!scripts/verify.sh' -- '--no-firewall|OPENAI_API_KEY|EnvFiles:.*Project|Networks:.*default|HostPath:.*Project|server-password|EnvFileForContainer|_audit|func Attach\(|"permission"[[:space:]]*:[[:space:]]*"allow"' internal cmd scripts; then
  fail static-boundary "found an obsolete unsafe execution path"
fi
pass "CLI and static boundary"

if [[ "${SUNABA_FUZZ:-0}" == "1" ]]; then
  go test ./internal/modelgateway -run '^$' -fuzz FuzzResponsesEnvelope -fuzztime 10s
  go test ./internal/gitgateway -run '^$' -fuzz FuzzCanonicalPushBinding -fuzztime 10s
  go test ./internal/webgateway -run '^$' -fuzz FuzzNormalizeHostname -fuzztime 10s
  go test ./internal/webgateway -run '^$' -fuzz FuzzHostsBlocklistParser -fuzztime 10s
  pass fuzz
else
  skip fuzz 'set SUNABA_FUZZ=1 for bounded fuzz runs'
fi

if [[ "${SUNABA_INTEGRATION:-0}" != "1" ]]; then
  skip integration 'set SUNABA_INTEGRATION=1 on the pinned macOS/Apple Container host'
  exit 0
fi

[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] || fail integration 'requires macOS on Apple silicon'
command -v container >/dev/null || fail integration 'container CLI not found'
command -v opencode >/dev/null || fail integration 'opencode CLI not found'

SUNABA_PHASE0_INTEGRATION=1 go test -tags=integration ./test/integration -run 'TestPhase0' -count=1 -v
SUNABA_PHASE1_INTEGRATION=1 go test -tags=integration ./test/integration -run 'TestPhase1' -count=1 -v
SUNABA_PHASE2_INTEGRATION=1 go test -tags=integration ./test/integration -run 'TestPhase2' -count=1 -v
SUNABA_CLI_INTEGRATION=1 go test -tags=integration ./test/integration -run 'TestPublicCLI' -count=1 -v
SUNABA_PHASE3_INTEGRATION=1 go test -tags=integration ./test/integration -run 'TestPhase3' -count=1 -v
SUNABA_PHASE4_INTEGRATION=1 go test -tags=integration ./test/integration -run 'TestPhase4WebGatewayInAgentVM' -count=1 -v
pass "Phase 0-4 isolated integration"

if [[ "${SUNABA_DEV_INTEGRATION:-0}" == "1" ]]; then
  SUNABA_DEV_INTEGRATION=1 go test -tags=integration ./test/integration -run 'TestDevSessionNetworkBoundary' -count=1 -v
  pass "dev network integration"
else
  skip dev-integration 'set SUNABA_DEV_INTEGRATION=1 after authorizing sudo ./bin/sunaba firewall operations'
fi

if [[ "${SUNABA_LIVE_OPENAI:-0}" == "1" ]]; then
  SUNABA_LIVE_OPENAI=1 go test -tags=integration ./test/integration -run '^TestLiveOpenAIThroughAgentVM$' -count=1 -v
  pass "live OpenAI Agent VM contract"
else
  skip live-openai 'set SUNABA_LIVE_OPENAI=1 to authorize one billable request using the macOS Keychain credential'
fi
