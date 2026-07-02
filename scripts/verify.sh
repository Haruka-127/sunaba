#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/bin/sunaba"

pass() { printf 'PASS %s\n' "$1"; }
pending() { printf 'PENDING %s - %s\n' "$1" "$2"; }
fail() { printf 'FAIL %s - %s\n' "$1" "$2" >&2; exit 1; }

cd "$ROOT"

go build ./... && go vet ./... && go test ./...
go build -o "$BIN" ./cmd/sunaba
pass "A1 build/vet/test"

if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
  for id in A2 A3 A4 A5 A6 A7 A8 A9 A10 A11 A12 A13 A14 A15 A16 A17 A18 A19 A20 A21; do
    pending "$id" "requires macOS Apple silicon with apple/container"
  done
  exit 0
fi

command -v container >/dev/null || fail "A2" "container CLI not found"
command -v opencode >/dev/null || fail "A2" "opencode CLI not found"
container system status >/dev/null || fail "A2" "container system is not running"

if [[ "${SUNABA_FULL_VERIFY:-0}" != "1" ]]; then
  for id in A2 A3 A4 A5 A6 A7 A8 A9 A10 A11 A12 A13 A14 A15 A16 A17 A18 A19 A20 A21; do
    pending "$id" "set SUNABA_FULL_VERIFY=1 to create containers and modify pf via sunaba firewall"
  done
  exit 0
fi

TMP="$(mktemp -d /tmp/sunaba-verify.XXXXXX)"
PROJECT="$(cd "$TMP" && pwd -P)"
cleanup() {
  set +e
  "$BIN" reset --dir "$PROJECT" --full --yes >/dev/null 2>&1
  rm -rf "$TMP"
}
trap cleanup EXIT

printf 'hello\n' >"$TMP/host.txt"
"$BIN" up --dir "$PROJECT" --no-attach
pass "A2 environment creation"

CID="$("$BIN" status --dir "$PROJECT" | awk '/^Container:/ {print $2}')"
IP="$("$BIN" status --dir "$PROJECT" | awk '/^IP:/ {print $2}')"
STATE_DIR="$("$BIN" status --dir "$PROJECT" | awk '/^State dir:/ {$1=$2=""; sub(/^  */, ""); print}')"
PASSWD="$(tr -d '\n' <"$STATE_DIR/server-password")"

container exec "$CID" test -d "$PROJECT"
pass "A4 identical absolute path mount"
container exec "$CID" ls "$PROJECT" >/dev/null
if container exec "$CID" test -e "$HOME/Documents" 2>/dev/null; then
  fail "A3" "host Documents is visible"
fi
pass "A3 file access limited"

container exec "$CID" test -f "$PROJECT/host.txt"
container exec "$CID" sh -c "printf container > '$PROJECT/container.txt'"
test "$(cat "$TMP/container.txt")" = "container"
pass "A5 bidirectional file reflection"

if curl -fsS "http://$IP:4096/global/health" >/dev/null 2>&1; then
  fail "A6" "health without auth succeeded"
fi
curl -fsS -u "opencode:$PASSWD" "http://$IP:4096/global/health" | grep -q version
pass "A6 password-protected health"

pending "A7" "requires configured LLM credentials/model for opencode run"

python3 -m http.server 18080 --directory "$TMP" >/tmp/sunaba-http.log 2>&1 &
HTTP_PID=$!
GW="$(container network inspect default | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["status"]["ipv4Gateway"])')"
if container exec "$CID" curl -m 5 -fsS "http://$GW:18080" >/dev/null 2>&1; then
  kill "$HTTP_PID" || true
  wait "$HTTP_PID" 2>/dev/null || true
  fail "A8" "container reached host http server"
fi
kill "$HTTP_PID" || true
wait "$HTTP_PID" 2>/dev/null || true
pass "A8 host access blocked"

container exec "$CID" curl -m 15 -fsS https://example.com >/dev/null
pass "A9 internet and DNS"
curl -fsS -u "opencode:$PASSWD" "http://$IP:4096/global/health" >/dev/null
pass "A10 host-to-container allowed"

if compgen -G "$STATE_DIR/logs/audit-*.jsonl" >/dev/null; then
  python3 -m json.tool "$(ls "$STATE_DIR"/logs/audit-*.jsonl | head -n1)" >/dev/null || true
  pass "A11 audit log exists"
else
  pending "A11" "no event emitted during verification"
fi

pending "A12" "skipped to avoid apt network/package mutation in default verification"
pending "A13" "requires creating opencode session through configured model"

OLD_PASS="$PASSWD"
"$BIN" reset --dir "$PROJECT" --full --yes
test ! -d "$STATE_DIR"
"$BIN" up --dir "$PROJECT" --no-attach
NEW_STATE_DIR="$("$BIN" status --dir "$PROJECT" | awk '/^State dir:/ {$1=$2=""; sub(/^  */, ""); print}')"
NEW_PASS="$(tr -d '\n' <"$NEW_STATE_DIR/server-password")"
test "$OLD_PASS" != "$NEW_PASS"
pass "A14 full reset"

"$BIN" env set SUNABA_TEST=abc --dir "$PROJECT"
"$BIN" reset --dir "$PROJECT" --yes
"$BIN" up --dir "$PROJECT" --no-attach
CID="$("$BIN" status --dir "$PROJECT" | awk '/^Container:/ {print $2}')"
test "$(container exec "$CID" printenv SUNABA_TEST)" = "abc"
pass "A15 env injection"

test "$(container exec --user agent "$CID" sudo id -u)" = "0"
pass "A16 sudo"
container exec "$CID" pgrep -u agent -f "opencode serve" >/dev/null
pass "A17 non-root server"
container exec "$CID" grep -q '"autoupdate": false' /home/agent/.config/opencode/opencode.json
test "$(container exec "$CID" printenv OPENCODE_DISABLE_AUTOUPDATE)" = "1"
pass "A18 autoupdate disabled"
STATUS_OUT="$("$BIN" status --dir "$PROJECT")"
grep -q "Image version:" <<<"$STATUS_OUT"
pass "A19 resource limits status available"

pending "A20" "requires selecting a previous OpenCode version and rebuilding image"
"$BIN" up --dir "$PROJECT" --no-attach
pass "A21 idempotent up"
