# TUI利用性実装記録

この記録は[`tui-usability-implementation-plan.md`](../plan/tui-usability-implementation-plan.md)の実装順序1〜10について、実装箇所と再現可能な証拠を対応付ける。実装基準日は2026-08-30、対象branchは`feat/opentui-ux`である。

## Checkpoint

| # | 実装結果 | 主な証拠 |
| --- | --- | --- |
| 1 | credential file、global settings、UI protocol、managed artifactのstrict contractを追加 | `internal/secretstore/store_test.go`、`internal/usersettings/settings_test.go`、`internal/tui/protocol_test.go`、`internal/dependency/dependency_test.go` |
| 2 | Keychain実装を削除し、owner-only file、atomic replacement、process間lockへAPI keyとOAuthを独立保存 | `internal/secretstore/store.go`、`internal/openauth/codex_test.go`、`scripts/verify.sh`の禁止API scan |
| 3 | OAuth既定のglobal設定へ認証方式を移し、Project schema migrationとSession開始時snapshotを実装 | `internal/usersettings/`、`internal/projectconfig/config_test.go`、`internal/policy/policy_test.go`、`internal/session/model_auth_test.go` |
| 4 | Bun 1.3.14、OpenTUI 0.5.9、standalone `sunaba-ui`をexact version/digestで固定。旧bootstrap lockを厳密に識別して確認後にtransactional migrationし、Go authorityとone-shot helperをowner/PID/UID/Project/nonceへ束縛 | `internal/dependency/manifest.json`、`ui/bun.lock`、`internal/tui/`、`internal/cli/version_commands_test.go`、`scripts/build-ui.sh` |
| 5 | canonical Project自動選択、bounded selector pagination、状態別Home、helper終了後だけOpenCodeへterminalをhandoffし終了後にfresh Homeを生成 | `internal/cli/tui_coordinator.go`、`internal/cli/tui_coordinator_test.go` |
| 6 | Continue前に永続化しないSetup、推奨Web詳細、明示選択Git remote、global AI接続、Settingsを実装 | `internal/cli/tui_coordinator.go`、`TestTUISetupDoesNotPersistBeforeContinue` |
| 7 | 変更fileだけのindex、A/M/D/R、mode/symlink/binary/large metadata、wide/narrow diff、pagination、Change Set identity再検証、全体applyを実装 | `internal/workspace/review_screen.go`、`internal/workspace/review_screen_test.go`、`internal/cli/tui_coordinator.go` |
| 8 | Recoveryに削除対象、保持対象、回復不能work、安全なexport/recreate順を表示。Git pushの既存one-shot host approvalをHomeから案内 | `internal/cli/tui_coordinator.go`、`internal/trustedui/approval_test.go`、`internal/approval/approval_test.go` |
| 9 | 引数なしTTYをTUI、non-TTYをfail-closed errorとし、`console`を正規名、`shell`をalias、model authをselectorなしglobal操作へ変更 | `internal/cli/commands.go`、`internal/cli/cli_test.go`、`internal/cli/tui_coordinator_test.go` |
| 10 | 導入、通常操作、設定、変更確認、復旧を現行UIへ更新し、内部進捗は本記録へ分離 | [`README.md`](../../README.md)、[`user-guide.md`](../user-guide.md)、[`workflows.md`](../workflows.md) |

## UI artifact gate

```sh
./scripts/build-ui.sh
```

2026-08-30にproject-local Bunで再実行し、OpenTUI helper test 10件、TypeScript typecheck、standalone build、SHA-256照合、Mach-O/owner/mode/architecture検証がPASSした。生成物SHA-256は`27ee3bc850a2bb9d822d9b9c3af977aec148c40e1250acf9199736b2eb8521c6`である。利用者環境へのglobal installは行っていない。

## 自動gate

2026-08-30の最終状態で次を再実行した。

```sh
./scripts/verify.sh
./scripts/verify-race.sh
go test -tags=integration -run '^$' ./test/integration
git diff --check
```

integration build-tag commandはcompile-onlyであり、Apple Container VMの実機通過とは扱わない。live Apple Container、外部OpenAI、sudo、pfは個別承認を得ていないため実行しない。

- `./scripts/verify.sh`: PASS。全unit、vet、host/guest build、CLI/help、Keychain禁止を含むstatic boundaryを通過
- `./scripts/verify-race.sh`: PASS。全packageのrace testを通過
- integration build-tag compile-only: PASS
- `git diff --check`: PASS
- Markdown相対link: PASS

## セキュリティ境界

- helperは表示とbounded event変換だけを担当し、Project、credential、policy、network、shellへ直接アクセスしない。
- Go側は表示済みrevision、action、Project、helper PID/UID、nonceを照合し、action受領後も既存serviceのlockとvalidationを通す。
- credential値はhost-only fileだけに保存し、argv、environment、Project設定、VM、audit、logへ渡さない。
- Keychain API、`/usr/bin/security`、Security.frameworkを製品経路から削除し、旧itemを読取、移行、自動削除しない。
- partial apply、toolchain/cacheの利用者領域への永続化、Session開始時の自動updateは追加していない。

## 実機gate

この変更ではApple Container、実OpenAI credential、sudo、pfを使う実機gateを実行していない。既存Phase 0〜5の過去証拠は[`final-verification.md`](./final-verification.md)に保持するが、本変更のPASSとは扱わず`LIVE RECHECK`とする。
