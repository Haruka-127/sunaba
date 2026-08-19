# AGENTS.md

OpenCodeをProject専用のApple Container VMで安全に実行する基盤、sunabaの開発リポジトリ。

## 文書

- 作業前に[`docs/plan/README.md`](docs/plan/README.md)を読み、そこから参照される現在の正本文書に従う
- 製品仕様とセキュリティ判断の正本は[`docs/plan/sunaba-secure-agent-platform.md`](docs/plan/sunaba-secure-agent-platform.md)
- 実装・検証で許可されるsudo、pf、Apple Container操作は[`docs/plan/allowed-host-operations.md`](docs/plan/allowed-host-operations.md)だけで定義する
- 利用者向けの導入と機能説明は[`README.md`](README.md)と[`docs/user-guide.md`](docs/user-guide.md)、目的別手順は[`docs/workflows.md`](docs/workflows.md)
- Phaseごとの証拠と検証履歴は[`docs/implementation/`](docs/implementation/README.md)
- `docs/plan/archive/`は過去資料であり、実装、テスト、ホスト操作、セキュリティ判断の根拠にしない。新しい参照も追加しない
- 現在のexact dependencyは`internal/dependency/manifest.json`とhost-only version lockを確認する
- README、ユーザーガイド、ワークフローには利用者が導入・判断・操作・復旧するための情報だけを書き、実装進捗や内部test台帳は`docs/implementation/`へ分離する

## Git運用

- トピックブランチやworktreeは、ユーザーが分離、並列委任、PR作業を明示した場合だけ作成する
- commitは1つの意図ごとに分け、Conventional Commits形式の日本語messageを使う
- pushは行わない。リモートへの反映は人間が行う。fetchとpullは実行してよい
- unrelatedな変更を保持し、未追跡fileを一括stageしない。破壊的なGit操作を行わない

## 検証

- 通常変更は`./scripts/verify.sh`と`./scripts/verify-race.sh`で確認する
- integration build-tagのコンパイルは`go test -tags=integration -run '^$' ./test/integration`で確認できるが、Apple Container実機gateの通過とは扱わない
- live Apple Container、外部service、Keychain、sudo、pfを使う検証は、許可文書の範囲とユーザーの個別承認を確認してから実行する
- docs変更では`git diff --check`、相対link、記載したCLIと`sunaba ... --help`の一致を確認する

## 環境衛生

- dependencyはproject-local環境とmanifest/lock fileで管理し、global installやglobal設定変更を行わない
- 一時fileはOSのtempまたはgitignore済みdirectoryへ置き、secret、credential、token、Project内容をlogやcommitへ含めない
- 外部serviceやcontainerを使う検証は隔離し、その検証が作成したexactな`sunaba-` resourceと不要な`sunaba-base:` imageだけを終了後に破棄する
- `docs/plan/allowed-host-operations.md`にないsudo、ホスト設定変更、任意のcontainer削除を行わない
