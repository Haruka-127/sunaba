# AGENTS.md

opencodeをセキュアに実行するための実行基盤、sunabaを開発するためのリポジトリ。`docs/plan/opencode-secure-agent-platform-implementation.md`に従って実装する。必ず読んでから実装を進めること。

## Git運用

- ブランチ戦略はGitHub Flow。`main` へ直接コミットせず、トピックブランチ(例: `feature/<内容>`)で作業し、完了後にローカルで `main` へマージする
- コミットメッセージは Conventional Commits に従い、日本語で記述する(例: `feat: スラッシュコマンドの受信処理を実装`)
- コミットは後から見返すことのできる単位で行う。1コミット = 1つの意図とし、各コミットでテストが通る状態を保つ
- **pushを含むリモートへの書き込みは禁止**(`fetch` / `pull` は可)。リモートへの反映は人間が行う

## 環境衛生

- 言語の仮想環境・プロジェクトローカルの依存で作業し、グローバル環境へインストールしない(Python は `.venv`、Node はローカルインストール、Go は `GOBIN` をリポジトリ内へ)
- グローバル設定の変更とリポジトリ外への書き込みをしない。一時ファイルはOSのtempかgitignore済みディレクトリを使う
- 依存はマニフェストとlockファイルで管理し、コミットに含める
- 外部サービスやコンテナを伴う統合テストは隔離し、終了後に作成した `sunaba-` プレフィックスのコンテナ・一時プロジェクト・ボリュームを破棄する

## ホスト側操作

- 実装・検証で実行してよい `sudo`、pf、container 操作は `docs/plan/allowed-host-operations.md` に記載された範囲に限定する
- `docs/plan/allowed-host-operations.md` にない `sudo` 操作、ホスト設定変更、任意のコンテナ削除は行わない
