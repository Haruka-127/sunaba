# AGENTS.md

opencodeをセキュアに実行するための実行基盤、sunabaを開発するためのリポジトリ。

## 仕様文書

- 実装前に `docs/plan/README.md` と、そこから参照される現在の正本文書を読む
- 製品仕様の正本は `docs/plan/sunaba-secure-agent-platform.md` とする
- 実装・検証で許可するホスト操作は `docs/plan/allowed-host-operations.md` だけで定義する
- `docs/plan/archive/` 配下は過去資料であり、実装、テスト、ホスト操作、セキュリティ判断の根拠として参照しない
- archiveと現在の文書が矛盾する場合はarchiveを無視する。新しいコードや文書からarchiveへの参照を追加しない
- READMEや既存コードは実装済みの旧プロトタイプを説明している場合がある。将来仕様の判断には正本文書を優先し、差異を暗黙に互換仕様として残さない
- OpenCodeは正本文書で固定したv1系のバージョンをserver/TUIの両方で使う。`latest`への自動追従、v2系への更新、server/TUIの異なるバージョンの混在を行わない

## Git運用

- 日常の開発は `dev` ブランチで行い、直接コミットする。トピックブランチは原則として作成しない
- `main` への直接コミットは禁止する。`dev` から `main` へのマージは、リリース等の最終統合をユーザーが明示的に指示したときにのみ行う
- コミットメッセージは Conventional Commits に従い、日本語で記述する(例: `feat: スラッシュコマンドの受信処理を実装`)。本文も変更内容や意図がわかるように日本語で記述する。
- コミットは後から見返すことのできる単位で行う。1コミット = 1つの意図とし、各コミットでテストが通る状態を保つ
- **pushを含むリモートへの書き込みは禁止**(`fetch` / `pull` は可)。リモートへの反映は人間が行う

## 環境衛生

- 言語の仮想環境・プロジェクトローカルの依存で作業し、グローバル環境へインストールしない(Python は `.venv`、Node はローカルインストール、Go は `GOBIN` をリポジトリ内へ)
- グローバル設定の変更とリポジトリ外への書き込みをしない。一時ファイルはOSのtempかgitignore済みディレクトリを使う
- 依存はマニフェストとlockファイルで管理し、コミットに含める
- 外部サービスやcontainerを伴う統合テストは隔離し、終了後にそのテストで作成した`sunaba-`プレフィックスのcontainer、network、volume、一時Project、不要な`sunaba-base:`イメージだけを破棄する

## ホスト側操作

- 実装・検証で実行してよい `sudo`、pf、container 操作は `docs/plan/allowed-host-operations.md` に記載された範囲に限定する
- `docs/plan/allowed-host-operations.md` にない `sudo` 操作、ホスト設定変更、任意のコンテナ削除は行わない
