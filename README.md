# sunaba

sunabaは、OpenCodeをプロジェクト専用のApple Container VMで動かす、Apple silicon Mac向けの実行基盤です。

OpenCodeとその実行コマンドはVM内で自由に動かしながら、ホストの作業ツリー、認証情報、他のプロジェクト、外部ネットワークとの境界をホスト側で管理します。VM内の変更はホストへ直接書き込まず、確認可能なChange Setとして取り出してから反映します。

## ドキュメント

- [ユーザーガイド](./docs/user-guide.md): 動作環境、ビルド、初期設定、各機能、トラブルシューティング
- [利用ワークフロー](./docs/workflows.md): 初回セットアップから日常作業、変更の反映、復旧までの目的別手順
- [セキュリティ設計・製品仕様](./docs/plan/sunaba-secure-agent-platform.md): 保証範囲、脅威モデル、アーキテクチャ、残余リスク
- [ホスト操作の許可範囲](./docs/plan/allowed-host-operations.md): sunabaの実装・検証で許可される`sudo`、pf、Apple Container操作

初めて使う場合は、[ユーザーガイドの「利用前の準備」](./docs/user-guide.md#利用前の準備)を済ませてから、[「初めてのプロジェクト」ワークフロー](./docs/workflows.md#初めてのプロジェクト)へ進んでください。

## 主な特徴

- プロジェクトごとに独立したAgent VMを使用
- ホストの作業ツリーをVMへbind mountしない
- OpenAIやGitの実credentialをVMへ渡さない
- 既定のsecure modeでは、許可したGateway以外の外向き通信を拒否
- ホストへ反映する変更とGit pushを、ホスト側の明示的な承認に束縛
- 同じVMを再利用でき、必要なときは承認済みのホスト状態からクリーン再生成可能

## 動作環境

- Apple silicon Mac / macOS 26
- Apple Container `1.2.2`
- OpenCode host TUI / guest server: 同じv1系exact version（初期値`1.18.18`）
- Go 1.22以降（ソースからビルドする場合）
- OpenAI API key、またはCodexを利用できるChatGPT subscription

Apple ContainerとOpenCodeは検証済みのexact versionへ固定されます。OpenCodeは利用者が明示的な`update check` / `update apply`でv1系の別versionへ更新できますが、`latest`へのsession時の自動追従、OpenCode v2、host TUIとguest serverのversion混在は使用できません。

## 最短の利用例

ビルド後、3つのsunaba binaryがあるdirectoryを`PATH`へ追加するか、3つとも既存の`PATH`上へ配置してください。また、macOS側へ固定versionのOpenCodeをインストールし、`opencode`コマンドを実行できる状態にします。最初に利用基盤をsetupし、credential登録を済ませたあと、対象プロジェクトで次を実行します。

```sh
sunaba setup
sunaba project init
sunaba up
sunaba agent
sunaba changes export
sunaba changes review
sunaba changes apply
```

`agent`を終了しても、secure modeのVM内にある編集状態は保持されます。`changes export`はVMを停止・検証してChange Setを作成し、`changes review`は固定した変更前後の内容をhostへ書き込まずに表示します。`changes apply`は同じreviewを再表示し、ホスト側で承認した場合だけ作業ツリーへ反映します。

## セキュリティ上の注意

secure modeでも、利用者が許可したLLMやWeb originへ送信した情報の安全性までは保証しません。特にWeb GatewayのHTTPS通信は暗号化されたtunnel内部のmethodやuploadを識別できません。

dev modeはactive session中の直接Internet接続を許可するため、情報流出防止を保証しません。必要な場合だけ明示的に選択してください。詳しくは[利用ワークフローの「直接Internet接続が必要な作業」](./docs/workflows.md#直接internet接続が必要な作業)を参照してください。
