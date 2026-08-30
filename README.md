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
- 引数なしの`sunaba`からSetup、Project選択、開始・再開、変更確認、設定、復旧を行える英語TUI
- ホストの作業ツリーをVMへbind mountしない
- OpenAIやGitの実credentialをVMへ渡さない
- 既定のsecure modeでは、許可したGateway以外の外向き通信を拒否
- Snapshot対象をmetadata previewし、exact digestを承認してからVMを作成
- `node_modules`等の大量treeをBulk pathsとして通常diffから分離し、VM-only dataをhost-onlyに保持
- ホストへ反映する変更とGit pushを、ホスト側の明示的な承認に束縛
- Agent Sessionごとに資格情報を再発行しながら同じVMの編集状態を再利用
- exportやSupervisorの途中失敗でも、停止VMとfrozen成果物を明示的に復旧可能
- `doctor`と`status`で前提条件、Session残り時間、quota、recovery状態を確認可能

## 動作環境

- Apple silicon Mac / macOS 26
- Apple Container `1.2.2`
- OpenCode host TUI / guest server: 同じv1系exact version（初期値`1.18.18`）
- Go 1.22以降（ソースからビルドする場合）
- OpenAI API key、またはCodexを利用できるChatGPT subscription

Apple ContainerとOpenCodeは検証済みのexact versionへ固定されます。OpenCode host artifactとbundled `sunaba-ui`はsunabaが管理するため、Bun、Node.js、OpenTUI、OpenCodeのglobal installは不要です。OpenCodeは利用者が明示的な`update check` / `update apply`でv1系の別versionへ更新できますが、`latest`へのsession時の自動追従、OpenCode v2、host TUIとguest serverのversion混在は使用できません。

## 最短の利用例

release bundleの4つのbinary（`sunaba`、`sunaba-ui`、`sunaba-guest-relay`、`sunaba-git-hook`）を同じdirectoryへ置き、そのdirectoryを`PATH`へ追加します。Apple Container systemを起動した後、Project directoryで次を実行します。

```sh
cd /path/to/project
sunaba
```

初回はSetupが、Secure mode、OAuth、開発用の標準Web accessを確認してから適用します。安全に検出できたGit remoteは候補に留まり、選択したものだけが登録されます。OAuthを中断してもSetup結果は保持され、Agent Session開始時だけ未認証として拒否されます。

通常画面はHome、Changes、Settingsの3つです。Homeの`Start`または`Resume`でsunaba TUIが完全に終了してOpenCodeへterminalを渡し、OpenCode終了後は新しいsunaba TUIでHomeへ戻ります。VM内の編集状態は自動apply・destroyされません。

ChangesはNormal changesとBulk pathsを分けます。Normalは左の変更file一覧と右のscroll可能なdiffを表示し、wide terminalではline番号付きside-by-side、narrow terminalではunified diffを使います。Bulkはdirectory単位の件数、size、分類理由、保持状態を表示し、descendant filenameを通常画面へ列挙しません。全Bulk pathの扱いを決めた後、Normal全件とBulk dispositionを一つのApply Planとして一回だけ確認します。digestやnonceの手入力は不要です。

既定では任意階層の`node_modules` directoryをSnapshot lowerへcopyしません。既存host directoryは変更せず、VM内で生成されたtreeも自動でhostへ反映・破棄しません。依存導入には許可済みWeb accessが必要です。directory全体のhost applyはApple Container実機gateが完了するまで無効で、`Keep host unchanged`、`Retain as artifact`、exact inventoryの`Discard VM-only data`だけを利用できます。

`Keep host unchanged`でProject-boundに保持したdataは`sunaba retained list --dir /path/to/project`で確認できます。恒久破棄にはopaque retained ID、exact object digest、logical byte数、`--yes`が必要です。保持dataが残るProject stateを`destroy`が暗黙削除することはありません。

自動化・高度な設定・復旧では従来のサブコマンドも使用できます。API keyへ切り替える例:

```sh
sunaba credentials openai api-key set
sunaba model auth api-key
```

認証方式は全Project共通で、変更は次のAgent Sessionから有効です。OAuthとAPI keyはhost-only credential fileへ別々に保存でき、別方式への自動fallbackはありません。

exportがExternal Git状態や保存失敗で拒否された場合、sunabaは停止VMを自動削除しません。`sunaba status`でrecovery状態と再試行コマンドを確認してください。schema v5 Work SetにBulk dataがある場合、旧`--discard-pending`だけでは破棄できません。各Bulk pathをexact identityへ束縛して解決してください。

## セキュリティ上の注意

secure modeでも、利用者が許可したLLMやWeb originへ送信した情報の安全性までは保証しません。特にWeb GatewayのHTTPS通信は暗号化されたtunnel内部のmethodやuploadを識別できません。

dev modeはactive session中の直接Internet接続を許可するため、情報流出防止を保証しません。必要な場合だけ明示的に選択してください。詳しくは[利用ワークフローの「直接Internet接続が必要な作業」](./docs/workflows.md#直接internet接続が必要な作業)を参照してください。
