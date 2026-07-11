# sunaba

sunaba は、opencode server をプロジェクト専用の apple/container Linux VM 内で起動し、ホスト側の opencode TUI から接続するための CLI です。

## 前提

- macOS / Apple silicon
- apple/container 1.0 以上
- `container system start` 済み
- ホスト側に opencode CLI がインストール済み
- Go 1.22 以上

## インストール

```sh
go build -o bin/sunaba ./cmd/sunaba
```

必要なら `bin/sunaba` を PATH の通った場所へ配置してください。

## 初回セットアップ

```sh
container system start
bin/sunaba update
cd /path/to/project
bin/sunaba up
```

初回 `up` ではプロジェクト状態が `~/.local/share/sunaba/projects/<projectID>/` に作成されます。opencode の認証情報はコンテナ内で設定します。

```sh
bin/sunaba shell
opencode auth login
```

認証情報は `opencode-data/` に保存され、通常の `reset` では保持されます。

## コマンド

```sh
sunaba up [--dir PATH] [--cpus N] [--memory SIZE] [--no-attach] [--no-firewall]
```

プロジェクト用コンテナを作成または起動し、opencode server の health を待ってから監査デーモンを起動します。既定ではホスト側 TUI を `opencode attach` で接続します。

```sh
sunaba shell [--dir PATH] [--no-firewall]
```

起動中のコンテナへ `agent` ユーザーとして入ります。コンテナが停止中または未作成の場合は先に起動します。`--no-firewall` を付けると、起動時の host firewall 適用をスキップします。`agent` は必要時に `sudo` を利用できます。

```sh
sunaba stop [--dir PATH]
```

監査デーモンを止め、プロジェクトコンテナを停止します。

```sh
sunaba reset [--dir PATH] [--full] [--yes]
```

通常 reset はコンテナのみを削除し、セッション履歴、認証情報、環境変数、server password、監査ログは保持します。`--full` はプロジェクト状態ディレクトリ全体を削除します。

```sh
sunaba update [--opencode-version X.Y.Z]
```

埋め込み Containerfile から `sunaba-base:<version>` をローカルビルドします。既存コンテナには次回 `reset` 後に反映されます。

```sh
sunaba status [--dir PATH]
sunaba list
```

プロジェクト状態、コンテナ状態、IP、opencode バージョン、firewall、監査デーモン状態を確認します。

```sh
sunaba env set KEY=VALUE... [--dir PATH]
sunaba env unset KEY... [--dir PATH]
sunaba env list [--dir PATH]
```

プロジェクト単位の環境変数を管理します。値は `env` ファイルに 0600 で保存され、コンテナ作成時に注入されます。稼働中コンテナには反映されないため、変更後は `sunaba reset` を実行してください。`list` は値をマスクして表示します。

```sh
sunaba config firewall [enabled|disabled|inherit] [--global] [--dir PATH]
```

firewall の自動適用設定を管理します。既定は有効です。`--global disabled` は全体の既定を無効にします。プロジェクト単位では `disabled` / `enabled` / `inherit` を設定でき、プロジェクト設定がグローバル設定を上書きします。引数なしで現在の設定と実効値を表示します。

例:

```sh
sunaba config firewall disabled --global
sunaba config firewall disabled --dir /path/to/project
sunaba config firewall enabled --dir /path/to/project
sunaba config firewall inherit --dir /path/to/project
```

```sh
sunaba firewall enable
sunaba firewall disable
sunaba firewall status
```

pf anchor `sunaba` を管理し、コンテナからホスト自身への通信を遮断します。root 権限が必要な場合は `sudo` で自分自身を再実行します。許可された host 操作の範囲は `docs/plan/allowed-host-operations.md` に限定されます。

```sh
sunaba logs [--dir PATH] [-f]
```

当日の監査ログのパスを表示し、内容を出力します。`-f` で追尾します。

## セキュリティ上の注意

- LLM API キーは sunaba 専用の低権限キーを使い、プロバイダ側で支出上限を設定してください
- `~/.ssh`、グローバル git 設定、Keychain などのホスト秘密情報はコンテナへマウントしません
- `sunaba env` で注入するトークンは、対象リポジトリを限定した fine-grained PAT など最小権限のものにしてください
- エージェントがプロジェクトフォルダに書いた git hooks、`.vscode`、`node_modules` などは、後からホスト側の git やエディタが実行し得ます。ホスト側でビルドやコミットをする前に diff を確認してください
- コンテナから外向きインターネット通信は許可されます。プロジェクト内容やコンテナ内認証情報の流出を完全には防げません
- 使わないプロジェクトは `sunaba stop` で停止してください。macOS の仮想化は稼働中コンテナのメモリを保持し続ける場合があります

## 既知の制限

- apple/container 1.0.0 の `container run` にディスク上限フラグが見当たらないため、ディスクサイズはランタイム既定に従います
- LAN 宛て通信は本版では許可のままです
- ホスト側編集のファイルウォッチイベントがコンテナ内へ即時伝播しない場合があります
- `sunaba update` は GitHub API のレート制限を受ける場合があります。その場合は `--opencode-version` を指定してください

## 検証

ビルド、静的解析、単体テストのみを実行する場合:

```sh
scripts/verify.sh
```

コンテナ作成、pf変更、自動承認、reset、イメージ更新を含むA2〜A21の統合検証には、opencodeの有効な認証・モデル設定と、一つ前の有効なリリース番号を指定します。

```sh
SUNABA_FULL_VERIFY=1 \
SUNABA_PREVIOUS_OPENCODE_VERSION=1.17.12 \
scripts/verify.sh
```

統合検証は `sunaba-` プレフィックスの検証コンテナと一時プロジェクトを作成し、終了時に削除します。pf変更に必要な `sudo` を対話的に許可できる端末で実行してください。
