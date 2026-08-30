# sunaba ユーザーガイド

sunabaは、OpenCodeをProject専用のApple Container VMで動かし、ホストの作業ツリー、認証情報、他Project、外部networkとの境界をホスト側で管理します。実際の作業順は[利用ワークフロー](./workflows.md)、保証範囲は[セキュリティ設計・製品仕様](./plan/sunaba-secure-agent-platform.md)を参照してください。

## 利用前の準備

必要な環境はApple silicon Mac、macOS 26、Apple Container exact `1.2.2`です。Apple Containerは利用者が公式手順で導入し、systemを起動します。sunabaは自動導入しません。

```sh
container system start
container system version
```

release bundleでは次の4 binaryを同じdirectoryへ置き、そのdirectoryを`PATH`へ追加します。

- `sunaba`
- `sunaba-ui`
- `sunaba-guest-relay`
- `sunaba-git-hook`

OpenCode host TUIとguest serverは同じv1系exact versionへ固定され、bootstrap値は`1.18.18`です。host OpenCode artifactはsunabaが公式releaseから取得して管理領域へ保存します。利用者がOpenCode、Bun、Node.js、OpenTUIをglobal installする必要はなく、既存のglobal OpenCodeや設定も変更しません。

ソースからbuildする場合はGo 1.22以降とproject-local Bun toolchainを使います。

```sh
./scripts/bootstrap-ui-toolchain.sh
./scripts/build-ui.sh
go build -trimpath -o bin/sunaba ./cmd/sunaba
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o bin/sunaba-guest-relay ./cmd/sunaba-guest-relay
go build -trimpath -o bin/sunaba-git-hook ./cmd/sunaba-git-hook
```

## 通常の入口

TTYで引数なしの`sunaba`を実行すると英語TUIを開きます。

```sh
cd /path/to/project
sunaba
```

current directoryが登録済みProject内なら、そのProjectを自動選択します。Project外では登録済みProjectを選択します。未設定でProjectもない場合はSetupを開きます。

恒常的なtop-level画面は次の3つです。

- `Home`: Project、VM、Agent Session、作業保持状態、pending Change Set、警告、次の推奨action
- `Changes`: 変更file一覧、diff、risk、Change Set全体の適用
- `Settings`: Execution mode、AI connection、Web access、Git remotes。resource、quota、TTL、Snapshot除外、dependency lockはAdvancedとしてCLIから扱う

Setup、Project selector、Recoveryは必要な状態でだけ表示されます。non-TTYで引数なしの`sunaba`を実行すると対話を始めず、明確なerrorで終了します。automationでは明示的なサブコマンドや`project list --json`を使ってください。

## Setup

初回Setupは保存前に次の推奨設定を表示します。`Continue`を選ぶまでProject設定や認証方式を保存しません。

- `Execution mode: Secure`
- `AI connection: OAuth`
- `Web access: Access to standard sites needed for development`
- 安全に検出できたGit remoteは候補として表示し、選択したものだけを登録

Webの通常表示ではorigin数を見せません。`Details`ではexact host/port/method、HTTPS CONNECT内部のmethodやupload内容を検査できない制限、quotaを確認できます。

Continue後、sunabaは固定manifestのhost OpenCode artifactをdownloadしてarchive・executable digestとversionを検証し、bundled `sunaba-ui`もowner、mode、regular file、architecture、digestを検証して管理領域へ保存します。guest artifactとAgent imageも既存の検証経路で準備します。すべてのruntime dependencyはhost-only version lockへ束縛されます。

Bun、OpenTUI、`sunaba-ui`がlockへ追加される前の旧版から更新した場合、引数なしの`sunaba`はProjectを開く前にdependency migrationの確認を表示します。`Continue`後、旧lock、active binding、登録済みProjectのdependency digestがbootstrap契約と完全一致する場合だけ一括移行します。CLIでは`sunaba setup`で同じ移行を実行できます。改変、混在形式、不完全なstateは推測で修復せず停止します。

その後OAuth device flowを開始します。表示されたverification URLをブラウザで開いてcodeを入力してください。ブラウザは自動起動しません。OAuthを中断してもSetup全体は取り消さず、Homeに未設定と表示します。Agent Session開始時は認証が整うまでfail closedで拒否します。

CLIで同じdependency setupだけを行う場合:

```sh
sunaba setup
```

version declarationとlockは次に保存されます。

```text
${XDG_CONFIG_HOME:-$HOME/.config}/sunaba/versions.json
${XDG_CONFIG_HOME:-$HOME/.config}/sunaba/versions.lock.json
```

確認command:

```sh
sunaba versions path
sunaba versions show
```

## ProjectとSnapshot

TUIのSetupまたはProject selectorからcurrent directoryを登録できます。CLIでは次を使います。認証方式はglobal設定を使うため、Project作成時の認証flagはありません。

```sh
sunaba project init /path/to/project
sunaba project list
sunaba project list --json
```

Project pathはsymlinkを解決したcanonical absolute pathとして登録されます。Projectのhost設定は作業ツリー外へ保存されます。

```text
${XDG_CONFIG_HOME:-$HOME/.config}/sunaba/projects/<ProjectID>/
```

新しいVMを作る前はSnapshot metadataをpreviewし、exact digestを承認します。内容やsecret値はpreviewへ表示しません。

```sh
sunaba snapshot preview --dir /path/to/project
sunaba snapshot approve --dir /path/to/project --digest <表示されたdigest>
```

host Projectが変わった後は、次のVM作成前にpreviewと承認をやり直します。

## HomeとOpenCode

Homeは現在実行できるactionだけを表示します。主なactionは`Start`、`Resume`、`Review changes`、`Settings`、`Recovery`です。

StartまたはResumeを選ぶと、sunaba TUIはterminalを完全にrestoreして終了し、Go側が固定artifactのOpenCode TUIを開始します。同じterminalで2つのTUIを同時に動かしません。OpenCode終了後、Session capability、relay、server password等を失効し、新しいsunaba TUIでHomeへ戻ります。

OpenCodeを終了してもVM workspaceは保持されます。自動export、自動apply、自動destroyは行いません。次回Resumeするか、Changesへ進んでください。

高度なCLI経路:

```sh
sunaba up --dir /path/to/project
sunaba agent --dir /path/to/project
sunaba console --dir /path/to/project
```

`console`はboundedな1行commandをVMで実行するsanitized consoleです。raw PTYではありません。旧script向けに`sunaba shell`をaliasとして維持します。argvを分離した単発実行はsecure modeで利用できます。

```sh
sunaba exec --dir /path/to/project --cwd . -- go test ./...
```

## AI connectionとcredential

認証方式は全Project共通の`OAuth`または`API key`です。既定はOAuthです。Settingsの`Change authentication method`またはglobal CLIだけが方式を変更します。

```sh
sunaba model auth oauth
sunaba model auth api-key
```

方式変更はactive Agent Sessionへ影響せず、全Projectの次Sessionから有効です。選択方式のcredentialがない、無効、期限切れ、refresh失敗、model allowlistと非互換の場合はSession開始前またはrequest時に拒否し、別方式へ自動fallbackしません。

OAuthとAPI keyは同時に保存でき、方式変更で未使用側を削除しません。TUIは再認証と方式変更を提供し、完全削除はCLIだけで行います。

```sh
sunaba credentials openai oauth login
sunaba credentials openai oauth status
sunaba credentials openai oauth delete

sunaba credentials openai api-key set
sunaba credentials openai api-key status
sunaba credentials openai api-key delete
```

API keyのTTY入力はechoを無効にし、TUI入力はmaskします。secretをargv、environment、Project設定、VM、画面、log、auditへ載せません。credentialは次のhost-only strict JSONへ保存されます。

```text
${XDG_DATA_HOME:-$HOME/.local/share}/sunaba/credentials/openai.json
```

activeな認証方式だけを含む非secret設定:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/sunaba/settings.json
```

directoryはcurrent user所有のmode `0700`、fileとlockはmode `0600`で、symlink・hardlink・不正type・不正ownerを拒否します。更新はprocess間lockとatomic renameで直列化されます。

sunabaはKeychain、`/usr/bin/security`、Security.frameworkを使用しません。旧`dev.sunaba.openai` Keychain itemは読み取らず、移行も自動削除もしないため、更新後は再認証が必要です。不要な旧itemを削除する場合だけ、利用者自身がKeychain Access等で手動削除してください。

このfile保存は同じmacOS user権限の別processから読まれ得ます。これは受容済みの残余リスクです。

## Model allowlist

`model list`はglobal認証方式のcatalogを表示し、`model set`は選択Projectのallowlistだけを変更します。

```sh
sunaba model list --dir /path/to/project
sunaba model set --dir /path/to/project --model gpt-5.5 --model gpt-5.6-sol
```

global方式とallowlistが非互換ならmodelを暗黙に置換せず、対象modelと修正actionを示します。

## Settingsと高度な設定

TUI SettingsではExecution mode、AI connection、Web access、Git remotesを扱います。Git remoteはhostで検出しただけでは登録せず、利用者が選択した場合だけ固定HTTPS `.git` URLとして保存します。

高度な設定はhost-only fileをCLIで編集します。

```sh
sunaba config path --dir /path/to/project
sunaba config edit --dir /path/to/project
sunaba config validate --dir /path/to/project
sunaba config diff --dir /path/to/project
sunaba config apply --dir /path/to/project
sunaba config show --effective --dir /path/to/project
```

mode、resource、dependency/image、Snapshot除外、export上限、Protected PathはVM再作成が必要です。Model/Git/Web、quota、TTL等は次のAgent Sessionから反映されます。未適用または不正な設定がある間、`up`、`agent`、`console`はfail closedで拒否します。

## Web access

Setupの推奨設定は`common-development` presetです。Web Gatewayは固定origin、DNS解決後のpublic IP、method、redirect、blocklist、request/concurrency/time/byte quotaをhostで強制し、実credentialをVMへ渡しません。

HTTPS CONNECTはhost、port、接続先IP、時間、byte数を制御できますが、暗号化された内部method、path、header、upload内容は検査できません。許可originへ送ったProject情報の安全性までは保証しません。

CLIで明示変更する場合:

```sh
sunaba web enable --default-origins --dir /path/to/project
sunaba web disable --dir /path/to/project
```

## Git remoteとpush承認

Git credentialはhost側だけで解決されます。remoteはcredentialを含まない固定HTTPS URLとして登録します。

```sh
sunaba git remote add --dir /path/to/project --name origin --url https://github.com/example/repository.git
sunaba git remote list --dir /path/to/project
```

OpenCode中の最初のpushはpending host approvalを作って拒否されます。OpenCode TUIはguest由来の画面なので、その中だけでは承認できません。別のhost terminalで次を実行します。

```sh
sunaba approvals --dir /path/to/project
```

remote、ref、old/new object ID、force/deleteを確認し、approveまたはrejectします。承認はexact bindingへのone-shotで、期限内に変更せず同じpushを再実行した場合だけ有効です。

## Changes

Changesにはhostがbaselineとexport結果から生成したChange Setの変更fileだけを表示します。状態は`A`、`M`、`D`、`R`です。wide terminalはbefore/afterのside-by-side、narrow terminalはunified diffへ切り替わります。

symlink、実行可能file、binary、巨大file、mode変更にはrisk表示が付きます。内容を安全に表示できない場合はtype、size、hash、理由を表示し、外部previewを起動しません。reviewを中断してもpending Change Setは保持されます。

`Apply all changes`は表示中のChange Set全体だけを適用します。部分適用はありません。Go側がview revision、Project、baseline、Merged View、Change Set、一回限りのapprovalを内部で束縛するため、digestやnonceの手入力は不要です。

CLI経路:

```sh
sunaba changes export --dir /path/to/project
sunaba changes review --dir /path/to/project
sunaba changes apply --dir /path/to/project
```

CLI applyの確認phraseは`apply all changes`です。適用後はhost Projectが変わるため、新しいVMの前にSnapshot previewと承認をやり直します。

## Recovery

Recovery画面は破壊的操作の前に、削除対象、保持対象、回復不能になる作業、安全な代替actionを表示します。error画面も拒否理由、作業が保持されているか、次のactionを示します。

exportやExternal Git guardで失敗した場合、sunabaは停止VMや検証済みfrozen成果物を自動削除しません。通常は原因を解消してexportを再試行します。

```sh
sunaba status --dir /path/to/project
sunaba changes export --dir /path/to/project
```

VM-only作業やpending成果物を明示的に捨てる場合だけ、次を使います。

```sh
sunaba recreate --dir /path/to/project --discard-pending
sunaba destroy --dir /path/to/project --yes --discard-pending
```

`destroy`はhost Project自体を削除しません。Project directoryが失われた場合は`project list`に表示される完全なProject IDで復旧操作を指定できます。

## OpenCode更新

更新はsession開始時に自動実行しません。明示的なcheck/applyだけを使います。

```sh
sunaba versions set 1.x.y
# または sunaba versions track v1-stable
sunaba update check
sunaba project list --active
sunaba update apply
```

`update check`は公式releaseのexact version、commit、host/guest artifactをhost-only quarantineへ固定し、active lockやProjectを変更しません。`update apply`は候補、設定、現行lock、digest、versionを再検証し、managed host OpenCode、guest image、Project policy、global lockをtransactionで切り替えます。旧imageや旧managed toolを自動削除しません。

## secure modeとdev mode

secure modeではModel、Git、Web Gateway以外の外向き通信を拒否します。host Projectをbind mountせず、credentialをVMへ渡しません。

dev modeはforegroundのAgentまたはconsole中だけ専用networkから直接Internetへ接続でき、情報流出防止を保証しません。終了時はegressをdeny-allへ戻してexport・destroyします。失敗時だけcapabilityとnetworkを失効した停止VMをRecoveryへ保持します。必要な場合だけ選択してください。

## 状態確認

```sh
sunaba doctor --dir /path/to/project
sunaba status --dir /path/to/project
sunaba project list --active
```

`doctor`はread-onlyで前提条件、fixed dependency、managed helper、設定、state、blocklistを確認します。`status`はVM、Session期限、pending/recovery、quota、global認証方式等を表示します。内部digestやschemaは通常TUIには表示しません。

## 保証しないこと

- 許可したLLM、Git remote、Web originへ利用者またはAgentが送信した情報の保存・再利用
- dev mode active session中の情報流出防止
- HTTPS CONNECT tunnel内部のmethod、path、header、upload内容の検査
- Agentが生成したcode、dependency、binaryの安全性
- 同じmacOS user権限の別processに対するcredential fileの秘匿
- toolchain/cache永続化、Change Set部分適用、syntax highlight、review済みfile追跡、mouse、日本語UI、plugin、embedded terminal
