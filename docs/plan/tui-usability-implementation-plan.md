# sunaba TUI・UX実装計画

## 1. 位置づけ

本文書は、sunabaの既存セキュリティ境界を維持したまま、通常操作をOpenTUIによるTUIへ集約するための実装計画である。製品仕様とセキュリティ判断は[`sunaba-secure-agent-platform.md`](./sunaba-secure-agent-platform.md)、実装・検証で許可されるホスト操作は[`allowed-host-operations.md`](./allowed-host-operations.md)を正本とする。矛盾した場合は正本を優先する。

本文書は実装手順、責務分割、状態遷移、受け入れ条件だけを定義する。実装進捗や検証結果は`docs/implementation/`へ記録する。

## 2. 実装範囲

今回実装する。

- 引数なしの`sunaba`を通常利用の入口とする英語TUI
- 初期設定、Project選択、Home、Settings、Change Set review、復旧確認
- OpenCode TUIへの安全なterminal引き渡しと、終了後のsunaba TUI復帰
- Git push承認をOpenCode TUIと分離したhost terminalで処理する導線
- 既存CLIを自動化、高度な操作、復旧用として維持する
- OAuthとAPI keyをKeychainではなくhost-only認証ファイルへ保存する
- Model認証方式をProject別ではなくsunaba全体の設定とする
- Web Gatewayを推奨設定で有効にし、`common-development` presetを使う
- 検出したGit remoteを候補として提示し、利用者の確認後だけ登録する
- `shell`の通常表示名を`console`へ変更し、CLIでは`shell`をaliasとして残す

今回実装しない。

- toolchainや依存cacheの永続化
- Change Setの部分適用
- diffのsyntax highlight
- review済みfileの追跡と、未review fileに対する警告
- mouse操作
- plugin方式のTUI拡張、embedded terminal、画像、clipboard、通知、外部editor起動
- 日本語UIと言語切替

## 3. 固定する利用者体験

### 3.1 起動とProject選択

- TTYで`sunaba`を引数なしで実行するとTUIを開く。
- current directoryが登録済みProject内なら、そのProjectを自動選択する。
- Project外なら、登録済みProjectの一覧を表示して選択させる。
- 登録済みProjectがなく、初期設定も未完了ならSetupを開始する。
- non-TTYでは対話を開始しない。既存サブコマンドまたは`--json`を使用し、曖昧な場合は明確なerrorで終了する。

### 3.2 恒常画面

恒常的なtop-level画面は次の3つだけにする。

1. `Home`
2. `Changes`
3. `Settings`

SetupとRecoveryは必要な状態でだけ表示する。機能ごとにtop-level画面を増やさない。

### 3.3 Home

Homeは内部digest、nonce、capability、policy schemaを通常表示しない。次だけを短く示す。

- 選択中Project
- VMとAgent Sessionの状態
- 現在の作業を安全に保持できているか
- pending Change Setの有無
- 利用者が判断すべき警告
- 次に行う推奨action

表示するactionは現在状態で実行可能なものだけに限定する。主なactionは`Start`、`Resume`、`Review changes`、`Settings`、`Recovery`である。

OpenCode終了後はVMとworkspaceを保持し、Homeへ戻す。自動export、自動apply、自動destroyは行わない。Homeから`Resume`、`Review changes`、終了・復旧操作を選べるようにする。

### 3.4 Setup

未設定状態で`sunaba`を起動するとSetupを表示する。推奨設定は次の1組とし、利用者が確認して`Continue`を選んだ後にだけ適用する。

- `Execution mode: Secure`
- `AI connection: OAuth`
- `Web access: Access to standard sites needed for development`
- Git remoteを安全に検出できた場合は候補を表示する。ただし確認済み既定値へ自動追加せず、利用者が選択したremoteだけを登録する

通常の確認画面ではWeb origin数を表示しない。`Details`にだけexact origin、HTTPS CONNECTでは暗号化された内部methodやupload内容を検査できない制限、quotaを表示する。

Setupは次を自動実行する。

- dependency manifestが固定するexact OpenCode host artifactをsunaba管理領域へdownloadする
- digestを検証し、host-only version lockへ束縛する
- guest artifactとAgent imageを既存の安全なsetup経路で準備する
- 利用者が既に導入したOpenCodeやglobal OpenCode設定を変更しない

利用者へBun、Node.js、OpenTUI、OpenCodeのglobal installを要求しない。Apple Containerがない場合は自動導入せず、公式の導入手順を表示する。

推奨設定の確認後にOAuth device flowを開始する。verification URLとcodeを表示するがbrowserは自動起動しない。認証を中断してもSetup全体は失敗扱いにせず、Homeで`AI connection: Not configured`を表示し、Agent Session開始時だけ認証を要求する。

認証情報の保存方式やfile pathはSetup画面へ表示しない。利用者向け説明は実装完了時に`docs/user-guide.md`へ記載する。

### 3.5 Settings

Settingsは次のsectionだけを通常表示する。

- `Execution mode`
- `AI connection`
- `Web access`
- `Git remotes`

CPU、memory、disk、quota、TTL、Snapshot除外、digest等は`Advanced`へ置く。

`AI connection`の通常表示は現在の認証方式と状態だけにする。`Used by all projects`等の補足は表示しない。未使用側の認証状態は`Change authentication method`を開いた場合だけ表示する。

認証方式はsunaba全体で`OAuth`または`API key`のどちらか1つを選ぶ。Project画面、Project作成、Agent Session開始時に選択を毎回表示しない。変更は`Settings > AI connection > Change authentication method`または対応するglobal CLIを明示実行した場合だけ行う。別方式のcredentialが登録済みでも自動fallbackしない。

OAuthとAPI keyは両方保存できる。方式を変更しても未使用側を削除しない。TUIには`Sign out`を設けない。再認証と方式変更だけを提供し、完全削除は高度な操作・廃棄用の`sunaba credentials openai ... delete`に限定する。

方式変更はactive Agent Sessionへ影響させない。新しい設定は次に開始するAgent Sessionから全Projectへ適用する。

API keyはmaskされた入力欄で受け取る。secretを画面、履歴、log、audit、argv、environmentへ出さない。OAuthはverification URLとcodeだけを表示する。

### 3.6 OpenCode TUIとの切替

`Start`または`Resume`を選ぶと、sunaba TUIはterminalを完全にrestoreして終了し、Go側がOpenCode TUIを開始する。同じterminal上で2つのTUIを同時に動かさない。

OpenCode TUI終了後、Go側がSession capability、relay、server password等を既存仕様どおり失効し、sunaba TUIを新しく起動してHomeへ戻す。OpenTUI helperがOpenCode process、VM、Gatewayを直接起動・停止しない。

### 3.7 Change Set review

Changes画面に表示するのは、hostがbaselineとexport結果から生成したChange Setに含まれる変更fileだけとする。

- 左pane: 変更file一覧
- 右pane: 選択fileのdiff
- 状態label: `A`、`M`、`D`、`R`
- wide terminal: before/afterのside-by-side
- narrow terminal: unified diffへ自動fallback

初期実装は追加行と削除行だけを色分けし、色だけに意味を依存させない。syntax highlightは行わない。

symlink、実行可能file、binary、巨大fileには明示的なrisk表示を付ける。安全に内容表示できないfileはtype、size、hash、表示できない理由を示し、外部previewを起動しない。

reviewは途中で終了できる。pending Change Setを保持し、同じChange Setのreviewを再開できる。初期実装では閲覧済みfileを記録しない。

`Apply all changes`はChanges画面からだけ実行でき、対象はChange Set全体とする。部分適用は行わない。利用者へdigestやnonceの手入力を求めず、Go側が表示中のChange Set identityと一回限りの承認を内部で束縛する。

### 3.8 Git push承認

OpenCode TUIをguest由来の画面として扱い、push承認をその内部で完結させない。OpenCode利用中のpush承認は別のhost terminalから既存approval経路を開いて行う。sunaba TUIへ戻った後はpending approvalの有無をHomeに表示できるが、guest表示だけで承認済みにしない。

### 3.9 Recovery

Recoveryは別applicationにせず、sunaba TUI内の確認画面とする。破壊的操作では次を表示してから明示確認を取る。

- 削除されるもの
- 保持されるもの
- 回復不能になる作業
- 推奨される安全な代替action

error表示は失敗内容だけでなく、拒否理由、作業が保持されているか、次に実行するactionを示す。

## 4. 実装アーキテクチャ

### 4.1 process境界

次の境界を固定する。

```text
sunaba (Go authority)
  <-> owner-only Unix socket + bounded JSON protocol
sunaba-ui (bundled OpenTUI executable)
  <-> host terminal
```

`sunaba` Go processだけが次を所有する。

- Project、VM、Sessionの状態判定
- policyのload、validation、compile
- Snapshot、export、Change Set生成
- credentialの保存と読取
- Gateway、capability、relay、監査
- apply、destroy、recovery等のmutation
- 表示データのsanitizationとsize bound
- actionが現在状態で許可されるかの最終判断

`sunaba-ui`は次だけを行う。

- Goが送ったview modelの描画
- keyboard inputの解釈
- 選択されたactionとboundedな入力値の返却
- terminalの初期化とrestore

TUI helperへProject pathを渡してfileを直接読ませない。credential file、policy、Change Set materialization、VM socketを開かせない。helperからnetwork接続、shell、browser、clipboard、通知、plugin、外部editorを起動するAPIを提供しない。

### 4.2 OpenTUI artifact

- UIは`@opentui/core`だけで構築する。React binding等は初期実装へ追加しない。
- build時に選定したOpenTUIとBunのexact versionをdependency manifestとhost-only lockへ追加する。
- `bun build --compile`相当のstandalone executableとして`sunaba-ui`を生成し、release bundleへ含める。
- 実行時にBun、Node.js、package manager、network downloadを要求しない。
- artifactのplatform、architecture、SHA-256をGo側が起動直前に検証する。
- helperのauto updateを行わない。更新は既存の`update check` / `update apply`へ統合する。

### 4.3 UI protocol

protocolはversion付き、request/response型のbounded JSON messageとする。newline区切りの無制限streamにせず、各frame lengthを先に検証する。最低限次を持つ。

- protocol version
- screen ID
- immutable view revision
- sanitized text field
- action ID
- bounded input field
- terminal capabilityとwidth/height
- normal exit、cancel、terminal error

actionはGoがそのview revisionに対して発行した固定IDだけを受け付ける。helperが任意のCLI commandやpathを返す形式にしない。古いrevision、未知action、oversize、unknown field、trailing dataを拒否する。

socket directoryはOS temp配下のsunaba専用mode `0700` directory、socketはcurrent user以外から接続できない状態にする。Project ID、process identity、ランダムnonceへ束縛し、接続は1つだけ許可する。helper終了、timeout、protocol違反時はsocketと一時directoryを除去し、mutationを行わずfail closedに戻る。

### 4.4 terminal安全性

- Go側でguest由来のtext、file name、diff、errorをsanitizeする。
- C0/C1、ESC、OSC、CSI、BEL、bidi override、改行によるlayout偽装をtest対象にする。
- helperは受信textをterminal escapeとして再解釈しない。
- terminal stateはnormal exit、cancel、panic、signalの全経路でrestoreする。
- color非対応terminalでもlabelと記号で同じ意味を読めるようにする。
- initial keyboard操作はarrow、Tab、Enter、Escapeと画面に表示した少数のshortcutに限定する。

## 5. 認証情報とglobal設定

### 5.1 保存場所

secretは次へ保存する。

```text
${XDG_DATA_HOME:-$HOME/.local/share}/sunaba/credentials/openai.json
```

globalな認証方式は次へ保存する。

```text
${XDG_CONFIG_HOME:-$HOME/.config}/sunaba/settings.json
```

`openai.json`はOAuthとAPI keyを別fieldとして同時に保持できるversion付きstrict JSONとする。`settings.json`はactiveな認証方式だけを保持し、secretを含めない。

### 5.2 file安全条件

両storeは既存`internal/securefs`のprimitiveを共通利用し、次を必須にする。

- parent directoryはcurrent user所有、mode `0700`、canonical absolute path、symlinkなし
- fileはcurrent user所有、mode `0600`、regular file、symlinkなし、hardlinkなし
- `O_NOFOLLOW`相当で開き、open後のidentity、owner、mode、sizeを検証する
- strict JSON、unknown field拒否、trailing data拒否、fieldごとの長さとcontrol文字検証
- 同一directoryの新規一時fileへmode `0600`で完全書込、`fsync`、atomic rename、directory `fsync`
- current user所有の固定lock fileでprocess間のread-modify-writeとOAuth token rotationを直列化する
- API key更新時にOAuthを、OAuth更新時にAPI keyを消さない
- secret値をerror、log、audit、argv、environment、Project設定、VM inputへ出さない

Keychainよりat-rest保護が弱く、同じmacOS user権限の別processから読まれ得ることは受容済みの残余リスクとする。暗号化keyをKeychainや利用者passwordへ戻す設計は採用しない。

### 5.3 Keychain廃止

- `/usr/bin/security`呼出しとSecurity.framework bindingを削除する。
- login Keychainをread、write、enumerate、deleteしない。
- 旧Keychain itemを移行しない。更新後は再認証を要求する。
- 旧Keychain itemを自動削除しない。
- user guideには必要な場合だけ手動削除できることを記載するが、通常Setupには表示しない。

### 5.4 global認証方式

- 既定値は`oauth`とする。
- Project作成時の`--model-auth`とProject別の認証切替UIを削除する。
- `sunaba model auth api-key|oauth`はProject selectorを取らないglobal操作へ変更する。
- Projectの利用者設定から認証方式を除き、Agent Session開始時にglobal設定を読み、session authorityへsnapshotする。
- active Sessionは開始時の方式を終了まで保持する。
- credentialがない、無効、期限切れ、refresh失敗の場合は別方式へfallbackせずSession開始またはModel requestを拒否する。
- global方式とProjectのmodel allowlistが両立しない場合はSession開始前に拒否し、対象modelと修正actionを示す。modelを暗黙に置換しない。
- Project設定schemaの変更ではper-Project auth fieldだけを取り除き、VM、pending Change Set、Project identityを破棄しないmigrationを用意する。credentialのKeychain migrationは用意しない。

## 6. 実装単位

### 6.1 認証store

対象: `internal/secretstore/`、`internal/openauth/`、`internal/cli/credentials.go`

- Keychain実装とplatform stubをfile storeへ置き換える。
- OAuth refreshのatomic rotationと複数Supervisor間lockを実装する。
- CLIの`set/status/delete/login`を同じfile storeへ接続する。
- API keyの対話入力はTTYではechoを無効にし、TUIではmasked fieldを使う。pipe入力を許す場合も1行、size bound、control文字拒否を適用する。
- `status`は存在と妥当性だけを返し、token、account ID、期限の不要な詳細を表示しない。

### 6.2 global settings

対象: 新規`internal/usersettings/`、`internal/cli/`、`internal/policy/`、`internal/projectconfig/`、`internal/configwizard/`

- `settings.json`のstrict storeを追加する。
- Project設定とwizardからauth選択を除く。
- global auth変更commandを追加し、active Sessionへ反映しない。
- session activationでglobal modeとProject model allowlistを同時に検証し、認証方式別model metadataを生成する。
- `model list`はglobal modeのcatalogを表示し、`model set`は選択Projectのallowlistだけを変更する。

### 6.3 Go側TUI coordinator

対象: 新規`internal/tui/`または同等のhost-only package、`internal/cli/commands.go`

- TTY判定、Project自動選択、screen state machineを実装する。
- 既存serviceを直接呼び、CLI command文字列をsubprocess実行しない。
- actionごとに既存lock、validation、audit経路を再利用する。
- OpenCodeへterminalを渡す前にhelperを終了し、終了後に新しいhelper processでHomeを再構築する。
- `sunaba-ui`のdigest、owner、mode、regular file、architectureを毎回検証する。

### 6.4 OpenTUI helper

対象: 新規のproject-local UI source directoryと`cmd/sunaba-ui`相当のbuild artifact定義

- Home、Project selector、Setup、Settings、Changes、Recovery componentを実装する。
- componentがpolicy判断を持たないよう、表示とevent変換だけにする。
- narrow/wide diff layoutをterminal widthから決める。
- exitとsignal時のterminal restore test harnessを用意する。

### 6.5 Change Set review

対象: `internal/workspace/`、既存review renderer、TUI coordinator

- host生成Change Setから変更file indexと選択fileのbounded diff modelを生成する。
- directory全体や未変更fileを列挙しない。
- binary、large file、symlink、mode、renameのmetadataをGo側で分類する。
- apply actionは表示中revisionとpending Change Set identityへ内部束縛し、再load時のidentity不一致を拒否する。
- CLI review/applyも同じrendererとauthorityを使い、自動化・復旧経路として維持する。

### 6.6 Setupとdependency

対象: `internal/dependency/manifest.json`、version lock、setup/update、release build

- OpenTUI、Bun、`sunaba-ui` artifactのexact dependencyとdigestをmanifest/lockへ追加する。
- build dependencyとruntime dependencyを区別する。
- setupでmanaged Host OpenCodeと`sunaba-ui`を取得・検証する。
- global install、利用者のOpenCode設定変更、session開始時の自動更新を行わない。

### 6.7 公開CLI差分

| 現在 | 実装後 |
|---|---|
| 引数なしはhelp | TTYはsunaba TUI、non-TTYは非対話error/help |
| `project init --model-auth ...` | flagを削除しglobal認証方式を使用 |
| `model auth ... --dir/--project-id` | selectorなしのglobal操作 |
| `shell` | `console`を正規名とし、`shell`をaliasとして維持 |
| Keychainを操作する`credentials` | 同じcommand群がhost-only credential fileを操作 |
| line-oriented `config edit` | 高度なCLIとして維持し、通常設定はTUIから同じGo serviceを利用 |
| line-oriented `changes review/apply` | 高度なCLIとして維持し、通常review/applyはChanges画面から同じGo serviceを利用 |

既存commandをTUIからshell-outして再利用しない。共通のGo serviceへCLIとTUIの両frontendを接続する。

## 7. 実装順序

1. 正本、schema、protocol、credential fileのcontract testを先に追加する。
2. Keychainをfile storeへ置換し、OAuth login/refresh、API key、並行更新をunit testする。
3. global settingsを追加し、Project別authを除去してsession snapshotへ接続する。
4. OpenTUI/Bunのexact versionとstandalone buildを固定し、空のHomeをGo coordinatorから起動する。
5. Project選択、Home、OpenCode handoff/returnを実装する。
6. SetupとSettingsを実装する。
7. file選択式Changes reviewと全体applyを実装する。
8. RecoveryとGit push承認導線を統合する。
9. CLI alias、non-TTY、JSON出力、error文を整合させる。
10. user guide、workflow、READMEを実装済み挙動へ更新し、implementation evidenceを記録する。

各段階は`./scripts/verify.sh`と`./scripts/verify-race.sh`を通してから次へ進む。OpenTUI helperのdependency取得やbuildはproject-local lockを使い、global installを行わない。

## 8. 必須テスト

### 8.1 credential

- directory/file/lockのowner、mode、symlink、hardlink、type、size異常を拒否する
- unknown JSON field、trailing data、oversize、control文字を拒否する
- API keyとOAuthを同時保存し、一方の更新・削除で他方を保持する
- crash境界と並行refreshでvalidな旧版または新版だけが残る
- secretがargv、environment、log、audit、error、Project、VMに出ない
- Keychain APIと`/usr/bin/security`を呼ばない
- Keychain itemが存在しても読まず、fileがなければ未認証になる

### 8.2 global auth

- fresh settingsはOAuthになる
- auth変更が全Projectの次Sessionへ適用され、active Sessionは不変になる
- Project作成・起動時にauth選択を毎回表示しない
- credential欠如時に別方式へfallbackしない
- incompatible model allowlistをSession開始前に拒否する
- Project設定migrationがVMとpending Change Setを削除しない

### 8.3 TUI protocolとterminal

- 別user、複数接続、古いrevision、未知action、oversize frame、unknown fieldを拒否する
- malicious file名、diff、error、ANSI/OSC/BEL/bidiでterminal作用やlayout偽装が起きない
- normal exit、Escape、panic、SIGINT、helper crashでterminalが復元される
- non-TTYでTUIを開始しない
- helperがProject、credential、policy fileやnetworkを直接利用しないことをtest seamで確認する

### 8.4 UX state

- Project内外、未設定、未認証、VMなし、paused、active、pending changes、recoveryの各Homeをgolden testする
- 表示actionがGo側の許可状態と一致する
- OpenCode前にsunaba TUIが終了し、OpenCode終了後にHomeへ戻る
- Setupの推奨設定は`Continue`前に永続化されない
- Webの通常表示がorigin数ではなく指定文言になる
- Git remoteは検出だけでは登録されず、確認後だけ保存される

### 8.5 Changes

- 変更fileだけを一覧表示する
- add、modify、delete、rename、mode、symlink、binary、large fileを分類する
- wide side-by-sideとnarrow unifiedが同じChange Setを表す
- review終了後もpendingを保持し再開できる
- applyは全体だけで、stale revision、baseline変更、Change Set identity変更を拒否する
- digestやnonceの手入力なしで一回限りの承認へ束縛される

## 9. 完了条件

- 通常利用者が`sunaba`以外のコマンドを覚えずにSetup、開始、再開、変更確認、適用、設定、復旧へ到達できる。
- 表示する機能は現在状態に必要なものだけで、top-level画面がHome、Changes、Settingsを超えない。
- guest由来の表示data、利用者入力、またはprotocol異常だけでは、Go authorityの許可を越えてVM、credential、host Project、policyを変更できない。
- 既存のVM、Gateway、Snapshot、Change Set、approvalのセキュリティ不変条件が維持される。
- 認証にmacOS password promptを必要とせず、Keychainへアクセスしない。
- UIは英語、利用者向け文書と実装計画は日本語で整合する。
- 保留したtoolchain/cache永続化と部分applyが混入していない。
