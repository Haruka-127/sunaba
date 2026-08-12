# sunaba 利用者ガイド

このガイドは、Apple silicon Macでsunabaを導入し、OpenCodeを隔離されたAgent VMで利用し、成果物をhost Projectへ安全に反映するための手順を説明する。製品保証の正本は[`plan/sunaba-secure-agent-platform.md`](./plan/sunaba-secure-agent-platform.md)、許可されたhost操作は[`plan/allowed-host-operations.md`](./plan/allowed-host-operations.md)である。

## 1. 前提条件

- Apple silicon搭載MacとmacOS 26
- Apple Container exact `1.2.2`
- OpenCode host TUI / guest server exact `1.18.16`
- buildにGo 1.22以降
- OpenAI APIの従量課金API key、またはCodexを利用できるChatGPT subscription

Apple Container systemは利用者が起動する。

```sh
container system start
container system version
```

hostの`opencode`はPATH上に置く。sunabaは実行前にversionと固定SHA-256を検証するため、v2、`latest`、別buildへの自動fallbackは行わない。

## 2. build

repository rootで3つのbinaryを同じdirectoryへbuildする。global installは不要である。

```sh
mkdir -p bin
go build -trimpath -o bin/sunaba ./cmd/sunaba
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o bin/sunaba-guest-relay ./cmd/sunaba-guest-relay
go build -trimpath -o bin/sunaba-git-hook ./cmd/sunaba-git-hook
bin/sunaba help
```

以降はrepository rootから`bin/sunaba`を使う例を示す。別directoryへ配置する場合も3 binaryを分離しない。

## 3. OpenAI credentialを登録する

API keyは環境変数ではなく、macOS login Keychainの固定itemへ登録する。

```sh
bin/sunaba credentials openai api-key set
bin/sunaba credentials openai api-key status
```

`set`を実行するとKeychain自身がpassword入力を求める。入力値はterminalに表示されず、argv、Project file、sunaba policy、auditへ保存されない。固定identityはservice `dev.sunaba.openai`、account `openai-api-key`である。

削除する場合は、先に各Projectで`changes export`または`destroy`を行い、起動中のSupervisorを終了してから実行する。既に起動しているSupervisorは、終了するまでmemory上に読み込み済みのkeyを保持し得る。

```sh
bin/sunaba credentials openai api-key delete
```

ChatGPT subscriptionを使う場合はdevice flowでログインする。表示されたURLをブラウザで開き、表示されたcodeを入力する。sunaba自身はブラウザを起動しない。

```sh
bin/sunaba credentials openai oauth login
bin/sunaba credentials openai oauth status
```

OAuth tokenは固定account `codex-oauth`へ保存され、期限前にhost側でrefreshされる。削除は`bin/sunaba credentials openai oauth delete`で行う。

## 4. 最短のsecure mode利用手順

`PROJECT`には既存Projectの絶対pathを指定する。

```sh
PROJECT=/absolute/project/path
bin/sunaba project init "$PROJECT" --mode secure
bin/sunaba up --dir "$PROJECT"
bin/sunaba agent --dir "$PROJECT"
```

`project init`はhost-onlyなProject設定と、そこからcompileした実効policyを作る。`up`はhost worktreeの安全なSnapshotからnetworkなしのVMを準備し、検証後にpauseして返す。`agent`は同じVMをresumeし、VM内rootかつOpenCode tool確認を全許可したOpenCode serverへ、隔離済みhost TUIを接続する。TUIを終了するとGatewayをinactiveにしてVMを再びpauseする。期限内の次回`agent`は同じVMと編集状態を再利用する。root権限はVM内に限定され、host Project、直接network、Gateway quota、Git pushとChange Set適用のHost承認は迂回できない。

Projectごとの起動設定はProject folder内ではなく、`${XDG_CONFIG_HOME:-$HOME/.config}/sunaba/projects/<ProjectID>/project.json`に置かれる。実際のpathは次で確認できる。

```sh
bin/sunaba config path --dir "$PROJECT"
bin/sunaba config show --dir "$PROJECT"
bin/sunaba config show --effective --dir "$PROJECT"
```

`project.json`ではmode、CPU/memory/disk/process上限、session TTL/idle、Model allowlist/quota、Git remote、Webの組み込みorigin presetとquota、export上限、audit retentionを管理する。dependency digest、credential、capability、preset内容/digest、blocklist digest、push承認必須、Protected Pathはsunabaが生成するため記述できない。設定directoryはmode `0700`、fileはmode `0600`であり、VMにはmount/copyされない。

通常はhost上の対話ウィザードで設定できる。現在値を既定として、secure/dev、Model認証と許可model、Git Gateway remote、Web Gatewayの組み込みpresetとProject固有origin、必要に応じてresourceとquotaを順に質問する。Git Gatewayを有効にすると、安全に検証できたProjectのlocal Git remoteを候補表示し、`y`で選択できる。候補がない場合や別remoteを使う場合は、固定remote名とcredentialを含まないHTTPS `.git` URLを入力する。候補は自動登録しない。dev modeまたはWeb Gatewayを選ぶと、その時点で保証範囲の警告を表示する。最終確認で`y`を入力するまでは設定fileも実効policyも変更しない。

```sh
bin/sunaba config edit --dir "$PROJECT"
```

`config edit`は設定を保存して同じ操作内で適用するため、active/paused VMまたはpending Change Setがある場合は開始を拒否する。先に変更をexportして`recreate`するか、pending Change Setを処理する。credentialはウィザードへ入力せず、`credentials` commandでKeychainへ別途登録する。

編集後は次の順序で明示適用する。未適用または不正な設定がある間、`up`、`agent`、`shell`は起動を拒否する。`status`と停止・export・recreate・destroyは復旧のため引き続き使用できる。active/paused VMまたはpending Change Setがある場合は、先に`changes export`または`recreate`を行う。

```sh
chmod 600 /path/shown/by/config/path/project.json
bin/sunaba config validate --dir "$PROJECT"
bin/sunaba config diff --dir "$PROJECT"
bin/sunaba config apply --dir "$PROJECT"
```

OAuthを使うProjectは初期化時に認証方式を指定する。OAuthの既定allowlistには認証別catalogの全モデルが入り、先頭の推奨モデルがOpenCodeの既定modelになる。既存Projectはactive sessionを終了した後に切り替えられる。認証方式を変えたとき、現在のmodel allowlistが移行先で使えなければ同じ認証別既定allowlistへ置き換わる。既存Projectで明示済みの有効なallowlistは自動拡張しない。

```sh
bin/sunaba project init "$PROJECT" --mode secure --model-auth oauth
# または既存Projectで
bin/sunaba model auth oauth --dir "$PROJECT"
```

OpenCodeにはcustom `sunaba` providerが設定される。API keyとOAuthではcontext/input/output上限が別定義であり、subscriptionの小さいinput上限に合わせてOpenCodeのcompactionが開始される。model discoveryは行わず、Project policyと認証別の固定catalogにないmodelはセッション開始前に拒否される。

現在の認証方式で利用可能なmodelと上限を確認し、Projectで許可するmodelを設定できる。`model set`の先頭を既定modelとしてOpenCodeへ渡す。

```sh
bin/sunaba model list --dir "$PROJECT"
bin/sunaba model set --model gpt-5.5 --model gpt-5.6-sol --dir "$PROJECT"
```

host ProjectはVMへbind mountされない。VM内の編集は、この時点ではhost worktreeに反映されない。

## 5. bounded shellを使う

```sh
bin/sunaba shell --dir "$PROJECT"
```

1行ごとにcommandを入力し、Ctrl-Dで終了する。各commandは16 KiB、2分、出力1 MiBの上限を持ち、結果はterminal sanitizerを通る。interactive TTY program、raw `container exec`、未検証PTYの代替ではない。

## 6. 変更をhostへ反映する

まずVMをfreeze/exportして、host側で検証済みChange Setを作る。

```sh
bin/sunaba changes export --dir "$PROJECT"
```

表示されたadd/modify/delete/renameとChange Set digestを確認する。exportはVMを破棄するが、変更がある場合はsunaba stateのpending領域へ保持する。`.git/`、path traversal、unsafe symlink/hardlink、special file、上限超過はhost worktreeへ到達する前に拒否される。

問題がなければ適用する。

```sh
bin/sunaba changes apply --dir "$PROJECT"
```

Trusted Approval UIがProjectとdigest、host生成nonceを表示する。同じnonceを手入力した場合だけ、baseline競合を再検証してtransactional applyする。export後にhost worktreeが変わっていれば自動mergeせず拒否する。

## 7. 複数のGit remoteを使う

Agent Sessionが存在しない状態で、credentialを含まない固定HTTPS `.git` URLを名前付きで登録する。remote名は小文字英字で始まり、小文字英数字または`-`を使う。

```sh
bin/sunaba git remote add --name origin \
  --url https://git.example/team/project.git --dir "$PROJECT"
bin/sunaba git remote add --name upstream \
  --url https://git.example/upstream/project.git --dir "$PROJECT"
bin/sunaba git remote list --dir "$PROJECT"
```

session開始時に、sunabaはremoteごとにhostの非対話Git credential helperを使う。事前にhost側の通常のGit操作で各URLのcredentialが取得できる状態にしておく。tokenやpasswordをURLへ埋め込まない。

VM内では通常のGit commandを使う。既定workspaceのGit historyはhost Snapshotから作るsynthetic baselineなので、外部repositoryとhistoryが一致しない場合がある。履歴が必要な作業は、固定Gateway URLを取得してVMの隔離領域へcloneする。既定のsynthetic repository用`GIT_DIR`/`GIT_WORK_TREE`はclone先で明示的に外す。

```sh
git fetch origin
REMOTE_URL=$(git remote get-url origin)
env -u GIT_DIR -u GIT_WORK_TREE git clone "$REMOTE_URL" /var/lib/sunaba/overlay/origin-clone
env -u GIT_DIR -u GIT_WORK_TREE git -C /var/lib/sunaba/overlay/origin-clone pull --ff-only origin main
env -u GIT_DIR -u GIT_WORK_TREE git -C /var/lib/sunaba/overlay/origin-clone push origin HEAD:refs/heads/main
```

clone/fetch/pullは固定remoteに対して承認なしで使える。各remoteは別の固定送信先、host bare quarantine、短命capability token、push approval bindingを持つ。一方のremoteのtokenで他方へアクセスすることはできない。

pushの初回は`approval pending`として拒否される。別のhost terminalで次を実行し、remote、送信先、ref、old/new object ID、force/delete、nonceを確認して承認する。

```sh
bin/sunaba approvals --dir "$PROJECT"
```

その後、VMで内容が変わっていない同じpushを期限内に再実行する。承認はone-shotであり、object/ref/remoteが変わると再承認が必要になる。

remoteを削除、または全Git Gatewayを無効化する場合も、先にVMをexportまたは破棄する。

```sh
bin/sunaba git remote remove --name upstream --dir "$PROJECT"
bin/sunaba git disable --dir "$PROJECT"
```

Git LFS endpointとSSH transportは対象外である。submoduleは親remoteのcredentialを継承しないため、必要なrepositoryを別remoteとして明示登録する。

## 8. Web Gatewayを使う

secure modeの一般Web通信は既定で拒否される。新規Projectの`project.json`は、依存導入でよく使う190件のoriginを収録した組み込み`common-development` presetを選択済みにするが、`web.enabled`は`false`なので通信は開始されない。Web Gatewayを有効にするとpresetが展開される。該当部分は次の形になる（他の必須fieldは省略）。

```json
{
  "web": {
    "enabled": true,
    "origin_presets": ["common-development"],
    "origins_file": "web-origins.txt"
  }
}
```

`web-origins.txt`はProject固有の追加分だけを保持する。

```text
# exact HTTPS origin
https://docs.example

# 明示した場合だけsubdomainを含める
https://packages.example include-subdomains
http://archive.example
```

`project.json`の`web.enabled`を`true`にし、両fileをmode `0600`にしたうえで`config validate`、`config diff`、`config apply`を実行する。presetを使わない場合は`origin_presets`を空配列にする。各行はHTTP(S) originだけを許可し、path、query、userinfo、非標準port、IP literal、未知option、重複ruleが1件でもあればfile全体を拒否する。上限は64 KiB、preset展開後を含め1024 ruleである。

既存のCLIでも同じhost設定と実効policyを同期して更新できる。

```sh
bin/sunaba web enable --origin https://docs.example \
  --origin https://packages.example --dir "$PROJECT"
# presetを使わずProject固有originだけにする場合
bin/sunaba web enable --default-origins=false \
  --origin https://packages.example --dir "$PROJECT"
bin/sunaba web refresh --dir "$PROJECT"
```

`web enable`は既定で`common-development`を利用し、`--origin`を追加分として扱う。引数なしの`web enable`はpresetだけを有効にする。`config apply`時にpreset展開結果とdigestを実効policyへ固定するため、sunaba更新でpreset内容が変わっても既存Projectへ黙って反映されず、`config diff`と再適用が必要になる。旧Projectのoriginはmigration時にProject固有ruleとして保持され、自動的にpresetへ拡張されない。

`enable`と`refresh`はhostで固定blocklist sourceを取得し、digestと期限へ束縛したsnapshotを保存する。`config apply`もWebの新規有効化時または有効なsnapshotがない場合だけ取得する。期限切れや取得・検証失敗時はfail closedとなる。設定変更はactive/paused VMがある間は拒否される。

HTTPはallowlist originへのGET/HEADだけを許し、body/uploadを拒否する。HTTPSは443へのTLS非終端CONNECTなので、送信先origin、解決後IP、時間、byte量は制限するが、暗号化されたtunnel内部のmethod、path、upload内容は識別・保証しない。

`common-development`にはpackage registry、CDN、public object storageなど第三者がcontentを公開できるoriginも含まれる。依存導入の互換性を目的とした広い許可集合であり、安全なcontentやread-only通信を意味しない。機密Projectではpresetを無効にし、必要最小限のProject固有originだけを使う。

```sh
bin/sunaba web disable --dir "$PROJECT"
```

## 9. dev mode

直接Internet egressが不可欠な場合だけ明示的に選ぶ。

```sh
bin/sunaba up --dir "$PROJECT" --mode dev
bin/sunaba agent --dir "$PROJECT"
```

dev modeはactiveなforeground `agent`または`shell`の間だけ専用networkとpf規則を作る。host、LAN/private/link-local/metadata、他VM、unsolicited inbound、host credential、host worktreeの境界は維持するが、public Internetへの情報流出防止は保証しない。終了時はegressをdeny-allへしてからVMをexport/destroyする。

pf操作には、[`plan/allowed-host-operations.md`](./plan/allowed-host-operations.md)に記載された固定の`sudo bin/sunaba firewall ...`だけを用いる。一般的なpf変更や`pfctl -d`は行わない。

## 10. 状態確認、停止、再生成、破棄

```sh
bin/sunaba project list
bin/sunaba project list --active
bin/sunaba status --dir "$PROJECT"
bin/sunaba down --dir "$PROJECT"
bin/sunaba recreate --dir "$PROJECT"
bin/sunaba destroy --dir "$PROJECT" --yes --discard-pending
```

- `project list`: 登録済みProjectとSupervisor、VM、pending Change Setの状態を一覧表示する。`--active`は到達可能なSupervisorまたはrunning状態のsunaba所有VMがあるProjectだけを表示する。pause中のVMでもSupervisorが起動中なら表示対象になる。自動修復や停止は行わず、機械処理には`--json`を使用できる
- `status`: mode、VM状態、期限、resource、quota、Git/Web policy、pending Change Setを表示する
- `down`: secure VMをpauseし、隔離されたupperを保持する
- `recreate`: VMがあれば原則exportし、次回をclean host Snapshotから開始する。pending Change Setはapplyまたは明示破棄が必要
- `destroy`: sunabaのProject state、host-only Project設定、所有確認済みVMを削除する。host Project自体は削除しない。未export/pending変更の破棄には`--discard-pending`が必要

既定の利用者設定は`${XDG_CONFIG_HOME:-$HOME/.config}/sunaba/`、内部stateは`${XDG_DATA_HOME:-$HOME/.local/share}/sunaba/`に置かれる。利用者設定は`config` commandで検証・適用し、内部stateを手作業で編集・削除しない。

## 11. 障害時

まず次を確認する。

```sh
container system version
bin/sunaba credentials openai api-key status
# OAuth Projectの場合
bin/sunaba credentials openai oauth status
bin/sunaba status --dir "$PROJECT"
```

- `credential is unavailable`: Projectの認証方式に対応する`api-key set`または`oauth login`を再実行する
- `credential helper`: host Git credential helperが該当する固定HTTPS URLを非対話で解決できるか確認する
- `cannot change ... active`: `changes export`または明示的な破棄を完了してからpolicyを変更する
- `capability expired`: `changes export`で成果物を保存するか、`recreate`でclean sessionへ移る
- baseline競合: host側変更を退避・確定してから、新しいSnapshotでやり直す。自動mergeは行われない
- Apple Container clientが停止・削除中にhangした: 対象外resourceを広く削除しない。許可された復旧手順は[`plan/allowed-host-operations.md`](./plan/allowed-host-operations.md)の「Apple Container serviceの限定復旧」を使う

sunabaのcleanupは完全なresource名とowner/project/session label、leaseを再検証する。単に`sunaba-` prefixがあるという理由だけでcontainer、network、volume、imageを削除しない。

## 12. 検証

host設定やcontainerを変更しない通常gate:

```sh
scripts/verify.sh
```

実Apple Container gateは明示的に有効化する。

```sh
SUNABA_INTEGRATION=1 scripts/verify.sh
```

dev network gateはdocumented sudo/pf操作を伴う。

```sh
SUNABA_INTEGRATION=1 SUNABA_DEV_INTEGRATION=1 scripts/verify.sh
```

実OpenAI gateはKeychainのAPI keyを使い、Agent VMからHost Model Gatewayを経由して少なくとも1回の従量課金requestを送る。費用と外部送信を理解した場合だけ実行する。

```sh
SUNABA_INTEGRATION=1 SUNABA_LIVE_OPENAI=1 scripts/verify.sh
```

通常gateは実credentialを使わず、同じResponses streaming/tool/error/cancel contractをmock upstreamで検証する。

## 13. 保証しないこと

- dev active session中のpublic Internetへの情報流出防止
- TLS非終端Web CONNECT内部のmethod、path、upload識別
- 許可したorigin、Git upstream、dependency、LLM生成成果物自体の安全性
- VM escape、Apple Container、guest kernel、OpenCode、Gateway/relay/parserの未知の脆弱性
- Git upstream push成功後にlocal ref更新だけが失敗する分散transaction窓の完全排除

secure modeでもLLMへ送るsourceやpromptはOpenAIへ送信される。適用した成果物をhost toolで実行する前には、通常のcode reviewとsupply-chain確認が必要である。
