# sunaba ユーザーガイド

このガイドでは、sunabaを利用するための動作環境、導入、設定、主要コマンド、障害時の確認方法を説明します。実際の作業を順番に進めたい場合は、先に[利用ワークフロー](./workflows.md)を参照してください。

sunabaのセキュリティ保証は[セキュリティ設計・製品仕様](./plan/sunaba-secure-agent-platform.md)、`sudo`、pf、Apple Containerに対する操作範囲は[ホスト操作の許可範囲](./plan/allowed-host-operations.md)を正とします。

## sunabaの動作

sunabaは、1つのプロジェクトに1台のAgent VMを割り当てます。OpenCode server、shell、build、test、依存導入などはこのVM内で動きます。ホストでは、sunabaが起動する固定versionのOpenCode TUIだけを使用します。

ホストのプロジェクトはVMへbind mountされません。sunabaは開始時点のSnapshotをVMへcopyし、VM内の編集を隔離された書き込み層へ保存します。作業結果をホストへ戻すときは、VMをfreezeしてChange Setを作成し、利用者がホスト側で承認してから適用します。

OpenAIやGitの実credentialはホストに保持され、VMにはsession限定のcapabilityだけが渡されます。VM内のroot権限やOpenCodeの許可設定によって、ホスト側の境界が広がることはありません。

## 利用前の準備

### 動作環境

- Apple silicon搭載Mac
- macOS 26
- Apple Container exact `1.2.2`
- OpenCode host TUI: sunabaがlockしたv1系exact version（bootstrap値`1.18.16`）
- Go 1.22以降（ソースからビルドする場合）
- OpenAI API key、またはCodexを利用できるChatGPT subscription

Apple ContainerとOpenCodeは検証済みのversionへ固定されます。OpenCodeは明示的な確認と適用で別のv1系exact versionへ更新できますが、範囲指定、session開始時の`latest`解決、OpenCode自身の自動update、OpenCode v2、hostとguestのversion混在は使用できません。

### Apple Containerを起動する

Apple Container `1.2.2`を導入したうえで、systemを起動してversionを確認します。

```sh
container system start
container system version
```

### OpenCodeをインストールする

初回はmacOS側へ[OpenCode v1.18.16](https://github.com/anomalyco/opencode/releases/tag/v1.18.16)のApple silicon版をインストールし、`opencode`コマンドを実行できる状態にします。特定のdirectoryへ手動配置する必要はありません。インストール後にversionを確認してください。

```sh
opencode --version
```

出力はexact `1.18.16`である必要があります。公式download archive `opencode-darwin-arm64.zip`のSHA-256は次の値です。

```text
1e670c94341a374824dc6700b6f38b2cb6634baf3ca20e645084c33ce6639320
```

sunabaは実行前に、macOSへインストールされたOpenCodeのversionと実行ファイルの固定digestを検証し、検証済みbinaryをsunabaの管理領域へcopyします。不一致の場合、別versionへ自動fallbackしません。初回のbootstrap固定値は[`internal/dependency/manifest.json`](../internal/dependency/manifest.json)で確認できます。

VM側のOpenCode serverを利用者がインストールする必要はありません。sunabaはAgent imageのbuild時に固定したLinux arm64 artifactを取得し、SHA-256を検証してimageへ組み込みます。OpenCodeを更新するときは、互換性を検証したうえでhost TUIとVM側serverを同じversionへ更新します。VM側だけを独立して更新したり、`latest`へ自動追従したりはしません。

### sunabaをビルドしてPATHを設定する

repository rootで3つのbinaryを同じdirectoryへbuildします。

```sh
mkdir -p bin
go build -trimpath -o bin/sunaba ./cmd/sunaba
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o bin/sunaba-guest-relay ./cmd/sunaba-guest-relay
go build -trimpath -o bin/sunaba-git-hook ./cmd/sunaba-git-hook
```

build後は、次のどちらかを行います。

- 3つのbinaryがある`bin` directoryを`PATH`へ追加する
- 3つのbinaryをすべて、すでに`PATH`の通っている同じdirectoryへ配置する

現在のshellでrepositoryの`bin`を`PATH`へ追加する例:

```sh
export PATH="/absolute/path/to/sunaba/bin:$PATH"
sunaba help
```

`sunaba help`が実行できることを確認してください。以降の例は、`sunaba`、`sunaba-guest-relay`、`sunaba-git-hook`が同じ`PATH`上のdirectoryに配置されている前提です。

### 初回setupを実行する

Apple Container systemを起動し、macOS側でbootstrap版の`opencode`を実行できる状態にしてから、次を実行します。

```sh
sunaba setup
```

`setup`はmacOS、Apple Container、host OpenCodeのversionと実行ファイルdigestを検証し、VM用OpenCodeを組み込んだAgent imageをbuildします。すべて成功した場合だけ、適用済みversion lockを確定します。`project init`、`up`、`agent`、`shell`はsetup完了前に拒否されます。

version設定とlockはProjectやrepository内ではなく、次のhost-only fileへ保存されます。

```text
${XDG_CONFIG_HOME:-$HOME/.config}/sunaba/versions.json
${XDG_CONFIG_HOME:-$HOME/.config}/sunaba/versions.lock.json
```

実際のpathと現在の宣言・lockは次のコマンドで確認できます。

```sh
sunaba versions path
sunaba versions show
```

`versions.json`は利用者が直接編集することもできます。exact指定の形式は次のとおりです。編集後もactive lockは変わらず、反映には`update check`と`update apply`が必要です。

```json
{
  "schema_version": 1,
  "opencode": {
    "strategy": "exact",
    "value": "1.18.16"
  }
}
```

channel指定では`strategy`を`channel`、`value`を`v1-stable`にします。未知field、v2、range、`latest`、不正なfile modeやsymlinkは拒否されます。`versions.lock.json`はsunabaが生成するため、手作業で編集しないでください。

初回からbootstrap以外のv1 versionを使う場合は、Agent imageをまだ作らず宣言fileだけを用意します。その後の手順は[「OpenCodeを更新する」](#opencodeを更新する)と同じです。

```sh
sunaba setup --config-only
printf 'OpenCode v1 exact version: '
read -r OPENCODE_VERSION
sunaba versions set "$OPENCODE_VERSION"
sunaba update check
# checkが示したexact versionのOpenCodeをmacOSへインストールする
sunaba update apply
```

### OpenCodeを更新する

特定のv1系exact versionへ更新する場合は、そのversionを宣言します。

```sh
printf 'OpenCode v1 exact version: '
read -r OPENCODE_VERSION
sunaba versions set "$OPENCODE_VERSION"
```

明示的に確認した時点の最新stable v1を選びたい場合だけ、固定channelを宣言します。この設定でも`up`や`agent`の実行時には更新されません。

```sh
sunaba versions track v1-stable
```

次に更新候補を確認します。

```sh
sunaba update check
```

`update check`は公式releaseからexact versionとsource commitを解決し、macOS/guest artifactをhost-only quarantineへdownloadしてSHA-256を計算します。現在のlock、Project policy、VMは変更しません。表示されたexact versionのApple silicon版OpenCodeをmacOSへインストールし、versionを確認します。

```sh
opencode --version
```

すべてのsunaba VMとSupervisorを終了してから、保存済み候補を適用します。pending Change Setはhost側に保持したままでも構いません。

```sh
sunaba project list --active
sunaba update apply
```

`update apply`はcheck後に設定や現行lockが変わっていないこと、候補が期限内であること、macOS側OpenCodeのversionとdigestが候補と一致することを再検証します。その後、同じguest versionのAgent imageをno-cacheでbuildし、Project policyとglobal lockをjournal付きtransactionで切り替えます。apply時にreleaseの`latest`を再解決せず、旧imageや旧managed TUIを自動削除しません。

VM内のOpenCodeだけを直接updateする操作はありません。host TUIとguest serverは常に同じlockから更新されます。

## OpenAI credentialを登録する

新規Projectの既定はOAuthです。ChatGPT subscriptionを使う場合は、device flowでログインします。sunabaが表示したURLをブラウザで開き、user codeを入力してください。ブラウザは自動的には起動しません。

```sh
sunaba credentials openai oauth login
sunaba credentials openai oauth status
```

従量課金API keyを使う場合は、macOS login Keychainへ登録します。API keyを環境変数やProject fileへ保存しないでください。

```sh
sunaba credentials openai api-key set
sunaba credentials openai api-key status
```

`set`ではKeychain自身のpromptへkeyを入力します。credentialは固定service `dev.sunaba.openai`に保存され、VM、Host TUI、Project設定、auditへは記録されません。

credentialを削除する場合は、先に該当Projectの作業をexportまたは破棄し、Supervisorを終了してください。起動済みのSupervisorは終了までcredentialをmemoryに保持している可能性があります。

```sh
sunaba credentials openai oauth delete
sunaba credentials openai api-key delete
```

## Projectを登録する

対象Projectのdirectoryで実行すると、pathを省略できます。OAuthを使う場合は次のとおりです。

```sh
cd /path/to/project
sunaba project init
```

API keyを使うProjectは初期化時に明示します。

```sh
sunaba project init --model-auth api-key
```

別directoryからは相対pathまたは絶対pathを1つ指定できます。sunabaはsymlinkを解決したcanonical absolute pathを登録し、同じProjectの重複登録を拒否します。

```sh
sunaba project init /path/to/project
sunaba project list
```

登録後の通常手順は[「初めてのプロジェクト」ワークフロー](./workflows.md#初めてのプロジェクト)を参照してください。

## Project設定

Project設定は作業ツリー内ではなく、ホスト専用の次のdirectoryへ保存されます。

```text
${XDG_CONFIG_HOME:-$HOME/.config}/sunaba/projects/<ProjectID>/
```

実際のpathと現在の設定はCLIで確認できます。

```sh
sunaba config path --dir /path/to/project
sunaba config show --dir /path/to/project
sunaba config show --effective --dir /path/to/project
```

通常は対話ウィザードを使います。mode、Model、Git remote、Web access、resource、quotaを設定し、最終確認後に保存と適用を同時に行います。credentialはこのウィザードへ入力しません。

```sh
sunaba config edit --dir /path/to/project
```

直接編集する場合は、`config path`が表示した`project.json`と`web-origins.txt`だけを編集します。保存後は検証、差分確認、適用を順番に実行します。

```sh
sunaba config validate --dir /path/to/project
sunaba config diff --dir /path/to/project
sunaba config apply --dir /path/to/project
```

設定変更は、activeまたはpaused VMとpending Change Setがないときだけ適用できます。先に`changes export`、`changes apply`、`recreate --discard-pending`などで現在の状態を処理してください。未適用または不正な設定がある間、`up`、`agent`、`shell`はfail closedで拒否されます。

`project.json`には利用者が選ぶmode、resource、session、Model、Git、Web、export、auditの設定だけを記述します。dependency digest、credential、capability、push承認方針、Protected Pathなど、sunabaが強制する値は変更できません。内部の実効policyは手作業で編集しないでください。

## Modelを選ぶ

現在の認証方式で利用できるmodelを確認できます。

```sh
sunaba model list --dir /path/to/project
```

Projectで許可するmodelは`--model`を複数指定して設定します。最初のmodelがOpenCodeの既定になります。

```sh
sunaba model set \
  --model gpt-5.5 \
  --model gpt-5.6-sol \
  --dir /path/to/project
```

既存Projectの認証方式を変更するには、VMとpending Change Setを処理したあとで次を実行します。

```sh
sunaba model auth oauth --dir /path/to/project
sunaba model auth api-key --dir /path/to/project
```

sunabaは認証方式ごとの固定catalogを使用し、OpenAIのmodel discovery APIへ依存しません。catalogにないmodelや、選択した認証方式で利用できないmodelが含まれるとsessionを開始しません。

## secure modeとdev mode

### secure mode

secure modeは既定です。VMからの直接Internet、外部DNS、ホスト一般service、LAN、他のVMへの接続を拒否し、Project専用経路上の有効なGatewayだけを利用します。分離を構成・検証できなければsession開始に失敗し、dev modeへ自動的に切り替わりません。

Model Gatewayは常に必要です。Git GatewayとWeb Gatewayは、Projectで設定した場合だけ有効になります。

### dev mode

dev modeは、foregroundの`agent`または`shell`が動いている間だけpublic Internetへの直接接続を許可します。この間の情報流出防止は保証しません。

host、LAN、private/link-local/metadata、他VM、unsolicited inbound、host credential、host worktreeとの境界は維持します。session終了時はegressをdeny-allへ切り替えてからVMをexport・破棄します。同時にactiveにできるdev sessionは1つです。

dev modeのpf操作は、[ホスト操作の許可範囲](./plan/allowed-host-operations.md)に記載された`sunaba firewall`操作だけに限定されます。一般的なpf変更や`pfctl -d`は使用しないでください。

## Agentとshell

OpenCodeを使うには`agent`を実行します。

```sh
sunaba up --dir /path/to/project
sunaba agent --dir /path/to/project
```

secure modeの`up`はVMを作成・検証してpaused状態にします。`agent`はVM内のOpenCode serverと、ホスト上の隔離されたOpenCode TUIを同時に管理します。TUIを終了するとGatewayを失効させ、VMをpauseします。session期限内であれば、次の`agent`で同じVMと編集状態を再利用できます。

単発のcommandを確認したい場合は、sanitized shellを使います。

```sh
sunaba shell --dir /path/to/project
```

shellは1行ずつcommandを受け付け、Ctrl-Dで終了します。command、時間、出力量には上限があり、出力はhost terminal sanitizerを通ります。interactive TTY、raw `container exec`、未検証PTYの代替ではありません。

## 変更をホストへ反映する

VM内の変更は自動ではホストへ反映されません。まずChange Setとしてexportします。

```sh
sunaba changes export --dir /path/to/project
```

exportはVMをfreeze・破棄し、追加、変更、削除、renameをホスト側で再構成します。unsafeなpath、symlink、hardlink、special file、`.git/`、sunaba管理領域、上限超過はホスト作業ツリーへ到達する前に拒否されます。

表示されたpathとdigestを確認し、問題がなければ適用します。

```sh
sunaba changes apply --dir /path/to/project
```

Trusted Approval UIに表示されたhost生成nonceを手入力した場合だけ適用されます。Snapshot作成後にホスト作業ツリーが変わっている場合は自動mergeせず拒否します。競合時はホスト側の変更を整理し、新しいSnapshotからやり直してください。

apply後はホスト上で通常どおりdiff、test、code reviewを行い、必要ならcommitします。VM内の`.git/`はホストへ反映されません。

## Git Gateway

Git Gatewayを使う場合は、VMとpending Change Setがない状態で、credentialを含まない固定HTTPS `.git` URLを登録します。SSH transportとGit LFS endpointは対象外です。

```sh
sunaba git remote add \
  --name origin \
  --url https://git.example/team/project.git \
  --dir /path/to/project
sunaba git remote list --dir /path/to/project
```

hostのGit credential helperが、このURLのcredentialを非対話で取得できるようにしておいてください。tokenやpasswordをURLへ埋め込まないでください。

VM内では通常の`git fetch`、`git pull`、`git push`を使えます。clone、fetch、pullは固定remoteとquotaの範囲で承認なしに利用できます。pushの初回はpending approvalを作って拒否されます。別のhost terminalで次を実行し、remote、ref、old/new object ID、force/delete、nonceを確認してください。

```sh
sunaba approvals --dir /path/to/project
```

承認後、VM内で内容が変わっていない同じpushを期限内に再実行します。承認はone-shotで、remote、object、ref、force/deleteのいずれかが変わると再承認が必要です。

VMの既定workspaceはhost Snapshotから作るsynthetic Git repositoryです。外部repositoryのhistoryが必要な作業は、登録済みGateway remoteからVM内の別directoryへcloneしてください。詳細な手順は[「外部Git履歴を使う」ワークフロー](./workflows.md#外部git履歴を使う)を参照してください。

```sh
sunaba git remote remove --name origin --dir /path/to/project
sunaba git disable --dir /path/to/project
```

## Web Gateway

secure modeの一般Web通信は既定で無効です。よく使う開発用originをまとめた組み込みpreset `common-development`は新規Projectで選択済みですが、Web Gatewayを有効にするまで通信は開始されません。

presetとProject固有originを使う場合:

```sh
sunaba web enable \
  --origin https://docs.example \
  --dir /path/to/project
```

presetを使わず、Project固有originだけを許可する場合:

```sh
sunaba web enable \
  --default-origins=false \
  --origin https://packages.example \
  --dir /path/to/project
```

`web enable`と`web refresh`は固定blocklistをhostで取得し、digestと期限に束縛したsnapshotを保存します。期限切れや検証失敗時は通信を拒否します。

Project固有originは、`config path`が示す`web-origins.txt`でも管理できます。各行には`http://host`または`https://host`と、必要な場合だけ`include-subdomains`を記述します。path、query、userinfo、非標準port、IP literalは使用できません。

```text
https://docs.example
https://packages.example include-subdomains
```

HTTPは許可したoriginへのGET/HEADだけを許可します。HTTPSは443へのTLS非終端CONNECTです。sunabaは接続先origin、解決後IP、時間、byte量を制限しますが、暗号化されたtunnel内部のmethod、path、upload、side effectは識別できません。

`common-development`にはpackage registry、CDN、public object storageなどのmulti-tenant originも含まれます。安全なcontentやread-only通信を意味しません。機密Projectではpresetを無効にし、必要最小限のoriginだけを設定してください。

```sh
sunaba web refresh --dir /path/to/project
sunaba web disable --dir /path/to/project
```

## Projectの指定方法

Projectを対象にするcommandは、通常次のいずれかで対象を選びます。

- `--dir /path/to/project`
- `--project-id 0123456789ab`
- どちらも省略し、current directoryを使用

`--dir`と`--project-id`は同時に指定できません。Project IDは`project list`が表示した12桁の小文字16進IDを完全一致で指定します。prefixやaliasは使用できません。

通常のID指定は、登録済みProject rootが存在し、policyのidentityと一致する場合だけ成功します。元のProject directoryやpolicyを失った隔離stateには、復旧用の`down`と`destroy`だけがID指定を受け付けます。

## 状態確認とライフサイクル

| コマンド | 用途 |
|---|---|
| `sunaba project list` | 登録済みProjectを一覧表示する |
| `sunaba project list --active` | 到達可能なSupervisorまたはrunning VMがあるProjectだけを表示する |
| `sunaba status` | mode、VM、session、quota、Gateway、pending Change Setを確認する |
| `sunaba up` | secure VMを準備してpauseする。devではforeground session用artifactだけを準備する |
| `sunaba agent` | OpenCode sessionを開始する |
| `sunaba shell` | sanitized shellを開始する |
| `sunaba down` | secure VMを停止し、隔離された状態を保持する |
| `sunaba recreate` | 現在のVMを処理し、次回をclean Snapshotから開始する |
| `sunaba destroy` | sunabaのProject stateとhost-only設定を削除する |

`destroy`はhostのProject fileを削除しません。pendingまたは未exportの変更を破棄する場合は、明示的な確認が必要です。

```sh
sunaba destroy \
  --dir /path/to/project \
  --yes \
  --discard-pending
```

元のProject directoryが存在しない場合は、一覧に表示された完全なIDを使用します。

```sh
sunaba project list
sunaba destroy \
  --project-id 0123456789ab \
  --yes \
  --discard-pending
```

## 保存場所

既定の保存場所は次のとおりです。

- 利用者が編集する設定: `${XDG_CONFIG_HOME:-$HOME/.config}/sunaba/`
- sunaba内部state: `${XDG_DATA_HOME:-$HOME/.local/share}/sunaba/`
- OpenAI credential: macOS login Keychainの固定item
- 作業対象のsource: 登録したhost Project directory

内部stateには実効policy、audit、lease、managed OpenCode、pending Change Setなどが含まれます。内部stateを手作業で編集・削除せず、`config`、`changes`、`recreate`、`destroy`を使用してください。

## トラブルシューティング

まず次を確認します。

```sh
container system version
sunaba versions show
sunaba project list
sunaba status --dir /path/to/project
sunaba credentials openai oauth status
# API keyを使うProjectの場合
sunaba credentials openai api-key status
```

よくある状態と対応:

- `credential is unavailable`: Projectの認証方式に合わせて`oauth login`または`api-key set`をやり直す
- `credential helper`: hostのGit credential helperが登録済みHTTPS URLを非対話で解決できるか確認する
- `cannot change ... active`: 先に`changes export`または`recreate`でVMを処理する
- pending Change Setがある: `changes apply`で反映するか、破棄を明示して`recreate`または`destroy`する
- `capability expired`: `changes export`で成果物を保存するか、`recreate`でclean環境へ移る
- baseline競合: host側の変更を整理し、新しいSnapshotから作業をやり直す
- OpenCode versionまたはdigest不一致: `sunaba versions show`でactive lockのexact versionを確認し、そのversionの公式Apple silicon artifactをmacOSへ再インストールする
- Web blocklist期限切れ: VMがない状態で`web refresh`を実行する

Apple Container clientが停止・削除中に応答しなくなった場合、任意のcontainerやserviceを広く停止・削除しないでください。[ホスト操作の許可範囲](./plan/allowed-host-operations.md)にある限定復旧手順を確認し、個別承認が必要な操作は実行前に承認を得てください。

## 保証しないこと

- dev modeのactive session中におけるpublic Internetへの情報流出防止
- Web GatewayのHTTPS tunnel内部にあるmethod、path、upload、side effectの識別
- 許可したLLM、Web origin、Git upstream、dependency、生成物自体の安全性
- Apple Container、macOS、guest kernel、OpenCode、Gatewayなどの未知の脆弱性によるVM escape
- Change Set適用後にhost toolで成果物を実行したときのsupply-chain risk

secure modeでも、LLMへ送ったsourceやpromptは選択したOpenAI endpointへ送信されます。Change Setを適用したあとは、通常のcode review、test、dependency確認を行ってください。
