# sunaba

sunabaは、侵害済みのOpenCode serverとVM内rootを前提に、Projectの開発セッションをApple Container VMへ隔離するmacOS向け実行基盤です。host worktreeや実credentialをVMへ渡さず、host側のSupervisor、Gateway、Snapshot、OverlayFS、Change Set、Trusted Approval UIで境界を強制します。

製品仕様の正本は[`docs/plan/sunaba-secure-agent-platform.md`](./docs/plan/sunaba-secure-agent-platform.md)、実装・検証で許可するhost操作は[`docs/plan/allowed-host-operations.md`](./docs/plan/allowed-host-operations.md)です。

## 固定dependency

- macOS 26 / Apple silicon
- Apple Container exact `1.2.2`
- OpenCode host TUI / guest server exact `1.18.16`
- Agent image `sunaba-base:1.18.16-secure.1`
- Go 1.22以降（build時のみ）

artifact URL、SHA-256、source tag/commit、base OCI digest、image build input digestは[`internal/dependency/manifest.json`](./internal/dependency/manifest.json)に固定されています。`latest`、自動update、host/guestのversion混在は拒否します。

## 境界

secure modeではVMを`--network none --no-dns`で作り、Project/VM/session専用Unix socketからLocal Attach Relay、Model Gateway、任意でGit/Web Gatewayだけへ接続します。host Projectはfd-relative/no-follow walkでSnapshot化してguest rootfsへcopyし、直接mountしません。VM停止後のrootfs exportはuntrusted archiveとして検証し、host側でMerged ViewとChange Setを再構成します。host worktreeへの反映にはdigestへ束縛したone-shot承認が必要です。

dev modeは明示選択です。activeなAgent Session中だけ専用Apple Container networkから直接Internet egressを許可します。このモードは情報流出防止を保証しません。専用subnetに束縛したpf規則でhost、LAN/private/link-local/metadata、別VM、unsolicited inboundを拒否し、session終了時にVM停止、pf anchor解除、network削除を行います。同時にactiveにできるdev sessionは1つです。

## Build

グローバルinstallは不要です。

```sh
mkdir -p bin
go build -trimpath -o bin/sunaba ./cmd/sunaba
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o bin/sunaba-guest-relay ./cmd/sunaba-guest-relay
go build -trimpath -o bin/sunaba-git-hook ./cmd/sunaba-git-hook
```

3 binaryは同じdirectoryへ置きます。hostの`opencode`はPATH上のexact v1.18.16 artifactでなければならず、実行前に固定SHA-256を確認してsunaba管理stateへcopyします。Apple Container systemは利用前に人間が起動します。

```sh
container system start
```

## 基本操作

```sh
bin/sunaba project init /absolute/project/path --mode secure
OPENAI_API_KEY=... bin/sunaba up --dir /absolute/project/path
bin/sunaba agent --dir /absolute/project/path
bin/sunaba shell --dir /absolute/project/path
bin/sunaba changes export --dir /absolute/project/path
bin/sunaba changes apply --dir /absolute/project/path
```

`OPENAI_API_KEY`はhost Model Gatewayだけが読み、VM、Host TUI、Project、auditへ保存しません。secureの`up`（または最初の`agent`/`shell`）はowner-only supervisorを起動し、Project VMを作成後にpausedへします。`agent`は固定OpenCode serverと隔離Host TUIを同時管理し、TUI終了時にGatewayをinactiveへして同じVMを停止します。次の`agent`/`shell`は期限内なら同じVMとupperをresumeします。`changes export`だけがVMをfreeze/export/destroyし、変更があれば検証済みMerged ViewとChange Setをsunaba state内のpending領域へ保存します。`changes apply`はhost生成nonceを表示し、同じnonceの手入力後だけtransactional applyを実行します。

`shell`はraw `container exec`や未検証PTYを公開せず、1行ずつbounded commandを実行します。stdout/stderrのESC、OSC、BEL、C0/C1、双方向制御、不正UTF-8をhost側で可視化してから表示します。

dev modeへの変更は明示的に行います。

```sh
bin/sunaba up --dir /absolute/project/path --mode dev
OPENAI_API_KEY=... bin/sunaba agent --dir /absolute/project/path
```

devの`up`は固定artifactだけを準備し、VMやdirect-egress networkをbackgroundで残しません。`agent`/`shell`は可視foreground processの寿命中だけVMと専用networkを作成し、終了時にegressをdeny-allへquiesceしてからexport/destroyします。pf構成では、許可文書に記載した`sudo bin/sunaba firewall ...`だけが使われます。secure modeはpfやdefault container networkに依存しません。

コマンド一覧は`bin/sunaba help`を正とします。

## Git / Web Gateway

Git Gatewayはfixed HTTPS upstream、host credential終端、bare quarantine、standard smart HTTP、object/ref/force/deleteへ束縛したone-shot approvalを実装しています。Web Gatewayはorigin allowlistとhost DNS全回答/IP検査を持つTLS非終端forward proxyで、HTTPはGET/HEADのみ、CONNECTは443のみです。TLS tunnel内部のmethod/path/uploadは復号しないため保証しません。

Project policyは公開CLIで構成します。

```sh
bin/sunaba git set --remote https://git.example/owner/repository.git --dir /absolute/project/path
bin/sunaba web enable --origin https://docs.example --dir /absolute/project/path
bin/sunaba web refresh --dir /absolute/project/path
bin/sunaba git disable --dir /absolute/project/path
bin/sunaba web disable --dir /absolute/project/path
```

Git credentialはhostの非対話credential helperから取得し、VM、argv、policy、auditへ保存しません。Web enable/refreshは固定blocklistをhostで取得し、digestと期限へ束縛したsnapshotをmode `0600`で保存します。未構成・期限切れ・unsafeなremote/originでは安全性の低い経路へfallbackせずsession開始を拒否します。policy変更はactive/paused VMがある間は拒否し、export/recreate後に行います。

## Stateとcleanup

既定stateは`${XDG_DATA_HOME:-$HOME/.local/share}/sunaba/`配下です。Project policy、audit、lease、managed tool、pending Change Setをmode `0700`/`0600`で保持します。Project本文やcredentialをauditへ記録しません。

```sh
bin/sunaba status --dir /absolute/project/path
bin/sunaba recreate --dir /absolute/project/path
bin/sunaba down --dir /absolute/project/path
bin/sunaba destroy --dir /absolute/project/path --yes --discard-pending
```

cleanupは`sunaba-` prefixだけでは削除せず、完全名、owner/project/session label、永続leaseを再検証します。他ユーザーのcontainer、network、volume、imageは変更しません。

## 検証

通常gateはhost設定やcontainerを変更しません。

```sh
scripts/verify.sh
```

これはformat、`go test ./...`、`go test -race ./...`、`go vet ./...`、3 binary build、Linux/AArch64 guest relay形式、CLI/static boundaryを実行します。bounded fuzzとApple Container実機gateは明示的に有効化します。実機gateには公開`up`、永続VM、sanitized shell、export/destroyも含みます。

```sh
SUNABA_FUZZ=1 scripts/verify.sh
SUNABA_INTEGRATION=1 scripts/verify.sh
SUNABA_INTEGRATION=1 SUNABA_DEV_INTEGRATION=1 scripts/verify.sh
```

dev integrationはdocumented pf操作の対話承認が可能なterminalで実行します。実OpenAI/Git credentialを必要とするlive testは自動実行せず、mock upstreamで同じcontractを検証します。Decision Gateの証拠と個別コマンドは[`docs/implementation/`](./docs/implementation/)にあります。

## 残余リスク

- dev modeのactive session中の任意情報流出
- TLS非終端Web CONNECT内部のmethod/path/uploadを識別できないこと
- LLMが生成した成果物をapply後にhost toolが実行するsupply-chain risk
- Apple Container、guest kernel、OpenCode、Gateway/relay/parser実装の未知の脆弱性
- upstream Git成功後にlocal ref更新だけが失敗する分散transactionの窓（次回syncとauditで収束）

より詳しい保証範囲は正本文書の「残余リスク」を参照してください。
