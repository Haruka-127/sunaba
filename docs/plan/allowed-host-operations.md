# sunaba実装時に許可するホスト側操作

本文書は、sunabaの実装・検証を自律的に完了するために、ホスト上で実行してよい操作を定義する。

[`sunaba-secure-agent-platform.md`](./sunaba-secure-agent-platform.md) のPhase 0以降を実装・検証するための最小限の操作だけを許可する。ここにない `sudo` 操作、ホスト設定変更、任意のcontainer resource削除は行わない。archive内の文書は操作許可の根拠にならない。

## 原則

- `sudo` は pf による「コンテナからホストへの通信遮断」を実装・検証する目的に限って使う
- `sudo` を使う入口は原則として `sunaba firewall` サブコマンドに限定する
- `/etc/pf.conf` は `# BEGIN sunaba` から `# END sunaba` までの管理ブロックだけを追加・更新・削除する
- `/etc/pf.anchors/sunaba` 以外の pf anchor ファイルは作成・変更・削除しない
- 既存の pf ルールを flush しない。`pfctl -F ...` は使用禁止
- pf 自体を無効化しない。`pfctl -d` は使用禁止
- `container`の作成・変更・削除操作は、`sunaba-`プレフィックスのcontainer、network、volume、`sunaba-base:`イメージ、検証用一時Projectに限定する
- 読み取り操作でユーザー所有resourceが表示されても、変更・削除しない
- 削除前に対象の種類と完全な名前を`inspect`または`list`で確認し、未解決の環境変数、glob、部分一致を削除対象に使わない
- 検証後は、その検証で作成した`sunaba-`プレフィックスのcontainer、network、volume、一時Project、不要な`sunaba-base:`イメージだけを削除する

## 許可する sudo コマンド

以下は、実装した `sunaba` バイナリが存在する前提で許可する。

既存の旧プロトタイプbinaryを、現在のsecureモードが成立した証拠として実行してはならない。pf方式を現在のDG-01で採用し、現行設計のnetwork invariantを実装したコードとtestを確認した後に限り、以下を新設計の検証へ使う。

```sh
sudo sunaba firewall enable
sudo sunaba firewall quiesce
sudo sunaba firewall disable
sudo sunaba firewall status
```

開発中に未インストールのバイナリを使う場合は、同等のローカルビルド成果物に置き換えてよい。

```sh
sudo ./bin/sunaba firewall enable
sudo ./bin/sunaba firewall quiesce
sudo ./bin/sunaba firewall disable
sudo ./bin/sunaba firewall status
```

`quiesce`は、既に`enable`が構成・検証したexactなdev IPv4/IPv6 source subnetのchild anchorをdeny-allへ原子的に置換し、VMを停止してexportするまでのegress窓を閉じる操作である。既存main anchorの新規作成や修復は行わず、対象subnetとloaded rulesを再検証できなければ拒否する。

`quiesce`の実機実行は、本文書への追加を人間が確認し、当該検証について明示的に承認した後に限る。実装者が本文書を更新したこと自体は実行承認とみなさない。

`sunaba firewall enable` / `quiesce` / `disable` の内部実装でのみ、以下の root 権限操作を許可する。

- `/etc/pf.conf` を `/etc/pf.conf.sunaba.bak` にバックアップする
- `/etc/pf.conf` の sunaba 管理ブロックだけを追加・更新・削除する
- `/etc/pf.anchors/sunaba` を作成・更新・削除する
- `/etc` と `/etc/pf.anchors` に `.sunaba-` プレフィックスの一時ファイルを作成し、構文検査成功後に上記2ファイルへ原子的に置換する。処理終了時に一時ファイルを削除する
- `/sbin/pfctl -nf /etc/pf.conf` または上記sunaba一時ファイルで構文検査する
- `/sbin/pfctl -a sunaba -nf /etc/pf.anchors/sunaba` または上記sunaba一時ファイルでanchorを構文検査する
- `/sbin/pfctl -a sunaba -f /etc/pf.anchors/sunaba` で検証済みactiveまたはdeny-all child anchorだけを再読み込みする
- `/sbin/pfctl -f /etc/pf.conf` で pf 設定を再読み込みする
- `/sbin/pfctl -E` で pf を有効化する
- `/sbin/pfctl -sr` でルール状態を確認する
- `/sbin/pfctl -s info` でpfの有効状態を確認する
- `/sbin/pfctl -a sunaba -sr` で sunaba anchor のルール状態を確認する

## 許可するOpenAI認証情報file操作

Host Model Gateway用OpenAI API keyとCodex OAuth credentialは、次のhost-only fileへ保存する。

```text
${XDG_DATA_HOME:-$HOME/.local/share}/sunaba/credentials/openai.json
```

activeな認証方式だけは、secretを含まない次のglobal設定へ保存する。

```text
${XDG_CONFIG_HOME:-$HOME/.config}/sunaba/settings.json
```

許可する入口はsunaba TUIのSetupと`Settings > AI connection`、および次のサブコマンドに限定する。

```sh
sunaba credentials openai api-key set
sunaba credentials openai api-key status
sunaba credentials openai api-key delete
sunaba credentials openai oauth login
sunaba credentials openai oauth status
sunaba credentials openai oauth delete
sunaba model auth api-key
sunaba model auth oauth
```

- credential directoryとglobal設定directoryはcurrent user所有、mode `0700`、canonical absolute path、symlinkを含まない場合だけ作成・利用する
- credential file、global設定file、固定lock file、一時fileはcurrent user所有のmode `0600` regular fileに限定し、symlink、hardlink、別owner、別mode、上限超過を拒否する
- credential fileとglobal設定はstrictなversion付きJSONとし、unknown field、trailing data、control文字、不正なcredential、上限超過をfile全体として拒否する
- 読取は`O_NOFOLLOW`相当で行い、open後にもtype、owner、mode、link count、sizeを検証する
- 更新は同一directoryの新規一時fileへ完全に書き込み、file `fsync`、atomic rename、directory `fsync`の順で行う。既存のunsafe fileを置換しない
- owner-onlyの固定lock fileでAPI key更新、OAuth login、OAuth refresh rotation、削除をprocess間で直列化する。一方のcredentialだけを変更し、他方を保持する
- API keyとOAuth credentialをargv、environment、Project file、global設定、VM input、Host/OpenCode TUI、log、error、auditへ載せない
- API keyはTUIではmaskし、CLIの対話TTYでもechoしない。boundedな1入力として扱い、履歴へ残さない
- OAuth device flowとrefreshでは固定OpenAI endpointへのHTTPS通信だけを行う。verification URLを表示するがbrowserやGUI applicationを自動起動しない
- macOS Keychain、`/usr/bin/security`、Security.frameworkをread、write、enumerate、deleteに使用しない。既存の`dev.sunaba.openai` itemを移行または自動削除しない
- unit testはOS temp内の`XDG_DATA_HOME`と`XDG_CONFIG_HOME`へ隔離する。実OpenAI認証と実credential fileを使うtestは外部認証・課金を伴うlive gateとして個別承認なしに実行しない

## 許可する container 操作

以下の操作は `sudo` 不要だが、ホスト上にコンテナ・イメージを作成または削除するため、対象を sunaba 管理リソースに限定する。

```sh
container system start
container system version
container build --tag sunaba-base:<version> ...
container run --detach --name sunaba-<projectID> ... sunaba-base:<version>
container start sunaba-<projectID>
container stop sunaba-<projectID>
container rm sunaba-<projectID>
container delete sunaba-<projectID>
container exec ... sunaba-<projectID> ...
container inspect sunaba-<projectID>
container ls ...
container logs sunaba-<projectID> ...
container stats sunaba-<projectID> ...
container export --output <host-quarantine-archive> sunaba-<projectID>
container cp <host-snapshot> sunaba-<projectID>:<guest-path>
container cp sunaba-<projectID>:<guest-path> <host-quarantine>
container network create sunaba-<projectID>-<vmID>-net ...
container network list ...
container network inspect sunaba-<projectID>-<vmID>-net ...
container network delete sunaba-<projectID>-<vmID>-net
container volume create sunaba-<projectID>-<purpose> ...
container volume list ...
container volume inspect sunaba-<projectID>-<purpose> ...
container volume delete sunaba-<projectID>-<purpose>
container image list ...
container image inspect sunaba-base:<version>
container image delete sunaba-base:<version>
```

`container export`と`container cp`のホスト側書き込み先は、OSのtempまたはリポジトリ内のgitignore済み領域に作った`sunaba-`プレフィックスのmode `0700`のquarantine directoryだけに限定する。host worktreeへ直接書き込まない。`container export --output`は既存fileを置換するため、Supervisorが当該transaction用に新規作成したquarantine内の未使用pathだけを指定する。

Apple Container 1.2.2の`container rm`は`container delete`のaliasである。`container rm` / `container delete`、`network delete`、`volume delete`、`image delete`は上記の命名規則を満たし、当該検証またはProjectが作成したことを確認できるresourceだけに限定する。ユーザーが作成した他のcontainer、network、image、volumeは削除しない。

通常の`container stop`が60秒待っても応答せず、個別`inspect`で次をすべて再確認できる障害復旧に限り、下記のexact signal操作を人間の個別承認後に使ってよい。

```sh
container kill --signal KILL sunaba-<projectID>-<vmID>
```

- 完全名がlabelのProject ID / VM IDと一致する
- `dev.sunaba.owner=sunaba-supervisor`であり、当該検証が作成したVMである
- 対応するSupervisor process、runtime directory、live guardが存在しない
- `container kill --all`、部分一致、glob、別containerとの同時指定を使わない
- signal後に個別`inspect`し、stoppedを確認できたVMだけを`container delete`する
- `buildkit`を含むuser-owned resource、container system、他のVMを停止・再起動しない

この復旧操作も、本文書を実装者が更新したこと自体は実行承認とみなさない。

上記のexact `container kill --signal KILL`も60秒以上応答せず、別clientの個別`inspect`で対象がなお`running`と確認された場合は、次をすべて満たすorphan test VMの最終復旧に限り、人間の追加個別承認後に下記を1台ずつ実行してよい。

```sh
container delete --force sunaba-<projectID>-<vmID>
```

- force delete直前の個別`inspect`で、完全名とowner/project/VM/mode labelが再び完全一致する
- 対応するSupervisor process、runtime directory、live guardが存在せず、VMに未exportの利用者成果物がないことを確認する
- 当該検証が作成した一時VMであり、VM overlayを破棄して同じtestをclean recreationできる
- 1 invocationにexactな1台だけを指定し、`--all`、glob、部分一致、複数指定を使わない
- 実行後は個別`inspect`がnot foundになることと、全resource listで対象だけが消えたことを確認する
- `buildkit`、container system、runtime/plugin process、他container、network、volume、imageを変更しない

force deleteは当該一時VMのoverlayを復元不能に破棄する。未承認成果物があるProject VMには使わず、通常のexport/stop/delete経路を使う。この例外も、本文書を実装者が更新したこと自体は実行承認とみなさない。

個別の通常stop、KILL、force deleteがすべて60秒以上固着し、Apple Containerの公開lifecycle APIだけではorphan test VMを回収できない場合は、次をすべて満たす最終復旧に限り、人間へ一時停止するuser-owned resourceと復元手順を提示して承認を得た後、system serviceを1回だけstop/startしてよい。

```sh
container system stop
container system start
```

- 直前に`container system version` / `status`、全container、network、volumeをinventoryし、exact orphan VM以外のresourceを完全名・設定・状態ごと記録する
- 未承認の一般containerがrunningなら実行を拒否する。plugin管理の`buildkit`だけがrunningの場合も、人間へ一時停止の影響を明示して承認を得る
- `container system restart`、`sudo`、`launchctl`、service/runtime/plugin processへの直接signalを使わない
- stop完了後に直ちにstartし、system version/statusと全resourceを再inventoryする
- orphan VMがstoppedになった場合だけ個別deleteする。なおrunningなら、この節を反復せず停止して人間へ報告する
- 事前にrunningだったplugin管理`buildkit`が自動復元されなければ、同じ完全名を個別`container start buildkit`で復元してよい。delete、recreate、設定変更は行わない
- 復旧後の`buildkit`について、ID、image、labels、mount、network、running状態が事前inventoryと一致することを確認する

このsystem cycleは全container serviceを一時停止する。通常のtest cleanupには使わず、上記の固着状態から利用者承認付きで復旧する場合だけに限定する。この例外も、本文書を実装者が更新したこと自体は実行承認とみなさない。

Apple Container 1.2.2の`container system stop`自体が全containerの停止待ちで60秒以上固着し、別clientの`container system status`でAPIServerがなおrunningの場合は、同versionの[公式`SystemStop`実装](https://github.com/apple/container/blob/1.2.2/Sources/ContainerCommands/System/SystemStop.swift)と[公式`ServiceManager`実装](https://github.com/apple/container/blob/1.2.2/Sources/ContainerPlugin/ServiceManager.swift)がstop後段で行うlaunchd deregistrationだけを、同じservice domainとprefixへ限定して実行してよい。

```sh
/bin/launchctl managername
/bin/launchctl list
/bin/launchctl bootout gui/<current-uid>/com.apple.container.apiserver
/bin/launchctl bootout gui/<current-uid>/<exact-com.apple.container.service-label>
container system start
```

- 人間へsystem serviceと`buildkit`の一時停止、exact bootout対象、復元手順を提示し、明示承認を得る
- `managername`が`Aqua`、current UIDとdomainが`gui/<current-uid>`であることを確認する。別domainなら実行を拒否する
- `launchctl list`で現在登録済みの完全labelを記録し、`com.apple.container.apiserver`を最初にbootoutする
- 続いて、事前listに存在した`com.apple.container.` prefixの完全labelだけを1件ずつbootoutする。glob、部分一致、未確認label、別prefixを使わない
- `bootout`以外の`launchctl` mutation、`sudo`、service/runtime/plugin processへの直接signalを使わない
- bootout後は直ちに`container system start`し、system version/status、全resource、事前にrunningだった`buildkit`の同一性を再検証する
- system startまたは復元検証に失敗した場合は、bootoutを反復したり範囲を広げず停止して人間へ報告する

このfallbackも、本文書を実装者が更新したこと自体は実行承認とみなさない。

同じ障害で、当該検証が起動した`container stop`、`container kill`、`container delete --force`、`container system stop`、または当該exact VMへの`container exec` client processだけが60秒以上応答せず残った場合は、`ps -axo user,pid,ppid,lstart,command`でcurrent user、完全なargv、対応VM名を再確認し、人間の個別承認後にそのclient PIDだけへ`kill -TERM`を送ってよい。Apple Containerのruntime/plugin process、Supervisor、`buildkit`、名前や由来を確認できないprocessへsignalを送らない。TERM後も残るclientへ別signalを送る場合は改めて人間へ確認する。

## 許可するRuntime Adapter操作

ローカルbuildした`sunaba`または薄いSwift Runtime Adapterは、上記`container`コマンドと同じlifecycle、inspect、export/copy、network、volume、image操作だけをApple Containerの公開API経由で実行してよい。

- 対象の命名規則、copy先、削除前確認はCLI操作と同じにする
- 実行したAPI操作、Project ID、resourceの完全な名前を監査またはtest logへ残す
- Apple Container、Containerization、macOSのglobal設定を変更しない
- host一般service、Keychain、任意file、他Project resourceへアクセスするAPIを追加しない
- この節に対応するCLI操作が列挙されていない新しいmutationが必要になった場合は、先に本文書を更新して人間の確認を受ける

## 禁止する操作

以下は実装完了に不要であり、ホストを壊すリスクが高いため禁止する。

```sh
sudo rm -rf /
sudo rm -rf /etc
sudo pfctl -d
sudo pfctl -F all
sudo pfctl -F rules
sudo launchctl ...
sudo nvram ...
sudo defaults write ...
sudo networksetup ...
container rm <sunaba- 以外のコンテナ>
container delete <sunaba- 以外のコンテナ>
container kill --all
container delete --all
container delete --force <上記の個別復旧条件を満たさない対象>
container image delete <sunaba-base: 以外のイメージ>
container network delete <sunaba- 以外のnetwork>
container volume delete <sunaba- 以外のvolume>
container system dns create ...
container system dns delete ...
```

必要性が生じた場合は、本文書を先に更新してから実行する。
