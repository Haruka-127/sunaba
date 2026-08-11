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
container network create sunaba-<projectID>-<sessionID>-net ...
container network list ...
container network inspect sunaba-<projectID>-<sessionID>-net ...
container network delete sunaba-<projectID>-<sessionID>-net
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
container kill --signal KILL sunaba-<projectID>-<sessionID>
```

- 完全名がlabelのProject ID / Session IDと一致する
- `dev.sunaba.owner=sunaba-supervisor`であり、当該検証が作成したVMである
- 対応するSupervisor process、runtime directory、live guardが存在しない
- `container kill --all`、部分一致、glob、別containerとの同時指定を使わない
- signal後に個別`inspect`し、stoppedを確認できたVMだけを`container delete`する
- `buildkit`を含むuser-owned resource、container system、他のVMを停止・再起動しない

この復旧操作も、本文書を実装者が更新したこと自体は実行承認とみなさない。

上記のexact `container kill --signal KILL`も60秒以上応答せず、別clientの個別`inspect`で対象がなお`running`と確認された場合は、次をすべて満たすorphan test VMの最終復旧に限り、人間の追加個別承認後に下記を1台ずつ実行してよい。

```sh
container delete --force sunaba-<projectID>-<sessionID>
```

- force delete直前の個別`inspect`で、完全名とowner/project/session/mode labelが再び完全一致する
- 対応するSupervisor process、runtime directory、live guardが存在せず、VMに未exportの利用者成果物がないことを確認する
- 当該検証が作成した一時VMであり、VM overlayを破棄して同じtestをclean recreationできる
- 1 invocationにexactな1台だけを指定し、`--all`、glob、部分一致、複数指定を使わない
- 実行後は個別`inspect`がnot foundになることと、全resource listで対象だけが消えたことを確認する
- `buildkit`、container system、runtime/plugin process、他container、network、volume、imageを変更しない

force deleteは当該一時VMのoverlayを復元不能に破棄する。未承認成果物があるProject VMには使わず、通常のexport/stop/delete経路を使う。この例外も、本文書を実装者が更新したこと自体は実行承認とみなさない。

同じ障害で、当該検証が起動した`container stop`、`container kill`、`container delete --force`、または当該exact VMへの`container exec` client processだけが60秒以上応答せず残った場合は、`ps -axo user,pid,ppid,lstart,command`でcurrent user、完全なargv、対応VM名を再確認し、人間の個別承認後にそのclient PIDだけへ`kill -TERM`を送ってよい。Apple Containerのruntime/plugin process、Supervisor、`buildkit`、名前や由来を確認できないprocessへsignalを送らない。TERM後も残るclientへ別signalを送る場合は改めて人間へ確認する。

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
