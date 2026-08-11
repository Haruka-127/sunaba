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
sudo sunaba firewall disable
sudo sunaba firewall status
```

開発中に未インストールのバイナリを使う場合は、同等のローカルビルド成果物に置き換えてよい。

```sh
sudo ./bin/sunaba firewall enable
sudo ./bin/sunaba firewall disable
sudo ./bin/sunaba firewall status
```

`sunaba firewall enable` / `disable` の内部実装でのみ、以下の root 権限操作を許可する。

- `/etc/pf.conf` を `/etc/pf.conf.sunaba.bak` にバックアップする
- `/etc/pf.conf` の sunaba 管理ブロックだけを追加・更新・削除する
- `/etc/pf.anchors/sunaba` を作成・更新・削除する
- `/etc` と `/etc/pf.anchors` に `.sunaba-` プレフィックスの一時ファイルを作成し、構文検査成功後に上記2ファイルへ原子的に置換する。処理終了時に一時ファイルを削除する
- `/sbin/pfctl -nf /etc/pf.conf` または上記sunaba一時ファイルで構文検査する
- `/sbin/pfctl -a sunaba -nf /etc/pf.anchors/sunaba` または上記sunaba一時ファイルでanchorを構文検査する
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

`container rm`、`network delete`、`volume delete`、`image delete`は上記の命名規則を満たし、当該検証またはProjectが作成したことを確認できるresourceだけに限定する。ユーザーが作成した他のcontainer、network、image、volumeは削除しない。

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
container image delete <sunaba-base: 以外のイメージ>
container network delete <sunaba- 以外のnetwork>
container volume delete <sunaba- 以外のvolume>
container system dns create ...
container system dns delete ...
```

必要性が生じた場合は、本文書を先に更新してから実行する。
