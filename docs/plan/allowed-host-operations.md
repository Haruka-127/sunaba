# sunaba実装時に許可するホスト側操作

本文書は、sunabaの実装・検証を自律的に完了するために、ホスト上で実行してよい操作を定義する。

`docs/plan/opencode-secure-agent-platform-implementation.md` に記載された機能を実装・検証するための最小限の操作だけを許可する。ここにない `sudo` 操作、ホスト設定変更、任意のコンテナ削除は行わない。

## 原則

- `sudo` は pf による「コンテナからホストへの通信遮断」を実装・検証する目的に限って使う
- `sudo` を使う入口は原則として `sunaba firewall` サブコマンドに限定する
- `/etc/pf.conf` は `# BEGIN sunaba` から `# END sunaba` までの管理ブロックだけを追加・更新・削除する
- `/etc/pf.anchors/sunaba` 以外の pf anchor ファイルは作成・変更・削除しない
- 既存の pf ルールを flush しない。`pfctl -F ...` は使用禁止
- pf 自体を無効化しない。`pfctl -d` は使用禁止
- `container` 操作は `sunaba-` プレフィックスのコンテナ、`sunaba-base:` イメージ、検証用一時プロジェクトに限定する
- 検証後は作成した `sunaba-` プレフィックスのコンテナ・一時プロジェクト・不要な検証リソースを削除する

## 許可する sudo コマンド

以下は、実装した `sunaba` バイナリが存在する前提で許可する。

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
container build --tag sunaba-base:<version> ...
container run --detach --name sunaba-<projectID> ... sunaba-base:<version>
container start sunaba-<projectID>
container stop sunaba-<projectID>
container rm sunaba-<projectID>
container exec ... sunaba-<projectID> ...
container inspect sunaba-<projectID>
container ls ...
container network inspect ...
```

`container rm` は `sunaba-` プレフィックスのコンテナに限定する。ユーザーが作成した他のコンテナ、イメージ、ボリュームは削除しない。

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
container image rm <sunaba-base: 以外のイメージ>
```

必要性が生じた場合は、本文書を先に更新してから実行する。
