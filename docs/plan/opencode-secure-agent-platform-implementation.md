# opencodeセキュア実行基盤 実装リファレンス

本文書は、設計文書 `docs/plan/opencode-secure-agent-platform.md` を自律型コーディングエージェント(codex)が実装を完遂できるレベルまで具体化した実装仕様である。

- 設計文書の「初期MVP」「MVP直後」という段階分けは**無視し、本文書に記載された全機能を一度に実装する**
- 設計文書と本文書に齟齬がある場合は**本文書を優先**する(未決定事項を実装用に確定させているため)
- 本文書内の「要確認」マークは、依存ツールのバージョン差により構文が変わり得る箇所である。実装時に必ず `--help` や公式ドキュメントで実際の構文を確認してから使うこと
- 実装・検証で許可するホスト側操作は `docs/plan/allowed-host-operations.md` に従う

## 1. 成果物

| 成果物 | 配置先 |
|---|---|
| CLIツール `sunaba`(Go製、単一バイナリ) | リポジトリルート配下にソース一式 |
| ベースイメージ定義(Containerfile、entrypoint.sh) | `assets/`(go:embedでバイナリに埋め込み) |
| pfルールテンプレート | `assets/` または `internal/firewall/` 内定数 |
| 統合検証スクリプト | `scripts/verify.sh` |
| README(利用者向け、日本語) | `README.md` |
| 単体テスト | 各パッケージ内 `*_test.go` |
| 許可するホスト側操作の定義 | `docs/plan/allowed-host-operations.md` |

## 2. 前提環境

実行(検証)に必要な環境:

- macOS 26 以降 / Apple silicon
- [apple/container](https://github.com/apple/container) 1.0 以上がインストール済みで、`container system start` 済み
- ホストに opencode CLI/TUI がインストール済み(`opencode` コマンドが PATH にある。デスクトップ版は使用しない)
- Go 1.22 以上

`sunaba` は起動時にこれらを検査し、満たさない場合は導入手順を示すエラーメッセージを出して終了する(§12)。

## 3. 確定した設計判断

設計文書の未決定事項および実装に必要な選択を以下の通り確定する。

| # | 項目 | 決定 |
|---|---|---|
| D1 | 実装言語・配布形態 | Go(標準ライブラリのみ。外部依存を追加しない)。単一バイナリ `sunaba` |
| D2 | ランタイム抽象化 | `internal/runtime` にインターフェースを定義し、apple container 実装は `container` CLI のサブプロセス呼び出しで行う |
| D3 | ホスト宛て通信遮断 | macOS の pf(パケットフィルタ)にアンカー `sunaba` を追加して実現(§9) |
| D4 | LAN宛て通信 | 本版では許可のまま(設計文書の未決定に従い実装しない) |
| D5 | 通信プロキシ拡張点 | プロジェクト設定 `proxy` を設けると `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` がコンテナ環境変数に注入される(プロキシ自体は実装しない) |
| D6 | GitHub認証等のトークン注入 | `sunaba env` コマンドでプロジェクト単位の環境変数として注入(§11) |
| D7 | ベースイメージのビルド・配布 | ローカルビルド。埋め込んだ Containerfile から `container build` する。レジストリ配布はしない |
| D8 | イメージ更新の既存環境への適用 | 次回 reset / コンテナ再作成時に反映。`sunaba up` が旧イメージ利用を検知したら警告して reset を提案 |
| D9 | opencodeデータの「別ボリューム」 | named volume ではなく、ホスト状態ディレクトリのbindマウントで実現(reset実装が単純・確実なため) |
| D10 | serverパスワード保管 | 状態ディレクトリ内の 0600 ファイル(脅威モデルはホスト側を信頼するため Keychain は使わない) |
| D11 | server ポート | コンテナ内 4096 固定。ホストからはコンテナIPへ直接接続(ポート公開はしない) |
| D12 | CLIメッセージ | 英語。README は日本語 |

## 4. 全体構成

```
ホスト (macOS)                          隔離環境 (Linux VM / apple container)
┌─────────────────────────────┐        ┌──────────────────────────────────┐
│ sunaba CLI                  │        │ entrypoint (root)                │
│  ├─ runtime抽象層 ──────────┼─exec──▶│  └─ opencode serve (agentユーザー)│
│  ├─ 監査デーモン(SSE購読) ◀─┼─HTTP───┤      0.0.0.0:4096 basic auth     │
│  └─ pf管理 (sudo)           │        │                                  │
│ opencode TUI (attach) ──────┼─HTTP──▶│                                  │
│ pf: コンテナ→ホスト遮断     │        │ マウント:                        │
│ 状態: ~/.local/share/sunaba │        │  <projectパス> = ホストと同一パス │
└─────────────────────────────┘        │  opencode-data → ~/.local/share/opencode │
                                       │  opencode-config → ~/.config/opencode    │
                                       └──────────────────────────────────┘
```

- 通信方向: ホスト→コンテナ(attach、監査、ヘルスチェック)は許可。コンテナ→ホストは pf で遮断。コンテナ→インターネットは許可
- コンテナはプロジェクトごとに1つ。名前 `sunaba-<projectID>`。TUI終了後も稼働し続け、`sunaba stop` で停止する

## 5. ホスト側状態管理

状態ディレクトリ: `~/.local/share/sunaba/`(`XDG_DATA_HOME` があれば従う)

```
~/.local/share/sunaba/
├── config.json                 # グローバル設定 { "image_version": "<opencodeバージョン>" }
├── network.json                # pf用に検出したサブネット/GW/IF のキャッシュ
└── projects/<projectID>/
    ├── config.json             # 下記スキーマ
    ├── server-password         # 0600。base64url 32バイト乱数
    ├── env                     # 0600。KEY=VALUE 形式(sunaba envで管理)
    ├── opencode-config/        # 生成した opencode.json を置く(コンテナへマウント)
    ├── opencode-data/          # セッション履歴・auth.json(コンテナへマウント)
    ├── audit.pid               # 監査デーモンのPIDファイル
    └── logs/audit-YYYYMMDD.jsonl
```

- `projectID` = プロジェクト絶対パス(シンボリックリンク解決済み)の SHA-256 先頭12桁hex
- プロジェクト `config.json` スキーマ:

```json
{
  "path": "/Users/alice/work/myapp",
  "container": "sunaba-a1b2c3d4e5f6",
  "image_version": "1.17.13",
  "cpus": 4,
  "memory": "8g",
  "proxy": "",
  "created_at": "2026-07-02T12:00:00Z"
}
```

- 状態ディレクトリとその配下は作成時に 0700/0600 を設定する
- パスの再解決に失敗した(プロジェクトが移動した)場合は、エラーで案内する(`sunaba list` で残骸を確認、`sunaba reset --full` 相当の掃除手順を表示)

## 6. ベースイメージ仕様

### 6.1 Containerfile(assets/Containerfile)

```dockerfile
FROM debian:bookworm-slim

ARG OPENCODE_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
        bash ca-certificates curl wget git tar unzip zip ripgrep \
        sudo procps openssh-client locales \
    && rm -rf /var/lib/apt/lists/*

# opencode CLI/TUI 本体の導入(linux arm64、バージョン固定)。デスクトップ版は使用しない。
# 現行の公式インストーラは linux-arm64 では opencode-linux-arm64.tar.gz を取得する。
RUN set -eux; \
    curl -fsSL -o /tmp/opencode.tar.gz \
      "https://github.com/anomalyco/opencode/releases/download/v${OPENCODE_VERSION}/opencode-linux-arm64.tar.gz"; \
    tar -xzf /tmp/opencode.tar.gz -C /usr/local/bin opencode; \
    chmod +x /usr/local/bin/opencode; \
    rm -f /tmp/opencode.tar.gz; \
    opencode --version

# バージョンピン留め: コンテナ内での自動更新は必ず無効化する(主制御は opencode.json の autoupdate=false)
ENV OPENCODE_DISABLE_AUTOUPDATE=1

LABEL dev.sunaba.opencode-version="${OPENCODE_VERSION}"

COPY entrypoint.sh /usr/local/bin/sunaba-entrypoint
RUN chmod +x /usr/local/bin/sunaba-entrypoint

ENTRYPOINT ["/usr/local/bin/sunaba-entrypoint"]
```

イメージタグ: `sunaba-base:<OPENCODE_VERSION>`

### 6.2 entrypoint.sh(assets/entrypoint.sh)

受け取る環境変数: `SUNABA_UID` `SUNABA_GID` `SUNABA_WORKDIR` `OPENCODE_SERVER_PASSWORD`(+ `sunaba env` による任意変数)

処理:

1. ユーザー `agent`(UID=`SUNABA_UID`、GID=`SUNABA_GID`、ホーム `/home/agent`、シェル bash)を冪等に作成
2. `/etc/sudoers.d/sunaba` に `agent ALL=(ALL) NOPASSWD:ALL` を書く(0440)— 設計文書「必要に応じてsudoを許可」の実装
3. `/home/agent/.local/share` `/home/agent/.config` を作成し、`chown -R agent` を試みる(virtiofs 上で chown が効かない場合があるため**失敗しても続行**)
4. `cd "$SUNABA_WORKDIR"`
5. `exec sudo -E -H -u agent opencode serve --hostname 0.0.0.0 --port 4096`

serverを**非rootで実行する**こと(設計文書の脅威モデルとの整合)。

### 6.3 opencode設定(自動承認の実現)

`sunaba` が `opencode-config/opencode.json` をホスト側で生成し、コンテナの `/home/agent/.config/opencode/opencode.json` にマウントする:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "autoupdate": false,
  "permission": "allow"
}
```

- opencode 1.17.13 時点では `permission: "allow"` で全権限を一括許可できる。目的は「隔離環境内では許可プロンプトが一切出ない」状態(設計文書: 常時自動承認)
- 補助手段として環境変数 `OPENCODE_PERMISSION`(インラインJSON)も利用可。設定ファイルで不足する場合に併用する
- 検証方法: attach したTUIでファイル編集・bash実行を指示し、許可プロンプトが出ないこと

## 7. CLIコマンド仕様

サブコマンド構成(標準ライブラリ `flag` で実装。フレームワーク不要):

```
sunaba up [--dir PATH] [--cpus N] [--memory SIZE] [--no-attach] [--no-firewall]
sunaba shell [--dir PATH]
sunaba stop [--dir PATH]
sunaba reset [--dir PATH] [--full] [--yes]
sunaba update [--opencode-version X.Y.Z]
sunaba status [--dir PATH]
sunaba list
sunaba env set KEY=VALUE... | unset KEY... | list   [--dir PATH]
sunaba firewall enable | disable | status
sunaba logs [--dir PATH] [-f]
sunaba _audit --project ID        # 内部用(非表示): 監査デーモン本体
```

`--dir` 省略時はカレントディレクトリをプロジェクトとする。

### 7.1 `sunaba up`(中核コマンド)

1. 前提検査(§2)。不合格なら導入手順を表示して終了
2. プロジェクト解決、状態ディレクトリ初期化。初回はパスワード生成、`opencode.json` 生成、**初回注意文の表示**(§11.4)
3. イメージ確認: グローバル `image_version` 未設定なら `sunaba update` 相当を実行(最新版の解決とビルド)。イメージ `sunaba-base:<ver>` が無ければビルド
4. コンテナ確認:
   - 存在しない → `container run --detach` で作成(§8)し、`config.json` に `image_version` を記録
   - 停止中 → `container start`
   - 稼働中 → そのまま
5. ファイアウォール確認(§9): 未適用なら `docs/plan/allowed-host-operations.md` で許可された権限昇格操作として `sudo` で適用を試みる。失敗した場合は**エラー終了**(明確な理由と手動手順を表示)。`--no-firewall` 指定時のみ警告を出して続行
6. コンテナIP取得(§8.3)、`/global/health` を basic auth 付きでポーリング(最大90秒)
7. バージョン検査(warn のみ、ブロックしない):
   - ホスト `opencode --version` と health レスポンスの `version` が不一致 → 警告(設計文書: attach時の警告)
   - コンテナ作成時の `image_version` とグローバル `image_version` が不一致 → 「新しいイメージがあります。反映するには `sunaba reset` を実行してください」と警告(D8)
8. 監査デーモン起動(§10)
9. attach(`--no-attach` 時はスキップ): 子プロセスとして
   `opencode attach http://<container-ip>:4096 --dir <プロジェクト絶対パス>` を実行。パスワードは環境変数 `OPENCODE_SERVER_PASSWORD` で渡す(コマンドライン引数に載せない)
10. TUI終了後もコンテナと監査デーモンは稼働継続。`Server keeps running. Use 'sunaba stop' to stop it.` を表示

### 7.2 `sunaba shell`

コンテナが稼働していなければ起動(up の 1-6 相当、attachなし)した上で:

```
container exec --interactive --tty <name> sudo -u agent -i bash -c 'cd <projectパス> && exec bash'
```

- 要確認: `container exec` に `--user` フラグがあればそちらを優先(`sudo -u` 不要)
- 一般ユーザー(agent)で入り、sudo が使えること(設計文書の要求)

### 7.3 `sunaba stop`

監査デーモン停止(pidfile → SIGTERM)→ `container stop <name>`。

### 7.4 `sunaba reset`

1. `--yes` が無ければ破棄内容を表示して確認プロンプト
2. 監査デーモン停止 → `container stop`(稼働時)→ `container rm <name>`
3. 通常reset: 削除するのはコンテナのみ。`opencode-data/`(セッション履歴・認証)、`env`、`server-password`、`logs/` は**保持**
4. `--full`: 加えてプロジェクト状態ディレクトリ全体を削除(履歴・認証・パスワード・ログすべて)
5. 完了メッセージと `sunaba up` での再作成案内

設計文書の段階式resetの実装である。次回 `up` は最新イメージでコンテナを作り直すため、イメージ更新の適用(D8)もここで行われる。

### 7.5 `sunaba update`

1. 対象バージョン解決: `--opencode-version` 指定が無ければ GitHub API
   `https://api.github.com/repos/anomalyco/opencode/releases/latest` の `tag_name`(先頭の `v` を除去)。API失敗時(レート制限等)はエラーにし、`--opencode-version` の明示指定を案内
2. 埋め込みアセット(Containerfile、entrypoint.sh)を一時ディレクトリに展開し、
   `container build --tag sunaba-base:<ver> --build-arg OPENCODE_VERSION=<ver> <dir>`(要確認: フラグ構文)
3. 成功したらグローバル `config.json` の `image_version` を更新
4. 「既存の隔離環境には次回 reset 時に反映されます」と表示(D8)。稼働中コンテナには触れない

### 7.6 `sunaba status`

表示項目: プロジェクトパス / projectID / コンテナ状態(稼働・停止・未作成)/ コンテナIP / コンテナのイメージ版と最新イメージ版 / server ヘルス(version含む)/ ホストopencodeバージョン / ファイアウォール適用状態 / 監査デーモン稼働状態 / ログ・状態ディレクトリのパス。

### 7.7 `sunaba list`

`projects/` 配下を列挙し、パス・コンテナ状態・作成日時を表形式で表示。

### 7.8 `sunaba env`

§11.2 参照。

### 7.9 `sunaba firewall`

§9 参照。`enable`/`disable` は root 権限が必要(root でなければ `sudo` で自分自身を再実行する)。

### 7.10 `sunaba logs`

当日の監査ログファイルのパス表示と内容出力。`-f` で追尾(tail -f 相当)。

## 8. コンテナ実行仕様

### 8.1 作成コマンド(概形)

```
container run --detach --name sunaba-<projectID> \
  --cpus <cpus> --memory <memory> \
  --volume "<projectパス>:<projectパス>" \
  --volume "<state>/projects/<id>/opencode-data:/home/agent/.local/share/opencode" \
  --volume "<state>/projects/<id>/opencode-config:/home/agent/.config/opencode" \
  --env SUNABA_UID=<ホストUID> --env SUNABA_GID=<ホストGID> \
  --env SUNABA_WORKDIR=<projectパス> \
  --env OPENCODE_SERVER_PASSWORD=<パスワード> \
  [--env KEY=VALUE ...            # sunaba env の内容] \
  [--env HTTP_PROXY=... など      # proxy設定時(D5)] \
  sunaba-base:<image_version>
```

- 要確認: `container run/create` の正確なフラグ名(`--volume` `--cpus` `--memory` `--env`)を `container run --help` で確認
- ディスク上限フラグ(例 `--disk-size`)が存在すれば既定値を設けて適用し、無ければ README に「ランタイム既定のディスクサイズに従う」と明記する(設計文書のディスク上限要求への対応)
- **マウントは上記の3点のみ。追加のホストパスを絶対にマウントしない**(設計文書: ファイルアクセス制限、ホスト秘密情報の非マウント)
- プロジェクトをホストと同一絶対パスでマウントする(設計文書の要求)。マウントの結果ゲスト内に親ディレクトリ階層(例 `/Users/alice/work`)が生成されるが、実体はプロジェクトフォルダのみであることを README に記載
- リソース既定値: `cpus=4`、`memory=8g`。`sunaba up --cpus/--memory` で上書きし `config.json` に永続化

### 8.2 ポート

公開(publish)しない。ホストは vmnet 経由でコンテナIPの 4096 に直接接続する。

### 8.3 コンテナIPの取得

`container inspect <name>` の JSON 出力からIPアドレスを取得する。

- 要確認: JSONの構造(ネットワーク情報のキー名)。`container inspect` の実出力をパースして決めること
- 代替: `container ls --format json` に含まれる場合はそちらでも可

## 9. ネットワーク制御(pf によるホスト遮断)

### 9.1 要件(設計文書より)

1. コンテナ→インターネット: 許可
2. コンテナ→ホスト(macOS自身): 遮断
3. ホスト→コンテナ: 許可(attach等)
4. 遮断は**ホスト側**で実施(ゲスト内では行わない。sudo許可方針と両立しないため)

### 9.2 実現方式

pf アンカー `sunaba` を使う。`sunaba firewall enable`(要root)が以下を行う:

1. サブネット等の検出(§9.4)
2. `/etc/pf.anchors/sunaba` にルールファイルを書く(§9.3)
3. `/etc/pf.conf` にマーカー付きでアンカー参照を追記(冪等):

```
# BEGIN sunaba
anchor "sunaba"
load anchor "sunaba" from "/etc/pf.anchors/sunaba"
# END sunaba
```

編集前に `/etc/pf.conf.sunaba.bak` へバックアップを取る。

4. `pfctl -f /etc/pf.conf` で再読み込み、`pfctl -E` で pf を有効化

`disable` はマーカー区間と anchors ファイルを除去して再読み込み。`status` は `pfctl -sr`・`pfctl -a sunaba -sr` の結果からアンカーの読込み状態を判定して表示。

### 9.3 ルールテンプレート

検出値を埋め込んで生成する(例: IF=`bridge100`、subnet=`192.168.64.0/24`、gw=`192.168.64.1`):

```
# Managed by sunaba. Do not edit.
# DHCP(これを塞ぐとコンテナのアドレス取得が壊れる)
pass in quick on bridge100 inet proto udp from any port 68 to any port 67
# ゲートウェイが提供するDNS(これを塞ぐと名前解決が壊れる)
pass in quick on bridge100 inet proto { tcp udp } from 192.168.64.0/24 to 192.168.64.1 port 53
# コンテナ→ホスト(ホストの全アドレス)を遮断
block drop in quick on bridge100 inet from 192.168.64.0/24 to self
# コンテナ→ホストのIPv6通信を送信元アドレスにかかわらず遮断
block drop in quick on bridge100 inet6 from any to self
```

**実装上の要点(誤りやすい)**:

- pf は**ステートテーブルを先に評価**する。ホスト→コンテナで確立した通信の戻りパケットは state に一致してルール評価をバイパスするため、この block はホスト発の接続(attach等)を壊さない
- アンカーは**メインルールセットから参照されない限り評価されない**。`/etc/pf.conf` への追記が必須
- DHCP/DNS の pass を block より前に(いずれも `quick` 付きで)置くこと。ゲートウェイIP はホスト(self)の一部なので、例外が無いとコンテナの通信全体が壊れる
- インターネット宛のパケットは宛先が self でないため block に一致しない(=要件1を満たす)

### 9.4 サブネット・インターフェース検出

1. 稼働中コンテナのIPを §8.3 で取得し、/24 と仮定してサブネットとゲートウェイ(第4オクテット1)を導出
2. `ifconfig` の出力からゲートウェイIPを持つインターフェース(通常 `bridge100`)を特定
3. 検出結果を `network.json` にキャッシュ。検出不能時のフォールバック既定値: `bridge100` / `192.168.64.0/24` / `192.168.64.1`
4. 要確認: `container network inspect`(macOS 26)でサブネットが取得できるならそちらを優先

## 10. 監視・監査ログ

設計文書の「監視・監査ログ」の実装。**本実装に含める**(MVP直後という段階指定は無視)。

- `sunaba up` が `sunaba _audit --project <id>` をデタッチした子プロセスとして起動(既に稼働中なら何もしない。判定は pidfile + プロセス存在確認)
- デーモンの動作:
  1. `GET http://<container-ip>:4096/event` に `Accept: text/event-stream` と basic auth(ユーザー名 `opencode`、パスワードはファイルから)で接続
  2. SSE をパースし(`data:` 行の連結が1イベント)、1イベント=1行の JSONL で書き出す: `{"ts":"<RFC3339Nano>","event":<受信JSONそのまま>}`
  3. 書き出し先: `logs/audit-YYYYMMDD.jsonl`(日付が変わったら新ファイル)
  4. 切断時は指数バックオフ(1s→最大30s)で再接続。コンテナが存在しない/停止状態を検知したら正常終了
- 最初のイベントは `server.connected`。以後、セッション・メッセージ・パーミッション・ファイル変更等のバスイベントが流れる(全て記録する。フィルタしない)
- ログはホスト側にのみ存在し、コンテナにマウントしない(改変不能の要求)
- `sunaba stop` / `sunaba reset` はデーモンを停止する

## 11. 秘密情報の取り扱い実装

### 11.1 serverパスワード

- 初回 `up` 時に crypto/rand で32バイト生成し base64url 化、`server-password`(0600)に保存
- コンテナへは環境変数 `OPENCODE_SERVER_PASSWORD` として渡す。attach・ヘルスチェック・監査デーモンも同じ値を使う(basic auth、ユーザー名は既定の `opencode`)
- パスワードを引数・ログ・エラーメッセージに出さない

### 11.2 `sunaba env`(最小権限トークンの注入。D6)

- `sunaba env set GITHUB_TOKEN=github_pat_xxx` → `env` ファイル(0600)に保存
- コンテナ**作成時**に `--env` で注入する。作成後の変更は反映されないため、set/unset 時に稼働中コンテナがあれば `Run 'sunaba reset' to apply.` と表示する
- `sunaba env list` は値をマスクして表示(先頭4文字+`…`)
- README に「対象リポジトリを限定した fine-grained PAT 等、権限を最小化したトークンのみを注入すること」を記載

### 11.3 マウント禁止の徹底

コンテナに渡すマウントは §8.1 の3点のみ。`~/.ssh` やグローバルgit設定を渡すオプションは**作らない**。

### 11.4 初回注意文(プロジェクト初回 `up` 時に表示)

以下の内容を含むこと(英語で簡潔に):

1. LLM APIキーは本基盤専用の低権限キーを使い、プロバイダ側で支出上限を設定すること(設計文書: 秘密情報)
2. エージェントがプロジェクトフォルダに書いたファイル(git hooks、.vscode、node_modules等)はホスト側のgit/エディタが実行し得る。ホスト側でビルド・コミットする前にdiffを確認すること(設計文書: マウント貫通の警告)
3. 外向きインターネット通信は許可されているため、プロジェクト内容とコンテナ内認証情報の流出は防げないこと(設計文書: 残余リスク)
4. 認証情報のセットアップ方法: `sunaba shell` 内で `opencode auth login`(保存先はマウントされた opencode-data 内の auth.json であり、通常resetでは保持される)

## 12. エラー処理・UX共通仕様

- 前提未達(container未導入、`container system start` 未実行、opencode未導入、Apple silicon以外)はそれぞれ具体的な解決コマンドを提示して exit 1
- すべての操作は冪等(既に存在する/稼働中/適用済みならスキップして成功)
- 外部コマンド実行は `exec.CommandContext` を使い、タイムアウト(ビルド以外は原則60秒、ビルドは30分)を設ける。失敗時は実行したコマンドラインと stderr を表示する
- `--verbose` グローバルフラグで実行する外部コマンドをすべて表示
- SIGINT/SIGTERM で子プロセス(attach中のTUI等)へシグナルを転送し、後始末をして終了

## 13. 検収チェックリスト(完了条件)

以下全項目を満たした時点で実装完了とする。`scripts/verify.sh` は A 群を自動化する(環境依存の B 群は手順を出力する)。設計文書の要求との対応を示す。

### A. 自動検証(verify.sh + go test)

| ID | 検証内容(対応する設計文書の要求) | 手順と期待結果 |
|---|---|---|
| A1 | ビルドと静的検査 | `go build ./...` `go vet ./...` `go test ./...` がすべて成功 |
| A2 | 環境作成・起動(隔離環境) | テスト用一時プロジェクトで `sunaba up --no-attach` 成功。`container ls` に `sunaba-<id>` が稼働状態で存在 |
| A3 | ファイルアクセス限定 | コンテナ内で `ls <プロジェクトパス>` 成功、プロジェクト外のホストパス(例 `~/Documents`)が存在しない |
| A4 | 同一絶対パスマウント | コンテナ内 `test -d <ホストと同一のプロジェクト絶対パス>` 成功 |
| A5 | 双方向のファイル反映 | ホストで作成したファイルがコンテナから見え、コンテナで作成したファイルがホストから見える |
| A6 | server起動とパスワード保護 | 認証なし `curl http://<ip>:4096/global/health` → 401。正しい basic auth → 200 で `version` を含む |
| A7 | 自動承認 | `opencode run --attach http://<ip>:4096 ...`(認証付き)でファイル書込みを伴うプロンプトを実行し、許可待ちにならず完了する |
| A8 | ホスト遮断 | ホストでIPv4/IPv6両対応のHTTP serverを起動し、コンテナからIPv4 gatewayおよびIPv6 link-local gatewayへの `curl` がともに**失敗**する |
| A9 | インターネット許可とDNS | コンテナから `curl -m 15 -sSf https://example.com` が成功する(遮断後も名前解決が生きていること) |
| A10 | ホスト→コンテナ許可 | 遮断適用後もホストから health エンドポイントに到達できる |
| A11 | 監査ログ | A7 実行後、`logs/audit-*.jsonl` に1行以上のイベントが追記されている。各行が有効なJSONである |
| A12 | 環境の永続化 | コンテナ内で `sudo apt-get install -y sl` 等を実行 → `sunaba stop` → `sunaba up --no-attach` 後もインストール済みである |
| A13 | 通常reset(段階式) | セッションを1つ作成し、コンテナ内 `/home/agent/marker` を作成 → `sunaba reset --yes` → 再作成後 marker は消えているが、`/session` API のセッション一覧は保持されている |
| A14 | フルreset | `sunaba reset --full --yes` 後、プロジェクト状態ディレクトリが消えている。再 `up` で新規パスワードが生成される |
| A15 | env注入 | `sunaba env set SUNABA_TEST=abc` → reset → コンテナ内 `printenv SUNABA_TEST` が `abc` |
| A16 | sudo | コンテナ内 agent ユーザーで `sudo id -u` → `0` |
| A17 | 非rootserver | コンテナ内で opencode serve プロセスの実行ユーザーが agent である |
| A18 | 自動更新無効 | コンテナ内の opencode 設定で `autoupdate=false`、かつ `printenv OPENCODE_DISABLE_AUTOUPDATE` → `1` |
| A19 | リソース上限 | `container inspect` の出力に cpus=4 / memory=8g(既定値)相当の設定が含まれる |
| A20 | イメージ更新 | `sunaba update --opencode-version <一つ前の版>` → `sunaba status` が版差を警告 → `sunaba reset` → 再作成後の server version が指定版になる |
| A21 | 冪等性 | `sunaba up --no-attach` を2回連続実行してもエラーにならない |

### B. 手動確認(実装者が手順をREADMEに記載し、可能なら実施)

| ID | 検証内容 | 手順 |
|---|---|---|
| B1 | TUI attach(利用者向け機能) | `sunaba up` でTUIが開き、対話できる。終了後 `sunaba up` で再接続できる |
| B2 | バージョン不一致警告 | ホストopencodeとイメージ版が異なる状態で `sunaba up` → 警告表示 |
| B3 | シェル接続 | `sunaba shell` で agent ユーザーのシェルに入れる |
| B4 | 初回注意文 | 新規プロジェクトの初回 `up` で §11.4 の注意が表示される |
| B5 | firewall無効環境の拒否 | `sunaba firewall disable` 状態で `sunaba up` がエラーになり、`--no-firewall` では警告付きで起動する |

### C. コード品質

- C1: `internal/runtime` がインターフェースで抽象化され、apple container 実装がその背後に隠れている(設計文書: 薄い抽象層)
- C2: 外部依存が Go 標準ライブラリのみ(go.mod に require が無い)
- C3: 単体テスト対象: projectID導出、env ファイルのパース/シリアライズ、pf.conf のマーカー編集(冪等性)、SSEパーサ、バージョン比較、pfルール生成

## 14. 実装ガイダンス

### 14.1 リポジトリレイアウト

```
./
├── go.mod                    # module sunaba
├── cmd/sunaba/main.go
├── internal/cli/             # サブコマンド分岐・フラグ・出力
├── internal/state/           # 状態ディレクトリ・config.json・パスワード・env
├── internal/runtime/         # Runtimeインターフェース + applecontainer実装
├── internal/image/           # アセットembed・build・バージョン解決(GitHub API)
├── internal/opencode/        # health/versionクライアント・attach子プロセス管理
├── internal/audit/           # SSEクライアント・デーモン・ログローテーション
├── internal/firewall/        # 検出・ルール生成・pf.conf編集・pfctl呼び出し
├── assets/                   # Containerfile / entrypoint.sh(go:embed)
├── scripts/verify.sh
└── README.md
```

### 14.2 Runtime インターフェース(例)

```go
type Runtime interface {
    ImageExists(ctx context.Context, tag string) (bool, error)
    BuildImage(ctx context.Context, tag, contextDir string, buildArgs map[string]string) error
    ContainerState(ctx context.Context, name string) (State, error) // NotFound/Stopped/Running
    Create(ctx context.Context, spec ContainerSpec) error           // run --detach
    Start(ctx context.Context, name string) error
    Stop(ctx context.Context, name string) error
    Remove(ctx context.Context, name string) error
    Exec(ctx context.Context, name string, interactive bool, cmd []string) error
    IPAddress(ctx context.Context, name string) (string, error)
}
```

### 14.3 陥りやすい罠(必読)

1. **pfアンカーはメインルールセットから参照しないと無効**(§9.3)。また DHCP/DNS 例外を忘れるとコンテナの全通信が壊れ、A9 が落ちる
2. **`--env` はコンテナ作成時のみ有効**。env変更後は reset が必要(§11.2 のメッセージを忘れない)
3. **virtiofs 上の chown は失敗し得る**。entrypoint で致命的エラーにしない
4. **attach の `--dir` はサーバー側(コンテナ内)パス**。同一パスマウントのためホストパスをそのまま渡せばよい
5. `container` CLI・opencode CLI ともに開発が速い。**フラグ構文は実行環境の `--help` を正とする**。想定と異なる場合は runtime 実装内で吸収する
6. GitHub API は未認証だとレート制限が厳しい。update はエラーメッセージで `--opencode-version` 指定を案内する
7. macOS の仮想化はメモリバルーニングが不完全で、稼働中コンテナはメモリを保持し続ける。README に「使わないプロジェクトは `sunaba stop`」と記載
8. ホスト側編集のイベントがコンテナ内のファイルウォッチャーに伝播しない場合がある(virtiofs の既知の性質)。機能保証はせず README の既知の制限に記載
9. パスワード等の秘密値をプロセス引数に載せない(`ps` で見えるため)。環境変数かファイルで渡す
10. `opencode serve` の待受は `0.0.0.0` にすること。既定の `127.0.0.1` のままではホストから到達できない

### 14.4 検証環境が無い場合の扱い

実装環境で apple container / macOS が使えない場合(例: Linux上のCI):

- A1 と C 群(単体テスト)は必ず実行して通す
- A2〜A21 は `scripts/verify.sh` として完全に実装し、実行できなかった項目を最終報告で「PENDING(要macOS実機)」として列挙する

## 15. 参考資料

- 設計文書: `docs/plan/opencode-secure-agent-platform.md`
- opencode server API・CLI: https://opencode.ai/docs/server/ , https://opencode.ai/docs/cli/
- opencode permissions: https://opencode.ai/docs/permissions/
- opencode config: https://opencode.ai/docs/config/
- apple/container: https://github.com/apple/container (docs/ 配下の technical-overview, how-to, command-reference)
- pf.conf(macOS): `man pf.conf`, `man pfctl`
