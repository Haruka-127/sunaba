# NOTES

## 確認結果

- 実行環境: `Darwin arm64`、Go `go1.26.4 darwin/arm64`
- `container`: `/usr/local/bin/container`、`container CLI version 1.0.0`
- `opencode`: `/Users/wataru/.opencode/bin/opencode`、`1.17.13`
- `container system status`: `running`
- `container run` は `--detach`、`--name`、`--cpus`、`--memory`、`--volume`、`--env`、`--env-file` をサポートする。ディスク上限に相当するフラグは `run --help` には見当たらない
- `container exec` は `--user` と `--workdir` をサポートするため、`sunaba shell` は `sudo -u` ではなく `container exec --user agent --workdir <project>` を使う
- `container build` は `--tag` と `--build-arg KEY=VALUE` をサポートする
- `container inspect` は JSON を返すが、ヘルプ上はフォーマット指定が無い。実装は再帰的に `IPAddress` / `address` / `state` / `status` などを探索する
- `container network inspect default` から `ipv4Gateway=192.168.64.1`、`ipv4Subnet=192.168.64.0/24` が取得できるため、pf の検出はこれを優先する
- `container build --platform linux/arm64 ...` は `build.rosetta = true` のままだと buildkit 起動時に `Rosetta is not installed` で失敗した。container 1.0.0 では `container system property set` が削除されているため、`~/.config/container/config.toml` に `[build] rosetta = false` を設定し、`container system stop && container system start` 後に `sunaba-base:1.17.13` のビルド成功を確認した
- 実機起動検証で、mount destination 作成の影響により `/home/agent` が root 所有になり、opencode/Bun が `/home/agent/.cache` を作成できず終了するケースを確認した。entrypoint で `/home/agent` と `/home/agent/.cache` の所有権を明示的に整えるよう修正し、`--no-firewall` 起動で health 成功を確認した
- `SUNABA_FULL_VERIFY=1 scripts/verify.sh` は本セッションでは firewall enable の `sudo` が非対話でパスワードを読めないため A2 開始時点で停止した。sudo 不要の範囲は `--no-firewall` で A3/A4/A5/A6/A15/A16/A17/A18/A21 相当を手動確認済み
- `bin/sunaba up` 後にコンテナ内 `127.0.0.1:4096/global/health` は 200 を返すが、ホストから `192.168.64.x:4096` が timeout するケースを確認した。原因は pf anchor の `block drop in quick ... from <subnet> to self` が、ホスト発 TCP 接続の戻り SYN-ACK/ACK まで遮断していたこと。`flags A/A` の pass ルールを block の前に追加し、ホスト発接続の戻り TCP のみ通すよう修正した
- コンテナ内 DNS は解決できるが `https://example.com` / `https://api.openai.com` / `https://api.anthropic.com` が timeout するケースを確認した。ホスト側 HTTPS は成功し、コンテナ内 DNS は `192.168.64.1` で成功するため、原因は opencode/LLM 設定ではなく apple/container の NAT 経路。`sunaba firewall enable` が毎回 `/sbin/pfctl -f /etc/pf.conf` で main ruleset 全体を reload していたため、apple/container が動的に入れる NAT ルールを消した可能性が高い。既に `/etc/pf.conf` に sunaba anchor がある場合は `/sbin/pfctl -a sunaba -f /etc/pf.anchors/sunaba` だけを実行し、main ruleset を reload しないよう修正した
- GitHub API `https://api.github.com/repos/anomalyco/opencode/releases/latest` の最新タグは確認時点で `v1.17.13`
- linux-arm64 リリース成果物 `https://github.com/anomalyco/opencode/releases/download/v1.17.13/opencode-linux-arm64.tar.gz` は HTTP 302 で release asset に解決される
- `opencode attach` は `--dir`、`--password`、`--username` をサポートし、パスワードは `OPENCODE_SERVER_PASSWORD` からも読む
- `opencode run` は `--attach`、`--dir`、`--password`、`--username`、`--auto` をサポートする
- `opencode serve` は `--hostname` と `--port` をサポートする
- OpenCode の permissions ドキュメントでは `permission` 設定で `ask` / `allow` / `deny` を制御する。実装リファレンスに従い、コンテナ内設定は `permission: "allow"` とした

## 実装判断

- server password や `sunaba env` の値は `container run --env KEY=VALUE` の引数に載せず、一時 `--env-file` 経由で渡す。これはリファレンスの「環境変数として渡す」と「秘密値をプロセス引数に載せない」を両立するため
- `sunaba update` は埋め込みアセット変更を確実に反映するため `container build --no-cache` を使う
- ディスク上限は apple/container 1.0.0 の `container run --help` に該当フラグが無いため未設定。README にランタイム既定に従う制限として記載
- `sunaba firewall enable` / `disable` は root でなければ `sudo` で自分自身を再実行する。内部で触るファイルと pfctl 操作は `docs/plan/allowed-host-operations.md` の範囲に限定した

## 設計文書との差分

- 設計文書では監査ログが「MVP完了直後」とされているが、実装リファレンスの絶対条件に従い今回の実装に含めた
- 設計文書の LAN 宛て通信扱いは未決定だが、実装リファレンス D4 に従い許可のままとした

## 既知の制限

- pf の実適用は host の `/etc/pf.conf` と `/etc/pf.anchors/sunaba` を変更するため、検証は `sudo ./bin/sunaba firewall ...` 経由でのみ行う
- apple/container のディスク上限は本環境の `run --help` で未確認のため、ランタイム既定に従う
- apple/container の `build.rosetta` が true で Rosetta 2 が未インストールの環境では `sunaba update` と `sunaba up` の初回イメージビルドは失敗する。Rosetta を使わない場合は `~/.config/container/config.toml` に `[build] rosetta = false` を設定し、container system を再起動する
- `opencode run` を使う自動承認検証は、有効な opencode 認証情報とモデル設定に依存する
- virtiofs の性質により、ホスト側編集イベントがコンテナ内ファイルウォッチャーへ常に即時伝播することは保証しない
