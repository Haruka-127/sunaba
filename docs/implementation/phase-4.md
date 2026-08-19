# Phase 4: Web Gateway

状態: 完了。実Agent VMの通信計測、方式決定、Web Gateway実装、secure session統合、attack/compatibility gateを完了した。

## 実通信計測

再現コマンド:

```sh
SUNABA_PHASE4_MEASUREMENT=1 go test -tags=integration ./test/integration -run 'TestPhase4MeasureWebClients$' -count=1 -v
```

計測VMはnetwork `none`を維持し、Project専用socket relayへ記録用proxyを接続する。外部へdialせず、HTTP requestを記録し、HTTPS CONNECTは`502`で停止する。

観測結果:

- curl/wget/OpenCode webfetchはHTTP proxyへGETし、`302`後の別requestでもproxyを使った
- curl HTTP POSTのbodyはproxyから観測できた。HTTPSはCONNECTしか観測できなかった
- aptは`InRelease`、`Release`、`Packages.{xz,bz2,lzma,gz,lz4,zst}`、無圧縮`Packages`をarchitecture `all`/`arm64`ごとにGETした
- OpenCode webfetchは固定Chrome UAでHTTP GETした
- OpenCode websearchはExa選択時に`mcp.exa.ai:443`へCONNECTした
- cold OpenCode processは`registry.npmjs.org:443`へCONNECTを試みた
- exact baseにはaptがあり、npm/pip/go/cargo CLIはない
- proxyからModel Gateway loopbackを除外しないとprovider requestまでproxyへ流れるため、`NO_PROXY=127.0.0.1,localhost`が必要

pinned OpenCodeソースとの照合:

- `webfetch.ts`: `http://`/`https://` URL、GET、format別Accept、5 MiB、30秒default/120秒上限
- `websearch.ts` / `mcp-websearch.ts`: ExaまたはParallelへのJSON-RPC POST、25秒timeout
- upstream source: <https://github.com/anomalyco/opencode/tree/v1.18.16/packages/opencode/src/tool>

## 候補比較

| 方式 | 互換性 | 強制可能範囲 | 採否 |
|---|---|---|---|
| DNS/blocklistだけ | 高い | direct IP、DoH、rebind、uploadを止められない | 不採用 |
| typed fetch APIだけ | read意味論を強くできる | curl/apt/OpenCode built-inの自然なUXを失う | general pathには不採用。将来のstrict originで併用可 |
| TLS MITM forward proxy | 多くのHTTP method/pathを識別可能 | CA注入、pinning破壊、TLS/parser TCBが大きい | MVP不採用 |
| TLS非終端forward proxy | 実測した全clientが利用可能 | origin/IP/quotaは強制、HTTPS内部操作は非保証 | 採用 |

## 実装gate

- 完了: strict proxy parser、Project/VM/Session/policy digest capability、origin policy、request/concurrency/time/upload/download/total quota、内容非保持audit
- 完了: host DNSの全回答検査、public IP判定、検査済みIPへの直接dial。private/link-local/metadata/CGN/documentation/benchmark/multicast/unspecified、mixed answer、IP literalを拒否
- 完了: HTTP GET/HEADだけ、body/upload拒否、client追跡redirectのorigin再検証
- 完了: TLS非終端CONNECT、443固定、byte/time/concurrency上限、client証明書検証維持
- 完了: 3本目のProject socket、guest `127.0.0.1:4343` relay、大小文字proxy環境、loopbackだけの`NO_PROXY`、apt専用config、pause/endでの不可逆失効と次Sessionでの再発行、export前secret除去
- 完了: URLhaus由来の外部maintainer feedをStevenBlack hosts repositoryの固定HTTPS pathからhostが取得する。各snapshotをSHA-256、取得時刻、最大14日の期限へ固定し、redirect、形式逸脱、改ざん、期限切れをfail closedにする
- 完了: 実OpenCode webfetch/websearch、curl、wget、非root apt metadata、証明書検証付きHTTPS CONNECTの実VM gate
- 完了: private/metadata、blocklist、direct IP、HTTP upload、cross-origin redirect、pause、secret export、audit redaction attack gate
- 完了: 指定Projectの190件（source SHA-256 `986b65106d38478b8fae51a8822110a794587c89b408059de6420e7bd25dc763`）を組み込み`common-development` presetへ固定し、preset不使用、Project固有追加、和集合と重複除去、preset digest差分、旧policyの非拡張migrationをunit testで固定

既定blocklist source:

```text
https://raw.githubusercontent.com/StevenBlack/hosts/master/data/URLHaus/hosts
```

source URL自体は固定し、mutable contentは取得時のdigestへ固定する。期限内snapshotだけをpolicy作成に利用する。allowlistとの積集合でのみ効くため、feed単独をsecurity boundaryにしない。

再現コマンド:

```sh
go test -race ./internal/webgateway ./internal/runtime ./internal/session
SUNABA_PHASE4_INTEGRATION=1 go test -tags=integration ./test/integration -run 'TestPhase4WebGatewayInAgentVM$' -count=1 -v
```

実VM gateはAgent VMのnetwork `none`、実OpenCode `v1.18.16`、curl `7.88.1`、wget `1.21.3`、apt `2.6.1`で通過した。exact baseに存在しないnpm/pip/go/cargo CLIは未対応を暗黙に表明せず、追加時に同じ計測とorigin/CDN policy gateを要求する。
