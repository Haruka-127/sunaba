# Phase 4: Web Gateway

状態: 方式決定済み、実装中。実Agent VMの通信計測を完了し、正本14章へProject専用forward proxy方式と保証範囲を固定した。

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

- strict proxy parser、capability、origin policy、quota、audit
- host DNS/IP validationとdial pinning
- HTTP GET/HEAD、redirect origin再検証
- HTTPS CONNECT tunnel、byte/time/concurrency上限
- private/link-local/metadata/host/LAN/他VM、IP literal、非許可port、upload attack
- secure session socket、proxy env、NO_PROXY、pause/resume/end
- 実OpenCode webfetch/websearch、curl/wget/apt gate
- blocklist manifest、expiry、fail-closed更新

これらを完了するまでPhase 4を完了扱いにしない。
