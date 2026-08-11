# Phase 0: 契約固定と技術probe

状態: 実施中。DG-01〜DG-03は未通過。

## Dependency contract

- Apple Container: exact `1.2.2`, commit `0190097d06df0b9065f4c2d2c7873c649d81d493`
- OpenCode host TUI / guest server: exact `1.18.16`
- 機械可読な正本: `internal/dependency/manifest.json`
- `latest`取得と任意versionのimage buildを拒否する。
- guest artifactはimage build時、展開前にSHA-256を検証する。

2026-08-11に公式v1.18.16 release URLからOS tempへ取得して確認した値:

| artifact | SHA-256 |
|---|---|
| `opencode-darwin-arm64.zip` | `1e670c94341a374824dc6700b6f38b2cb6634baf3ca20e645084c33ce6639320` |
| `opencode-linux-arm64.tar.gz` | `4fdce5f9bc877d977304d71c0c90ad6e83efa381fe0edf0a61e6142a625e1c41` |

再現コマンド（`ARTIFACT_DIR`にはOS temp上の新規directoryを指定する）:

```sh
curl --fail --location --output "$ARTIFACT_DIR/opencode-darwin-arm64.zip" \
  https://github.com/anomalyco/opencode/releases/download/v1.18.16/opencode-darwin-arm64.zip
curl --fail --location --output "$ARTIFACT_DIR/opencode-linux-arm64.tar.gz" \
  https://github.com/anomalyco/opencode/releases/download/v1.18.16/opencode-linux-arm64.tar.gz
shasum -a 256 "$ARTIFACT_DIR"/*
```

## Host baseline probe

2026-08-11の開始時点:

- macOS `26.5.1`
- architecture `arm64`
- Apple Container client/server `1.2.2`, system `running`
- hostで検出したOpenCode version `1.18.16`
- `go test ./...` と `go vet ./...` はOS tempの`GOCACHE`を使って成功

これはdependencyとhost前提の確認だけであり、secure network、transport、OverlayFS/export、Host TUI安全性を証明しない。

## 未解決のDecision Gate

- DG-01: Gateway専用transportとsecure/dev network invariantの実測
- DG-02: immutable lower、freeze、merged semantics、safe exportの実測
- DG-03: pinned host artifact、serve/attach、isolated config、terminal境界、Responses contractの実測

これらが再現可能なintegration/attack testで成功するまでPhase 1へ進まない。
