# Phase 0: 契約固定と技術probe

状態: 実施中。DG-01〜DG-03は未通過。

## Dependency contract

- Apple Container: exact `1.2.2`, commit `0190097d06df0b9065f4c2d2c7873c649d81d493`
- OpenCode host TUI / guest server: exact `1.18.16`
- 機械可読な正本: `internal/dependency/manifest.json`
- `latest`取得と任意versionのimage buildを拒否する。
- guest artifactはimage build時、展開前にSHA-256を検証する。
- base imageはOCI index digest `sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df`へ固定する。
- Phase 0 secure build tagは`sunaba-base:1.18.16-secure.1`。2026-08-11の最終probe buildで得たOCI index digestは`sha256:d32a78aaead9ac1fee1c11137b45a8652714fa7efee3bd93b5d194f239438095`。

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

## DG-01 secure network probe

採用候補は、secure VMをApple Container `--network none --no-dns`で作成し、Project/VMごとのhost Unix socketだけをApple Container 1.2.2のvsock socket relayでguestへ渡す方式とする。固定版sourceの次の実装を確認した。

- `Sources/Services/ContainerAPIService/Client/Utility.swift`: network名`none`をnetwork attachmentなしへ変換
- `Sources/Services/RuntimeLinux/Server/RuntimeService.swift`: host Unix socket mountを`UnixSocketConfiguration(direction: .into)`へ変換
- tag `1.2.2`, commit `0190097d06df0b9065f4c2d2c7873c649d81d493`

2026-08-11に`test/integration/phase0_network_test.go`を実行し、次を実測した。

- guestのupなinterfaceはloopbackだけ
- public IPv4/IPv6 TCP、UDP、external DNS、raw ICMPを拒否
- host default gateway、private、link-local/metadata相当、既存の別VM宛てを拒否
- 専用host Unix socket上のmock Model Gatewayだけに到達
- guest loopbackだけでlistenするOpenCode 1.18.16をreverse Unix socket relay経由でhostからhealth確認
- OpenCode healthはBasic認証なしでは拒否
- probe containerは`dev.sunaba.owner`と一意run IDをinspectしてから停止・削除し、一覧から消えたことを確認

再現コマンド:

```sh
SUNABA_PHASE0_INTEGRATION=1 \
go test -tags=integration -run TestPhase0SecureNetworkAndGatewayTransport -v ./test/integration
```

この結果はDG-01のsecure egress、guest-to-host Gateway transport、host-to-guest reverse attach transportの中核証拠である。DG-01通過には、別Project socket非共有、構成検証失敗時のsession fail-closed、dev session egress leaseも追加で実測する。

## 未解決のDecision Gate

- DG-01: Project間socket分離、fail-closed、dev egress leaseの実測
- DG-02: immutable lower、freeze、merged semantics、safe exportの実測
- DG-03: pinned host artifact、serve/attach、isolated config、terminal境界、Responses contractの実測

これらが再現可能なintegration/attack testで成功するまでPhase 1へ進まない。
