# Phase 0: 契約固定と技術probe

状態: 実施中。DG-02は通過。DG-01とDG-03は未通過。

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

## DG-02 Snapshot + OverlayFS + export

状態: **通過**。2026-08-11に固定版Apple Container 1.2.2と`sunaba-base:1.18.16-secure.1`で再現した。

host Projectから固定Snapshotを作る処理は次の性質を持つ。

- canonical Project rootをdirectory descriptorで開き、`openat` / `fstatat` / `O_NOFOLLOW`で相対walkする。
- symlinkはtarget文字列だけを記録し、Project root内外を問わずリンク先を読まない。
- `.git`と`.sunaba`をcase-insensitiveなProtected PathとしてSnapshot対象外にする。
- socket、FIFO、device等の特殊file、depth、entry数、個別size、総size超過を拒否する。
- path、type、mode、size、content SHA-256、symlink targetを整列したcanonical manifestからdigestを作る。macOS/Linuxで意味が一致しないsymlinkのmodeは`0777`へ正規化する。
- 新規Snapshot directoryへfd-relative/no-followでcopyし、copy後のmanifest digestがsourceと一致しなければ失敗して、そのtransactionが作成したdestinationだけを削除する。
- xattrとhost hardlink関係はSnapshotへ継承しない。

unit testは外部symlink targetの内容変更がdigestへ影響しないこと、Protected Path除外、特殊fileと上限の拒否、host編集から独立した固定copy、既存またはProject内destinationの拒否を検証する。

実Apple Container probeでは次を確認した。

- Project Snapshotをhost bind mountせずguest rootfsへcopyし、Projectの`.git`と外部symlink先の内容をguestへcopyしない。
- Snapshotをlower、Project専用のupper/workを使うOverlayFSでadd、modify、delete、rename、symlink、opaque directoryを作る。host Projectのmanifestは変化しない。
- guest協調ではなくApple Containerの停止をfreeze境界とし、停止状態を再確認してからmode `0700`の一意な`sunaba-*` quarantineへ`container export`する。
- Apple Container 1.2.2のexportはOCI layoutではなくflat rootfs tarである。通常directoryの末尾`/`、whiteoutのwork/index hardlink表現、opaque/redirect/metacopyの`trusted.overlay.*` PAX keyを実測した。
- safe parserは通常のarchive extractorを使わずentry streamを検証する。絶対/非正規/重複/Protected Path、未知xattr、任意hardlink、特殊file、size/entry上限を拒否し、lower全体のcanonical digestをhost baselineと照合する。PAXのbinary valueは記録・表示せず、許可したkeyの必要な値だけを解釈する。
- renameの`metacopy` upper本文は実測上NUL bytesであり、内容として信頼しない。redirect元のtrusted lower entryについて型、size、SHA-256が一致する場合だけlower内容を参照する。
- 検証済みlower/upperからhost側でMerged Viewを新規quarantine directoryへno-follow materializeし、同じexportから2回生成したmanifest digestが一致する。
- baselineとMerged Viewだけからadd/modify/delete/rename/symlink/opaque directoryを含むChange Setを生成し、同じ入力のChange Set digestが一致する。
- guest rootでlowerを直接書き換えた二度目の停止exportはbaseline digest不一致として拒否する。

再現コマンド:

```sh
SUNABA_PHASE0_INTEGRATION=1 \
go test -tags=integration -run TestPhase0OverlayFreezeAndExportLayout -v ./test/integration
```

attack/unit testはpath traversal、Protected Pathとredirect、任意hardlink、FIFO、未知xattr、重複path、lower改変、fabricated staging path、非canonical tar directory名、曖昧なrename推測を拒否する。これによりDG-02のlower改変検知、Project専用upper/work、rename/delete/whiteout/symlink/opaque、host-enforced freeze、停止後Merged View再現、再現可能なChange Setを満たす。

## 未解決のDecision Gate

- DG-01: Project間socket分離、fail-closed、dev egress leaseの実測
- DG-03: pinned host artifact、serve/attach、isolated config、terminal境界、Responses contractの実測

これらが再現可能なintegration/attack testで成功するまでPhase 1へ進まない。
