# Phase 0: 契約固定と技術probe

状態: **完了**。DG-01、DG-02、DG-03とProject lockのprobeを通過した。

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
| zipから展開したhost `opencode` executable | `a41776bf64c75786d6baf531b840ffb873c090d7c44793ae2dd4b1896de56a1f` |
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

状態: **通過**。2026-08-11に固定版Apple Container 1.2.2で再現した。

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
- 別Project用host Unix socketはguestへmountされず、guest内に対応pathが存在せず到達不能
- secure session validatorは固定image/resource、`--network none`単独、`--no-dns`、Project/session専用のmode `0600` Gateway socketとattach socket、host policy digest labelを一致させる。不足、追加network、host directory mount、別Project socket、env file、mode/digest改変はcontainer CLIを呼ぶ前に拒否
- 採用経路はApple Container CLI 1.2.2の公開機能だけで成立し、pf、default network、既存container、host設定を変更しない

再現コマンド:

```sh
SUNABA_PHASE0_INTEGRATION=1 \
go test -tags=integration -run TestPhase0SecureNetworkAndGatewayTransport -v ./test/integration
```

この結果はGateway専用経路、public/host/LAN/private/link-local/other VMの同時遮断、既存host設定への非干渉、CLI経路の安定利用を満たすため、DG-01を通過とする。devモードのactive session限定egress leaseはsecure networkのDecision Gateとは分け、該当Phaseのsession lifecycleで実装・検証する。

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

## DG-03 OpenCode + Local Attach Relay + Model Gateway

状態: **通過**。2026-08-11にhost/guestとも固定したOpenCode 1.18.16と`sunaba-base:1.18.16-secure.1`で再現した。

host側OpenCodeは公式`opencode-darwin-arm64.zip`をgitignore済みの`bin/tools/opencode/v1.18.16/`へ取得し、archiveと展開後executableのSHA-256をdependency contractへ固定した。Host TUI起動処理はmanaged directory内のregular executable、実行時digest、`opencode --version`の完全一致を検証する。session専用mode `0700`領域へcwd、HOME、XDG、OpenCode config/data/state/cacheを分離し、host環境はterminal等のallowlistだけを引き継ぐ。`--pure`とProject/default plugin/update/model/LSP download無効化を強制し、API key、proxy、host Project設定を渡さない。guest workspaceはhostに存在しない`/workspace/sunaba-*`だけを受け付け、外部editorは`/usr/bin/false`へ固定する。

Local Attach Relayは次を強制する。

- `127.0.0.1`のrandom portだけでlistenし、固定されたProject/session Unix socketだけへ接続する。
- session固有のhigh-entropy passwordによるBasic認証、HTTP method/path allowlist、同時接続上限を適用し、OpenCodeの`/tui`、認証、instance、log、doc管理面をguestへ到達させない。
- JSONとSSEに含まれるESC、OSC構成文字、BEL、C0/C1制御文字、双方向制御文字、不正UTF-8を可視表現へ変換する。
- `tui.command.execute`は安全側の最小command allowlistとし、`editor.open`等のhost作用を持つeventをTUIへ渡さない。

Model GatewayはProject、VM、session、固定model、期限へ束縛した短命tokenをhashで保持し、guestへはloopback `/v1/responses`のbase URL、短命token、固定provider/model設定だけを渡す。upstream URLと実API keyはhost側Gatewayだけが持ち、redirectと環境proxyを使わない。request回数、並行数、request/response sizeを制限し、本文やcredentialを含めないmetadataを監査callbackへ渡す。Responsesのstream、tool event、upstream error、downstream cancelを保持するunit/race testを通した。

実Apple Container probeでは次を確認した。

- guestのOpenCode 1.18.16をloopback、Basic認証、mDNS無効、auto update/models fetch/LSP download無効で起動した。
- `/global/health`のguest versionが固定versionと一致し、認証なしのhealth requestを拒否した。
- 公式macOS artifactのHost TUI 1.18.16がHTTP-aware Local Attach Relay経由で実際に`attach`し、event streamを開始した。
- guest OpenCode sessionが`@ai-sdk/openai` custom providerから固定Model GatewayへResponses requestを送り、host側mock upstreamのstreaming応答を受け取った。upstreamにはhost側実credentialだけが届いた。
- guestがOpenCode APIから`editor.open` eventを発生させてもrelayが拒否し、Host TUIは外部editorを起動せず継続した。
- probe終了後にLocal Attach Relay、Host TUI、guest server、短命capabilityを終了し、所有labelとrun IDを確認したprobe containerだけを削除した。

再現コマンド:

```sh
SUNABA_PHASE0_INTEGRATION=1 \
go test -tags=integration -run TestPhase0SecureNetworkAndGatewayTransport -v ./test/integration
```

attack/unit testは認証なし、管理path、許可外model、別token、並行数超過、悪意あるSSE TUI command、ANSI/OSC/BEL、双方向文字、不正UTF-8、悪意あるdiff/file名を拒否または無害化する。これによりDG-03の固定artifact、serve/attach/health契約、Host TUI分離、terminal境界、Responses subset、stream/tool/error/cancel、短命token、provider/model固定を満たす。

## Project lock probe

状態: **通過**。canonical Project rootからProject IDを導出し、sunaba state内のmode `0700`専用directoryにmode `0600`のlock fileを置く。lock fileは`O_NOFOLLOW`で開き、current user所有のregular fileだけを受け付け、non-blockingなkernel `flock`をdescriptorの生存期間だけ保持する。

unit/race testは次を確認した。

- 同じProjectを直接pathとsymlink aliasから取得しても同じcanonical identityとなり、二つ目を`ErrProjectLocked`で拒否する。
- lock fileを外部fileへのsymlinkへ置換しても追跡せず、外部fileを変更しない。
- holder processを強制終了してもkernelがlockを解放し、次のprocessが取得できる。staleなPID recordをlock保持判定には使わない。
- 明示`Close`後に再取得でき、lock metadataにcanonical Project、Project ID、PID、取得時刻を残す。

再現コマンド:

```sh
go test -race -v ./internal/state
```

以上によりPhase 0の全probeを完了し、Phase 1のvertical sliceへ進める。
