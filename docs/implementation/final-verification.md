# 最終検証台帳

この台帳はPhase単位の完了記録とは別に、最終終了条件を現在のcode、test、実機resourceへ照合する。`PASS`は記載した再現手順が当該境界を直接検証した場合だけ使う。過去の実機gateは証拠として保持するが、現在mainで再実行していない場合は`LIVE RECHECK`と明記し、unit testやintegration build-tagのコンパイルだけを実機通過と扱わない。

現在の基準は2026-08-30の`feat/opentui-ux`実装である。通常gate、全race、integration build-tagのコンパイル、OpenTUI standalone buildを再実行した。Apple Containerを起動する実機gate、実OpenAI request、clean-room、bounded fuzzは再実行していない。直前のmain基準は2026-08-20のmerge commit `f83bc7b1e4cc16de488b0f082b24f66fa2d5d0af`であり、その過去証拠は以下に保持する。

## 要件と証拠

| 最終要件 | 実装・再現可能な証拠 | 現在の判定 |
| --- | --- | --- |
| Phase 0〜5成果物 | [`phase-0.md`](./phase-0.md)〜[`phase-5.md`](./phase-5.md)、各`internal/*` unit/race test | AUTO PASS。current mainで通常gateと全raceを再実行済み。LIVE RECHECK |
| DG-01 secure network | `TestPhase0SecureNetworkAndGatewayTransport`、`runtime.ValidateSecureSessionSpec` attack test | LIVE PASSは2026-08-11の当時HEAD。current mainはunit/raceとintegration compileのみ。LIVE RECHECK |
| DG-02 Snapshot / Overlay / export | `TestPhase0OverlayFreezeAndExportLayout`、`internal/workspace` attack test | LIVE PASSは2026-08-11の当時HEAD。current mainのSnapshot preview/除外、recovery変更はunit/raceのみ。LIVE RECHECK |
| DG-03 OpenCode / Model / Attach / terminal | Phase 0/1 integration、[`phase-5.md`](./phase-5.md)のv1.18.18更新gate、`internal/modelgateway`、`internal/attachrelay`、`internal/opencode`、`internal/trustedui` | 固定v1.18.18の更新gateは2026-08-13にPASS。current mainのHost TUI session root修正はunit/raceのみ。LIVE RECHECK |
| Phase 2 lifecycle / apply / approval | Phase 1/2 integration、`internal/session`、`internal/apply`、`internal/approval`、`internal/lease`、`internal/cleanup` | 過去の実機gateはPASS。current mainのVM/Session分離、pause timer、frozen recoveryはunit/raceのみ。LIVE RECHECK |
| 永続Project VM / shell / TTL / idle | `TestPublicCLIPersistentSupervisorAndSanitizedShell`、supervisor control unit/race test | current mainのunit/raceとdeadline反復testはPASS。公開CLI実機gateは変更前の証拠。LIVE RECHECK |
| Git Gateway | `TestPhase3GitGatewayInAgentVM`、`internal/gitgateway` smart HTTP/TOCTOU/partial-failure/fuzz test | 2026-08-11の実VMgateはPASS。current mainの番号/ID承認とExternal Git guardはunit/raceのみ。LIVE RECHECK |
| Web Gateway | Phase 4 measurement/integration、`internal/webgateway` attack/compatibility/fuzz test | 過去の実VMattack/compatibility gateはPASS。current mainでは再実行していない。LIVE RECHECK |
| Phase 5 hardening | dependency/provenance、migration、retention/redaction、ENOSPC/reboot/partial failure、4 bounded fuzz target | current mainの通常gateはPASS。clean-roomと4 bounded fuzz targetは再実行していない |
| TUI利用性 Checkpoint 1〜10 | [`tui-usability.md`](./tui-usability.md)、`internal/tui`、`internal/cli/tui_coordinator_test.go`、`internal/secretstore`、`internal/usersettings`、`ui/test` | AUTO PASS。protocol v2の構造化Changes表示を含む通常gate、全race、UI build、integration compileを2026-08-30に再実行。LIVE RECHECK |
| dev active-session egress | `TestDevSessionNetworkBoundary`がactive public egress、host/LAN/peer/inbound拒否、稼働VMのdeny-all quiesce、stopを検査 | 2026-08-11の実機gateはPASS。current mainのdev recovery変更後は再実行していない。LIVE RECHECK |
| 最終cleanup / user resource非干渉 | exact nameとowner/project/VM labelを再検証するcleanup、最終`container ls` / network / volume / process / temp inventory | 2026-08-11の実機作業後はPASS。current mainではcontainerを起動しておらず、新しい実機inventoryは未実施 |
| Git運用 | topic branch上の意図別Conventional Commit、`git status` | `feat/opentui-ux`で作業し、pushは行わない。2026-08-20以前のmain統合履歴は保持 |

## 最新の自動gate

```sh
./scripts/verify.sh
./scripts/verify-race.sh
go test -tags=integration -run '^$' ./test/integration
./scripts/build-ui.sh
```

2026-08-30の`feat/opentui-ux`で上記4 commandを再実行しPASSした。UI gateはOpenTUI helper test 15件、TypeScript typecheck、standalone build、固定SHA-256 `2a1670a64c2883458128fb85e9d9d26e77b16f29417205630c49c0ead8adc8a2`、Mach-O/owner/mode/architectureを検証した。通常gateは全unit、vet、host/guest build、CLI/help、Keychain禁止を含むstatic boundaryを検証した。全raceとintegration build-tagのcompile-onlyもPASSした。Apple Container、実credential、sudo、pfを使う実機操作は実行していない。

2026-08-20の当時mainで先頭3 commandを実行し、通常gate、全race、integration build-tagのコンパイルがPASSした。通常gateはformat、全unit、vet、host binary、Linux/AArch64 guest relay、Git hook、CLI/static unsafe-path boundaryを検証する。`go test -tags=integration -run '^$'`はcompile-onlyであり、Apple Container VMを起動しない。

`./scripts/verify-clean.sh`と`SUNABA_FUZZ=1 ./scripts/verify.sh`は以前のPhase 5 gateでPASSしているが、current mainでは再実行していない。実OpenAI credentialを使うbillable live requestも自動実行せず、mock upstream contractを正とする。

2026-08-12のModel Gateway認証拡張では、同じ通常gateを再実行してPASSした。追加したmock contractはAPI key/OAuth別model catalog、custom `sunaba` provider設定、schema v4からv5へのmigration、OAuth device flow/PKCE、期限前refreshとtoken rotation、固定Keychain identity、Codex endpoint/header/request差分を含む。実ChatGPT accountへのdevice loginとsubscription requestは外部認証を伴うため自動実行していない。

2026-08-12のWeb origin preset追加では、同じ通常gateを再実行してPASSした。指定Projectのsource SHA-256 `986b65106d38478b8fae51a8822110a794587c89b408059de6420e7bd25dc763`、190 rule、HTTP 2 rule、subdomain 8 ruleを組み込み`common-development` presetとして固定し、Project設定schema v1からv2の読込、policy v5からv6の非拡張migration、preset単独・不使用・Project固有追加・重複除去・digest差分をunit/race/vet/build/static gateで検証した。preset更新の実Internet互換性と実Agent VM通信は外部状態を伴うため通常gateでは再実行していない。

2026-08-12のhost対話設定追加でも通常gateを再実行してPASSした。`config edit`のcancel/EOF/input上限、dev警告、固定Model catalog選択、検出Git remoteの明示選択、Git Gateway remote構成、宣言設定と実効policyの同期適用をunit/CLI testで固定した。fuzzとApple Container実機integrationはこの変更では再実行していない。

2026-08-13の共通Project ID selector追加でも通常gateを再実行してPASSした。すべての公開Project操作で`--project-id`の完全一致、`--dir`との排他、重複指定を共通化し、通常操作ではread-only policy、Project ID、現存するcanonical Project rootを検証する。復旧操作の`down`と`destroy`では、unsafe/symlink stateとSupervisor ID不一致を拒否し、元Project directoryとpolicy・host設定がないsafeな`unknown` stateを扱う経路をunit/race/CLI/static gateで検証した。公開CLI integrationは`up`、`status`、`shell`、`changes export`をID指定で実行し、元Project directoryを除去してからID指定でdestroyする経路へ更新してintegration tagでcompileした。Apple Container実機integrationとfuzzはこの変更では再実行していない。

2026-08-13のChange Set review追加でも通常gateと`internal/workspace`、`internal/trustedui`、`internal/cli`のrace testを再実行してPASSした。pending schema v3のbaseline/Merged View自己完結保存、旧schema v2互換、manifest/digestとfd-relative content再検証、bounded text diff、binary/巨大fileの未表示警告、実行属性・symlink risk、ANSI/OSC/BEL/bidi sanitize、exact path filter、apply前の同一digest再reviewをunit testへ固定した。公開CLI実機gateには`changes review`を追加したが、Apple Container実機integrationはこの変更では再実行していない。

2026-08-20の利用性hardeningでは、Snapshot preview/除外、VM/Session identity分離、Sessionごとの資格情報再発行、設定反映の三分類、doctor/status/argv exec、番号/IDによるGit push承認、External Git guard、secure/dev frozen recovery、Host TUI session root分離、pause中timer停止をmainへ統合した。`./scripts/verify.sh`、`./scripts/verify-race.sh`、integration compileがPASSし、Supervisor deadline回帰testは通常100反復、race付き10反復でもPASSした。Apple Container実機gateはこの統合後に実行していない。

## 最新の実機gate（current mainより前）

一式を最後に直接実行したのは2026-08-11の当時HEADである。OpenCode v1.18.18への更新固有gateは2026-08-13に実行しており、詳細は[`phase-5.md`](./phase-5.md)に記録する。current mainでは以下を再実行していない。

```sh
SUNABA_INTEGRATION=1 scripts/verify.sh
SUNABA_PHASE3_INTEGRATION=1 go test -tags=integration ./test/integration -run '^TestPhase3GitGatewayInAgentVM$' -count=1 -v
SUNABA_PHASE4_INTEGRATION=1 go test -tags=integration ./test/integration -run '^TestPhase4WebGatewayInAgentVM$' -count=1 -v
SUNABA_PHASE4_MEASUREMENT=1 go test -tags=integration ./test/integration -run '^TestPhase4MeasureWebClients$' -count=1 -v
SUNABA_DEV_INTEGRATION=1 go test -tags=integration ./test/integration -run '^TestDevSessionNetworkBoundary$' -count=1 -v
```

一括scriptは通常gate、Phase 0、Phase 1、Phase 2、公開CLIまでPASSした後、Apple Container 1.2.2のguest exec/runtimeがPhase 3 VMで無応答となり中断した。VMはserver healthだけでなく個別`container exec`、通常stop、exact KILL、exact force deleteも応答しなかったため、製品test failureとruntime固着を混同せず、[`allowed-host-operations.md`](../plan/allowed-host-operations.md)の承認済み限定復旧を適用した。clean system直後の同一Phase 3 gateは27秒でPASSし、Phase 4 integrationとmeasurementも続けてPASSした。したがって全実機境界の合成判定はPASSだが、「一括scriptが無中断で完走した」とは記録しない。

dev gateはsudo timestampがterminal単位であり自動実行環境から認証票を利用できなかったため、人間の同一terminalで実行した。public DNS/HTTPS、host listener、別network VM、metadata、host-to-VM inbound、deny-all quiesce、session stop、firewall disable、exact cleanupを含め41.19秒でPASSした。

## 復旧と最終cleanup

固着したVMは完全名、`dev.sunaba.owner`、Project、Session、mode label、Supervisor/runtime/guard不在を毎段再検証し、未exportの利用者成果物がない一時test VMだけを対象にした。2回の独立した復旧cycleで、Apple Container 1.2.2のAPIServerを公式stop後段と同じ`gui/501` domainのexact labelでそれぞれ1回だけbootoutし、直ちにsystem startした（合計2回）。同じcycle内でbootoutを反復せず、他prefix、sudo、runtime/plugin processへの直接signalは使っていない。

復旧前にrunningだったplugin管理`buildkit`は、同じID、image、labels、mount、network設定でrunningへ復元した。system再起動により動的IP/MAC addressは再割当されたため、runtime addressまで不変とは主張しない。最終inventoryではcontainerは`buildkit`だけ、networkはbuiltin `default`だけ、volumeなし、sunaba Supervisor/client processなしである。列挙・由来確認した検証用`/private/tmp/sunaba-*` directory、socket、cacheも削除した。利用者container、network、volume、image、Project成果物、remote repositoryは変更していない。
