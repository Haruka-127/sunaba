# Phase 5: hardeningと運用

状態: 完了。fuzz/property、dependency更新契約、policy migration、audit retention/redaction、disk pressure、host reboot、Git partial failure、supply-chain provenanceを自動testへ固定し、dev pf実機gateまで通過した。

## Fuzz / property

対象:

- Model Gateway Responses envelope: malformed JSON、model substitution、size境界
- Git Gateway push binding: object/ref/force/deleteのcanonicalityとdigest束縛
- Web Gateway hostname: ASCII正規化、IP literal、label/port境界
- Web blocklist hosts parser: record形式、domain数、重複、invalid hostname

再現コマンド:

```sh
go test ./internal/modelgateway -run '^$' -fuzz FuzzResponsesEnvelope -fuzztime 10s
go test ./internal/gitgateway -run '^$' -fuzz FuzzCanonicalPushBinding -fuzztime 10s
go test ./internal/webgateway -run '^$' -fuzz FuzzNormalizeHostname -fuzztime 10s
go test ./internal/webgateway -run '^$' -fuzz FuzzHostsBlocklistParser -fuzztime 10s
```

2026-08-11の最終実行ではそれぞれ72,877、594,323、546,627、776,192 inputを処理し、crashまたは不変条件違反はなかった。corpus本文はcommitせずseedだけをtestに保持する。

## Dependency / supply chain

dependency manifest schema v2は次を固定する。

- Apple Container `1.2.2`のrepository、tag、commit
- OpenCode `v1.18.16`のrepository、tag、commit、host/guest artifact SHA-256
- base OCI index digest
- embedded `Containerfile` / `entrypoint.sh`のSHA-256

image buildはembedded bytesをmanifestへ再照合してから実行する。version更新candidateはexact versionが変わり、artifact digest、runtime version、lifecycle、network isolation、copy/export、resource limitの全証拠が揃わなければ拒否する。`latest`と部分的な更新証拠はtestで拒否する。

現行固定版の再検証にはPhase 0〜4の実機gateを再実行する。新versionへ更新するときは、先にmanifest/source pinをreviewし、同じgateの結果を新しいimplementation recordへ記録する。自動updateは行わない。

## Project policy migration

Project policy schema v5はProject identity/root、mode、dependency、resource、session、Model/Git/Web、export、audit retention、Protected Pathを一つのdigest可能な文書へ統合し、Git remoteを名前と固定URLの組として保持する。v4でModel Gatewayの既定quotaとtransport sizeを長時間のagent session向けに更新し、v5でModel Gatewayの`api_key`/`oauth`認証方式を追加した。

- JSON unknown field、trailing data、unsupported schemaを拒否
- canonical rootとProject IDの差し替えを拒否
- mode `0600` current-user regular fileとmode `0700` canonical parentだけを受理
- v1/v2/v3/v4からv5へのmigrationをprivate temporary file + fsync + atomic renameで行う。v2のGit URL配列はnamed remoteへ変換し、v3のModel Gateway値は旧既定値と完全一致する場合だけ新既定値へ更新し、既存policyの認証方式は`api_key`とする
- legacy Web originがあるpolicyは、blocklist snapshot/digestを推測せずmigrationを拒否

## Host-only Project configuration

Projectの利用者設定を内部stateから分離し、`${XDG_CONFIG_HOME:-$HOME/.config}/sunaba/projects/<ProjectID>/project.json`を起動設定、同directoryの`web-origins.txt`をWeb allowlistの正本とした。両fileはcurrent user所有のmode `0600`、directoryはmode `0700`とし、symlink、未知JSON field、trailing data、oversize、不正originを拒否する。Project worktreeとVMには設定directoryを公開しない。

- `config path|validate|diff|apply|show`でpath確認、厳格検証、実効policyとの差分、停止状態でのcompile、declarative/effective表示を行う
- dependency、blocklist binding、push承認必須、Protected Path、runtime identity、credential/capabilityはdeclarative設定から除外し、host側で生成する
- 未適用設定がある場合は`up`、`agent`、`shell`、Supervisor起動を拒否する一方、`status`、`down`、export、recreate、destroyは復旧経路として維持する
- `web-origins.txt`は64 KiB/1024 ruleを上限とし、HTTP(S) root originと任意の`include-subdomains`だけを行単位で受理する
- Model/Git/Webの既存設定CLIはhost設定と実効policyを同時更新し、一方だけが古くなる経路を残さない

## Audit retention / redaction

auditはmetadata-onlyのhost JSONLであり、sensitive key名、credentialに似た値、URL userinfo、Bearer/Basic、API key形式を拒否またはredactする。保持期間は1〜365日に制限し、exactな`audit-YYYYMMDD.jsonl`だけを対象にmode、owner、symlinkを再検証して削除する。directory fsync前の失敗を成功扱いしない。

## Fault injection

自動testは次を固定する。

- session guest setupの`ENOSPC`: 作成済みVMをownership再検証後に削除し、lease/Project lockを解放
- transactional applyの`ENOSPC`: host baselineをrollbackし、未完了transactionを成功扱いしない
- host reboot相当: durable active leaseは残るがprocess guardがない状態から、exact label/lease一致のVMだけを停止・削除してcapabilityをrevoke
- Git partial failure: upstream push成功後にlocal receive ref更新が失敗してもupstream成功auditを正とし、次のadvertisement前`Sync`で収束

再現コマンド:

```sh
go test -race ./internal/session ./internal/apply ./internal/cleanup ./internal/gitgateway
```

## dev session direct-egress boundary

final integration用にProject/session専用Apple Container networkを追加した。default networkを共有せず、owner/project/session/mode labelとinspect結果を毎回照合する。source IPv4/IPv6 subnetへ束縛したpf anchorはDNS/DHCPとpublic egressのstateだけを許可し、host/self、RFC1918、CGNAT、link-local、metadata相当、documentation/benchmark、multicast、別VM private subnet、unsolicited inboundを拒否する。

同時dev sessionはcurrent-user所有のmode `0600` flockで1つへ制限する。開始・再開前にnetworkを再inspectしてpfを再検証する。export前は、既存のexact source subnet用child anchorをdeny-allへ原子的にquiesceしてloaded main/child rulesを再検証してからVMを停止する。quiesce失敗時はGatewayをinactiveにしVM停止を試み、exportは拒否する。destroy時はVM削除後にanchorとnetworkを失効する。secure sessionは引き続き`network none`でありpfへ依存しない。

再現コマンド:

```sh
SUNABA_DEV_INTEGRATION=1 \
go test -tags=integration ./test/integration -run 'TestDevSessionNetworkBoundary$' -count=1 -v
```

このgateはdocumented `sudo ./bin/sunaba firewall enable|quiesce|disable`を使うため、許可文書の変更と当該実行を人間が確認し、対話sudoを承認できるterminalが必要である。public DNS/HTTPS、host listener、別network VM、metadata、host-to-VM inbound、稼働VMのdeny-all quiesce、session stopを一回の隔離testで確認し、作成した完全名のVM/networkだけをcleanupする。2026-08-11に認証済みの人間のterminalから実行し、41.19秒でPASSした。test終了時のfirewall disableまたはVM/network cleanupが失敗した場合もtestをFAILにするため、このPASSは後処理の成功を含む。

## 通常verify

[`scripts/verify.sh`](../../scripts/verify.sh)は旧prototypeのA2〜A21を廃止し、次を正とする。

```sh
scripts/verify.sh
```

- gofmt / `git diff --check`
- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `sunaba`、Linux/AArch64 guest relay、Git hook helperのbuildとguest relay ELF形式検証
- CLI helpと旧unsafe entrypointのstatic boundary

static boundaryは旧`_audit` daemon、永続`server-password`/Project env API、`OPENAI_API_KEY`環境変数、Project bind mount、default network、firewall bypass、guest側automatic approvalがproduction codeへ戻ることも拒否する。旧prototypeのstate/audit API自体を削除し、global image stateはowner-only mode `0600` regular fileとしてno-followで読み、同一private directory内のfsync済みtempから原子的に置換する。

container mutation、pf、optional fuzz、live credentialは通常gateで暗黙に実行しない。

## Security review / residual risk

レビューで明示的に残すもの:

- dev active session中は任意の直接情報流出を防がない
- TLS非終端Web CONNECT内部のmethod/path/uploadは識別しない
- allowlistされたHTTPS origin自体の侵害、content supply chain、LLM生成成果物のhost側実行
- Apple Container、guest kernel、OpenCode、Gateway/relay/parserの未知の脆弱性
- Git upstream成功後のlocal ref更新失敗はatomicにできず、auditと次回syncで収束する
- credential/providerがない環境ではbillable live testを実行せずmock upstream contractを正とする

これらを保証済み事項として表現せず、secure/devの警告、policy、README、正本文書へ一致させる。
