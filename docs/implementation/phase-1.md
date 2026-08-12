# Phase 1: 最小vertical slice

状態: **完了**。内部vertical sliceとして実装・実機検証済み。host applyを持たないためMVP完成ではなく、一般利用へは公開しない。

## Supervisor session lifecycle

`internal/session`がcanonical Projectに対する一つのsecure sessionを所有する。

- canonical Project lockを最初に取得し、VM削除まで保持する。稼働VMが残る状態で`Close`だけを呼んでもlockを解放しない。
- Unix socket path長に依存しない短いOS temp上のmode `0700` runtime baseへ、一意な`sunaba-session-*` rootを作る。永続stateとlockはStore側に分離する。
- host Projectをfd-relative/no-followで固定Snapshotへcopyし、worktreeをVMへbind mountしない。
- 固定image、CPU/memory、`--network none --no-dns`、`SYS_ADMIN`だけのbootstrap、専用Model Gateway/attach socket、policy digest/ownership labelをsecure spec validatorで強制する。inline env、env file、host directory mount、追加capability、任意bootstrapはcontainer CLI前に拒否する。
- guestへSnapshot、固定provider config、guest relay、短命password/tokenだけをcopyする。upstream credentialとhost Project pathは渡さない。
- Snapshotをlower、Project/session専用upper/workを使うOverlayFSとして`/workspace/sunaba-*`へmountする。
- guest-local bare repositoryを`/var/lib/sunaba/repository`へ作り、merged workspaceをsynthetic baseline commitにする。server childへ`GIT_DIR`/`GIT_WORK_TREE`を渡すため、`.git`はChange Setへ混入しない。
- OpenCode serverをguest loopback、Basic認証、mDNS/update/model fetch/LSP download無効で起動する。Model Gatewayはguest loopback TCPから専用Unix socketへ、attachはguest Unix socketからserver loopbackへrelayする。
- host Local Attach Relay経由の`/global/health`が固定OpenCode 1.18.16と完全一致した場合だけreadyにする。
- snapshot、VM、Gateway、relay、ready、Change Set、destroyのmetadata eventを必須host audit sinkへ渡す。secretやProject本文はevent detailへ入れない。

開始途中で失敗した場合は、sessionが作成したVMだけをownership labelで確認して削除し、短命channel、secret file、Project lock、一意なruntime rootを片付ける。

## Freeze、成果物、失効、再生成

session終了はLocal Attach RelayとModel Gatewayを先に閉じ、VMを停止して停止状態を再確認してから、新規mode `0700` quarantineへexportする。safe parserでtrusted lowerを再検証し、Merged Viewと決定的Change Setを生成する。host baseline digestが開始時から変化していれば成果物を成功扱いしない。

VM削除は`dev.sunaba.owner`、Project ID、session IDの完全一致をinspectしてから行う。短命Gateway serverとattach endpointは停止後に到達不能となり、同じhost baselineから作る次のVMに未承認upperは再利用されない。

Model Gatewayは期限、request回数、並行数、request/response size、Project policy由来のmodel allowlistを強制し、期限切れ、別token、許可外model、quota超過、過大bodyをupstream到達前に拒否する。既定値は1,000回、同時4回、request 32 MiB、response 64 MiBで、policy validationが過大な上限を拒否する。CPU/memoryはApple Container、server childのprocess/file上限はguest bootstrapで設定する。

## 実機証跡

2026-08-11にApple Container 1.2.2、`sunaba-base:1.18.16-secure.1`、OpenCode 1.18.16で次を一続きに確認した。

- 固定Snapshotからsecure VMを生成し、一般networkなしでOpenCodeが専用Model GatewayだけへResponses requestを送った。
- v1.18.16が実際に送るtoolなし補助requestと`apply_patch` function tool contractをmock Responses upstreamが返し、OpenCode自身がmerged workspaceへ`model-edit.txt`を作成した。
- OpenCodeが`function_call_output`を二回目のmodel requestへ返し、最終streaming responseをsession APIへ返した。
- upstream credentialをguestの`/run/sunaba`、workspace、sunaba rootfs領域から検索しても存在しなかった。
- model toolによるaddと、modify/deleteを含むhost再現可能なChange Setを停止exportから生成した。実行中も終了後もhost Project digestは変化しなかった。
- channel停止後は以前のBasic secretを持つclientでもattach endpointへ接続できなかった。
- VMをownership確認後に削除し、同じhost baselineから別identityのclean VMを生成した。未承認add/modify/deleteは存在しなかった。
- 2台のprobe VMを両方削除し、検証前から存在したresourceへ変更を加えなかった。

実provider credentialをCIへ置かないため、上流はResponses互換mockを使用した。実APIと同じfunction call/stream eventを使い、host側credential注入、OpenCode provider互換、tool round tripを検証対象とした。

## Host Secret Storeとlive opt-in gate

実OpenAI API keyは環境変数から取得せず、macOS login Keychainの固定generic password（service `dev.sunaba.openai`、account `openai-api-key`）だけを使う。固定`/usr/bin/security login-keychain`のquoted absolute pathを検証し、find/add/deleteへ同じpathを明示する。登録時はKeychain promptを使い、secretをargvへ置かない。unit testと公開CLI実機gateはcommand pathをlink-time fakeへ差し替え、実Keychainを変更せずに固定引数、output bound、control文字拒否、環境変数非依存を検証した。

実providerへの従量課金requestは通常gateで送らない。利用者が`SUNABA_LIVE_OPENAI=1`を明示した場合だけ、実Keychain credentialをHost Model Gatewayで終端し、secure Agent VMからResponses requestを送るgateを提供する。2026-08-11の本変更検証では課金許可を独立に得ていないため、このlive gate自体は未実行である。

```sh
SUNABA_LIVE_OPENAI=1 \
go test -tags=integration ./test/integration -run '^TestLiveOpenAIThroughAgentVM$' -count=1 -v
```

再現コマンド:

```sh
SUNABA_PHASE1_INTEGRATION=1 \
go test -tags=integration -run TestPhase1SecureSessionVerticalSlice -v ./test/integration
```

unit/race test:

```sh
go test -race ./internal/session ./internal/modelgateway ./internal/runtime ./internal/workspace
```

Phase 2でcrash-safe host apply、Trusted Approval UI、複数session/recovery、orphan cleanupを完成させるまで、生成したChange Setをhost worktreeへ適用しない。
