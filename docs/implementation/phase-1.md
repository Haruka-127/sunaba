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

Codex OAuth経路ではCLIProxyAPIのCodex Responses変換に合わせ、subscription backendが受理しない`max_output_tokens`、`max_completion_tokens`、`temperature`、`top_p`を上流転送前に除去する。この変換はOAuth経路だけに適用し、OpenAI API key経路ではResponses APIの同フィールドをそのまま転送する。

## VM内OpenCode権限

Agent VMはuntrusted sandboxであり、OpenCode serverとそのbash/tool subprocessをVM内rootで実行する。sunaba生成のOpenCode v1設定はglobal `permission`を`allow`にし、既定の`external_directory`、`.env`読取、doom-loop等の確認待ちを含めてVM内toolを自動許可する。Phase 1実機gateは固定v1.18.16が解決した`/config`で`permission.*=allow`を確認し、modelの`apply_patch`が追加承認なしで成功することと、OpenCode PIDのUIDが0であることをresource probeで検証する。

この権限はVM内だけに限定する。host Project非mount、secure modeのnetwork-none、Model Gatewayのmodel allowlistとquota、Git/Web Gateway policy、Host Trusted Approval、VM resource limit、停止後のsafe export parserは変更しない。

## 対話起動latency

secure VMの停止、capability失効、固定OpenCodeのdigest/version検証、server health/version検証、resource probeは維持したまま、対話経路の固定待ちを削減した。

- OpenCode healthは最初に即時確認し、失敗時だけ25 msから最大100 msまでのbounded backoffで再確認する。個々のreadiness probeは200 msで打ち切り、guest relayがbackend起動前の接続を保持しても全体の60秒deadlineを消費させない。従来の2秒固定pollと10秒の単一probe待ちを廃止した。
- Host TUIのdigestと`--version`検証をVM再開と並列化する。検証結果は外部から構築できない短命identityとして渡し、command生成直前にinode、mode、size、mtimeが変わっていないことを再確認する。管理copyが正常ならPATH上の別copyをhashしない。
- 実際のVM停止・再開で空になるguest tmpfsの`/run/sunaba`は、Host memory内のsession設定から再生成する。capabilityを永続VMへ保存せず、mode 0700のruntime内一時directoryをcopy成否にかかわらず直後に削除する。
- TUI終了時はattachとcapabilityを先に失効し、`container stop --time 1`で通常のSIGTERM停止を行った後、stopped状態を再確認する。Apple Container既定の5秒graceを対話終了ごとに待たない。
- Phase 1実機gateはstartup、pause、resumeと主要runtime操作の所要時間を個別に出力し、8秒、0.75秒、8秒の上限で固定待ちの再混入を拒否する。pauseの上限は1秒graceを正常系で常時消費する退行を検出する。

2026-08-12の追加チューニングでは構成と検証項目を変えず、Apple Containerの`--init`をsecure specで必須化してSIGTERM forwardingとchild reapを有効化した。短命session inputは単一private directoryへまとめ、resumeの事前`mkdir`と4〜5回の個別copyを1回のdirectory copyへ置換した。guest service起動とresource probeも同じexec transactionへ集約し、host側のresource値検証とserver health/version検証は維持した。export前の固定`sleep 1`は最大1秒のprocess-exit確認へ置換し、正常終了時は直ちに次へ進む。macOS、OpenCode、Apple Container、Container serviceの前提確認は同じ結果を固定順で検証しつつ並列実行する。

2026-08-12の固定環境（Apple Container 1.2.2、`sunaba-base:1.18.16-secure.1`、OpenCode 1.18.16）では、同じvertical sliceで初回startup 2.46秒、pause 1.24秒、resume 1.74秒を記録した。VM create/start自体は0.87秒/0.39秒であり、従来約12秒の主因はVMではなく最初のhealth probeが10秒timeoutまで保持されることだった。

追加チューニング後に同じ固定環境とPhase 1 vertical sliceを2回再実行し、初回startup 2.24〜2.31秒、pause 0.129〜0.130秒、resume 1.67〜1.71秒を記録した。pause内のruntime stopは0.082〜0.083秒となり、1秒graceの常時消費を解消した。export前のguest停止・workspace freeze処理も0.123〜0.128秒で完了し、固定1秒待機を解消した。resumeでは1回のsession input copyが0.119〜0.138秒、guest service起動とresource probeの統合execが0.074秒、VM startが0.403〜0.442秒であり、残る約1秒は固定OpenCode serverがhealthへ到達するまでのcold startが中心である。2回目のexport後VM stopには3.17秒の外れ値があり、export全体の分布評価とApple Container側の停止変動は別途追跡する。

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

実OpenAI API keyとCodex OAuth credentialは環境変数から取得せず、macOS login Keychainの固定generic password（service `dev.sunaba.openai`、account `openai-api-key`または`codex-oauth`）だけを使う。固定`/usr/bin/security login-keychain`のquoted absolute pathを検証し、API keyのread/deleteへ同じpathを明示する。API key登録時はKeychain promptを使う。OAuth credentialはdevice flow後の保存からModel Gatewayの読取、refresh rotation、status、deleteまでSecurity.frameworkで固定login Keychain itemだけを操作し、secretをargv、environment、fileへ置かない。unit testと公開CLI実機gateはcommand pathとnative Keychain lifecycleをtest seamへ差し替え、実Keychainを変更せずに固定identity、output bound、control文字拒否、環境変数非依存を検証する。

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
