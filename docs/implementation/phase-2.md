# Phase 2: Projectライフサイクルと成果物境界

状態: 完了。Trusted Approval、crash-safe host apply、永続session leaseを伴う同一VMのpause/resume、orphan cleanup、resource limit、host audit、公開CLI supervisor、sanitized shellを実装し、自動testと再現可能な実機gateへ固定した。

## Trusted Approval

host memory上のApproval Managerが256-bit nonceを生成し、Project ID、host baseline digest、Merged View digest、Change Set digest、有効期限へrequestを束縛する。確認時に提示digestをconstant-timeで照合し、nonceは成功・失敗を問わず一回で失効する。得られたgrantも一回だけconsumeでき、別digestや別Projectへ転用できない。

承認表示のguest由来summaryは、改行、tab、C0/C1、ESC/OSC構成文字、BEL、双方向制御文字、不正UTF-8を`<U+XXXX>`等へ可視化する。nonceと4つのidentity/digestはhostが構成した固定fieldとして表示するため、guestの偽画面やserver eventだけではgrantを生成できない。

Trusted Approval UIはmanagerの自由形式`Display`を描画せず、structured requestのProject ID、3 digest、expiry、nonceから固定host画面を再構成する。利用者が短い1行でnonceを完全一致入力した場合だけ承認し、`yes`、前後空白、追加文字、control sequence、512 byte超の入力を拒否する。比較はnonceのSHA-256をconstant-timeで行う。UI確認後もmanagerが同じbindingとexpiryを再検証するため、画面表示だけでgrantは成立しない。

audited managerはrequest、confirmの成功・拒否、grant consumeをProject/VM/Sessionへ束縛してhost JSONLへ記録する。表示対象nonceと3 digest、summaryのSHA-256だけを記録し、guest由来summary本文は保存しない。requestのauditに失敗した場合はpending nonceを破棄し、confirmのauditに失敗した場合はgrantを発行せず、consumeのauditに失敗した場合はgrantを失効させてapplyを拒否する。

## Change Set review

pending Change Set schema v3は、検証済みbaseline SnapshotとMerged ViewをProjectのowner-only stateへ両方保存する。両方のmanifestと再構築したChange Set digestが一致した場合だけpendingを確定し、保存失敗時はVMを破棄しない。旧schema v2はhost worktreeがbaseline digestと一致する場合だけ内容reviewでき、一致しない場合も変更metadataとapply拒否理由を表示する。従来のapply互換性も保持する。

公開`sunaba changes review`はadd/modify/delete/rename、type、mode、実行属性、symlink target、boundedなtext unified diffをhost worktreeへ書き込まず表示する。外部Git、diff、pager、editor、preview helperは起動しない。Snapshot全体と表示直前のfile identity、size、mode、SHA-256をfd-relative、`O_NOFOLLOW`で再検証し、binary、invalid UTF-8、巨大file、行・総量・表示件数上限はmetadataと未表示理由を明示する。path、target、diff本文はterminal sanitizerを通し、`--path`は表示だけを絞って部分applyにはしない。`changes apply`も同じrendererを再実行し、reviewしたChange Set digestへ従来のone-shot nonceを束縛する。

unit/race testはtext diffの再構築、binary、実行属性、symlink、exact path filter、ANSI/OSC/BEL/bidi、baseline/Merged View改変、schema v2互換、bounded表示を検証する。公開CLI実機gateにもexport後の`changes review`を追加した。

## crash-safe apply

applyはProject lockを取得し、残存transactionを回復してからhost baseline、Merged View実体、再計算したChange Setを照合する。全検証後にだけone-shot grantをconsumeする。

- Project rootの`.sunaba/transactions/sunaba-apply-*`をmode `0700`の同一filesystem transaction領域として使う。`.git`と`.sunaba`はmanifestとChange Setから除外され、apply対象pathとして拒否する。
- approved Merged Viewをtransaction内stageへno-follow copyし、影響pathの最小root集合を決定する。
- canonical相対pathの各親を`openat(O_NOFOLLOW|O_DIRECTORY)`で開き、既存entryをflat backupへ`renameat`してからstage entryを`renameat`する。symlink parentを追跡しない。
- journalはProject/digest、元entryの存在、backup名、desired entryを記録し、temp fileの`fsync`、rename、journal directoryの`fsync`を行う。
- 通常errorは逆順rollbackする。processがdeferなしで終了しても、次回Recoveryはbackupの実在を根拠に現在entryをfd-relativeに除去し、元entryを戻す。stale PIDやguest申告を回復判断に使わない。
- journal前の失敗はその呼出しが新規作成したtransactionだけを削除する。journal後の失敗を成功扱いせず、回復不能な未知entry/journalはfail-closedで停止する。
- apply後manifestがapproved Merged digestと一致した場合だけtransactionを削除して成功を返す。

applyはProject lockやgrant consumeより前に対象3 digestをhost auditへdurable appendできた場合だけ開始し、成功・拒否理由を追記する。開始eventを記録できない場合はhost worktreeへ触れない。最終成功eventの記録に失敗した場合はerrorを返し、callerはapproved Merged digestとの再照合で適用済み状態を判定できる。

unit/race testはadd、modify、delete、rename、Protected Path保持、承認なし、digest差し替え、baseline競合、grant再利用、symlink parent race、途中error rollbackを検証する。別test processを実際にentry install直後の`os.Exit(42)`で終了させ、次process相当のRecoveryが元baselineを復元しjournal/backupを片付けることも確認する。

## pause / resume

同じsession objectとProject lockを保持したままVMをpause/resumeできる。Apple Containerのsocket mountはVM作成時のhost Unix listenerへ結び付くため、Model Gateway listenerはVM寿命中固定する。pauseはLocal Attach Relayを閉じ、host側atomic gateと永続leaseをinactiveにしてからVMを停止する。このため、停止処理が途中で失敗しても正しいtokenのrequestを含めてfail closedで`503`にする。resumeはVMとguest serviceを再開し、Local Attach Relay経由のhealth/version完全一致を確認してからleaseとgateをactiveへ戻す。pause中もProject lockを解放せず、attach capabilityは到達不能である。

## 永続session lease

Model Gateway capabilityはmode `0700`のhost state directoryに、mode `0600`のJSON recordとして原子的に永続化する。recordはProject ID、VM ID、Session ID、用途、状態、絶対有効期限へ束縛し、symlink、所有者・mode不一致、不正identity、期限切れ、別Project/VM/用途を拒否する。起動中はpausedで発行し、OpenCode serverのhealth/version確認後だけactiveにする。pauseはVM停止より先にpausedへ遷移し、session終了・export・VM破棄・起動失敗ではrevokedへ遷移する。revoked recordとSession IDは再利用しない。Supervisor processが終了すると専用Unix listenerも失われるため、persisted active recordだけからcapabilityを再発行せずfail closedとなる。

## host boundary audit

旧prototypeのguest OpenCode SSE収集とは別に、Supervisorが信頼境界eventをhost state配下のProject別JSONLへ直接追記する。directoryはmode `0700`、logはmode `0600`かつcurrent user所有のregular fileに限定し、`O_NOFOLLOW`、process間排他、1 event 1 JSON line、`fsync`を強制する。symlink・mode・owner不一致、64 KiB超のevent、token/password/API key/body/prompt/content等の機密keyを拒否し、guest由来文字列のterminal制御文字を可視化する。

secure sessionはこのrecorderを必須とし、Project/VM/Session identity、snapshot、VM lifecycle、attach relay、Model Gateway lifecycleとrequest metadata、capability、pause/resume、export後のChange Set digest、cleanupを記録する。本文、upstream key、capability token、OpenCode server passwordは記録しない。audit追記不能時のpause/cleanupは、先にGateway gateと永続leaseをinactiveにしてVM停止・所有VM cleanupを継続し、操作自体はerrorとして返す。

## orphan cleanup

sessionは永続leaseに加え、Supervisor process寿命中だけOSが保持するsession別file guardを取得する。pause中もguardを保持し、process crashではkernelが自動解放する。orphan cleanupはApple Containerの一覧を読むだけでは削除せず、個別inspectを行い、`sunaba-<ProjectID>-<SessionID>`の完全名、owner/project/session/mode label、永続leaseのProject/VM/Session/用途identityをすべて完全一致させる。live guardがあればactive/paused sessionとして維持する。guardがなく、identityが完全一致する管理VMだけをauditへ事前記録し、leaseをrevokeし、再inspectしてから停止・削除し、結果を追記する。label欠落、名前差し替え、lease欠落・破損・identity不一致、audit障害では削除を拒否し、他resourceへ範囲を広げない。

## resource limits

secure policy digestはCPU、memory、workspace disk bytes、process、file size、open-file hard limitを含む。Apple Container 1.2.2の`--cpus`、`--memory`、`--ulimit nproc/fsize/nofile`をVM作成時に設定し、inspect可能な構成として固定する。OpenCodeはUID 1000の非特権`sunaba-agent`として起動し、Project codeからhard limitを引き上げられない。OverlayFSのupper/workとsynthetic Git repositoryは、host policyのbyte数で作ったext4 loop image内へ置くため、ファイル数を増やしてもworkspace全体が設定量を越えてhost diskを消費できない。pause/resume時は同じimageを再mountする。

session ready前とresume時に、guest vCPU、memory、bounded filesystem size、OpenCode UID、`/proc/<pid>/limits`をhost側からprobeし、policyと一致しなければcapabilityをactiveにしない。Apple Containerは指定vCPUにkernel用1 vCPU、指定memoryに固定VM overheadを加えるため、採用版で測定した上限としてCPUは指定値+1以下、memoryは指定値+128 MiB以下を許容する。workspace disk、nproc、fsize、nofileはpolicy値以下ではなく完全一致を要求し、結果をauditする。

freeze/exportではOpenCodeとguest relayを終了し、session credential fileを削除する。停止したApple Containerをexport用に再開するとLinux mount namespaceが新しくなるため、先にGateway gateとleaseを失効させ、Local Attach Relayを閉じた状態でVMを再開し、ext4 loopとOverlayFS workspaceだけを再mountする。この間はOpenCode、guest relay、capabilityを再開しない。mount確認後にhost channelを閉じ、bounded overlayのmerged workspaceを停止VMのrootfs内へcopyする。

host safe parserはtrusted baselineとの差からadd/modify/deleteを再計算し、guest提供diffやmanifestを使わない。snapshot manifest確定時はcallerのentry sliceを共有せず、materialize直前にもcanonical digestを再計算して一致を要求する。不一致診断はpathとfieldだけに限定し、内容やdigest値をlogへ出さない。ext4 imageはunmount後にexport対象から削除する。safe parserはpath traversal、Protected Path、hardlink、special file、xattr、size/entry上限を同じく拒否する。

再現コマンド:

```sh
go test -race -v ./internal/approval ./internal/apply ./internal/lease ./internal/session ./internal/workspace ./internal/trustedui ./internal/cli
SUNABA_PHASE1_INTEGRATION=1 go test -tags=integration -run TestPhase1SecureSessionVerticalSlice -count=1 -v ./test/integration
SUNABA_PHASE2_INTEGRATION=1 go test -tags=integration -run TestPhase2ActualOrphanCleanup -count=1 -v ./test/integration
```

実Apple Container試験はstart、pause中のattach到達不能と有効tokenによるModel Gateway requestの`503`拒否、同じVMのresume、再度のOpenCode tool call、停止export、承認済みbaselineからのclean recreation、Trusted Approval、host applyまでを通過した。実OpenCodeが生成したadd/modify/deleteだけが反映され、Protected Pathの`.git`は保持された。128 MiB bounded diskへの160 MiB writeとhard process limit引き上げが失敗し、CPU/memory/runtime hard limitのprobeも通過した。frozen archive、host audit、Projectにupstream key、capability、server passwordが存在しないことを確認した。別の実機試験ではlive guard中のVMを維持し、guard解放後だけ同じVMをorphanとして停止・削除した。

## 公開CLI lifecycle

secureの`sunaba up`はowner-only detached supervisorを起動し、VMを作成後にGateway/leaseをinactiveへしてpausedで返す。`agent`/`shell`は期限内の同じVMとupperをresumeし、終了時に再びpauseする。`changes export`は停止VMをexportしてChange Setを永続化し、ownership再検証後にVMをdestroyする。`down`、`recreate`、`destroy`も同じcontrol socketを使い、stale locatorはexact ownership/lease orphan cleanup後だけ除去する。

control locator、Unix socket、startup logはcurrent user所有のprivate directoryへ置き、locator/socketはmode `0600`で検証する。OpenCode server passwordとGateway capabilityを含むcopy元はmode `0600`で作り、guest `/run/sunaba/session.env`へcopy完了直後にhost filesystemから削除する。passwordをhost clientへ渡す経路はowner-only control socket応答だけとし、guest credential fileはexport前に削除する。TTL到達時はVMをpauseし、それ以降のresume/shellを拒否する。active Host TUIはpolicyのidle timeoutより短い間隔でowner-only heartbeatを送り、client消失後にidle deadlineへ到達するとSupervisorがGatewayをinactive化してVMをpauseする。Git push承認も同じowner-only control socket上のhost Trusted UIからだけ処理する。

`sunaba shell`は16 KiB以下の1行command、commandごとの2分timeout、1 MiB出力上限を持つ。guestのUID 1000、Overlay workspace、同じGateway policyで実行し、host表示前にESC/OSC/BEL/C0/C1/bidi/invalid UTF-8を必ずescapeする。未検証PTYとraw `container exec`は公開しない。

公開CLI実機gate:

```sh
SUNABA_CLI_INTEGRATION=1 go test -tags=integration ./test/integration -run 'TestPublicCLI' -count=1 -v
```

このgateは公開`project init`/`up`からpaused VMを作成し、shellで作ったfileがpause/resume後も残ること、悪意あるOSC/BELが可視化されること、停止VMのOverlayFSを再構成したexport後に正しいChange Setが得られ、supervisor/VM/Project stateをexact cleanupできることを検証する。OpenAI credential取得はlink-time fakeのlogin Keychainへ差し替えるため、実credentialや環境変数へ依存しない。2026-08-11の最新HEAD実機再実行で44.42秒でPASSした。
