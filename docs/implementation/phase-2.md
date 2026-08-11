# Phase 2: Projectライフサイクルと成果物境界

状態: 実施中。Trusted Approvalとcrash-safe host applyの中核transactionを実装・検証済み。session reuse、orphan cleanup、永続audit hardeningは継続中。

## Trusted Approval

host memory上のApproval Managerが256-bit nonceを生成し、Project ID、host baseline digest、Merged View digest、Change Set digest、有効期限へrequestを束縛する。確認時に提示digestをconstant-timeで照合し、nonceは成功・失敗を問わず一回で失効する。得られたgrantも一回だけconsumeでき、別digestや別Projectへ転用できない。

承認表示のguest由来summaryは、改行、tab、C0/C1、ESC/OSC構成文字、BEL、双方向制御文字、不正UTF-8を`<U+XXXX>`等へ可視化する。nonceと4つのidentity/digestはhostが構成した固定fieldとして表示するため、guestの偽画面やserver eventだけではgrantを生成できない。

## crash-safe apply

applyはProject lockを取得し、残存transactionを回復してからhost baseline、Merged View実体、再計算したChange Setを照合する。全検証後にだけone-shot grantをconsumeする。

- Project rootの`.sunaba/transactions/sunaba-apply-*`をmode `0700`の同一filesystem transaction領域として使う。`.git`と`.sunaba`はmanifestとChange Setから除外され、apply対象pathとして拒否する。
- approved Merged Viewをtransaction内stageへno-follow copyし、影響pathの最小root集合を決定する。
- canonical相対pathの各親を`openat(O_NOFOLLOW|O_DIRECTORY)`で開き、既存entryをflat backupへ`renameat`してからstage entryを`renameat`する。symlink parentを追跡しない。
- journalはProject/digest、元entryの存在、backup名、desired entryを記録し、temp fileの`fsync`、rename、journal directoryの`fsync`を行う。
- 通常errorは逆順rollbackする。processがdeferなしで終了しても、次回Recoveryはbackupの実在を根拠に現在entryをfd-relativeに除去し、元entryを戻す。stale PIDやguest申告を回復判断に使わない。
- journal前の失敗はその呼出しが新規作成したtransactionだけを削除する。journal後の失敗を成功扱いせず、回復不能な未知entry/journalはfail-closedで停止する。
- apply後manifestがapproved Merged digestと一致した場合だけtransactionを削除して成功を返す。

unit/race testはadd、modify、delete、rename、Protected Path保持、承認なし、digest差し替え、baseline競合、grant再利用、symlink parent race、途中error rollbackを検証する。別test processを実際にentry install直後の`os.Exit(42)`で終了させ、次process相当のRecoveryが元baselineを復元しjournal/backupを片付けることも確認する。

再現コマンド:

```sh
go test -race -v ./internal/approval ./internal/apply
```

## 残件

- stop/start/reuseを含む永続session leaseと期限失効
- ownership labelとactive leaseを照合するorphan cleanup
- session/Gateway/export/applyをhost JSONLへ安全に永続化するaudit recorder
- actual Phase 1 export artifactから承認・applyまでの統合試験
- resource quotaとTrusted UIのCLI統合

これらを完了するまでPhase 2およびMVPを完了扱いにしない。
