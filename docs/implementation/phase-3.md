# Phase 3: Git Gateway

状態: 実施中。object-bound one-shot push approval coreを実装済み。host credential終端、smart HTTP relay、clone/fetch/pull/pushの実統合は継続中。

## push approval binding

push requestはProject ID、repository identity、remote名、credentialを含まない正規化済みHTTPS/SSH URL、refごとのold/new object ID、force/deleteへ束縛する。更新順はref名でcanonical sortし、canonical JSONのSHA-256をapproval digestとする。host生成256-bit nonceは5分以内の一回限りで、confirmの成功・失敗でpending requestを消費し、grantもpush retry時に一回だけconsumeする。

object ID、ref、force/delete、remote、Projectのいずれかがapproval後に変化した場合はconstant-time digest比較で拒否する。credentialをuserinfoへ埋め込んだURL、query/fragment、HTTPS/SSH以外、重複ref、不正zero object/deleteをrequest作成前に拒否する。request、confirm、consumeはProject/VM/Sessionとpush digestへ束縛してhost auditへ記録する。

再現コマンド:

```sh
go test -race -v ./internal/gitgateway
```

## 残件

- host bare quarantineでnew object存在、current old ref、fast-forward/force/deleteを再計算する
- Git credentialをguestへ返さずhost transportだけへ注入する
- standard Git smart HTTPによるclone/fetch/pullと、pending approval後のpush retry
- session終了、expiry、別Project/VM、object/ref差し替えの実統合試験

これらを完了するまでPhase 3を完了扱いにしない。
