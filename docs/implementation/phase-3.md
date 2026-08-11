# Phase 3: Git Gateway

状態: 実施中。object-bound one-shot push approval、host quarantine resolver、HTTPS credential終端、smart HTTP read/receive relayを実装済み。session lifecycle統合は継続中。

## push approval binding

push requestはProject ID、repository identity、remote名、credentialを含まない正規化済みHTTPS/SSH URL、refごとのold/new object ID、force/deleteへ束縛する。更新順はref名でcanonical sortし、canonical JSONのSHA-256をapproval digestとする。host生成256-bit nonceは5分以内の一回限りで、confirmの成功・失敗でpending requestを消費し、grantもpush retry時に一回だけconsumeする。

object ID、ref、force/delete、remote、Projectのいずれかがapproval後に変化した場合はconstant-time digest比較で拒否する。credentialをuserinfoへ埋め込んだURL、query/fragment、HTTPS/SSH以外、重複ref、不正zero object/deleteをrequest作成前に拒否する。request、confirm、consumeはProject/VM/Sessionとpush digestへ束縛してhost auditへ記録する。

## host quarantine resolver

mode `0700`でsymlinkを含まないhost bare repositoryだけを読み、Git自身の`check-ref-format`とobject databaseを使ってbindingを構築する。current refがguestのold object IDと一致すること、new objectがhost quarantineに存在すること、branch targetがcommitであることを確認する。deleteはzero objectから、forceはhostのcommit graphに対するancestor判定から再計算する。Git subprocessはshellを使わず、system/global config、terminal prompt、継承環境を無効化する。

## upstream push transaction

承認retryではhost repository lock内でresolverとone-shot grant consumeを再実行し、HTTPS upstreamへ`--atomic`かつrefごとのexact object leaseを付けてpushする。Authorizationはhost Git subprocessの環境設定だけへ注入し、remote URL、argv、guest、auditへ返さない。upstream refが承認時のold objectから変化していれば拒否し、失敗したgrantも再利用できない。

## smart HTTP read relay

標準Gitの`upload-pack`で使う固定の`info/refs`とPOSTだけをProject/VM/Session、短期限、request/body/response/concurrency上限へ束縛したguest capabilityで許可する。固定HTTPS upstreamへのAuthorizationはhostで置換し、redirect、receive-pack、別repository、別routeを拒否する。実smart HTTP serverを使った`git clone`、`git fetch`、`git pull --ff-only`で互換性とcredential非混入を検証する。

## smart HTTP receive relay

hostが固定したpre-receive helperはGit自身のobject quarantine pathとold/new/refだけを、mode `0600`のprivate Unix socketおよびhost-only channel tokenでbrokerへ送る。brokerはquarantine objectをhost resolverで検査する。初回pushはobject ID-bound pending approvalを作って拒否し、hostでconfirmされた同一digestのretry時だけ、upstream push transactionを実行してreceive-packを受理する。delete-only receiveではGitがobject quarantineを作らない実挙動を扱い、new objectを必要としない削除だけを同じ承認経路で処理する。

実smart HTTP経路の`git push`で通常更新、non-fast-forward、ref deleteをそれぞれ初回拒否、明示承認、同一retry成功まで検証する。force/deleteはhostが再計算した別flagとしてpending bindingへ記録し、hook broker終了後のpushはupstreamへ到達しない。helperはupstream credentialやapproval結果を生成できず、brokerからの固定accept/rejectだけをpre-receive exitへ反映する。

## Trusted Git Approval UI

host UIはProject、repository、remote名、固定送信先、push digest、期限、各refのold/new object IDとforce/deleteを構造化表示する。表示したbindingとdigestの整合性を再検証してから、host生成nonceの完全一致入力だけを受理する。OpenCode、guest terminal、hook messageだけではconfirmを呼べず、force/deleteを通常pushとして表示できない。

## secure session lifecycle

Git Gatewayはmodel channelと別のProject/VM専用mode `0600` Unix socketとしてsecure session policy digestへ含める。VMへはsocket mount、guest loopback relay、実credentialではない短命Git capabilityだけを渡す。OpenCodeのGit subprocessには固定loopback repositoryだけへ送るcapability headerをprocess environmentで設定し、guest repositoryのremote URLにはcredentialを含めない。pause中は永続leaseとin-process gateの双方で`503`にし、resume時は同一VM/socket relayで再開する。session endではHTTP handlerに加えてapproval hook channelのclose callbackを一度だけ実行する。

再現コマンド:

```sh
go test -race -v ./internal/gitgateway
```

## 残件

- 実Agent VMでclone/fetch/pull/push、pause/end、credential非混入を統合試験する
- expiry、別Project/VM、object/ref差し替えのVM攻撃試験

これらを完了するまでPhase 3を完了扱いにしない。
