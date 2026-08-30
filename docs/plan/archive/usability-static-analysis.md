# [ARCHIVE] sunaba 利用者体験に関する静的解析レポート

- 調査日: 2026-08-19
- 調査方法: ソースコードと現行文書の静的解析
- 実行検証: 未実施（調査環境が Linux であり、macOS/Apple Container を前提とする実行経路は検証していない）
- 文書の位置付け: 2026-08-19時点の旧改善検討資料。現在の実装、テスト、セキュリティ判断の根拠にしない

## 1. 目的

sunaba を初めて導入する利用者と、日常的に開発へ利用する利用者の両方を想定し、操作の分かりにくさ、作業損失につながる挙動、過度な手間、誤解しやすい仕様を静的に調査した。

セキュリティ境界を弱めずに改善できるかを重視し、次の3種類を区別して評価する。

- 実装上の問題: 現在の実装により、作業損失や意図しない情報持ち出しが起こり得るもの
- 仕様上の摩擦: セキュリティ上の理由はあるが、操作方法やライフサイクルに改善余地があるもの
- 導線・説明上の問題: 必要な情報や診断手段が、利用者へ適切な時点で提示されないもの

## 2. 調査範囲と前提

仕様判断には、現行の正本文書である [`docs/plan/sunaba-secure-agent-platform.md`](../sunaba-secure-agent-platform.md) と、許可されるホスト操作を定めた [`docs/plan/allowed-host-operations.md`](../allowed-host-operations.md) を使用した。`docs/plan/archive/` は調査根拠に使用していない。

主に次を確認した。

- セットアップ、Project 登録、VM 起動、Agent Session、export/review/apply の利用者導線
- Project snapshot と Change Set の対象範囲
- External Git、Git Gateway、Web Gateway、承認操作
- Session/VM の寿命と設定変更時の制約
- ベースイメージ、HOME、キャッシュ、開発ツールの永続性
- CLI のエラー、状態表示、診断機能

静的解析のみであるため、表示崩れ、実際の待ち時間、Apple Container 固有の挙動、OpenCode TUI の操作感は評価対象外とした。また、本書中の「起こり得る」は、実装経路から判断したものであり、実環境での再現確認を意味しない。

## 3. 結果概要

| ID | 優先度 | 分類 | 指摘 |
| --- | --- | --- | --- |
| UX-01 | 高 | 実装上の問題 | External Git の clone 先が Change Set 対象外で、未 push の変更を失う可能性がある |
| UX-02 | 高 | 実装・導線上の問題 | snapshot の除外設定と事前確認がなく、秘密情報や巨大な生成物まで取り込み得る |
| UX-03 | 高 | 仕様上の摩擦 | Agent Session の絶対 TTL により、再利用可能な VM でも export/recreate が必要になる |
| UX-04 | 中〜高 | 仕様上の摩擦 | Project 設定やポリシー変更のために、VM と未適用 Change Set の整理を要求される |
| UX-05 | 中〜高 | 導線・仕様上の問題 | 標準イメージの開発ツールが限定的で、HOME 配下の環境やキャッシュも停止時に失われる |
| UX-06 | 中 | 仕様・導線上の摩擦 | Change Set と Git push の承認が安全だが、日常操作として重い |
| UX-07 | 中 | 導線上の問題 | Web Gateway の既定プリセットが広く、更新にも VM 不在が要求される |
| UX-08 | 中 | 導線上の問題 | setup/update/status が分散し、導入不備をまとめて診断できない |
| UX-09 | 中 | 仕様・説明上の問題 | `sunaba shell` が対話 shell に見える一方、実際は各行が独立実行される |
| UX-10 | 低〜中 | 実装上の問題 | `project init` で作成する初期 snapshot が Session 起動に利用されず、処理と容量が無駄になる |

## 4. 詳細

### UX-01: External Git の未 push 変更を失う可能性がある

**分類:** 実装上の問題  
**優先度:** 高

External Git の案内では、VM 内の `/var/lib/sunaba/overlay/origin-clone` へリポジトリを clone する手順になっている（[`docs/workflows.md`](../../workflows.md) 302–312行付近）。一方、Session の export は `WorkspacePath` だけを `/var/lib/sunaba/merged-export` へコピーし、その後 overlay イメージを削除する（[`internal/session/session.go`](../../../internal/session/session.go) 979–1000行付近）。Change Set の解析対象も merged export に限定されている（[`internal/workspace/export.go`](../../../internal/workspace/export.go) 16–20行付近）。

したがって、案内どおりの clone 先で編集し、Git push も元の Project workspace へのコピーも行わないまま export すると、その編集は Change Set に含まれず、VM 破棄に伴って失われる可能性がある。

利用者にとっては「VM 内で正常に保存され、Git の working tree にも存在する変更」が sunaba の export 対象外であることを予測しにくい。特に push が承認待ちまたは失敗した状態で終了すると、作業損失につながる。

改善案:

1. External Git の working tree を、明確に Change Set 対象となる workspace 内へ置く。
2. clone 用の保存領域を分離する必要がある場合は、終了前に workspace へ変更を取り込む専用コマンドを用意する。
3. export 前に Change Set 対象外の Git working tree に未 commit/未 push の変更がないか検査し、破棄前に強い警告を出す。

### UX-02: snapshot の除外設定と秘密情報の事前警告がない

**分類:** 実装・導線上の問題  
**優先度:** 高

正本仕様は、Project snapshot の対象をホスト側の Project policy で決めること、`.env`、秘密鍵、証明書などが guest と LLM へ渡り得るため初回 snapshot 時に警告すること、include/exclude policy をホスト側で持つことを求めている（[`docs/plan/sunaba-secure-agent-platform.md`](../sunaba-secure-agent-platform.md) 439–450行付近）。

現在の snapshot walker は、保護対象として渡されたパス以外を再帰的に走査する（[`internal/workspace/snapshot.go`](../../../internal/workspace/snapshot.go) 29–46行、140–203行付近）。既定の保護対象は主に `.git` と `.sunaba` であり（[`internal/policy/policy.go`](../../../internal/policy/policy.go) 127–138行付近、[`internal/projectconfig/config.go`](../../../internal/projectconfig/config.go) 332–366行付近）、`.gitignore` や利用者が指定する snapshot 除外設定は反映されない。`project init` の成功表示にも、秘密情報が guest/LLM へ渡ることの警告はない（[`internal/cli/cli.go`](../../../internal/cli/cli.go) 152–167行付近）。

このため、次の問題が起こり得る。

- `.env`、秘密鍵、ローカル証明書などが、利用者の認識なしに guest と LLM の参照可能範囲へ入る。
- `node_modules`、`.venv`、`target`、ビルド成果物などを取り込み、初回処理が遅くなる、または snapshot 上限で失敗する。
- 利用者が「`.gitignore` に入っているため対象外」と誤認する。

既定上限は、100,000 entries、1ファイル128 MiB、合計2 GiB である（[`internal/policy/policy.go`](../../../internal/policy/policy.go) 174–188行付近）。大規模 Project では、sunaba の利用を開始する前に上限エラーへ到達する可能性もある。

改善案:

1. ホストだけが管理できる snapshot include/exclude policy を実装する。Project 内のファイルから制約を緩和できない設計にする。
2. 初回 snapshot の前に、対象ファイル数・合計容量・大容量ファイル・秘密情報らしいファイル名をプレビューする。
3. `.gitignore` は自動的なセキュリティ境界にせず、「除外候補として取り込む」「明示的に無視する」をホスト設定で選択できるようにする。
4. `.env`、`*.pem`、`id_rsa` などが含まれる場合は、guest/LLM へ渡ることを明示して確認を求める。

### UX-03: Session TTL が VM 再利用性を実質的に制限する

**分類:** 仕様上の摩擦  
**優先度:** 高

既定の Session TTL は3,600秒、idle timeout は900秒である（[`internal/policy/policy.go`](../../../internal/policy/policy.go) 174–175行付近）。Session 開始時に絶対有効期限が一度だけ計算され（[`internal/cli/supervisor.go`](../../../internal/cli/supervisor.go) 93–108行付近）、期限後の `agent` は「export または recreate」が必要として拒否される（[`internal/cli/cli.go`](../../../internal/cli/cli.go) 241–265行付近）。正本仕様にも、この制約は現在の振る舞いとして記載されている（[`docs/plan/sunaba-secure-agent-platform.md`](../sunaba-secure-agent-platform.md) 1183–1185行付近）。

一方、製品の基本モデルでは、同一 Project の次回 Session で同じ VM/upper を再利用し、stop/start 後も状態を維持することを意図している（同文書 313–318行付近）。利用者から見ると、VM の状態が残っているのに1時間で export/recreate を求められ、「再利用できる VM」と「再利用できない認証 Session」の違いが操作上の負担になる。

改善案:

1. VM/upper の寿命と Agent Session の認証寿命を分離する。
2. Agent 終了時には旧 token、session ID、server password を失効させつつ、同じ paused VM に新しい Session 資格情報を発行できるようにする。
3. TTL 到達前に残り時間を表示し、長時間作業が中断される可能性を通知する。

### UX-04: 設定変更に VM と Change Set の整理が必要になる

**分類:** 仕様上の摩擦  
**優先度:** 中〜高

Project config の適用は、所有 VM または pending Change Set があると拒否される（[`internal/cli/config_commands.go`](../../../internal/cli/config_commands.go) 224–244行付近）。policy 変更にも同様の制限がある（[`internal/cli/policy_commands.go`](../../../internal/cli/policy_commands.go) 238–245行付近）。操作手順としても、設定変更の前に export/apply または discard が必要と案内されている（[`docs/workflows.md`](../../workflows.md) 211–240行付近）。

たとえば作業中に Web origin の不足へ気付いた場合、利用者は一度 Agent を終了し、export、review、apply または discard を済ませ、設定を変更し、新しい VM/Session を作る必要がある。小さな許可追加に対して、作業ライフサイクル全体の終了を要求している。

改善案:

- image、CPU、memory、workspace など「VM 再作成が必須の設定」と、model、Web origin、Gateway quota など「次 Session で更新可能な設定」を分離する。
- VM-bound policy の同一性を維持する必要がある設定でも、paused VM を残して新 Session の開始時に安全に再束縛できる仕組みを検討する。
- 拒否メッセージには、現在何が設定変更を妨げているかと、変更を失わない最短手順を表示する。

### UX-05: 開発ツールと HOME/キャッシュの永続性が不足する

**分類:** 導線・仕様上の問題  
**優先度:** 中〜高

標準イメージに含まれる主なツールは bash、curl、wget、Git、tar、zip、ripgrep、sudo、SSH などであり、Go、Node.js、Python/pip、Rust/Cargo、コンパイラなどの一般的な言語ツールチェーンは含まれない（[`assets/Containerfile`](../../../assets/Containerfile) 1–9行付近）。Web Gateway も既定では無効である（[`internal/policy/policy.go`](../../../internal/policy/policy.go) 182–185行付近）。

また、guest の `HOME`、設定、データディレクトリは `/run/sunaba/...` に置かれ（[`internal/session/session.go`](../../../internal/session/session.go) 528–531行付近）、`/run` は stop/resume で空になる tmpfs として扱われる（同ファイル 756–771行付近）。そのため、HOME に入る言語バージョン管理ツール、ユーザー設定、パッケージキャッシュなどは Session をまたいで維持されない。

OpenCode server 自体は root で起動するため、VM rootfs へ導入したツールは VM の存続中は残り得る。しかし、利用者がどこへ導入すれば保持されるか、どのキャッシュが消えるかは直感的ではなく、Project ごとに毎回環境構築が必要になりやすい。

改善案:

1. 言語別の検証済み toolchain profile、または署名・digest 固定されたカスタムイメージを Project 設定で選べるようにする。
2. Change Set とは分離した、容量制限付きの永続 package cache を用意する。
3. Session 開始時に Project の manifest を検出し、不足ツールと永続化されない導入先を案内する。
4. HOME、rootfs、workspace のうち、何が stop、recreate、export で残るかを CLI 上で表示する。

### UX-06: 承認操作が日常利用には重い

**分類:** 仕様・導線上の摩擦  
**優先度:** 中

Change Set は export 後に review を要求し、apply 時にも完全な review を再実行する（[`internal/cli/cli.go`](../../../internal/cli/cli.go) 554–580行付近）。これは TOCTOU 対策として妥当だが、変更量が多い場合には確認負担が大きい。

Git push は、最初の push が拒否された後、別のホスト terminal で `sunaba approvals` を開き、長いランダム nonce を正確に入力し、期限内に同じ push を再試行する手順である（[`docs/user-guide.md`](../../user-guide.md) 341–363行付近、[`internal/trustedui/approval.go`](../../../internal/trustedui/approval.go) 25–38行付近）。承認画面は pending request を順番に処理し、対象選択、skip、明示的な reject を行う導線を持たない（[`internal/cli/approval_control.go`](../../../internal/cli/approval_control.go) 431–500行付近）。

承認の独立性や intent binding は維持すべきであり、単純な自動承認へ変えるべきではない。ただし、64文字相当の nonce を人間に転記させること自体は、セキュリティ保証より入力ミスと疲労を増やしている。

改善案:

- request の内容、digest、対象 remote/ref、期限をホスト所有 UI に表示し、対象を選んで approve/reject/skip できるようにする。
- nonce と request binding は内部検証に残し、利用者の確認はローカル UI の yes/no、または OS のネイティブ認証に置き換える。
- review 済み Change Set が apply 直前に同一 digest である場合、再確認の意図を保ちながら差分表示の重複を減らす。

### UX-07: Web Gateway の既定プリセットと更新手順が分かりにくい

**分類:** 導線上の問題  
**優先度:** 中

`web enable` は origin を指定しなくても、既定で common-development origins を有効にする（[`internal/cli/commands.go`](../../../internal/cli/commands.go) 218–226行付近）。このプリセットは多数の origin を含む（[`internal/webgateway/common-development-origins.txt`](../../../internal/webgateway/common-development-origins.txt)）。config wizard には警告がある一方、直接の `web enable` 経路では有効化前の範囲確認がなく、適用後の表示が中心である（[`internal/cli/policy_commands.go`](../../../internal/cli/policy_commands.go) 150–224行付近）。

また、blocklist snapshot の取得有効期限は7日で固定され（[`internal/cli/config_commands.go`](../../../internal/cli/config_commands.go) 503–507行付近）、`web refresh` は VM が存在する状態では policy 変更として拒否される。利用ガイドも VM が存在しない状態での refresh を求めている（[`docs/user-guide.md`](../../user-guide.md) 480–489行付近）。

結果として、利用者は「必要な1 origin だけ許可したつもりで広い preset を許可する」、または作業開始後に blocklist 期限切れへ気付き、VM を整理してから更新する可能性がある。

改善案:

1. `--preset common-development` を明示指定にし、origin 未指定時は対話確認またはエラーにする。
2. 有効化前に origin 数、代表例、deny/blocklist の状態、適用範囲を表示する。
3. `status` に blocklist snapshot の取得日時と期限を表示し、期限前に警告する。
4. policy digest の安全な更新方法を設け、VM/upper を破棄せず snapshot だけ更新できるか検討する。

### UX-08: 導入・更新・診断手段が分散している

**分類:** 導線上の問題  
**優先度:** 中

導入手順は、複数バイナリの build、固定版 OpenCode の host への配置、PATH 設定、base image build、`setup` を利用者が順に行う構成である（[`docs/user-guide.md`](../../user-guide.md) 18–180行付近）。`setup` は主要な前提や OpenCode/image を検査するが、Session 起動時に必要な sibling helper すべてを事前検査せず、成功を表示する（[`internal/cli/version_commands.go`](../../../internal/cli/version_commands.go) 450–542行付近）。たとえば `sunaba-guest-relay` の不足は最初の Session 起動時に判明する（[`internal/cli/supervisor.go`](../../../internal/cli/supervisor.go) 144–149行付近）。

更新確認は artifact を取得・検証する一方、適用時には固定版 OpenCode を macOS 側へ別途導入するよう利用者へ求め、現在インストール済みの host OpenCode を再検証する（[`internal/cli/version_commands.go`](../../../internal/cli/version_commands.go) 126–153行、210–220行付近）。また、CLI は標準の version flag を隠しており（[`internal/cli/commands.go`](../../../internal/cli/commands.go) 17–33行付近）、構成要素の版や digest を一覧化する `version`/`doctor` 相当の導線がない。

改善案:

- `sunaba doctor` を設け、CLI、helper、OpenCode server/TUI、base image digest、Apple Container、pf anchor、state directory、blocklist expiry を一括して read-only 診断する。
- `setup` の成功条件に、実際の初回 Session に必要な全 helper と digest の検査を含める。
- 固定版一式を同じ release bundle または package installer で配布し、手動配置箇所を減らす。
- `sunaba version` で、CLI だけでなく相互に整合すべき各 component の版を表示する。
- `status` に quota の設定値だけでなく、現在使用量、残量、期限切れ予定を表示する。

### UX-09: `sunaba shell` は一般的な対話 shell と挙動が異なる

**分類:** 仕様・説明上の問題  
**優先度:** 中

`sunaba shell` は標準入力を1行ずつ読み取り、各行を個別の guest command として実行する（[`internal/cli/cli.go`](../../../internal/cli/cli.go) 392–412行付近）。guest 側では各 command が `/bin/bash -lc` として実行されるため（[`internal/session/session.go`](../../../internal/session/session.go) 765–771行付近）、`cd`、shell variable、function などの shell state は次の行に引き継がれない。

コマンド名と prompt は対話 shell を連想させるため、利用者は次のような入力が成立すると期待しやすい。

```console
cd src
go test ./...
```

実際には2行目が元の working directory で実行される。また、command output は1 MiBで切り詰められる実装だが（[`internal/cli/approval_control.go`](../../../internal/cli/approval_control.go) 256–271行付近）、切り詰められたことが明確に示されない可能性がある。

改善案:

- 現在の方式を維持するなら `exec-console` など、各行独立であることが伝わる名称・prompt・help にする。
- `pwd` と「各行は独立した `/bin/bash -lc`」という注意を開始時に表示する。
- 対話 shell を提供する場合は、TTY と継続 process を明示的な別機能として設計し、既存の認証・監査境界を維持する。
- 出力打ち切り時に、上限と完全な結果を得る方法を表示する。

### UX-10: `project init` の初期 snapshot が利用されない

**分類:** 実装上の問題  
**優先度:** 低〜中

`project init` は Project 登録時に `initial-snapshot` と metadata を作成する（[`internal/cli/cli.go`](../../../internal/cli/cli.go) 152–162行付近）。しかし Session 開始時には Project root から新しい snapshot を作成しており（[`internal/session/session.go`](../../../internal/session/session.go) 182–184行付近）、登録時の initial snapshot を起動に利用する production 経路は確認できなかった。

このため、登録処理が大きな Project で時間・容量上限に到達しても、その成果物は実際の Session baseline にならない。利用者は `project init` を完了した時点で snapshot が確定したと誤解する可能性もある。

改善案:

- initial snapshot を最初の VM 作成時の正規 baseline として利用するか、登録時の snapshot 作成を廃止する。
- 後者の場合は `project init` を明確に「Project 登録」と位置付け、実 snapshot は `up`/Session 作成時に行われることを表示する。
- snapshot が作られた時刻と、それ以降の host 側変更が conflict 判定へ与える影響を `status` に表示する。

## 5. 横断的な利用者導線の課題

現在の標準的な流れは、おおむね次のようになる。

```text
導入・setup
  → Project 登録
  → VM/Session 作成
  → Agent または shell で作業
  → 必要に応じて Gateway 承認
  → export
  → review
  → apply または discard
```

各段階のセキュリティ境界は明確だが、段階をまたいで状態を変更しにくい。Web origin の追加、blocklist 更新、TTL 到達など、作業内容そのものとは別の理由でも最後まで export/apply/discard を進める必要がある。また、host working tree が baseline から変化すると apply が conflict になるため、sunaba の Session と並行して host 側を編集するチーム開発では調整負担が増える。

改善の中心は、セキュリティ確認を減らすことではなく、次の状態を CLI が一貫して説明することにある。

- 現在の作業はどこに保存され、export 対象か
- stop、Session expiry、recreate、discard のそれぞれで何が失われるか
- 次に必要な操作と、その理由
- snapshot/Change Set/Gateway approval の対象と期限
- 設定変更に VM 再作成が本当に必要か

## 6. 改善の優先順位

### P0: 作業損失と意図しない情報共有を防ぐ

1. External Git working tree を Change Set 対象へ含めるか、未保存変更を破棄前に検出する（UX-01）。
2. host-only snapshot 除外設定、対象 preview、秘密情報警告を実装する（UX-02）。

### P1: 日常作業を不必要に終了させない

1. VM lifetime と Agent Session lifetime を分離する（UX-03）。
2. 設定を recreate-required と session-rotatable に分類する（UX-04）。
3. toolchain profile と限定的な永続 cache を提供する（UX-05）。
4. Web blocklist と許可 origin を、作業損失なしに安全に更新する方法を設ける（UX-07）。

### P2: 操作負担と自己診断性を改善する

1. 承認対象を選択できる host-owned UI と、入力転記を不要にする確認方式を導入する（UX-06）。
2. `doctor`、`version`、拡張された `status` を追加する（UX-08）。
3. `shell` の名称・help・状態維持の期待を実際の挙動へ合わせる（UX-09）。
4. 未使用の initial snapshot を整理する（UX-10）。

## 7. 改善時に維持すべき条件

使いやすさの改善で、次のセキュリティ条件を弱めないことが重要である。

- guest や Project 内のファイルから host policy を緩和できないこと
- host への適用は、検証済み Change Set と明示的な host 操作に限定すること
- Gateway の許可対象、request digest、期限、Session binding を維持すること
- OpenCode server/TUI は正本仕様で固定された同一 v1 系バージョンを使うこと
- Project ごとの VM/upper、認証情報、監査の分離を維持すること
- host 側で許可される操作は [`docs/plan/allowed-host-operations.md`](../allowed-host-operations.md) の範囲に限定すること

## 8. 結論

最も優先すべき問題は、External Git での作業損失リスクと、snapshot 対象を利用者が制御・確認できない点である。これらは単なる操作回数の多さではなく、利用者の成果物や秘密情報へ直接影響する。

その次に、VM、Agent Session、policy の寿命が強く結合しているため、小さな設定変更や TTL 到達でも作業終了を要求される点を改善する価値が高い。承認や Change Set review のセキュリティモデルは維持しつつ、状態の可視化、対象選択、事前診断、入力転記の削減を進めることで、sunaba の隔離性を損なわずに日常利用の負担を大きく減らせる。
