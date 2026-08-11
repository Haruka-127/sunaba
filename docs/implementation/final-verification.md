# 最終検証台帳

この台帳はPhase単位の完了記録とは別に、最終終了条件を現在のcode、test、実機resourceへ照合する。`PASS`は記載した再現手順が当該境界を直接検証した場合だけ使う。実装済み、unit test済み、過去の個別gate通過だけでは、最新HEADの最終統合を`PASS`にしない。

## 要件と証拠

| 最終要件 | 実装・再現可能な証拠 | 現在の判定 |
| --- | --- | --- |
| Phase 0〜5成果物 | [`phase-0.md`](./phase-0.md)〜[`phase-5.md`](./phase-5.md)、各`internal/*` unit/race test | 実装済み。最新HEADの通常gateはPASS |
| DG-01 secure network | `TestPhase0SecureNetworkAndGatewayTransport`、`runtime.ValidateSecureSessionSpec` attack test | 個別実機gateの通過記録あり。最終一括再実行待ち |
| DG-02 Snapshot / Overlay / export | `TestPhase0OverlayFreezeAndExportLayout`、`internal/workspace` attack test | 個別実機gateの通過記録あり。最終一括再実行待ち |
| DG-03 OpenCode / Model / Attach / terminal | Phase 0/1 integration、`internal/modelgateway`、`internal/attachrelay`、`internal/opencode`、`internal/trustedui` | 個別実機gateの通過記録あり。最終一括再実行待ち |
| Phase 2 lifecycle / apply / approval | Phase 1/2 integration、`internal/session`、`internal/apply`、`internal/approval`、`internal/lease`、`internal/cleanup` | 個別実機gateの通過記録あり。公開CLI実機gate待ち |
| 永続Project VM / shell / TTL / idle | `TestPublicCLIPersistentSupervisorAndSanitizedShell`、supervisor control unit/race test | 実装・自動test済み。公開CLI実機gate待ち |
| Git Gateway | `TestPhase3GitGatewayInAgentVM`、`internal/gitgateway` smart HTTP/TOCTOU/partial-failure/fuzz test | 個別gateの通過記録あり。最終一括再実行待ち |
| Web Gateway | Phase 4 measurement/integration、`internal/webgateway` attack/compatibility/fuzz test | 個別gateの通過記録あり。最終一括再実行待ち |
| Phase 5 hardening | dependency/provenance、migration、retention/redaction、ENOSPC/reboot/partial failure、4 bounded fuzz target | 自動gateはPASS。dev pf実機gate待ち |
| dev active-session egress | `TestDevSessionNetworkBoundary`がactive public egress、host/LAN/peer/inbound拒否、稼働VMのdeny-all quiesce、stopを検査 | 実装・compile済み。人間承認を伴うsudo実行待ち |
| 最終cleanup / user resource非干渉 | exact nameとowner/project/session labelを再検証するcleanup、最終`container ls` / network / volume inventory | 未完了。stuckしたexact-owned VM 2台の個別復旧承認待ち。`buildkit`は変更禁止 |
| Git運用 | `dev`上の意図別Conventional Commit、`git status`、remote非書込み | 本台帳のcommit後はclean、pushなし。最終操作後に再確認する |

## 最新の非破壊gate

```sh
scripts/verify.sh
SUNABA_FUZZ=1 scripts/verify.sh
```

通常gateはformat、全unit、全race、vet、host binary、Linux/AArch64 guest relay、Git hook、CLI/static unsafe-path boundaryを通過した。bounded fuzzはModel Responses envelope、Git push binding、Web hostname、blocklist parserの4 targetを各10秒実行して通過した。実OpenAI/Git credentialを使うbillable live requestは自動実行せず、mock upstream contractを正とする。

## 未完了の最終手順

1. [`allowed-host-operations.md`](../plan/allowed-host-operations.md)の個別復旧手順について人間の承認を得る。
2. 対応Supervisor/runtime directoryがないことを再確認し、hung client processとexact-owned stuck VMだけを復旧・削除する。`buildkit`、runtime plugin、container system、他resourceを変更しない。
3. 隔離実機gateを実行する。

   ```sh
   SUNABA_INTEGRATION=1 scripts/verify.sh
   ```

4. pf操作の個別承認後、dev gateを実行する。

   ```sh
   SUNABA_INTEGRATION=1 SUNABA_DEV_INTEGRATION=1 scripts/verify.sh
   ```

5. 作成したexact `sunaba-` test resourceをcleanupし、container/network/volume、一時Project、host process、worktreeの最終inventoryを記録する。

上記が完了するまで、最新HEADの最終統合とgoalを完了扱いにしない。
