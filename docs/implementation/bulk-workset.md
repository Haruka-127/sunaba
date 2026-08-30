# Bulk Work Set実装記録

## 実装した境界

- Project config v5、effective policy v9、pending Work Set v5、Recovery v2、TUI protocol v4
- exact component `node_modules`とliteral/component rule、structural overflowの決定的分類
- Core/Bulk共通partition、bounded summary、canonical Merkle/object digest
- current-user private Bulk Object store、blob検証、hardlink flatten、special file拒否
- Resolution revision、single Apply Plan、Work Set単位のone-shot approval
- unresolved Bulk gate、Normal/Bulk TUI section、bounded CLI/JSON status
- Project transactionとretention finalizationの別journal、crash後のrollback/roll-forward判定
- Review normallyによるderived Work Set、元objectのApply Plan-bound cleanup
- opaque retained ID、exact digest/byte acknowledgement付きdiscard、Project-bound retained dataがあるdestroyの拒否

後方互換性は開発中のため完成条件にしない。runtimeは現行schemaだけを生成し、旧pending schemaを暗黙変換しない。

## Fail-closed gate

Apple Container実機でfull merged copyに依存しない停止VM readout、OverlayFS whiteout/opaque/rename、hardlink、same-filesystem stagingを証明していない。このためdirectory transaction codeは`absent -> directory`までunit test対象として存在するが、製品の`Apply entire directory` actionは無効である。gate未通過を理由にidentity検査を緩めない。

exact Bulk Object capture、pending保存、retention保存のいずれかが失敗した場合、停止VMをRecoveryへ保持する。opaque artifact化とoffline seedは未実装であり、自動importや推測による代替を行わない。

現行export backendは固定上限付きのrootfs export後もguest側`merged-export`への全量copyを使用する。容量不足、timeout、parser失敗では成功扱いせず停止VMをRecoveryへ保持し、実機で安全な停止VM readoutを証明するまでdirectory applyを有効化しない。

## 自動検証

最終結果は[`final-verification.md`](./final-verification.md)へ追記する。Apple Container実機gateは通常unit/race/integration compileと区別し、個別承認なしに実行しない。
