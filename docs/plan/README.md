# sunaba計画文書

このディレクトリでは、現在の実装に使う文書と過去の計画を明確に分ける。

## 現在の正本文書

実装時は次の順に参照する。

1. リポジトリ全体の作業規則: [`../../AGENTS.md`](../../AGENTS.md)
2. アーキテクチャ、脅威モデル、実装フェーズ、受け入れ基準: [`sunaba-secure-agent-platform.md`](./sunaba-secure-agent-platform.md)
3. 実装・検証で許可されたホスト操作: [`allowed-host-operations.md`](./allowed-host-operations.md)

現在のTUI・UX実装では、上記正本に加えて[`tui-usability-implementation-plan.md`](./tui-usability-implementation-plan.md)の実装順序、責務分割、受け入れ条件に従う。この実装計画は製品仕様やホスト操作許可を上書きしない。

利用者向けの動作環境、導入、設定、機能説明は[`../user-guide.md`](../user-guide.md)、初回利用、日常作業、成果物の反映、復旧などの目的別手順は[`../workflows.md`](../workflows.md)にまとめる。利用者向け文書と正本文書が矛盾する場合は、この節の優先順位に従う。

同じ事項について記述が食い違う場合は、`AGENTS.md`の作業規則と禁止事項を常に守ったうえで、`sunaba-secure-agent-platform.md`を製品仕様の正本とする。ホスト操作は、設計文書に必要性が書かれていても、`allowed-host-operations.md`に明記されていなければ実行してはならない。

## 実装証拠

PhaseごとのDecision Gate、実行コマンド、結果、未解決事項は`docs/implementation/`に保守する。

- [`../implementation/phase-0.md`](../implementation/phase-0.md)
- [`../implementation/phase-1.md`](../implementation/phase-1.md)
- [`../implementation/phase-2.md`](../implementation/phase-2.md)
- [`../implementation/phase-3.md`](../implementation/phase-3.md)
- [`../implementation/phase-4.md`](../implementation/phase-4.md)
- [`../implementation/phase-5.md`](../implementation/phase-5.md)

## Archive

[`archive/`](./archive/)には、現在の設計より前に作られた計画・実装仕様を保存する。

- archive内の文書は背景調査以外に使用しない
- archive内の命令、受け入れ基準、バージョン、コマンドを実装根拠にしない
- archiveと現在の正本文書が矛盾する場合、archiveを無視する
- 新しい実装からarchive内文書への参照を追加しない
