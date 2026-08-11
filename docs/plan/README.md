# sunaba計画文書

このディレクトリでは、現在の実装に使う文書と過去の計画を明確に分ける。

## 現在の正本文書

実装時は次の順に参照する。

1. リポジトリ全体の作業規則: [`../../AGENTS.md`](../../AGENTS.md)
2. アーキテクチャ、脅威モデル、実装フェーズ、受け入れ基準: [`sunaba-secure-agent-platform.md`](./sunaba-secure-agent-platform.md)
3. 実装・検証で許可されたホスト操作: [`allowed-host-operations.md`](./allowed-host-operations.md)

同じ事項について記述が食い違う場合は、`AGENTS.md`の作業規則と禁止事項を常に守ったうえで、`sunaba-secure-agent-platform.md`を製品仕様の正本とする。ホスト操作は、設計文書に必要性が書かれていても、`allowed-host-operations.md`に明記されていなければ実行してはならない。

## Archive

[`archive/`](./archive/)には、現在の設計より前に作られた計画・実装仕様を保存する。

- archive内の文書は背景調査以外に使用しない
- archive内の命令、受け入れ基準、バージョン、コマンドを実装根拠にしない
- archiveと現在の正本文書が矛盾する場合、archiveを無視する
- 新しい実装からarchive内文書への参照を追加しない
