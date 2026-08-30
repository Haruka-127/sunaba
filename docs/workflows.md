# sunaba 利用ワークフロー

この文書は目的別の操作手順です。設定項目と安全上の注意は[ユーザーガイド](./user-guide.md)、保証範囲は[セキュリティ設計・製品仕様](./plan/sunaba-secure-agent-platform.md)を参照してください。

## 初めてのProject

1. Apple Container `1.2.2`を公式手順で導入し、systemを起動します。

   ```sh
   container system start
   container system version
   ```

2. release bundleの`sunaba`、`sunaba-ui`、`sunaba-guest-relay`、`sunaba-git-hook`を同じ`PATH` directoryへ置きます。OpenCode、Bun、Node.js、OpenTUIのglobal installは不要です。

3. Project directoryでTUIを開きます。

   ```sh
   cd /path/to/project
   sunaba
   ```

4. Setupで推奨設定を確認します。Continue前には保存されません。

   - Secure mode
   - OAuth
   - 開発用の標準Web access
   - 検出Git remoteは候補だけ。必要なものだけ選択

5. Continue後、固定OpenCode artifact、bundled `sunaba-ui`、guest artifact、Agent imageが検証・準備されます。OAuth URLとcodeが表示されたら手動でブラウザを開きます。中断した場合はSettingsで再認証できます。

6. 初回VM用のSnapshot metadataをpreviewして承認します。

   ```sh
   sunaba snapshot preview
   sunaba snapshot approve --digest <表示されたexact digest>
   ```

7. `sunaba`へ戻り、Homeの`Start`を選びます。OpenCode終了後は新しいHomeへ戻り、VM内の作業は隔離されたまま保持されます。

## 日常のsecure mode作業

```sh
cd /path/to/project
sunaba
```

Homeで状態に応じて次を選びます。

- `Start`: host Snapshotから新しいVMを作る
- `Resume`: 同じVM workspaceへ新しいAgent Session authorityで戻る
- `Review changes`: pending Change Setを確認する
- `Settings`: AI connection、Web、Git、modeを変更する
- `Recovery`: 停止VMや失敗したexportを安全に回収する

OpenCodeを終了しても自動export、apply、destroyは行いません。作業を続けるならResume、hostへ戻すなら次の手順へ進みます。

## 変更をhostへ反映する

1. VM作業をexportしてpending Change Setを作ります。通常はHomeからChangesへ進みます。CLIでは次を使います。

   ```sh
   sunaba changes export --dir /path/to/project
   ```

2. Changesで変更fileを選択してdiffとriskを確認します。wide terminalはside-by-side、narrow terminalはunifiedです。binary、巨大file、symlink、実行可能file、mode変更の警告を見落とさないでください。

3. 途中で戻ってもpendingは保持されます。適用する場合は`Apply all changes`を選びます。部分適用はなく、表示中のChange Set全体だけが対象です。digestやnonceは入力しません。

CLIでreview/applyする場合:

```sh
sunaba changes review --dir /path/to/project
sunaba changes apply --dir /path/to/project
```

CLI確認では`apply all changes`と入力します。apply後はhost Projectが変わるため、次のVM作成前にSnapshot previewと承認をやり直します。

## AI connectionを変更する

TUIの`Settings > AI connection > Change authentication method`を開きます。通常Settingsにはactive方式と状態だけを表示し、この画面でOAuthとAPI key双方の登録状態を確認できます。

- OAuth: device flowを再実行する
- API key: maskされた欄へ入力する

CLIでは次を使います。

```sh
sunaba credentials openai oauth login
sunaba model auth oauth

# または
sunaba credentials openai api-key set
sunaba model auth api-key
```

方式は全Project共通で、active Sessionは変わりません。次Sessionだけが新しいsnapshotを取得します。選択方式が使えなくても別方式へfallbackしません。

完全削除は高度な廃棄操作です。TUIにSign outはありません。

```sh
sunaba credentials openai oauth delete
sunaba credentials openai api-key delete
```

## Projectごとのmodelを変更する

global認証方式で利用できるcatalogを確認し、Project allowlistだけを変更します。

```sh
sunaba model list --dir /path/to/project
sunaba model set --dir /path/to/project --model gpt-5.5 --model gpt-5.6-sol
```

認証方式と非互換なallowlistはSession開始前に拒否されます。自動置換は行いません。

## Web accessを変更する

通常はSettingsのWeb accessを使います。推奨表示は`Access to standard sites needed for development`です。exact host/port/method、HTTPS CONNECTの検査制限、quotaはSetup Detailsまたは高度な設定で確認します。

CLIで推奨presetを有効化する場合:

```sh
sunaba web enable --default-origins --dir /path/to/project
```

Project固有originを使う場合:

```sh
sunaba web enable \
  --origin https://api.example.com \
  --dir /path/to/project
```

無効化:

```sh
sunaba web disable --dir /path/to/project
```

HTTPS CONNECTは暗号化された内部methodやupload内容を検査できません。許可先へ送信してよい情報だけを扱ってください。

## Git remoteとpush

SetupまたはSettingsはhost local Git設定から安全なHTTPS `.git` URLだけを候補にします。検出だけでは登録せず、選択したremoteだけを保存します。

CLIで登録する場合:

```sh
sunaba git remote add \
  --dir /path/to/project \
  --name origin \
  --url https://github.com/example/repository.git
```

VM内のfetch/pullは固定remoteとquotaの範囲で承認不要です。pushの最初の試行はpending approvalを作って拒否されます。

```sh
git push origin HEAD:refs/heads/main
```

OpenCodeを動かしたまま、別のhost terminalで確認します。

```sh
sunaba approvals --dir /path/to/project
```

remote、ref、old/new object ID、force/deleteを確認してapproveまたはrejectします。approveした場合だけ、VM内で変更を加えず期限内に同じpushを再実行します。OpenCode TUI内の表示だけでは承認になりません。

## 高度なProject設定

resource、quota、TTL、Snapshot除外等はCLI wizardまたはhost-only設定fileで扱います。

```sh
sunaba config edit --dir /path/to/project
sunaba config validate --dir /path/to/project
sunaba config diff --dir /path/to/project
sunaba config apply --dir /path/to/project
```

Git remote候補も最終確認前には保存されません。mode、resource、Snapshot/export境界等の変更はVM再作成を要求します。activeまたはretained VMがある場合は先にexport・reviewし、必要ならrecreateします。

## sanitized consoleとautomation

TUI外でbounded line consoleを開く場合:

```sh
sunaba console --dir /path/to/project
```

`shell`は互換aliasです。raw PTYやhost shell fallbackはありません。

secure modeのargv単発実行:

```sh
sunaba exec --dir /path/to/project --cwd . -- go test ./...
```

non-TTYでは引数なしの`sunaba`を使わず、明示的サブコマンドまたはJSON出力を使います。

```sh
sunaba project list --json
```

## OpenCode v1を更新する

更新は明示的にcheck/applyします。Session開始時の自動更新はありません。

```sh
sunaba versions set 1.x.y
# または sunaba versions track v1-stable
sunaba update check
sunaba project list --active
sunaba update apply
```

checkはexact releaseとartifactをquarantineへ固定するだけで、active lockやProjectを変更しません。apply前にすべてのVMとSupervisorを終了してください。applyはmanaged host OpenCode、guest image、Project policy、host lockをtransactionで切り替えます。

## 直接Internet接続が必要な作業

Web Gatewayでは足りない場合だけSettingsでDevelopment modeを選びます。mode変更前にVMとpending成果物を処理してください。

dev modeはforegroundのAgentまたはconsole中だけ直接egressを許可し、情報流出防止を保証しません。終了時にdeny-allへ戻し、VMをexportして破棄します。exportが拒否された場合だけ、capabilityとnetworkを失効した停止VMをRecoveryへ保持します。

## Recovery

Recovery画面は削除されるもの、保持されるもの、回復不能になる作業、安全な代替actionを表示します。推奨は原因を解消してexportを再試行することです。

```sh
sunaba status --dir /path/to/project
sunaba changes export --dir /path/to/project
```

External Gitのdirty/unpushed状態を意図的に捨ててmain workspaceだけを回収する場合:

```sh
sunaba changes export --discard-external-git --dir /path/to/project
```

VM-only作業やpendingを復元不能にしてよい場合だけ:

```sh
sunaba recreate --dir /path/to/project --discard-pending
sunaba destroy --dir /path/to/project --yes --discard-pending
```

`destroy`はhost Projectを削除しません。元Project directoryがない場合は、完全なProject IDを使います。

```sh
sunaba project list
sunaba destroy --project-id 0123456789ab --yes --discard-pending
```

## 次に読むもの

- 設定、保存場所、残余リスク: [ユーザーガイド](./user-guide.md)
- セキュリティ境界: [セキュリティ設計・製品仕様](./plan/sunaba-secure-agent-platform.md)
- Apple Containerやpfの限定復旧: [ホスト操作の許可範囲](./plan/allowed-host-operations.md)
