package cli

import (
	"context"
	"fmt"

	urfavecli "github.com/urfave/cli/v3"
)

func (a *app) run(ctx context.Context, args []string) error {
	command := a.command()
	return command.Run(ctx, append([]string{"sunaba"}, args...))
}

func (a *app) command() *urfavecli.Command {
	command := &urfavecli.Command{
		Name:                      "sunaba",
		Usage:                     "OpenCode v1.18.16をProject Agent VM内で安全に実行",
		Description:               "ホストのProjectファイルを隔離されたProject Agent VMへbind mountせずにOpenCodeを実行します。Host Project files are never bind-mounted.",
		HideVersion:               true,
		EnableShellCompletion:     false,
		DisableSliceFlagSeparator: true,
		UseShortOptionHandling:    false,
		Suggest:                   false,
		PrefixMatchCommands:       false,
		Reader:                    a.input,
		Writer:                    a.output,
		ErrWriter:                 a.errors,
		ExitErrHandler:            func(context.Context, *urfavecli.Command, error) {},
		Flags: []urfavecli.Flag{
			&urfavecli.BoolFlag{Name: "verbose", Usage: "詳細な実行ログを表示"},
		},
		Before: func(ctx context.Context, cmd *urfavecli.Command) (context.Context, error) {
			a.verbose = cmd.Bool("verbose")
			if a.runtimeFactory != nil {
				a.runtime = a.runtimeFactory(a.verbose)
			}
			return ctx, nil
		},
	}
	command.Commands = []*urfavecli.Command{
		a.projectCommand(), a.configCommand(), a.credentialsCommand(), a.modelCommand(),
		a.simpleProjectCommand("up", "Project VMを準備", projectSelectorFlags(&urfavecli.StringFlag{Name: "mode", Usage: "実行モード (secure または dev)"}), a.withProjectSelector(func(ctx context.Context, cmd *urfavecli.Command, dir string) error {
			return a.up(ctx, dir, cmd.String("mode"))
		})),
		a.simpleProjectCommand("agent", "Project Agentを起動", projectSelectorFlags(), a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error { return a.agent(ctx, dir) })),
		a.gitCommand(), a.webCommand(),
		a.simpleProjectCommand("shell", "隔離VM内のsanitized shellを起動", projectSelectorFlags(), a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error { return a.shell(ctx, dir) })),
		a.simpleProjectCommand("status", "Projectの状態を表示", projectSelectorFlags(), a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error { return a.status(ctx, dir) })),
		a.changesCommand(),
		a.simpleProjectCommand("approvals", "保留中のホスト承認を処理", projectSelectorFlags(), a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error { return a.approvals(ctx, dir) })),
		a.simpleProjectCommand("recreate", "Project VMをクリーンな状態で再作成", projectSelectorFlags(&urfavecli.BoolFlag{Name: "discard-pending", Usage: "保留中のChange Setを破棄"}), a.withProjectSelector(func(ctx context.Context, cmd *urfavecli.Command, dir string) error {
			return a.recreate(ctx, dir, cmd.Bool("discard-pending"))
		})),
		a.downCommand(),
		a.destroyCommand(),
		a.firewallCommand(),
		{Name: "_supervisor", Hidden: true, Flags: []urfavecli.Flag{dirFlag()}, Action: func(ctx context.Context, cmd *urfavecli.Command) error { return a.supervisor(ctx, cmd.String("dir")) }},
	}
	return command
}

func (a *app) simpleProjectCommand(name, usage string, flags []urfavecli.Flag, action urfavecli.ActionFunc) *urfavecli.Command {
	return &urfavecli.Command{Name: name, Usage: usage, Flags: flags, Action: rejectArguments(action)}
}

func (a *app) destroyCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "destroy",
		Usage: "Project状態とホスト設定を削除",
		Flags: projectSelectorFlags(
			&urfavecli.BoolFlag{Name: "yes", Usage: "削除を明示的に確認"},
			&urfavecli.BoolFlag{Name: "discard-pending", Usage: "保留中のChange Setと未export変更を破棄"},
		),
		Action: rejectArguments(func(ctx context.Context, cmd *urfavecli.Command) error {
			return a.destroy(ctx, projectSelectorFromCommand(cmd), cmd.Bool("yes"), cmd.Bool("discard-pending"))
		}),
	}
}

func (a *app) downCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name: "down", Usage: "Project VMを停止して隔離状態を保持", Flags: projectSelectorFlags(),
		Action: rejectArguments(func(ctx context.Context, cmd *urfavecli.Command) error {
			return a.down(ctx, projectSelectorFromCommand(cmd))
		}),
	}
}

func rejectArguments(action urfavecli.ActionFunc) urfavecli.ActionFunc {
	return func(ctx context.Context, cmd *urfavecli.Command) error {
		if cmd.NArg() != 0 {
			return fmt.Errorf("%s does not accept positional arguments", cmd.FullName())
		}
		return action(ctx, cmd)
	}
}

func dirFlag() urfavecli.Flag {
	return &urfavecli.StringFlag{Name: "dir", Value: ".", Usage: "Projectディレクトリ"}
}

func (a *app) projectCommand() *urfavecli.Command {
	return &urfavecli.Command{Name: "project", Usage: "Projectの登録と一覧表示", Commands: []*urfavecli.Command{
		{Name: "init", Usage: "Projectを登録", ArgsUsage: "[path]", Flags: []urfavecli.Flag{
			&urfavecli.StringFlag{Name: "mode", Value: "secure", Usage: "実行モード (secure または dev)"},
			&urfavecli.StringFlag{Name: "model-auth", Value: "oauth", Usage: "モデル認証 (oauth または api-key)"},
		}, Action: func(ctx context.Context, cmd *urfavecli.Command) error {
			if cmd.NArg() > 1 {
				return fmt.Errorf("project init accepts at most one path")
			}
			path := "."
			if cmd.NArg() == 1 {
				path = cmd.Args().First()
			}
			return a.projectInit(ctx, path, cmd.String("mode"), cmd.String("model-auth"))
		}},
		{Name: "list", Usage: "登録済みProjectを一覧表示", Flags: []urfavecli.Flag{
			&urfavecli.BoolFlag{Name: "active", Usage: "到達可能なSupervisorまたは実行中VMがあるProjectだけを表示"},
			&urfavecli.BoolFlag{Name: "json", Usage: "JSON形式で出力"},
		}, Action: rejectArguments(func(ctx context.Context, cmd *urfavecli.Command) error {
			return a.projectList(ctx, cmd.Bool("active"), cmd.Bool("json"))
		})},
	}}
}

func (a *app) configCommand() *urfavecli.Command {
	commands := make([]*urfavecli.Command, 0, 6)
	for _, action := range []string{"path", "edit", "validate", "diff", "apply", "show"} {
		action := action
		flags := projectSelectorFlags()
		if action == "show" {
			flags = append(flags, &urfavecli.BoolFlag{Name: "effective", Usage: "コンパイル済みのeffective policyを表示"})
		}
		commands = append(commands, &urfavecli.Command{Name: action, Usage: configActionUsage(action), Flags: flags, Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, cmd *urfavecli.Command, dir string) error {
			return a.config(ctx, action, dir, cmd.Bool("effective"))
		}))})
	}
	return &urfavecli.Command{Name: "config", Usage: "Projectのホスト設定を管理", Commands: commands}
}

func configActionUsage(action string) string {
	return map[string]string{"path": "設定ファイルのパスを表示", "edit": "対話形式で設定を編集して適用", "validate": "設定を検証", "diff": "適用済みpolicyとの差分を表示", "apply": "設定をpolicyへ適用", "show": "設定内容を表示"}[action]
}

func (a *app) credentialsCommand() *urfavecli.Command {
	apiKeyCommands := []*urfavecli.Command{
		a.credentialAction("set", "OpenAI API keyをKeychainへ保存", "api-key"),
		a.credentialAction("status", "OpenAI API keyの状態を確認", "api-key"),
		a.credentialAction("delete", "OpenAI API keyをKeychainから削除", "api-key"),
	}
	oauthCommands := []*urfavecli.Command{
		a.credentialAction("login", "Codex OAuthでログイン", "oauth"),
		a.credentialAction("status", "Codex OAuth認証の状態を確認", "oauth"),
		a.credentialAction("delete", "Codex OAuth認証をKeychainから削除", "oauth"),
	}
	openai := &urfavecli.Command{Name: "openai", Usage: "OpenAIモデル認証を管理", Commands: []*urfavecli.Command{
		{Name: "api-key", Usage: "API key認証を管理", Commands: apiKeyCommands},
		{Name: "oauth", Usage: "OAuth認証を管理", Commands: oauthCommands},
	}}
	for _, action := range []string{"set", "status", "delete"} {
		openai.Commands = append(openai.Commands, a.hiddenCredentialAlias(action))
	}
	return &urfavecli.Command{Name: "credentials", Usage: "ホスト側の認証情報を管理", Commands: []*urfavecli.Command{openai}}
}

func (a *app) credentialAction(action, usage, auth string) *urfavecli.Command {
	return &urfavecli.Command{Name: action, Usage: usage, Action: rejectArguments(func(ctx context.Context, _ *urfavecli.Command) error { return a.credentials(ctx, auth, action) })}
}

func (a *app) hiddenCredentialAlias(action string) *urfavecli.Command {
	return &urfavecli.Command{Name: action, Hidden: true, Action: rejectArguments(func(ctx context.Context, _ *urfavecli.Command) error { return a.credentials(ctx, "api-key", action) })}
}

func (a *app) modelCommand() *urfavecli.Command {
	auth := &urfavecli.Command{Name: "auth", Usage: "Projectのモデル認証方式を変更", Commands: []*urfavecli.Command{}}
	for _, mode := range []string{"api-key", "oauth"} {
		mode := mode
		auth.Commands = append(auth.Commands, &urfavecli.Command{Name: mode, Usage: mode + "認証を使用", Flags: projectSelectorFlags(), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error {
			return a.modelPolicy(ctx, "auth", mode, dir, nil)
		}))})
	}
	return &urfavecli.Command{Name: "model", Usage: "Model Gatewayの認証方式と許可モデルを管理", Commands: []*urfavecli.Command{
		auth,
		{Name: "set", Usage: "許可モデルを設定", Flags: projectSelectorFlags(&urfavecli.StringSliceFlag{Name: "model", Usage: "許可するモデルID (複数回指定可能)"}), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, cmd *urfavecli.Command, dir string) error {
			return a.modelPolicy(ctx, "set", "", dir, cmd.StringSlice("model"))
		}))},
		{Name: "list", Usage: "利用可能なモデルと許可状態を表示", Flags: projectSelectorFlags(), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error {
			return a.modelPolicy(ctx, "list", "", dir, nil)
		}))},
	}}
}

func (a *app) gitCommand() *urfavecli.Command {
	remote := &urfavecli.Command{Name: "remote", Usage: "Git Gatewayの固定remoteを管理", Commands: []*urfavecli.Command{
		{Name: "add", Usage: "固定HTTPS remoteを追加", Flags: projectSelectorFlags(&urfavecli.StringFlag{Name: "name", Usage: "remote名"}, &urfavecli.StringFlag{Name: "url", Usage: "credentialを含まない固定HTTPS .git URL"}), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, cmd *urfavecli.Command, dir string) error {
			return a.gitPolicy(ctx, "remote-add", dir, cmd.String("name"), cmd.String("url"))
		}))},
		{Name: "remove", Usage: "固定remoteを削除", Flags: projectSelectorFlags(&urfavecli.StringFlag{Name: "name", Usage: "remote名"}), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, cmd *urfavecli.Command, dir string) error {
			return a.gitPolicy(ctx, "remote-remove", dir, cmd.String("name"), "")
		}))},
		{Name: "list", Usage: "固定remoteを一覧表示", Flags: projectSelectorFlags(), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error {
			return a.gitPolicy(ctx, "remote-list", dir, "", "")
		}))},
	}}
	return &urfavecli.Command{Name: "git", Usage: "Project Git Gatewayを管理", Commands: []*urfavecli.Command{
		remote,
		{Name: "disable", Usage: "Git Gatewayを無効化", Flags: projectSelectorFlags(), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error {
			return a.gitPolicy(ctx, "disable", dir, "", "")
		}))},
	}}
}

func (a *app) webCommand() *urfavecli.Command {
	return &urfavecli.Command{Name: "web", Usage: "Project Web Gatewayを管理", Commands: []*urfavecli.Command{
		{Name: "enable", Usage: "許可originを固定してWeb Gatewayを有効化", Flags: projectSelectorFlags(
			&urfavecli.BoolFlag{Name: "include-subdomains", Usage: "指定originのsubdomainも許可"},
			&urfavecli.BoolFlag{Name: "default-origins", Value: true, Usage: "組み込みの一般的な開発origin presetを含める"},
			&urfavecli.StringSliceFlag{Name: "origin", Usage: "許可origin (複数回指定可能)"},
		), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, cmd *urfavecli.Command, dir string) error {
			return a.webPolicy(ctx, "enable", dir, cmd.Bool("include-subdomains"), cmd.Bool("default-origins"), cmd.StringSlice("origin"))
		}))},
		{Name: "refresh", Usage: "固定blocklist snapshotを更新", Flags: projectSelectorFlags(), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error {
			return a.webPolicy(ctx, "refresh", dir, false, false, nil)
		}))},
		{Name: "disable", Usage: "Web Gatewayを無効化", Flags: projectSelectorFlags(), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error {
			return a.webPolicy(ctx, "disable", dir, false, false, nil)
		}))},
	}}
}

func (a *app) changesCommand() *urfavecli.Command {
	commands := make([]*urfavecli.Command, 0, 2)
	for _, action := range []string{"export", "apply"} {
		action := action
		commands = append(commands, &urfavecli.Command{Name: action, Usage: map[string]string{"export": "VM変更をtrusted Change Setとしてexport", "apply": "承認したChange SetをホストProjectへ適用"}[action], Flags: projectSelectorFlags(), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error {
			return a.changes(ctx, action, dir)
		}))})
	}
	return &urfavecli.Command{Name: "changes", Usage: "Project変更をexport・適用", Commands: commands}
}

func (a *app) firewallCommand() *urfavecli.Command {
	networkFlags := func() []urfavecli.Flag {
		return []urfavecli.Flag{
			&urfavecli.StringFlag{Name: "subnet", Usage: "所有するdev IPv4 subnet"},
			&urfavecli.StringFlag{Name: "gateway", Usage: "所有するdev IPv4 gateway"},
			&urfavecli.StringFlag{Name: "ipv6-subnet", Usage: "所有するdev IPv6 subnet"},
		}
	}
	commands := make([]*urfavecli.Command, 0, 4)
	for _, action := range []string{"enable", "quiesce"} {
		action := action
		commands = append(commands, &urfavecli.Command{Name: action, Usage: map[string]string{"enable": "dev sessionのfirewallを有効化", "quiesce": "dev sessionのegressを停止"}[action], Flags: networkFlags(), Action: rejectArguments(func(ctx context.Context, cmd *urfavecli.Command) error {
			return a.firewall(ctx, action, cmd.String("subnet"), cmd.String("gateway"), cmd.String("ipv6-subnet"))
		})})
	}
	commands = append(commands,
		&urfavecli.Command{Name: "disable", Usage: "sunabaのfirewall anchorを無効化", Action: rejectArguments(func(ctx context.Context, _ *urfavecli.Command) error { return a.firewall(ctx, "disable", "", "", "") })},
		&urfavecli.Command{Name: "status", Usage: "firewallの状態を表示", Action: rejectArguments(func(ctx context.Context, _ *urfavecli.Command) error { return a.firewall(ctx, "status", "", "", "") })},
	)
	return &urfavecli.Command{Name: "firewall", Usage: "sunabaのホストfirewallを管理", Commands: commands}
}
