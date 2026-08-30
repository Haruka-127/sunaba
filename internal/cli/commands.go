package cli

import (
	"context"
	"fmt"
	"time"

	urfavecli "github.com/urfave/cli/v3"

	"sunaba/internal/workspace"
)

func (a *app) run(ctx context.Context, args []string) error {
	command := a.command()
	return command.Run(ctx, append([]string{"sunaba"}, args...))
}

func (a *app) command() *urfavecli.Command {
	command := &urfavecli.Command{
		Name:                      "sunaba",
		Usage:                     "Run a locked OpenCode v1 release securely inside a Project Agent VM",
		Description:               "Runs OpenCode in an isolated Project Agent VM without bind-mounting host Project files. Host Project files are never bind-mounted.",
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
			&urfavecli.BoolFlag{Name: "verbose", Usage: "Show detailed execution logs", OnlyOnce: true},
		},
		Before: func(ctx context.Context, cmd *urfavecli.Command) (context.Context, error) {
			a.verbose = cmd.Bool("verbose")
			if a.runtimeFactory != nil {
				a.runtime = a.runtimeFactory(a.verbose)
			}
			return ctx, nil
		},
		Action: rejectArguments(func(ctx context.Context, _ *urfavecli.Command) error {
			return a.tui(ctx)
		}),
	}
	command.Commands = []*urfavecli.Command{
		a.setupCommand(), a.versionsCommand(), a.updateCommand(),
		a.simpleProjectCommand("doctor", "Run read-only host and Project diagnostics", projectSelectorFlags(), a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error { return a.doctor(ctx, dir) })),
		a.projectCommand(), a.configCommand(), a.credentialsCommand(), a.modelCommand(),
		a.snapshotCommand(),
		a.simpleProjectCommand("up", "Prepare the Project VM", projectSelectorFlags(&urfavecli.StringFlag{Name: "mode", Usage: "Execution mode (secure or dev)", OnlyOnce: true, Validator: optionalEnum("mode", "secure", "dev")}), a.withProjectSelector(func(ctx context.Context, cmd *urfavecli.Command, dir string) error {
			return a.up(ctx, dir, cmd.String("mode"))
		})),
		a.simpleProjectCommand("agent", "Start the Project Agent", projectSelectorFlags(), a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error { return a.agent(ctx, dir) })),
		a.gitCommand(), a.webCommand(),
		{Name: "console", Aliases: []string{"shell"}, Usage: "Start a sanitized console in the isolated VM", Flags: projectSelectorFlags(), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error { return a.shell(ctx, dir) }))},
		a.execCommand(),
		a.simpleProjectCommand("status", "Show Project status", projectSelectorFlags(), a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error { return a.status(ctx, dir) })),
		a.changesCommand(),
		a.simpleProjectCommand("approvals", "Process pending host approvals", projectSelectorFlags(), a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error { return a.approvals(ctx, dir) })),
		a.simpleProjectCommand("recreate", "Recreate the Project VM from a clean state", projectSelectorFlags(&urfavecli.BoolFlag{Name: "discard-pending", Usage: "Discard the pending Change Set"}), a.withProjectSelector(func(ctx context.Context, cmd *urfavecli.Command, dir string) error {
			return a.recreate(ctx, dir, cmd.Bool("discard-pending"))
		})),
		a.downCommand(),
		a.destroyCommand(),
		a.firewallCommand(),
		{Name: "_supervisor", Hidden: true, Flags: []urfavecli.Flag{dirFlag()}, Action: func(ctx context.Context, cmd *urfavecli.Command) error { return a.supervisor(ctx, cmd.String("dir")) }},
	}
	addProjectSelectorConstraints(command)
	return command
}

func (a *app) execCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name: "exec", Usage: "Run one argv-based command in the isolated VM", ArgsUsage: "-- <command> [args...]",
		Flags: projectSelectorFlags(
			&urfavecli.StringFlag{Name: "cwd", Value: ".", Usage: "Guest working directory relative to the Project workspace", OnlyOnce: true},
			&urfavecli.DurationFlag{Name: "timeout", Value: 2 * time.Minute, Usage: "Command timeout (1s-10m)", OnlyOnce: true},
		),
		Action: a.withProjectSelector(func(ctx context.Context, cmd *urfavecli.Command, dir string) error {
			return a.execGuest(ctx, dir, cmd.String("cwd"), cmd.Duration("timeout"), cmd.Args().Slice())
		}),
	}
}

func (a *app) snapshotCommand() *urfavecli.Command {
	return &urfavecli.Command{Name: "snapshot", Usage: "Preview and approve host Project snapshots", Commands: []*urfavecli.Command{
		{Name: "preview", Usage: "Show bounded snapshot metadata without file contents", Flags: projectSelectorFlags(), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error {
			return a.snapshotPreview(dir)
		}))},
		{Name: "approve", Usage: "Approve the exact digest shown by snapshot preview", Flags: projectSelectorFlags(&urfavecli.StringFlag{Name: "digest", Usage: "Exact preview digest", Required: true, OnlyOnce: true}), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, cmd *urfavecli.Command, dir string) error {
			return a.snapshotApprove(dir, cmd.String("digest"))
		}))},
		{Name: "exclude", Usage: "Manage host-only snapshot exclusions", Commands: []*urfavecli.Command{
			{Name: "import-gitignore", Usage: "Import literal .gitignore entries as exclusion candidates", Flags: projectSelectorFlags(), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error {
				return a.snapshotImportGitignore(dir)
			}))},
		}},
	}}
}

func (a *app) simpleProjectCommand(name, usage string, flags []urfavecli.Flag, action urfavecli.ActionFunc) *urfavecli.Command {
	return &urfavecli.Command{Name: name, Usage: usage, Flags: flags, Action: rejectArguments(action)}
}

func (a *app) destroyCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "destroy",
		Usage: "Delete Project state and host configuration",
		Flags: projectSelectorFlags(
			&urfavecli.BoolFlag{Name: "yes", Usage: "Explicitly confirm deletion"},
			&urfavecli.BoolFlag{Name: "discard-pending", Usage: "Discard the pending Change Set and unexported changes"},
		),
		Action: rejectArguments(func(ctx context.Context, cmd *urfavecli.Command) error {
			return a.destroy(ctx, projectSelectorFromCommand(cmd), cmd.Bool("yes"), cmd.Bool("discard-pending"))
		}),
	}
}

func (a *app) downCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name: "down", Usage: "Stop the Project VM while preserving its isolated state", Flags: projectSelectorFlags(),
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
	return &urfavecli.StringFlag{Name: "dir", Value: ".", Usage: "Project directory", Required: true, OnlyOnce: true}
}

func (a *app) projectCommand() *urfavecli.Command {
	return &urfavecli.Command{Name: "project", Usage: "Register and list Projects", Commands: []*urfavecli.Command{
		{Name: "init", Usage: "Register a Project", ArgsUsage: "[path]", Flags: []urfavecli.Flag{
			&urfavecli.StringFlag{Name: "mode", Value: "secure", Usage: "Execution mode (secure or dev)", OnlyOnce: true, Validator: enum("mode", "secure", "dev"), ValidateDefaults: true},
		}, Action: func(ctx context.Context, cmd *urfavecli.Command) error {
			if cmd.NArg() > 1 {
				return fmt.Errorf("project init accepts at most one path")
			}
			path := "."
			if cmd.NArg() == 1 {
				path = cmd.Args().First()
			}
			return a.projectInit(ctx, path, cmd.String("mode"))
		}},
		{Name: "list", Usage: "List registered Projects", Flags: []urfavecli.Flag{
			&urfavecli.BoolFlag{Name: "active", Usage: "Show only Projects with a reachable Supervisor or running VM", OnlyOnce: true},
			&urfavecli.BoolFlag{Name: "json", Usage: "Output as JSON", OnlyOnce: true},
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
			flags = append(flags, &urfavecli.BoolFlag{Name: "effective", Usage: "Show the compiled effective policy", OnlyOnce: true})
		}
		commands = append(commands, &urfavecli.Command{Name: action, Usage: configActionUsage(action), Flags: flags, Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, cmd *urfavecli.Command, dir string) error {
			return a.config(ctx, action, dir, cmd.Bool("effective"))
		}))})
	}
	return &urfavecli.Command{Name: "config", Usage: "Manage host-side Project configuration", Commands: commands}
}

func configActionUsage(action string) string {
	return map[string]string{"path": "Show configuration file paths", "edit": "Interactively edit and apply configuration", "validate": "Validate configuration", "diff": "Show differences from the applied policy", "apply": "Apply configuration to the policy", "show": "Show configuration"}[action]
}

func (a *app) credentialsCommand() *urfavecli.Command {
	apiKeyCommands := []*urfavecli.Command{
		a.credentialAction("set", "Store the OpenAI API key in the host credential file", "api-key"),
		a.credentialAction("status", "Show OpenAI API key status", "api-key"),
		a.credentialAction("delete", "Delete the OpenAI API key from the host credential file", "api-key"),
	}
	oauthCommands := []*urfavecli.Command{
		a.credentialAction("login", "Log in with Codex OAuth", "oauth"),
		a.credentialAction("status", "Show Codex OAuth status", "oauth"),
		a.credentialAction("delete", "Delete Codex OAuth credentials from the host credential file", "oauth"),
	}
	openai := &urfavecli.Command{Name: "openai", Usage: "Manage OpenAI model authentication", Commands: []*urfavecli.Command{
		{Name: "api-key", Usage: "Manage API key authentication", Commands: apiKeyCommands},
		{Name: "oauth", Usage: "Manage OAuth authentication", Commands: oauthCommands},
	}}
	for _, action := range []string{"set", "status", "delete"} {
		openai.Commands = append(openai.Commands, a.hiddenCredentialAlias(action))
	}
	return &urfavecli.Command{Name: "credentials", Usage: "Manage host-side credentials", Commands: []*urfavecli.Command{openai}}
}

func (a *app) credentialAction(action, usage, auth string) *urfavecli.Command {
	return &urfavecli.Command{Name: action, Usage: usage, Action: rejectArguments(func(ctx context.Context, _ *urfavecli.Command) error { return a.credentials(ctx, auth, action) })}
}

func (a *app) hiddenCredentialAlias(action string) *urfavecli.Command {
	return &urfavecli.Command{Name: action, Hidden: true, Action: rejectArguments(func(ctx context.Context, _ *urfavecli.Command) error { return a.credentials(ctx, "api-key", action) })}
}

func (a *app) modelCommand() *urfavecli.Command {
	auth := &urfavecli.Command{Name: "auth", Usage: "Change the global model authentication method", Commands: []*urfavecli.Command{}}
	for _, mode := range []string{"api-key", "oauth"} {
		mode := mode
		auth.Commands = append(auth.Commands, &urfavecli.Command{Name: mode, Usage: "Use " + mode + " authentication for future Agent Sessions", Action: rejectArguments(func(ctx context.Context, _ *urfavecli.Command) error {
			return a.modelAuth(ctx, mode)
		})})
	}
	return &urfavecli.Command{Name: "model", Usage: "Manage Model Gateway authentication and allowed models", Commands: []*urfavecli.Command{
		auth,
		{Name: "set", Usage: "Set allowed models", Flags: projectSelectorFlags(&urfavecli.StringSliceFlag{Name: "model", Usage: "Allowed model ID (may be specified multiple times)"}), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, cmd *urfavecli.Command, dir string) error {
			return a.modelPolicy(ctx, "set", "", dir, cmd.StringSlice("model"))
		}))},
		{Name: "list", Usage: "Show available models and their allowed status", Flags: projectSelectorFlags(), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error {
			return a.modelPolicy(ctx, "list", "", dir, nil)
		}))},
	}}
}

func (a *app) gitCommand() *urfavecli.Command {
	remote := &urfavecli.Command{Name: "remote", Usage: "Manage pinned Git Gateway remotes", Commands: []*urfavecli.Command{
		{Name: "add", Usage: "Add a pinned HTTPS remote", Flags: projectSelectorFlags(&urfavecli.StringFlag{Name: "name", Usage: "Remote name", Required: true, OnlyOnce: true}, &urfavecli.StringFlag{Name: "url", Usage: "Pinned HTTPS .git URL without credentials", Required: true, OnlyOnce: true}), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, cmd *urfavecli.Command, dir string) error {
			return a.gitPolicy(ctx, "remote-add", dir, cmd.String("name"), cmd.String("url"))
		}))},
		{Name: "remove", Usage: "Remove a pinned remote", Flags: projectSelectorFlags(&urfavecli.StringFlag{Name: "name", Usage: "Remote name", Required: true, OnlyOnce: true}), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, cmd *urfavecli.Command, dir string) error {
			return a.gitPolicy(ctx, "remote-remove", dir, cmd.String("name"), "")
		}))},
		{Name: "list", Usage: "List pinned remotes", Flags: projectSelectorFlags(), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error {
			return a.gitPolicy(ctx, "remote-list", dir, "", "")
		}))},
	}}
	return &urfavecli.Command{Name: "git", Usage: "Manage the Project Git Gateway", Commands: []*urfavecli.Command{
		remote,
		{Name: "disable", Usage: "Disable the Git Gateway", Flags: projectSelectorFlags(), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error {
			return a.gitPolicy(ctx, "disable", dir, "", "")
		}))},
	}}
}

func (a *app) webCommand() *urfavecli.Command {
	return &urfavecli.Command{Name: "web", Usage: "Manage the Project Web Gateway", Commands: []*urfavecli.Command{
		{Name: "enable", Usage: "Enable the Web Gateway with pinned allowed origins", Flags: projectSelectorFlags(
			&urfavecli.BoolFlag{Name: "include-subdomains", Usage: "Also allow subdomains of each specified origin", OnlyOnce: true},
			&urfavecli.BoolFlag{Name: "default-origins", Value: true, Usage: "Include the built-in common development origin preset", OnlyOnce: true},
			&urfavecli.StringSliceFlag{Name: "origin", Usage: "Allowed origin (may be specified multiple times)"},
		), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, cmd *urfavecli.Command, dir string) error {
			return a.webPolicy(ctx, "enable", dir, cmd.Bool("include-subdomains"), cmd.Bool("default-origins"), cmd.StringSlice("origin"))
		}))},
		{Name: "refresh", Usage: "Refresh the pinned blocklist snapshot", Flags: projectSelectorFlags(), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error {
			return a.webPolicy(ctx, "refresh", dir, false, false, nil)
		}))},
		{Name: "disable", Usage: "Disable the Web Gateway", Flags: projectSelectorFlags(), Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, _ *urfavecli.Command, dir string) error {
			return a.webPolicy(ctx, "disable", dir, false, false, nil)
		}))},
	}}
}

func (a *app) changesCommand() *urfavecli.Command {
	commands := make([]*urfavecli.Command, 0, 3)
	for _, action := range []string{"export", "review", "apply"} {
		action := action
		flags := projectSelectorFlags()
		if action == "export" {
			flags = projectSelectorFlags(&urfavecli.BoolFlag{Name: "discard-external-git", Usage: "Explicitly discard guarded External Git state after exporting the main workspace", OnlyOnce: true})
		}
		if action == "review" {
			flags = projectSelectorFlags(
				&urfavecli.BoolFlag{Name: "stat", Usage: "Show metadata and risk summary without file content", OnlyOnce: true},
				&urfavecli.StringFlag{Name: "path", Usage: "Review one exact Change Set path (apply still applies the entire set)", OnlyOnce: true},
				&urfavecli.IntFlag{Name: "context", Value: workspace.DefaultReviewContext, Usage: "Unified diff context lines (0-20)", OnlyOnce: true},
			)
		}
		commands = append(commands, &urfavecli.Command{Name: action, Usage: map[string]string{"export": "Export VM changes as a trusted Change Set", "review": "Safely review a pending Change Set before host apply", "apply": "Review and apply an approved Change Set to the host Project"}[action], Flags: flags, Action: rejectArguments(a.withProjectSelector(func(ctx context.Context, cmd *urfavecli.Command, dir string) error {
			return a.changes(ctx, action, dir, workspace.ReviewOptions{Context: cmd.Int("context"), StatOnly: cmd.Bool("stat"), Path: cmd.String("path")}, cmd.Bool("discard-external-git"))
		}))})
	}
	return &urfavecli.Command{Name: "changes", Usage: "Export, review, and apply Project changes", Commands: commands}
}

func (a *app) firewallCommand() *urfavecli.Command {
	networkFlags := func() []urfavecli.Flag {
		return []urfavecli.Flag{
			&urfavecli.StringFlag{Name: "subnet", Usage: "Owned dev IPv4 subnet", Required: true, OnlyOnce: true},
			&urfavecli.StringFlag{Name: "gateway", Usage: "Owned dev IPv4 gateway", Required: true, OnlyOnce: true},
			&urfavecli.StringFlag{Name: "ipv6-subnet", Usage: "Owned dev IPv6 subnet", Required: true, OnlyOnce: true},
		}
	}
	commands := make([]*urfavecli.Command, 0, 4)
	for _, action := range []string{"enable", "quiesce"} {
		action := action
		commands = append(commands, &urfavecli.Command{Name: action, Usage: map[string]string{"enable": "Enable the firewall for a dev session", "quiesce": "Stop egress for a dev session"}[action], Flags: networkFlags(), Action: rejectArguments(func(ctx context.Context, cmd *urfavecli.Command) error {
			return a.firewall(ctx, action, cmd.String("subnet"), cmd.String("gateway"), cmd.String("ipv6-subnet"))
		})})
	}
	commands = append(commands,
		&urfavecli.Command{Name: "disable", Usage: "Disable sunaba's firewall anchor", Action: rejectArguments(func(ctx context.Context, _ *urfavecli.Command) error { return a.firewall(ctx, "disable", "", "", "") })},
		&urfavecli.Command{Name: "status", Usage: "Show firewall status", Action: rejectArguments(func(ctx context.Context, _ *urfavecli.Command) error { return a.firewall(ctx, "status", "", "", "") })},
	)
	return &urfavecli.Command{Name: "firewall", Usage: "Manage sunaba's host firewall", Commands: commands}
}

func enum(name string, allowed ...string) func(string) error {
	return func(value string) error {
		for _, candidate := range allowed {
			if value == candidate {
				return nil
			}
		}
		return fmt.Errorf("%s must be one of %v", name, allowed)
	}
}

func optionalEnum(name string, allowed ...string) func(string) error {
	validate := enum(name, allowed...)
	return func(value string) error {
		if value == "" {
			return nil
		}
		return validate(value)
	}
}
