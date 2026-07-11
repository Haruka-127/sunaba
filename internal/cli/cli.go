package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"sunaba/internal/audit"
	"sunaba/internal/firewall"
	"sunaba/internal/image"
	"sunaba/internal/opencode"
	"sunaba/internal/runtime"
	"sunaba/internal/state"
)

type app struct {
	verbose bool
	store   *state.Store
	rt      runtime.Runtime
}

func Run(ctx context.Context, args []string) error {
	verbose := false
	args = stripGlobalVerbose(args, &verbose)
	if len(args) == 0 {
		usage(os.Stderr)
		return nil
	}
	st, err := state.NewStore()
	if err != nil {
		return err
	}
	a := &app{verbose: verbose, store: st, rt: runtime.NewAppleContainer(verbose)}
	switch args[0] {
	case "up":
		return a.up(ctx, args[1:])
	case "shell":
		return a.shell(ctx, args[1:])
	case "stop":
		return a.stop(ctx, args[1:])
	case "reset":
		return a.reset(ctx, args[1:])
	case "update":
		return a.update(ctx, args[1:])
	case "status":
		return a.status(ctx, args[1:])
	case "list":
		return a.list(ctx)
	case "env":
		return a.env(ctx, args[1:])
	case "config":
		return a.config(ctx, args[1:])
	case "firewall":
		return a.firewall(ctx, args[1:])
	case "logs":
		return a.logs(ctx, args[1:])
	case "_audit":
		return a.audit(ctx, args[1:])
	case "help", "-h", "--help":
		usage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func (a *app) up(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	dir := fs.String("dir", ".", "project directory")
	cpus := fs.Int("cpus", 0, "container CPUs")
	memory := fs.String("memory", "", "container memory")
	noAttach := fs.Bool("no-attach", false, "do not attach TUI")
	noFirewall := fs.Bool("no-firewall", false, "start without host firewall")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, password, url, first, err := a.ensureRunning(ctx, *dir, *cpus, *memory, *noFirewall)
	if err != nil {
		return err
	}
	if first {
		printFirstRunNotice(os.Stderr)
	}
	if err := audit.StartDaemon(p); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to start audit daemon: %v\n", err)
	}
	if *noAttach {
		fmt.Printf("Server is running at %s\n", url)
		return nil
	}
	err = opencode.Attach(ctx, url, p.Cfg.Path, password)
	fmt.Println("Server keeps running. Use 'sunaba stop' to stop it.")
	return err
}

func (a *app) shell(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("shell", flag.ContinueOnError)
	dir := fs.String("dir", ".", "project directory")
	noFirewall := fs.Bool("no-firewall", false, "start without host firewall")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, _, _, _, err := a.ensureRunning(ctx, *dir, 0, "", *noFirewall)
	if err != nil {
		return err
	}
	return containerExecShell(ctx, p.Cfg.Container, p.Cfg.Path)
}

func (a *app) stop(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	dir := fs.String("dir", ".", "project directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, _, err := a.project(*dir)
	if err != nil {
		return err
	}
	audit.StopDaemon(p.AuditPIDPath())
	stt, err := a.rt.ContainerState(ctx, p.Cfg.Container)
	if err != nil {
		return err
	}
	if stt == runtime.StateRunning {
		if err := a.rt.Stop(ctx, p.Cfg.Container); err != nil {
			return err
		}
	}
	fmt.Println("Stopped.")
	return nil
}

func (a *app) reset(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("reset", flag.ContinueOnError)
	dir := fs.String("dir", ".", "project directory")
	full := fs.Bool("full", false, "remove all project state")
	yes := fs.Bool("yes", false, "skip confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, _, err := a.project(*dir)
	if err != nil {
		return err
	}
	if !*yes && !confirmReset(*full) {
		return fmt.Errorf("reset cancelled")
	}
	audit.StopDaemon(p.AuditPIDPath())
	stt, err := a.rt.ContainerState(ctx, p.Cfg.Container)
	if err != nil {
		return err
	}
	if stt == runtime.StateRunning {
		if err := a.rt.Stop(ctx, p.Cfg.Container); err != nil {
			return err
		}
	}
	if stt != runtime.StateNotFound {
		if err := a.rt.Remove(ctx, p.Cfg.Container); err != nil {
			return err
		}
	}
	if *full {
		if err := p.RemoveFull(); err != nil {
			return err
		}
	}
	fmt.Println("Reset complete. Run 'sunaba up' to recreate the environment.")
	return nil
}

func (a *app) update(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	version := fs.String("opencode-version", "", "OpenCode version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := a.store.Init(); err != nil {
		return err
	}
	v := *version
	var err error
	if v == "" {
		v, err = image.LatestVersion(ctx)
		if err != nil {
			return err
		}
	}
	if err := image.Build(ctx, a.rt, v); err != nil {
		return err
	}
	cfg, err := a.store.LoadGlobal()
	if err != nil {
		return err
	}
	cfg.ImageVersion = v
	if err := a.store.SaveGlobal(cfg); err != nil {
		return err
	}
	fmt.Printf("Built %s. Existing environments will use it after reset.\n", image.Tag(v))
	return nil
}

func (a *app) status(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	dir := fs.String("dir", ".", "project directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, _, err := a.project(*dir)
	if err != nil {
		return err
	}
	g, _ := a.store.LoadGlobal()
	projectFirewall, _ := state.NormalizeProjectFirewallMode(p.Cfg.FirewallMode)
	globalFirewall, _ := state.NormalizeGlobalFirewallMode(g.FirewallMode)
	effectiveFirewall := state.FirewallEnabled
	if state.EffectiveFirewallDisabled(g, p.Cfg) {
		effectiveFirewall = state.FirewallDisabled
	}
	info, err := a.rt.Inspect(ctx, p.Cfg.Container)
	if err != nil {
		info = runtime.Info{Name: p.Cfg.Container, State: runtime.StateNotFound}
	}
	hostVer, _ := opencode.HostVersion(ctx)
	fw, _ := firewall.Status(ctx)
	fmt.Printf("Project: %s\nProject ID: %s\nState dir: %s\nContainer: %s (%s)\nIP: %s\nImage version: %s\nLatest image: %s\nHost opencode: %s\nFirewall config: effective=%s project=%s global=%s\nFirewall: %s\nAudit: %v\nLogs: %s\n",
		p.Cfg.Path, p.ID, p.Dir, p.Cfg.Container, info.State, info.IP, p.Cfg.ImageVersion, g.ImageVersion, hostVer, effectiveFirewall, projectFirewall, globalFirewall, firstLine(fw), audit.Running(p.AuditPIDPath()), p.AuditLogDir())
	if info.IP != "" {
		if pass, err := p.Password(); err == nil {
			if h, err := opencode.GetHealth(ctx, "http://"+info.IP+":4096", pass); err == nil {
				fmt.Printf("Server health: ok version=%s\n", h.Version)
				if g.ImageVersion != "" && opencode.CompareVersion(p.Cfg.ImageVersion, g.ImageVersion) != 0 {
					fmt.Println("Warning: a newer/different base image is available. Run 'sunaba reset' to apply it.")
				}
			}
		}
	}
	return nil
}

func (a *app) list(ctx context.Context) error {
	ps, err := a.store.Projects()
	if err != nil {
		return err
	}
	fmt.Printf("%-12s %-20s %-8s %s\n", "PROJECT ID", "CONTAINER", "STATE", "PATH")
	for _, p := range ps {
		stt, _ := a.rt.ContainerState(ctx, p.Cfg.Container)
		fmt.Printf("%-12s %-20s %-8s %s\n", p.ID, p.Cfg.Container, stt, p.Cfg.Path)
	}
	return nil
}

func (a *app) env(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sunaba env set KEY=VALUE... | unset KEY... | list [--dir PATH]")
	}
	dir, rest, err := extractDir(args)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return fmt.Errorf("usage: sunaba env set KEY=VALUE... | unset KEY... | list [--dir PATH]")
	}
	p, _, err := a.project(dir)
	if err != nil {
		return err
	}
	env, err := p.ReadEnv()
	if err != nil {
		return err
	}
	switch rest[0] {
	case "set":
		for _, kv := range rest[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || k == "" {
				return fmt.Errorf("invalid KEY=VALUE: %s", kv)
			}
			env[k] = v
		}
		if err := p.WriteEnv(env); err != nil {
			return err
		}
		a.warnResetIfRunning(ctx, p)
	case "unset":
		for _, k := range rest[1:] {
			delete(env, k)
		}
		if err := p.WriteEnv(env); err != nil {
			return err
		}
		a.warnResetIfRunning(ctx, p)
	case "list":
		for k, v := range env {
			fmt.Printf("%s=%s\n", k, state.MaskValue(v))
		}
	default:
		return fmt.Errorf("unknown env action %q", rest[0])
	}
	return nil
}

func (a *app) config(_ context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sunaba config firewall [enabled|disabled|inherit] [--global] [--dir PATH]")
	}
	switch args[0] {
	case "firewall":
		return a.configFirewall(args[1:])
	default:
		return fmt.Errorf("unknown config key %q", args[0])
	}
}

func (a *app) configFirewall(args []string) error {
	mode := ""
	dir := "."
	globalScope := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--global":
			globalScope = true
		case "--dir":
			if i+1 >= len(args) {
				return fmt.Errorf("--dir requires a value")
			}
			dir = args[i+1]
			i++
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("unknown config firewall option %q", args[i])
			}
			if mode != "" {
				return fmt.Errorf("usage: sunaba config firewall [enabled|disabled|inherit] [--global] [--dir PATH]")
			}
			mode = args[i]
		}
	}
	if globalScope {
		return a.configGlobalFirewall(mode)
	}
	return a.configProjectFirewall(dir, mode)
}

func (a *app) configGlobalFirewall(mode string) error {
	cfg, err := a.store.LoadGlobal()
	if err != nil {
		return err
	}
	if mode == "" {
		current, err := state.NormalizeGlobalFirewallMode(cfg.FirewallMode)
		if err != nil {
			return err
		}
		fmt.Printf("Global firewall: %s\n", current)
		return nil
	}
	normalized, err := state.NormalizeGlobalFirewallMode(mode)
	if err != nil {
		return err
	}
	cfg.FirewallMode = normalized
	if err := a.store.SaveGlobal(cfg); err != nil {
		return err
	}
	if normalized == state.FirewallDisabled {
		fmt.Println("Global firewall: disabled. Projects inherit this unless they set firewall enabled.")
	} else {
		fmt.Println("Global firewall: enabled.")
	}
	return nil
}

func (a *app) configProjectFirewall(dir, mode string) error {
	p, _, err := a.project(dir)
	if err != nil {
		return err
	}
	global, err := a.store.LoadGlobal()
	if err != nil {
		return err
	}
	if mode == "" {
		projectMode, err := state.NormalizeProjectFirewallMode(p.Cfg.FirewallMode)
		if err != nil {
			return err
		}
		globalMode, _ := state.NormalizeGlobalFirewallMode(global.FirewallMode)
		effective := state.FirewallEnabled
		if state.EffectiveFirewallDisabled(global, p.Cfg) {
			effective = state.FirewallDisabled
		}
		fmt.Printf("Project: %s\nProject firewall: %s\nGlobal firewall: %s\nEffective firewall: %s\n", p.Cfg.Path, projectMode, globalMode, effective)
		return nil
	}
	normalized, err := state.NormalizeProjectFirewallMode(mode)
	if err != nil {
		return err
	}
	if normalized == state.FirewallInherit {
		p.Cfg.FirewallMode = ""
	} else {
		p.Cfg.FirewallMode = normalized
	}
	if err := p.Save(); err != nil {
		return err
	}
	effective := state.FirewallEnabled
	if state.EffectiveFirewallDisabled(global, p.Cfg) {
		effective = state.FirewallDisabled
	}
	fmt.Printf("Project firewall: %s. Effective firewall: %s\n", normalized, effective)
	return nil
}

func (a *app) firewall(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sunaba firewall enable | disable | status")
	}
	switch args[0] {
	case "enable":
		fs := flag.NewFlagSet("firewall enable", flag.ContinueOnError)
		iface := fs.String("interface", "", "detected container network interface")
		subnet := fs.String("subnet", "", "detected container subnet")
		gateway := fs.String("gateway", "", "detected container gateway")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		var n firewall.Network
		var err error
		if *iface != "" || *subnet != "" || *gateway != "" {
			if *iface == "" || *subnet == "" || *gateway == "" {
				return fmt.Errorf("--interface, --subnet, and --gateway must be specified together")
			}
			n = firewall.Network{Interface: *iface, Subnet: *subnet, Gateway: *gateway}
		} else {
			n, err = firewall.Detect(ctx, a.store.Root, "")
			if err != nil {
				return err
			}
		}
		return firewall.Enable(ctx, n)
	case "disable":
		return firewall.Disable(ctx)
	case "status":
		out, err := firewall.Status(ctx)
		fmt.Println(out)
		return err
	default:
		return fmt.Errorf("unknown firewall action %q", args[0])
	}
}

func (a *app) logs(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	dir := fs.String("dir", ".", "project directory")
	follow := fs.Bool("f", false, "follow")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, _, err := a.project(*dir)
	if err != nil {
		return err
	}
	path := filepath.Join(p.AuditLogDir(), "audit-"+time.Now().Format("20060102")+".jsonl")
	fmt.Println(path)
	if !*follow {
		b, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(b)
		return err
	}
	return followFile(ctx, path, os.Stdout)
}

func (a *app) audit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("_audit", flag.ContinueOnError)
	id := fs.String("project", "", "project ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("--project is required")
	}
	return audit.Run(ctx, a.store, a.rt, *id)
}

func (a *app) ensureRunning(ctx context.Context, dir string, cpus int, memory string, noFirewall bool) (*state.Project, string, string, bool, error) {
	if err := opencode.CheckPrerequisites(ctx); err != nil {
		return nil, "", "", false, err
	}
	if err := a.store.Init(); err != nil {
		return nil, "", "", false, err
	}
	version, err := image.Ensure(ctx, a.rt, a.store, "")
	if err != nil {
		return nil, "", "", false, err
	}
	p, first, err := a.store.ProjectByPath(dir)
	if err != nil {
		return nil, "", "", false, err
	}
	first2, err := p.Ensure(version, cpus, memory)
	if err != nil {
		return nil, "", "", false, err
	}
	first = first || first2
	if p.Cfg.ImageVersion == "" {
		p.Cfg.ImageVersion = version
	}
	password, err := p.Password()
	if err != nil {
		return nil, "", "", first, err
	}
	stt, err := a.rt.ContainerState(ctx, p.Cfg.Container)
	if err != nil {
		return nil, "", "", first, err
	}
	switch stt {
	case runtime.StateNotFound:
		if err := a.createContainer(ctx, p, password, version); err != nil {
			return nil, "", "", first, err
		}
		p.Cfg.ImageVersion = version
		if err := p.Save(); err != nil {
			return nil, "", "", first, err
		}
	case runtime.StateStopped:
		if err := a.rt.Start(ctx, p.Cfg.Container); err != nil {
			return nil, "", "", first, err
		}
	}
	ip, err := a.rt.IPAddress(ctx, p.Cfg.Container)
	if err != nil {
		return nil, "", "", first, err
	}
	global, _ := a.store.LoadGlobal()
	configDisablesFirewall := state.EffectiveFirewallDisabled(global, p.Cfg)
	if noFirewall {
		fmt.Fprintln(os.Stderr, "warning: firewall disabled by --no-firewall; container may reach host services")
	} else if configDisablesFirewall {
		fmt.Fprintln(os.Stderr, "warning: firewall disabled by configuration; container may reach host services")
	} else if !firewall.IsLoaded(ctx) {
		n, err := firewall.Detect(ctx, a.store.Root, ip)
		if err != nil {
			return nil, "", "", first, err
		}
		if err := firewall.Enable(ctx, n); err != nil {
			return nil, "", "", first, fmt.Errorf("failed to enable firewall; rerun with sudo-capable terminal or use --no-firewall only if you accept the risk: %w", err)
		}
	}
	url := "http://" + ip + ":4096"
	h, err := opencode.WaitHealth(ctx, url, password, 90*time.Second)
	if err != nil {
		return nil, "", "", first, err
	}
	if host, err := opencode.HostVersion(ctx); err == nil && h.Version != "" && host != h.Version {
		fmt.Fprintf(os.Stderr, "warning: host opencode version %s differs from server version %s\n", host, h.Version)
	}
	if global.ImageVersion != "" && p.Cfg.ImageVersion != "" && p.Cfg.ImageVersion != global.ImageVersion {
		fmt.Fprintln(os.Stderr, "warning: a newer/different image is available. Run 'sunaba reset' to apply it.")
	}
	return p, password, url, first, nil
}

func (a *app) createContainer(ctx context.Context, p *state.Project, password, version string) error {
	extra := map[string]string{
		"SUNABA_UID":                  strconv.Itoa(os.Getuid()),
		"SUNABA_GID":                  strconv.Itoa(os.Getgid()),
		"SUNABA_WORKDIR":              p.Cfg.Path,
		"OPENCODE_DISABLE_AUTOUPDATE": "1",
	}
	if p.Cfg.Proxy != "" {
		extra["HTTP_PROXY"] = p.Cfg.Proxy
		extra["HTTPS_PROXY"] = p.Cfg.Proxy
		extra["NO_PROXY"] = "localhost,127.0.0.1"
	}
	envFile, cleanup, err := state.EnvFileForContainer(p, password, extra)
	if err != nil {
		return err
	}
	defer cleanup()
	spec := runtime.ContainerSpec{
		Name:   p.Cfg.Container,
		Image:  image.Tag(version),
		CPUs:   p.Cfg.CPUs,
		Memory: p.Cfg.Memory,
		Mounts: []runtime.Mount{
			{Source: p.Cfg.Path, Target: p.Cfg.Path},
			{Source: filepath.Join(p.Dir, "opencode-data"), Target: "/home/agent/.local/share/opencode"},
			{Source: filepath.Join(p.Dir, "opencode-config"), Target: "/home/agent/.config/opencode"},
		},
		EnvFiles: []string{envFile},
		Labels:   map[string]string{"dev.sunaba.project": p.ID},
	}
	return a.rt.Create(ctx, spec)
}

func (a *app) project(dir string) (*state.Project, bool, error) {
	if err := a.store.Init(); err != nil {
		return nil, false, err
	}
	p, first, err := a.store.ProjectByPath(dir)
	if err != nil {
		return nil, false, err
	}
	if first {
		if _, err := p.Ensure("", 0, ""); err != nil {
			return nil, false, err
		}
	}
	return p, first, nil
}

func (a *app) warnResetIfRunning(ctx context.Context, p *state.Project) {
	if stt, _ := a.rt.ContainerState(ctx, p.Cfg.Container); stt == runtime.StateRunning {
		fmt.Println("Environment variables are applied when the container is created. Run 'sunaba reset' to apply.")
	}
}

func stripGlobalVerbose(args []string, verbose *bool) []string {
	out := args[:0]
	for _, a := range args {
		if a == "--verbose" {
			*verbose = true
			continue
		}
		out = append(out, a)
	}
	return out
}

func extractDir(args []string) (string, []string, error) {
	dir := "."
	var rest []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--dir" {
			if i+1 >= len(args) {
				return "", nil, fmt.Errorf("--dir requires a value")
			}
			dir = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	return dir, rest, nil
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `sunaba commands:
  up [--dir PATH] [--cpus N] [--memory SIZE] [--no-attach] [--no-firewall]
  shell [--dir PATH] [--no-firewall]
  stop [--dir PATH]
  reset [--dir PATH] [--full] [--yes]
  update [--opencode-version X.Y.Z]
  status [--dir PATH]
  list
  env set KEY=VALUE... | unset KEY... | list [--dir PATH]
  config firewall [enabled|disabled|inherit] [--global] [--dir PATH]
  firewall enable | disable | status
  logs [--dir PATH] [-f]`)
}

func printFirstRunNotice(w io.Writer) {
	fmt.Fprintln(w, `Security notice:
- Use low-privilege LLM API keys dedicated to sunaba and set provider spending limits.
- Files written in the project directory, including git hooks, .vscode, and node_modules, can later be executed by host tools. Review diffs before host-side builds or commits.
- Outbound internet access is allowed; sunaba cannot prevent exfiltration of project contents or credentials stored inside the container.
- Run 'sunaba shell' and then 'opencode auth login' to configure credentials. Auth data is preserved across normal reset.`)
}

func confirmReset(full bool) bool {
	if full {
		fmt.Print("This will remove the container and all project state, including auth, sessions, password, env, and logs. Continue? [y/N] ")
	} else {
		fmt.Print("This will remove only the container. Auth, sessions, env, password, and logs are kept. Continue? [y/N] ")
	}
	in := bufio.NewScanner(os.Stdin)
	if !in.Scan() {
		return false
	}
	ans := strings.ToLower(strings.TrimSpace(in.Text()))
	return ans == "y" || ans == "yes"
}

func followFile(ctx context.Context, path string, w io.Writer) error {
	var offset int64
	for {
		f, err := os.Open(path)
		if err == nil {
			if _, err := f.Seek(offset, io.SeekStart); err == nil {
				n, _ := io.Copy(w, f)
				offset += n
			}
			_ = f.Close()
		} else if !os.IsNotExist(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func containerExecShell(ctx context.Context, container, workdir string) error {
	cmd := exec.CommandContext(ctx, "container", "exec", "--interactive", "--tty", "--user", "agent", "--workdir", workdir, container, "bash", "-l")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
