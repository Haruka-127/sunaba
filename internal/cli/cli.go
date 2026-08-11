package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	hostapply "sunaba/internal/apply"
	"sunaba/internal/approval"
	"sunaba/internal/audit"
	"sunaba/internal/cleanup"
	"sunaba/internal/dependency"
	"sunaba/internal/devnetwork"
	"sunaba/internal/firewall"
	"sunaba/internal/image"
	"sunaba/internal/modelgateway"
	"sunaba/internal/opencode"
	"sunaba/internal/policy"
	"sunaba/internal/runtime"
	"sunaba/internal/session"
	"sunaba/internal/state"
	"sunaba/internal/trustedui"
	"sunaba/internal/workspace"
)

type app struct {
	verbose bool
	store   *state.Store
	runtime runtime.Runtime
	input   io.Reader
	output  io.Writer
	errors  io.Writer
}

func Run(ctx context.Context, args []string) error {
	verbose := false
	filtered := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "--verbose" {
			verbose = true
			continue
		}
		filtered = append(filtered, arg)
	}
	if len(filtered) == 0 {
		usage(os.Stdout)
		return nil
	}
	store, err := state.NewStore()
	if err != nil {
		return err
	}
	a := &app{verbose: verbose, store: store, runtime: runtime.NewAppleContainer(verbose), input: os.Stdin, output: os.Stdout, errors: os.Stderr}
	switch filtered[0] {
	case "project":
		return a.project(ctx, filtered[1:])
	case "up":
		return a.up(ctx, filtered[1:])
	case "agent":
		return a.agent(ctx, filtered[1:])
	case "shell":
		return a.shell(filtered[1:])
	case "status":
		return a.status(ctx, filtered[1:])
	case "changes":
		return a.changes(ctx, filtered[1:])
	case "approvals":
		return a.approvals(filtered[1:])
	case "recreate":
		return a.recreate(ctx, filtered[1:])
	case "down":
		return a.down(ctx, filtered[1:])
	case "destroy":
		return a.destroy(ctx, filtered[1:])
	case "firewall":
		return a.firewall(ctx, filtered[1:])
	case "help", "-h", "--help":
		usage(a.output)
		return nil
	default:
		return fmt.Errorf("unknown command %q; run 'sunaba help'", filtered[0])
	}
}

func usage(output io.Writer) {
	fmt.Fprint(output, `sunaba securely runs OpenCode v1.18.16 in a Project Agent VM.

Usage:
  sunaba project init <path> [--mode secure|dev]
  sunaba up [--dir <path>] [--mode secure|dev]
  sunaba agent [--dir <path>]
  sunaba shell [--dir <path>]
  sunaba status [--dir <path>]
  sunaba changes export [--dir <path>]
  sunaba changes apply [--dir <path>]
  sunaba approvals [--dir <path>]
  sunaba recreate [--dir <path>] [--discard-pending]
  sunaba down [--dir <path>]
  sunaba destroy [--dir <path>] --yes [--discard-pending]

Modes:
  secure  No direct VM network. Model/Git/Web access is possible only through scoped Gateways.
  dev     Direct Internet egress exists only during the Agent Session. Exfiltration prevention is NOT provided;
          host, LAN, inbound, credential, and worktree boundaries remain enforced.

The Host TUI uses an isolated configuration and a loopback Local Attach Relay. Host Project files are never bind-mounted.
`)
}

func (a *app) project(_ context.Context, args []string) error {
	if len(args) == 0 || args[0] != "init" {
		return fmt.Errorf("usage: sunaba project init <path> [--mode secure|dev]")
	}
	if len(args) < 2 || strings.HasPrefix(args[1], "-") {
		return fmt.Errorf("usage: sunaba project init <path> [--mode secure|dev]")
	}
	projectArgument := args[1]
	fs := flag.NewFlagSet("project init", flag.ContinueOnError)
	fs.SetOutput(a.errors)
	mode := fs.String("mode", "secure", "secure or dev")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || (*mode != "secure" && *mode != "dev") {
		return fmt.Errorf("usage: sunaba project init <path> [--mode secure|dev]")
	}
	root, err := state.ResolveProjectPath(projectArgument)
	if err != nil {
		return err
	}
	if err := a.store.Init(); err != nil {
		return err
	}
	projectState := a.projectState(root)
	_, stateStatErr := os.Lstat(projectState)
	stateWasAbsent := errors.Is(stateStatErr, os.ErrNotExist)
	policyPath := filepath.Join(projectState, "policy.json")
	if _, err := os.Lstat(policyPath); err == nil {
		return fmt.Errorf("Project is already registered; use 'sunaba up --mode %s' to change its mode", *mode)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	createdState := false
	defer func() {
		if createdState {
			_ = os.RemoveAll(projectState)
		}
	}()
	manifestDigest, err := dependency.ManifestSHA256()
	if err != nil {
		return err
	}
	pinned := dependency.MustPinned()
	projectPolicy, err := policy.New(root, manifestDigest, dependency.OpenCodeVersion, dependency.AppleContainerVersion, pinned.AgentImage.Tag, *mode, time.Now())
	if err != nil {
		return err
	}
	if err := policy.Save(policyPath, projectPolicy); err != nil {
		return err
	}
	createdState = stateWasAbsent
	initialRoot := filepath.Join(projectState, "initial-snapshot")
	initial, err := workspace.CreateProjectSnapshot(root, initialRoot, workspace.DefaultSnapshotPolicy())
	if err != nil {
		return err
	}
	if err := writePrivateJSON(filepath.Join(projectState, "initial-snapshot.json"), initial); err != nil {
		return err
	}
	createdState = false
	fmt.Fprintf(a.output, "Registered Project %s (%s) in %s mode.\n", projectPolicy.ProjectID, root, projectPolicy.Mode)
	return nil
}

func (a *app) up(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	fs.SetOutput(a.errors)
	dir := fs.String("dir", ".", "Project directory")
	mode := fs.String("mode", "", "secure or dev")
	if err := fs.Parse(args); err != nil {
		return err
	}
	projectPolicy, path, _, err := a.loadPolicy(*dir)
	if err != nil {
		return err
	}
	if *mode != "" {
		if *mode != "secure" && *mode != "dev" {
			return fmt.Errorf("mode must be secure or dev")
		}
		if projectPolicy.Mode != *mode {
			projectPolicy.Mode = *mode
			projectPolicy.UpdatedAt = time.Now().UTC()
			if err := policy.Save(path, projectPolicy); err != nil {
				return err
			}
		}
	}
	if projectPolicy.Mode == "dev" {
		fmt.Fprintln(a.errors, "WARNING: dev mode permits direct Internet egress during the active Agent Session and does not provide exfiltration prevention.")
	}
	if err := opencode.CheckPrerequisites(ctx); err != nil {
		return err
	}
	if _, err := image.Ensure(ctx, a.runtime, a.store, dependency.OpenCodeVersion); err != nil {
		return err
	}
	fmt.Fprintf(a.output, "Project %s is prepared in %s mode. No session network is active; run 'sunaba agent'.\n", projectPolicy.ProjectID, projectPolicy.Mode)
	return nil
}

func (a *app) agent(ctx context.Context, args []string) (returnErr error) {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	fs.SetOutput(a.errors)
	dir := fs.String("dir", ".", "Project directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	projectPolicy, _, projectState, err := a.loadPolicy(*dir)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(projectState, "pending", "change.json")); err == nil {
		return fmt.Errorf("a pending Change Set exists; apply or discard it before starting another Agent Session")
	}
	if len(projectPolicy.Git.Remotes) != 0 {
		return fmt.Errorf("Git remotes are configured but this CLI cannot safely infer host credential routing; remove them or use the tested Git Gateway integration API")
	}
	if projectPolicy.Web.Enabled {
		return fmt.Errorf("Web policy is enabled but its blocklist snapshot must be provisioned by an explicit host policy workflow")
	}
	if err := opencode.CheckPrerequisites(ctx); err != nil {
		return err
	}
	if _, err := image.Ensure(ctx, a.runtime, a.store, dependency.OpenCodeVersion); err != nil {
		return err
	}
	recorder, err := audit.NewRecorder(filepath.Join(a.store.Root, "audit"))
	if err != nil {
		return err
	}
	cleanupResult, err := cleanup.Run(ctx, cleanup.Config{Store: a.store, Runtime: a.runtime, Audit: recorder})
	if err != nil {
		return err
	}
	if len(cleanupResult.Refused) > 0 {
		fmt.Fprintf(a.errors, "WARNING: cleanup refused resources without matching current ownership/lease: %s\n", strings.Join(cleanupResult.Refused, ", "))
	}
	upstreamKey := os.Getenv("OPENAI_API_KEY")
	if upstreamKey == "" {
		return fmt.Errorf("OPENAI_API_KEY is required by the host Model Gateway; it is never copied into the VM, Host TUI, Project, or audit log")
	}
	sessionID, err := newSessionID()
	if err != nil {
		return err
	}
	vmID := "sunaba-" + projectPolicy.ProjectID + "-" + sessionID
	modelToken, err := session.NewSecret()
	if err != nil {
		return err
	}
	serverPassword, err := session.NewSecret()
	if err != nil {
		return err
	}
	expiresAt := time.Now().Add(time.Duration(projectPolicy.Session.TTLSeconds) * time.Second)
	modelID := projectPolicy.Model.AllowedModels[0]
	capability, err := modelgateway.NewCapability(modelToken, projectPolicy.ProjectID, vmID, sessionID, modelID, expiresAt)
	if err != nil {
		return err
	}
	capability.MaxRequests = projectPolicy.Model.MaxRequests
	capability.MaxConcurrent = projectPolicy.Model.MaxConcurrent
	capability.MaxRequestBytes = projectPolicy.Model.MaxRequestBytes
	capability.MaxResponseBytes = projectPolicy.Model.MaxResponseBytes
	gateway, err := modelgateway.New(modelgateway.Config{
		UpstreamBaseURL: "https://api.openai.com", UpstreamAPIKey: upstreamKey, Capability: capability,
		Audit: func(event modelgateway.AuditEvent) {
			_ = recorder.Append(audit.BoundaryEvent{Category: "model", Action: "model.request", Outcome: statusOutcome(event.Status), ProjectID: event.ProjectID, VMID: event.VMID, SessionID: event.SessionID, Details: map[string]string{
				"model": event.Model, "status": fmt.Sprint(event.Status), "request_bytes": fmt.Sprint(event.RequestBytes), "response_bytes": fmt.Sprint(event.ResponseBytes), "reason": event.Reason,
			}})
		},
	})
	if err != nil {
		return err
	}
	provider, err := opencode.BuildModelGatewayConfig(opencode.ModelGatewayProviderConfig{BaseURL: "http://127.0.0.1:4141/v1", Model: modelID, TokenEnv: "SUNABA_MODEL_GATEWAY_TOKEN", ContextLimit: 200_000, OutputLimit: 32_000})
	if err != nil {
		return err
	}
	runtimeBase, err := os.MkdirTemp("", "sunaba-runtime-")
	if err != nil {
		return err
	}
	if err := os.Chmod(runtimeBase, 0700); err != nil {
		return err
	}
	defer os.RemoveAll(runtimeBase)
	guestRelay, err := siblingExecutable("sunaba-guest-relay")
	if err != nil {
		return err
	}
	managedDir, hostOpenCode, err := a.prepareManagedOpenCode(ctx)
	if err != nil {
		return err
	}
	config := session.Config{
		Store: a.store, Runtime: a.runtime, ProjectRoot: projectPolicy.ProjectRoot, RuntimeBase: runtimeBase,
		SessionID: sessionID, Mode: projectPolicy.Mode, Image: projectPolicy.Dependency.AgentImage,
		CPUs: projectPolicy.Resources.CPUs, Memory: projectPolicy.Resources.Memory, DiskBytes: projectPolicy.Resources.DiskBytes,
		ProcessMax: projectPolicy.Resources.ProcessMax, FileSizeMax: projectPolicy.Resources.FileSizeMax, OpenFileMax: projectPolicy.Resources.OpenFileMax,
		GuestRelayBinary: guestRelay, ProviderConfig: provider, ModelGateway: gateway, ModelToken: modelToken,
		ServerPassword: serverPassword, LeaseTTL: time.Duration(projectPolicy.Session.TTLSeconds) * time.Second, Audit: recorder,
	}
	var devBoundary *devnetwork.Boundary
	if projectPolicy.Mode == "dev" {
		fmt.Fprintln(a.errors, "WARNING: starting dev direct egress; exfiltration prevention is not provided.")
		devBoundary, err = devnetwork.Activate(ctx, a.store.Root, projectPolicy.ProjectID, sessionID)
		if err != nil {
			return err
		}
		config.DevNetworkName = devBoundary.Network.Name
		config.DevNetworkVerify = devBoundary.Verify
		config.DevNetworkClose = devBoundary.Close
	}
	active, err := session.Start(ctx, config)
	if err != nil {
		if devBoundary != nil {
			_ = devBoundary.Close(context.Background())
		}
		return err
	}
	destroyed := false
	defer func() {
		if !destroyed {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			returnErr = errors.Join(returnErr, active.Destroy(cleanupContext))
		}
	}()
	tui, err := opencode.BuildHostTUICommand(ctx, opencode.HostTUIConfig{
		Binary: hostOpenCode, ManagedToolDir: managedDir, SessionRoot: active.Root, ServerURL: active.AttachURL,
		GuestWorkspace: active.WorkspacePath, Password: serverPassword,
		ExpectedExecutableSHA256: dependency.MustPinned().OpenCode.Host.ExecutableSHA256,
	}, os.Environ())
	if err != nil {
		return err
	}
	tui.Stdin, tui.Stdout, tui.Stderr = a.input, a.output, a.errors
	tuiErr := tui.Run()
	exportContext, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	result, exportErr := active.StopAndExport(exportContext)
	cancel()
	if exportErr == nil && len(result.ChangeSet.Changes) > 0 {
		pending, persistErr := persistPending(projectState, active, result)
		if persistErr != nil {
			exportErr = persistErr
		} else {
			fmt.Fprintf(a.output, "Exported pending Change Set %s (%d changes). Review with 'sunaba changes export'.\n", pending.ChangeSet.Digest, len(pending.ChangeSet.Changes))
		}
	} else if exportErr == nil {
		fmt.Fprintln(a.output, "Agent Session ended with no Project changes.")
	}
	destroyContext, destroyCancel := context.WithTimeout(context.Background(), 90*time.Second)
	destroyErr := active.Destroy(destroyContext)
	destroyCancel()
	destroyed = destroyErr == nil
	return errors.Join(tuiErr, exportErr, destroyErr)
}

func (a *app) shell(args []string) error {
	fs := flag.NewFlagSet("shell", flag.ContinueOnError)
	fs.SetOutput(a.errors)
	_ = fs.String("dir", ".", "Project directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return fmt.Errorf("guest shell is unavailable until an interactive terminal relay can enforce the tested sanitizer; direct 'container exec' is intentionally not exposed")
}

func (a *app) status(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(a.errors)
	dir := fs.String("dir", ".", "Project directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	projectPolicy, _, projectState, err := a.loadPolicy(*dir)
	if err != nil {
		return err
	}
	containers, listErr := a.runtime.List(ctx)
	states := make([]string, 0)
	if listErr == nil {
		for _, item := range containers {
			if item.Labels["dev.sunaba.owner"] == "sunaba-supervisor" && item.Labels["dev.sunaba.project"] == projectPolicy.ProjectID {
				states = append(states, item.Name+"="+string(item.State)+"/"+item.Labels["dev.sunaba.mode"])
			}
		}
	}
	sort.Strings(states)
	pending := "none"
	if change, pendingErr := loadPending(projectState, projectPolicy.ProjectRoot, projectPolicy.ProjectID); pendingErr == nil {
		pending = fmt.Sprintf("%s (%d changes)", change.ChangeSet.Digest, len(change.ChangeSet.Changes))
	}
	fmt.Fprintf(a.output, "Project: %s\nProject ID: %s\nMode: %s\nPolicy schema: %d\nOpenCode: %s\nApple Container: %s\nAgent image: %s\nSession VMs: %s\nPending Change Set: %s\n",
		projectPolicy.ProjectRoot, projectPolicy.ProjectID, projectPolicy.Mode, projectPolicy.SchemaVersion,
		projectPolicy.Dependency.OpenCode, projectPolicy.Dependency.AppleContainer, projectPolicy.Dependency.AgentImage,
		strings.Join(states, ", "), pending)
	return listErr
}

func (a *app) changes(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sunaba changes export|apply [--dir <path>]")
	}
	fs := flag.NewFlagSet("changes "+args[0], flag.ContinueOnError)
	fs.SetOutput(a.errors)
	dir := fs.String("dir", ".", "Project directory")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	projectPolicy, _, projectState, err := a.loadPolicy(*dir)
	if err != nil {
		return err
	}
	pending, err := loadPending(projectState, projectPolicy.ProjectRoot, projectPolicy.ProjectID)
	if err != nil {
		return err
	}
	switch args[0] {
	case "export":
		fmt.Fprintf(a.output, "Change Set: %s\nBaseline: %s\nMerged: %s\nCreated: %s\n", pending.ChangeSet.Digest, pending.Baseline.Digest, pending.Merged.Digest, pending.CreatedAt.Format(time.RFC3339))
		for _, change := range pending.ChangeSet.Changes {
			if change.Kind == workspace.ChangeRename {
				fmt.Fprintf(a.output, "%s %s <- %s\n", change.Kind, approval.SanitizeText(change.Path), approval.SanitizeText(change.From))
			} else {
				fmt.Fprintf(a.output, "%s %s\n", change.Kind, approval.SanitizeText(change.Path))
			}
		}
		return nil
	case "apply":
		recorder, err := audit.NewRecorder(filepath.Join(a.store.Root, "audit"))
		if err != nil {
			return err
		}
		approvals, err := approval.NewAuditedManager(nil, recorder, pending.ProjectID, pending.VMID, pending.SessionID)
		if err != nil {
			return err
		}
		binding := approval.Binding{ProjectID: pending.ProjectID, BaselineDigest: pending.Baseline.Digest, MergedDigest: pending.Merged.Digest, ChangeSetDigest: pending.ChangeSet.Digest}
		request, err := approvals.NewRequest(binding, fmt.Sprintf("%d paths", len(pending.ChangeSet.Changes)), 5*time.Minute)
		if err != nil {
			return err
		}
		if err := trustedui.ConfirmApply(a.input, a.output, request); err != nil {
			return err
		}
		grant, err := approvals.Confirm(request.Nonce, binding)
		if err != nil {
			return err
		}
		applied, err := hostapply.Apply(hostapply.Config{Store: a.store, ProjectRoot: pending.ProjectRoot, ProjectID: pending.ProjectID, MergedRoot: pending.MergedRoot, Baseline: pending.Baseline, Merged: pending.Merged, ChangeSet: pending.ChangeSet, Approvals: approvals, Grant: grant, Audit: recorder})
		if err != nil {
			return err
		}
		if applied.Digest != pending.Merged.Digest {
			return fmt.Errorf("applied Project digest does not match approved Merged View")
		}
		if err := removePending(projectState); err != nil {
			return err
		}
		fmt.Fprintf(a.output, "Applied Change Set %s.\n", pending.ChangeSet.Digest)
		return nil
	default:
		return fmt.Errorf("unknown changes action %q", args[0])
	}
}

func (a *app) approvals(args []string) error {
	fs := flag.NewFlagSet("approvals", flag.ContinueOnError)
	fs.SetOutput(a.errors)
	dir := fs.String("dir", ".", "Project directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	projectPolicy, _, projectState, err := a.loadPolicy(*dir)
	if err != nil {
		return err
	}
	pending, err := loadPending(projectState, projectPolicy.ProjectRoot, projectPolicy.ProjectID)
	if err != nil {
		fmt.Fprintln(a.output, "No pending host approval requests.")
		return nil
	}
	fmt.Fprintf(a.output, "Pending apply: %s (%d changes). Run 'sunaba changes apply'.\n", pending.ChangeSet.Digest, len(pending.ChangeSet.Changes))
	return nil
}

func (a *app) recreate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("recreate", flag.ContinueOnError)
	fs.SetOutput(a.errors)
	dir := fs.String("dir", ".", "Project directory")
	discard := fs.Bool("discard-pending", false, "discard the pending Change Set")
	if err := fs.Parse(args); err != nil {
		return err
	}
	projectPolicy, _, projectState, err := a.loadPolicy(*dir)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(projectState, "pending", "change.json")); err == nil && !*discard {
		return fmt.Errorf("pending Change Set exists; export/apply it or pass --discard-pending explicitly")
	}
	if *discard {
		if err := removePending(projectState); err != nil {
			return err
		}
	}
	if err := a.cleanupOrphans(ctx); err != nil {
		return err
	}
	fmt.Fprintf(a.output, "Project %s will start its next Agent Session from a clean host snapshot.\n", projectPolicy.ProjectID)
	return nil
}

func (a *app) down(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("down", flag.ContinueOnError)
	fs.SetOutput(a.errors)
	_ = fs.String("dir", ".", "Project directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := a.cleanupOrphans(ctx); err != nil {
		return err
	}
	fmt.Fprintln(a.output, "Recovered guardless Agent VMs. A live foreground Agent Session must be exited from its Host TUI.")
	return nil
}

func (a *app) destroy(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("destroy", flag.ContinueOnError)
	fs.SetOutput(a.errors)
	dir := fs.String("dir", ".", "Project directory")
	yes := fs.Bool("yes", false, "confirm destruction")
	discard := fs.Bool("discard-pending", false, "discard the pending Change Set")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*yes {
		return fmt.Errorf("destroy requires --yes")
	}
	projectPolicy, _, projectState, err := a.loadPolicy(*dir)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(projectState, "pending", "change.json")); err == nil && !*discard {
		return fmt.Errorf("pending Change Set exists; pass --discard-pending explicitly to destroy it")
	}
	if err := a.cleanupOrphans(ctx); err != nil {
		return err
	}
	items, err := a.runtime.List(ctx)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.Labels["dev.sunaba.owner"] == "sunaba-supervisor" && item.Labels["dev.sunaba.project"] == projectPolicy.ProjectID {
			return fmt.Errorf("refusing to delete Project state while owned VM %s still exists", item.Name)
		}
	}
	if *discard {
		if err := removePending(projectState); err != nil {
			return err
		}
	}
	info, err := os.Lstat(projectState)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || filepath.Dir(projectState) != filepath.Join(a.store.Root, "projects") || filepath.Base(projectState) != projectPolicy.ProjectID {
		return fmt.Errorf("refusing to remove unverified Project state")
	}
	if err := os.RemoveAll(projectState); err != nil {
		return err
	}
	fmt.Fprintf(a.output, "Destroyed Project state %s. Host Project files were not removed.\n", projectPolicy.ProjectID)
	return nil
}

func (a *app) firewall(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sunaba firewall enable|disable|status")
	}
	switch args[0] {
	case "disable":
		return firewall.Disable(ctx)
	case "enable":
		fs := flag.NewFlagSet("firewall enable", flag.ContinueOnError)
		fs.SetOutput(a.errors)
		subnet := fs.String("subnet", "", "owned dev IPv4 subnet")
		gateway := fs.String("gateway", "", "owned dev IPv4 gateway")
		ipv6 := fs.String("ipv6-subnet", "", "owned dev IPv6 subnet")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *subnet == "" || *gateway == "" || *ipv6 == "" {
			return fmt.Errorf("firewall enable requires --subnet, --gateway, and --ipv6-subnet")
		}
		return firewall.Enable(ctx, firewall.Network{Subnet: *subnet, Gateway: *gateway, IPv6Subnet: *ipv6})
	case "status":
		status, err := firewall.Status(ctx)
		fmt.Fprintln(a.output, status)
		return err
	default:
		return fmt.Errorf("unknown firewall action %q", args[0])
	}
}

func (a *app) loadPolicy(directory string) (policy.ProjectPolicy, string, string, error) {
	root, err := state.ResolveProjectPath(directory)
	if err != nil {
		return policy.ProjectPolicy{}, "", "", err
	}
	projectState := a.projectState(root)
	path := filepath.Join(projectState, "policy.json")
	loaded, migrated, err := policy.LoadAndMigrate(path, time.Now())
	if err != nil {
		if strings.Contains(err.Error(), "mode 0600") {
			return policy.ProjectPolicy{}, "", "", fmt.Errorf("Project is not registered; run 'sunaba project init %s'", root)
		}
		return policy.ProjectPolicy{}, "", "", err
	}
	if loaded.ProjectRoot != root || loaded.ProjectID != state.ProjectID(root) {
		return policy.ProjectPolicy{}, "", "", fmt.Errorf("Project policy identity does not match canonical path")
	}
	if migrated {
		fmt.Fprintf(a.errors, "Migrated Project policy to schema %d.\n", policy.CurrentSchemaVersion)
	}
	return loaded, path, projectState, nil
}

func (a *app) projectState(root string) string {
	return filepath.Join(a.store.Root, "projects", state.ProjectID(root))
}

func (a *app) cleanupOrphans(ctx context.Context) error {
	recorder, err := audit.NewRecorder(filepath.Join(a.store.Root, "audit"))
	if err != nil {
		return err
	}
	result, err := cleanup.Run(ctx, cleanup.Config{Store: a.store, Runtime: a.runtime, Audit: recorder})
	if err != nil {
		return err
	}
	if len(result.Refused) > 0 {
		return fmt.Errorf("refused to mutate resources without matching ownership and lease: %s", strings.Join(result.Refused, ", "))
	}
	return nil
}

func (a *app) prepareManagedOpenCode(ctx context.Context) (string, string, error) {
	source, err := exec.LookPath("opencode")
	if err != nil {
		return "", "", err
	}
	source, err = filepath.Abs(source)
	if err != nil {
		return "", "", err
	}
	digest, err := fileSHA256(source)
	if err != nil {
		return "", "", err
	}
	pinned := dependency.MustPinned()
	if digest != pinned.OpenCode.Host.ExecutableSHA256 {
		return "", "", fmt.Errorf("host OpenCode executable digest does not match the pinned v%s artifact", dependency.OpenCodeVersion)
	}
	managedDir := filepath.Join(a.store.Root, "tools", "opencode", "v"+dependency.OpenCodeVersion)
	if err := os.MkdirAll(managedDir, 0700); err != nil {
		return "", "", err
	}
	destination := filepath.Join(managedDir, "opencode")
	if current, err := fileSHA256(destination); err == nil && current == digest {
		return managedDir, destination, nil
	}
	input, err := os.Open(source)
	if err != nil {
		return "", "", err
	}
	defer input.Close()
	temporary, err := os.CreateTemp(managedDir, ".sunaba-opencode-*")
	if err != nil {
		return "", "", err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := io.Copy(temporary, input); err != nil {
		temporary.Close()
		return "", "", err
	}
	if err := temporary.Chmod(0700); err != nil {
		temporary.Close()
		return "", "", err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return "", "", err
	}
	if err := temporary.Close(); err != nil {
		return "", "", err
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return "", "", err
	}
	versionContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(versionContext, destination, "--version").Output(); err != nil || strings.TrimSpace(string(out)) != dependency.OpenCodeVersion {
		return "", "", fmt.Errorf("managed Host TUI version verification failed")
	}
	return managedDir, destination, nil
}

func siblingExecutable(name string) (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	path := filepath.Join(filepath.Dir(executable), name)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("required helper %s must be an executable next to the sunaba binary", name)
	}
	return filepath.Abs(path)
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func newSessionID() (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "s" + hex.EncodeToString(raw), nil
}

func statusOutcome(status int) string {
	if status >= http.StatusOK && status < http.StatusBadRequest {
		return "success"
	}
	return "rejected"
}
