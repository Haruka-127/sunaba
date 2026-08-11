package cli

import (
	"bufio"
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
	"sunaba/internal/firewall"
	"sunaba/internal/image"
	"sunaba/internal/opencode"
	"sunaba/internal/policy"
	"sunaba/internal/runtime"
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
	case "_supervisor":
		return a.supervisor(ctx, filtered[1:])
	case "git":
		return a.gitPolicy(ctx, filtered[1:])
	case "web":
		return a.webPolicy(ctx, filtered[1:])
	case "shell":
		return a.shell(ctx, filtered[1:])
	case "status":
		return a.status(ctx, filtered[1:])
	case "changes":
		return a.changes(ctx, filtered[1:])
	case "approvals":
		return a.approvals(ctx, filtered[1:])
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
  sunaba git set --remote <https-url> [--dir <path>]
  sunaba git disable [--dir <path>]
  sunaba web enable --origin <http(s)://host>... [--dir <path>]
  sunaba web refresh|disable [--dir <path>]
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
	projectPolicy, path, projectState, err := a.loadPolicy(*dir)
	if err != nil {
		return err
	}
	if *mode != "" {
		if *mode != "secure" && *mode != "dev" {
			return fmt.Errorf("mode must be secure or dev")
		}
		if projectPolicy.Mode != *mode {
			if err := refuseActivePolicyChange(projectState); err != nil {
				return err
			}
			items, err := a.runtime.List(ctx)
			if err != nil {
				return err
			}
			for _, item := range items {
				if item.Labels["dev.sunaba.owner"] == "sunaba-supervisor" && item.Labels["dev.sunaba.project"] == projectPolicy.ProjectID {
					return fmt.Errorf("mode change requires export/recreate of existing Project VM %s", item.Name)
				}
			}
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
	if projectPolicy.Mode == "dev" {
		return a.runForegroundDevAgent(ctx, projectPolicy, projectState)
	}
	client, info, err := a.ensureSupervisor(ctx, projectPolicy.ProjectRoot, projectState)
	if err != nil {
		return err
	}
	defer client.close()
	if info.ProjectID != projectPolicy.ProjectID {
		return fmt.Errorf("active supervisor Project identity does not match policy")
	}
	if !time.Now().Before(info.ExpiresAt) {
		pauseContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		return errors.Join(fmt.Errorf("Agent Session capability expired; export or recreate the stopped VM"), client.operation(pauseContext, "pause"))
	}
	if info.State == "paused" {
		resumeContext, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err = client.operation(resumeContext, "resume")
		cancel()
		if err != nil {
			return err
		}
		info, err = client.info(ctx)
		if err != nil {
			return err
		}
	}
	if info.State != "running" {
		return fmt.Errorf("active supervisor is in non-runnable state %s; export or recreate it", info.State)
	}
	managedDir, hostOpenCode, err := a.prepareManagedOpenCode(ctx)
	if err != nil {
		pauseContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		return errors.Join(err, client.operation(pauseContext, "pause"))
	}
	tui, err := opencode.BuildHostTUICommand(ctx, opencode.HostTUIConfig{
		Binary: hostOpenCode, ManagedToolDir: managedDir, SessionRoot: info.RuntimeRoot, ServerURL: info.AttachURL,
		GuestWorkspace: info.WorkspacePath, Password: info.ServerPassword,
		ExpectedExecutableSHA256: dependency.MustPinned().OpenCode.Host.ExecutableSHA256,
	}, os.Environ())
	if err != nil {
		pauseContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		return errors.Join(err, client.operation(pauseContext, "pause"))
	}
	tui.Stdin, tui.Stdout, tui.Stderr = a.input, a.output, a.errors
	tuiErr := tui.Run()
	pauseContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	pauseErr := client.operation(pauseContext, "pause")
	cancel()
	if pauseErr == nil {
		fmt.Fprintf(a.output, "Agent Session paused in persistent VM %s. Resume with 'sunaba agent' or export with 'sunaba changes export'.\n", info.Container)
	}
	return errors.Join(tuiErr, pauseErr)
}

func (a *app) shell(ctx context.Context, args []string) (returnErr error) {
	fs := flag.NewFlagSet("shell", flag.ContinueOnError)
	fs.SetOutput(a.errors)
	dir := fs.String("dir", ".", "Project directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	projectPolicy, _, projectState, err := a.loadPolicy(*dir)
	if err != nil {
		return err
	}
	if projectPolicy.Mode == "dev" {
		return a.runForegroundDevShell(ctx, projectPolicy, projectState)
	}
	client, info, err := a.ensureSupervisor(ctx, projectPolicy.ProjectRoot, projectState)
	if err != nil {
		return err
	}
	defer client.close()
	if info.State == "paused" {
		if err := client.operation(ctx, "resume"); err != nil {
			return err
		}
	}
	defer func() {
		pauseContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		returnErr = errors.Join(returnErr, client.operation(pauseContext, "pause"))
	}()
	return a.runSanitizedShell(ctx, client.shell)
}

func (a *app) runSanitizedShell(ctx context.Context, execute func(context.Context, string) (string, error)) error {
	fmt.Fprintln(a.output, "sunaba sanitized line shell; each line runs in the guest workspace. Ctrl-D exits. Interactive TTY programs are not supported.")
	scanner := bufio.NewScanner(a.input)
	scanner.Buffer(make([]byte, 4096), 16<<10)
	for {
		fmt.Fprint(a.output, "sunaba$ ")
		if !scanner.Scan() {
			break
		}
		if scanner.Text() == "" {
			continue
		}
		commandContext, cancel := context.WithTimeout(ctx, 2*time.Minute)
		output, err := execute(commandContext, scanner.Text())
		cancel()
		if err != nil {
			return err
		}
		fmt.Fprint(a.output, output)
	}
	return scanner.Err()
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
	states := make([]string, 0)
	listErr := error(nil)
	if client, clientErr := openSupervisorClient(projectState); clientErr == nil {
		if info, infoErr := client.info(ctx); infoErr == nil && info.ProjectID == projectPolicy.ProjectID {
			states = append(states, info.Container+"="+info.State+"/"+projectPolicy.Mode)
		} else if infoErr != nil {
			listErr = infoErr
		} else {
			listErr = fmt.Errorf("active supervisor Project identity does not match policy")
		}
		client.close()
	} else if errors.Is(clientErr, errNoSupervisor) {
		containers, runtimeErr := a.runtime.List(ctx)
		listErr = runtimeErr
		for _, item := range containers {
			if item.Labels["dev.sunaba.owner"] == "sunaba-supervisor" && item.Labels["dev.sunaba.project"] == projectPolicy.ProjectID {
				states = append(states, item.Name+"="+string(item.State)+"/"+item.Labels["dev.sunaba.mode"])
			}
		}
	} else {
		listErr = clientErr
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
	switch args[0] {
	case "export":
		pending, pendingErr := loadPending(projectState, projectPolicy.ProjectRoot, projectPolicy.ProjectID)
		if pendingErr != nil {
			pendingPath := filepath.Join(projectState, "pending", "change.json")
			if _, err := os.Lstat(pendingPath); err == nil {
				return pendingErr
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			client, err := openSupervisorClient(projectState)
			if err != nil {
				if errors.Is(err, errNoSupervisor) {
					return fmt.Errorf("no persistent Agent VM or pending Change Set to export")
				}
				return err
			}
			exportContext, cancel := context.WithTimeout(ctx, 12*time.Minute)
			err = client.operation(exportContext, "export")
			cancel()
			client.close()
			if err != nil {
				return err
			}
			pending, pendingErr = loadPending(projectState, projectPolicy.ProjectRoot, projectPolicy.ProjectID)
			if pendingErr != nil {
				if _, err := os.Lstat(pendingPath); errors.Is(err, os.ErrNotExist) {
					fmt.Fprintln(a.output, "Export completed with no Project changes; the persistent VM was removed.")
					return nil
				}
				return pendingErr
			}
		}
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
		pending, err := loadPending(projectState, projectPolicy.ProjectRoot, projectPolicy.ProjectID)
		if err != nil {
			return err
		}
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

func (a *app) approvals(ctx context.Context, args []string) error {
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
	approved, err := a.approveActivePushes(ctx, projectState)
	if err != nil {
		return err
	}
	if approved > 0 {
		fmt.Fprintf(a.output, "Approved %d Git push request(s). Retry the unchanged push in the Agent VM before the approval expires.\n", approved)
	}
	pending, pendingErr := loadPending(projectState, projectPolicy.ProjectRoot, projectPolicy.ProjectID)
	if pendingErr == nil {
		fmt.Fprintf(a.output, "Pending apply: %s (%d changes). Run 'sunaba changes apply'.\n", pending.ChangeSet.Digest, len(pending.ChangeSet.Changes))
		return nil
	}
	if approved == 0 {
		fmt.Fprintln(a.output, "No pending host approval requests.")
	}
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
	if client, err := openSupervisorClient(projectState); err == nil {
		operation := "export"
		if *discard {
			operation = "destroy"
		}
		operationContext, cancel := context.WithTimeout(ctx, 12*time.Minute)
		err = client.operation(operationContext, operation)
		cancel()
		client.close()
		if err != nil {
			return err
		}
		waitContext, waitCancel := context.WithTimeout(ctx, 5*time.Second)
		err = waitSupervisorGone(waitContext, projectState)
		waitCancel()
		if err != nil {
			return err
		}
	} else if errors.Is(err, errStaleSupervisor) {
		if err := a.recoverStaleSupervisor(ctx, projectState); err != nil {
			return err
		}
	} else if !errors.Is(err, errNoSupervisor) {
		return err
	} else if err := a.cleanupOrphans(ctx); err != nil {
		return err
	}
	fmt.Fprintf(a.output, "Project %s will start its next Agent Session from a clean host snapshot after any pending Change Set is applied or discarded.\n", projectPolicy.ProjectID)
	return nil
}

func (a *app) down(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("down", flag.ContinueOnError)
	fs.SetOutput(a.errors)
	dir := fs.String("dir", ".", "Project directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, _, projectState, err := a.loadPolicy(*dir)
	if err != nil {
		return err
	}
	if client, err := openSupervisorClient(projectState); err == nil {
		pauseContext, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err = client.operation(pauseContext, "pause")
		cancel()
		client.close()
		if err != nil {
			return err
		}
		fmt.Fprintln(a.output, "Persistent Agent VM is stopped with its isolated upper state retained.")
		return nil
	} else if errors.Is(err, errStaleSupervisor) {
		if err := a.recoverStaleSupervisor(ctx, projectState); err != nil {
			return err
		}
	} else if !errors.Is(err, errNoSupervisor) {
		return err
	} else if err := a.cleanupOrphans(ctx); err != nil {
		return err
	}
	fmt.Fprintln(a.output, "No managed persistent Agent VM was active; guardless owned resources were recovered.")
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
	if client, err := openSupervisorClient(projectState); err == nil {
		if !*discard {
			client.close()
			return fmt.Errorf("a persistent Agent VM may contain unexported changes; run 'sunaba changes export' or pass --discard-pending")
		}
		destroyContext, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err = client.operation(destroyContext, "destroy")
		cancel()
		client.close()
		if err != nil {
			return err
		}
		waitContext, waitCancel := context.WithTimeout(ctx, 5*time.Second)
		err = waitSupervisorGone(waitContext, projectState)
		waitCancel()
		if err != nil {
			return err
		}
	} else if errors.Is(err, errStaleSupervisor) {
		if err := a.recoverStaleSupervisor(ctx, projectState); err != nil {
			return err
		}
	} else if !errors.Is(err, errNoSupervisor) {
		return err
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
		return fmt.Errorf("usage: sunaba firewall enable|quiesce|disable|status")
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
	case "quiesce":
		fs := flag.NewFlagSet("firewall quiesce", flag.ContinueOnError)
		fs.SetOutput(a.errors)
		subnet := fs.String("subnet", "", "owned dev IPv4 subnet")
		gateway := fs.String("gateway", "", "owned dev IPv4 gateway")
		ipv6 := fs.String("ipv6-subnet", "", "owned dev IPv6 subnet")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *subnet == "" || *gateway == "" || *ipv6 == "" {
			return fmt.Errorf("firewall quiesce requires --subnet, --gateway, and --ipv6-subnet")
		}
		return firewall.Quiesce(ctx, firewall.Network{Subnet: *subnet, Gateway: *gateway, IPv6Subnet: *ipv6})
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

func makeRuntimeBase() (string, error) {
	base := os.TempDir()
	if info, err := os.Lstat("/private/tmp"); err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		base = "/private/tmp"
	}
	path, err := os.MkdirTemp(base, "sunaba-runtime-")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0700); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func statusOutcome(status int) string {
	if status >= http.StatusOK && status < http.StatusBadRequest {
		return "success"
	}
	return "rejected"
}
