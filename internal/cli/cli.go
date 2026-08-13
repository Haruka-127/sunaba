package cli

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	"sunaba/internal/modelcatalog"
	"sunaba/internal/opencode"
	"sunaba/internal/policy"
	"sunaba/internal/projectconfig"
	"sunaba/internal/runtime"
	"sunaba/internal/state"
	"sunaba/internal/trustedui"
	"sunaba/internal/workspace"
)

type app struct {
	verbose        bool
	store          *state.Store
	configs        *projectconfig.Store
	runtime        runtime.Runtime
	runtimeFactory func(bool) runtime.Runtime
	input          io.Reader
	output         io.Writer
	errors         io.Writer
}

type managedOpenCodeResult struct {
	dir      string
	binary   string
	verified *opencode.VerifiedHostTUIExecutable
	err      error
}

func Run(ctx context.Context, args []string) error {
	store, err := state.NewStore()
	if err != nil {
		return err
	}
	configs, err := projectconfig.NewStore()
	if err != nil {
		return err
	}
	a := &app{
		store: store, configs: configs, input: os.Stdin, output: os.Stdout, errors: os.Stderr,
		runtimeFactory: func(verbose bool) runtime.Runtime { return runtime.NewAppleContainer(verbose) },
	}
	return a.run(ctx, args)
}

func (a *app) projectInit(ctx context.Context, projectArgument, mode, modelAuth string) error {
	if mode != "secure" && mode != "dev" {
		return fmt.Errorf("mode must be secure or dev")
	}
	if modelAuth != "api-key" && modelAuth != "oauth" {
		return fmt.Errorf("model-auth must be oauth or api-key")
	}
	operationLock, err := a.store.AcquireOperationReadLock()
	if err != nil {
		return err
	}
	defer operationLock.Close()
	activeLock, err := a.activeVersionLock()
	if err != nil {
		return err
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
		return fmt.Errorf("Project is already registered; edit its host configuration and run 'sunaba config apply'")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	createdState := false
	defer func() {
		if createdState {
			_ = os.RemoveAll(projectState)
		}
	}()
	manifestDigest, err := dependency.ManifestDigest(activeLock.Manifest)
	if err != nil {
		return err
	}
	projectPolicy, err := policy.New(root, manifestDigest, activeLock.Manifest.OpenCode.Version, activeLock.Manifest.AppleContainer.Version, activeLock.Manifest.AgentImage.Tag, mode, time.Now())
	if err != nil {
		return err
	}
	authMode := modelcatalog.AuthOAuth
	if modelAuth == "api-key" {
		authMode = modelcatalog.AuthAPIKey
	}
	defaultModels, err := modelcatalog.DefaultModels(authMode)
	if err != nil {
		return err
	}
	projectPolicy.Model.AuthMode = authMode
	projectPolicy.Model.AllowedModels = defaultModels
	configStore, err := a.projectConfigStore()
	if err != nil {
		return err
	}
	configPaths, err := configStore.ProjectPaths(projectPolicy.ProjectID)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(configPaths.Directory); err == nil {
		return fmt.Errorf("Project host configuration already exists at %s", configPaths.Directory)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	projectConfig, originRules := projectconfig.FromPolicy(projectPolicy)
	createdConfig := false
	defer func() {
		if createdConfig {
			_ = os.RemoveAll(configPaths.Directory)
		}
	}()
	createdConfig = true
	createdState = stateWasAbsent
	if err := persistConfigAndPolicy(configStore, projectState, policyPath, projectConfig, originRules, projectPolicy); err != nil {
		return err
	}
	initialRoot := filepath.Join(projectState, "initial-snapshot")
	exportPolicy, err := policy.CompileExportPolicy(projectPolicy.Export, projectPolicy.ProtectedPaths)
	if err != nil {
		return err
	}
	initial, err := workspace.CreateProjectSnapshot(root, initialRoot, exportPolicy.Snapshot)
	if err != nil {
		return err
	}
	if err := writePrivateJSON(filepath.Join(projectState, "initial-snapshot.json"), initial); err != nil {
		return err
	}
	createdState = false
	createdConfig = false
	fmt.Fprintf(a.output, "Registered Project %s (%s) in %s mode. Host configuration: %s\n", projectPolicy.ProjectID, root, projectPolicy.Mode, configPaths.Project)
	return nil
}

func (a *app) up(ctx context.Context, dir, mode string) error {
	projectPolicy, path, projectState, err := a.loadPolicy(dir)
	if err != nil {
		return err
	}
	activeLock, err := a.requireActiveProjectDependency(projectPolicy)
	if err != nil {
		return err
	}
	if mode != "" {
		if mode != "secure" && mode != "dev" {
			return fmt.Errorf("mode must be secure or dev")
		}
		if projectPolicy.Mode != mode {
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
			projectPolicy.Mode = mode
			projectPolicy.UpdatedAt = time.Now().UTC()
			if err := a.savePolicyAndConfig(path, projectPolicy); err != nil {
				return err
			}
		}
	}
	if projectPolicy.Mode == "dev" {
		fmt.Fprintln(a.errors, "WARNING: dev mode permits direct Internet egress during the active Agent Session and does not provide exfiltration prevention.")
		if err := opencode.CheckPrerequisitesFor(ctx, activeLock.Manifest); err != nil {
			return err
		}
		if _, err := image.EnsureManifest(ctx, a.runtime, activeLock.Manifest); err != nil {
			return err
		}
		fmt.Fprintf(a.output, "Project %s is prepared in dev mode. No VM or direct-egress session is active; run 'sunaba agent' in the foreground.\n", projectPolicy.ProjectID)
		return nil
	}
	client, info, err := a.ensureSupervisor(ctx, projectPolicy.ProjectRoot, projectState)
	if err != nil {
		return err
	}
	defer client.close()
	if info.ProjectID != projectPolicy.ProjectID {
		return fmt.Errorf("active supervisor Project identity does not match policy")
	}
	if info.State == "running" {
		pauseContext, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err = client.operation(pauseContext, "pause")
		cancel()
		if err != nil {
			return err
		}
		info, err = client.info(ctx)
		if err != nil {
			return err
		}
	}
	if info.State != "paused" {
		return fmt.Errorf("Project VM preparation ended in unexpected state %s", info.State)
	}
	fmt.Fprintf(a.output, "Project VM %s is prepared and paused in secure mode. No Agent Session channel is active; run 'sunaba agent' or 'sunaba shell'.\n", info.Container)
	return nil
}

func (a *app) agent(ctx context.Context, dir string) (returnErr error) {
	projectPolicy, _, projectState, err := a.loadPolicy(dir)
	if err != nil {
		return err
	}
	activeLock, err := a.requireActiveProjectDependency(projectPolicy)
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
	managedOpenCode := a.prepareManagedOpenCodeAsync(ctx)
	if info.State == "paused" {
		resumeContext, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err = client.operation(resumeContext, "resume")
		cancel()
		if err != nil {
			prepared := <-managedOpenCode
			return errors.Join(err, prepared.err)
		}
		info, err = client.info(ctx)
		if err != nil {
			return err
		}
	}
	if info.State != "running" {
		prepared := <-managedOpenCode
		return errors.Join(fmt.Errorf("active supervisor is in non-runnable state %s; export or recreate it", info.State), prepared.err)
	}
	prepared := <-managedOpenCode
	if prepared.err != nil {
		pauseContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		return errors.Join(prepared.err, client.operation(pauseContext, "pause"))
	}
	tui, err := opencode.BuildHostTUICommand(ctx, opencode.HostTUIConfig{
		Binary: prepared.binary, ManagedToolDir: prepared.dir, VerifiedExecutable: prepared.verified,
		SessionRoot: info.RuntimeRoot, ServerURL: info.AttachURL,
		GuestWorkspace: info.WorkspacePath, Password: info.ServerPassword,
		ExpectedExecutableSHA256: activeLock.Manifest.OpenCode.Host.ExecutableSHA256,
	}, os.Environ())
	if err != nil {
		pauseContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		return errors.Join(err, client.operation(pauseContext, "pause"))
	}
	tui.Stdin, tui.Stdout, tui.Stderr = a.input, a.output, a.errors
	tuiErr := runHostTUIWithHeartbeat(ctx, tui, time.Duration(projectPolicy.Session.IdleSeconds)*time.Second, func(heartbeatContext context.Context) error {
		return client.operation(heartbeatContext, "heartbeat")
	})
	pauseContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	pauseErr := client.operation(pauseContext, "pause")
	cancel()
	if pauseErr == nil {
		fmt.Fprintf(a.output, "Agent Session paused in persistent VM %s. Resume with 'sunaba agent' or export with 'sunaba changes export'.\n", info.Container)
	}
	return errors.Join(tuiErr, pauseErr)
}

func runHostTUIWithHeartbeat(ctx context.Context, tui *exec.Cmd, idleTimeout time.Duration, heartbeat func(context.Context) error) error {
	if tui == nil || heartbeat == nil || idleTimeout < time.Second {
		return fmt.Errorf("Host TUI heartbeat configuration is incomplete")
	}
	if err := tui.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- tui.Wait() }()
	interval := idleTimeout / 3
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	waitAfterInterrupt := func(reason error) error {
		if tui.Process != nil {
			_ = tui.Process.Signal(os.Interrupt)
		}
		select {
		case waitErr := <-done:
			return errors.Join(reason, waitErr)
		case <-time.After(5 * time.Second):
			if tui.Process != nil {
				_ = tui.Process.Kill()
			}
			return errors.Join(reason, <-done)
		}
	}
	for {
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			return waitAfterInterrupt(ctx.Err())
		case <-ticker.C:
			heartbeatContext, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := heartbeat(heartbeatContext)
			cancel()
			if err != nil {
				return waitAfterInterrupt(fmt.Errorf("Host TUI heartbeat failed: %w", err))
			}
		}
	}
}

func (a *app) shell(ctx context.Context, dir string) (returnErr error) {
	projectPolicy, _, projectState, err := a.loadPolicy(dir)
	if err != nil {
		return err
	}
	if _, err := a.requireActiveProjectDependency(projectPolicy); err != nil {
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

func (a *app) status(ctx context.Context, dir string) error {
	projectPolicy, _, projectState, err := a.loadEffectivePolicy(dir)
	if err != nil {
		return err
	}
	states := make([]string, 0)
	sessionExpiry := "none"
	idleDeadline := "none"
	unexported := "none"
	listErr := error(nil)
	if client, clientErr := openSupervisorClient(projectState); clientErr == nil {
		if info, infoErr := client.info(ctx); infoErr == nil && info.ProjectID == projectPolicy.ProjectID {
			states = append(states, info.Container+"="+info.State+"/"+projectPolicy.Mode)
			sessionExpiry = info.ExpiresAt.UTC().Format(time.RFC3339)
			idleDeadline = info.IdleDeadline.UTC().Format(time.RFC3339)
			unexported = "possible (run 'sunaba changes export' to compute the trusted Change Set)"
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
				unexported = "possible (owned VM exists without an attached supervisor)"
			}
		}
	} else {
		listErr = clientErr
	}
	sort.Strings(states)
	sessionVMs := strings.Join(states, ", ")
	if sessionVMs == "" {
		sessionVMs = "none"
	}
	pending := "none"
	if change, pendingErr := loadPending(projectState, projectPolicy); pendingErr == nil {
		pending = fmt.Sprintf("%s (%d changes)", change.ChangeSet.Digest, len(change.ChangeSet.Changes))
	}
	gitState := "disabled"
	if len(projectPolicy.Git.Remotes) > 0 {
		gitState = fmt.Sprintf("enabled (%d fixed HTTPS remotes)", len(projectPolicy.Git.Remotes))
	}
	webState := "disabled"
	if projectPolicy.Web.Enabled {
		webState = fmt.Sprintf("enabled (%d origin rules, pinned blocklist %s)", len(projectPolicy.Web.Rules), projectPolicy.Web.BlocklistSHA256)
	}
	configState := "invalid"
	configPath := "unavailable"
	configStore, configStoreErr := a.projectConfigStore()
	if configStoreErr == nil {
		if paths, pathErr := configStore.ProjectPaths(projectPolicy.ProjectID); pathErr == nil {
			configPath = paths.Project
		}
		config, rules, configErr := configStore.Load(projectPolicy.ProjectID)
		if configErr == nil {
			configState = "unapplied"
			if config.ProjectRoot == projectPolicy.ProjectRoot && projectconfig.Matches(config, rules, projectPolicy) {
				configState = "applied"
			}
		} else {
			configState = "invalid: " + configErr.Error()
		}
	} else {
		configState = "invalid: " + configStoreErr.Error()
	}
	dependencyState := "active"
	if _, err := a.requireActiveProjectDependency(projectPolicy); err != nil {
		dependencyState = "not active: " + err.Error()
	}
	fmt.Fprintf(a.output, "Project: %s\nProject ID: %s\nMode: %s\nPolicy schema: %d\nHost configuration: %s (%s)\nDependency lock: %s\nOpenCode: %s\nApple Container: %s\nAgent image: %s\nSession VMs: %s\nSession expiry: %s\nIdle deadline: %s\nSession policy: ttl_seconds=%d idle_seconds=%d\nUnexported VM changes: %s\nPending Change Set: %s\nResources: cpus=%d memory=%s disk_bytes=%d nproc=%d fsize=%d nofile=%d\nModel authentication: %s\nModel allowlist: %s\nModel quota: requests=%d concurrent=%d request_bytes=%d response_bytes=%d\nGit Gateway: %s\nWeb Gateway: %s\n",
		projectPolicy.ProjectRoot, projectPolicy.ProjectID, projectPolicy.Mode, projectPolicy.SchemaVersion,
		configPath, configState, dependencyState,
		projectPolicy.Dependency.OpenCode, projectPolicy.Dependency.AppleContainer, projectPolicy.Dependency.AgentImage,
		sessionVMs, sessionExpiry, idleDeadline, projectPolicy.Session.TTLSeconds, projectPolicy.Session.IdleSeconds, unexported, pending,
		projectPolicy.Resources.CPUs, projectPolicy.Resources.Memory, projectPolicy.Resources.DiskBytes, projectPolicy.Resources.ProcessMax, projectPolicy.Resources.FileSizeMax, projectPolicy.Resources.OpenFileMax,
		projectPolicy.Model.AuthMode, strings.Join(projectPolicy.Model.AllowedModels, ","),
		projectPolicy.Model.MaxRequests, projectPolicy.Model.MaxConcurrent, projectPolicy.Model.MaxRequestBytes, projectPolicy.Model.MaxResponseBytes,
		gitState, webState)
	return listErr
}

func (a *app) changes(ctx context.Context, action, dir string) error {
	projectPolicy, _, projectState, err := a.loadEffectivePolicy(dir)
	if err != nil {
		return err
	}
	switch action {
	case "export":
		pending, pendingErr := loadPending(projectState, projectPolicy)
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
			pending, pendingErr = loadPending(projectState, projectPolicy)
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
		pending, err := loadPending(projectState, projectPolicy)
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
		compiled, err := policy.CompileExportPolicy(projectPolicy.Export, projectPolicy.ProtectedPaths)
		if err != nil {
			return err
		}
		applied, err := hostapply.Apply(hostapply.Config{Store: a.store, ProjectRoot: pending.ProjectRoot, ProjectID: pending.ProjectID, MergedRoot: pending.MergedRoot, Baseline: pending.Baseline, Merged: pending.Merged, ChangeSet: pending.ChangeSet, Approvals: approvals, Grant: grant, Audit: recorder, SnapshotPolicy: compiled.Snapshot})
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
		return fmt.Errorf("unknown changes action %q", action)
	}
}

func (a *app) approvals(ctx context.Context, dir string) error {
	projectPolicy, _, projectState, err := a.loadEffectivePolicy(dir)
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
	pending, pendingErr := loadPending(projectState, projectPolicy)
	if pendingErr == nil {
		fmt.Fprintf(a.output, "Pending apply: %s (%d changes). Run 'sunaba changes apply'.\n", pending.ChangeSet.Digest, len(pending.ChangeSet.Changes))
		return nil
	}
	if approved == 0 {
		fmt.Fprintln(a.output, "No pending host approval requests.")
	}
	return nil
}

func (a *app) recreate(ctx context.Context, dir string, discard bool) error {
	projectPolicy, _, projectState, err := a.loadEffectivePolicy(dir)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(projectState, "pending", "change.json")); err == nil && !discard {
		return fmt.Errorf("pending Change Set exists; export/apply it or pass --discard-pending explicitly")
	}
	if discard {
		if err := removePending(projectState); err != nil {
			return err
		}
	}
	if client, err := openSupervisorClient(projectState); err == nil {
		operation := "export"
		if discard {
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

func (a *app) down(ctx context.Context, selector projectSelector) error {
	target, err := a.resolveProjectStateTarget(selector)
	if err != nil {
		return err
	}
	if client, err := openSupervisorClient(target.ProjectState); err == nil {
		info, infoErr := client.info(ctx)
		if infoErr != nil {
			client.close()
			return infoErr
		}
		if info.ProjectID != target.ProjectID {
			client.close()
			return fmt.Errorf("active supervisor Project identity does not match down target")
		}
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
		if err := a.recoverStaleSupervisor(ctx, target.ProjectState); err != nil {
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

func (a *app) destroy(ctx context.Context, selector projectSelector, yes, discard bool) error {
	if !yes {
		return fmt.Errorf("destroy requires --yes")
	}
	target, err := a.resolveProjectStateTarget(selector)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(target.ProjectState, "pending", "change.json")); err == nil {
		if !discard {
			return fmt.Errorf("pending Change Set exists; pass --discard-pending explicitly to destroy it")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect pending Change Set: %w", err)
	}
	if client, err := openSupervisorClient(target.ProjectState); err == nil {
		info, infoErr := client.info(ctx)
		if infoErr != nil {
			client.close()
			return infoErr
		}
		if info.ProjectID != target.ProjectID {
			client.close()
			return fmt.Errorf("active supervisor Project identity does not match destroy target")
		}
		if !discard {
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
		err = waitSupervisorGone(waitContext, target.ProjectState)
		waitCancel()
		if err != nil {
			return err
		}
	} else if errors.Is(err, errStaleSupervisor) {
		if err := a.recoverStaleSupervisor(ctx, target.ProjectState); err != nil {
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
		if item.Labels["dev.sunaba.owner"] == "sunaba-supervisor" && item.Labels["dev.sunaba.project"] == target.ProjectID {
			return fmt.Errorf("refusing to delete Project state while owned VM %s still exists", item.Name)
		}
	}
	if discard {
		if err := removePending(target.ProjectState); err != nil {
			return err
		}
	}
	verified, err := a.store.LookupProjectState(target.ProjectID)
	if err != nil || verified.Path != target.ProjectState {
		return fmt.Errorf("refusing to remove unverified Project state")
	}
	if err := os.RemoveAll(target.ProjectState); err != nil {
		return err
	}
	configStore, err := a.projectConfigStore()
	if err != nil {
		return err
	}
	if err := configStore.Remove(target.ProjectID); err != nil {
		return fmt.Errorf("Project state was removed, but its host configuration could not be removed: %w", err)
	}
	fmt.Fprintf(a.output, "Destroyed Project state and host configuration %s. Host Project files were not removed.\n", target.ProjectID)
	return nil
}

func (a *app) firewall(ctx context.Context, action, subnet, gateway, ipv6 string) error {
	switch action {
	case "disable":
		return firewall.Disable(ctx)
	case "enable":
		if subnet == "" || gateway == "" || ipv6 == "" {
			return fmt.Errorf("firewall enable requires --subnet, --gateway, and --ipv6-subnet")
		}
		return firewall.Enable(ctx, firewall.Network{Subnet: subnet, Gateway: gateway, IPv6Subnet: ipv6})
	case "quiesce":
		if subnet == "" || gateway == "" || ipv6 == "" {
			return fmt.Errorf("firewall quiesce requires --subnet, --gateway, and --ipv6-subnet")
		}
		return firewall.Quiesce(ctx, firewall.Network{Subnet: subnet, Gateway: gateway, IPv6Subnet: ipv6})
	case "status":
		status, err := firewall.Status(ctx)
		fmt.Fprintln(a.output, status)
		return err
	default:
		return fmt.Errorf("unknown firewall action %q", action)
	}
}

func (a *app) loadPolicy(directory string) (policy.ProjectPolicy, string, string, error) {
	loaded, path, projectState, err := a.loadEffectivePolicy(directory)
	if err != nil {
		return policy.ProjectPolicy{}, "", "", err
	}
	configStore, err := a.projectConfigStore()
	if err != nil {
		return policy.ProjectPolicy{}, "", "", err
	}
	config, rules, err := configStore.Load(loaded.ProjectID)
	if err != nil {
		return policy.ProjectPolicy{}, "", "", fmt.Errorf("load host Project configuration: %w", err)
	}
	if config.ProjectRoot != loaded.ProjectRoot || !projectconfig.Matches(config, rules, loaded) {
		return policy.ProjectPolicy{}, "", "", fmt.Errorf("host Project configuration has unapplied changes; run 'sunaba config diff --dir %s' and 'sunaba config apply --dir %s'", loaded.ProjectRoot, loaded.ProjectRoot)
	}
	return loaded, path, projectState, nil
}

func (a *app) loadEffectivePolicy(directory string) (policy.ProjectPolicy, string, string, error) {
	root, err := state.ResolveProjectPath(directory)
	if err != nil {
		return policy.ProjectPolicy{}, "", "", err
	}
	projectState := a.projectState(root)
	path := filepath.Join(projectState, "policy.json")
	if err := recoverConfigPolicyTransaction(projectState); err != nil {
		return policy.ProjectPolicy{}, "", "", fmt.Errorf("recover Project configuration transaction: %w", err)
	}
	loaded, migrated, err := policy.LoadAndMigrate(path, time.Now())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "mode 0600") {
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

func (a *app) projectConfigStore() (*projectconfig.Store, error) {
	if a.configs != nil {
		return a.configs, nil
	}
	if a.store == nil || !filepath.IsAbs(a.store.Root) {
		return nil, fmt.Errorf("Project configuration store is unavailable")
	}
	// Tests and embedded callers that inject a state store get an isolated sibling
	// configuration root. The public CLI always supplies the XDG configuration root.
	a.configs = &projectconfig.Store{Root: filepath.Join(filepath.Dir(a.store.Root), "config", "sunaba")}
	return a.configs, nil
}

func (a *app) savePolicyAndConfig(policyPath string, effective policy.ProjectPolicy) error {
	operationLock, err := a.store.AcquireOperationReadLock()
	if err != nil {
		return err
	}
	defer operationLock.Close()
	if _, err := a.requireActiveProjectDependency(effective); err != nil {
		return err
	}
	configStore, err := a.projectConfigStore()
	if err != nil {
		return err
	}
	config, rules := projectconfig.FromPolicy(effective)
	return persistConfigAndPolicy(configStore, filepath.Dir(policyPath), policyPath, config, rules, effective)
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

func (a *app) prepareManagedOpenCode(ctx context.Context) (string, string, *opencode.VerifiedHostTUIExecutable, error) {
	activeLock, err := a.activeVersionLock()
	if err != nil {
		return "", "", nil, err
	}
	manifest := activeLock.Manifest
	managedDir := filepath.Join(a.store.Root, "tools", "opencode", "v"+manifest.OpenCode.Version)
	if err := os.MkdirAll(managedDir, 0700); err != nil {
		return "", "", nil, err
	}
	destination := filepath.Join(managedDir, "opencode")
	verified, verifyErr := opencode.VerifyHostTUIExecutableVersion(ctx, managedDir, destination, manifest.OpenCode.Host.ExecutableSHA256, manifest.OpenCode.Version)
	if verifyErr == nil {
		return managedDir, destination, verified, nil
	}
	if ctx.Err() != nil {
		return "", "", nil, ctx.Err()
	}
	source, err := exec.LookPath("opencode")
	if err != nil {
		return "", "", nil, errors.Join(verifyErr, err)
	}
	source, err = filepath.Abs(source)
	if err != nil {
		return "", "", nil, errors.Join(verifyErr, err)
	}
	if err := installManagedOpenCode(source, destination, manifest.OpenCode.Host.ExecutableSHA256, manifest.OpenCode.Version); err != nil {
		return "", "", nil, errors.Join(verifyErr, err)
	}
	verified, err = opencode.VerifyHostTUIExecutableVersion(ctx, managedDir, destination, manifest.OpenCode.Host.ExecutableSHA256, manifest.OpenCode.Version)
	if err != nil {
		return "", "", nil, err
	}
	return managedDir, destination, verified, nil
}

func (a *app) prepareManagedOpenCodeAsync(ctx context.Context) <-chan managedOpenCodeResult {
	result := make(chan managedOpenCodeResult, 1)
	go func() {
		dir, binary, verified, err := a.prepareManagedOpenCode(ctx)
		result <- managedOpenCodeResult{dir: dir, binary: binary, verified: verified, err: err}
	}()
	return result
}

func installManagedOpenCode(source, destination, expectedDigest, expectedVersion string) error {
	digest, err := fileSHA256(source)
	if err != nil {
		return err
	}
	if digest != expectedDigest {
		return fmt.Errorf("host OpenCode executable digest does not match the pinned v%s artifact", expectedVersion)
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".sunaba-opencode-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := io.Copy(temporary, input); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(0700); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return err
	}
	return nil
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
