package cli

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sunaba/internal/audit"
	"sunaba/internal/cleanup"
	"sunaba/internal/devnetwork"
	"sunaba/internal/image"
	"sunaba/internal/modelcatalog"
	"sunaba/internal/modelgateway"
	"sunaba/internal/openauth"
	"sunaba/internal/opencode"
	"sunaba/internal/policy"
	"sunaba/internal/projectconfig"
	"sunaba/internal/recovery"
	"sunaba/internal/secretstore"
	"sunaba/internal/session"
	"sunaba/internal/state"
	"sunaba/internal/workspace"
)

type managedSession struct {
	active            *session.Session
	projectPolicy     policy.ProjectPolicy
	projectState      string
	runtimeBase       string
	initialActivation managedActivation
	activationFactory func(context.Context) (managedActivation, error)
	gitBroker         *rotatingPushBroker
	operationLock     *state.OperationLock
}

type managedActivation struct {
	activation  session.Activation
	expiresAt   time.Time
	idleTimeout time.Duration
	gitBroker   pushApprovalBroker
	modelUsage  func() (int64, int64)
}

func (a *app) startManagedSession(ctx context.Context, projectPolicy policy.ProjectPolicy, projectState string) (*managedSession, error) {
	configLock, err := a.store.AcquireConfigLock(projectPolicy.ProjectID)
	if err != nil {
		return nil, err
	}
	defer configLock.Close()
	currentPolicy, _, currentProjectState, err := a.loadPolicyLocked(projectPolicy.ProjectRoot)
	if err != nil {
		return nil, err
	}
	if currentProjectState != projectState || currentPolicy.ProjectID != projectPolicy.ProjectID {
		return nil, fmt.Errorf("Project policy identity changed before VM creation")
	}
	projectPolicy = currentPolicy
	operationLock, err := a.store.AcquireOperationReadLock()
	if err != nil {
		return nil, err
	}
	handedOff := false
	defer func() {
		if !handedOff {
			_ = operationLock.Close()
		}
	}()
	if _, err := os.Lstat(filepath.Join(projectState, "pending", "change.json")); err == nil {
		return nil, fmt.Errorf("a pending Change Set exists; apply or discard it before starting another Agent Session")
	}
	if _, err := recovery.Load(projectState); err == nil {
		return nil, fmt.Errorf("a stopped VM is retained after an incomplete export; run 'sunaba status' and recover or explicitly discard it before starting another Agent Session")
	} else if !errors.Is(err, os.ErrNotExist) {
		if _, statErr := os.Lstat(recovery.Path(projectState)); statErr == nil {
			return nil, fmt.Errorf("export recovery metadata is unsafe: %w", err)
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return nil, statErr
		}
	}
	exportPolicy, err := policy.CompileExportPolicy(projectPolicy.Export, projectPolicy.ProtectedPaths, projectPolicy.Snapshot.Exclude)
	if err != nil {
		return nil, err
	}
	approvedManifest, err := workspace.BuildSnapshotManifest(projectPolicy.ProjectRoot, exportPolicy.Snapshot)
	if err != nil {
		return nil, err
	}
	_, err = verifySnapshotApproval(projectState, exportPolicy, approvedManifest)
	if err != nil {
		return nil, err
	}
	activeLock, err := a.requireActiveProjectDependency(projectPolicy)
	if err != nil {
		return nil, err
	}
	if err := opencode.CheckPrerequisitesFor(ctx, activeLock.Manifest); err != nil {
		return nil, err
	}
	if _, err := image.EnsureManifest(ctx, a.runtime, activeLock.Manifest); err != nil {
		return nil, err
	}
	recorder, err := audit.NewRecorder(filepath.Join(a.store.Root, "audit"))
	if err != nil {
		return nil, err
	}
	if err := pruneProjectAudit(recorder, projectPolicy, time.Now()); err != nil {
		return nil, err
	}
	cleanupResult, err := cleanup.Run(ctx, cleanup.Config{Store: a.store, Runtime: a.runtime, Audit: recorder})
	if err != nil {
		return nil, err
	}
	if len(cleanupResult.Refused) > 0 {
		var blocked []string
		for _, name := range cleanupResult.Refused {
			info, inspectErr := a.runtime.Inspect(ctx, name)
			if inspectErr != nil {
				return nil, inspectErr
			}
			if info.Labels["dev.sunaba.owner"] == "sunaba-supervisor" && info.Labels["dev.sunaba.project"] == projectPolicy.ProjectID {
				blocked = append(blocked, name)
			}
		}
		if len(blocked) > 0 {
			return nil, fmt.Errorf("stopped Project VM requires recovery or explicit discard before a new VM can be created: %s", strings.Join(blocked, ", "))
		}
		fmt.Fprintf(a.errors, "WARNING: cleanup refused resources without matching current ownership/lease: %s\n", strings.Join(cleanupResult.Refused, ", "))
	}
	vmID, err := newVMID()
	if err != nil {
		return nil, err
	}
	var runtimeBase string
	if projectPolicy.Mode == "dev" {
		runtimeBase, err = recovery.NewRuntimeBase(projectState, vmID)
	} else {
		runtimeBase, err = recovery.NewSecureRuntimeBase(projectPolicy.ProjectID, vmID)
	}
	if err != nil {
		return nil, err
	}
	cleanupRuntime := true
	defer func() {
		if cleanupRuntime {
			_ = os.RemoveAll(runtimeBase)
		}
	}()
	guestRelay, err := siblingExecutable("sunaba-guest-relay")
	if err != nil {
		return nil, err
	}
	if err := validateGuestRelay(guestRelay); err != nil {
		return nil, err
	}
	activation, err := a.newManagedActivation(ctx, projectPolicy, projectState, runtimeBase, vmID, recorder)
	if err != nil {
		return nil, err
	}
	activationHandedOff := false
	defer func() {
		if !activationHandedOff {
			if activation.activation.ModelGatewayClose != nil {
				_ = activation.activation.ModelGatewayClose()
			}
			if activation.activation.WebGatewayClose != nil {
				_ = activation.activation.WebGatewayClose()
			}
			if activation.activation.GitGatewayClose != nil {
				_ = activation.activation.GitGatewayClose()
			}
		}
	}()
	config := session.Config{
		Store: a.store, Runtime: a.runtime, ProjectRoot: projectPolicy.ProjectRoot, RuntimeBase: runtimeBase,
		VMID: vmID, SessionID: activation.activation.SessionID, Mode: projectPolicy.Mode, Image: projectPolicy.Dependency.AgentImage,
		CPUs: projectPolicy.Resources.CPUs, Memory: projectPolicy.Resources.Memory, DiskBytes: projectPolicy.Resources.DiskBytes,
		ProcessMax: projectPolicy.Resources.ProcessMax, FileSizeMax: projectPolicy.Resources.FileSizeMax, OpenFileMax: projectPolicy.Resources.OpenFileMax,
		GuestRelayBinary: guestRelay, ProviderConfig: activation.activation.ProviderConfig, ModelGateway: activation.activation.ModelGateway, ModelGatewayClose: activation.activation.ModelGatewayClose, ModelToken: activation.activation.ModelToken,
		GitGateway: activation.activation.GitGateway, GitRemotes: activation.activation.GitRemotes, GitGatewayClose: activation.activation.GitGatewayClose,
		WebGateway: activation.activation.WebGateway, WebToken: activation.activation.WebToken, WebGatewayClose: activation.activation.WebGatewayClose,
		ServerPassword: activation.activation.ServerPassword, LeaseTTL: activation.activation.LeaseTTL, Audit: recorder,
		SnapshotPolicy: exportPolicy.Snapshot, ApprovedSnapshot: approvedManifest, ExportPolicy: exportPolicy.Export, ExportPolicyDigest: exportPolicy.Digest,
	}
	var devBoundary *devnetwork.Boundary
	if projectPolicy.Mode == "dev" {
		devBoundary, err = devnetwork.Activate(ctx, a.store.Root, projectPolicy.ProjectID, vmID)
		if err != nil {
			return nil, err
		}
		config.DevNetworkName = devBoundary.Network.Name
		config.DevNetworkVerify = devBoundary.Verify
		config.DevNetworkQuiesce = devBoundary.Quiesce
		config.DevNetworkClose = devBoundary.Close
	}
	active, err := session.Start(ctx, config)
	if err != nil {
		if devBoundary != nil {
			_ = devBoundary.Close(context.Background())
		}
		return nil, err
	}
	activationHandedOff = true
	cleanupRuntime = false
	handedOff = true
	broker := &rotatingPushBroker{}
	broker.Set(activation.gitBroker)
	return &managedSession{
		active: active, projectPolicy: projectPolicy, projectState: projectState, runtimeBase: runtimeBase,
		initialActivation: activation, gitBroker: broker, operationLock: operationLock,
		activationFactory: func(factoryContext context.Context) (managedActivation, error) {
			current, err := a.reloadActivationPolicy(projectPolicy, filepath.Join(projectState, "policy.json"))
			if err != nil {
				return managedActivation{}, err
			}
			return a.newManagedActivation(factoryContext, current, projectState, runtimeBase, vmID, recorder)
		},
	}, nil
}

func (a *app) reloadActivationPolicy(vmPolicy policy.ProjectPolicy, policyPath string) (policy.ProjectPolicy, error) {
	current, migrated, err := policy.LoadReadOnly(policyPath, time.Now())
	if err != nil {
		return policy.ProjectPolicy{}, fmt.Errorf("reload policy for the next Agent Session: %w", err)
	}
	if migrated {
		return policy.ProjectPolicy{}, fmt.Errorf("the current policy requires migration; stop the VM and run a host configuration command before resuming")
	}
	configStore, err := a.projectConfigStore()
	if err != nil {
		return policy.ProjectPolicy{}, err
	}
	config, rules, err := configStore.Load(current.ProjectID)
	if err != nil || config.ProjectRoot != current.ProjectRoot || !projectconfig.Matches(config, rules, current) {
		return policy.ProjectPolicy{}, fmt.Errorf("host Project configuration is not atomically synchronized with the effective policy; retry 'sunaba config apply'")
	}
	plan, err := policy.ClassifyApplication(vmPolicy, current)
	if err != nil {
		return policy.ProjectPolicy{}, err
	}
	if plan.Has(policy.ApplyAfterRecreate) {
		return policy.ProjectPolicy{}, fmt.Errorf("current configuration changed VM-bound fields [%s]; export changes and run 'sunaba recreate'", strings.Join(plan.Paths(policy.ApplyAfterRecreate), ", "))
	}
	return current, nil
}

func (a *app) newManagedActivation(ctx context.Context, projectPolicy policy.ProjectPolicy, projectState, runtimeBase, vmID string, recorder *audit.Recorder) (managedActivation, error) {
	upstreamBaseURL := "https://api.openai.com"
	upstreamKey := ""
	var oauthTokens modelgateway.OAuthTokenSource
	if projectPolicy.Model.AuthMode == modelcatalog.AuthOAuth {
		manager := openauth.NewManager()
		if _, err := manager.AccessToken(ctx); err != nil {
			return managedActivation{}, err
		}
		upstreamBaseURL = "https://chatgpt.com/backend-api/codex"
		oauthTokens = manager
	} else {
		var err error
		upstreamKey, err = secretstore.LoadOpenAIKey(ctx)
		if err != nil {
			return managedActivation{}, err
		}
	}
	sessionID, err := newSessionID()
	if err != nil {
		return managedActivation{}, err
	}
	modelToken, err := session.NewSecret()
	if err != nil {
		return managedActivation{}, err
	}
	serverPassword, err := session.NewSecret()
	if err != nil {
		return managedActivation{}, err
	}
	expiresAt := time.Now().Add(time.Duration(projectPolicy.Session.TTLSeconds) * time.Second)
	capability, err := modelgateway.NewCapability(modelToken, projectPolicy.ProjectID, "sunaba-"+projectPolicy.ProjectID+"-"+vmID, sessionID, projectPolicy.Model.AllowedModels, expiresAt)
	if err != nil {
		return managedActivation{}, err
	}
	capability.MaxRequests = projectPolicy.Model.MaxRequests
	capability.MaxConcurrent = projectPolicy.Model.MaxConcurrent
	capability.MaxRequestBytes = projectPolicy.Model.MaxRequestBytes
	capability.MaxResponseBytes = projectPolicy.Model.MaxResponseBytes
	gateway, err := modelgateway.New(modelgateway.Config{
		UpstreamBaseURL: upstreamBaseURL, UpstreamAPIKey: upstreamKey, AuthMode: projectPolicy.Model.AuthMode, OAuthTokens: oauthTokens, Capability: capability,
		Audit: func(event modelgateway.AuditEvent) error {
			return recorder.Append(audit.BoundaryEvent{Category: "model", Action: "model.request", Outcome: statusOutcome(event.Status), ProjectID: event.ProjectID, VMID: event.VMID, SessionID: event.SessionID, Details: map[string]string{
				"model": event.Model, "status": fmt.Sprint(event.Status), "request_bytes": fmt.Sprint(event.RequestBytes), "response_bytes": fmt.Sprint(event.ResponseBytes), "reason": event.Reason,
			}})
		},
	})
	if err != nil {
		return managedActivation{}, err
	}
	provider, err := opencode.BuildModelGatewayConfig(opencode.ModelGatewayProviderConfig{
		BaseURL: "http://127.0.0.1:4141/v1", AllowedModels: projectPolicy.Model.AllowedModels,
		DefaultModel: projectPolicy.Model.AllowedModels[0], TokenEnv: "SUNABA_MODEL_GATEWAY_TOKEN", AuthMode: projectPolicy.Model.AuthMode,
	})
	if err != nil {
		return managedActivation{}, err
	}
	vmName := "sunaba-" + projectPolicy.ProjectID + "-" + vmID
	gateways, err := a.configureGateways(ctx, projectPolicy, projectState, runtimeBase, vmName, sessionID, expiresAt, recorder)
	if err != nil {
		return managedActivation{}, err
	}
	return managedActivation{activation: session.Activation{
		SessionID: sessionID, ProviderConfig: provider, ModelGateway: gateway, ModelGatewayClose: func() error { gateway.Revoke(); return nil }, ModelToken: modelToken,
		GitGateway: gateways.gitHandler, GitRemotes: gateways.gitRemotes, GitGatewayClose: gateways.gitClose,
		WebGateway: gateways.webHandler, WebToken: gateways.webToken, WebGatewayClose: gateways.webClose,
		ServerPassword: serverPassword, LeaseTTL: time.Duration(projectPolicy.Session.TTLSeconds) * time.Second,
	}, expiresAt: expiresAt, idleTimeout: time.Duration(projectPolicy.Session.IdleSeconds) * time.Second, gitBroker: gateways.gitBroker, modelUsage: gateway.Usage}, nil
}

func pruneProjectAudit(recorder *audit.Recorder, projectPolicy policy.ProjectPolicy, now time.Time) error {
	retention := time.Duration(projectPolicy.Audit.RetentionDays) * 24 * time.Hour
	removed, pruneErr := recorder.PruneProject(projectPolicy.ProjectID, retention, now)
	outcome := "success"
	details := map[string]string{
		"retention_days": fmt.Sprint(projectPolicy.Audit.RetentionDays),
		"removed":        fmt.Sprint(removed),
	}
	if pruneErr != nil {
		outcome = "rejected"
		details["reason"] = pruneErr.Error()
	}
	auditErr := recorder.Append(audit.BoundaryEvent{
		At: now, Category: "audit", Action: "audit.prune", Outcome: outcome,
		ProjectID: projectPolicy.ProjectID, Details: details,
	})
	return errors.Join(pruneErr, auditErr)
}

func validateGuestRelay(path string) error {
	file, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("guest relay must be a Linux ELF/AArch64 executable: %w", err)
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || file.Machine != elf.EM_AARCH64 || (file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN) {
		return fmt.Errorf("guest relay must be a 64-bit little-endian Linux ELF/AArch64 executable")
	}
	return nil
}

func (a *app) supervisor(ctx context.Context, dir string) (returnErr error) {
	projectPolicy, _, projectState, err := a.loadPolicy(dir)
	if err != nil {
		return err
	}
	if projectPolicy.Mode != "secure" {
		return fmt.Errorf("detached supervisor is available only for secure mode; dev mode must remain foreground-bound")
	}
	managed, err := a.startManagedSession(ctx, projectPolicy, projectState)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, managed.operationLock.Close()) }()
	destroyed := false
	recoveryRetained := false
	defer func() {
		if !destroyed {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			returnErr = errors.Join(returnErr, managed.active.Destroy(cleanupContext))
		}
		if !recoveryRetained {
			_ = os.RemoveAll(managed.runtimeBase)
		}
	}()
	idleTimeout := managed.initialActivation.idleTimeout
	controlled, err := newControlledSession(managed.active, projectState, managed.initialActivation, idleTimeout, managed.activationFactory, managed.gitBroker)
	if err != nil {
		return err
	}
	control, err := startApprovalControl(projectState, managed.runtimeBase, managed.gitBroker, controlled)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, control.Close()) }()
	expiry := time.NewTimer(controlled.expiryDelay(time.Now()))
	defer expiry.Stop()
	idleTimer := time.NewTimer(controlled.idleDelay(time.Now()))
	defer idleTimer.Stop()
	resetIdle := func(delay time.Duration) {
		if !idleTimer.Stop() {
			select {
			case <-idleTimer.C:
			default:
			}
		}
		idleTimer.Reset(delay)
	}
	resetExpiry := func(delay time.Duration) {
		if !expiry.Stop() {
			select {
			case <-expiry.C:
			default:
			}
		}
		expiry.Reset(delay)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-controlled.exit:
			recoveryRetained = controlled.recoveryRetained()
			destroyed = true
			return nil
		case <-expiry.C:
			pauseContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			pauseErr := controlled.pause(pauseContext)
			cancel()
			if pauseErr != nil {
				return fmt.Errorf("pause expired Agent Session: %w", pauseErr)
			}
			resetExpiry(controlled.expiryDelay(time.Now()))
		case <-controlled.activity:
			resetIdle(controlled.idleDelay(time.Now()))
			resetExpiry(controlled.expiryDelay(time.Now()))
		case now := <-idleTimer.C:
			if controlled.idleExpired(now) {
				pauseContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				pauseErr := controlled.pause(pauseContext)
				cancel()
				if pauseErr != nil {
					return fmt.Errorf("pause idle Agent Session: %w", pauseErr)
				}
			}
			idleTimer.Reset(controlled.idleDelay(time.Now()))
		}
	}
}

func (a *app) runForegroundDevAgent(ctx context.Context, projectPolicy policy.ProjectPolicy, projectState string) (returnErr error) {
	fmt.Fprintln(a.errors, "WARNING: dev mode permits direct Internet egress only while this foreground Agent Session is active; exfiltration prevention is not provided.")
	activeLock, err := a.requireActiveProjectDependency(projectPolicy)
	if err != nil {
		return err
	}
	managedOpenCode := a.prepareManagedOpenCodeAsync(ctx)
	managed, err := a.startManagedSession(ctx, projectPolicy, projectState)
	if err != nil {
		prepared := <-managedOpenCode
		return errors.Join(err, prepared.err)
	}
	defer func() { returnErr = errors.Join(returnErr, managed.operationLock.Close()) }()
	destroyed := false
	recoveryRetained := false
	defer func() {
		if !destroyed {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			returnErr = errors.Join(returnErr, managed.active.Destroy(cleanupContext))
		}
		if !recoveryRetained {
			_ = os.RemoveAll(managed.runtimeBase)
		}
	}()
	controlled, err := newControlledSession(managed.active, projectState, managed.initialActivation, managed.initialActivation.idleTimeout, managed.activationFactory, managed.gitBroker)
	if err != nil {
		return err
	}
	control, err := startApprovalControl(projectState, managed.runtimeBase, managed.gitBroker, controlled)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, control.Close()) }()
	prepared := <-managedOpenCode
	if prepared.err != nil {
		return prepared.err
	}
	tuiSessionRoot, err := createHostTUISessionRoot(managed.active.Root, managed.active.VMID, managed.initialActivation.activation.SessionID)
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, removeHostTUISessionRoot(managed.active.Root, managed.active.VMID, managed.initialActivation.activation.SessionID, tuiSessionRoot))
	}()
	tui, err := opencode.BuildHostTUICommand(ctx, opencode.HostTUIConfig{
		Binary: prepared.binary, ManagedToolDir: prepared.dir, VerifiedExecutable: prepared.verified,
		SessionRoot: tuiSessionRoot, ServerURL: managed.active.AttachURL,
		GuestWorkspace: managed.active.WorkspacePath, Password: managed.initialActivation.activation.ServerPassword,
		ExpectedExecutableSHA256: activeLock.Manifest.OpenCode.Host.ExecutableSHA256,
	}, os.Environ())
	if err != nil {
		return err
	}
	tui.Stdin, tui.Stdout, tui.Stderr = a.input, a.output, a.errors
	tuiErr := runHostTUIWithHeartbeat(ctx, tui, managed.initialActivation.idleTimeout, func(context.Context) error { return controlled.heartbeat() })
	exportContext, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	exportErr := controlled.exportAndDestroy(exportContext)
	cancel()
	recoveryRetained = controlled.recoveryRetained()
	destroyed = exportErr == nil || recoveryRetained
	if recoveryRetained {
		fmt.Fprintln(a.errors, "Dev export was refused. Direct egress and all session capabilities were revoked; the stopped VM was retained. Run 'sunaba status'; retry 'sunaba changes export', export the main workspace while explicitly discarding External Git state with 'sunaba changes export --discard-external-git', or discard the VM with 'sunaba recreate --discard-pending' / 'sunaba destroy --yes --discard-pending'.")
	}
	if exportErr == nil {
		if pending, err := loadPending(projectState, projectPolicy); err == nil {
			fmt.Fprintf(a.output, "Dev Agent Session ended; direct egress was quiesced and Change Set %s (%d changes) was exported.\n", pending.ChangeSet.Digest, len(pending.ChangeSet.Changes))
		} else {
			fmt.Fprintln(a.output, "Dev Agent Session ended; direct egress was quiesced and the VM was removed with no Project changes.")
		}
	}
	return errors.Join(tuiErr, exportErr)
}

func (a *app) runForegroundDevShell(ctx context.Context, projectPolicy policy.ProjectPolicy, projectState string) (returnErr error) {
	fmt.Fprintln(a.errors, "WARNING: dev mode permits direct Internet egress only while this foreground shell session is active; exfiltration prevention is not provided.")
	managed, err := a.startManagedSession(ctx, projectPolicy, projectState)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, managed.operationLock.Close()) }()
	destroyed := false
	recoveryRetained := false
	defer func() {
		if !destroyed {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			returnErr = errors.Join(returnErr, managed.active.Destroy(cleanupContext))
		}
		if !recoveryRetained {
			_ = os.RemoveAll(managed.runtimeBase)
		}
	}()
	controlled, err := newControlledSession(managed.active, projectState, managed.initialActivation, managed.initialActivation.idleTimeout, managed.activationFactory, managed.gitBroker)
	if err != nil {
		return err
	}
	control, err := startApprovalControl(projectState, managed.runtimeBase, managed.gitBroker, controlled)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, control.Close()) }()
	if err := a.runSanitizedShell(ctx, func(commandContext context.Context, command string) (string, error) {
		return controlled.shell(commandContext, command)
	}); err != nil {
		return err
	}
	exportContext, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	err = controlled.exportAndDestroy(exportContext)
	cancel()
	recoveryRetained = controlled.recoveryRetained()
	destroyed = err == nil || recoveryRetained
	if recoveryRetained {
		fmt.Fprintln(a.errors, "Dev export was refused. Direct egress and all session capabilities were revoked; the stopped VM was retained. Run 'sunaba status'; retry 'sunaba changes export', export the main workspace while explicitly discarding External Git state with 'sunaba changes export --discard-external-git', or discard the VM with 'sunaba recreate --discard-pending' / 'sunaba destroy --yes --discard-pending'.")
	}
	return err
}
