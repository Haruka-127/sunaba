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
	"sunaba/internal/secretstore"
	"sunaba/internal/session"
	"sunaba/internal/state"
)

type managedSession struct {
	active         *session.Session
	projectPolicy  policy.ProjectPolicy
	projectState   string
	runtimeBase    string
	serverPassword string
	expiresAt      time.Time
	gitBroker      pushApprovalBroker
	operationLock  *state.OperationLock
}

func (a *app) startManagedSession(ctx context.Context, projectPolicy policy.ProjectPolicy, projectState string) (*managedSession, error) {
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
	cleanupResult, err := cleanup.Run(ctx, cleanup.Config{Store: a.store, Runtime: a.runtime, Audit: recorder})
	if err != nil {
		return nil, err
	}
	if len(cleanupResult.Refused) > 0 {
		fmt.Fprintf(a.errors, "WARNING: cleanup refused resources without matching current ownership/lease: %s\n", strings.Join(cleanupResult.Refused, ", "))
	}
	upstreamBaseURL := "https://api.openai.com"
	upstreamKey := ""
	var oauthTokens modelgateway.OAuthTokenSource
	if projectPolicy.Model.AuthMode == modelcatalog.AuthOAuth {
		manager := openauth.NewManager()
		if _, err := manager.AccessToken(ctx); err != nil {
			return nil, err
		}
		upstreamBaseURL = "https://chatgpt.com/backend-api/codex"
		oauthTokens = manager
	} else {
		var err error
		upstreamKey, err = secretstore.LoadOpenAIKey(ctx)
		if err != nil {
			return nil, err
		}
	}
	sessionID, err := newSessionID()
	if err != nil {
		return nil, err
	}
	vmID := "sunaba-" + projectPolicy.ProjectID + "-" + sessionID
	modelToken, err := session.NewSecret()
	if err != nil {
		return nil, err
	}
	serverPassword, err := session.NewSecret()
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().Add(time.Duration(projectPolicy.Session.TTLSeconds) * time.Second)
	modelID := projectPolicy.Model.AllowedModels[0]
	capability, err := modelgateway.NewCapability(modelToken, projectPolicy.ProjectID, vmID, sessionID, projectPolicy.Model.AllowedModels, expiresAt)
	if err != nil {
		return nil, err
	}
	capability.MaxRequests = projectPolicy.Model.MaxRequests
	capability.MaxConcurrent = projectPolicy.Model.MaxConcurrent
	capability.MaxRequestBytes = projectPolicy.Model.MaxRequestBytes
	capability.MaxResponseBytes = projectPolicy.Model.MaxResponseBytes
	gateway, err := modelgateway.New(modelgateway.Config{
		UpstreamBaseURL: upstreamBaseURL, UpstreamAPIKey: upstreamKey, AuthMode: projectPolicy.Model.AuthMode, OAuthTokens: oauthTokens, Capability: capability,
		Audit: func(event modelgateway.AuditEvent) {
			_ = recorder.Append(audit.BoundaryEvent{Category: "model", Action: "model.request", Outcome: statusOutcome(event.Status), ProjectID: event.ProjectID, VMID: event.VMID, SessionID: event.SessionID, Details: map[string]string{
				"model": event.Model, "status": fmt.Sprint(event.Status), "request_bytes": fmt.Sprint(event.RequestBytes), "response_bytes": fmt.Sprint(event.ResponseBytes), "reason": event.Reason,
			}})
		},
	})
	if err != nil {
		return nil, err
	}
	provider, err := opencode.BuildModelGatewayConfig(opencode.ModelGatewayProviderConfig{
		BaseURL: "http://127.0.0.1:4141/v1", AllowedModels: projectPolicy.Model.AllowedModels,
		DefaultModel: modelID, TokenEnv: "SUNABA_MODEL_GATEWAY_TOKEN", AuthMode: projectPolicy.Model.AuthMode,
	})
	if err != nil {
		return nil, err
	}
	runtimeBase, err := makeRuntimeBase()
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
	gateways, err := a.configureGateways(ctx, projectPolicy, projectState, runtimeBase, vmID, sessionID, expiresAt, recorder)
	if err != nil {
		return nil, err
	}
	gatewaysHandedOff := false
	defer func() {
		if !gatewaysHandedOff {
			if gateways.webClose != nil {
				_ = gateways.webClose()
			}
			if gateways.gitClose != nil {
				_ = gateways.gitClose()
			}
		}
	}()
	exportPolicy, err := policy.CompileExportPolicy(projectPolicy.Export, projectPolicy.ProtectedPaths)
	if err != nil {
		return nil, err
	}
	config := session.Config{
		Store: a.store, Runtime: a.runtime, ProjectRoot: projectPolicy.ProjectRoot, RuntimeBase: runtimeBase,
		SessionID: sessionID, Mode: projectPolicy.Mode, Image: projectPolicy.Dependency.AgentImage,
		CPUs: projectPolicy.Resources.CPUs, Memory: projectPolicy.Resources.Memory, DiskBytes: projectPolicy.Resources.DiskBytes,
		ProcessMax: projectPolicy.Resources.ProcessMax, FileSizeMax: projectPolicy.Resources.FileSizeMax, OpenFileMax: projectPolicy.Resources.OpenFileMax,
		GuestRelayBinary: guestRelay, ProviderConfig: provider, ModelGateway: gateway, ModelToken: modelToken,
		GitGateway: gateways.gitHandler, GitRemotes: gateways.gitRemotes, GitGatewayClose: gateways.gitClose,
		WebGateway: gateways.webHandler, WebToken: gateways.webToken, WebGatewayClose: gateways.webClose,
		ServerPassword: serverPassword, LeaseTTL: time.Duration(projectPolicy.Session.TTLSeconds) * time.Second, Audit: recorder,
		SnapshotPolicy: exportPolicy.Snapshot, ExportPolicy: exportPolicy.Export, ExportPolicyDigest: exportPolicy.Digest,
	}
	var devBoundary *devnetwork.Boundary
	if projectPolicy.Mode == "dev" {
		devBoundary, err = devnetwork.Activate(ctx, a.store.Root, projectPolicy.ProjectID, sessionID)
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
	gatewaysHandedOff = true
	cleanupRuntime = false
	handedOff = true
	return &managedSession{
		active: active, projectPolicy: projectPolicy, projectState: projectState, runtimeBase: runtimeBase,
		serverPassword: serverPassword, expiresAt: expiresAt, gitBroker: gateways.gitBroker, operationLock: operationLock,
	}, nil
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
	defer func() {
		if !destroyed {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			returnErr = errors.Join(returnErr, managed.active.Destroy(cleanupContext))
		}
		_ = os.RemoveAll(managed.runtimeBase)
	}()
	idleTimeout := time.Duration(managed.projectPolicy.Session.IdleSeconds) * time.Second
	controlled, err := newControlledSession(managed.active, projectState, managed.serverPassword, managed.expiresAt, idleTimeout)
	if err != nil {
		return err
	}
	control, err := startApprovalControl(projectState, managed.runtimeBase, managed.gitBroker, controlled)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, control.Close()) }()
	expiry := time.NewTimer(time.Until(managed.expiresAt))
	defer expiry.Stop()
	expiryChannel := expiry.C
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
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-controlled.exit:
			destroyed = true
			return nil
		case <-expiryChannel:
			pauseContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			pauseErr := controlled.pause(pauseContext)
			cancel()
			if pauseErr != nil {
				return fmt.Errorf("pause expired Agent Session: %w", pauseErr)
			}
			expiryChannel = nil
		case <-controlled.activity:
			resetIdle(controlled.idleDelay(time.Now()))
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
	defer func() {
		if !destroyed {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			returnErr = errors.Join(returnErr, managed.active.Destroy(cleanupContext))
		}
		_ = os.RemoveAll(managed.runtimeBase)
	}()
	controlled, err := newControlledSession(managed.active, projectState, managed.serverPassword, managed.expiresAt, time.Duration(managed.projectPolicy.Session.IdleSeconds)*time.Second)
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
	tui, err := opencode.BuildHostTUICommand(ctx, opencode.HostTUIConfig{
		Binary: prepared.binary, ManagedToolDir: prepared.dir, VerifiedExecutable: prepared.verified,
		SessionRoot: managed.active.Root, ServerURL: managed.active.AttachURL,
		GuestWorkspace: managed.active.WorkspacePath, Password: managed.serverPassword,
		ExpectedExecutableSHA256: activeLock.Manifest.OpenCode.Host.ExecutableSHA256,
	}, os.Environ())
	if err != nil {
		return err
	}
	tui.Stdin, tui.Stdout, tui.Stderr = a.input, a.output, a.errors
	tuiErr := runHostTUIWithHeartbeat(ctx, tui, time.Duration(managed.projectPolicy.Session.IdleSeconds)*time.Second, func(context.Context) error { return controlled.heartbeat() })
	exportContext, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	exportErr := controlled.exportAndDestroy(exportContext)
	cancel()
	destroyed = exportErr == nil
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
	defer func() {
		if !destroyed {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			returnErr = errors.Join(returnErr, managed.active.Destroy(cleanupContext))
		}
		_ = os.RemoveAll(managed.runtimeBase)
	}()
	controlled, err := newControlledSession(managed.active, projectState, managed.serverPassword, managed.expiresAt, time.Duration(managed.projectPolicy.Session.IdleSeconds)*time.Second)
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
	destroyed = err == nil
	return err
}
