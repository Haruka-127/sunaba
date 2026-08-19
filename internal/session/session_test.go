package session

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"sunaba/internal/audit"
	"sunaba/internal/dependency"
	"sunaba/internal/lease"
	"sunaba/internal/opencode"
	"sunaba/internal/runtime"
	"sunaba/internal/state"
	"sunaba/internal/testutil"
	"sunaba/internal/workspace"
)

func TestStartBuildsIsolatedVerticalSliceAndSerializesProject(t *testing.T) {
	cfg, fake := sessionFixture(t)
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if fake.spec.Image != dependency.MustPinned().AgentImage.Tag || len(fake.spec.Networks) != 1 || fake.spec.Networks[0] != "none" || !fake.spec.NoDNS {
		t.Fatalf("secure spec=%+v", fake.spec)
	}
	if len(fake.spec.Mounts) != 1 || fake.spec.Mounts[0].Type != "socket" || len(fake.spec.Sockets) != 1 {
		t.Fatalf("unexpected host mounts: %+v %+v", fake.spec.Mounts, fake.spec.Sockets)
	}
	if strings.Contains(fake.setup, cfg.ServerPassword) || strings.Contains(fake.setup, cfg.ModelToken) || strings.Contains(fake.setup, cfg.ProjectRoot) {
		t.Fatal("guest setup command leaked a secret or host Project path")
	}
	for _, expected := range []string{"mount -t overlay", "git init -q", "sunaba synthetic baseline", "--mdns=false", "127.0.0.1:4141"} {
		if !strings.Contains(fake.setup, expected) {
			t.Fatalf("guest setup missing %q: %s", expected, fake.setup)
		}
	}
	assertGuestRuntimeInputPermissions(t, fake.setup)
	if strings.Contains(fake.setup, "runuser -u sunaba-agent -- /bin/bash -lc 'set -a") {
		t.Fatal("OpenCode server was not started as VM root")
	}
	shellWrapper := fake.copies["/run/sunaba/shell-wrapper"]
	for _, expected := range []string{"/run/sunaba/session.env", "cd " + s.WorkspacePath, "GIT_DIR=/var/lib/sunaba/repository", `/bin/bash -lc "$1"`} {
		if !strings.Contains(string(shellWrapper), expected) {
			t.Fatalf("guest shell wrapper missing %q: %s", expected, shellWrapper)
		}
	}
	if strings.Contains(string(shellWrapper), cfg.ModelToken) || strings.Contains(string(shellWrapper), cfg.ServerPassword) {
		t.Fatal("guest shell wrapper contained a concrete capability")
	}
	wrapper := filepath.Join(t.TempDir(), "shell-wrapper")
	if err := os.WriteFile(wrapper, shellWrapper, 0500); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("/bin/bash", "-n", wrapper).CombinedOutput(); err != nil {
		t.Fatalf("guest shell wrapper syntax: %v: %s", err, output)
	}
	for _, name := range []string{"session.env", "opencode.json", "shell-wrapper", "session-input-bundle"} {
		if _, err := os.Lstat(filepath.Join(s.Root, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("copied host session input %s remained: %v", name, err)
		}
	}
	if err := s.Close(); err == nil {
		t.Fatal("Close released a live session without owned VM cleanup")
	}
	if _, err := Start(context.Background(), cfg); !errors.Is(err, state.ErrProjectLocked) {
		t.Fatalf("concurrent session error=%v", err)
	}
	if err := s.Pause(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.state != runtime.StateStopped {
		t.Fatalf("paused state=%s", fake.state)
	}
	if _, err := Start(context.Background(), cfg); !errors.Is(err, state.ErrProjectLocked) {
		t.Fatalf("pause released Project lock: %v", err)
	}
	if err := s.ResumeWith(context.Background(), rotatedActivation(cfg, "resume1")); err != nil {
		t.Fatal(err)
	}
	if fake.copyCount["/run/"] != 2 {
		t.Fatalf("resume did not restore the bundled ephemeral guest inputs: copies=%d", fake.copyCount["/run/"])
	}
	if fake.state != runtime.StateRunning {
		t.Fatalf("resumed state=%s", fake.state)
	}
	if !strings.Contains(fake.setup, "test -d /var/lib/sunaba/repository") {
		t.Fatalf("resume did not restart guest services: %s", fake.setup)
	}
	assertGuestRuntimeInputPermissions(t, fake.setup)
	if err := s.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(s.Root, "session.env")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("session secret file remained: %v", err)
	}
	if !fake.removed {
		t.Fatal("owned VM was not destroyed")
	}
	logs, err := filepath.Glob(filepath.Join(cfg.Audit.Root, s.ProjectID, "audit-*.jsonl"))
	if err != nil || len(logs) != 1 {
		t.Fatalf("audit logs=%v error=%v", logs, err)
	}
	encodedAudit, err := os.ReadFile(logs[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"capability.issued", "snapshot.created", "vm.created", "session.ready", "session.paused", "session.started", "capability.revoked", "vm.destroyed"} {
		if !strings.Contains(string(encodedAudit), `"action":"`+action+`"`) {
			t.Fatalf("audit missing action %q: %s", action, encodedAudit)
		}
	}
	if strings.Contains(string(encodedAudit), cfg.ModelToken) || strings.Contains(string(encodedAudit), cfg.ServerPassword) {
		t.Fatal("session secret was written to host audit")
	}
}

func assertGuestRuntimeInputPermissions(t *testing.T, command string) {
	t.Helper()
	for _, expected := range []string{
		"chown 0:1000 /run/sunaba",
		"chmod 0710 /run/sunaba",
		"chown 0:0 /run/sunaba/guest-relay",
		"chmod 0700 /run/sunaba/guest-relay",
		"chown 1000:1000 /run/sunaba/session.env /run/sunaba/opencode.json /run/sunaba/shell-wrapper",
		"chmod 0400 /run/sunaba/session.env /run/sunaba/opencode.json",
		"chmod 0500 /run/sunaba/shell-wrapper",
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("guest session input permissions missing %q: %s", expected, command)
		}
	}
}

func TestStartEnforcesConfiguredExportFileLimit(t *testing.T) {
	cfg, _ := sessionFixture(t)
	cfg.SnapshotPolicy.MaxFileSize = 4
	cfg.SnapshotPolicy.MaxTotalSize = 16
	cfg.ExportPolicy.Workspace = cfg.SnapshotPolicy
	if _, err := Start(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "exceeds maximum size 4") {
		t.Fatalf("configured export limit was not enforced: %v", err)
	}
}

func TestResumeKeepsAttachRelayAliveAfterOperationContextEnds(t *testing.T) {
	lifecycleContext, cancelLifecycle := context.WithCancel(context.Background())
	defer cancelLifecycle()
	cfg, _ := sessionFixture(t)
	s, err := Start(lifecycleContext, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Pause(context.Background()); err != nil {
		t.Fatal(err)
	}
	operationContext, cancelOperation := context.WithCancel(context.Background())
	activation := rotatedActivation(cfg, "resume2")
	if err := s.ResumeWith(operationContext, activation); err != nil {
		cancelOperation()
		t.Fatal(err)
	}
	cancelOperation()
	select {
	case err := <-s.attachDone:
		t.Fatalf("resume operation context stopped the session attach relay: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := opencode.GetHealth(context.Background(), s.AttachURL, activation.ServerPassword); err != nil {
		t.Fatalf("resumed attach relay is unavailable after operation completion: %v", err)
	}
	if err := s.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestResumeWithRotatesSessionAuthorityAfterExpiryAndRejectsOldToken(t *testing.T) {
	cfg, fake := sessionFixture(t)
	oldSessionID, oldToken := cfg.SessionID, cfg.ModelToken
	closed := 0
	cfg.LeaseTTL = 250 * time.Millisecond
	cfg.ModelGateway = tokenHandler(oldToken)
	cfg.ModelGatewayClose = func() error { closed++; return nil }
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	container := s.Container
	time.Sleep(300 * time.Millisecond)
	if err := s.Pause(context.Background()); err != nil {
		t.Fatal(err)
	}
	if closed != 1 {
		t.Fatalf("old Model Gateway authority was not revoked: closes=%d", closed)
	}
	activation := rotatedActivation(cfg, "rotated1")
	activation.LeaseTTL = time.Minute
	activation.ModelGateway = tokenHandler(activation.ModelToken)
	if err := s.ResumeWith(context.Background(), activation); err != nil {
		t.Fatal(err)
	}
	if s.Container != container || fake.spec.Name != container || s.SessionID != activation.SessionID {
		t.Fatalf("VM identity changed across rotation: container=%q spec=%q session=%q", s.Container, fake.spec.Name, s.SessionID)
	}
	registry := &lease.Registry{Root: filepath.Join(cfg.Store.Root, "leases")}
	oldLease, err := registry.Load(oldSessionID)
	if err != nil || oldLease.State != lease.Revoked {
		t.Fatalf("old lease=%+v error=%v", oldLease, err)
	}
	if err := registry.ValidateActive(s.ProjectID, s.Container, activation.SessionID, "model"); err != nil {
		t.Fatalf("new lease is inactive: %v", err)
	}
	client := sessionUnixHTTPClient(filepath.Join(s.Root, "model-gateway.sock"))
	request, _ := http.NewRequest(http.MethodGet, "http://sunaba/test", nil)
	request.Header.Set("Authorization", "Bearer "+oldToken)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old token status=%d", response.StatusCode)
	}
	request.Header.Set("Authorization", "Bearer "+activation.ModelToken)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("new token status=%d", response.StatusCode)
	}
	if err := s.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestResumeWithFailureRevokesPartialActivationAndAllowsFreshRetry(t *testing.T) {
	cfg, fake := sessionFixture(t)
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Pause(context.Background()); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(s.Root, "model-gateway.sock")
	if err := os.WriteFile(blocked, []byte("not a socket"), 0600); err != nil {
		t.Fatal(err)
	}
	failed := rotatedActivation(cfg, "failed1")
	failedClosed := 0
	failed.ModelGatewayClose = func() error { failedClosed++; return nil }
	if err := s.ResumeWith(context.Background(), failed); err == nil {
		t.Fatal("unsafe Gateway path did not fail activation")
	}
	registry := &lease.Registry{Root: filepath.Join(cfg.Store.Root, "leases")}
	record, err := registry.Load(failed.SessionID)
	if err != nil || record.State != lease.Revoked || failedClosed != 1 || fake.state != runtime.StateStopped {
		t.Fatalf("failed activation lease=%+v closes=%d VM=%s error=%v", record, failedClosed, fake.state, err)
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	retry := rotatedActivation(cfg, "retry01")
	if err := s.ResumeWith(context.Background(), retry); err != nil {
		t.Fatalf("fresh activation retry failed: %v", err)
	}
	if s.SessionID != retry.SessionID {
		t.Fatalf("retry Session ID=%q", s.SessionID)
	}
	if err := s.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func tokenHandler(token string) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token {
			http.Error(response, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		response.WriteHeader(http.StatusOK)
	})
}

func TestDevSessionVerifiesBoundaryOnStartAndResumeAndRevokesOnDestroy(t *testing.T) {
	cfg, fake := sessionFixture(t)
	cfg.Mode = "dev"
	canonical, err := state.ResolveProjectPath(cfg.ProjectRoot)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DevNetworkName = "sunaba-" + state.ProjectID(canonical) + "-" + cfg.VMID + "-net"
	verified, closed := 0, 0
	cfg.DevNetworkVerify = func(context.Context) error { verified++; return nil }
	quiesced := 0
	cfg.DevNetworkQuiesce = func(context.Context) error { quiesced++; return nil }
	cfg.DevNetworkClose = func(context.Context) error { closed++; return nil }
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if verified != 1 || fake.spec.NoDNS || len(fake.spec.Networks) != 1 || fake.spec.Networks[0] != cfg.DevNetworkName || fake.spec.Labels["dev.sunaba.mode"] != "dev" {
		t.Fatalf("dev boundary was not bound: verified=%d spec=%+v", verified, fake.spec)
	}
	if err := s.Pause(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.ResumeWith(context.Background(), rotatedActivation(cfg, "resume3")); err != nil {
		t.Fatal(err)
	}
	if verified != 2 {
		t.Fatalf("resume verification count=%d", verified)
	}
	if err := s.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if closed != 1 {
		t.Fatalf("dev boundary close count=%d", closed)
	}
	if quiesced != 0 {
		t.Fatalf("pause/resume unexpectedly quiesced export boundary: %d", quiesced)
	}
	if err := s.Close(); err != nil || closed != 1 {
		t.Fatalf("close was not idempotent: count=%d error=%v", closed, err)
	}
}

func TestDevSessionFailsClosedWhenBoundaryVerificationFails(t *testing.T) {
	cfg, fake := sessionFixture(t)
	cfg.Mode = "dev"
	canonical, err := state.ResolveProjectPath(cfg.ProjectRoot)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DevNetworkName = "sunaba-" + state.ProjectID(canonical) + "-" + cfg.VMID + "-net"
	closed := 0
	cfg.DevNetworkVerify = func(context.Context) error { return errors.New("injected firewall mismatch") }
	cfg.DevNetworkQuiesce = func(context.Context) error { return nil }
	cfg.DevNetworkClose = func(context.Context) error { closed++; return nil }
	if _, err := Start(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "boundary verification") {
		t.Fatalf("verification error=%v", err)
	}
	current, _ := fake.ContainerState(context.Background(), "")
	if current != runtime.StateNotFound || closed != 1 {
		t.Fatalf("failed dev start created VM or retained network: state=%s closed=%d", current, closed)
	}
}

func TestDevExportQuiesceFailureStopsVMAndCapabilities(t *testing.T) {
	cfg, fake := sessionFixture(t)
	cfg.Mode = "dev"
	canonical, err := state.ResolveProjectPath(cfg.ProjectRoot)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DevNetworkName = "sunaba-" + state.ProjectID(canonical) + "-" + cfg.VMID + "-net"
	cfg.DevNetworkVerify = func(context.Context) error { return nil }
	cfg.DevNetworkQuiesce = func(context.Context) error { return errors.New("injected quiesce failure") }
	cfg.DevNetworkClose = func(context.Context) error { return nil }
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StopAndExport(context.Background()); err == nil || !strings.Contains(err.Error(), "quiesce") {
		t.Fatalf("quiesce error=%v", err)
	}
	if fake.state != runtime.StateStopped || s.gatewayActive.Load() {
		t.Fatalf("failed quiesce left dev VM active: state=%s gateway=%t", fake.state, s.gatewayActive.Load())
	}
	if err := s.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDevExternalGitRefusalStopsVMRevokesCapabilitiesAndClosesNetwork(t *testing.T) {
	cfg, fake := sessionFixture(t)
	cfg.Mode = "dev"
	canonical, err := state.ResolveProjectPath(cfg.ProjectRoot)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DevNetworkName = "sunaba-" + state.ProjectID(canonical) + "-" + cfg.VMID + "-net"
	cfg.DevNetworkVerify = func(context.Context) error { return nil }
	quiesced, closed := 0, 0
	cfg.DevNetworkQuiesce = func(context.Context) error { quiesced++; return nil }
	cfg.DevNetworkClose = func(context.Context) error { closed++; return nil }
	fake.externalGitUnsafe = true
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.StopAndExport(context.Background())
	var recoveryErr *RecoveryRequiredError
	if !errors.As(err, &recoveryErr) {
		t.Fatalf("error=%v", err)
	}
	if fake.state != runtime.StateStopped || fake.removed || quiesced != 1 || closed != 1 || s.gatewayActive.Load() || s.leaseCreated {
		t.Fatalf("state=%s removed=%t quiesced=%d closed=%d gateway=%t lease=%t", fake.state, fake.removed, quiesced, closed, s.gatewayActive.Load(), s.leaseCreated)
	}
	if err := s.DetachForRecovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.removed {
		t.Fatal("detaching recovery removed the stopped VM")
	}
}

func TestPausedExportRevokesCapabilityBeforeRestartAndKeepsMountSocket(t *testing.T) {
	cfg, fake := sessionFixture(t)
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Pause(context.Background()); err != nil {
		t.Fatal(err)
	}
	startObserved := false
	fake.startHook = func() {
		startObserved = true
		if s.gatewayActive.Load() {
			t.Fatal("paused export re-enabled the Gateway before restart")
		}
		if err := s.leaseRegistry.ValidateActive(s.ProjectID, s.Container, s.SessionID, "model"); err == nil {
			t.Fatal("paused export restarted the VM with an active capability")
		}
		info, err := os.Lstat(filepath.Join(s.Root, "model-gateway.sock"))
		if err != nil || info.Mode()&os.ModeSocket == 0 {
			t.Fatalf("Gateway mount source disappeared before restart: mode=%v error=%v", info, err)
		}
	}
	fake.startError = errors.New("injected restart failure")
	if _, err := s.StopAndExport(context.Background()); err == nil || !strings.Contains(err.Error(), "start paused session VM for export") {
		t.Fatalf("restart error=%v", err)
	}
	if !startObserved {
		t.Fatal("paused export did not attempt a bounded restart")
	}
	if err := s.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPausedExportRemountsWorkspaceBeforeFreeze(t *testing.T) {
	cfg, fake := sessionFixture(t)
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Pause(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := len(fake.commands)
	if _, err := s.StopAndExport(context.Background()); err == nil || !strings.Contains(err.Error(), "export frozen session root filesystem") {
		t.Fatalf("export error=%v", err)
	}
	commands := fake.commands[before:]
	if len(commands) < 3 || !strings.Contains(commands[0], "test -f /var/lib/sunaba/overlay.img") || !strings.Contains(commands[0], "mount -t overlay overlay") || strings.Contains(commands[0], "nohup") {
		t.Fatalf("paused export remount command=%q", commands)
	}
	if !strings.Contains(commands[1], "SUNABA_EXTERNAL_GIT_SAFE") || !strings.Contains(commands[2], "/var/lib/sunaba/merged-export") {
		t.Fatalf("workspace freeze did not follow remount: %q", commands)
	}
	if strings.Contains(commands[2], "/var/lib/sunaba/overlay/upper/. /var/lib/sunaba/upper/") {
		t.Fatalf("workspace freeze copied both merged and upper trees: %q", commands[2])
	}
	if err := s.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDestroyBypassesExportGuardForExplicitDiscard(t *testing.T) {
	cfg, fake := sessionFixture(t)
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	before := len(fake.commands)
	if err := s.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, command := range fake.commands[before:] {
		if strings.Contains(command, "SUNABA_EXTERNAL_GIT_SAFE") {
			t.Fatalf("explicit destroy unexpectedly ran export guard: %q", command)
		}
	}
}

func TestPauseFailsClosedWhenAuditCannotAppend(t *testing.T) {
	cfg, fake := sessionFixture(t)
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	projectAudit := filepath.Join(cfg.Audit.Root, s.ProjectID)
	if err := os.Chmod(projectAudit, 0755); err != nil {
		t.Fatal(err)
	}
	if err := s.Pause(context.Background()); err == nil {
		t.Fatal("audit failure was hidden")
	}
	if fake.state != runtime.StateStopped || s.gatewayActive.Load() {
		t.Fatalf("pause did not fail closed: state=%s gate=%v", fake.state, s.gatewayActive.Load())
	}
	if err := s.leaseRegistry.ValidateActive(s.ProjectID, s.Container, s.SessionID, "model"); err == nil {
		t.Fatal("audit failure left the persistent capability active")
	}
	if err := os.Chmod(projectAudit, 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSessionBindsOptionalGitGatewayToLifecycle(t *testing.T) {
	cfg, fake := sessionFixture(t)
	closed := false
	cfg.GitRemotes = []GitRemote{
		{Name: "origin", Token: strings.Repeat("g", 43)},
		{Name: "upstream", Token: strings.Repeat("h", 43)},
	}
	cfg.GitGateway = http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "git-gateway")
	})
	cfg.GitGatewayClose = func() error { closed = true; return nil }
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.spec.Mounts) != 2 || fake.spec.Mounts[1].Target != runtime.SecureGitGatewayGuestPath {
		t.Fatalf("Git Gateway mount=%+v", fake.spec.Mounts)
	}
	if !strings.Contains(fake.setup, "127.0.0.1:4242") || !strings.Contains(fake.setup, "remote.origin.url") || !strings.Contains(fake.setup, "remote.upstream.url") || !strings.Contains(fake.setup, "GIT_CONFIG_COUNT=2") || strings.Contains(fake.setup, cfg.GitRemotes[0].Token) || strings.Contains(fake.setup, cfg.GitRemotes[1].Token) {
		t.Fatalf("Git guest setup is incomplete or leaked capability: %s", fake.setup)
	}
	client := sessionUnixHTTPClient(filepath.Join(s.Root, "git-gateway.sock"))
	request, _ := http.NewRequest(http.MethodGet, "http://sunaba/origin.git/info/refs?service=git-upload-pack", nil)
	response, err := client.Do(request)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("active Git Gateway response=%v error=%v", response, err)
	}
	_ = response.Body.Close()
	if err := s.Pause(context.Background()); err != nil {
		t.Fatal(err)
	}
	if response, err = client.Do(request.Clone(context.Background())); err == nil {
		_ = response.Body.Close()
		t.Fatalf("paused Git Gateway remained reachable: status=%d", response.StatusCode)
	}
	if err := s.ResumeWith(context.Background(), rotatedActivation(cfg, "resume4")); err != nil {
		t.Fatal(err)
	}
	response, err = client.Do(request.Clone(context.Background()))
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("resumed Git Gateway response=%v error=%v", response, err)
	}
	_ = response.Body.Close()
	if err := s.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !closed {
		t.Fatal("session end did not close the Git approval channel")
	}
}

func TestSessionBindsOptionalWebGatewayAndProxyEnvironmentToLifecycle(t *testing.T) {
	cfg, fake := sessionFixture(t)
	closed := false
	cfg.WebToken = strings.Repeat("w", 43)
	cfg.WebGateway = http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "web-gateway")
	})
	cfg.WebGatewayClose = func() error { closed = true; return nil }
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.spec.Mounts) != 2 || fake.spec.Mounts[1].Target != runtime.SecureWebGatewayGuestPath {
		t.Fatalf("Web Gateway mount=%+v", fake.spec.Mounts)
	}
	for _, expected := range []string{"127.0.0.1:4343", "HTTP_PROXY=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343", "NO_PROXY=127.0.0.1,localhost", "APT_CONFIG=/run/sunaba/apt-proxy.conf"} {
		if !strings.Contains(fake.setup, expected) {
			t.Fatalf("Web guest setup missing %q: %s", expected, fake.setup)
		}
	}
	assertGuestWebRuntimeInputPermissions(t, fake.setup)
	if strings.Contains(fake.setup, cfg.WebToken) {
		t.Fatal("guest setup command leaked Web capability")
	}
	aptConfig := fake.copies["/run/sunaba/apt-proxy.conf"]
	if !strings.Contains(string(aptConfig), cfg.WebToken) {
		t.Fatalf("bounded apt config was not copied into the guest: data=%q", aptConfig)
	}
	if _, err := os.Lstat(filepath.Join(s.Root, "apt-proxy.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("host Web capability file remained after guest copy: %v", err)
	}
	client := sessionUnixHTTPClient(filepath.Join(s.Root, "web-gateway.sock"))
	request, _ := http.NewRequest(http.MethodGet, "http://sunaba/test", nil)
	response, err := client.Do(request)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("active Web Gateway response=%v error=%v", response, err)
	}
	_ = response.Body.Close()
	if err := s.Pause(context.Background()); err != nil {
		t.Fatal(err)
	}
	if response, err = client.Do(request.Clone(context.Background())); err == nil {
		_ = response.Body.Close()
		t.Fatalf("paused Web Gateway remained reachable: status=%d", response.StatusCode)
	}
	if err := s.ResumeWith(context.Background(), rotatedActivation(cfg, "resume5")); err != nil {
		t.Fatal(err)
	}
	assertGuestWebRuntimeInputPermissions(t, fake.setup)
	if err := s.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !closed {
		t.Fatal("session end did not revoke the Web Gateway")
	}
	if _, err := os.Lstat(filepath.Join(s.Root, "apt-proxy.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("host apt capability file remained: %v", err)
	}
}

func assertGuestWebRuntimeInputPermissions(t *testing.T, command string) {
	t.Helper()
	for _, expected := range []string{
		"chown 1000:1000 /run/sunaba/apt-proxy.conf",
		"chmod 0400 /run/sunaba/apt-proxy.conf",
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("guest Web session input permissions missing %q: %s", expected, command)
		}
	}
}

func TestSessionRejectsReusedWebCapability(t *testing.T) {
	cfg, _ := sessionFixture(t)
	cfg.WebGateway = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	cfg.WebGatewayClose = func() error { return nil }
	cfg.WebToken = cfg.ModelToken
	if _, err := Start(context.Background(), cfg); err == nil {
		t.Fatal("reused Model/Web capability was accepted")
	}
}

func sessionUnixHTTPClient(socketPath string) *http.Client {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	}}
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}
}

func TestStartFailureRemovesOwnedVMAndReleasesProjectLock(t *testing.T) {
	cfg, fake := sessionFixture(t)
	fake.setupError = errors.New("injected setup failure")
	if _, err := Start(context.Background(), cfg); err == nil {
		t.Fatal("injected setup failure was ignored")
	}
	if !fake.removed {
		t.Fatal("partially created VM was not removed")
	}
	fake.setupError = nil
	fake.removed = false
	cfg.SessionID = "phase1retry"
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Project lock remained after rollback: %v", err)
	}
	defer s.Destroy(context.Background())
}

func TestStartDiskPressureFailsClosedAndReleasesProject(t *testing.T) {
	cfg, fake := sessionFixture(t)
	fake.setupError = unix.ENOSPC
	if _, err := Start(context.Background(), cfg); !errors.Is(err, unix.ENOSPC) {
		t.Fatalf("disk pressure error=%v", err)
	}
	if !fake.removed || fake.state != runtime.StateNotFound {
		t.Fatalf("disk pressure left owned VM state=%s removed=%v", fake.state, fake.removed)
	}
	fake.setupError = nil
	fake.removed = false
	cfg.SessionID = "diskretry"
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("disk pressure rollback retained Project lock: %v", err)
	}
	if err := s.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNewSecretProducesDistinctURLSafeValues(t *testing.T) {
	first, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !secretPattern.MatchString(first) || !secretPattern.MatchString(second) {
		t.Fatalf("invalid secrets %q %q", first, second)
	}
}

func sessionFixture(t *testing.T) (Config, *fakeRuntime) {
	t.Helper()
	root := t.TempDir()
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "hello.txt"), []byte("baseline\n"), 0600); err != nil {
		t.Fatal(err)
	}
	relay := filepath.Join(root, "guest-relay")
	if err := os.WriteFile(relay, []byte("fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	fake := &fakeRuntime{}
	auditRecorder, err := audit.NewRecorder(filepath.Join(root, "state", "audit"))
	if err != nil {
		t.Fatal(err)
	}
	runtimeBase := testutil.PrivateTempDir(t, "sunaba-runtime-test-")
	return Config{
		Store: &state.Store{Root: filepath.Join(root, "state")}, Runtime: fake,
		ProjectRoot: project, RuntimeBase: runtimeBase, VMID: "vmphase1test", SessionID: "phase1test", Image: dependency.MustPinned().AgentImage.Tag,
		CPUs: 2, Memory: "2G", GuestRelayBinary: relay, ProviderConfig: []byte(`{"provider":{}}`),
		DiskBytes: 128 << 20, ProcessMax: 64, FileSizeMax: 128 << 20, OpenFileMax: 1024,
		ModelGateway:      http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{}`) }),
		ModelGatewayClose: func() error { return nil },
		ModelToken:        strings.Repeat("m", 43), ServerPassword: strings.Repeat("p", 43),
		LeaseTTL: time.Minute, Audit: auditRecorder,
		SnapshotPolicy: workspace.DefaultSnapshotPolicy(), ExportPolicy: workspace.DefaultExportPolicy(), ExportPolicyDigest: strings.Repeat("a", 64),
		OnEvent: func(Event) {},
	}, fake
}

func rotatedActivation(cfg Config, sessionID string) Activation {
	activation := activationFromConfig(cfg)
	activation.SessionID = sessionID
	activation.ModelToken = strings.Repeat("n", 42) + sessionID[len(sessionID)-1:]
	activation.ServerPassword = strings.Repeat("q", 42) + sessionID[len(sessionID)-1:]
	for index := range activation.GitRemotes {
		activation.GitRemotes[index].Token = strings.Repeat(string(rune('r'+index)), 42) + sessionID[len(sessionID)-1:]
	}
	if activation.WebGateway != nil {
		activation.WebToken = strings.Repeat("z", 42) + sessionID[len(sessionID)-1:]
	}
	return activation
}

type fakeRuntime struct {
	mu                sync.Mutex
	spec              runtime.ContainerSpec
	state             runtime.State
	setup             string
	externalGitUnsafe bool
	setupError        error
	listener          net.Listener
	server            *http.Server
	removed           bool
	copies            map[string][]byte
	copyCount         map[string]int
	commands          []string
	startHook         func()
	startError        error
}

func (f *fakeRuntime) ImageExists(context.Context, string) (bool, error) { return true, nil }
func (f *fakeRuntime) BuildImage(context.Context, string, string, map[string]string) error {
	return nil
}
func (f *fakeRuntime) ContainerState(context.Context, string) (runtime.State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.removed || f.state == "" {
		return runtime.StateNotFound, nil
	}
	return f.state, nil
}
func (f *fakeRuntime) Create(context.Context, runtime.ContainerSpec) error {
	return errors.New("unsafe Create called")
}
func (f *fakeRuntime) CreateSecure(_ context.Context, spec runtime.ContainerSpec, policy runtime.SecureSessionPolicy) error {
	if err := runtime.ValidateSecureSessionSpec(spec, policy); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.spec, f.state, f.removed = spec, runtime.StateRunning, false
	listener, err := net.Listen("unix", spec.Sockets[0].HostPath)
	if err != nil {
		return err
	}
	f.listener = listener
	f.server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/global/health" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"version":"`+dependency.OpenCodeVersion+`"}`)
			return
		}
		http.NotFound(w, r)
	})}
	go func() { _ = f.server.Serve(listener) }()
	return nil
}
func (f *fakeRuntime) Start(context.Context, string) error {
	if f.startHook != nil {
		f.startHook()
	}
	if f.startError != nil {
		return f.startError
	}
	f.state = runtime.StateRunning
	return nil
}
func (f *fakeRuntime) Stop(context.Context, string) error { f.state = runtime.StateStopped; return nil }
func (f *fakeRuntime) Remove(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.server != nil {
		_ = f.server.Close()
	}
	f.removed, f.state = true, runtime.StateNotFound
	return nil
}
func (f *fakeRuntime) Exec(context.Context, string, bool, []string) error { return nil }
func (f *fakeRuntime) ExecOutput(_ context.Context, _ string, command []string) (string, error) {
	joined := strings.Join(command, " ")
	f.commands = append(f.commands, joined)
	if strings.Contains(joined, "SUNABA_EXTERNAL_GIT_SAFE") {
		if f.externalGitUnsafe {
			return "SUNABA_EXTERNAL_GIT_UNSAFE", nil
		}
		return "SUNABA_EXTERNAL_GIT_SAFE", nil
	}
	if strings.Contains(joined, "opencode serve") {
		f.setup = joined
		if f.setupError != nil {
			return "", f.setupError
		}
	}
	if strings.Contains(joined, "getconf _NPROCESSORS_ONLN") {
		return guestResourceProbeBegin + "\ncpu=2\nmemory_kb=1048576\ndisk=120000000\nuid=0\nnproc=64\nfsize=134217728\nnofile=1024\n" + guestResourceProbeEnd + "\n", nil
	}
	f.setup = joined
	return "", f.setupError
}
func (f *fakeRuntime) CopyTo(_ context.Context, _ string, source, target string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		if info, statErr := os.Stat(source); statErr == nil && info.IsDir() {
			if f.copyCount == nil {
				f.copyCount = make(map[string]int)
			}
			f.copyCount[target]++
			if target != "/run/" || filepath.Base(source) != "sunaba" {
				return nil
			}
			if f.copies == nil {
				f.copies = make(map[string][]byte)
			}
			return filepath.Walk(source, func(path string, entry os.FileInfo, walkErr error) error {
				if walkErr != nil || entry.IsDir() {
					return walkErr
				}
				relative, relErr := filepath.Rel(source, path)
				if relErr != nil {
					return relErr
				}
				contents, readErr := os.ReadFile(path)
				if readErr != nil {
					return readErr
				}
				f.copies[filepath.Join("/run/sunaba", relative)] = contents
				return nil
			})
		}
		return err
	}
	if f.copies == nil {
		f.copies = make(map[string][]byte)
	}
	if f.copyCount == nil {
		f.copyCount = make(map[string]int)
	}
	f.copies[target] = append([]byte(nil), data...)
	f.copyCount[target]++
	return nil
}
func (f *fakeRuntime) Export(context.Context, string, string) error {
	return errors.New("not implemented")
}
func (f *fakeRuntime) IPAddress(context.Context, string) (string, error) { return "", nil }
func (f *fakeRuntime) Inspect(context.Context, string) (runtime.Info, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.removed || f.state == "" {
		return runtime.Info{}, errors.New("not found")
	}
	return runtime.Info{Name: f.spec.Name, State: f.state, Labels: f.spec.Labels}, nil
}
func (f *fakeRuntime) List(context.Context) ([]runtime.Info, error) { return nil, nil }
