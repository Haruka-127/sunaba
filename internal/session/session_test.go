package session

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"sunaba/internal/audit"
	"sunaba/internal/dependency"
	"sunaba/internal/runtime"
	"sunaba/internal/state"
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
	if err := s.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.state != runtime.StateRunning {
		t.Fatalf("resumed state=%s", fake.state)
	}
	if !strings.Contains(fake.setup, "test -d /var/lib/sunaba/repository") {
		t.Fatalf("resume did not restart guest services: %s", fake.setup)
	}
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
	for _, action := range []string{"capability.issued", "snapshot.created", "vm.created", "session.ready", "session.paused", "session.resumed", "capability.revoked", "vm.destroyed"} {
		if !strings.Contains(string(encodedAudit), `"action":"`+action+`"`) {
			t.Fatalf("audit missing action %q: %s", action, encodedAudit)
		}
	}
	if strings.Contains(string(encodedAudit), cfg.ModelToken) || strings.Contains(string(encodedAudit), cfg.ServerPassword) {
		t.Fatal("session secret was written to host audit")
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
	cfg.GitToken = strings.Repeat("g", 43)
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
	if !strings.Contains(fake.setup, "127.0.0.1:4242") || !strings.Contains(fake.setup, "remote.origin.url") || strings.Contains(fake.setup, cfg.GitToken) {
		t.Fatalf("Git guest setup is incomplete or leaked capability: %s", fake.setup)
	}
	client := sessionUnixHTTPClient(filepath.Join(s.Root, "git-gateway.sock"))
	request, _ := http.NewRequest(http.MethodGet, "http://sunaba/repository.git/info/refs?service=git-upload-pack", nil)
	response, err := client.Do(request)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("active Git Gateway response=%v error=%v", response, err)
	}
	_ = response.Body.Close()
	if err := s.Pause(context.Background()); err != nil {
		t.Fatal(err)
	}
	response, err = client.Do(request.Clone(context.Background()))
	if err != nil || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("paused Git Gateway response=%v error=%v", response, err)
	}
	_ = response.Body.Close()
	if err := s.Resume(context.Background()); err != nil {
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
	if strings.Contains(fake.setup, cfg.WebToken) {
		t.Fatal("guest setup command leaked Web capability")
	}
	aptConfig, err := os.ReadFile(filepath.Join(s.Root, "apt-proxy.conf"))
	if err != nil || !strings.Contains(string(aptConfig), cfg.WebToken) {
		t.Fatalf("bounded apt config was not created: error=%v data=%q", err, aptConfig)
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
	response, err = client.Do(request.Clone(context.Background()))
	if err != nil || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("paused Web Gateway response=%v error=%v", response, err)
	}
	_ = response.Body.Close()
	if err := s.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
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
	runtimeBase, err := os.MkdirTemp("/private/tmp", "sunaba-runtime-test-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runtimeBase, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeBase) })
	return Config{
		Store: &state.Store{Root: filepath.Join(root, "state")}, Runtime: fake,
		ProjectRoot: project, RuntimeBase: runtimeBase, SessionID: "phase1test", Image: dependency.MustPinned().AgentImage.Tag,
		CPUs: 2, Memory: "2G", GuestRelayBinary: relay, ProviderConfig: []byte(`{"provider":{}}`),
		DiskBytes: 128 << 20, ProcessMax: 64, FileSizeMax: 128 << 20, OpenFileMax: 1024,
		ModelGateway: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{}`) }),
		ModelToken:   strings.Repeat("m", 43), ServerPassword: strings.Repeat("p", 43),
		LeaseTTL: time.Minute, Audit: auditRecorder,
		OnEvent: func(Event) {},
	}, fake
}

type fakeRuntime struct {
	mu         sync.Mutex
	spec       runtime.ContainerSpec
	state      runtime.State
	setup      string
	setupError error
	listener   net.Listener
	server     *http.Server
	removed    bool
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
	if strings.Contains(joined, "getconf _NPROCESSORS_ONLN") {
		return "cpu=2\nmemory_kb=1048576\ndisk=120000000\nuid=1000\nnproc=64\nfsize=134217728\nnofile=1024\n", nil
	}
	f.setup = joined
	return "", f.setupError
}
func (f *fakeRuntime) CopyTo(context.Context, string, string, string) error { return nil }
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
