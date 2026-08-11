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
	defer s.Destroy(context.Background())
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
		ModelGateway: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{}`) }),
		ModelToken:   strings.Repeat("m", 43), ServerPassword: strings.Repeat("p", 43),
		LeaseTTL: time.Minute,
		OnEvent:  func(Event) {},
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
	f.setup = strings.Join(command, " ")
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
