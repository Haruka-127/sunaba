package cleanup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sunaba/internal/audit"
	"sunaba/internal/lease"
	"sunaba/internal/runtime"
	"sunaba/internal/state"
)

func TestCleanupKeepsLiveSessionAndRemovesGuardlessOrphan(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	recorder, err := audit.NewRecorder(filepath.Join(root, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	registry := &lease.Registry{Root: filepath.Join(root, "leases")}
	name := "sunaba-project-session"
	if _, err := registry.Register("project", name, "session", "model", time.Minute); err != nil {
		t.Fatal(err)
	}
	guard, err := registry.AcquireGuard("session")
	if err != nil {
		t.Fatal(err)
	}
	managed := runtime.Info{Name: name, State: runtime.StateRunning, Labels: ownedLabels("project", "session")}
	fake := &cleanupRuntime{resources: map[string]runtime.Info{name: managed, "unrelated": {Name: "unrelated", State: runtime.StateRunning}}}
	cfg := Config{Store: &state.Store{Root: root}, Runtime: fake, Audit: recorder}
	result, err := Run(context.Background(), cfg)
	if err != nil || len(result.Kept) != 1 || fake.removed != "" {
		t.Fatalf("live result=%+v removed=%q error=%v", result, fake.removed, err)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	result, err = Run(context.Background(), cfg)
	if err != nil || len(result.Removed) != 1 || fake.stopped != name || fake.removed != name {
		t.Fatalf("orphan result=%+v stopped=%q removed=%q error=%v", result, fake.stopped, fake.removed, err)
	}
	record, err := registry.Load("session")
	if err != nil || record.State != lease.Revoked {
		t.Fatalf("lease=%+v error=%v", record, err)
	}
}

func TestCleanupRecoversPersistedActiveLeaseAfterSupervisorRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	recorder, err := audit.NewRecorder(filepath.Join(root, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	name := "sunaba-project-restarted"
	registryBeforeRestart := &lease.Registry{Root: filepath.Join(root, "leases")}
	if _, err := registryBeforeRestart.Register("project", name, "restarted", "model", time.Hour); err != nil {
		t.Fatal(err)
	}
	// No process guard survives a host reboot. A new Supervisor instance only has
	// the durable lease and exact ownership labels from before the restart.
	fake := &cleanupRuntime{resources: map[string]runtime.Info{name: {Name: name, State: runtime.StateRunning, Labels: ownedLabels("project", "restarted")}}}
	result, err := Run(context.Background(), Config{Store: &state.Store{Root: root}, Runtime: fake, Audit: recorder})
	if err != nil || len(result.Removed) != 1 || result.Removed[0] != name || fake.stopped != name || fake.removed != name {
		t.Fatalf("restart recovery result=%+v stopped=%q removed=%q error=%v", result, fake.stopped, fake.removed, err)
	}
	registryAfterRestart := &lease.Registry{Root: filepath.Join(root, "leases")}
	record, err := registryAfterRestart.Load("restarted")
	if err != nil || record.State != lease.Revoked {
		t.Fatalf("restart recovery lease=%+v error=%v", record, err)
	}
}

func TestCleanupRefusesLabelOrLeaseSubstitution(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	recorder, err := audit.NewRecorder(filepath.Join(root, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	registry := &lease.Registry{Root: filepath.Join(root, "leases")}
	if _, err := registry.Register("project", "sunaba-project-session", "session", "model", time.Minute); err != nil {
		t.Fatal(err)
	}
	wrongLabels := runtime.Info{Name: "sunaba-project-other", State: runtime.StateStopped, Labels: ownedLabels("project", "session")}
	wrongLease := runtime.Info{Name: "sunaba-project-session", State: runtime.StateStopped, Labels: ownedLabels("other", "session")}
	fake := &cleanupRuntime{resources: map[string]runtime.Info{wrongLabels.Name: wrongLabels, wrongLease.Name: wrongLease}}
	result, err := Run(context.Background(), Config{Store: &state.Store{Root: root}, Runtime: fake, Audit: recorder})
	if err != nil || len(result.Refused) != 2 || fake.removed != "" {
		t.Fatalf("result=%+v removed=%q error=%v", result, fake.removed, err)
	}
}

func TestCleanupDoesNotMutateWhenAuditIsUnsafe(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	recorder, err := audit.NewRecorder(filepath.Join(root, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	registry := &lease.Registry{Root: filepath.Join(root, "leases")}
	name := "sunaba-project-session"
	if _, err := registry.Register("project", name, "session", "model", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(recorder.Root, 0755); err != nil {
		t.Fatal(err)
	}
	fake := &cleanupRuntime{resources: map[string]runtime.Info{name: {Name: name, State: runtime.StateRunning, Labels: ownedLabels("project", "session")}}}
	if _, err := Run(context.Background(), Config{Store: &state.Store{Root: root}, Runtime: fake, Audit: recorder}); err == nil {
		t.Fatal("unsafe audit did not stop cleanup")
	}
	if fake.stopped != "" || fake.removed != "" {
		t.Fatalf("cleanup mutated resource without audit: stopped=%q removed=%q", fake.stopped, fake.removed)
	}
}

func ownedLabels(projectID, sessionID string) map[string]string {
	return map[string]string{"dev.sunaba.owner": "sunaba-supervisor", "dev.sunaba.project": projectID, "dev.sunaba.session": sessionID, "dev.sunaba.mode": "secure"}
}

type cleanupRuntime struct {
	resources map[string]runtime.Info
	stopped   string
	removed   string
}

func (f *cleanupRuntime) List(context.Context) ([]runtime.Info, error) {
	out := make([]runtime.Info, 0, len(f.resources))
	for _, info := range f.resources {
		out = append(out, info)
	}
	return out, nil
}
func (f *cleanupRuntime) Inspect(_ context.Context, name string) (runtime.Info, error) {
	info, ok := f.resources[name]
	if !ok {
		return runtime.Info{}, errors.New("not found")
	}
	return info, nil
}
func (f *cleanupRuntime) Stop(_ context.Context, name string) error {
	info := f.resources[name]
	info.State = runtime.StateStopped
	f.resources[name] = info
	f.stopped = name
	return nil
}
func (f *cleanupRuntime) Remove(_ context.Context, name string) error {
	delete(f.resources, name)
	f.removed = name
	return nil
}
func (f *cleanupRuntime) ImageExists(context.Context, string) (bool, error) { return false, nil }
func (f *cleanupRuntime) BuildImage(context.Context, string, string, map[string]string) error {
	return nil
}
func (f *cleanupRuntime) ContainerState(context.Context, string) (runtime.State, error) {
	return runtime.StateUnknown, nil
}
func (f *cleanupRuntime) Create(context.Context, runtime.ContainerSpec) error { return nil }
func (f *cleanupRuntime) CreateSecure(context.Context, runtime.ContainerSpec, runtime.SecureSessionPolicy) error {
	return nil
}
func (f *cleanupRuntime) Start(context.Context, string) error                { return nil }
func (f *cleanupRuntime) Exec(context.Context, string, bool, []string) error { return nil }
func (f *cleanupRuntime) ExecOutput(context.Context, string, []string) (string, error) {
	return "", nil
}
func (f *cleanupRuntime) CopyTo(context.Context, string, string, string) error { return nil }
func (f *cleanupRuntime) Export(context.Context, string, string) error         { return nil }
func (f *cleanupRuntime) IPAddress(context.Context, string) (string, error)    { return "", nil }
