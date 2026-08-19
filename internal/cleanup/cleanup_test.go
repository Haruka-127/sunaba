package cleanup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/audit"
	"sunaba/internal/lease"
	"sunaba/internal/recovery"
	"sunaba/internal/runtime"
	"sunaba/internal/state"
	"sunaba/internal/workspace"
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

func TestCleanupKeepsExactStoppedDevRecoveryWithoutProcessGuard(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	root, _ = filepath.EvalSymlinks(root)
	recorder, err := audit.NewRecorder(filepath.Join(root, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	const projectID, vmID, sessionID = "0123456789ab", "vm123456", "session1"
	projectState := filepath.Join(root, "projects", projectID)
	if err := os.MkdirAll(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	projectState, err = filepath.EvalSymlinks(projectState)
	if err != nil {
		t.Fatal(err)
	}
	runtimeBase, err := recovery.NewRuntimeBase(projectState, vmID)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot := filepath.Join(runtimeBase, "sunaba-vm-"+vmID)
	if err := os.MkdirAll(filepath.Join(runtimeRoot, "snapshot"), 0700); err != nil {
		t.Fatal(err)
	}
	projectRoot, _ := filepath.EvalSymlinks(t.TempDir())
	baseline, err := workspace.BuildSnapshotManifest(projectRoot, workspace.DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	name := "sunaba-" + projectID + "-" + vmID
	record := recovery.State{Version: recovery.Version, ProjectID: projectID, ProjectRoot: projectRoot, VMID: vmID, SessionID: sessionID, Container: name, RuntimeBase: runtimeBase, RuntimeRoot: runtimeRoot, WorkspacePath: "/workspace/sunaba-" + vmID, Baseline: baseline, ExportPolicyDigest: strings.Repeat("a", 64), Reason: "guard refused", CreatedAt: time.Now().UTC()}
	if err := recovery.Save(projectState, record); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Load(projectState); err != nil {
		t.Fatalf("load recovery: %v", err)
	}
	labels := ownedLabels(projectID, vmID)
	labels["dev.sunaba.mode"] = "dev"
	fake := &cleanupRuntime{resources: map[string]runtime.Info{name: {Name: name, State: runtime.StateStopped, Labels: labels}}}
	result, err := Run(context.Background(), Config{Store: &state.Store{Root: root}, Runtime: fake, Audit: recorder})
	if err != nil || len(result.Kept) != 1 || result.Kept[0] != name || fake.removed != "" {
		t.Fatalf("result=%+v removed=%q error=%v", result, fake.removed, err)
	}
	// A running or label-substituted resource is never trusted merely because
	// a recovery record exists.
	item := fake.resources[name]
	item.State = runtime.StateRunning
	fake.resources[name] = item
	result, err = Run(context.Background(), Config{Store: &state.Store{Root: root}, Runtime: fake, Audit: recorder})
	if err != nil || len(result.Refused) != 1 || fake.removed != "" {
		t.Fatalf("running recovery result=%+v removed=%q error=%v", result, fake.removed, err)
	}
}

func TestCleanupRefusesStoppedVMWhenRecoveryRecordCouldNotBeSaved(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	recorder, err := audit.NewRecorder(filepath.Join(root, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	const projectID = "0123456789ab"
	resources := make(map[string]runtime.Info)
	for mode, vmID := range map[string]string{"dev": "vm123456", "secure": "vm654321"} {
		name := "sunaba-" + projectID + "-" + vmID
		labels := ownedLabels(projectID, vmID)
		labels["dev.sunaba.mode"] = mode
		resources[name] = runtime.Info{Name: name, State: runtime.StateStopped, Labels: labels}
	}
	fake := &cleanupRuntime{resources: resources}
	result, err := Run(context.Background(), Config{Store: &state.Store{Root: root}, Runtime: fake, Audit: recorder})
	if err != nil || len(result.Refused) != 2 || fake.stopped != "" || fake.removed != "" {
		t.Fatalf("unrecorded stopped dev result=%+v stopped=%q removed=%q error=%v", result, fake.stopped, fake.removed, err)
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

func ownedLabels(projectID, vmID string) map[string]string {
	return map[string]string{"dev.sunaba.owner": "sunaba-supervisor", "dev.sunaba.project": projectID, "dev.sunaba.vm": vmID, "dev.sunaba.mode": "secure"}
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
