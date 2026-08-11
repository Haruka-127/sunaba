//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sunaba/internal/audit"
	"sunaba/internal/cleanup"
	"sunaba/internal/dependency"
	"sunaba/internal/lease"
	sunabaruntime "sunaba/internal/runtime"
	"sunaba/internal/state"
)

func TestPhase2ActualOrphanCleanup(t *testing.T) {
	if os.Getenv("SUNABA_PHASE2_INTEGRATION") != "1" {
		t.Skip("set SUNABA_PHASE2_INTEGRATION=1 on the pinned macOS/Apple Container host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	runID := randomID(t)
	projectID := "cleanup" + runID
	sessionID := "session" + runID
	name := "sunaba-" + projectID + "-" + sessionID
	runtimeBase, err := os.MkdirTemp("/private/tmp", "sunaba-phase2-cleanup-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runtimeBase, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(runtimeBase)
	rt := sunabaruntime.NewAppleContainer(false)
	defer cleanupContainer(t, context.Background(), rt, name, runID)
	labels := map[string]string{
		"dev.sunaba.owner": "sunaba-supervisor", "dev.sunaba.project": projectID,
		"dev.sunaba.session": sessionID, "dev.sunaba.mode": "secure", "dev.sunaba.run-id": runID,
	}
	if err := rt.Create(ctx, sunabaruntime.ContainerSpec{
		Name: name, Image: dependency.MustPinned().AgentImage.Tag, CPUs: 1, Memory: "1G",
		Networks: []string{"none"}, NoDNS: true, Labels: labels,
		Entrypoint: "/bin/bash", Args: []string{"-lc", "exec tail -f /dev/null"},
	}); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(runtimeBase, "state")}
	recorder, err := audit.NewRecorder(filepath.Join(store.Root, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	registry := &lease.Registry{Root: filepath.Join(store.Root, "leases")}
	if _, err := registry.Register(projectID, name, sessionID, "model", time.Minute); err != nil {
		t.Fatal(err)
	}
	guard, err := registry.AcquireGuard(sessionID)
	if err != nil {
		t.Fatal(err)
	}
	cfg := cleanup.Config{Store: store, Runtime: rt, Audit: recorder}
	result, err := cleanup.Run(ctx, cfg)
	if err != nil || len(result.Kept) != 1 || result.Kept[0] != name {
		t.Fatalf("live cleanup result=%+v error=%v", result, err)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	result, err = cleanup.Run(ctx, cfg)
	if err != nil || len(result.Removed) != 1 || result.Removed[0] != name {
		t.Fatalf("orphan cleanup result=%+v error=%v", result, err)
	}
	if current, err := rt.ContainerState(ctx, name); err != nil || current != sunabaruntime.StateNotFound {
		t.Fatalf("orphan remained: state=%s error=%v", current, err)
	}
	record, err := registry.Load(sessionID)
	if err != nil || record.State != lease.Revoked {
		t.Fatalf("orphan lease=%+v error=%v", record, err)
	}
}
