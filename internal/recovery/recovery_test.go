package recovery

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/workspace"
)

func TestRecoveryRecordBindsPrivateRuntimeAndRejectsSubstitution(t *testing.T) {
	projectState, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	const vmID = "vm123456"
	runtimeBase, err := NewRuntimeBase(projectState, vmID)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot := filepath.Join(runtimeBase, "sunaba-vm-"+vmID)
	if err := os.MkdirAll(filepath.Join(runtimeRoot, "snapshot"), 0700); err != nil {
		t.Fatal(err)
	}
	projectRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := workspace.BuildSnapshotManifest(projectRoot, workspace.DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	record := State{Version: Version, ProjectID: "0123456789ab", ProjectRoot: projectRoot, VMID: vmID, SessionID: "session1", Container: "sunaba-0123456789ab-" + vmID, RuntimeBase: runtimeBase, RuntimeRoot: runtimeRoot, WorkspacePath: "/workspace/sunaba-" + vmID, Baseline: baseline, ExportPolicyDigest: strings.Repeat("a", 64), GitGateway: true, WebGateway: true, Reason: "guard refused", CreatedAt: time.Now().UTC()}
	if err := Save(projectState, record); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(projectState)
	if err != nil || loaded.Container != record.Container || !loaded.GitGateway || !loaded.WebGateway {
		t.Fatalf("loaded=%+v error=%v", loaded, err)
	}
	loaded.VMID = "different"
	if err := Save(projectState, loaded); err == nil {
		t.Fatal("substituted recovery identity was accepted")
	}
	if err := Remove(projectState, record); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(runtimeBase); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime remained after explicit removal: %v", err)
	}
}

func TestRecoveryRecordRoundTripsFrozenPendingExport(t *testing.T) {
	projectState, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	const projectID, vmID, sessionID = "0123456789ab", "vm123456", "session1"
	runtimeBase, err := NewRuntimeBase(projectState, vmID)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot := filepath.Join(runtimeBase, "sunaba-vm-"+vmID)
	if err := os.MkdirAll(filepath.Join(runtimeRoot, "snapshot"), 0700); err != nil {
		t.Fatal(err)
	}
	projectRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	policy := workspace.DefaultSnapshotPolicy()
	baseline, err := workspace.BuildSnapshotManifest(projectRoot, policy)
	if err != nil {
		t.Fatal(err)
	}
	mergedRoot := filepath.Join(runtimeRoot, "sunaba-quarantine-"+sessionID, "sunaba-merged-"+sessionID)
	if err := os.MkdirAll(mergedRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mergedRoot, "result.txt"), []byte("retained\n"), 0600); err != nil {
		t.Fatal(err)
	}
	merged, err := workspace.BuildSnapshotManifest(mergedRoot, policy)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := workspace.BuildChangeSet(baseline, merged, policy)
	if err != nil {
		t.Fatal(err)
	}
	record := State{
		Version: Version, ProjectID: projectID, ProjectRoot: projectRoot, VMID: vmID, SessionID: sessionID,
		Container: "sunaba-" + projectID + "-" + vmID, RuntimeBase: runtimeBase, RuntimeRoot: runtimeRoot,
		WorkspacePath: "/workspace/sunaba-" + vmID, Baseline: baseline, ExportPolicyDigest: strings.Repeat("a", 64),
		PendingExport: &PendingExport{MergedRoot: mergedRoot, MergedDigest: merged.Digest, ChangeSetDigest: changes.Digest},
		Reason:        "pending metadata failed", CreatedAt: time.Now().UTC(),
	}
	if err := Save(projectState, record); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(projectState)
	if err != nil || loaded.PendingExport == nil || loaded.PendingExport.ChangeSetDigest != changes.Digest || loaded.PendingExport.MergedDigest != merged.Digest {
		t.Fatalf("loaded=%+v error=%v", loaded, err)
	}
}
