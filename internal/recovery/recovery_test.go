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
