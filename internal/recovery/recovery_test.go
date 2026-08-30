package recovery

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/policy"
	"sunaba/internal/unixsocket"
	"sunaba/internal/workspace"
)

func recoveryFixture(t *testing.T, projectRoot, runtimeRoot string) (workspace.SnapshotManifest, workspace.PartitionedManifest, []workspace.BulkRecord, policy.CompiledWorkspacePolicy) {
	t.Helper()
	export := policy.ExportPolicy{MaxEntries: 100_000, MaxFileBytes: 128 << 20, MaxTotalBytes: 2 << 30}
	compiled, err := policy.CompileWorkspacePolicy(export, []string{".git", ".sunaba"}, nil, workspace.DefaultBulkPolicyV1())
	if err != nil {
		t.Fatal(err)
	}
	partitioned, bulk, err := workspace.BuildPartitionedSnapshotManifest(projectRoot, compiled.Core.Snapshot, compiled.Bulk, compiled.Digest)
	if err != nil {
		t.Fatal(err)
	}
	baseline := partitioned.Core
	baseline.Root = filepath.Join(runtimeRoot, "snapshot")
	return baseline, partitioned, bulk, compiled
}

func uniqueTestVMID(t *testing.T) string {
	t.Helper()
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	return "v" + hex.EncodeToString(random)
}

func TestRuntimeBasesKeepAllHostSocketsWithinPlatformLimit(t *testing.T) {
	projectState, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	const projectID = "0123456789ab"
	vmID := uniqueTestVMID(t)
	for _, test := range []struct {
		name string
		make func() (string, error)
	}{
		{name: "dev", make: func() (string, error) { return NewRuntimeBase(projectState, vmID) }},
		{name: "secure", make: func() (string, error) { return NewSecureRuntimeBase(projectID, vmID) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			base, err := test.make()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(base) })
			root := filepath.Join(base, "sunaba-vm-"+vmID)
			for _, socket := range []string{
				filepath.Join(root, "model-gateway.sock"),
				filepath.Join(root, "git-gateway.sock"),
				filepath.Join(root, "web-gateway.sock"),
				filepath.Join(root, "attach.sock"),
				filepath.Join(base, "approval-control.sock"),
				filepath.Join(base, "git-hook-"+strings.Repeat("r", 32)+".sock"),
			} {
				if err := unixsocket.ValidatePath(socket); err != nil {
					t.Fatalf("runtime socket %q exceeds the platform limit: %v", socket, err)
				}
			}
		})
	}
	legacyFailure := filepath.Join(LegacySecureRuntimeBase(projectID, vmID), "sunaba-vm-"+vmID, "model-gateway.sock")
	if err := unixsocket.ValidatePath(legacyFailure); err == nil {
		t.Fatalf("regression fixture unexpectedly fits the platform socket limit: %q", legacyFailure)
	}
}

func TestLegacyRecoveryRuntimePathsRemainStrictlyReadable(t *testing.T) {
	projectState, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	projectRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const projectID, sessionID = "0123456789ab", "session1"
	vmID := uniqueTestVMID(t)
	for _, test := range []struct {
		name string
		mode string
		base string
	}{
		{name: "dev", mode: "dev", base: LegacyRuntimeBase(projectState, vmID)},
		{name: "secure", mode: "secure", base: LegacySecureRuntimeBase(projectID, vmID)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Cleanup(func() { _ = os.RemoveAll(test.base) })
			root := filepath.Join(test.base, "sunaba-vm-"+vmID)
			if err := os.MkdirAll(filepath.Join(root, "snapshot"), 0700); err != nil {
				t.Fatal(err)
			}
			baseline, partitioned, bulk, compiled := recoveryFixture(t, projectRoot, root)
			record := State{
				Version: Version, ProjectID: projectID, ProjectRoot: projectRoot, VMID: vmID, SessionID: sessionID,
				Container: "sunaba-" + projectID + "-" + vmID, RuntimeBase: test.base, RuntimeRoot: root,
				WorkspacePath: "/workspace/sunaba-" + vmID, Mode: test.mode, Baseline: baseline, BaselinePartitioned: partitioned, BaselineBulk: bulk,
				ExportPolicyDigest: compiled.Core.Digest, WorkspacePolicy: compiled, Reason: "legacy recovery", CreatedAt: time.Now().UTC(),
			}
			if err := validate(projectState, record); err != nil {
				t.Fatalf("legacy recovery path was rejected: %v", err)
			}
			record.RuntimeBase += "-substituted"
			if err := validate(projectState, record); err == nil {
				t.Fatal("substituted legacy recovery path was accepted")
			}
		})
	}
}

func TestRecoveryRecordBindsPrivateRuntimeAndRejectsSubstitution(t *testing.T) {
	projectState, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	vmID := uniqueTestVMID(t)
	runtimeBase, err := NewRuntimeBase(projectState, vmID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeBase) })
	runtimeRoot := filepath.Join(runtimeBase, "sunaba-vm-"+vmID)
	if err := os.MkdirAll(filepath.Join(runtimeRoot, "snapshot"), 0700); err != nil {
		t.Fatal(err)
	}
	projectRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	baseline, partitioned, bulk, compiled := recoveryFixture(t, projectRoot, runtimeRoot)
	record := State{Version: Version, ProjectID: "0123456789ab", ProjectRoot: projectRoot, VMID: vmID, SessionID: "session1", Container: "sunaba-0123456789ab-" + vmID, RuntimeBase: runtimeBase, RuntimeRoot: runtimeRoot, WorkspacePath: "/workspace/sunaba-" + vmID, Baseline: baseline, BaselinePartitioned: partitioned, BaselineBulk: bulk, ExportPolicyDigest: compiled.Core.Digest, WorkspacePolicy: compiled, GitGateway: true, WebGateway: true, Reason: "guard refused", CreatedAt: time.Now().UTC()}
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
	const projectID, sessionID = "0123456789ab", "session1"
	vmID := uniqueTestVMID(t)
	runtimeBase, err := NewRuntimeBase(projectState, vmID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeBase) })
	runtimeRoot := filepath.Join(runtimeBase, "sunaba-vm-"+vmID)
	if err := os.MkdirAll(filepath.Join(runtimeRoot, "snapshot"), 0700); err != nil {
		t.Fatal(err)
	}
	projectRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	baseline, partitioned, bulk, compiled := recoveryFixture(t, projectRoot, runtimeRoot)
	mergedRoot := filepath.Join(runtimeRoot, "sunaba-quarantine-"+sessionID, "sunaba-merged-"+sessionID)
	if err := os.MkdirAll(mergedRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mergedRoot, "result.txt"), []byte("retained\n"), 0600); err != nil {
		t.Fatal(err)
	}
	merged, err := workspace.BuildSnapshotManifest(mergedRoot, compiled.Core.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	workSet, err := workspace.BuildPendingWorkSet(projectID, projectRoot, vmID, sessionID, compiled.Digest, partitioned.Core, merged, compiled.Core.Snapshot, compiled.Bulk, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	record := State{
		Version: Version, ProjectID: projectID, ProjectRoot: projectRoot, VMID: vmID, SessionID: sessionID,
		Container: "sunaba-" + projectID + "-" + vmID, RuntimeBase: runtimeBase, RuntimeRoot: runtimeRoot,
		WorkspacePath: "/workspace/sunaba-" + vmID, Baseline: baseline, BaselinePartitioned: partitioned, BaselineBulk: bulk, ExportPolicyDigest: compiled.Core.Digest, WorkspacePolicy: compiled,
		PendingExport: &PendingExport{MergedRoot: mergedRoot, WorkSet: workSet},
		Reason:        "pending metadata failed", CreatedAt: time.Now().UTC(),
	}
	if err := Save(projectState, record); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(projectState)
	if err != nil || loaded.PendingExport == nil || loaded.PendingExport.WorkSet.Digest != workSet.Digest {
		t.Fatalf("loaded=%+v error=%v", loaded, err)
	}
}
