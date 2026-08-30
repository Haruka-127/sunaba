package apply

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/approval"
	"sunaba/internal/audit"
	"sunaba/internal/state"
	"sunaba/internal/workspace"
)

func TestApplyWorkSetCommitsCoreAndBulkWithOneApproval(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	projectRoot := filepath.Join(base, "project")
	resultRoot := filepath.Join(base, "result")
	for _, directory := range []string{projectRoot, resultRoot, filepath.Join(resultRoot, "node_modules")} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(resultRoot, "main.js"), []byte("main\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resultRoot, "node_modules", "dep.js"), []byte("dep\n"), 0755); err != nil {
		t.Fatal(err)
	}
	snapshotPolicy := workspace.DefaultSnapshotPolicy()
	bulkPolicy := workspace.DefaultBulkPolicyV1()
	policyDigest := strings.Repeat("a", 64)
	baseline, err := workspace.BuildSnapshotManifest(projectRoot, workspace.BulkCaptureSnapshotPolicy(snapshotPolicy))
	if err != nil {
		t.Fatal(err)
	}
	result, err := workspace.BuildSnapshotManifest(resultRoot, workspace.BulkCaptureSnapshotPolicy(snapshotPolicy))
	if err != nil {
		t.Fatal(err)
	}
	partitionedBaseline, partitionedResult, records, err := workspace.PartitionManifestPair(baseline, result, bulkPolicy, policyDigest)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("Bulk records=%+v", records)
	}
	store := &state.Store{Root: filepath.Join(base, "state")}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	projectID := state.ProjectID(projectRoot)
	projectState := filepath.Join(store.Root, "projects", projectID)
	if err := os.Mkdir(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	retainedRoot := filepath.Join(projectState, "retained")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	object, err := workspace.CaptureBulkObject(ctx, retainedRoot, resultRoot, result, records[0].Root, workspace.BulkCaptureSnapshotPolicy(snapshotPolicy))
	if err != nil {
		t.Fatal(err)
	}
	records[0].Capture = object.Capture
	records[0].Result = object.Result
	records[0].Summary = object.Result.Summary
	records[0].BulkID = workspace.BulkRecordID(policyDigest, records[0].Root, records[0].Baseline, records[0].Result)
	partitionedResult.BulkRoots[0] = object.Result
	partitionedResult, err = workspace.RebuildPartitionedManifestDigest(partitionedResult)
	if err != nil {
		t.Fatal(err)
	}
	workSet, err := workspace.BuildPendingWorkSetFromPartitions(projectID, projectRoot, "vm-1", "session-1", policyDigest, partitionedBaseline, partitionedResult, records, snapshotPolicy, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := workspace.BuildResolution(workSet, snapshotPolicy, 1, []workspace.BulkResolution{{BulkID: records[0].BulkID, Disposition: workspace.DispositionApplyDirectory}})
	if err != nil {
		t.Fatal(err)
	}
	recorder, err := audit.NewRecorder(filepath.Join(store.Root, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := approval.NewAuditedManager(nil, recorder, projectID, "vm-1", "session-1")
	if err != nil {
		t.Fatal(err)
	}
	cfg := WorkSetConfig{
		Store: store, ProjectRoot: projectRoot, ProjectID: projectID, BaselineRoot: projectRoot, ResultRoot: resultRoot,
		RetainedRoot: retainedRoot, WorkSet: workSet, Resolution: resolution, BulkPolicy: bulkPolicy,
		Approvals: manager, Audit: recorder, SnapshotPolicy: snapshotPolicy, DirectoryApplyEnabled: true,
	}
	plan, err := PrepareWorkSetPlan(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Plan = plan
	binding := workSetApprovalBinding(plan)
	request, err := manager.NewWorkSetRequest(binding, "Core and one Bulk directory", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := manager.ConfirmWorkSet(request.Nonce, binding)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Grant = grant
	cfg.ProjectCommit = func() error { return fmt.Errorf("simulated retention marker interruption") }
	if _, err := ApplyWorkSet(ctx, cfg); err == nil {
		t.Fatal("post-commit interruption was not reported")
	}
	committed, err := ResumeWorkSetTransaction(ctx, cfg)
	if err != nil || !committed {
		t.Fatalf("committed Work Set did not roll forward: committed=%t error=%v", committed, err)
	}
	for path, want := range map[string]string{"main.js": "main\n", "node_modules/dep.js": "dep\n"} {
		data, err := os.ReadFile(filepath.Join(projectRoot, filepath.FromSlash(path)))
		if err != nil || string(data) != want {
			t.Fatalf("applied %s=%q error=%v", path, data, err)
		}
	}
	if err := manager.ConsumeWorkSet(grant, binding); err == nil {
		t.Fatal("Work Set approval grant was reusable")
	}
}
