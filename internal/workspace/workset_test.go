package workspace

import (
	"strings"
	"testing"
	"time"
)

func workSetFixture(t *testing.T) (PendingWorkSet, SnapshotPolicy) {
	t.Helper()
	policy := DefaultSnapshotPolicy()
	bulkPolicy := DefaultBulkPolicyV1()
	baseline := bulkTestManifest(t, []SnapshotEntry{{Path: "src", Type: TypeDirectory, Mode: 0755}})
	result := bulkTestManifest(t, []SnapshotEntry{
		{Path: "node_modules", Type: TypeDirectory, Mode: 0755},
		{Path: "node_modules/a.js", Type: TypeFile, Mode: 0644, Size: 1, SHA256: strings.Repeat("1", 64)},
		{Path: "src", Type: TypeDirectory, Mode: 0755},
		{Path: "src/main.js", Type: TypeFile, Mode: 0644, Size: 2, SHA256: strings.Repeat("2", 64)},
	})
	workSet, err := BuildPendingWorkSet("project-1", "/private/tmp/project", "vm-1", "session-1", strings.Repeat("a", 64), baseline, result, policy, bulkPolicy, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	return workSet, policy
}

func TestResolutionMayRemainUnresolvedButApplyPlanCannot(t *testing.T) {
	workSet, policy := workSetFixture(t)
	resolution, err := BuildResolution(workSet, policy, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolution.Bulk) != 1 || resolution.Bulk[0].Disposition != DispositionUnresolved {
		t.Fatalf("resolution=%+v", resolution)
	}
	if _, err := BuildApplyPlan(workSet, resolution, policy, workSet.Baseline.Core.Digest); err == nil || !strings.Contains(err.Error(), "unresolved") {
		t.Fatalf("unresolved Work Set entered Apply Plan: %v", err)
	}
}

func TestApplyPlanRequiresDurableRetentionAndBindsResolution(t *testing.T) {
	workSet, policy := workSetFixture(t)
	choice := []BulkResolution{{BulkID: workSet.Bulk[0].BulkID, Disposition: DispositionKeepHost}}
	resolution, err := BuildResolution(workSet, policy, 1, choice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildApplyPlan(workSet, resolution, policy, workSet.Baseline.Core.Digest); err == nil || !strings.Contains(err.Error(), "durably retained") {
		t.Fatalf("frozen-VM-only data entered Apply Plan: %v", err)
	}
	workSet.Bulk[0].Capture = BulkCapture{State: "exact_managed", ObjectID: "object-1", ObjectDigest: workSet.Bulk[0].Result.ObjectDigest}
	workSet.Digest, err = pendingWorkSetDigest(workSet)
	if err != nil {
		t.Fatal(err)
	}
	resolution, err = BuildResolution(workSet, policy, 2, choice)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildApplyPlan(workSet, resolution, policy, workSet.Baseline.Core.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ResolutionDigest != resolution.Digest || plan.WorkSetDigest != workSet.Digest || len(plan.NoTouchRoots) != 1 || plan.NoTouchRoots[0] != "node_modules" {
		t.Fatalf("plan=%+v", plan)
	}
	changed, err := BuildResolution(workSet, policy, 3, []BulkResolution{{BulkID: workSet.Bulk[0].BulkID, Disposition: DispositionRetainArtifact}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateApplyPlan(workSet, changed, policy, plan); err == nil {
		t.Fatal("stale Apply Plan survived a Resolution change")
	}
}

func TestApplyDirectoryRejectsPresentUntrackedAndAcceptsExactCapture(t *testing.T) {
	workSet, policy := workSetFixture(t)
	record := &workSet.Bulk[0]
	record.Capture = BulkCapture{State: "exact_managed", ObjectID: "object-1", ObjectDigest: record.Result.ObjectDigest}
	record.Baseline = BulkManifestRef{Root: record.Root, State: "present_untracked"}
	workSet.Baseline.BulkRoots[0] = record.Baseline
	var err error
	workSet.Baseline.Digest, err = partitionedManifestDigest(workSet.Baseline)
	if err != nil {
		t.Fatal(err)
	}
	workSet.Digest, err = pendingWorkSetDigest(workSet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildResolution(workSet, policy, 1, []BulkResolution{{BulkID: record.BulkID, Disposition: DispositionApplyDirectory}}); err == nil {
		t.Fatal("present-untracked Bulk root was eligible for replace")
	}
}

func TestWorkSetDigestChangesWithCaptureIdentity(t *testing.T) {
	workSet, policy := workSetFixture(t)
	first := workSet.Digest
	workSet.Bulk[0].Capture = BulkCapture{State: "exact_managed", ObjectID: "object-1", ObjectDigest: workSet.Bulk[0].Result.ObjectDigest}
	workSet.Digest, _ = pendingWorkSetDigest(workSet)
	if first == workSet.Digest {
		t.Fatal("Work Set digest ignored capture identity")
	}
	if err := ValidatePendingWorkSet(workSet, policy); err != nil {
		t.Fatal(err)
	}
}

func TestReviewNormallyMovesExactAbsentBulkIntoCoreAndBindsCleanup(t *testing.T) {
	workSet, policy := workSetFixture(t)
	record := workSet.Bulk[0]
	workSet.Bulk[0].Capture = BulkCapture{State: "exact_managed", ObjectID: strings.Repeat("b", 64), ObjectDigest: record.Result.ObjectDigest}
	var err error
	workSet.Digest, err = pendingWorkSetDigest(workSet)
	if err != nil {
		t.Fatal(err)
	}
	fullResult := bulkTestManifest(t, []SnapshotEntry{
		{Path: "node_modules", Type: TypeDirectory, Mode: 0755},
		{Path: "node_modules/a.js", Type: TypeFile, Mode: 0644, Size: 1, SHA256: strings.Repeat("1", 64)},
		{Path: "src", Type: TypeDirectory, Mode: 0755},
		{Path: "src/main.js", Type: TypeFile, Mode: 0644, Size: 2, SHA256: strings.Repeat("2", 64)},
	})
	derived, err := DeriveWorkSetReviewNormally(workSet, record.BulkID, fullResult, policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(derived.Bulk) != 0 || len(derived.NormalRoots) != 1 || derived.NormalRoots[0] != record.Root || len(derived.ReviewedBulk) != 1 {
		t.Fatalf("derived Work Set lanes are wrong: %+v", derived)
	}
	found := false
	for _, change := range derived.CoreChangeSet.Changes {
		found = found || change.Path == "node_modules/a.js"
	}
	if !found {
		t.Fatalf("promoted Bulk content is absent from Core Change Set: %+v", derived.CoreChangeSet.Changes)
	}
	resolution, err := BuildResolution(derived, policy, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildApplyPlan(derived, resolution, policy, derived.Baseline.Core.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.RetentionOperations) != 1 || plan.RetentionOperations[0].Disposition != RetentionDispositionReviewedNormal || plan.RetentionOperations[0].ObjectID != strings.Repeat("b", 64) {
		t.Fatalf("reviewed Bulk cleanup is not bound to the Apply Plan: %+v", plan.RetentionOperations)
	}
}

func TestReviewNormallyRejectsPresentUntrackedBaseline(t *testing.T) {
	workSet, _ := workSetFixture(t)
	workSet.Bulk[0].Baseline.State = "present_untracked"
	workSet.Baseline.BulkRoots[0] = workSet.Bulk[0].Baseline
	workSet.Bulk[0].Capture = BulkCapture{State: "exact_managed", ObjectID: strings.Repeat("b", 64), ObjectDigest: workSet.Bulk[0].Result.ObjectDigest}
	var err error
	workSet.Baseline.Digest, err = partitionedManifestDigest(workSet.Baseline)
	if err != nil {
		t.Fatal(err)
	}
	workSet.Digest, err = pendingWorkSetDigest(workSet)
	if err != nil {
		t.Fatal(err)
	}
	if CanReviewBulkNormally(workSet.Bulk[0]) {
		t.Fatal("present-untracked baseline was eligible for Normal review")
	}
}
