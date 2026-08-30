package retention

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/workspace"
)

func TestFinalizeIsIdempotentAndFailsTowardRetainingData(t *testing.T) {
	storeRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(storeRoot, 0700); err != nil {
		t.Fatal(err)
	}
	projectState := filepath.Join(storeRoot, "projects", "0123456789ab")
	for _, directory := range []string{filepath.Join(projectState, "pending"), filepath.Join(projectState, "retained", "objects")} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	objectID := strings.Repeat("b", 64)
	reviewedObjectID := strings.Repeat("e", 64)
	for _, id := range []string{objectID, reviewedObjectID} {
		if err := os.Mkdir(filepath.Join(projectState, "retained", "objects", id), 0700); err != nil {
			t.Fatal(err)
		}
	}
	workSet := workspace.PendingWorkSet{
		ProjectID: "0123456789ab", Digest: strings.Repeat("a", 64),
		Bulk: []workspace.BulkRecord{
			{BulkID: "bulk-keep", Capture: workspace.ExactAbsentBulkCapture("kept")},
			{BulkID: "bulk-discard", Capture: workspace.BulkCapture{State: "exact_managed", ObjectID: objectID, ObjectDigest: strings.Repeat("c", 64)}},
		},
		ReviewedBulk: []workspace.ReviewedBulkCapture{{BulkID: "bulk-reviewed", Capture: workspace.BulkCapture{State: "exact_managed", ObjectID: reviewedObjectID, ObjectDigest: strings.Repeat("f", 64)}}},
	}
	plan := workspace.ApplyPlan{
		ProjectID: workSet.ProjectID, WorkSetDigest: workSet.Digest, Digest: strings.Repeat("d", 64),
		RetentionOperations: []workspace.RetentionOperation{
			{BulkID: "bulk-keep", Disposition: workspace.DispositionKeepHost, ObjectDigest: workSet.Bulk[0].Capture.ObjectDigest},
			{BulkID: "bulk-discard", Disposition: workspace.DispositionDiscard, ObjectID: objectID, ObjectDigest: strings.Repeat("c", 64), EntryCount: 3, LogicalBytes: 12},
			{BulkID: "bulk-reviewed", Disposition: workspace.RetentionDispositionReviewedNormal, ObjectID: reviewedObjectID, ObjectDigest: strings.Repeat("f", 64), EntryCount: 2, LogicalBytes: 8},
		},
	}
	journal, err := Prepare(projectState, workSet, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := MarkProjectCommitted(projectState, journal); err != nil {
		t.Fatal(err)
	}
	if err := Finalize(storeRoot, projectState, workSet, plan); err != nil {
		t.Fatal(err)
	}
	if err := Finalize(storeRoot, projectState, workSet, plan); err != nil {
		t.Fatalf("finalization was not idempotent: %v", err)
	}
	for _, id := range []string{objectID, reviewedObjectID} {
		if _, err := os.Lstat(filepath.Join(projectState, "retained", "objects", id)); !os.IsNotExist(err) {
			t.Fatalf("approved cleanup object remained: %v", err)
		}
	}
	for _, record := range []string{
		filepath.Join(projectState, "retained", "receipts", retainedID(workSet.Digest, "bulk-keep")+".json"),
		filepath.Join(projectState, "retained", "receipts", retainedID(workSet.Digest, "bulk-discard")+".json"),
		filepath.Join(projectState, "retained", "receipts", retainedID(workSet.Digest, "bulk-reviewed")+".json"),
	} {
		if info, err := os.Lstat(record); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatalf("retention record %s is unsafe: %v", record, err)
		}
	}
	finalized, err := Load(projectState)
	if err != nil || finalized.Phase != "retention_finalized" || finalized.CreatedAt.Before(time.Unix(1, 0)) {
		t.Fatalf("final journal=%+v error=%v", finalized, err)
	}
	if err := RemoveFinalized(projectState, finalized); err != nil {
		t.Fatal(err)
	}
}

func TestPreparedJournalCannotDeleteRetainedData(t *testing.T) {
	projectState, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(projectState, "pending"), 0700); err != nil {
		t.Fatal(err)
	}
	workSet := workspace.PendingWorkSet{ProjectID: "0123456789ab", Digest: strings.Repeat("a", 64)}
	plan := workspace.ApplyPlan{ProjectID: workSet.ProjectID, WorkSetDigest: workSet.Digest, Digest: strings.Repeat("b", 64)}
	journal, err := Prepare(projectState, workSet, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := Finalize(filepath.Dir(projectState), projectState, workSet, plan); err == nil {
		t.Fatal("prepared retention journal allowed finalization before Project commit")
	}
	if err := RemovePrepared(projectState, journal); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupFinalizedPendingRecoversInterruptedMetadataRemoval(t *testing.T) {
	projectState, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	pendingRoot := filepath.Join(projectState, "pending")
	if err := os.Mkdir(pendingRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pendingRoot, "remaining-private-data"), []byte("committed"), 0600); err != nil {
		t.Fatal(err)
	}
	workSet := workspace.PendingWorkSet{ProjectID: "0123456789ab", Digest: strings.Repeat("a", 64)}
	plan := workspace.ApplyPlan{ProjectID: workSet.ProjectID, WorkSetDigest: workSet.Digest, Digest: strings.Repeat("b", 64)}
	journal, err := Prepare(projectState, workSet, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := MarkProjectCommitted(projectState, journal); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(projectState)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Phase = "retention_finalized"
	if err := writeJournal(JournalPath(projectState), loaded); err != nil {
		t.Fatal(err)
	}
	cleaned, err := CleanupFinalizedPending(projectState)
	if err != nil || !cleaned {
		t.Fatalf("cleanup=%v error=%v", cleaned, err)
	}
	for _, target := range []string{pendingRoot, JournalPath(projectState)} {
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Fatalf("finalized state remained at %s: %v", target, err)
		}
	}
}

func TestProjectBoundItemRequiresExactIdentityToDiscard(t *testing.T) {
	projectState, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	retainedRoot := filepath.Join(projectState, "retained")
	itemsRoot := filepath.Join(retainedRoot, "items")
	objectsRoot := filepath.Join(retainedRoot, "objects")
	for _, root := range []string{itemsRoot, objectsRoot} {
		if err := os.MkdirAll(root, 0700); err != nil {
			t.Fatal(err)
		}
	}
	workSetDigest := strings.Repeat("a", 64)
	objectID := strings.Repeat("b", 64)
	objectDigest := strings.Repeat("c", 64)
	id := retainedID(workSetDigest, "bulk-1")
	if err := os.Mkdir(filepath.Join(objectsRoot, objectID), 0700); err != nil {
		t.Fatal(err)
	}
	record := retainedRecord{
		Version: 1, RetainedID: id, Kind: "project_bound", ProjectID: "project-1",
		WorkSetDigest: workSetDigest, ApplyPlanDigest: strings.Repeat("d", 64), BulkID: "bulk-1",
		Root: "node_modules", ObjectID: objectID, ObjectDigest: objectDigest,
		EntryCount: 12, LogicalBytes: 34, CreatedAt: time.Unix(100, 0).UTC(),
	}
	if err := writeRecord(filepath.Join(itemsRoot, id+".json"), record); err != nil {
		t.Fatal(err)
	}
	items, err := ListProjectItems(projectState)
	if err != nil || len(items) != 1 || items[0].RetainedID != id || items[0].Root != "node_modules" {
		t.Fatalf("items=%+v error=%v", items, err)
	}
	if err := DiscardProjectItem(projectState, id, strings.Repeat("e", 64), 34); err == nil {
		t.Fatal("changed object digest authorized retained discard")
	}
	if _, err := os.Lstat(filepath.Join(objectsRoot, objectID)); err != nil {
		t.Fatalf("failed discard removed retained object: %v", err)
	}
	if err := DiscardProjectItem(projectState, id, objectDigest, 34); err != nil {
		t.Fatal(err)
	}
	if items, err := ListProjectItems(projectState); err != nil || len(items) != 0 {
		t.Fatalf("discarded items=%+v error=%v", items, err)
	}
}
