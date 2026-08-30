package retention

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"sunaba/internal/securefs"
	"sunaba/internal/workspace"
)

const journalVersion = 1

type Inventory struct {
	ProjectBound int
	Objects      int
	Trash        int
	Journal      bool
}

func Inspect(projectState string) (Inventory, error) {
	var result Inventory
	for path, destination := range map[string]*int{
		filepath.Join(projectState, "retained", "items"):   &result.ProjectBound,
		filepath.Join(projectState, "retained", "objects"): &result.Objects,
		filepath.Join(projectState, "retained", "trash"):   &result.Trash,
	} {
		entries, err := os.ReadDir(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || securefs.CheckCanonicalOwnedDir(path) != nil {
			return Inventory{}, fmt.Errorf("retained data inventory is unsafe")
		}
		*destination = len(entries)
	}
	if _, err := Load(projectState); err == nil {
		result.Journal = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return Inventory{}, err
	}
	return result, nil
}

func (i Inventory) BlocksProjectRemoval() bool {
	return i.ProjectBound > 0 || i.Objects > 0 || i.Trash > 0 || i.Journal
}

type Journal struct {
	Version         int                 `json:"version"`
	ProjectID       string              `json:"project_id"`
	WorkSetDigest   string              `json:"work_set_digest"`
	ApplyPlanDigest string              `json:"apply_plan_digest"`
	Plan            workspace.ApplyPlan `json:"apply_plan"`
	Phase           string              `json:"phase"`
	CreatedAt       time.Time           `json:"created_at"`
}

type retainedRecord struct {
	Version         int       `json:"version"`
	RetainedID      string    `json:"retained_id"`
	Kind            string    `json:"kind"`
	ProjectID       string    `json:"project_id"`
	WorkSetDigest   string    `json:"work_set_digest"`
	ApplyPlanDigest string    `json:"apply_plan_digest"`
	BulkID          string    `json:"bulk_id"`
	Root            string    `json:"root"`
	ObjectID        string    `json:"object_id,omitempty"`
	ObjectDigest    string    `json:"object_digest"`
	EntryCount      int       `json:"entry_count"`
	LogicalBytes    int64     `json:"logical_bytes"`
	CreatedAt       time.Time `json:"created_at"`
}

type Item struct {
	RetainedID    string `json:"retained_id"`
	Kind          string `json:"kind"`
	WorkSetDigest string `json:"work_set_digest"`
	BulkID        string `json:"bulk_id"`
	Root          string `json:"root"`
	ObjectDigest  string `json:"object_digest"`
	EntryCount    int    `json:"entry_count"`
	LogicalBytes  int64  `json:"logical_bytes"`
}

func JournalPath(projectState string) string {
	return filepath.Join(projectState, "retention-finalization.json")
}

func Prepare(projectState string, workSet workspace.PendingWorkSet, plan workspace.ApplyPlan) (Journal, error) {
	if workSet.Digest != plan.WorkSetDigest || workSet.ProjectID != plan.ProjectID || plan.Digest == "" {
		return Journal{}, fmt.Errorf("retention journal identity is invalid")
	}
	journal := Journal{Version: journalVersion, ProjectID: workSet.ProjectID, WorkSetDigest: workSet.Digest, ApplyPlanDigest: plan.Digest, Plan: plan, Phase: "prepared", CreatedAt: time.Now().UTC()}
	if err := writeJournal(JournalPath(projectState), journal); err != nil {
		return Journal{}, err
	}
	return journal, nil
}

func MarkProjectCommitted(projectState string, expected Journal) error {
	journal, err := Load(projectState)
	if err != nil {
		return err
	}
	if !sameJournalIdentity(journal, expected) || journal.Phase != "prepared" {
		return fmt.Errorf("retention journal changed before Project commit")
	}
	journal.Phase = "project_committed"
	return writeJournal(JournalPath(projectState), journal)
}

func Load(projectState string) (Journal, error) {
	data, err := securefs.ReadOwnedRegular(JournalPath(projectState), 64<<10)
	if err != nil {
		return Journal{}, err
	}
	var journal Journal
	if securefs.DecodeStrictJSON(data, &journal) != nil || journal.Version != journalVersion || journal.ProjectID == "" || len(journal.WorkSetDigest) != 64 || len(journal.ApplyPlanDigest) != 64 || journal.Plan.ProjectID != journal.ProjectID || journal.Plan.WorkSetDigest != journal.WorkSetDigest || journal.Plan.Digest != journal.ApplyPlanDigest || (journal.Phase != "prepared" && journal.Phase != "project_committed" && journal.Phase != "retention_finalized") || journal.CreatedAt.IsZero() {
		return Journal{}, fmt.Errorf("retention journal is unsafe")
	}
	return journal, nil
}

func RemovePrepared(projectState string, expected Journal) error {
	journal, err := Load(projectState)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !sameJournalIdentity(journal, expected) || journal.Phase != "prepared" {
		return fmt.Errorf("refusing to remove changed retention journal")
	}
	if err := os.Remove(JournalPath(projectState)); err != nil {
		return err
	}
	return securefs.SyncDir(filepath.Dir(JournalPath(projectState)))
}

func RemoveFinalized(projectState string, expected Journal) error {
	journal, err := Load(projectState)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !sameJournalIdentity(journal, expected) || journal.Phase != "retention_finalized" {
		return fmt.Errorf("refusing to remove an unfinished retention journal")
	}
	if err := os.Remove(JournalPath(projectState)); err != nil {
		return err
	}
	return securefs.SyncDir(filepath.Dir(JournalPath(projectState)))
}

// CleanupFinalizedPending completes an interrupted post-commit cleanup. A
// finalized journal proves that Project mutation and all retention decisions
// already committed; only the private pending copy and journal remain.
func CleanupFinalizedPending(projectState string) (bool, error) {
	journal, err := Load(projectState)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if journal.Phase != "retention_finalized" {
		return false, nil
	}
	pendingRoot := filepath.Join(projectState, "pending")
	if filepath.Dir(pendingRoot) != projectState || filepath.Base(pendingRoot) != "pending" {
		return false, fmt.Errorf("refusing to remove an unbound pending directory")
	}
	var stat unix.Stat_t
	if err := unix.Lstat(pendingRoot, &stat); err == nil {
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0777 != 0700 || stat.Uid != uint32(os.Geteuid()) {
			return false, fmt.Errorf("refusing to remove unsafe finalized pending data")
		}
		if err := os.RemoveAll(pendingRoot); err != nil {
			return false, err
		}
		if err := securefs.SyncDir(projectState); err != nil {
			return false, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := RemoveFinalized(projectState, journal); err != nil {
		return false, err
	}
	return true, nil
}

func sameJournalIdentity(left, right Journal) bool {
	return left.Version == right.Version && left.ProjectID == right.ProjectID && left.WorkSetDigest == right.WorkSetDigest && left.ApplyPlanDigest == right.ApplyPlanDigest && left.CreatedAt.Equal(right.CreatedAt)
}

// Finalize is idempotent and always fails toward retaining extra data. Object
// deletion happens only for an already approved apply/discard disposition and
// only after a durable Project commit marker exists.
func Finalize(storeRoot, projectState string, workSet workspace.PendingWorkSet, plan workspace.ApplyPlan) error {
	journal, err := Load(projectState)
	if err != nil {
		return err
	}
	if journal.Phase == "retention_finalized" {
		return nil
	}
	if journal.Phase != "project_committed" || journal.ProjectID != workSet.ProjectID || journal.WorkSetDigest != workSet.Digest || journal.ApplyPlanDigest != plan.Digest {
		return fmt.Errorf("retention finalization identity is stale")
	}
	retainedRoot := filepath.Join(projectState, "retained")
	if err := securefs.EnsureCanonicalOwnedDir(retainedRoot); err != nil {
		return err
	}
	itemsRoot := filepath.Join(retainedRoot, "items")
	receiptsRoot := filepath.Join(retainedRoot, "receipts")
	trashRoot := filepath.Join(retainedRoot, "trash")
	for _, directory := range []string{itemsRoot, receiptsRoot, trashRoot} {
		if err := securefs.EnsureCanonicalOwnedDir(directory); err != nil {
			return err
		}
	}
	byID := make(map[string]workspace.BulkRecord, len(workSet.Bulk))
	for _, record := range workSet.Bulk {
		byID[record.BulkID] = record
	}
	reviewedByID := make(map[string]workspace.ReviewedBulkCapture, len(workSet.ReviewedBulk))
	for _, reviewed := range workSet.ReviewedBulk {
		reviewedByID[reviewed.BulkID] = reviewed
	}
	for _, operation := range plan.RetentionOperations {
		record, bulkExists := byID[operation.BulkID]
		reviewed, reviewedExists := reviewedByID[operation.BulkID]
		if bulkExists == reviewedExists {
			return fmt.Errorf("retention operation does not match Work Set")
		}
		capture := record.Capture
		if reviewedExists {
			capture = reviewed.Capture
		}
		recordData := retainedRecord{
			Version: 1, ProjectID: workSet.ProjectID, WorkSetDigest: workSet.Digest, ApplyPlanDigest: plan.Digest,
			BulkID: operation.BulkID, ObjectID: capture.ObjectID, ObjectDigest: capture.ObjectDigest,
			EntryCount: operation.EntryCount, LogicalBytes: operation.LogicalBytes, CreatedAt: journal.CreatedAt,
		}
		recordData.RetainedID = retainedID(workSet.Digest, operation.BulkID)
		if bulkExists {
			recordData.Root = record.Root
		} else {
			recordData.Root = reviewed.Root
		}
		switch operation.Disposition {
		case workspace.DispositionKeepHost:
			destination := filepath.Join(itemsRoot, recordData.RetainedID+".json")
			recordData.Kind = "project_bound"
			if record.Capture.State == "exact_absence" {
				recordData.Kind = "no_vm_data"
				destination = filepath.Join(receiptsRoot, recordData.RetainedID+".json")
			}
			if err := writeRecordOnce(destination, recordData); err != nil {
				return err
			}
		case workspace.DispositionRetainArtifact:
			recordData.Kind = "pinned_artifact"
			artifactRoot := filepath.Join(storeRoot, "artifacts")
			artifactObjects := filepath.Join(artifactRoot, "objects")
			artifactRecords := filepath.Join(artifactRoot, "records")
			for _, directory := range []string{artifactRoot, artifactObjects, artifactRecords} {
				if err := securefs.EnsureCanonicalOwnedDir(directory); err != nil {
					return err
				}
			}
			recordPath := filepath.Join(artifactRecords, recordData.RetainedID+".json")
			complete, err := recordMatches(recordPath, recordData)
			if err != nil {
				return err
			}
			if !complete && record.Capture.ObjectID != "" {
				if err := moveObject(filepath.Join(retainedRoot, "objects"), artifactObjects, record.Capture.ObjectID); err != nil {
					return err
				}
			}
			if !complete {
				if err := writeRecord(recordPath, recordData); err != nil {
					return err
				}
			}
		case workspace.DispositionApplyDirectory, workspace.DispositionDiscard, workspace.RetentionDispositionReviewedNormal:
			recordData.Kind = "discard_receipt"
			receiptPath := filepath.Join(receiptsRoot, recordData.RetainedID+".json")
			complete, err := recordMatches(receiptPath, recordData)
			if err != nil {
				return err
			}
			if !complete && capture.ObjectID != "" {
				if err := moveObject(filepath.Join(retainedRoot, "objects"), trashRoot, capture.ObjectID); err != nil {
					return err
				}
			}
			if !complete {
				if err := writeRecord(receiptPath, recordData); err != nil {
					return err
				}
			}
			if capture.ObjectID != "" {
				if err := removeObject(trashRoot, capture.ObjectID); err != nil {
					return fmt.Errorf("retention cleanup pending with data preserved in trash: %w", err)
				}
			}
		default:
			return fmt.Errorf("unresolved retention operation")
		}
	}
	journal.Phase = "retention_finalized"
	return writeJournal(JournalPath(projectState), journal)
}

func writeJournal(path string, journal Journal) error { return writeRecord(path, journal) }

func writeRecord(path string, value any) error {
	data, err := jsonMarshal(value)
	if err != nil {
		return err
	}
	return securefs.AtomicWriteOwned(path, data)
}

func writeRecordOnce(path string, record retainedRecord) error {
	matches, err := recordMatches(path, record)
	if err != nil || matches {
		return err
	}
	return writeRecord(path, record)
}

func recordMatches(path string, expected retainedRecord) (bool, error) {
	data, err := securefs.ReadOwnedRegular(path, 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var actual retainedRecord
	if securefs.DecodeStrictJSON(data, &actual) != nil || actual != expected {
		return false, fmt.Errorf("retention record %q conflicts with the approved plan", filepath.Base(path))
	}
	return true, nil
}

func jsonMarshal(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func moveObject(sourceRoot, destinationRoot, objectID string) error {
	if !validObjectID(objectID) {
		return fmt.Errorf("retained object ID is invalid")
	}
	source := filepath.Join(sourceRoot, objectID)
	destination := filepath.Join(destinationRoot, objectID)
	if _, err := os.Lstat(destination); err == nil {
		if _, sourceErr := os.Lstat(source); errors.Is(sourceErr, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("retained object destination already exists")
	}
	if err := securefs.CheckCanonicalOwnedDir(source); err != nil {
		return err
	}
	if err := os.Rename(source, destination); err != nil {
		return err
	}
	return errors.Join(securefs.SyncDir(sourceRoot), securefs.SyncDir(destinationRoot))
}

func removeObject(root, objectID string) error {
	if !validObjectID(objectID) || filepath.Dir(filepath.Join(root, objectID)) != root {
		return fmt.Errorf("refusing to remove an unbound retained object")
	}
	object := filepath.Join(root, objectID)
	var stat unix.Stat_t
	if err := unix.Lstat(object, &stat); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0777 != 0700 || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("refusing to remove an unsafe retained object")
	}
	if err := os.RemoveAll(object); err != nil {
		return err
	}
	return securefs.SyncDir(root)
}

func validObjectID(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func retainedID(workSetDigest, bulkID string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte("sunaba.retained.item.v1\x00"+workSetDigest+"\x00"+bulkID)))
}

func ListProjectItems(projectState string) ([]Item, error) {
	itemsRoot := filepath.Join(projectState, "retained", "items")
	entries, err := os.ReadDir(itemsRoot)
	if errors.Is(err, os.ErrNotExist) {
		return []Item{}, nil
	}
	if err != nil || securefs.CheckCanonicalOwnedDir(itemsRoot) != nil {
		return nil, fmt.Errorf("retained item directory is unsafe")
	}
	items := make([]Item, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return nil, fmt.Errorf("retained item directory contains an unsafe entry")
		}
		record, err := loadRetainedRecord(filepath.Join(itemsRoot, entry.Name()))
		if err != nil || entry.Name() != record.RetainedID+".json" || record.Kind != "project_bound" {
			return nil, fmt.Errorf("retained item %q is unsafe", entry.Name())
		}
		items = append(items, Item{
			RetainedID: record.RetainedID, Kind: record.Kind, WorkSetDigest: record.WorkSetDigest,
			BulkID: record.BulkID, Root: record.Root, ObjectDigest: record.ObjectDigest,
			EntryCount: record.EntryCount, LogicalBytes: record.LogicalBytes,
		})
	}
	return items, nil
}

func ShowProjectItem(projectState, id string) (Item, error) {
	if !validObjectID(id) {
		return Item{}, fmt.Errorf("retained ID is invalid")
	}
	items, err := ListProjectItems(projectState)
	if err != nil {
		return Item{}, err
	}
	for _, item := range items {
		if item.RetainedID == id {
			return item, nil
		}
	}
	return Item{}, fmt.Errorf("retained item was not found")
}

// DiscardProjectItem deletes one project-bound retained object only after its
// exact public identity and loss size are repeated by the caller. The receipt
// makes interruption after trash rename idempotently recoverable.
func DiscardProjectItem(projectState, id, expectedObjectDigest string, expectedLogicalBytes int64) error {
	if !validObjectID(id) || !validObjectID(expectedObjectDigest) || expectedLogicalBytes < 0 {
		return fmt.Errorf("retained discard expectation is invalid")
	}
	retainedRoot := filepath.Join(projectState, "retained")
	itemsRoot := filepath.Join(retainedRoot, "items")
	objectsRoot := filepath.Join(retainedRoot, "objects")
	receiptsRoot := filepath.Join(retainedRoot, "receipts")
	trashRoot := filepath.Join(retainedRoot, "trash")
	for _, root := range []string{retainedRoot, itemsRoot, objectsRoot, receiptsRoot, trashRoot} {
		if err := securefs.EnsureCanonicalOwnedDir(root); err != nil {
			return err
		}
	}
	itemPath := filepath.Join(itemsRoot, id+".json")
	record, err := loadRetainedRecord(itemPath)
	if err != nil {
		return err
	}
	if record.RetainedID != id || record.Kind != "project_bound" || record.ObjectDigest != expectedObjectDigest || record.LogicalBytes != expectedLogicalBytes || !validObjectID(record.ObjectID) {
		return fmt.Errorf("retained item identity or loss summary changed")
	}
	receipt := record
	receipt.Kind = "retained_discard_receipt"
	receiptPath := filepath.Join(receiptsRoot, id+".json")
	complete, err := recordMatches(receiptPath, receipt)
	if err != nil {
		return err
	}
	if !complete {
		if err := moveObject(objectsRoot, trashRoot, record.ObjectID); err != nil {
			return err
		}
		if err := writeRecord(receiptPath, receipt); err != nil {
			return err
		}
	}
	if err := removeObject(trashRoot, record.ObjectID); err != nil {
		return fmt.Errorf("retained discard cleanup is pending with data preserved in trash: %w", err)
	}
	if err := os.Remove(itemPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return securefs.SyncDir(itemsRoot)
}

func loadRetainedRecord(path string) (retainedRecord, error) {
	data, err := securefs.ReadOwnedRegular(path, 64<<10)
	if err != nil {
		return retainedRecord{}, err
	}
	var record retainedRecord
	if securefs.DecodeStrictJSON(data, &record) != nil || record.Version != 1 || !validObjectID(record.RetainedID) || record.ProjectID == "" || !validObjectID(record.WorkSetDigest) || record.BulkID == "" || !validRetainedRoot(record.Root) || !validObjectID(record.ObjectDigest) || record.EntryCount < 0 || record.LogicalBytes < 0 || record.CreatedAt.IsZero() || (record.Kind == "project_bound" && !validObjectID(record.ObjectID)) {
		return retainedRecord{}, fmt.Errorf("retained record is unsafe")
	}
	return record, nil
}

func validRetainedRoot(root string) bool {
	return root != "" && !filepath.IsAbs(root) && filepath.Clean(root) == root && root != ".." && !strings.HasPrefix(root, "../") && !strings.ContainsAny(root, "\\\x00\r\n")
}
