package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"sunaba/internal/trustedui"
	"sunaba/internal/workspace"
)

type bulkStatusItem struct {
	BulkID         string   `json:"bulk_id"`
	Root           string   `json:"root"`
	Reason         string   `json:"reason"`
	CaptureState   string   `json:"capture_state"`
	Disposition    string   `json:"disposition"`
	EntryCount     int      `json:"entry_count"`
	LogicalBytes   int64    `json:"logical_bytes"`
	MerkleDigest   string   `json:"merkle_digest,omitempty"`
	ObjectDigest   string   `json:"object_digest"`
	AllowedActions []string `json:"allowed_actions"`
}

type changesStatusDocument struct {
	SchemaVersion    int    `json:"schema_version"`
	WorkSetDigest    string `json:"work_set_digest"`
	ResolutionDigest string `json:"resolution_digest"`
	ApplyPlan        struct {
		Ready          bool `json:"ready"`
		UnresolvedBulk int  `json:"unresolved_bulk"`
	} `json:"apply_plan"`
	Normal struct {
		ChangeSetDigest string `json:"change_set_digest"`
		Add             int    `json:"add"`
		Modify          int    `json:"modify"`
		Delete          int    `json:"delete"`
		Rename          int    `json:"rename"`
	} `json:"normal"`
	Bulk []bulkStatusItem `json:"bulk"`
}

func (a *app) changesStatus(dir string, jsonOutput bool) error {
	projectPolicy, _, projectState, err := a.loadEffectivePolicy(dir)
	if err != nil {
		return err
	}
	pending, err := loadPending(projectState, projectPolicy)
	if err != nil {
		return err
	}
	document := buildChangesStatus(pending)
	if jsonOutput {
		encoded, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			return err
		}
		if len(encoded) > 1<<20 {
			return fmt.Errorf("bounded Work Set status exceeds 1 MiB")
		}
		_, err = fmt.Fprintf(a.output, "%s\n", encoded)
		return err
	}
	fmt.Fprintf(a.output, "Work Set: %s\nNormal changes: %d\nBulk paths: %d (%d unresolved)\nApply current plan: %t\n", document.WorkSetDigest, len(pending.ChangeSet.Changes), len(document.Bulk), document.ApplyPlan.UnresolvedBulk, document.ApplyPlan.Ready)
	return nil
}

func (a *app) changesBulkList(dir string, jsonOutput bool) error {
	projectPolicy, _, projectState, err := a.loadEffectivePolicy(dir)
	if err != nil {
		return err
	}
	pending, err := loadPending(projectState, projectPolicy)
	if err != nil {
		return err
	}
	document := buildChangesStatus(pending)
	if jsonOutput {
		encoded, err := json.MarshalIndent(document.Bulk, "", "  ")
		if err != nil {
			return err
		}
		if len(encoded) > 1<<20 {
			return fmt.Errorf("bounded Bulk list exceeds 1 MiB")
		}
		_, err = fmt.Fprintf(a.output, "%s\n", encoded)
		return err
	}
	for _, item := range document.Bulk {
		fmt.Fprintf(a.output, "%s  %s\n  %d entries · %d bytes · %s\n  Why: %s\n  Host: %s\n  Digest: %s\n", item.BulkID, trustedui.SanitizeTerminal(item.Root), item.EntryCount, item.LogicalBytes, item.CaptureState, item.Reason, item.Disposition, item.ObjectDigest)
	}
	return nil
}

func (a *app) changesBulkShow(dir, bulkID string) error {
	projectPolicy, _, projectState, err := a.loadEffectivePolicy(dir)
	if err != nil {
		return err
	}
	pending, err := loadPending(projectState, projectPolicy)
	if err != nil {
		return err
	}
	for _, item := range buildChangesStatus(pending).Bulk {
		if item.BulkID != bulkID {
			continue
		}
		fmt.Fprintf(a.output, "%s\n\nClassification\n  %s\n  This does not mean the data is disposable.\n\nCaptured result\n  Entries       %d\n  Logical size  %d bytes\n  Merkle digest %s\n\nDisposition\n  %s\n\nAllowed actions\n", trustedui.SanitizeTerminal(item.Root), item.Reason, item.EntryCount, item.LogicalBytes, item.MerkleDigest, item.Disposition)
		for _, action := range item.AllowedActions {
			fmt.Fprintf(a.output, "  %s\n", action)
		}
		return nil
	}
	return fmt.Errorf("Bulk ID is not part of the current Work Set")
}

func (a *app) changesBulkResolve(dir, bulkID, expectedWorkSet, expectedBulk, disposition string) error {
	projectPolicy, _, projectState, err := a.loadEffectivePolicy(dir)
	if err != nil {
		return err
	}
	lock, err := a.store.AcquireProjectLock(projectPolicy.ProjectRoot)
	if err != nil {
		return err
	}
	defer lock.Close()
	if lock.ProjectID != projectPolicy.ProjectID {
		return fmt.Errorf("Project identity mismatch")
	}
	pending, err := updatePendingResolution(projectState, projectPolicy, expectedWorkSet, bulkID, expectedBulk, disposition)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.output, "Updated Bulk disposition at Resolution revision %d. No Project data was changed or deleted.\nResolution digest: %s\n", pending.Resolution.Revision, pending.Resolution.Digest)
	return nil
}

func (a *app) changesBulkReviewNormally(ctx context.Context, dir, bulkID, expectedWorkSet, expectedBulk string) error {
	projectPolicy, _, projectState, err := a.loadEffectivePolicy(dir)
	if err != nil {
		return err
	}
	lock, err := a.store.AcquireProjectLock(projectPolicy.ProjectRoot)
	if err != nil {
		return err
	}
	defer lock.Close()
	if lock.ProjectID != projectPolicy.ProjectID {
		return fmt.Errorf("Project identity mismatch")
	}
	pending, err := reviewPendingBulkNormally(ctx, projectState, projectPolicy, expectedWorkSet, bulkID, expectedBulk)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.output, "Created derived Work Set %s. The selected path is now in Normal changes; the prior Work Set was not partially applied.\n", pending.WorkSet.Digest)
	return nil
}

func buildChangesStatus(pending pendingChange) changesStatusDocument {
	document := changesStatusDocument{SchemaVersion: 1, WorkSetDigest: pending.WorkSet.Digest, ResolutionDigest: pending.Resolution.Digest, Bulk: []bulkStatusItem{}}
	dispositions := make(map[string]string, len(pending.Resolution.Bulk))
	for _, item := range pending.Resolution.Bulk {
		dispositions[item.BulkID] = item.Disposition
		if item.Disposition == workspace.DispositionUnresolved {
			document.ApplyPlan.UnresolvedBulk++
		}
	}
	document.ApplyPlan.Ready = pendingPlanResolvable(pending)
	document.Normal.ChangeSetDigest = pending.ChangeSet.Digest
	for _, change := range pending.ChangeSet.Changes {
		switch change.Kind {
		case workspace.ChangeAdd:
			document.Normal.Add++
		case workspace.ChangeModify:
			document.Normal.Modify++
		case workspace.ChangeDelete:
			document.Normal.Delete++
		case workspace.ChangeRename:
			document.Normal.Rename++
		}
	}
	for _, record := range pending.WorkSet.Bulk {
		allowed := workspace.AllowedBulkDispositions(record)
		if workspace.CanReviewBulkNormally(record) {
			allowed = append(allowed, "review_normally")
		}
		document.Bulk = append(document.Bulk, bulkStatusItem{
			BulkID: record.BulkID, Root: record.Root, Reason: record.Discovery.Reason, CaptureState: record.Capture.State,
			Disposition: dispositions[record.BulkID], EntryCount: record.Summary.Files + record.Summary.Directories + record.Summary.Symlinks,
			LogicalBytes: record.Summary.LogicalBytes, MerkleDigest: record.Result.MerkleDigest,
			ObjectDigest: workspace.BulkIdentity(record), AllowedActions: allowed,
		})
	}
	return document
}
