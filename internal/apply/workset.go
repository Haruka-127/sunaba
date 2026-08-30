package apply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/sys/unix"
	"sunaba/internal/approval"
	"sunaba/internal/audit"
	"sunaba/internal/state"
	"sunaba/internal/workspace"
)

type WorkSetConfig struct {
	Store          *state.Store
	ProjectRoot    string
	ProjectID      string
	BaselineRoot   string
	ResultRoot     string
	RetainedRoot   string
	WorkSet        workspace.PendingWorkSet
	Resolution     workspace.Resolution
	Plan           workspace.ApplyPlan
	BulkPolicy     workspace.BulkPolicy
	Approvals      *approval.Manager
	Grant          *approval.Grant
	Audit          *audit.Recorder
	SnapshotPolicy workspace.SnapshotPolicy
	ProjectCommit  func() error
	// DirectoryApplyEnabled is set only by the Apple Container runtime gate.
	// Production callers leave it false until stopped-VM readout semantics have
	// been verified on the pinned runtime.
	DirectoryApplyEnabled bool
}

func ApplyWorkSet(ctx context.Context, cfg WorkSetConfig) (result workspace.SnapshotManifest, err error) {
	if ctx == nil || cfg.Store == nil || cfg.Approvals == nil || cfg.Audit == nil || cfg.ProjectID == "" || !filepath.IsAbs(cfg.ProjectRoot) || !filepath.IsAbs(cfg.ResultRoot) || !filepath.IsAbs(cfg.RetainedRoot) {
		return workspace.SnapshotManifest{}, fmt.Errorf("Work Set apply configuration is incomplete")
	}
	if err := workspace.ValidateApplyPlan(cfg.WorkSet, cfg.Resolution, cfg.SnapshotPolicy, cfg.Plan); err != nil {
		return workspace.SnapshotManifest{}, err
	}
	cfg.BulkPolicy, err = workspace.EffectiveWorkSetBulkPolicy(cfg.BulkPolicy, cfg.WorkSet)
	if err != nil {
		return workspace.SnapshotManifest{}, err
	}
	details := map[string]string{"work_set_digest": cfg.WorkSet.Digest, "resolution_digest": cfg.Resolution.Digest, "apply_plan_digest": cfg.Plan.Digest}
	if err := cfg.Audit.Append(audit.BoundaryEvent{Category: "apply", Action: "workset.apply", Outcome: "started", ProjectID: cfg.ProjectID, Details: details}); err != nil {
		return workspace.SnapshotManifest{}, err
	}
	defer func() {
		outcome := "success"
		if err != nil {
			outcome = "rejected"
		}
		err = errors.Join(err, cfg.Audit.Append(audit.BoundaryEvent{Category: "apply", Action: "workset.apply", Outcome: outcome, ProjectID: cfg.ProjectID, Details: details}))
	}()
	lock, err := cfg.Store.AcquireProjectLock(cfg.ProjectRoot)
	if err != nil {
		return workspace.SnapshotManifest{}, err
	}
	defer lock.Close()
	if lock.ProjectID != cfg.ProjectID || cfg.WorkSet.ProjectID != cfg.ProjectID || cfg.Plan.ProjectID != cfg.ProjectID {
		return workspace.SnapshotManifest{}, fmt.Errorf("Project identity mismatch")
	}
	if err := RecoverLocked(cfg.ProjectRoot, cfg.ProjectID, cfg.SnapshotPolicy); err != nil {
		return workspace.SnapshotManifest{}, err
	}
	current, _, err := workspace.BuildPartitionedSnapshotManifest(cfg.ProjectRoot, cfg.SnapshotPolicy, cfg.BulkPolicy, cfg.WorkSet.WorkspacePolicyDigest)
	if err != nil || current.Core.Digest != cfg.Plan.CurrentCoreBaselineDigest {
		return workspace.SnapshotManifest{}, fmt.Errorf("host Core baseline changed before apply")
	}
	if err := validateBulkBeforeGuards(cfg, current); err != nil {
		return workspace.SnapshotManifest{}, err
	}
	if err := validateRetainedObjects(ctx, cfg); err != nil {
		return workspace.SnapshotManifest{}, err
	}
	binding := workSetApprovalBinding(cfg.Plan)
	if err := cfg.Approvals.ConsumeWorkSet(cfg.Grant, binding); err != nil {
		return workspace.SnapshotManifest{}, err
	}
	return applyWorkSetLocked(ctx, cfg)
}

func workSetApprovalBinding(plan workspace.ApplyPlan) approval.WorkSetApprovalBinding {
	return approval.WorkSetApprovalBinding{
		ProjectID: plan.ProjectID, WorkSetDigest: plan.WorkSetDigest, ResolutionDigest: plan.ResolutionDigest,
		ApplyPlanDigest: plan.Digest, CoreBaselineDigest: plan.CurrentCoreBaselineDigest,
		CoreChangeSetDigest: plan.CoreChangeSetDigest, BulkSelectionDigest: plan.BulkSelectionDigest,
	}
}

func validateRetainedObjects(ctx context.Context, cfg WorkSetConfig) error {
	byID := make(map[string]workspace.BulkRecord, len(cfg.WorkSet.Bulk))
	for _, record := range cfg.WorkSet.Bulk {
		byID[record.BulkID] = record
	}
	for _, operation := range cfg.Plan.BulkOperations {
		record := byID[operation.BulkID]
		if record.Capture.State == "exact_managed" {
			if _, err := workspace.ValidateBulkObject(ctx, cfg.RetainedRoot, record.Capture, record.Result); err != nil {
				return fmt.Errorf("validate retained Bulk object: %w", err)
			}
		} else if record.Capture.State != "exact_absence" {
			return fmt.Errorf("Bulk path %q is not durably available for apply", record.Root)
		}
	}
	for _, reviewed := range cfg.WorkSet.ReviewedBulk {
		if _, err := workspace.ValidateBulkObject(ctx, cfg.RetainedRoot, reviewed.Capture, reviewed.Result); err != nil {
			return fmt.Errorf("validate normally reviewed Bulk source object: %w", err)
		}
	}
	return nil
}

func validateBulkBeforeGuards(cfg WorkSetConfig, current workspace.PartitionedManifest) error {
	rootFD, err := openDirectory(cfg.ProjectRoot)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	for _, operation := range cfg.Plan.BulkOperations {
		if operation.Disposition != workspace.DispositionApplyDirectory {
			continue
		}
		if !cfg.DirectoryApplyEnabled {
			return fmt.Errorf("entire-directory apply is unavailable until the Apple Container runtime readout gate passes")
		}
		if operation.BeforeState != "absent" {
			return fmt.Errorf("exact Bulk replace/delete remains disabled until its runtime gate passes")
		}
		exists, err := relativeExists(rootFD, operation.Root)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("Bulk create conflict at %q", operation.Root)
		}
		if operation.AfterState != "exact" {
			return fmt.Errorf("Bulk delete is not enabled in the create-only transaction phase")
		}
	}
	_ = current
	return nil
}

func applyWorkSetLocked(ctx context.Context, cfg WorkSetConfig) (result workspace.SnapshotManifest, err error) {
	transactionRoot, err := newTransactionRoot(cfg.ProjectRoot, cfg.ProjectID)
	if err != nil {
		return workspace.SnapshotManifest{}, err
	}
	journalReady := false
	projectCommitted := false
	defer func() {
		if err != nil && !journalReady {
			_ = removeTransactionRoot(transactionRoot, cfg.ProjectRoot)
		}
	}()
	backupRoot := filepath.Join(transactionRoot, "backup")
	if err := os.Mkdir(backupRoot, 0700); err != nil {
		return workspace.SnapshotManifest{}, err
	}
	affected := affectedRoots(cfg.WorkSet.CoreChangeSet)
	for _, operation := range cfg.Plan.BulkOperations {
		if operation.Disposition == workspace.DispositionApplyDirectory {
			affected = append(affected, operation.Root)
		}
	}
	sort.Strings(affected)
	stageRoot := filepath.Join(transactionRoot, "stage")
	if _, err := workspace.CreateApprovedSnapshotSubset(cfg.ResultRoot, stageRoot, cfg.WorkSet.Result.Core, affectedRoots(cfg.WorkSet.CoreChangeSet), cfg.SnapshotPolicy); err != nil {
		return workspace.SnapshotManifest{}, fmt.Errorf("stage approved Core result: %w", err)
	}
	byID := make(map[string]workspace.BulkRecord, len(cfg.WorkSet.Bulk))
	for _, record := range cfg.WorkSet.Bulk {
		byID[record.BulkID] = record
	}
	for _, operation := range cfg.Plan.BulkOperations {
		if operation.Disposition != workspace.DispositionApplyDirectory {
			continue
		}
		record := byID[operation.BulkID]
		if err := workspace.MaterializeBulkObjectAt(ctx, cfg.RetainedRoot, record.Capture, record.Result, stageRoot, cfg.WorkSet.Result.Core, cfg.SnapshotPolicy); err != nil {
			return workspace.SnapshotManifest{}, fmt.Errorf("stage Bulk directory: %w", err)
		}
	}
	rootFD, err := openDirectory(cfg.ProjectRoot)
	if err != nil {
		return workspace.SnapshotManifest{}, err
	}
	defer unix.Close(rootFD)
	backupFD, err := openDirectory(backupRoot)
	if err != nil {
		return workspace.SnapshotManifest{}, err
	}
	defer unix.Close(backupFD)
	stageFD, err := openDirectory(stageRoot)
	if err != nil {
		return workspace.SnapshotManifest{}, err
	}
	defer unix.Close(stageFD)
	desired := make(map[string]struct{}, len(cfg.WorkSet.Result.Core.Entries)+len(cfg.Plan.BulkOperations))
	for _, entry := range cfg.WorkSet.Result.Core.Entries {
		desired[entry.Path] = struct{}{}
	}
	for _, operation := range cfg.Plan.BulkOperations {
		if operation.Disposition == workspace.DispositionApplyDirectory && operation.AfterState == "exact" {
			desired[operation.Root] = struct{}{}
		}
	}
	j := journal{Version: 2, ProjectID: cfg.ProjectID, BaselineDigest: cfg.WorkSet.Baseline.Core.Digest, MergedDigest: cfg.WorkSet.Result.Core.Digest, ChangeSetDigest: cfg.WorkSet.CoreChangeSet.Digest, WorkSetDigest: cfg.WorkSet.Digest, ApplyPlanDigest: cfg.Plan.Digest}
	for index, entryPath := range affected {
		exists, err := relativeExists(rootFD, entryPath)
		if err != nil && !projectCommitted {
			return workspace.SnapshotManifest{}, err
		}
		_, wanted := desired[entryPath]
		j.Entries = append(j.Entries, journalEntry{Path: entryPath, BackupName: fmt.Sprintf("item-%06d", index), Original: exists, Desired: wanted})
	}
	if err := writeJournal(filepath.Join(transactionRoot, "journal.json"), j); err != nil {
		return workspace.SnapshotManifest{}, err
	}
	journalReady = true
	defer func() {
		if err != nil && !projectCommitted {
			if rollbackErr := rollback(rootFD, backupFD, j); rollbackErr != nil {
				err = fmt.Errorf("Work Set apply failed: %v; rollback failed: %w", err, rollbackErr)
				return
			}
			_ = removeTransactionRoot(transactionRoot, cfg.ProjectRoot)
		}
	}()
	for _, item := range j.Entries {
		if item.Original {
			if err := renameRelative(rootFD, item.Path, backupFD, item.BackupName); err != nil {
				return workspace.SnapshotManifest{}, err
			}
		}
		if item.Desired {
			if err := renameRelative(stageFD, item.Path, rootFD, item.Path); err != nil {
				return workspace.SnapshotManifest{}, err
			}
		}
	}
	post, err := verifyWorkSetProjection(cfg, byID)
	if err != nil {
		return workspace.SnapshotManifest{}, err
	}
	j.ProjectCommitted = true
	if err := writeJournal(filepath.Join(transactionRoot, "journal.json"), j); err != nil {
		return workspace.SnapshotManifest{}, fmt.Errorf("persist Project transaction commit: %w", err)
	}
	projectCommitted = true
	if cfg.ProjectCommit != nil {
		if err := cfg.ProjectCommit(); err != nil {
			return workspace.SnapshotManifest{}, fmt.Errorf("persist Project commit marker: %w", err)
		}
	}
	if err := removeTransactionRoot(transactionRoot, cfg.ProjectRoot); err != nil {
		return workspace.SnapshotManifest{}, err
	}
	return post.Core, nil
}

// ResumeWorkSetTransaction resolves a transaction interrupted after approval.
// An uncommitted journal is rolled back; a committed journal is only cleaned
// up. The caller can then resume retention finalization without consuming a
// second approval or applying the Project twice.
func ResumeWorkSetTransaction(ctx context.Context, cfg WorkSetConfig) (bool, error) {
	if ctx == nil || cfg.Store == nil || !filepath.IsAbs(cfg.ProjectRoot) || cfg.ProjectID == "" {
		return false, fmt.Errorf("Work Set recovery configuration is incomplete")
	}
	if err := workspace.ValidateApplyPlan(cfg.WorkSet, cfg.Resolution, cfg.SnapshotPolicy, cfg.Plan); err != nil {
		return false, err
	}
	var err error
	cfg.BulkPolicy, err = workspace.EffectiveWorkSetBulkPolicy(cfg.BulkPolicy, cfg.WorkSet)
	if err != nil {
		return false, err
	}
	lock, err := cfg.Store.AcquireProjectLock(cfg.ProjectRoot)
	if err != nil {
		return false, err
	}
	defer lock.Close()
	if lock.ProjectID != cfg.ProjectID {
		return false, fmt.Errorf("Project identity mismatch")
	}
	if err := RecoverLocked(cfg.ProjectRoot, cfg.ProjectID, cfg.SnapshotPolicy); err != nil {
		return false, err
	}
	byID := make(map[string]workspace.BulkRecord, len(cfg.WorkSet.Bulk))
	for _, record := range cfg.WorkSet.Bulk {
		byID[record.BulkID] = record
	}
	if _, err := verifyWorkSetProjection(cfg, byID); err == nil {
		return true, nil
	}
	current, _, currentErr := workspace.BuildPartitionedSnapshotManifest(cfg.ProjectRoot, cfg.SnapshotPolicy, cfg.BulkPolicy, cfg.WorkSet.WorkspacePolicyDigest)
	if currentErr != nil {
		return false, currentErr
	}
	if current.Core.Digest != cfg.Plan.CurrentCoreBaselineDigest {
		return false, fmt.Errorf("Project is neither the approved before-state nor complete after-state")
	}
	if err := validateBulkBeforeGuards(cfg, current); err != nil {
		return false, fmt.Errorf("Project is neither the approved before-state nor complete after-state: %w", err)
	}
	return false, nil
}

func verifyWorkSetProjection(cfg WorkSetConfig, byID map[string]workspace.BulkRecord) (workspace.PartitionedManifest, error) {
	post, _, err := workspace.BuildPartitionedSnapshotManifest(cfg.ProjectRoot, cfg.SnapshotPolicy, cfg.BulkPolicy, cfg.WorkSet.WorkspacePolicyDigest)
	if err != nil || post.Core.Digest != cfg.Plan.ExpectedCoreDigest {
		return workspace.PartitionedManifest{}, fmt.Errorf("post-apply Core projection mismatch")
	}
	needsBulkScan := false
	for _, operation := range cfg.Plan.BulkOperations {
		needsBulkScan = needsBulkScan || operation.Disposition == workspace.DispositionApplyDirectory
	}
	if !needsBulkScan {
		return post, nil
	}
	full, err := workspace.BuildSnapshotManifest(cfg.ProjectRoot, workspace.BulkCaptureSnapshotPolicy(cfg.SnapshotPolicy))
	if err != nil {
		return workspace.PartitionedManifest{}, err
	}
	for _, operation := range cfg.Plan.BulkOperations {
		if operation.Disposition != workspace.DispositionApplyDirectory {
			continue
		}
		record := byID[operation.BulkID]
		actual, err := workspace.ExactBulkRefFromManifest(full, record.Root)
		if err != nil || actual.MerkleDigest != record.Result.MerkleDigest {
			return workspace.PartitionedManifest{}, fmt.Errorf("post-apply Bulk directory mismatch")
		}
	}
	return post, nil
}

func PrepareWorkSetPlan(ctx context.Context, cfg WorkSetConfig) (workspace.ApplyPlan, error) {
	if ctx == nil {
		return workspace.ApplyPlan{}, fmt.Errorf("Apply Plan requires a bounded context")
	}
	effective, err := workspace.EffectiveWorkSetBulkPolicy(cfg.BulkPolicy, cfg.WorkSet)
	if err != nil {
		return workspace.ApplyPlan{}, err
	}
	cfg.BulkPolicy = effective
	current, _, err := workspace.BuildPartitionedSnapshotManifest(cfg.ProjectRoot, cfg.SnapshotPolicy, cfg.BulkPolicy, cfg.WorkSet.WorkspacePolicyDigest)
	if err != nil {
		return workspace.ApplyPlan{}, err
	}
	plan, err := workspace.BuildApplyPlan(cfg.WorkSet, cfg.Resolution, cfg.SnapshotPolicy, current.Core.Digest)
	if err != nil {
		return workspace.ApplyPlan{}, err
	}
	cfg.Plan = plan
	verification, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if err := validateBulkBeforeGuards(cfg, current); err != nil {
		return workspace.ApplyPlan{}, err
	}
	if err := validateRetainedObjects(verification, cfg); err != nil {
		return workspace.ApplyPlan{}, err
	}
	return plan, nil
}
