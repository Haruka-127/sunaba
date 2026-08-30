package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sunaba/internal/policy"
	"sunaba/internal/retention"
	"sunaba/internal/securefs"
	"sunaba/internal/session"
	"sunaba/internal/workspace"
)

const pendingChangeVersion = workspace.PendingWorkSetVersion

// pendingChange schema v5 is the only supported development schema. The
// compatibility view fields are process-local conveniences and are never
// persisted or trusted as a second authority.
type pendingChange struct {
	Version         int                            `json:"version"`
	WorkSet         workspace.PendingWorkSet       `json:"work_set"`
	Resolution      workspace.Resolution           `json:"-"`
	WorkspacePolicy policy.CompiledWorkspacePolicy `json:"workspace_policy"`

	ProjectID          string                     `json:"-"`
	ProjectRoot        string                     `json:"-"`
	VMID               string                     `json:"-"`
	SessionID          string                     `json:"-"`
	BaselineRoot       string                     `json:"-"`
	MergedRoot         string                     `json:"-"`
	Baseline           workspace.SnapshotManifest `json:"-"`
	Merged             workspace.SnapshotManifest `json:"-"`
	ChangeSet          workspace.ChangeSet        `json:"-"`
	SnapshotPolicy     workspace.SnapshotPolicy   `json:"-"`
	ExportPolicy       workspace.ExportPolicy     `json:"-"`
	ExportPolicyDigest string                     `json:"-"`
	CreatedAt          time.Time                  `json:"-"`
}

func persistPending(projectState string, active *session.Session, result session.ExportResult) (pendingChange, error) {
	if active == nil || !filepath.IsAbs(projectState) {
		return pendingChange{}, fmt.Errorf("cannot persist an incomplete Work Set")
	}
	workSet := result.WorkSet
	workspacePolicy, err := activeWorkspacePolicy(active)
	if err != nil {
		return pendingChange{}, err
	}
	if workSet.Digest == "" {
		// Internal callers still emit only schema v5 when Bulk is disabled.
		digest := workspacePolicy.Digest
		var err error
		workSet, err = workspace.BuildPendingWorkSet(active.ProjectID, active.ProjectRoot, active.VMID, active.SessionID, digest, active.Baseline, result.Merged, active.SnapshotPolicy, workspace.DisabledBulkPolicy(), time.Now().UTC())
		if err != nil {
			return pendingChange{}, fmt.Errorf("construct Work Set: %w", err)
		}
	}
	if workSet.ProjectID != active.ProjectID || workSet.ProjectRoot != active.ProjectRoot || workSet.VMID != active.VMID || workSet.SessionID != active.SessionID || workSet.WorkspacePolicyDigest != workspacePolicy.Digest {
		return pendingChange{}, fmt.Errorf("Work Set identity does not match its Agent Session")
	}
	if err := policy.ValidateCompiledWorkspacePolicy(workspacePolicy); err != nil {
		return pendingChange{}, fmt.Errorf("Work Set saved workspace policy is invalid: %w", err)
	}
	pendingRoot := filepath.Join(projectState, "pending")
	if _, err := os.Lstat(filepath.Join(pendingRoot, "change.json")); err == nil {
		return pendingChange{}, fmt.Errorf("a pending Work Set already exists; apply or discard it before another Agent Session")
	} else if !errors.Is(err, os.ErrNotExist) {
		return pendingChange{}, err
	}
	if err := os.Mkdir(pendingRoot, 0700); err != nil {
		return pendingChange{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(pendingRoot)
		}
	}()
	baselineRoot := filepath.Join(pendingRoot, "baseline")
	approvedBaseline := active.Baseline
	approvedBaseline.Root = active.SnapshotRoot
	baseline, err := workspace.CreateApprovedProjectSnapshot(active.SnapshotRoot, baselineRoot, approvedBaseline, active.SnapshotPolicy)
	if err != nil {
		return pendingChange{}, fmt.Errorf("persist verified Core baseline: %w", err)
	}
	mergedRoot := filepath.Join(pendingRoot, "merged")
	approvedResult := workSet.Result.Core
	approvedResult.Root = result.MergedRoot
	merged, err := workspace.CreateApprovedProjectSnapshot(result.MergedRoot, mergedRoot, approvedResult, active.SnapshotPolicy)
	if err != nil {
		return pendingChange{}, fmt.Errorf("persist verified Core result: %w", err)
	}
	if baseline.Digest != workSet.Baseline.Core.Digest || merged.Digest != workSet.Result.Core.Digest {
		return pendingChange{}, fmt.Errorf("persisted Core snapshot digest changed")
	}
	workSet, err = workspace.RebindPendingWorkSetRoots(workSet, baselineRoot, mergedRoot, active.SnapshotPolicy)
	if err != nil {
		return pendingChange{}, err
	}
	resolution, err := workspace.BuildResolution(workSet, active.SnapshotPolicy, 1, nil)
	if err != nil {
		return pendingChange{}, err
	}
	pending := hydratePending(pendingChange{Version: pendingChangeVersion, WorkSet: workSet, Resolution: resolution, WorkspacePolicy: workspacePolicy})
	if err := writePrivateJSON(filepath.Join(pendingRoot, "resolution.json"), resolution); err != nil {
		return pendingChange{}, err
	}
	if err := writePrivateJSON(filepath.Join(pendingRoot, "change.json"), pending); err != nil {
		return pendingChange{}, err
	}
	cleanup = false
	return pending, nil
}

func activeWorkspacePolicy(active *session.Session) (policy.CompiledWorkspacePolicy, error) {
	if active.WorkspacePolicyDigest != "" {
		compiled := policy.CompiledWorkspacePolicy{
			Core: policy.CompiledExportPolicy{Snapshot: active.SnapshotPolicy, Export: active.ExportPolicy, Digest: active.ExportPolicyDigest},
			Bulk: active.BulkPolicy, Digest: active.WorkspacePolicyDigest,
		}
		return compiled, policy.ValidateCompiledWorkspacePolicy(compiled)
	}
	protected := make([]string, 0, len(active.SnapshotPolicy.ProtectedPaths))
	for _, item := range active.SnapshotPolicy.ProtectedPaths {
		if strings.EqualFold(item, ".git") || strings.EqualFold(item, ".sunaba") {
			continue
		}
		protected = append(protected, item)
	}
	compiled, err := policy.CompileWorkspacePolicy(policy.ExportPolicy{
		MaxEntries: active.SnapshotPolicy.MaxEntries, MaxFileBytes: active.SnapshotPolicy.MaxFileSize, MaxTotalBytes: active.SnapshotPolicy.MaxTotalSize,
	}, protected, active.SnapshotPolicy.ExcludedPaths, workspace.DisabledBulkPolicy())
	if err != nil || compiled.Core.Digest != active.ExportPolicyDigest {
		return policy.CompiledWorkspacePolicy{}, fmt.Errorf("Work Set saved workspace policy is invalid")
	}
	return compiled, nil
}

func loadPending(projectState string, projectPolicy policy.ProjectPolicy) (pendingChange, error) {
	if cleaned, err := retention.CleanupFinalizedPending(projectState); err != nil {
		return pendingChange{}, fmt.Errorf("recover finalized Work Set cleanup: %w", err)
	} else if cleaned {
		return pendingChange{}, fmt.Errorf("no pending Work Set")
	}
	if err := securefs.RecoverTransaction(filepath.Join(projectState, "pending", "metadata-transaction.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return pendingChange{}, fmt.Errorf("recover pending Work Set metadata: %w", err)
	}
	path := filepath.Join(projectState, "pending", "change.json")
	data, err := securefs.ReadOwnedRegular(path, 16<<20)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return pendingChange{}, fmt.Errorf("no pending Work Set")
		}
		return pendingChange{}, fmt.Errorf("pending Work Set metadata is unsafe")
	}
	var persisted pendingChange
	if err := securefs.DecodeStrictJSON(data, &persisted); err != nil || persisted.Version != pendingChangeVersion {
		return pendingChange{}, fmt.Errorf("pending Work Set schema is unsupported or invalid")
	}
	resolutionData, err := securefs.ReadOwnedRegular(filepath.Join(projectState, "pending", "resolution.json"), 1<<20)
	if err != nil || securefs.DecodeStrictJSON(resolutionData, &persisted.Resolution) != nil {
		return pendingChange{}, fmt.Errorf("pending Work Set Resolution metadata is unsafe")
	}
	pending := hydratePending(persisted)
	if pending.ProjectRoot != projectPolicy.ProjectRoot || pending.ProjectID != projectPolicy.ProjectID || pending.BaselineRoot != filepath.Join(projectState, "pending", "baseline") || !isPendingResultRoot(projectState, pending.MergedRoot) {
		return pendingChange{}, fmt.Errorf("pending Work Set identity does not match Project")
	}
	if err := policy.ValidateCompiledWorkspacePolicy(pending.WorkspacePolicy); err != nil || pending.WorkSet.WorkspacePolicyDigest != pending.WorkspacePolicy.Digest {
		return pendingChange{}, fmt.Errorf("pending Work Set saved workspace policy is invalid")
	}
	if projectPolicy.Export.MaxEntries != 0 {
		current, err := policy.CompileWorkspacePolicy(projectPolicy.Export, projectPolicy.ProtectedPaths, projectPolicy.Snapshot.Exclude, projectPolicy.Bulk)
		if err != nil || current.Digest != pending.WorkspacePolicy.Digest {
			return pendingChange{}, fmt.Errorf("pending Work Set workspace policy no longer matches Project policy (saved=%s current=%s): %v", pending.WorkspacePolicy.Digest, current.Digest, err)
		}
	}
	if securefs.CheckCanonicalOwnedDir(pending.BaselineRoot) != nil || securefs.CheckCanonicalOwnedDir(pending.MergedRoot) != nil {
		return pendingChange{}, fmt.Errorf("pending Work Set Core roots are not private current-user directories")
	}
	actualBaseline, err := workspace.BuildSnapshotManifest(pending.BaselineRoot, pending.SnapshotPolicy)
	if err != nil || actualBaseline.Digest != pending.WorkSet.Baseline.Core.Digest {
		return pendingChange{}, fmt.Errorf("pending Core baseline no longer matches its manifest")
	}
	actualResult, err := workspace.BuildSnapshotManifest(pending.MergedRoot, pending.SnapshotPolicy)
	if err != nil || actualResult.Digest != pending.WorkSet.Result.Core.Digest {
		return pendingChange{}, fmt.Errorf("pending Core result no longer matches its manifest")
	}
	if err := workspace.ValidatePendingWorkSet(pending.WorkSet, pending.SnapshotPolicy); err != nil {
		return pendingChange{}, fmt.Errorf("pending Work Set is invalid: %w", err)
	}
	if err := workspace.ValidateResolution(pending.WorkSet, pending.Resolution); err != nil {
		return pendingChange{}, fmt.Errorf("pending Work Set Resolution is invalid: %w", err)
	}
	return pending, nil
}

func isPendingResultRoot(projectState, root string) bool {
	pendingRoot := filepath.Join(projectState, "pending")
	return filepath.Dir(root) == pendingRoot && (filepath.Base(root) == "merged" || strings.HasPrefix(filepath.Base(root), "merged-normal-"))
}

func reviewPendingBulkNormally(ctx context.Context, projectState string, projectPolicy policy.ProjectPolicy, expectedWorkSet, bulkID, expectedBulk string) (pendingChange, error) {
	if ctx == nil {
		return pendingChange{}, fmt.Errorf("Normal review derivation requires a bounded context")
	}
	pending, err := loadPending(projectState, projectPolicy)
	if err != nil {
		return pendingChange{}, err
	}
	if pending.WorkSet.Digest != expectedWorkSet {
		return pendingChange{}, fmt.Errorf("expected Work Set digest is stale or missing")
	}
	var record workspace.BulkRecord
	found := false
	for _, candidate := range pending.WorkSet.Bulk {
		if candidate.BulkID == bulkID {
			record, found = candidate, true
			break
		}
	}
	if !found || workspace.BulkIdentity(record) != expectedBulk || !workspace.CanReviewBulkNormally(record) {
		return pendingChange{}, fmt.Errorf("Bulk path is stale or cannot be reviewed normally")
	}
	priorResultRoot := pending.MergedRoot
	randomID, err := newSessionID()
	if err != nil {
		return pendingChange{}, err
	}
	resultRoot := filepath.Join(projectState, "pending", "merged-normal-"+randomID)
	result, err := workspace.CreateApprovedProjectSnapshot(pending.MergedRoot, resultRoot, pending.Merged, pending.SnapshotPolicy)
	if err != nil {
		return pendingChange{}, fmt.Errorf("stage derived Normal result: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(resultRoot)
		}
	}()
	materializeContext, cancel := context.WithTimeout(ctx, 10*time.Minute)
	err = workspace.MaterializeBulkObjectAt(materializeContext, filepath.Join(projectState, "retained"), record.Capture, record.Result, resultRoot, result, pending.SnapshotPolicy)
	cancel()
	if err != nil {
		return pendingChange{}, fmt.Errorf("materialize Bulk object for Normal review: %w", err)
	}
	fullResult, err := workspace.BuildSnapshotManifest(resultRoot, pending.SnapshotPolicy)
	if err != nil {
		return pendingChange{}, fmt.Errorf("derived Normal review exceeds its hard limit: %w", err)
	}
	derived, err := workspace.DeriveWorkSetReviewNormally(pending.WorkSet, bulkID, fullResult, pending.SnapshotPolicy)
	if err != nil {
		return pendingChange{}, err
	}
	choices := make([]workspace.BulkResolution, 0, len(pending.Resolution.Bulk)-1)
	for _, choice := range pending.Resolution.Bulk {
		if choice.BulkID != bulkID {
			choices = append(choices, choice)
		}
	}
	resolution, err := workspace.BuildResolution(derived, pending.SnapshotPolicy, pending.Resolution.Revision+1, choices)
	if err != nil {
		return pendingChange{}, err
	}
	pending.WorkSet, pending.Resolution = derived, resolution
	pending = hydratePending(pending)
	changeData, err := json.MarshalIndent(pending, "", "  ")
	if err != nil {
		return pendingChange{}, err
	}
	resolutionData, err := json.MarshalIndent(resolution, "", "  ")
	if err != nil {
		return pendingChange{}, err
	}
	changeData, resolutionData = append(changeData, '\n'), append(resolutionData, '\n')
	if err := securefs.WriteTransaction(filepath.Join(projectState, "pending", "metadata-transaction.json"), []securefs.Replacement{
		{Path: filepath.Join(projectState, "pending", "resolution.json"), Data: resolutionData, MaximumBytes: 1 << 20},
		{Path: filepath.Join(projectState, "pending", "change.json"), Data: changeData, MaximumBytes: 16 << 20},
	}, securefs.TransactionOptions{}); err != nil {
		return pendingChange{}, err
	}
	committed = true
	_ = removeDerivedPendingResult(projectState, priorResultRoot, resultRoot)
	return pending, nil
}

func removeDerivedPendingResult(projectState, oldRoot, currentRoot string) error {
	if oldRoot == currentRoot || !isPendingResultRoot(projectState, oldRoot) {
		return fmt.Errorf("refusing to remove an unbound derived result")
	}
	info, err := os.Lstat(oldRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return fmt.Errorf("refusing to remove unsafe derived result")
	}
	if err := os.RemoveAll(oldRoot); err != nil {
		return err
	}
	return securefs.SyncDir(filepath.Dir(oldRoot))
}

func updatePendingResolution(projectState string, projectPolicy policy.ProjectPolicy, expectedWorkSet, bulkID, expectedBulk, disposition string) (pendingChange, error) {
	pending, err := loadPending(projectState, projectPolicy)
	if err != nil {
		return pendingChange{}, err
	}
	if expectedWorkSet == "" || expectedWorkSet != pending.WorkSet.Digest {
		return pendingChange{}, fmt.Errorf("expected Work Set digest is stale or missing")
	}
	if disposition == workspace.DispositionApplyDirectory {
		return pendingChange{}, fmt.Errorf("entire-directory apply is unavailable until the Apple Container runtime readout gate passes")
	}
	var target *workspace.BulkRecord
	for index := range pending.WorkSet.Bulk {
		if pending.WorkSet.Bulk[index].BulkID == bulkID {
			target = &pending.WorkSet.Bulk[index]
			break
		}
	}
	if target == nil || expectedBulk == "" || (expectedBulk != target.Result.ObjectDigest && expectedBulk != target.Capture.ObjectDigest) {
		return pendingChange{}, fmt.Errorf("expected Bulk identity is stale or missing")
	}
	choices := append([]workspace.BulkResolution(nil), pending.Resolution.Bulk...)
	found := false
	for index := range choices {
		if choices[index].BulkID == bulkID {
			choices[index].Disposition = disposition
			found = true
			break
		}
	}
	if !found {
		return pendingChange{}, fmt.Errorf("Bulk path is not part of the current Resolution")
	}
	resolution, err := workspace.BuildResolution(pending.WorkSet, pending.SnapshotPolicy, pending.Resolution.Revision+1, choices)
	if err != nil {
		return pendingChange{}, err
	}
	if err := writePrivateJSON(filepath.Join(projectState, "pending", "resolution.json"), resolution); err != nil {
		return pendingChange{}, err
	}
	pending.Resolution = resolution
	return pending, nil
}

func hydratePending(pending pendingChange) pendingChange {
	pending.ProjectID = pending.WorkSet.ProjectID
	pending.ProjectRoot = pending.WorkSet.ProjectRoot
	pending.VMID = pending.WorkSet.VMID
	pending.SessionID = pending.WorkSet.SessionID
	pending.BaselineRoot = pending.WorkSet.Baseline.Core.Root
	pending.MergedRoot = pending.WorkSet.Result.Core.Root
	pending.Baseline = pending.WorkSet.Baseline.Core
	pending.Merged = pending.WorkSet.Result.Core
	pending.ChangeSet = pending.WorkSet.CoreChangeSet
	pending.SnapshotPolicy = pending.WorkspacePolicy.Core.Snapshot
	pending.ExportPolicy = pending.WorkspacePolicy.Core.Export
	pending.ExportPolicyDigest = pending.WorkspacePolicy.Core.Digest
	pending.CreatedAt = pending.WorkSet.CreatedAt
	return pending
}

func removePending(projectState string) error {
	root := filepath.Join(projectState, "pending")
	if filepath.Dir(root) != projectState || filepath.Base(root) != "pending" {
		return fmt.Errorf("refusing to remove an unbound pending directory")
	}
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return fmt.Errorf("refusing to remove unsafe pending directory")
	}
	return os.RemoveAll(root)
}

func writePrivateJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	parent := filepath.Dir(path)
	if err := securefs.EnsureOwnedDir(parent); err != nil {
		return err
	}
	return securefs.AtomicWriteOwned(path, data)
}
