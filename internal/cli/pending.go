package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"sunaba/internal/policy"
	"sunaba/internal/securefs"
	"sunaba/internal/session"
	"sunaba/internal/workspace"
)

const (
	pendingChangeVersion              = 4
	selfContainedPendingChangeVersion = 3
	legacyPendingChangeVersion        = 2
)

type pendingChange struct {
	Version            int                        `json:"version"`
	ProjectID          string                     `json:"project_id"`
	ProjectRoot        string                     `json:"project_root"`
	VMID               string                     `json:"vm_id"`
	SessionID          string                     `json:"session_id"`
	BaselineRoot       string                     `json:"baseline_root,omitempty"`
	MergedRoot         string                     `json:"merged_root"`
	Baseline           workspace.SnapshotManifest `json:"baseline"`
	Merged             workspace.SnapshotManifest `json:"merged"`
	ChangeSet          workspace.ChangeSet        `json:"change_set"`
	SnapshotPolicy     workspace.SnapshotPolicy   `json:"snapshot_policy,omitempty"`
	ExportPolicy       workspace.ExportPolicy     `json:"export_policy,omitempty"`
	ExportPolicyDigest string                     `json:"export_policy_digest"`
	CreatedAt          time.Time                  `json:"created_at"`
}

func persistPending(projectState string, active *session.Session, result session.ExportResult) (pendingChange, error) {
	if active == nil || !filepath.IsAbs(projectState) || result.ChangeSet.Digest == "" {
		return pendingChange{}, fmt.Errorf("cannot persist an incomplete Change Set")
	}
	pendingRoot := filepath.Join(projectState, "pending")
	if _, err := os.Lstat(filepath.Join(pendingRoot, "change.json")); err == nil {
		return pendingChange{}, fmt.Errorf("a pending Change Set already exists; apply or discard it before another Agent Session")
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
	baselineSource, err := workspace.CreateProjectSnapshot(active.SnapshotRoot, baselineRoot, active.SnapshotPolicy)
	if err != nil {
		return pendingChange{}, fmt.Errorf("persist verified baseline: %w", err)
	}
	if baselineSource.Digest != active.Baseline.Digest {
		return pendingChange{}, fmt.Errorf("persisted baseline source digest changed")
	}
	baseline, err := workspace.BuildSnapshotManifest(baselineRoot, active.SnapshotPolicy)
	if err != nil {
		return pendingChange{}, fmt.Errorf("verify persisted baseline: %w", err)
	}
	if baseline.Digest != active.Baseline.Digest {
		return pendingChange{}, fmt.Errorf("persisted baseline digest changed")
	}
	mergedRoot := filepath.Join(pendingRoot, "merged")
	source, err := workspace.CreateProjectSnapshot(result.MergedRoot, mergedRoot, active.SnapshotPolicy)
	if err != nil {
		return pendingChange{}, fmt.Errorf("persist verified Merged View: %w", err)
	}
	if source.Digest != result.Merged.Digest {
		return pendingChange{}, fmt.Errorf("persisted Merged View digest changed")
	}
	merged, err := workspace.BuildSnapshotManifest(mergedRoot, active.SnapshotPolicy)
	if err != nil {
		return pendingChange{}, fmt.Errorf("verify persisted Merged View: %w", err)
	}
	if merged.Digest != result.Merged.Digest {
		return pendingChange{}, fmt.Errorf("persisted Merged View digest changed")
	}
	rebuilt, err := workspace.BuildChangeSet(baseline, merged, active.SnapshotPolicy)
	if err != nil {
		return pendingChange{}, fmt.Errorf("rebuild persisted Change Set: %w", err)
	}
	if rebuilt.Digest != result.ChangeSet.Digest {
		return pendingChange{}, fmt.Errorf("persisted Change Set digest changed")
	}
	pending := pendingChange{
		Version: pendingChangeVersion, ProjectID: active.ProjectID, ProjectRoot: active.ProjectRoot, VMID: active.Container,
		SessionID: active.SessionID, BaselineRoot: baselineRoot, MergedRoot: mergedRoot, Baseline: baseline, Merged: merged,
		ChangeSet: rebuilt, SnapshotPolicy: active.SnapshotPolicy, ExportPolicy: active.ExportPolicy,
		ExportPolicyDigest: active.ExportPolicyDigest, CreatedAt: time.Now().UTC(),
	}
	if err := writePrivateJSON(filepath.Join(pendingRoot, "change.json"), pending); err != nil {
		return pendingChange{}, err
	}
	cleanup = false
	return pending, nil
}

func loadPending(projectState string, projectPolicy policy.ProjectPolicy) (pendingChange, error) {
	path := filepath.Join(projectState, "pending", "change.json")
	data, err := securefs.ReadOwnedRegular(path, 16<<20)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return pendingChange{}, fmt.Errorf("no pending Change Set")
		}
		return pendingChange{}, fmt.Errorf("pending Change Set metadata is unsafe")
	}
	var pending pendingChange
	if err := securefs.DecodeStrictJSON(data, &pending); err != nil || (pending.Version != pendingChangeVersion && pending.Version != selfContainedPendingChangeVersion && pending.Version != legacyPendingChangeVersion) || pending.ProjectRoot != projectPolicy.ProjectRoot || pending.ProjectID != projectPolicy.ProjectID || pending.MergedRoot != filepath.Join(projectState, "pending", "merged") {
		return pendingChange{}, fmt.Errorf("pending Change Set identity or schema does not match Project")
	}
	if pending.Version == pendingChangeVersion || pending.Version == selfContainedPendingChangeVersion {
		expectedBaselineRoot := filepath.Join(projectState, "pending", "baseline")
		if pending.BaselineRoot != expectedBaselineRoot || pending.Baseline.Root != expectedBaselineRoot || pending.Merged.Root != pending.MergedRoot {
			return pendingChange{}, fmt.Errorf("pending Change Set snapshot roots do not match Project state")
		}
		if securefs.CheckCanonicalOwnedDir(pending.BaselineRoot) != nil || securefs.CheckCanonicalOwnedDir(pending.MergedRoot) != nil {
			return pendingChange{}, fmt.Errorf("pending Change Set snapshot roots are not private current-user directories")
		}
	} else if pending.BaselineRoot != "" || pending.Baseline.Root != pending.ProjectRoot || pending.Merged.Root != pending.MergedRoot {
		return pendingChange{}, fmt.Errorf("legacy pending Change Set snapshot roots do not match Project state")
	}
	var compiled policy.CompiledExportPolicy
	if pending.Version == pendingChangeVersion {
		compiled, err = policy.ValidateCompiledExportPolicy(pending.SnapshotPolicy, pending.ExportPolicy)
		if err != nil || pending.ExportPolicyDigest != compiled.Digest {
			return pendingChange{}, fmt.Errorf("pending Change Set saved export policy is invalid")
		}
	} else {
		compiled, err = policy.CompileExportPolicy(projectPolicy.Export, projectPolicy.ProtectedPaths, projectPolicy.Snapshot.Exclude)
		if err != nil {
			return pendingChange{}, err
		}
		if pending.ExportPolicyDigest != compiled.Digest {
			return pendingChange{}, fmt.Errorf("legacy pending Change Set export policy no longer matches Project policy")
		}
	}
	if pending.Version == pendingChangeVersion || pending.Version == selfContainedPendingChangeVersion {
		actualBaseline, err := workspace.BuildSnapshotManifest(pending.BaselineRoot, compiled.Snapshot)
		if err != nil || actualBaseline.Root != pending.BaselineRoot || actualBaseline.Digest != pending.Baseline.Digest {
			return pendingChange{}, fmt.Errorf("pending baseline no longer matches its manifest")
		}
	}
	actual, err := workspace.BuildSnapshotManifest(pending.MergedRoot, compiled.Snapshot)
	if err != nil || actual.Root != pending.MergedRoot || actual.Digest != pending.Merged.Digest {
		return pendingChange{}, fmt.Errorf("pending Merged View no longer matches its manifest")
	}
	rebuilt, err := workspace.BuildChangeSet(pending.Baseline, pending.Merged, compiled.Snapshot)
	if err != nil || rebuilt.Digest != pending.ChangeSet.Digest {
		return pendingChange{}, fmt.Errorf("pending Change Set no longer matches its manifests")
	}
	return pending, nil
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
