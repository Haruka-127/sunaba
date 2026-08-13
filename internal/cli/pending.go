package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"sunaba/internal/policy"
	"sunaba/internal/session"
	"sunaba/internal/workspace"
)

type pendingChange struct {
	Version            int                        `json:"version"`
	ProjectID          string                     `json:"project_id"`
	ProjectRoot        string                     `json:"project_root"`
	VMID               string                     `json:"vm_id"`
	SessionID          string                     `json:"session_id"`
	MergedRoot         string                     `json:"merged_root"`
	Baseline           workspace.SnapshotManifest `json:"baseline"`
	Merged             workspace.SnapshotManifest `json:"merged"`
	ChangeSet          workspace.ChangeSet        `json:"change_set"`
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
	mergedRoot := filepath.Join(pendingRoot, "merged")
	merged, err := workspace.CreateProjectSnapshot(result.MergedRoot, mergedRoot, active.SnapshotPolicy)
	if err != nil || merged.Digest != result.Merged.Digest {
		return pendingChange{}, fmt.Errorf("persist verified Merged View: %w", err)
	}
	rebuilt, err := workspace.BuildChangeSet(active.Baseline, merged, active.SnapshotPolicy)
	if err != nil || rebuilt.Digest != result.ChangeSet.Digest {
		return pendingChange{}, fmt.Errorf("persisted Change Set digest changed")
	}
	pending := pendingChange{
		Version: 2, ProjectID: active.ProjectID, ProjectRoot: active.ProjectRoot, VMID: active.Container,
		SessionID: active.SessionID, MergedRoot: mergedRoot, Baseline: active.Baseline, Merged: merged,
		ChangeSet: rebuilt, ExportPolicyDigest: active.ExportPolicyDigest, CreatedAt: time.Now().UTC(),
	}
	if err := writePrivateJSON(filepath.Join(pendingRoot, "change.json"), pending); err != nil {
		return pendingChange{}, err
	}
	cleanup = false
	return pending, nil
}

func loadPending(projectState string, projectPolicy policy.ProjectPolicy) (pendingChange, error) {
	compiled, err := policy.CompileExportPolicy(projectPolicy.Export, projectPolicy.ProtectedPaths)
	if err != nil {
		return pendingChange{}, err
	}
	path := filepath.Join(projectState, "pending", "change.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		if errors.Is(err, os.ErrNotExist) {
			return pendingChange{}, fmt.Errorf("no pending Change Set")
		}
		return pendingChange{}, fmt.Errorf("pending Change Set metadata is unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return pendingChange{}, err
	}
	if len(data) > 16<<20 {
		return pendingChange{}, fmt.Errorf("pending Change Set metadata exceeds size limit")
	}
	var pending pendingChange
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&pending); err != nil || decoder.Decode(&struct{}{}) != io.EOF || pending.Version != 2 || pending.ProjectRoot != projectPolicy.ProjectRoot || pending.ProjectID != projectPolicy.ProjectID || pending.MergedRoot != filepath.Join(projectState, "pending", "merged") {
		return pendingChange{}, fmt.Errorf("pending Change Set identity or schema does not match Project")
	}
	if pending.ExportPolicyDigest != compiled.Digest {
		return pendingChange{}, fmt.Errorf("pending Change Set export policy no longer matches Project policy")
	}
	actual, err := workspace.BuildSnapshotManifest(pending.MergedRoot, compiled.Snapshot)
	if err != nil || actual.Digest != pending.Merged.Digest {
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
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(parent, ".sunaba-pending-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
