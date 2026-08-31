package recovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sunaba/internal/policy"
	"sunaba/internal/securefs"
	"sunaba/internal/unixsocket"
	"sunaba/internal/workspace"
)

const (
	Version  = 2
	FileName = "dev-export-recovery.json"
)

var identityPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{5,63}$`)

// State is host-owned metadata for a stopped VM whose export did not
// complete. It contains no capability or credential.
type State struct {
	Version             int                            `json:"version"`
	ProjectID           string                         `json:"project_id"`
	ProjectRoot         string                         `json:"project_root"`
	VMID                string                         `json:"vm_id"`
	SessionID           string                         `json:"session_id"`
	Container           string                         `json:"container"`
	RuntimeBase         string                         `json:"runtime_base"`
	RuntimeRoot         string                         `json:"runtime_root"`
	WorkspacePath       string                         `json:"workspace_path"`
	Mode                string                         `json:"mode,omitempty"`
	Baseline            workspace.SnapshotManifest     `json:"baseline"`
	BaselinePartitioned workspace.PartitionedManifest  `json:"baseline_partitioned"`
	BaselineBulk        []workspace.BulkRecord         `json:"baseline_bulk"`
	ExportPolicyDigest  string                         `json:"export_policy_digest"`
	WorkspacePolicy     policy.CompiledWorkspacePolicy `json:"workspace_policy"`
	GitGateway          bool                           `json:"git_gateway"`
	WebGateway          bool                           `json:"web_gateway"`
	PendingExport       *PendingExport                 `json:"pending_export,omitempty"`
	Reason              string                         `json:"reason"`
	CreatedAt           time.Time                      `json:"created_at"`
}

// RuntimeMode returns the bound VM mode. Records created before secure frozen
// export recovery existed omitted the field and are legacy dev records.
func (s State) RuntimeMode() string {
	if s.Mode == "" {
		return "dev"
	}
	return s.Mode
}

// PendingExport is a frozen, already verified export whose host pending
// transaction did not commit. It allows retry without restarting the VM.
type PendingExport struct {
	MergedRoot string                   `json:"merged_root"`
	WorkSet    workspace.PendingWorkSet `json:"work_set"`
}

func RuntimeBase(_ string, vmID string) string {
	return filepath.Join(shortRuntimeRoot(), "sunaba-d-"+vmID)
}

func SecureRuntimeBase(_ string, vmID string) string {
	return filepath.Join(shortRuntimeRoot(), "sunaba-s-"+vmID)
}

// LegacyRuntimeBase and LegacySecureRuntimeBase preserve exact validation for
// recovery records created before runtime paths were shortened for sun_path.
func LegacyRuntimeBase(projectState, vmID string) string {
	return filepath.Join(projectState, "dev-recovery-"+vmID)
}

func LegacySecureRuntimeBase(projectID, vmID string) string {
	return filepath.Join(shortRuntimeRoot(), "sunaba-recovery-"+projectID+"-"+vmID)
}

func shortRuntimeRoot() string {
	base := os.TempDir()
	if info, err := os.Lstat("/private/tmp"); err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		base = "/private/tmp"
	}
	return filepath.Clean(base)
}

func Path(projectState string) string { return filepath.Join(projectState, FileName) }

func NewRuntimeBase(projectState, vmID string) (string, error) {
	if err := validateProjectState(projectState); err != nil || !identityPattern.MatchString(vmID) {
		return "", fmt.Errorf("invalid dev recovery runtime identity")
	}
	base := RuntimeBase(projectState, vmID)
	if err := validateRuntimeSocketPaths(base, vmID); err != nil {
		return "", err
	}
	if err := os.Mkdir(base, 0700); err != nil {
		return "", err
	}
	return base, nil
}

func NewSecureRuntimeBase(projectID, vmID string) (string, error) {
	if !identityPattern.MatchString(projectID) || !identityPattern.MatchString(vmID) {
		return "", fmt.Errorf("invalid secure recovery runtime identity")
	}
	base := SecureRuntimeBase(projectID, vmID)
	if err := validateRuntimeSocketPaths(base, vmID); err != nil {
		return "", err
	}
	if err := os.Mkdir(base, 0700); err != nil {
		return "", err
	}
	return base, nil
}

func validateRuntimeSocketPaths(base, vmID string) error {
	root := filepath.Join(base, "sunaba-vm-"+vmID)
	for _, path := range []string{
		filepath.Join(root, "model-gateway.sock"),
		filepath.Join(root, "git-gateway.sock"),
		filepath.Join(root, "web-gateway.sock"),
		filepath.Join(root, "attach.sock"),
		filepath.Join(base, "approval-control.sock"),
		filepath.Join(base, "git-hook-"+strings.Repeat("r", 32)+".sock"),
	} {
		if err := unixsocket.ValidatePath(path); err != nil {
			return fmt.Errorf("runtime Unix socket path: %w", err)
		}
	}
	return nil
}

func Save(projectState string, state State) error {
	if err := validate(projectState, state); err != nil {
		return err
	}
	if _, err := os.Lstat(Path(projectState)); err == nil {
		return fmt.Errorf("an export recovery already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return securefs.AtomicWriteOwned(Path(projectState), append(data, '\n'))
}

func Load(projectState string) (State, error) {
	if err := validateProjectState(projectState); err != nil {
		return State{}, err
	}
	data, err := securefs.ReadOwnedRegular(Path(projectState), 16<<20)
	if err != nil {
		return State{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state State
	if decoder.Decode(&state) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return State{}, fmt.Errorf("dev recovery metadata has an invalid schema")
	}
	if err := validate(projectState, state); err != nil {
		return State{}, err
	}
	return state, nil
}

func Remove(projectState string, state State) error {
	if err := validate(projectState, state); err != nil {
		return err
	}
	if err := os.Remove(Path(projectState)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := securefs.SyncDir(projectState); err != nil {
		return err
	}
	info, err := os.Lstat(state.RuntimeBase)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return fmt.Errorf("refusing to remove unsafe dev recovery runtime")
	}
	return os.RemoveAll(state.RuntimeBase)
}

func validate(projectState string, state State) error {
	if err := validateProjectState(projectState); err != nil {
		return err
	}
	if state.Version != Version || !identityPattern.MatchString(state.ProjectID) || !identityPattern.MatchString(state.VMID) || !identityPattern.MatchString(state.SessionID) || state.ProjectRoot == "" || !filepath.IsAbs(state.ProjectRoot) || state.CreatedAt.IsZero() || state.Reason == "" || (state.RuntimeMode() != "dev" && state.RuntimeMode() != "secure") {
		return fmt.Errorf("dev recovery identity or schema is invalid")
	}
	expectedRuntimeBases := []string{RuntimeBase(projectState, state.VMID), LegacyRuntimeBase(projectState, state.VMID)}
	if state.RuntimeMode() == "secure" {
		expectedRuntimeBases = []string{SecureRuntimeBase(state.ProjectID, state.VMID), LegacySecureRuntimeBase(state.ProjectID, state.VMID)}
	}
	matchesRuntimeBase := false
	for _, expected := range expectedRuntimeBases {
		matchesRuntimeBase = matchesRuntimeBase || state.RuntimeBase == expected
	}
	if state.Container != "sunaba-"+state.ProjectID+"-"+state.VMID || !matchesRuntimeBase || state.RuntimeRoot != filepath.Join(state.RuntimeBase, "sunaba-vm-"+state.VMID) || state.WorkspacePath != "/workspace/sunaba-"+state.VMID || state.Baseline.Root != filepath.Join(state.RuntimeRoot, "snapshot") {
		return fmt.Errorf("dev recovery paths do not match its Project and VM identity")
	}
	if len(state.ExportPolicyDigest) != 64 || len(state.Baseline.Digest) != 64 || policy.ValidateCompiledWorkspacePolicy(state.WorkspacePolicy) != nil || state.WorkspacePolicy.Core.Digest != state.ExportPolicyDigest || state.BaselinePartitioned.Root != state.ProjectRoot || state.BaselinePartitioned.Core.Root != state.ProjectRoot || state.BaselinePartitioned.Core.Digest != state.Baseline.Digest || state.BaselinePartitioned.PolicyDigest != state.WorkspacePolicy.Digest || len(state.BaselinePartitioned.Digest) != 64 || len(state.BaselineBulk) != len(state.BaselinePartitioned.BulkRoots) {
		return fmt.Errorf("dev recovery policy or baseline digest is invalid")
	}
	rebuiltPartition, err := workspace.RebuildPartitionedManifestDigest(state.BaselinePartitioned)
	if err != nil || rebuiltPartition.Digest != state.BaselinePartitioned.Digest {
		return fmt.Errorf("dev recovery partitioned baseline is invalid")
	}
	for index, record := range state.BaselineBulk {
		if record.Root != state.BaselinePartitioned.BulkRoots[index].Root || record.Baseline != state.BaselinePartitioned.BulkRoots[index] {
			return fmt.Errorf("dev recovery Bulk baseline is invalid")
		}
	}
	if checkOwnedDirIfExists(state.RuntimeBase) != nil || checkOwnedDirIfExists(state.RuntimeRoot) != nil || checkOwnedDirIfExists(filepath.Join(state.RuntimeRoot, "snapshot")) != nil {
		return fmt.Errorf("dev recovery runtime is not a private current-user directory")
	}
	if state.PendingExport != nil {
		expectedMergedRoot := filepath.Join(state.RuntimeRoot, "sunaba-quarantine-"+state.SessionID, "sunaba-merged-"+state.SessionID)
		pending := state.PendingExport
		if pending.MergedRoot != expectedMergedRoot || pending.WorkSet.ProjectID != state.ProjectID || pending.WorkSet.ProjectRoot != state.ProjectRoot || pending.WorkSet.VMID != state.VMID || pending.WorkSet.SessionID != state.SessionID || pending.WorkSet.WorkspacePolicyDigest != state.WorkspacePolicy.Digest || pending.WorkSet.Result.Core.Root != pending.MergedRoot || workspace.ValidatePendingWorkSet(pending.WorkSet, state.WorkspacePolicy.Core.Snapshot) != nil || checkOwnedDirIfExists(expectedMergedRoot) != nil {
			return fmt.Errorf("dev recovery pending export is invalid")
		}
	}
	return nil
}

// checkOwnedDirIfExists enforces the private-directory contract only while the
// path still exists. macOS periodically reclaims unused /private/tmp content,
// and a runtime directory removed that way must not turn its recovery record
// into an undeletable lock that fails every Project command.
func checkOwnedDirIfExists(path string) error {
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return securefs.CheckCanonicalOwnedDir(path)
}

func validateProjectState(projectState string) error {
	if !filepath.IsAbs(projectState) || filepath.Clean(projectState) != projectState {
		return fmt.Errorf("dev recovery requires a canonical Project state path")
	}
	return securefs.CheckCanonicalOwnedDir(projectState)
}
