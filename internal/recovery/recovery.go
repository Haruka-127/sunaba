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
	"time"

	"sunaba/internal/securefs"
	"sunaba/internal/workspace"
)

const (
	Version  = 1
	FileName = "dev-export-recovery.json"
)

var identityPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{5,63}$`)

// State is host-owned metadata for a stopped dev VM whose export did not
// complete. It contains no capability or credential.
type State struct {
	Version            int                        `json:"version"`
	ProjectID          string                     `json:"project_id"`
	ProjectRoot        string                     `json:"project_root"`
	VMID               string                     `json:"vm_id"`
	SessionID          string                     `json:"session_id"`
	Container          string                     `json:"container"`
	RuntimeBase        string                     `json:"runtime_base"`
	RuntimeRoot        string                     `json:"runtime_root"`
	WorkspacePath      string                     `json:"workspace_path"`
	Baseline           workspace.SnapshotManifest `json:"baseline"`
	ExportPolicyDigest string                     `json:"export_policy_digest"`
	GitGateway         bool                       `json:"git_gateway"`
	WebGateway         bool                       `json:"web_gateway"`
	Reason             string                     `json:"reason"`
	CreatedAt          time.Time                  `json:"created_at"`
}

func RuntimeBase(projectState, vmID string) string {
	return filepath.Join(projectState, "dev-recovery-"+vmID)
}

func Path(projectState string) string { return filepath.Join(projectState, FileName) }

func NewRuntimeBase(projectState, vmID string) (string, error) {
	if err := validateProjectState(projectState); err != nil || !identityPattern.MatchString(vmID) {
		return "", fmt.Errorf("invalid dev recovery runtime identity")
	}
	base := RuntimeBase(projectState, vmID)
	if err := os.Mkdir(base, 0700); err != nil {
		return "", err
	}
	return base, nil
}

func Save(projectState string, state State) error {
	if err := validate(projectState, state); err != nil {
		return err
	}
	if _, err := os.Lstat(Path(projectState)); err == nil {
		return fmt.Errorf("a dev export recovery already exists")
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
	if state.Version != Version || !identityPattern.MatchString(state.ProjectID) || !identityPattern.MatchString(state.VMID) || !identityPattern.MatchString(state.SessionID) || state.ProjectRoot == "" || !filepath.IsAbs(state.ProjectRoot) || state.CreatedAt.IsZero() || state.Reason == "" {
		return fmt.Errorf("dev recovery identity or schema is invalid")
	}
	if state.Container != "sunaba-"+state.ProjectID+"-"+state.VMID || state.RuntimeBase != RuntimeBase(projectState, state.VMID) || state.RuntimeRoot != filepath.Join(state.RuntimeBase, "sunaba-vm-"+state.VMID) || state.WorkspacePath != "/workspace/sunaba-"+state.VMID || state.Baseline.Root != state.ProjectRoot {
		return fmt.Errorf("dev recovery paths do not match its Project and VM identity")
	}
	if len(state.ExportPolicyDigest) != 64 || len(state.Baseline.Digest) != 64 {
		return fmt.Errorf("dev recovery policy or baseline digest is invalid")
	}
	if securefs.CheckCanonicalOwnedDir(state.RuntimeBase) != nil || securefs.CheckCanonicalOwnedDir(state.RuntimeRoot) != nil || securefs.CheckCanonicalOwnedDir(filepath.Join(state.RuntimeRoot, "snapshot")) != nil {
		return fmt.Errorf("dev recovery runtime is not a private current-user directory")
	}
	return nil
}

func validateProjectState(projectState string) error {
	if !filepath.IsAbs(projectState) || filepath.Clean(projectState) != projectState {
		return fmt.Errorf("dev recovery requires a canonical Project state path")
	}
	return securefs.CheckCanonicalOwnedDir(projectState)
}
