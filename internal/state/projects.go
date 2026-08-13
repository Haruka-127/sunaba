package state

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const MaxRegisteredProjects = 256

type ProjectState struct {
	ProjectID string
	Path      string
	Err       error
}

// ListProjectStates inventories direct children of the private Project state
// directory. It never creates, repairs, migrates, or removes state.
func (s *Store) ListProjectStates() ([]ProjectState, error) {
	if s == nil || !filepath.IsAbs(s.Root) || filepath.Clean(s.Root) != s.Root {
		return nil, fmt.Errorf("state root must be absolute and clean")
	}
	if err := inspectPrivateDirectory(s.Root); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("inspect state root: %w", err)
	}
	projectsRoot := filepath.Join(s.Root, "projects")
	if err := inspectPrivateDirectory(projectsRoot); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("inspect Project state root: %w", err)
	}
	directory, err := os.Open(projectsRoot)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	names, err := directory.Readdirnames(MaxRegisteredProjects + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		// Readdirnames reports io.EOF after returning the final bounded batch.
		return nil, err
	}
	if len(names) > MaxRegisteredProjects {
		return nil, fmt.Errorf("registered Project count exceeds %d", MaxRegisteredProjects)
	}
	sort.Strings(names)
	projects := make([]ProjectState, 0, len(names))
	for _, name := range names {
		entry := ProjectState{ProjectID: name, Path: filepath.Join(projectsRoot, name)}
		if !ValidProjectID(name) {
			entry.Err = fmt.Errorf("state entry name is not a Project ID")
		} else if err := inspectPrivateDirectory(entry.Path); err != nil {
			entry.Err = fmt.Errorf("Project state directory is unsafe: %w", err)
		}
		projects = append(projects, entry)
	}
	return projects, nil
}

// ValidProjectID reports whether value is an exact Project state identifier.
func ValidProjectID(value string) bool {
	if len(value) != 12 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 6
}

// LookupProjectState resolves one exact direct child of the private Project
// state directory without reading or trusting its policy.
func (s *Store) LookupProjectState(projectID string) (ProjectState, error) {
	if s == nil || !filepath.IsAbs(s.Root) || filepath.Clean(s.Root) != s.Root {
		return ProjectState{}, fmt.Errorf("state root must be absolute and clean")
	}
	if !ValidProjectID(projectID) {
		return ProjectState{}, fmt.Errorf("Project ID must be exactly 12 lowercase hexadecimal characters")
	}
	if err := inspectPrivateDirectory(s.Root); err != nil {
		return ProjectState{}, fmt.Errorf("inspect state root: %w", err)
	}
	projectsRoot := filepath.Join(s.Root, "projects")
	if err := inspectPrivateDirectory(projectsRoot); err != nil {
		return ProjectState{}, fmt.Errorf("inspect Project state root: %w", err)
	}
	path := filepath.Join(projectsRoot, projectID)
	if filepath.Dir(path) != projectsRoot || filepath.Base(path) != projectID {
		return ProjectState{}, fmt.Errorf("Project state path is not an exact direct child")
	}
	if err := inspectPrivateDirectory(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ProjectState{}, fmt.Errorf("Project ID %s is not registered: %w", projectID, os.ErrNotExist)
		}
		return ProjectState{}, fmt.Errorf("Project state directory is unsafe: %w", err)
	}
	return ProjectState{ProjectID: projectID, Path: path}, nil
}

func inspectPrivateDirectory(path string) error {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0777 != 0700 || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("must be a mode 0700 directory owned by the current user")
	}
	return nil
}
