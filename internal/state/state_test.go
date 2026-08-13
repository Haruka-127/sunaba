package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"sunaba/internal/dependency"
)

func TestProjectID(t *testing.T) {
	id := ProjectID("/Users/alice/work/myapp")
	if len(id) != 12 || id != ProjectID("/Users/alice/work/myapp") {
		t.Fatalf("ProjectID is not stable: %q", id)
	}
}

func TestGlobalStateRoundTripIsPrivate(t *testing.T) {
	store := &Store{Root: filepath.Join(t.TempDir(), "sunaba")}
	if err := store.SaveGlobal(GlobalConfig{ImageVersion: "1.18.16"}); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadGlobal()
	if err != nil || loaded.ImageVersion != "1.18.16" {
		t.Fatalf("loaded=%+v error=%v", loaded, err)
	}
	for _, path := range []string{store.Root, filepath.Join(store.Root, "projects")} {
		if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0700 {
			t.Fatalf("private directory %s info=%v error=%v", path, info, err)
		}
	}
	if info, err := os.Lstat(filepath.Join(store.Root, "config.json")); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private config info=%v error=%v", info, err)
	}
}

func TestActiveDependencyRoundTrip(t *testing.T) {
	store := &Store{Root: filepath.Join(t.TempDir(), "sunaba")}
	binding, err := NewDependencyBinding(3, dependency.MustPinned())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveActiveDependency(binding); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadActiveDependency()
	if err != nil || loaded != binding {
		t.Fatalf("loaded=%+v error=%v", loaded, err)
	}
}

func TestGlobalStateRejectsSymlinkAndUnknownLegacyFields(t *testing.T) {
	store := &Store{Root: filepath.Join(t.TempDir(), "sunaba")}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte(`{"image_version":"1.18.16"}`), 0600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(store.Root, "config.json")
	if err := os.Symlink(target, config); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadGlobal(); err == nil {
		t.Fatal("symlink global state was accepted")
	}
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte(`{"image_version":"1.18.16","firewall_mode":"disabled"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadGlobal(); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatal("obsolete global firewall policy was accepted")
	}
}

func TestListProjectStatesIsReadOnlyAndIsolatesUnsafeEntries(t *testing.T) {
	store := &Store{Root: filepath.Join(t.TempDir(), "sunaba")}
	if projects, err := store.ListProjectStates(); err != nil || len(projects) != 0 {
		t.Fatalf("absent state projects=%v error=%v", projects, err)
	}
	if _, err := os.Lstat(store.Root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only listing created the state root: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	projectsRoot := filepath.Join(store.Root, "projects")
	if err := os.Mkdir(filepath.Join(projectsRoot, "0123456789ab"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(projectsRoot, "abcdefabcdef"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectsRoot, "not-a-project"), []byte("untrusted"), 0600); err != nil {
		t.Fatal(err)
	}
	projects, err := store.ListProjectStates()
	if err != nil || len(projects) != 3 {
		t.Fatalf("projects=%v error=%v", projects, err)
	}
	byID := make(map[string]ProjectState, len(projects))
	for _, project := range projects {
		byID[project.ProjectID] = project
	}
	if byID["0123456789ab"].Err != nil || byID["abcdefabcdef"].Err == nil || byID["not-a-project"].Err == nil {
		t.Fatalf("unsafe entries were not isolated: %+v", byID)
	}
}

func TestLookupProjectStateRequiresExactSafeDirectChild(t *testing.T) {
	store := &Store{Root: filepath.Join(t.TempDir(), "sunaba")}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	projectsRoot := filepath.Join(store.Root, "projects")
	projectID := "0123456789ab"
	projectState := filepath.Join(projectsRoot, projectID)
	if err := os.Mkdir(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	resolved, err := store.LookupProjectState(projectID)
	if err != nil || resolved.ProjectID != projectID || resolved.Path != projectState {
		t.Fatalf("resolved=%+v error=%v", resolved, err)
	}
	for _, invalid := range []string{"", "0123456789a", "0123456789AB", "../0123456789ab", "0123456789abcdef"} {
		if _, err := store.LookupProjectState(invalid); err == nil {
			t.Errorf("invalid Project ID was accepted: %q", invalid)
		}
	}
	if _, err := store.LookupProjectState("abcdefabcdef"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing Project ID error=%v", err)
	}
	if err := os.Chmod(projectState, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupProjectState(projectID); err == nil {
		t.Fatal("unsafe Project state directory was accepted")
	}
	if err := os.RemoveAll(projectState); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, projectState); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupProjectState(projectID); err == nil {
		t.Fatal("symlink Project state directory was accepted")
	}
}
