package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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
