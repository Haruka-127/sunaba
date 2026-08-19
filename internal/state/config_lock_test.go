package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigLockSerializesWritersWithoutProjectLock(t *testing.T) {
	store := &Store{Root: filepath.Join(t.TempDir(), "state")}
	projectID := "0123456789ab"
	first, err := store.AcquireConfigLock(projectID)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := store.AcquireConfigLock(projectID); err == nil {
		t.Fatal("a concurrent configuration writer acquired the same lock")
	}
	projectRoot := filepath.Join(t.TempDir(), "project")
	if err := os.Mkdir(projectRoot, 0700); err != nil {
		t.Fatal(err)
	}
	project, err := store.AcquireProjectLock(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	project.Close()
}
