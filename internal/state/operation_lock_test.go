package state

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestOperationLockAllowsReadersAndExcludesUpdates(t *testing.T) {
	store := &Store{Root: filepath.Join(t.TempDir(), "sunaba")}
	first, err := store.AcquireOperationReadLock()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := store.AcquireOperationReadLock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireOperationLock(); !errors.Is(err, ErrOperationLocked) {
		t.Fatalf("exclusive lock error=%v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	exclusive, err := store.AcquireOperationLock()
	if err != nil {
		t.Fatal(err)
	}
	defer exclusive.Close()
	if _, err := store.AcquireOperationReadLock(); !errors.Is(err, ErrOperationLocked) {
		t.Fatalf("shared lock while update is active error=%v", err)
	}
}
