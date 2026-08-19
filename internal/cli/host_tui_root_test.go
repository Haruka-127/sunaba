package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestHostTUISessionRootIsFreshVMBoundAndRemoved(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const vmID = "vm123456"
	const sessionID = "session123456"
	runtimeRoot := filepath.Join(base, "sunaba-vm-"+vmID)
	if err := os.Mkdir(runtimeRoot, 0700); err != nil {
		t.Fatal(err)
	}
	sessionRoot, err := createHostTUISessionRoot(runtimeRoot, vmID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if sessionRoot != filepath.Join(runtimeRoot, "sunaba-session-"+sessionID) {
		t.Fatalf("session root=%q", sessionRoot)
	}
	if info, err := os.Lstat(sessionRoot); err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatalf("session root info=%v error=%v", info, err)
	}
	if _, err := createHostTUISessionRoot(runtimeRoot, vmID, sessionID); err == nil {
		t.Fatal("an existing Host TUI session root was reused")
	}
	if err := removeHostTUISessionRoot(runtimeRoot, vmID, sessionID, sessionRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(sessionRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Host TUI session root remained: %v", err)
	}
}

func TestHostTUISessionRootRejectsIdentitySubstitution(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot := filepath.Join(base, "sunaba-vm-vm123456")
	if err := os.Mkdir(runtimeRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := createHostTUISessionRoot(runtimeRoot, "different-vm", "session123456"); err == nil {
		t.Fatal("a substituted VM identity was accepted")
	}
	if _, err := createHostTUISessionRoot(runtimeRoot, "vm123456", "../escape"); err == nil {
		t.Fatal("an unsafe Agent Session identity was accepted")
	}
}
