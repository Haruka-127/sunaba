package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"sunaba/internal/securefs"
)

var hostTUIIdentityPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{5,63}$`)

func createHostTUISessionRoot(runtimeRoot, vmID, sessionID string) (string, error) {
	if !filepath.IsAbs(runtimeRoot) || filepath.Clean(runtimeRoot) != runtimeRoot || !hostTUIIdentityPattern.MatchString(vmID) || !hostTUIIdentityPattern.MatchString(sessionID) || vmID == sessionID {
		return "", fmt.Errorf("Host TUI runtime identity is invalid")
	}
	if filepath.Base(runtimeRoot) != "sunaba-vm-"+vmID {
		return "", fmt.Errorf("Host TUI runtime root does not match the Project VM")
	}
	if err := securefs.CheckCanonicalOwnedDir(runtimeRoot); err != nil {
		return "", fmt.Errorf("Host TUI runtime root is unsafe: %w", err)
	}
	sessionRoot := filepath.Join(runtimeRoot, "sunaba-session-"+sessionID)
	if err := os.Mkdir(sessionRoot, 0700); err != nil {
		return "", fmt.Errorf("create Host TUI session root: %w", err)
	}
	if err := os.Chmod(sessionRoot, 0700); err != nil {
		_ = os.Remove(sessionRoot)
		return "", fmt.Errorf("protect Host TUI session root: %w", err)
	}
	if err := securefs.CheckCanonicalOwnedDir(sessionRoot); err != nil {
		_ = os.Remove(sessionRoot)
		return "", fmt.Errorf("Host TUI session root is unsafe: %w", err)
	}
	return sessionRoot, nil
}

func removeHostTUISessionRoot(runtimeRoot, vmID, sessionID, sessionRoot string) error {
	expected := filepath.Join(runtimeRoot, "sunaba-session-"+sessionID)
	if !filepath.IsAbs(runtimeRoot) || filepath.Base(runtimeRoot) != "sunaba-vm-"+vmID || sessionRoot != expected {
		return fmt.Errorf("refusing to remove an unbound Host TUI session root")
	}
	if _, err := os.Lstat(sessionRoot); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if err := securefs.CheckCanonicalOwnedDir(sessionRoot); err != nil {
		return fmt.Errorf("refusing to remove an unsafe Host TUI session root: %w", err)
	}
	return os.RemoveAll(sessionRoot)
}
