package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"golang.org/x/sys/unix"
)

var auditFilenamePattern = regexp.MustCompile(`^audit-([0-9]{8})\.jsonl$`)

func (r *Recorder) PruneProject(projectID string, retention time.Duration, now time.Time) (int, error) {
	if !auditFieldPattern.MatchString(projectID) || retention < 24*time.Hour || retention > 365*24*time.Hour || now.IsZero() {
		return 0, fmt.Errorf("audit retention must be between 1 and 365 days")
	}
	if err := r.ensureRoot(); err != nil {
		return 0, err
	}
	cutoff := now.UTC().Add(-retention).Format("20060102")
	projectPath := filepath.Join(r.Root, projectID)
	if _, err := os.Lstat(projectPath); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	if err := validatePrivateOwnedDirectory(projectPath); err != nil {
		return 0, err
	}
	entries, err := os.ReadDir(projectPath)
	if err != nil {
		return 0, err
	}
	removed := 0
	changed := false
	for _, entry := range entries {
		match := auditFilenamePattern.FindStringSubmatch(entry.Name())
		if match == nil {
			continue
		}
		if _, err := time.Parse("20060102", match[1]); err != nil {
			return removed, fmt.Errorf("audit log has an invalid date %q", entry.Name())
		}
		if match[1] >= cutoff {
			continue
		}
		path := filepath.Join(projectPath, entry.Name())
		if err := validatePrivateOwnedLog(path); err != nil {
			return removed, err
		}
		if err := os.Remove(path); err != nil {
			return removed, err
		}
		removed++
		changed = true
	}
	if changed {
		directory, err := os.Open(projectPath)
		if err != nil {
			return removed, err
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil || closeErr != nil {
			return removed, fmt.Errorf("durably prune audit directory")
		}
	}
	return removed, nil
}

func validatePrivateOwnedDirectory(path string) error {
	var stat unix.Stat_t
	info, err := os.Lstat(path)
	statErr := unix.Lstat(path, &stat)
	if err != nil || statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("audit project directory must be an owned mode 0700 directory")
	}
	return nil
}

func validatePrivateOwnedLog(path string) error {
	var stat unix.Stat_t
	info, err := os.Lstat(path)
	statErr := unix.Lstat(path, &stat)
	if err != nil || statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("audit log must be an owned mode 0600 regular file")
	}
	return nil
}
