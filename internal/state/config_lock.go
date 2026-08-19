package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"golang.org/x/sys/unix"
)

var configProjectIDPattern = regexp.MustCompile(`^[0-9a-f]{12}$`)

type ConfigLock struct {
	file     *os.File
	close    sync.Once
	closeErr error
}

// AcquireConfigLock serializes host-only declarative/effective policy writers
// without taking the long-lived Project VM lock.
func (s *Store) AcquireConfigLock(projectID string) (*ConfigLock, error) {
	if s == nil || !filepath.IsAbs(s.Root) || !configProjectIDPattern.MatchString(projectID) {
		return nil, fmt.Errorf("state root or Project ID is invalid")
	}
	directory := filepath.Join(s.Root, "locks")
	if err := ensurePrivateLockDirectory(directory); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, projectID+".config.lock")
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open Project configuration lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	fail := func(cause error) (*ConfigLock, error) {
		if file != nil {
			_ = file.Close()
		} else {
			_ = unix.Close(fd)
		}
		return nil, cause
	}
	if file == nil {
		return fail(fmt.Errorf("open Project configuration lock file"))
	}
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != uint32(os.Geteuid()) {
		return fail(fmt.Errorf("Project configuration lock must be a regular file owned by the current user"))
	}
	if err := unix.Fchmod(fd, 0600); err != nil {
		return fail(fmt.Errorf("protect Project configuration lock: %w", err))
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return fail(fmt.Errorf("Project configuration is already being changed: %s", projectID))
		}
		return fail(fmt.Errorf("acquire Project configuration lock: %w", err))
	}
	return &ConfigLock{file: file}, nil
}

func (l *ConfigLock) Close() error {
	if l == nil {
		return nil
	}
	l.close.Do(func() {
		if l.file != nil {
			l.closeErr = l.file.Close()
		}
	})
	return l.closeErr
}
