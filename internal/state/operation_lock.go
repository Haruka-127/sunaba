package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

var ErrOperationLocked = errors.New("global sunaba operation lock is already held")

type OperationLock struct {
	file     *os.File
	close    sync.Once
	closeErr error
}

func (s *Store) AcquireOperationLock() (*OperationLock, error) {
	return s.acquireOperationLock(unix.LOCK_EX)
}

// AcquireOperationReadLock prevents setup/update transactions while allowing
// independent Project operations to proceed concurrently.
func (s *Store) AcquireOperationReadLock() (*OperationLock, error) {
	return s.acquireOperationLock(unix.LOCK_SH)
}

func (s *Store) acquireOperationLock(mode int) (*OperationLock, error) {
	if err := s.Init(); err != nil {
		return nil, err
	}
	directory := filepath.Join(s.Root, "locks")
	if err := ensurePrivateLockDirectory(directory); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, "global-operation.lock")
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open global operation lock")
	}
	fail := func(cause error) (*OperationLock, error) { _ = file.Close(); return nil, cause }
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) {
		return fail(fmt.Errorf("global operation lock must be a regular file owned by the current user"))
	}
	if err := unix.Fchmod(fd, 0600); err != nil {
		return fail(err)
	}
	if err := unix.Flock(fd, mode|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return fail(ErrOperationLocked)
		}
		return fail(err)
	}
	return &OperationLock{file: file}, nil
}

func (l *OperationLock) Close() error {
	if l == nil {
		return nil
	}
	l.close.Do(func() { l.closeErr = l.file.Close() })
	return l.closeErr
}
