package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var ErrProjectLocked = errors.New("project lock is already held")

type ProjectLock struct {
	ProjectID   string
	ProjectRoot string
	Path        string

	file     *os.File
	close    sync.Once
	closeErr error
}

func (s *Store) AcquireProjectLock(projectPath string) (*ProjectLock, error) {
	if s == nil || !filepath.IsAbs(s.Root) {
		return nil, fmt.Errorf("state root must be absolute")
	}
	projectRoot, err := ResolveProjectPath(projectPath)
	if err != nil {
		return nil, err
	}
	projectID := ProjectID(projectRoot)
	lockDirectory := filepath.Join(s.Root, "locks")
	if err := ensurePrivateLockDirectory(lockDirectory); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(lockDirectory, projectID+".lock")
	fd, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open Project lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), lockPath)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open Project lock file")
	}
	fail := func(err error) (*ProjectLock, error) {
		_ = file.Close()
		return nil, err
	}
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return fail(fmt.Errorf("inspect Project lock: %w", err))
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != uint32(os.Geteuid()) {
		return fail(fmt.Errorf("Project lock must be a regular file owned by the current user"))
	}
	if err := unix.Fchmod(fd, 0600); err != nil {
		return fail(fmt.Errorf("protect Project lock: %w", err))
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return fail(fmt.Errorf("%w: %s", ErrProjectLocked, projectID))
		}
		return fail(fmt.Errorf("acquire Project lock: %w", err))
	}
	lock := &ProjectLock{ProjectID: projectID, ProjectRoot: projectRoot, Path: lockPath, file: file}
	if err := lock.writeOwnerRecord(); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return lock, nil
}

func ensurePrivateLockDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return fmt.Errorf("create Project lock directory: %w", err)
	}
	if err := os.Chmod(path, 0700); err != nil {
		return fmt.Errorf("protect Project lock directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("Project lock directory must be a mode 0700 directory")
	}
	return nil
}

func (l *ProjectLock) writeOwnerRecord() error {
	record := struct {
		ProjectID   string    `json:"project_id"`
		ProjectRoot string    `json:"project_root"`
		PID         int       `json:"pid"`
		AcquiredAt  time.Time `json:"acquired_at"`
	}{l.ProjectID, l.ProjectRoot, os.Getpid(), time.Now().UTC()}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := l.file.Truncate(0); err != nil {
		return fmt.Errorf("truncate Project lock record: %w", err)
	}
	if _, err := l.file.Seek(0, 0); err != nil {
		return fmt.Errorf("seek Project lock record: %w", err)
	}
	if _, err := l.file.Write(encoded); err != nil {
		return fmt.Errorf("write Project lock record: %w", err)
	}
	if err := l.file.Sync(); err != nil {
		return fmt.Errorf("sync Project lock record: %w", err)
	}
	return nil
}

func (l *ProjectLock) Close() error {
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
