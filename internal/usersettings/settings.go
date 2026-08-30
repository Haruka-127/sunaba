// Package usersettings manages sunaba's global, non-secret user settings.
package usersettings

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
	"sunaba/internal/modelcatalog"
	"sunaba/internal/projectconfig"
	"sunaba/internal/securefs"
)

const (
	SchemaVersion = 1
	SettingsFile  = "settings.json"
	LockFile      = "settings.lock"
	maxFileBytes  = 64 << 10
)

type Settings struct {
	SchemaVersion int                   `json:"schema_version"`
	ModelAuth     modelcatalog.AuthMode `json:"model_auth"`
}

type Store struct {
	Root string
}

type Paths struct {
	Directory string
	Settings  string
	Lock      string
}

type lock struct {
	file     *os.File
	close    sync.Once
	closeErr error
}

func NewStore() (*Store, error) {
	projects, err := projectconfig.NewStore()
	if err != nil {
		return nil, err
	}
	return &Store{Root: projects.Root}, nil
}

func Default() Settings {
	return Settings{SchemaVersion: SchemaVersion, ModelAuth: modelcatalog.AuthOAuth}
}

func (s Settings) Validate() error {
	if s.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported global settings schema %d", s.SchemaVersion)
	}
	if err := modelcatalog.ValidateAuthMode(s.ModelAuth); err != nil {
		return fmt.Errorf("global Model authentication setting is invalid: %w", err)
	}
	return nil
}

func (s *Store) Paths() (Paths, error) {
	if s == nil || !filepath.IsAbs(s.Root) || filepath.Clean(s.Root) != s.Root {
		return Paths{}, fmt.Errorf("global settings root must be absolute and clean")
	}
	return Paths{Directory: s.Root, Settings: filepath.Join(s.Root, SettingsFile), Lock: filepath.Join(s.Root, LockFile)}, nil
}

// Load returns the OAuth default when settings.json has not been created yet.
// An existing unsafe or malformed store is always rejected instead of falling
// back to defaults.
func (s *Store) Load() (Settings, error) {
	paths, err := s.Paths()
	if err != nil {
		return Settings{}, err
	}
	if _, err := os.Lstat(paths.Directory); errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	} else if err != nil {
		return Settings{}, err
	}
	if err := securefs.CheckCanonicalOwnedDir(paths.Directory); err != nil {
		return Settings{}, fmt.Errorf("global settings directory is unsafe: %w", err)
	}
	data, err := securefs.ReadOwnedRegular(paths.Settings, maxFileBytes)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("read global settings: %w", err)
	}
	var settings Settings
	if err := securefs.DecodeStrictJSON(data, &settings); err != nil {
		return Settings{}, fmt.Errorf("decode global settings: %w", err)
	}
	return settings, settings.Validate()
}

func (s *Store) Save(settings Settings) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	paths, err := s.Paths()
	if err != nil {
		return err
	}
	if err := (&projectconfig.Store{Root: s.Root}).Init(); err != nil {
		return fmt.Errorf("initialize global settings directory: %w", err)
	}
	guard, err := acquireLock(paths.Lock)
	if err != nil {
		return err
	}
	defer guard.Close()
	if _, err := os.Lstat(paths.Settings); err == nil {
		if _, err := s.Load(); err != nil {
			return fmt.Errorf("refusing to replace invalid global settings: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	encoded, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxFileBytes {
		return fmt.Errorf("global settings exceed their size bound")
	}
	if err := securefs.AtomicWriteOwned(paths.Settings, encoded); err != nil {
		return fmt.Errorf("write global settings: %w", err)
	}
	return nil
}

func (s *Store) SetModelAuth(mode modelcatalog.AuthMode) error {
	settings := Default()
	settings.ModelAuth = mode
	return s.Save(settings)
}

func acquireLock(path string) (*lock, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open global settings lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	fail := func(cause error) (*lock, error) {
		if file != nil {
			_ = file.Close()
		} else {
			_ = unix.Close(fd)
		}
		return nil, cause
	}
	if file == nil {
		return fail(fmt.Errorf("open global settings lock file"))
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return fail(fmt.Errorf("global settings lock must be a current-user owned mode 0600 regular file without hard links"))
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		return fail(fmt.Errorf("lock global settings: %w", err))
	}
	return &lock{file: file}, nil
}

func (l *lock) Close() error {
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
