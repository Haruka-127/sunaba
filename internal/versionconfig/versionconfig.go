// Package versionconfig manages sunaba's host-only dependency declaration and lock.
package versionconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"time"

	"sunaba/internal/dependency"
	"sunaba/internal/projectconfig"
	"sunaba/internal/securefs"
)

const (
	SchemaVersion = 1
	ConfigFile    = "versions.json"
	LockFile      = "versions.lock.json"
	maxFileBytes  = 1 << 20
)

var exactV1Pattern = regexp.MustCompile(`^1\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

type Store struct {
	Root string
}

type Selection struct {
	Strategy string `json:"strategy"`
	Value    string `json:"value"`
}

type Config struct {
	SchemaVersion int       `json:"schema_version"`
	OpenCode      Selection `json:"opencode"`
}

type Lock struct {
	SchemaVersion int                 `json:"schema_version"`
	Generation    uint64              `json:"generation"`
	ResolvedAt    time.Time           `json:"resolved_at"`
	Manifest      dependency.Manifest `json:"manifest"`
}

type Paths struct {
	Directory string
	Config    string
	Lock      string
}

func NewStore() (*Store, error) {
	configs, err := projectconfig.NewStore()
	if err != nil {
		return nil, err
	}
	return &Store{Root: configs.Root}, nil
}

func (s *Store) Paths() (Paths, error) {
	if s == nil || !filepath.IsAbs(s.Root) || filepath.Clean(s.Root) != s.Root {
		return Paths{}, fmt.Errorf("version configuration root must be absolute and clean")
	}
	return Paths{Directory: s.Root, Config: filepath.Join(s.Root, ConfigFile), Lock: filepath.Join(s.Root, LockFile)}, nil
}

func (s *Store) Init() error {
	if _, err := s.Paths(); err != nil {
		return err
	}
	return (&projectconfig.Store{Root: s.Root}).Init()
}

func BootstrapConfig() Config {
	return Config{SchemaVersion: SchemaVersion, OpenCode: Selection{Strategy: "exact", Value: dependency.OpenCodeVersion}}
}

// BootstrapLock is the deterministic source contract used before first apply.
func BootstrapLock() Lock {
	return Lock{
		SchemaVersion: SchemaVersion, Generation: 1,
		ResolvedAt: time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC),
		Manifest:   dependency.MustPinned(),
	}
}

func (c Config) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported version configuration schema %d", c.SchemaVersion)
	}
	switch c.OpenCode.Strategy {
	case "exact":
		if !exactV1Pattern.MatchString(c.OpenCode.Value) {
			return fmt.Errorf("OpenCode exact version %q must be a v1 semantic version", c.OpenCode.Value)
		}
	case "channel":
		if c.OpenCode.Value != "v1-stable" {
			return fmt.Errorf("unsupported OpenCode channel %q", c.OpenCode.Value)
		}
	default:
		return fmt.Errorf("OpenCode strategy must be exact or channel")
	}
	return nil
}

func (l Lock) Validate() error {
	if l.SchemaVersion != SchemaVersion || l.Generation == 0 || l.ResolvedAt.IsZero() || l.ResolvedAt.Location() != time.UTC {
		return fmt.Errorf("version lock metadata is invalid")
	}
	if err := dependency.ValidateRuntimeManifest(l.Manifest); err != nil {
		return fmt.Errorf("version lock manifest: %w", err)
	}
	return nil
}

func ConfigDigest(config Config) (string, error) {
	if err := config.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func LockDigest(lock Lock) (string, error) {
	if err := lock.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(lock)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (s *Store) LoadConfig() (Config, error) {
	var config Config
	paths, err := s.Paths()
	if err != nil {
		return config, err
	}
	if err := load(paths.Config, &config); err != nil {
		return config, err
	}
	return config, config.Validate()
}

func (s *Store) SaveConfig(config Config) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if err := s.Init(); err != nil {
		return err
	}
	paths, _ := s.Paths()
	return save(paths.Config, config)
}

func (s *Store) LoadLock() (Lock, error) {
	var lock Lock
	paths, err := s.Paths()
	if err != nil {
		return lock, err
	}
	if err := load(paths.Lock, &lock); err != nil {
		return lock, err
	}
	return lock, lock.Validate()
}

func (s *Store) SaveLock(lock Lock) error {
	if err := lock.Validate(); err != nil {
		return err
	}
	if err := s.Init(); err != nil {
		return err
	}
	paths, _ := s.Paths()
	return save(paths.Lock, lock)
}

func load(path string, target any) error {
	data, err := securefs.ReadOwnedRegular(path, maxFileBytes)
	if err != nil {
		return err
	}
	if err := securefs.DecodeStrictJSON(data, target); err != nil {
		return fmt.Errorf("decode %s: %w", filepath.Base(path), err)
	}
	return nil
}

func save(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxFileBytes {
		return fmt.Errorf("version file exceeds its size bound")
	}
	return securefs.AtomicWriteOwned(path, encoded)
}
