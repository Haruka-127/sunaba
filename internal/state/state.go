package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"sunaba/internal/dependency"
	"sunaba/internal/securefs"
)

type Store struct {
	Root string
}

type GlobalConfig struct {
	SchemaVersion int                `json:"schema_version,omitempty"`
	Active        *DependencyBinding `json:"active_dependency,omitempty"`
	// ImageVersion is accepted only to recognize the pre-setup state format.
	ImageVersion string `json:"image_version,omitempty"`
}

type DependencyBinding struct {
	Generation            uint64 `json:"generation"`
	ManifestSHA256        string `json:"manifest_sha256"`
	OpenCodeVersion       string `json:"opencode_version"`
	AppleContainerVersion string `json:"apple_container_version"`
	AgentImage            string `json:"agent_image"`
}

func NewDependencyBinding(generation uint64, manifest dependency.Manifest) (DependencyBinding, error) {
	digest, err := dependency.ManifestDigest(manifest)
	if err != nil {
		return DependencyBinding{}, err
	}
	binding := DependencyBinding{
		Generation: generation, ManifestSHA256: digest, OpenCodeVersion: manifest.OpenCode.Version,
		AppleContainerVersion: manifest.AppleContainer.Version, AgentImage: manifest.AgentImage.Tag,
	}
	return binding, binding.Validate()
}

func (b DependencyBinding) Validate() error {
	if b.Generation == 0 || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(b.ManifestSHA256) ||
		!regexp.MustCompile(`^1\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`).MatchString(b.OpenCodeVersion) || b.AppleContainerVersion == "" || b.AgentImage != "sunaba-base:"+b.OpenCodeVersion+"-secure.1" {
		return fmt.Errorf("active dependency binding is invalid")
	}
	return nil
}

func (c GlobalConfig) Validate() error {
	if c.SchemaVersion != 2 || c.Active == nil || c.ImageVersion != "" {
		return fmt.Errorf("global state is not an active schema v2 dependency binding")
	}
	return c.Active.Validate()
}

func NewStore() (*Store, error) {
	root := os.Getenv("XDG_DATA_HOME")
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		root = filepath.Join(home, ".local", "share")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return &Store{Root: filepath.Join(filepath.Clean(root), "sunaba")}, nil
}

func ResolveProjectPath(path string) (string, error) {
	if path == "" {
		path = "."
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("cannot resolve project path %s: %w", abs, err)
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", real)
	}
	return real, nil
}

func ProjectID(path string) string {
	digest := sha256.Sum256([]byte(path))
	return hex.EncodeToString(digest[:])[:12]
}

func (s *Store) Init() error {
	if s == nil || !filepath.IsAbs(s.Root) || filepath.Clean(s.Root) != s.Root {
		return fmt.Errorf("state root must be absolute and clean")
	}
	if err := ensurePrivateStateDirectory(s.Root); err != nil {
		return err
	}
	return ensurePrivateStateDirectory(filepath.Join(s.Root, "projects"))
}

func (s *Store) LoadGlobal() (GlobalConfig, error) {
	var config GlobalConfig
	data, err := readPrivateStateFile(filepath.Join(s.Root, "config.json"), 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return config, nil
	}
	if err != nil {
		return config, err
	}
	if err := securefs.DecodeStrictJSON(data, &config); err != nil {
		return config, fmt.Errorf("decode global state: %w", err)
	}
	return config, nil
}

func (s *Store) SaveGlobal(config GlobalConfig) error {
	if err := s.Init(); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return writePrivateStateFile(filepath.Join(s.Root, "config.json"), encoded)
}

func (s *Store) LoadActiveDependency() (DependencyBinding, error) {
	config, err := s.LoadGlobal()
	if err != nil {
		return DependencyBinding{}, err
	}
	if err := config.Validate(); err != nil {
		if config.ImageVersion != "" {
			return DependencyBinding{}, fmt.Errorf("sunaba setup is required to migrate legacy OpenCode %s state", config.ImageVersion)
		}
		return DependencyBinding{}, fmt.Errorf("sunaba setup has not completed: %w", err)
	}
	return *config.Active, nil
}

func (s *Store) SaveActiveDependency(binding DependencyBinding) error {
	if err := binding.Validate(); err != nil {
		return err
	}
	return s.SaveGlobal(GlobalConfig{SchemaVersion: 2, Active: &binding})
}

func ensurePrivateStateDirectory(path string) error {
	return securefs.EnsureOwnedDir(path)
}

func readPrivateStateFile(path string, maximum int64) ([]byte, error) {
	return securefs.ReadOwnedRegular(path, maximum)
}

func writePrivateStateFile(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := ensurePrivateStateDirectory(directory); err != nil {
		return err
	}
	return securefs.AtomicWriteOwned(path, data)
}
