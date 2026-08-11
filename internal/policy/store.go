package policy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const maxPolicyBytes = 1 << 20

type legacyPolicyV1 struct {
	SchemaVersion      int       `json:"schema_version"`
	ProjectID          string    `json:"project_id"`
	ProjectRoot        string    `json:"project_root"`
	Mode               string    `json:"mode"`
	ManifestSHA256     string    `json:"manifest_sha256"`
	OpenCode           string    `json:"opencode"`
	AppleContainer     string    `json:"apple_container"`
	AgentImage         string    `json:"agent_image"`
	CPUs               int       `json:"cpus"`
	Memory             string    `json:"memory"`
	DiskBytes          int64     `json:"disk_bytes"`
	SessionTTLSeconds  int64     `json:"session_ttl_seconds"`
	AllowedModels      []string  `json:"allowed_models"`
	WebOrigins         []string  `json:"web_origins"`
	AuditRetentionDays int       `json:"audit_retention_days"`
	CreatedAt          time.Time `json:"created_at"`
}

func LoadAndMigrate(path string, now time.Time) (ProjectPolicy, bool, error) {
	data, err := readPolicyFile(path)
	if err != nil {
		return ProjectPolicy{}, false, err
	}
	var envelope struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return ProjectPolicy{}, false, fmt.Errorf("decode policy schema: %w", err)
	}
	switch envelope.SchemaVersion {
	case CurrentSchemaVersion:
		var current ProjectPolicy
		if err := decodeStrict(data, &current); err != nil {
			return ProjectPolicy{}, false, err
		}
		return current, false, current.Validate()
	case 1:
		var legacy legacyPolicyV1
		if err := decodeStrict(data, &legacy); err != nil {
			return ProjectPolicy{}, false, err
		}
		migrated, err := migrateV1(legacy, now)
		if err != nil {
			return ProjectPolicy{}, false, err
		}
		if err := Save(path, migrated); err != nil {
			return ProjectPolicy{}, false, err
		}
		return migrated, true, nil
	default:
		return ProjectPolicy{}, false, fmt.Errorf("unsupported Project policy schema %d", envelope.SchemaVersion)
	}
}

func Save(path string, policy ProjectPolicy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("policy path must be absolute and clean")
	}
	parent := filepath.Dir(path)
	if err := ensurePrivatePolicyDirectory(parent); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	temporary := filepath.Join(parent, ".sunaba-policy-"+filepath.Base(path)+"-"+hex.EncodeToString(random)+".tmp")
	fd, err := unix.Open(temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(encoded); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		var stat unix.Stat_t
		if statErr := unix.Lstat(path, &stat); statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Uid != uint32(os.Geteuid()) {
			return fmt.Errorf("existing policy file is unsafe")
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	cleanup = false
	directory, err := os.Open(parent)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}

func readPolicyFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("policy path must be absolute and clean")
	}
	var stat unix.Stat_t
	info, err := os.Lstat(path)
	statErr := unix.Lstat(path, &stat)
	if err != nil || statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > maxPolicyBytes || stat.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("policy must be a bounded mode 0600 regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, maxPolicyBytes+1))
}

func decodeStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode Project policy: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("Project policy contains trailing data")
	}
	return nil
}

func migrateV1(legacy legacyPolicyV1, now time.Time) (ProjectPolicy, error) {
	if len(legacy.WebOrigins) != 0 {
		return ProjectPolicy{}, fmt.Errorf("legacy enabled Web policy requires an explicit blocklist refresh before migration")
	}
	policy := ProjectPolicy{
		SchemaVersion: CurrentSchemaVersion, ProjectID: legacy.ProjectID, ProjectRoot: legacy.ProjectRoot, Mode: legacy.Mode,
		Dependency: DependencyPolicy{ManifestSHA256: legacy.ManifestSHA256, OpenCode: legacy.OpenCode, AppleContainer: legacy.AppleContainer, AgentImage: legacy.AgentImage},
		Resources:  ResourcePolicy{CPUs: legacy.CPUs, Memory: legacy.Memory, DiskBytes: legacy.DiskBytes, ProcessMax: 512, FileSizeMax: legacy.DiskBytes, OpenFileMax: 4096},
		Session:    SessionPolicy{TTLSeconds: legacy.SessionTTLSeconds, IdleSeconds: min(legacy.SessionTTLSeconds, 900)},
		Model:      ModelPolicy{AllowedModels: legacy.AllowedModels, MaxRequests: 100, MaxConcurrent: 2, MaxRequestBytes: 4 << 20, MaxResponseBytes: 16 << 20},
		Git:        GitPolicy{PushApprovalRequired: true},
		Web:        WebPolicy{Enabled: false, MaxRequests: 500, MaxConcurrent: 4, MaxConnectSeconds: 120, MaxUploadBytes: 1 << 20, MaxDownloadBytes: 64 << 20, MaxTotalBytes: 256 << 20},
		Export:     ExportPolicy{MaxEntries: 100_000, MaxFileBytes: 128 << 20, MaxTotalBytes: 2 << 30},
		Audit:      AuditPolicy{RetentionDays: legacy.AuditRetentionDays}, ProtectedPaths: []string{".git"},
		CreatedAt: legacy.CreatedAt.UTC(), UpdatedAt: now.UTC(),
	}
	if policy.CreatedAt.IsZero() {
		return ProjectPolicy{}, fmt.Errorf("legacy policy creation time is required")
	}
	return policy, policy.Validate()
}

func ensurePrivatePolicyDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	var stat unix.Stat_t
	statErr := unix.Lstat(path, &stat)
	canonical, canonicalErr := filepath.EvalSymlinks(path)
	if err != nil || statErr != nil || canonicalErr != nil || canonical != path || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("policy directory must be mode 0700 and not a symlink")
	}
	return nil
}
