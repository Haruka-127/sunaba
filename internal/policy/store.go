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
	"sunaba/internal/modelcatalog"
	"sunaba/internal/modelgateway"
	"sunaba/internal/webgateway"
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

type legacyPolicyV2 struct {
	SchemaVersion  int              `json:"schema_version"`
	ProjectID      string           `json:"project_id"`
	ProjectRoot    string           `json:"project_root"`
	Mode           string           `json:"mode"`
	Dependency     DependencyPolicy `json:"dependency"`
	Resources      ResourcePolicy   `json:"resources"`
	Session        SessionPolicy    `json:"session"`
	Model          ModelPolicy      `json:"model"`
	Git            legacyGitV2      `json:"git"`
	Web            WebPolicy        `json:"web"`
	Export         ExportPolicy     `json:"export"`
	Audit          AuditPolicy      `json:"audit"`
	ProtectedPaths []string         `json:"protected_paths"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
}

type legacyPolicyV3 ProjectPolicy
type legacyPolicyV4 ProjectPolicy

type legacyPolicyV5 struct {
	SchemaVersion  int              `json:"schema_version"`
	ProjectID      string           `json:"project_id"`
	ProjectRoot    string           `json:"project_root"`
	Mode           string           `json:"mode"`
	Dependency     DependencyPolicy `json:"dependency"`
	Resources      ResourcePolicy   `json:"resources"`
	Session        SessionPolicy    `json:"session"`
	Model          ModelPolicy      `json:"model"`
	Git            GitPolicy        `json:"git"`
	Web            legacyWebPolicy  `json:"web"`
	Export         ExportPolicy     `json:"export"`
	Audit          AuditPolicy      `json:"audit"`
	ProtectedPaths []string         `json:"protected_paths"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
}

type legacyWebPolicy struct {
	Enabled           bool                    `json:"enabled"`
	Rules             []webgateway.OriginRule `json:"rules"`
	BlocklistManifest string                  `json:"blocklist_manifest,omitempty"`
	BlocklistSHA256   string                  `json:"blocklist_sha256,omitempty"`
	MaxRequests       int                     `json:"max_requests"`
	MaxConcurrent     int                     `json:"max_concurrent"`
	MaxConnectSeconds int64                   `json:"max_connect_seconds"`
	MaxUploadBytes    int64                   `json:"max_upload_bytes"`
	MaxDownloadBytes  int64                   `json:"max_download_bytes"`
	MaxTotalBytes     int64                   `json:"max_total_bytes"`
}

type legacyGitV2 struct {
	Remotes              []string `json:"remotes"`
	PushApprovalRequired bool     `json:"push_approval_required"`
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
	case 5:
		var legacy legacyPolicyV5
		if err := decodeStrict(data, &legacy); err != nil {
			return ProjectPolicy{}, false, err
		}
		migrated, err := migrateV5(legacy, now)
		if err != nil {
			return ProjectPolicy{}, false, err
		}
		if err := Save(path, migrated); err != nil {
			return ProjectPolicy{}, false, err
		}
		return migrated, true, nil
	case 4:
		var legacy legacyPolicyV4
		if err := decodeStrict(data, &legacy); err != nil {
			return ProjectPolicy{}, false, err
		}
		migrated, err := migrateV4(legacy, now)
		if err != nil {
			return ProjectPolicy{}, false, err
		}
		if err := Save(path, migrated); err != nil {
			return ProjectPolicy{}, false, err
		}
		return migrated, true, nil
	case 3:
		var legacy legacyPolicyV3
		if err := decodeStrict(data, &legacy); err != nil {
			return ProjectPolicy{}, false, err
		}
		migrated, err := migrateV3(legacy, now)
		if err != nil {
			return ProjectPolicy{}, false, err
		}
		if err := Save(path, migrated); err != nil {
			return ProjectPolicy{}, false, err
		}
		return migrated, true, nil
	case 2:
		var legacy legacyPolicyV2
		if err := decodeStrict(data, &legacy); err != nil {
			return ProjectPolicy{}, false, err
		}
		migrated, err := migrateV2(legacy, now)
		if err != nil {
			return ProjectPolicy{}, false, err
		}
		if err := Save(path, migrated); err != nil {
			return ProjectPolicy{}, false, err
		}
		return migrated, true, nil
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

func migrateV5(legacy legacyPolicyV5, now time.Time) (ProjectPolicy, error) {
	policy := ProjectPolicy{
		SchemaVersion: CurrentSchemaVersion, ProjectID: legacy.ProjectID, ProjectRoot: legacy.ProjectRoot, Mode: legacy.Mode,
		Dependency: legacy.Dependency, Resources: legacy.Resources, Session: legacy.Session, Model: legacy.Model, Git: legacy.Git,
		Web: WebPolicy{
			Enabled: legacy.Web.Enabled, Rules: append([]webgateway.OriginRule(nil), legacy.Web.Rules...),
			BlocklistManifest: legacy.Web.BlocklistManifest, BlocklistSHA256: legacy.Web.BlocklistSHA256,
			MaxRequests: legacy.Web.MaxRequests, MaxConcurrent: legacy.Web.MaxConcurrent, MaxConnectSeconds: legacy.Web.MaxConnectSeconds,
			MaxUploadBytes: legacy.Web.MaxUploadBytes, MaxDownloadBytes: legacy.Web.MaxDownloadBytes, MaxTotalBytes: legacy.Web.MaxTotalBytes,
		},
		Export: legacy.Export, Audit: legacy.Audit, ProtectedPaths: legacy.ProtectedPaths,
		CreatedAt: legacy.CreatedAt.UTC(), UpdatedAt: now.UTC(),
	}
	migrateLegacyWebSelection(&policy.Web)
	return policy, policy.Validate()
}

func migrateV3(legacy legacyPolicyV3, now time.Time) (ProjectPolicy, error) {
	policy := ProjectPolicy(legacy)
	policy.SchemaVersion = CurrentSchemaVersion
	setLegacyAuthenticationDefault(&policy.Model)
	upgradeLegacyModelDefaults(&policy.Model)
	migrateLegacyWebSelection(&policy.Web)
	policy.UpdatedAt = now.UTC()
	return policy, policy.Validate()
}

func migrateV4(legacy legacyPolicyV4, now time.Time) (ProjectPolicy, error) {
	policy := ProjectPolicy(legacy)
	policy.SchemaVersion = CurrentSchemaVersion
	setLegacyAuthenticationDefault(&policy.Model)
	migrateLegacyWebSelection(&policy.Web)
	policy.UpdatedAt = now.UTC()
	return policy, policy.Validate()
}

func setLegacyAuthenticationDefault(model *ModelPolicy) {
	if model.AuthMode == "" {
		model.AuthMode = modelcatalog.AuthAPIKey
	}
}

func upgradeLegacyModelDefaults(model *ModelPolicy) {
	if model.MaxRequests != 100 || model.MaxConcurrent != 2 || model.MaxRequestBytes != 4<<20 || model.MaxResponseBytes != 16<<20 {
		return
	}
	model.MaxRequests = modelgateway.DefaultMaxRequests
	model.MaxConcurrent = modelgateway.DefaultMaxConcurrent
	model.MaxRequestBytes = modelgateway.DefaultMaxRequestBytes
	model.MaxResponseBytes = modelgateway.DefaultMaxResponseBytes
}

func migrateLegacyWebSelection(web *WebPolicy) {
	if len(web.OriginPresets) != 0 || web.OriginPresetSHA256 != "" || len(web.CustomRules) != 0 {
		return
	}
	web.CustomRules = append([]webgateway.OriginRule(nil), web.Rules...)
	for index := range web.CustomRules {
		web.CustomRules[index].Category = "user"
	}
	if web.Enabled {
		web.Rules = append([]webgateway.OriginRule(nil), web.CustomRules...)
	}
}

func migrateV2(legacy legacyPolicyV2, now time.Time) (ProjectPolicy, error) {
	remotes := make([]GitRemotePolicy, 0, len(legacy.Git.Remotes))
	for index, remoteURL := range legacy.Git.Remotes {
		name := "origin"
		if index > 0 {
			name = fmt.Sprintf("remote-%d", index+1)
		}
		remotes = append(remotes, GitRemotePolicy{Name: name, URL: remoteURL})
	}
	policy := ProjectPolicy{
		SchemaVersion: CurrentSchemaVersion, ProjectID: legacy.ProjectID, ProjectRoot: legacy.ProjectRoot, Mode: legacy.Mode,
		Dependency: legacy.Dependency, Resources: legacy.Resources, Session: legacy.Session, Model: legacy.Model,
		Git: GitPolicy{Remotes: remotes, PushApprovalRequired: legacy.Git.PushApprovalRequired},
		Web: legacy.Web, Export: legacy.Export, Audit: legacy.Audit, ProtectedPaths: legacy.ProtectedPaths,
		CreatedAt: legacy.CreatedAt.UTC(), UpdatedAt: now.UTC(),
	}
	setLegacyAuthenticationDefault(&policy.Model)
	upgradeLegacyModelDefaults(&policy.Model)
	migrateLegacyWebSelection(&policy.Web)
	return policy, policy.Validate()
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
		Model: ModelPolicy{
			AuthMode: modelcatalog.AuthAPIKey, AllowedModels: legacy.AllowedModels, MaxRequests: modelgateway.DefaultMaxRequests,
			MaxConcurrent: modelgateway.DefaultMaxConcurrent, MaxRequestBytes: modelgateway.DefaultMaxRequestBytes,
			MaxResponseBytes: modelgateway.DefaultMaxResponseBytes,
		},
		Git:    GitPolicy{PushApprovalRequired: true},
		Web:    WebPolicy{Enabled: false, MaxRequests: 500, MaxConcurrent: 4, MaxConnectSeconds: 120, MaxUploadBytes: 1 << 20, MaxDownloadBytes: 64 << 20, MaxTotalBytes: 256 << 20},
		Export: ExportPolicy{MaxEntries: 100_000, MaxFileBytes: 128 << 20, MaxTotalBytes: 2 << 30},
		Audit:  AuditPolicy{RetentionDays: legacy.AuditRetentionDays}, ProtectedPaths: []string{".git"},
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
