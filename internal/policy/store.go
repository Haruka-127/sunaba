package policy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"sunaba/internal/modelcatalog"
	"sunaba/internal/modelgateway"
	"sunaba/internal/securefs"
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
	SchemaVersion  int               `json:"schema_version"`
	ProjectID      string            `json:"project_id"`
	ProjectRoot    string            `json:"project_root"`
	Mode           string            `json:"mode"`
	Dependency     DependencyPolicy  `json:"dependency"`
	Resources      ResourcePolicy    `json:"resources"`
	Session        SessionPolicy     `json:"session"`
	Model          legacyModelPolicy `json:"model"`
	Git            legacyGitV2       `json:"git"`
	Web            WebPolicy         `json:"web"`
	Export         ExportPolicy      `json:"export"`
	Audit          AuditPolicy       `json:"audit"`
	ProtectedPaths []string          `json:"protected_paths"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

type legacyPolicyV3 legacyProjectPolicy
type legacyPolicyV4 legacyProjectPolicy
type legacyPolicyV6 legacyProjectPolicy
type legacyPolicyV7 legacyProjectPolicy

type legacyModelPolicy struct {
	AuthMode         modelcatalog.AuthMode `json:"auth,omitempty"`
	AllowedModels    []string              `json:"allowed_models"`
	MaxRequests      int                   `json:"max_requests"`
	MaxConcurrent    int                   `json:"max_concurrent"`
	MaxRequestBytes  int64                 `json:"max_request_bytes"`
	MaxResponseBytes int64                 `json:"max_response_bytes"`
}

type legacyProjectPolicy struct {
	SchemaVersion  int               `json:"schema_version"`
	ProjectID      string            `json:"project_id"`
	ProjectRoot    string            `json:"project_root"`
	Mode           string            `json:"mode"`
	Dependency     DependencyPolicy  `json:"dependency"`
	Resources      ResourcePolicy    `json:"resources"`
	Session        SessionPolicy     `json:"session"`
	Model          legacyModelPolicy `json:"model"`
	Git            GitPolicy         `json:"git"`
	Web            WebPolicy         `json:"web"`
	Export         ExportPolicy      `json:"export"`
	Snapshot       SnapshotPolicy    `json:"snapshot"`
	Audit          AuditPolicy       `json:"audit"`
	ProtectedPaths []string          `json:"protected_paths"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

type legacyPolicyV5 struct {
	SchemaVersion  int               `json:"schema_version"`
	ProjectID      string            `json:"project_id"`
	ProjectRoot    string            `json:"project_root"`
	Mode           string            `json:"mode"`
	Dependency     DependencyPolicy  `json:"dependency"`
	Resources      ResourcePolicy    `json:"resources"`
	Session        SessionPolicy     `json:"session"`
	Model          legacyModelPolicy `json:"model"`
	Git            GitPolicy         `json:"git"`
	Web            legacyWebPolicy   `json:"web"`
	Export         ExportPolicy      `json:"export"`
	Audit          AuditPolicy       `json:"audit"`
	ProtectedPaths []string          `json:"protected_paths"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
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
	loaded, migrated, err := LoadReadOnly(path, now)
	if err != nil {
		return ProjectPolicy{}, false, err
	}
	if migrated {
		if err := Save(path, loaded); err != nil {
			return ProjectPolicy{}, false, err
		}
	}
	return loaded, migrated, nil
}

// LoadReadOnly validates and, when necessary, migrates a Project policy in
// memory without modifying its state file. Inventory and diagnostic commands
// use this path so observation never changes Project state.
func LoadReadOnly(path string, now time.Time) (ProjectPolicy, bool, error) {
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
	case 7:
		var legacy legacyPolicyV7
		if err := decodeStrict(data, &legacy); err != nil {
			return ProjectPolicy{}, false, err
		}
		if err := modelcatalog.ValidateAuthMode(legacy.Model.AuthMode); err != nil {
			return ProjectPolicy{}, false, fmt.Errorf("legacy Project policy authentication is invalid: %w", err)
		}
		migrated := fromLegacyProject(legacyProjectPolicy(legacy))
		migrated.SchemaVersion = CurrentSchemaVersion
		return migrated, true, migrated.Validate()
	case 5:
		var legacy legacyPolicyV5
		if err := decodeStrict(data, &legacy); err != nil {
			return ProjectPolicy{}, false, err
		}
		migrated, err := migrateV5(legacy, now)
		if err != nil {
			return ProjectPolicy{}, false, err
		}
		return migrated, true, nil
	case 6:
		var legacy legacyPolicyV6
		if err := decodeStrict(data, &legacy); err != nil {
			return ProjectPolicy{}, false, err
		}
		migrated, err := migrateV6(legacy, now)
		if err != nil {
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
		return migrated, true, nil
	default:
		return ProjectPolicy{}, false, fmt.Errorf("unsupported Project policy schema %d", envelope.SchemaVersion)
	}
}

func migrateV6(legacy legacyPolicyV6, now time.Time) (ProjectPolicy, error) {
	result := fromLegacyProject(legacyProjectPolicy(legacy))
	result.SchemaVersion = CurrentSchemaVersion
	result.Snapshot = SnapshotPolicy{}
	result.UpdatedAt = now.UTC()
	return result, result.Validate()
}

func migrateV5(legacy legacyPolicyV5, now time.Time) (ProjectPolicy, error) {
	policy := ProjectPolicy{
		SchemaVersion: CurrentSchemaVersion, ProjectID: legacy.ProjectID, ProjectRoot: legacy.ProjectRoot, Mode: legacy.Mode,
		Dependency: legacy.Dependency, Resources: legacy.Resources, Session: legacy.Session, Model: modelWithoutAuth(legacy.Model), Git: legacy.Git,
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
	policy := fromLegacyProject(legacyProjectPolicy(legacy))
	policy.SchemaVersion = CurrentSchemaVersion
	upgradeLegacyModelDefaults(&policy.Model)
	migrateLegacyWebSelection(&policy.Web)
	policy.UpdatedAt = now.UTC()
	return policy, policy.Validate()
}

func migrateV4(legacy legacyPolicyV4, now time.Time) (ProjectPolicy, error) {
	policy := fromLegacyProject(legacyProjectPolicy(legacy))
	policy.SchemaVersion = CurrentSchemaVersion
	migrateLegacyWebSelection(&policy.Web)
	policy.UpdatedAt = now.UTC()
	return policy, policy.Validate()
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
		Dependency: legacy.Dependency, Resources: legacy.Resources, Session: legacy.Session, Model: modelWithoutAuth(legacy.Model),
		Git: GitPolicy{Remotes: remotes, PushApprovalRequired: legacy.Git.PushApprovalRequired},
		Web: legacy.Web, Export: legacy.Export, Audit: legacy.Audit, ProtectedPaths: legacy.ProtectedPaths,
		CreatedAt: legacy.CreatedAt.UTC(), UpdatedAt: now.UTC(),
	}
	upgradeLegacyModelDefaults(&policy.Model)
	migrateLegacyWebSelection(&policy.Web)
	return policy, policy.Validate()
}

func modelWithoutAuth(legacy legacyModelPolicy) ModelPolicy {
	return ModelPolicy{
		AllowedModels: append([]string(nil), legacy.AllowedModels...), MaxRequests: legacy.MaxRequests,
		MaxConcurrent: legacy.MaxConcurrent, MaxRequestBytes: legacy.MaxRequestBytes,
		MaxResponseBytes: legacy.MaxResponseBytes,
	}
}

func fromLegacyProject(legacy legacyProjectPolicy) ProjectPolicy {
	return ProjectPolicy{
		SchemaVersion: legacy.SchemaVersion, ProjectID: legacy.ProjectID, ProjectRoot: legacy.ProjectRoot, Mode: legacy.Mode,
		Dependency: legacy.Dependency, Resources: legacy.Resources, Session: legacy.Session, Model: modelWithoutAuth(legacy.Model),
		Git: legacy.Git, Web: legacy.Web, Export: legacy.Export, Snapshot: legacy.Snapshot, Audit: legacy.Audit,
		ProtectedPaths: append([]string(nil), legacy.ProtectedPaths...), CreatedAt: legacy.CreatedAt, UpdatedAt: legacy.UpdatedAt,
	}
}

func Save(path string, policy ProjectPolicy) error {
	replacement, err := PrepareReplacement(path, policy)
	if err != nil {
		return err
	}
	return securefs.AtomicWriteOwned(replacement.Path, replacement.Data)
}

func PrepareReplacement(path string, policy ProjectPolicy) (securefs.Replacement, error) {
	if err := policy.Validate(); err != nil {
		return securefs.Replacement{}, err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return securefs.Replacement{}, fmt.Errorf("policy path must be absolute and clean")
	}
	parent := filepath.Dir(path)
	if err := ensurePrivatePolicyDirectory(parent); err != nil {
		return securefs.Replacement{}, err
	}
	encoded, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return securefs.Replacement{}, err
	}
	encoded = append(encoded, '\n')
	return securefs.Replacement{Path: path, Data: encoded, MaximumBytes: maxPolicyBytes}, nil
}

func readPolicyFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("policy path must be absolute and clean")
	}
	data, err := securefs.ReadOwnedRegular(path, maxPolicyBytes)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("policy must not be empty")
	}
	return data, nil
}

func decodeStrict(data []byte, destination any) error {
	if err := securefs.DecodeStrictJSON(data, destination); err != nil {
		return fmt.Errorf("decode Project policy: %w", err)
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
			AllowedModels: legacy.AllowedModels, MaxRequests: modelgateway.DefaultMaxRequests,
			MaxConcurrent: modelgateway.DefaultMaxConcurrent, MaxRequestBytes: modelgateway.DefaultMaxRequestBytes,
			MaxResponseBytes: modelgateway.DefaultMaxResponseBytes,
		},
		Git: GitPolicy{PushApprovalRequired: true},
		Web: WebPolicy{
			Enabled: false, MaxRequests: webgateway.DefaultMaxRequests, MaxConcurrent: webgateway.DefaultMaxConcurrent,
			MaxConnectSeconds: int64(webgateway.DefaultMaxConnectTime / time.Second), MaxUploadBytes: webgateway.DefaultMaxUploadBytes,
			MaxDownloadBytes: webgateway.DefaultMaxDownloadBytes, MaxTotalBytes: webgateway.DefaultMaxTotalBytes,
		},
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
	return securefs.EnsureCanonicalOwnedDir(path)
}
