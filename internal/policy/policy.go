package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"sunaba/internal/state"
	"sunaba/internal/webgateway"
)

const CurrentSchemaVersion = 3

var identityPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var memoryPattern = regexp.MustCompile(`^[1-9][0-9]*[KMGTP]$`)
var gitRemoteNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

type ProjectPolicy struct {
	SchemaVersion  int              `json:"schema_version"`
	ProjectID      string           `json:"project_id"`
	ProjectRoot    string           `json:"project_root"`
	Mode           string           `json:"mode"`
	Dependency     DependencyPolicy `json:"dependency"`
	Resources      ResourcePolicy   `json:"resources"`
	Session        SessionPolicy    `json:"session"`
	Model          ModelPolicy      `json:"model"`
	Git            GitPolicy        `json:"git"`
	Web            WebPolicy        `json:"web"`
	Export         ExportPolicy     `json:"export"`
	Audit          AuditPolicy      `json:"audit"`
	ProtectedPaths []string         `json:"protected_paths"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
}

type DependencyPolicy struct {
	ManifestSHA256 string `json:"manifest_sha256"`
	OpenCode       string `json:"opencode"`
	AppleContainer string `json:"apple_container"`
	AgentImage     string `json:"agent_image"`
}

type ResourcePolicy struct {
	CPUs        int    `json:"cpus"`
	Memory      string `json:"memory"`
	DiskBytes   int64  `json:"disk_bytes"`
	ProcessMax  int64  `json:"process_max"`
	FileSizeMax int64  `json:"file_size_max"`
	OpenFileMax int64  `json:"open_file_max"`
}

type SessionPolicy struct {
	TTLSeconds  int64 `json:"ttl_seconds"`
	IdleSeconds int64 `json:"idle_seconds"`
}

type ModelPolicy struct {
	AllowedModels    []string `json:"allowed_models"`
	MaxRequests      int      `json:"max_requests"`
	MaxConcurrent    int      `json:"max_concurrent"`
	MaxRequestBytes  int64    `json:"max_request_bytes"`
	MaxResponseBytes int64    `json:"max_response_bytes"`
}

type GitPolicy struct {
	Remotes              []GitRemotePolicy `json:"remotes"`
	PushApprovalRequired bool              `json:"push_approval_required"`
}

type GitRemotePolicy struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type WebPolicy struct {
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

type ExportPolicy struct {
	MaxEntries    int   `json:"max_entries"`
	MaxFileBytes  int64 `json:"max_file_bytes"`
	MaxTotalBytes int64 `json:"max_total_bytes"`
}

type AuditPolicy struct {
	RetentionDays int `json:"retention_days"`
}

func New(projectRoot, manifestDigest, openCodeVersion, containerVersion, agentImage, mode string, now time.Time) (ProjectPolicy, error) {
	canonical, err := canonicalProjectRoot(projectRoot)
	if err != nil {
		return ProjectPolicy{}, err
	}
	policy := ProjectPolicy{
		SchemaVersion: CurrentSchemaVersion, ProjectID: state.ProjectID(canonical), ProjectRoot: canonical, Mode: mode,
		Dependency: DependencyPolicy{ManifestSHA256: manifestDigest, OpenCode: openCodeVersion, AppleContainer: containerVersion, AgentImage: agentImage},
		Resources:  ResourcePolicy{CPUs: 2, Memory: "2G", DiskBytes: 512 << 20, ProcessMax: 512, FileSizeMax: 512 << 20, OpenFileMax: 4096},
		Session:    SessionPolicy{TTLSeconds: 3600, IdleSeconds: 900},
		Model:      ModelPolicy{AllowedModels: []string{"gpt-5"}, MaxRequests: 100, MaxConcurrent: 2, MaxRequestBytes: 4 << 20, MaxResponseBytes: 16 << 20},
		Git:        GitPolicy{PushApprovalRequired: true},
		Web:        WebPolicy{Enabled: false, MaxRequests: 500, MaxConcurrent: 4, MaxConnectSeconds: 120, MaxUploadBytes: 1 << 20, MaxDownloadBytes: 64 << 20, MaxTotalBytes: 256 << 20},
		Export:     ExportPolicy{MaxEntries: 100_000, MaxFileBytes: 128 << 20, MaxTotalBytes: 2 << 30},
		Audit:      AuditPolicy{RetentionDays: 30}, ProtectedPaths: []string{".git"}, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}
	return policy, policy.Validate()
}

func (p ProjectPolicy) Validate() error {
	if p.SchemaVersion != CurrentSchemaVersion || !identityPattern.MatchString(p.ProjectID) || (p.Mode != "secure" && p.Mode != "dev") {
		return fmt.Errorf("Project policy identity, schema, or mode is invalid")
	}
	canonical, err := canonicalProjectRoot(p.ProjectRoot)
	if err != nil || canonical != p.ProjectRoot || state.ProjectID(canonical) != p.ProjectID {
		return fmt.Errorf("Project policy root identity does not match")
	}
	if !digestPattern.MatchString(p.Dependency.ManifestSHA256) || p.Dependency.OpenCode == "" || p.Dependency.AppleContainer == "" || p.Dependency.AgentImage == "" || strings.Contains(strings.ToLower(p.Dependency.AgentImage), "latest") {
		return fmt.Errorf("Project dependency policy is not pinned")
	}
	resources := p.Resources
	if resources.CPUs <= 0 || resources.CPUs > 32 || !memoryPattern.MatchString(strings.ToUpper(resources.Memory)) || resources.DiskBytes < 64<<20 || resources.DiskBytes > 8<<30 || resources.ProcessMax < 16 || resources.ProcessMax > 4096 || resources.FileSizeMax != resources.DiskBytes || resources.OpenFileMax < 256 || resources.OpenFileMax > 1<<20 {
		return fmt.Errorf("Project resource policy is invalid")
	}
	if p.Session.TTLSeconds <= 0 || p.Session.TTLSeconds > 86400 || p.Session.IdleSeconds <= 0 || p.Session.IdleSeconds > p.Session.TTLSeconds {
		return fmt.Errorf("Project session policy is invalid")
	}
	if len(p.Model.AllowedModels) == 0 || len(p.Model.AllowedModels) > 32 || p.Model.MaxRequests <= 0 || p.Model.MaxConcurrent <= 0 || p.Model.MaxRequestBytes <= 0 || p.Model.MaxResponseBytes <= 0 {
		return fmt.Errorf("Project Model Gateway policy is invalid")
	}
	if !uniqueSafeStrings(p.Model.AllowedModels, 128) || !validGitRemotes(p.Git.Remotes) || !p.Git.PushApprovalRequired {
		return fmt.Errorf("Project Model/Git policy is invalid")
	}
	if p.Web.Enabled {
		web := webgateway.Policy{Rules: p.Web.Rules}
		if _, err := web.Digest(); err != nil || p.Web.MaxRequests <= 0 || p.Web.MaxConcurrent <= 0 || p.Web.MaxConnectSeconds <= 0 || p.Web.MaxConnectSeconds > 600 || p.Web.MaxUploadBytes <= 0 || p.Web.MaxDownloadBytes <= 0 || p.Web.MaxTotalBytes <= 0 {
			return fmt.Errorf("Project Web Gateway policy is invalid")
		}
		if !filepath.IsAbs(p.Web.BlocklistManifest) || filepath.Clean(p.Web.BlocklistManifest) != p.Web.BlocklistManifest || !digestPattern.MatchString(p.Web.BlocklistSHA256) {
			return fmt.Errorf("Project blocklist manifest path is invalid")
		}
	} else if len(p.Web.Rules) != 0 || p.Web.BlocklistManifest != "" || p.Web.BlocklistSHA256 != "" {
		return fmt.Errorf("disabled Web Gateway must not retain active rules")
	}
	if p.Export.MaxEntries <= 0 || p.Export.MaxEntries > 1_000_000 || p.Export.MaxFileBytes <= 0 || p.Export.MaxTotalBytes < p.Export.MaxFileBytes || p.Export.MaxTotalBytes > 8<<30 || p.Audit.RetentionDays < 1 || p.Audit.RetentionDays > 365 {
		return fmt.Errorf("Project export or audit policy is invalid")
	}
	if !uniqueRelativePaths(p.ProtectedPaths) || p.CreatedAt.IsZero() || p.UpdatedAt.Before(p.CreatedAt) {
		return fmt.Errorf("Project protected paths or timestamps are invalid")
	}
	return nil
}

func ValidateGitRemote(remote GitRemotePolicy) error {
	if !gitRemoteNamePattern.MatchString(remote.Name) {
		return fmt.Errorf("Git remote name must match %s", gitRemoteNamePattern)
	}
	parsed, err := url.Parse(remote.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !strings.HasSuffix(parsed.Path, ".git") || parsed.Path == ".git" {
		return fmt.Errorf("Git remote must be a credential-free fixed HTTPS URL ending in .git")
	}
	if parsed.Port() != "" && parsed.Port() != "443" {
		return fmt.Errorf("Git remote must use the standard HTTPS port")
	}
	if len(remote.URL) > 2048 || strings.ContainsAny(remote.URL, "\x00\r\n") {
		return fmt.Errorf("Git remote URL is invalid")
	}
	return nil
}

func validGitRemotes(remotes []GitRemotePolicy) bool {
	if len(remotes) > 16 {
		return false
	}
	names := make(map[string]struct{}, len(remotes))
	urls := make(map[string]struct{}, len(remotes))
	for _, remote := range remotes {
		if ValidateGitRemote(remote) != nil {
			return false
		}
		if _, exists := names[remote.Name]; exists {
			return false
		}
		if _, exists := urls[remote.URL]; exists {
			return false
		}
		names[remote.Name] = struct{}{}
		urls[remote.URL] = struct{}{}
	}
	return true
}

func (p ProjectPolicy) Digest() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func canonicalProjectRoot(root string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", fmt.Errorf("Project root must be an absolute clean path")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("Project root must be a real directory")
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	if canonical != root {
		return "", fmt.Errorf("Project root must already be canonical")
	}
	return canonical, nil
}

func uniqueSafeStrings(values []string, maximum int) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || len(value) > maximum || strings.ContainsAny(value, "\x00\r\n") {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func uniqueRelativePaths(paths []string) bool {
	if len(paths) == 0 || len(paths) > 128 {
		return false
	}
	sorted := append([]string(nil), paths...)
	sort.Strings(sorted)
	for index, path := range sorted {
		if path == "" || path == "." || filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasPrefix(path, "..") || strings.ContainsRune(path, '\x00') || (index > 0 && path == sorted[index-1]) {
			return false
		}
	}
	return true
}
