// Package projectconfig manages the host-only, user-editable Project configuration.
package projectconfig

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"sunaba/internal/policy"
	"sunaba/internal/securefs"
	"sunaba/internal/state"
	"sunaba/internal/webgateway"
)

const (
	CurrentSchemaVersion = 2
	ProjectFileName      = "project.json"
	WebOriginsFileName   = "web-origins.txt"
	maxConfigBytes       = 1 << 20
	maxOriginsBytes      = 64 << 10
)

var projectIDPattern = regexp.MustCompile(`^[0-9a-f]{12}$`)

type Store struct {
	Root string
}

type Config struct {
	SchemaVersion int                   `json:"schema_version"`
	ProjectRoot   string                `json:"project_root"`
	Mode          string                `json:"mode"`
	Resources     policy.ResourcePolicy `json:"resources"`
	Session       policy.SessionPolicy  `json:"session"`
	Model         policy.ModelPolicy    `json:"model"`
	Git           GitConfig             `json:"git"`
	Web           WebConfig             `json:"web"`
	Export        policy.ExportPolicy   `json:"export"`
	Audit         policy.AuditPolicy    `json:"audit"`
}

type GitConfig struct {
	Remotes []policy.GitRemotePolicy `json:"remotes"`
}

type WebConfig struct {
	Enabled           bool     `json:"enabled"`
	OriginPresets     []string `json:"origin_presets"`
	OriginsFile       string   `json:"origins_file"`
	MaxRequests       int      `json:"max_requests"`
	MaxConcurrent     int      `json:"max_concurrent"`
	MaxConnectSeconds int64    `json:"max_connect_seconds"`
	MaxUploadBytes    int64    `json:"max_upload_bytes"`
	MaxDownloadBytes  int64    `json:"max_download_bytes"`
	MaxTotalBytes     int64    `json:"max_total_bytes"`
}

type Paths struct {
	Directory  string
	Project    string
	WebOrigins string
}

func NewStore() (*Store, error) {
	root := os.Getenv("XDG_CONFIG_HOME")
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		root = filepath.Join(home, ".config")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return &Store{Root: filepath.Join(filepath.Clean(absolute), "sunaba")}, nil
}

func (s *Store) ProjectPaths(projectID string) (Paths, error) {
	if s == nil || !filepath.IsAbs(s.Root) || filepath.Clean(s.Root) != s.Root || !projectIDPattern.MatchString(projectID) {
		return Paths{}, fmt.Errorf("Project configuration root or Project ID is invalid")
	}
	directory := filepath.Join(s.Root, "projects", projectID)
	return Paths{Directory: directory, Project: filepath.Join(directory, ProjectFileName), WebOrigins: filepath.Join(directory, WebOriginsFileName)}, nil
}

func (s *Store) Init() error {
	if s == nil || !filepath.IsAbs(s.Root) || filepath.Clean(s.Root) != s.Root {
		return fmt.Errorf("Project configuration root must be absolute and clean")
	}
	if err := ensureOwnedBaseDirectory(filepath.Dir(s.Root)); err != nil {
		return err
	}
	if err := ensurePrivateDirectory(s.Root); err != nil {
		return err
	}
	return ensurePrivateDirectory(filepath.Join(s.Root, "projects"))
}

func ensureOwnedBaseDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("Project configuration base must be absolute and clean")
	}
	if info, err := os.Lstat(path); err == nil {
		var stat unix.Stat_t
		canonical, canonicalErr := filepath.EvalSymlinks(path)
		if unix.Lstat(path, &stat) != nil || canonicalErr != nil || canonical != path || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != uint32(os.Geteuid()) {
			return fmt.Errorf("Project configuration base must be current-user owned and not a symlink")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	var stat unix.Stat_t
	canonical, canonicalErr := filepath.EvalSymlinks(parent)
	if err != nil || unix.Lstat(parent, &stat) != nil || canonicalErr != nil || canonical != parent || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("Project configuration base parent must be current-user owned and not a symlink")
	}
	return os.Mkdir(path, 0700)
}

func (s *Store) Save(projectID string, config Config, rules []webgateway.OriginRule) error {
	if err := s.Init(); err != nil {
		return err
	}
	paths, err := s.ProjectPaths(projectID)
	if err != nil {
		return err
	}
	if state.ProjectID(config.ProjectRoot) != projectID {
		return fmt.Errorf("Project configuration identity does not match its directory")
	}
	if err := Validate(config, rules); err != nil {
		return err
	}
	if err := ensurePrivateDirectory(paths.Directory); err != nil {
		return err
	}
	encoded, err := Marshal(config)
	if err != nil {
		return err
	}
	if err := writePrivateFile(paths.WebOrigins, RenderOrigins(rules)); err != nil {
		return err
	}
	return writePrivateFile(paths.Project, encoded)
}

func (s *Store) Load(projectID string) (Config, []webgateway.OriginRule, error) {
	paths, err := s.ProjectPaths(projectID)
	if err != nil {
		return Config{}, nil, err
	}
	if err := checkPrivateDirectory(s.Root); err != nil {
		return Config{}, nil, err
	}
	if err := checkPrivateDirectory(filepath.Join(s.Root, "projects")); err != nil {
		return Config{}, nil, err
	}
	if err := checkPrivateDirectory(paths.Directory); err != nil {
		return Config{}, nil, err
	}
	data, err := readPrivateFile(paths.Project, maxConfigBytes)
	if err != nil {
		return Config{}, nil, err
	}
	var config Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, nil, fmt.Errorf("decode Project configuration: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Config{}, nil, fmt.Errorf("Project configuration contains trailing data")
	}
	if config.SchemaVersion == 1 {
		config.SchemaVersion = CurrentSchemaVersion
	}
	if state.ProjectID(config.ProjectRoot) != projectID {
		return Config{}, nil, fmt.Errorf("Project configuration identity does not match its directory")
	}
	rules, err := loadOriginsFile(paths.WebOrigins)
	if err != nil {
		return Config{}, nil, err
	}
	if err := Validate(config, rules); err != nil {
		return Config{}, nil, err
	}
	return config, rules, nil
}

func (s *Store) Remove(projectID string) error {
	paths, err := s.ProjectPaths(projectID)
	if err != nil {
		return err
	}
	if filepath.Dir(paths.Directory) != filepath.Join(s.Root, "projects") || filepath.Base(paths.Directory) != projectID {
		return fmt.Errorf("refusing to remove an unbound Project configuration directory")
	}
	if _, err := os.Lstat(s.Root); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := checkPrivateDirectory(s.Root); err != nil {
		return err
	}
	projectsRoot := filepath.Join(s.Root, "projects")
	if _, err := os.Lstat(projectsRoot); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := checkPrivateDirectory(projectsRoot); err != nil {
		return err
	}
	info, err := os.Lstat(paths.Directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return fmt.Errorf("refusing to remove an unsafe Project configuration directory")
	}
	if err := checkPrivateDirectory(paths.Directory); err != nil {
		return err
	}
	return os.RemoveAll(paths.Directory)
}

func Marshal(config Config) ([]byte, error) {
	encoded, err := json.MarshalIndent(normalizeConfig(config), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func FromPolicy(effective policy.ProjectPolicy) (Config, []webgateway.OriginRule) {
	config := Config{
		SchemaVersion: CurrentSchemaVersion,
		ProjectRoot:   effective.ProjectRoot,
		Mode:          effective.Mode,
		Resources:     effective.Resources,
		Session:       effective.Session,
		Model:         effective.Model,
		Git:           GitConfig{Remotes: append([]policy.GitRemotePolicy(nil), effective.Git.Remotes...)},
		Web: WebConfig{
			Enabled: effective.Web.Enabled, OriginPresets: append([]string(nil), effective.Web.OriginPresets...), OriginsFile: WebOriginsFileName,
			MaxRequests: effective.Web.MaxRequests, MaxConcurrent: effective.Web.MaxConcurrent,
			MaxConnectSeconds: effective.Web.MaxConnectSeconds, MaxUploadBytes: effective.Web.MaxUploadBytes,
			MaxDownloadBytes: effective.Web.MaxDownloadBytes, MaxTotalBytes: effective.Web.MaxTotalBytes,
		},
		Export: effective.Export,
		Audit:  effective.Audit,
	}
	return normalizeConfig(config), normalizeRules(effective.Web.CustomRules)
}

func Validate(config Config, rules []webgateway.OriginRule) error {
	if config.SchemaVersion != CurrentSchemaVersion {
		return fmt.Errorf("unsupported Project configuration schema %d", config.SchemaVersion)
	}
	if config.Web.OriginsFile != WebOriginsFileName {
		return fmt.Errorf("web.origins_file must be %q", WebOriginsFileName)
	}
	resolvedRules, presetDigest, err := ResolveWebRules(config, rules)
	if err != nil {
		return err
	}
	if config.Web.Enabled && len(resolvedRules) == 0 {
		return fmt.Errorf("enabled Web Gateway requires at least one origin")
	}
	created := time.Unix(1, 0).UTC()
	normalizedPresets := normalizeConfig(config).Web.OriginPresets
	candidate := policy.ProjectPolicy{
		SchemaVersion: policy.CurrentSchemaVersion, ProjectID: state.ProjectID(config.ProjectRoot), ProjectRoot: config.ProjectRoot, Mode: config.Mode,
		Dependency: policy.DependencyPolicy{ManifestSHA256: strings.Repeat("0", 64), OpenCode: "pinned", AppleContainer: "pinned", AgentImage: "sunaba-base:pinned"},
		Resources:  config.Resources, Session: config.Session, Model: config.Model,
		Git: policy.GitPolicy{Remotes: append([]policy.GitRemotePolicy(nil), config.Git.Remotes...), PushApprovalRequired: true},
		Web: policy.WebPolicy{
			Enabled: config.Web.Enabled, OriginPresets: normalizedPresets, OriginPresetSHA256: presetDigest,
			CustomRules: append([]webgateway.OriginRule(nil), rules...), Rules: append([]webgateway.OriginRule(nil), resolvedRules...),
			MaxRequests: config.Web.MaxRequests, MaxConcurrent: config.Web.MaxConcurrent, MaxConnectSeconds: config.Web.MaxConnectSeconds,
			MaxUploadBytes: config.Web.MaxUploadBytes, MaxDownloadBytes: config.Web.MaxDownloadBytes, MaxTotalBytes: config.Web.MaxTotalBytes,
		},
		Export: config.Export, Audit: config.Audit, ProtectedPaths: []string{".git"}, CreatedAt: created, UpdatedAt: created,
	}
	if candidate.Web.Enabled {
		candidate.Web.BlocklistManifest = filepath.Join(config.ProjectRoot, ".sunaba-validation-blocklist.json")
		candidate.Web.BlocklistSHA256 = strings.Repeat("0", 64)
	}
	if !candidate.Web.Enabled {
		candidate.Web.Rules = nil
	}
	if err := candidate.Validate(); err != nil {
		return fmt.Errorf("invalid Project configuration: %w", err)
	}
	return nil
}

func Compile(config Config, rules []webgateway.OriginRule, base policy.ProjectPolicy, blocklistManifest, blocklistSHA256 string, now time.Time) (policy.ProjectPolicy, error) {
	if err := Validate(config, rules); err != nil {
		return policy.ProjectPolicy{}, err
	}
	if base.ProjectRoot != config.ProjectRoot || base.ProjectID != state.ProjectID(config.ProjectRoot) {
		return policy.ProjectPolicy{}, fmt.Errorf("effective policy and Project configuration identities differ")
	}
	result := base
	result.SchemaVersion = policy.CurrentSchemaVersion
	result.Mode = config.Mode
	result.Resources = config.Resources
	result.Session = config.Session
	result.Model = config.Model
	result.Model.AllowedModels = append([]string(nil), config.Model.AllowedModels...)
	result.Git = policy.GitPolicy{Remotes: append([]policy.GitRemotePolicy(nil), config.Git.Remotes...), PushApprovalRequired: true}
	resolvedRules, presetDigest, err := ResolveWebRules(config, rules)
	if err != nil {
		return policy.ProjectPolicy{}, err
	}
	normalizedPresets := normalizeConfig(config).Web.OriginPresets
	result.Web = policy.WebPolicy{
		Enabled: config.Web.Enabled, OriginPresets: normalizedPresets, OriginPresetSHA256: presetDigest,
		CustomRules: normalizeRules(rules), Rules: resolvedRules, BlocklistManifest: blocklistManifest, BlocklistSHA256: blocklistSHA256,
		MaxRequests: config.Web.MaxRequests, MaxConcurrent: config.Web.MaxConcurrent, MaxConnectSeconds: config.Web.MaxConnectSeconds,
		MaxUploadBytes: config.Web.MaxUploadBytes, MaxDownloadBytes: config.Web.MaxDownloadBytes, MaxTotalBytes: config.Web.MaxTotalBytes,
	}
	if !result.Web.Enabled {
		result.Web.Rules = nil
		result.Web.BlocklistManifest = ""
		result.Web.BlocklistSHA256 = ""
	}
	result.Export = config.Export
	result.Audit = config.Audit
	result.ProtectedPaths = []string{".git"}
	result.UpdatedAt = now.UTC()
	if err := result.Validate(); err != nil {
		return policy.ProjectPolicy{}, err
	}
	return result, nil
}

func Matches(config Config, rules []webgateway.OriginRule, effective policy.ProjectPolicy) bool {
	applied, appliedRules := FromPolicy(effective)
	if !reflect.DeepEqual(normalizeConfig(config), applied) || !reflect.DeepEqual(normalizeRules(rules), appliedRules) {
		return false
	}
	resolvedRules, presetDigest, err := ResolveWebRules(config, rules)
	if err != nil || presetDigest != effective.Web.OriginPresetSHA256 {
		return false
	}
	if !config.Web.Enabled {
		resolvedRules = nil
	}
	return reflect.DeepEqual(resolvedRules, effective.Web.Rules)
}

func ResolveWebRules(config Config, rules []webgateway.OriginRule) ([]webgateway.OriginRule, string, error) {
	resolved, digest, err := webgateway.ResolveOriginRules(config.Web.OriginPresets, rules)
	if err != nil {
		return nil, "", fmt.Errorf("invalid Web origin selection: %w", err)
	}
	return resolved, digest, nil
}

func ParseOrigin(raw string, includeSubdomains bool) (webgateway.OriginRule, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") || strings.ContainsAny(raw, "\x00\r\n") {
		return webgateway.OriginRule{}, fmt.Errorf("Web origin must contain only scheme and hostname")
	}
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	expectedAuthority := host
	if port != "" {
		expectedAuthority += ":" + port
	}
	if strings.ToLower(parsed.Host) != expectedAuthority {
		return webgateway.OriginRule{}, fmt.Errorf("Web origin authority is invalid")
	}
	rule := webgateway.OriginRule{Host: host, Category: "user", IncludeSubdomains: includeSubdomains}
	switch parsed.Scheme {
	case "http":
		if port != "" && port != "80" {
			return webgateway.OriginRule{}, fmt.Errorf("HTTP Web origins must use port 80")
		}
		rule.Port, rule.AllowHTTP = 80, true
	case "https":
		if port != "" && port != "443" {
			return webgateway.OriginRule{}, fmt.Errorf("HTTPS Web origins must use port 443")
		}
		rule.Port, rule.AllowConnect = 443, true
	default:
		return webgateway.OriginRule{}, fmt.Errorf("Web origin scheme must be http or https")
	}
	if _, err := (webgateway.Policy{Rules: []webgateway.OriginRule{rule}}).Digest(); err != nil {
		return webgateway.OriginRule{}, fmt.Errorf("invalid Web origin: %w", err)
	}
	return rule, nil
}

func ParseOrigins(data []byte) ([]webgateway.OriginRule, error) {
	if len(data) > maxOriginsBytes {
		return nil, fmt.Errorf("Web origins file exceeds %d bytes", maxOriginsBytes)
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxOriginsBytes)
	rules := make([]webgateway.OriginRule, 0)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 || len(fields) > 2 || (len(fields) == 2 && fields[1] != "include-subdomains") {
			return nil, fmt.Errorf("Web origins line %d must be '<origin>' or '<origin> include-subdomains'", lineNumber)
		}
		rule, err := ParseOrigin(fields[0], len(fields) == 2)
		if err != nil {
			return nil, fmt.Errorf("Web origins line %d: %w", lineNumber, err)
		}
		rules = append(rules, rule)
		if len(rules) > 1024 {
			return nil, fmt.Errorf("Web origins file exceeds 1024 rules")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan Web origins: %w", err)
	}
	if len(rules) > 0 {
		if _, err := (webgateway.Policy{Rules: rules}).Digest(); err != nil {
			return nil, fmt.Errorf("invalid Web origins file: %w", err)
		}
	}
	return normalizeRules(rules), nil
}

func RenderOrigins(rules []webgateway.OriginRule) []byte {
	var output strings.Builder
	output.WriteString("# Project-specific additions only; built-in presets are selected in project.json.\n")
	output.WriteString("# One HTTP(S) origin per line. Add 'include-subdomains' only when explicitly required.\n")
	for _, rule := range normalizeRules(rules) {
		scheme := "https"
		if rule.AllowHTTP {
			scheme = "http"
		}
		fmt.Fprintf(&output, "%s://%s", scheme, rule.Host)
		if rule.IncludeSubdomains {
			output.WriteString(" include-subdomains")
		}
		output.WriteByte('\n')
	}
	return []byte(output.String())
}

func normalizeConfig(config Config) Config {
	config.Model.AllowedModels = append([]string(nil), config.Model.AllowedModels...)
	config.Git.Remotes = append(make([]policy.GitRemotePolicy, 0, len(config.Git.Remotes)), config.Git.Remotes...)
	sort.Slice(config.Git.Remotes, func(i, j int) bool { return config.Git.Remotes[i].Name < config.Git.Remotes[j].Name })
	config.Web.OriginPresets = append(make([]string, 0, len(config.Web.OriginPresets)), config.Web.OriginPresets...)
	sort.Strings(config.Web.OriginPresets)
	return config
}

func normalizeRules(rules []webgateway.OriginRule) []webgateway.OriginRule {
	keyed := make([]struct {
		rule webgateway.OriginRule
		key  string
	}, len(rules))
	for index, rule := range rules {
		encoded, _ := json.Marshal(rule)
		keyed[index] = struct {
			rule webgateway.OriginRule
			key  string
		}{rule: rule, key: string(encoded)}
	}
	sort.Slice(keyed, func(i, j int) bool { return keyed[i].key < keyed[j].key })
	result := make([]webgateway.OriginRule, len(keyed))
	for index := range keyed {
		result[index] = keyed[index].rule
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func loadOriginsFile(path string) ([]webgateway.OriginRule, error) {
	data, err := readPrivateFile(path, maxOriginsBytes)
	if err != nil {
		return nil, err
	}
	return ParseOrigins(data)
}

func ensurePrivateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("Project configuration directory must be absolute and clean")
	}
	if _, err := os.Lstat(path); err == nil {
		return securefs.CheckCanonicalOwnedDir(path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	var parentStat unix.Stat_t
	parentStatErr := unix.Lstat(parent, &parentStat)
	parentCanonical, parentCanonicalErr := filepath.EvalSymlinks(parent)
	if err != nil || parentStatErr != nil || parentCanonicalErr != nil || parentCanonical != parent || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentStat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("Project configuration parent must exist, be current-user owned, and not be a symlink")
	}
	if err := os.Mkdir(path, 0700); err != nil {
		return err
	}
	return securefs.CheckCanonicalOwnedDir(path)
}

func checkPrivateDirectory(path string) error {
	return securefs.CheckCanonicalOwnedDir(path)
}

func readPrivateFile(path string, maximum int64) ([]byte, error) {
	return securefs.ReadOwnedRegular(path, maximum)
}

func writePrivateFile(path string, data []byte) error {
	if len(data) == 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("Project configuration path or content is invalid")
	}
	parent := filepath.Dir(path)
	if err := ensurePrivateDirectory(parent); err != nil {
		return err
	}
	return securefs.AtomicWriteOwned(path, data)
}
