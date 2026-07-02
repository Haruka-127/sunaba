package state

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	DefaultCPUs   = 4
	DefaultMemory = "8g"

	FirewallEnabled  = "enabled"
	FirewallDisabled = "disabled"
	FirewallInherit  = "inherit"
)

type Store struct {
	Root string
}

type GlobalConfig struct {
	ImageVersion string `json:"image_version"`
	FirewallMode string `json:"firewall_mode,omitempty"`
}

type ProjectConfig struct {
	Path         string    `json:"path"`
	Container    string    `json:"container"`
	ImageVersion string    `json:"image_version"`
	CPUs         int       `json:"cpus"`
	Memory       string    `json:"memory"`
	Proxy        string    `json:"proxy"`
	FirewallMode string    `json:"firewall_mode,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type Project struct {
	ID  string
	Dir string
	Cfg ProjectConfig
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
	return &Store{Root: filepath.Join(root, "sunaba")}, nil
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
	st, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%s is not a directory", real)
	}
	return real, nil
}

func ProjectID(path string) string {
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:])[:12]
}

func NormalizeGlobalFirewallMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", FirewallEnabled:
		return FirewallEnabled, nil
	case FirewallDisabled:
		return FirewallDisabled, nil
	default:
		return "", fmt.Errorf("invalid global firewall mode %q; use enabled or disabled", mode)
	}
}

func NormalizeProjectFirewallMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", FirewallInherit:
		return FirewallInherit, nil
	case FirewallEnabled:
		return FirewallEnabled, nil
	case FirewallDisabled:
		return FirewallDisabled, nil
	default:
		return "", fmt.Errorf("invalid project firewall mode %q; use inherit, enabled, or disabled", mode)
	}
}

func EffectiveFirewallDisabled(global GlobalConfig, project ProjectConfig) bool {
	switch projectMode, _ := NormalizeProjectFirewallMode(project.FirewallMode); projectMode {
	case FirewallDisabled:
		return true
	case FirewallEnabled:
		return false
	}
	globalMode, _ := NormalizeGlobalFirewallMode(global.FirewallMode)
	return globalMode == FirewallDisabled
}

func (s *Store) Init() error {
	return os.MkdirAll(filepath.Join(s.Root, "projects"), 0700)
}

func (s *Store) LoadGlobal() (GlobalConfig, error) {
	var cfg GlobalConfig
	err := readJSON(filepath.Join(s.Root, "config.json"), &cfg)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	return cfg, err
}

func (s *Store) SaveGlobal(cfg GlobalConfig) error {
	if err := s.Init(); err != nil {
		return err
	}
	return writeJSON0600(filepath.Join(s.Root, "config.json"), cfg)
}

func (s *Store) ProjectByPath(path string) (*Project, bool, error) {
	resolved, err := ResolveProjectPath(path)
	if err != nil {
		return nil, false, err
	}
	id := ProjectID(resolved)
	dir := filepath.Join(s.Root, "projects", id)
	cfgPath := filepath.Join(dir, "config.json")
	var cfg ProjectConfig
	err = readJSON(cfgPath, &cfg)
	if errors.Is(err, os.ErrNotExist) {
		cfg = ProjectConfig{
			Path:      resolved,
			Container: "sunaba-" + id,
			CPUs:      DefaultCPUs,
			Memory:    DefaultMemory,
			CreatedAt: time.Now().UTC(),
		}
		return &Project{ID: id, Dir: dir, Cfg: cfg}, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	if cfg.Path != resolved {
		return nil, false, fmt.Errorf("project state mismatch: config path %s does not match %s", cfg.Path, resolved)
	}
	return &Project{ID: id, Dir: dir, Cfg: cfg}, false, nil
}

func (s *Store) Projects() ([]Project, error) {
	root := filepath.Join(s.Root, "projects")
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Project
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		var cfg ProjectConfig
		if err := readJSON(filepath.Join(dir, "config.json"), &cfg); err != nil {
			continue
		}
		out = append(out, Project{ID: e.Name(), Dir: dir, Cfg: cfg})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Cfg.Path < out[j].Cfg.Path })
	return out, nil
}

func (p *Project) Ensure(imageVersion string, cpus int, memory string) (bool, error) {
	first := false
	if _, err := os.Stat(filepath.Join(p.Dir, "config.json")); errors.Is(err, os.ErrNotExist) {
		first = true
	}
	if err := os.MkdirAll(p.Dir, 0700); err != nil {
		return first, err
	}
	for _, dir := range []string{"opencode-config", "opencode-data", "logs"} {
		if err := os.MkdirAll(filepath.Join(p.Dir, dir), 0700); err != nil {
			return first, err
		}
	}
	if cpus > 0 {
		p.Cfg.CPUs = cpus
	}
	if memory != "" {
		p.Cfg.Memory = memory
	}
	if p.Cfg.CPUs == 0 {
		p.Cfg.CPUs = DefaultCPUs
	}
	if p.Cfg.Memory == "" {
		p.Cfg.Memory = DefaultMemory
	}
	if imageVersion != "" && p.Cfg.ImageVersion == "" {
		p.Cfg.ImageVersion = imageVersion
	}
	if p.Cfg.Container == "" {
		p.Cfg.Container = "sunaba-" + p.ID
	}
	if p.Cfg.CreatedAt.IsZero() {
		p.Cfg.CreatedAt = time.Now().UTC()
	}
	if err := writeJSON0600(filepath.Join(p.Dir, "config.json"), p.Cfg); err != nil {
		return first, err
	}
	if _, err := p.EnsurePassword(); err != nil {
		return first, err
	}
	return first, p.WriteOpenCodeConfig()
}

func (p *Project) Save() error {
	return writeJSON0600(filepath.Join(p.Dir, "config.json"), p.Cfg)
}

func (p *Project) EnsurePassword() (string, error) {
	path := filepath.Join(p.Dir, "server-password")
	b, err := os.ReadFile(path)
	if err == nil {
		return strings.TrimSpace(string(b)), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	pass := base64.RawURLEncoding.EncodeToString(raw)
	return pass, os.WriteFile(path, []byte(pass+"\n"), 0600)
}

func (p *Project) Password() (string, error) {
	b, err := os.ReadFile(filepath.Join(p.Dir, "server-password"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (p *Project) EnvPath() string {
	return filepath.Join(p.Dir, "env")
}

func (p *Project) ReadEnv() (map[string]string, error) {
	return ReadEnvFile(p.EnvPath())
}

func (p *Project) WriteEnv(env map[string]string) error {
	return WriteEnvFile(p.EnvPath(), env)
}

func (p *Project) WriteOpenCodeConfig() error {
	cfg := map[string]any{
		"$schema":    "https://opencode.ai/config.json",
		"autoupdate": false,
		"permission": "allow",
	}
	return writeJSON0600(filepath.Join(p.Dir, "opencode-config", "opencode.json"), cfg)
}

func (p *Project) AuditPIDPath() string {
	return filepath.Join(p.Dir, "audit.pid")
}

func (p *Project) AuditLogDir() string {
	return filepath.Join(p.Dir, "logs")
}

func (p *Project) RemoveFull() error {
	return os.RemoveAll(p.Dir)
}

func ReadEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	env := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || !validEnvKey(k) {
			return nil, fmt.Errorf("invalid env line %q", line)
		}
		env[k] = v
	}
	return env, sc.Err()
}

func WriteEnvFile(path string, env map[string]string) error {
	keys := make([]string, 0, len(env))
	for k := range env {
		if !validEnvKey(k) {
			return fmt.Errorf("invalid env key %q", k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(env[k])
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0600)
}

func EnvFileForContainer(p *Project, password string, extra map[string]string) (string, func(), error) {
	tmp, err := os.CreateTemp("", "sunaba-env-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.Remove(tmp.Name()) }
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		cleanup()
		return "", nil, err
	}
	env, err := p.ReadEnv()
	if err != nil {
		tmp.Close()
		cleanup()
		return "", nil, err
	}
	for k, v := range extra {
		env[k] = v
	}
	env["OPENCODE_SERVER_PASSWORD"] = password
	env["OPENCODE_SERVER_USERNAME"] = "opencode"
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !validEnvKey(k) {
			tmp.Close()
			cleanup()
			return "", nil, fmt.Errorf("invalid env key %q", k)
		}
		if _, err := fmt.Fprintf(tmp, "%s=%s\n", k, env[k]); err != nil {
			tmp.Close()
			cleanup()
			return "", nil, err
		}
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return tmp.Name(), cleanup, nil
}

func validEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		if i == 0 {
			if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
				return false
			}
			continue
		}
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func readJSON(path string, dst any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

func writeJSON0600(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0600)
}

func MaskValue(v string) string {
	if v == "" {
		return ""
	}
	r := []rune(v)
	if len(r) <= 4 {
		return strings.Repeat("*", len(r))
	}
	return string(r[:4]) + "..."
}
