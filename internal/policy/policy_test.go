package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/state"
)

func TestPolicyV3RoundTripAndIdentityBinding(t *testing.T) {
	project, _ := filepath.EvalSymlinks(t.TempDir())
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	policy, err := New(project, strings.Repeat("a", 64), "1.18.16", "1.2.2", "sunaba-base:1.18.16-secure.1", "secure", now)
	if err != nil {
		t.Fatal(err)
	}
	policyRoot, _ := filepath.EvalSymlinks(t.TempDir())
	path := filepath.Join(policyRoot, "state", "policy.json")
	if err := Save(path, policy); err != nil {
		t.Fatal(err)
	}
	loaded, migrated, err := LoadAndMigrate(path, now.Add(time.Hour))
	if err != nil || migrated || loaded.ProjectID != state.ProjectID(project) {
		t.Fatalf("loaded=%+v migrated=%v error=%v", loaded, migrated, err)
	}
	first, _ := policy.Digest()
	second, _ := loaded.Digest()
	if first != second {
		t.Fatal("policy digest changed after round trip")
	}
	loaded.ProjectID = "substituted"
	if err := loaded.Validate(); err == nil {
		t.Fatal("Project identity substitution was accepted")
	}
}

func TestLegacyV1MigratesAtomicallyToStrictV3(t *testing.T) {
	project, _ := filepath.EvalSymlinks(t.TempDir())
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	legacy := legacyPolicyV1{
		SchemaVersion: 1, ProjectID: state.ProjectID(project), ProjectRoot: project, Mode: "secure",
		ManifestSHA256: strings.Repeat("b", 64), OpenCode: "1.18.16", AppleContainer: "1.2.2", AgentImage: "sunaba-base:1.18.16-secure.1",
		CPUs: 1, Memory: "2G", DiskBytes: 128 << 20, SessionTTLSeconds: 3600,
		AllowedModels: []string{"gpt-5"}, AuditRetentionDays: 30, CreatedAt: now.Add(-time.Hour),
	}
	encoded, _ := json.Marshal(legacy)
	policyRoot, _ := filepath.EvalSymlinks(t.TempDir())
	directory := filepath.Join(policyRoot, "policy")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "policy.json")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	migrated, changed, err := LoadAndMigrate(path, now)
	if err != nil || !changed || migrated.SchemaVersion != CurrentSchemaVersion || migrated.Web.Enabled || len(migrated.Web.Rules) != 0 {
		t.Fatalf("migrated=%+v changed=%v error=%v", migrated, changed, err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"schema_version": 3`) || strings.Contains(string(data), `"web_origins"`) {
		t.Fatalf("policy file was not atomically replaced with v3: %s", data)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(directory, ".sunaba-policy-*.tmp")); len(leftovers) != 0 {
		t.Fatalf("migration temporary files remained: %v", leftovers)
	}
}

func TestLegacyV2MigratesStringRemotesToNamedV3Remotes(t *testing.T) {
	project, _ := filepath.EvalSymlinks(t.TempDir())
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	current, err := New(project, strings.Repeat("c", 64), "1.18.16", "1.2.2", "sunaba-base:1.18.16-secure.1", "secure", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	legacy := legacyPolicyV2{
		SchemaVersion: 2, ProjectID: current.ProjectID, ProjectRoot: current.ProjectRoot, Mode: current.Mode,
		Dependency: current.Dependency, Resources: current.Resources, Session: current.Session, Model: current.Model,
		Git: legacyGitV2{Remotes: []string{"https://git.example/one.git", "https://git.example/two.git"}, PushApprovalRequired: true},
		Web: current.Web, Export: current.Export, Audit: current.Audit, ProtectedPaths: current.ProtectedPaths,
		CreatedAt: current.CreatedAt, UpdatedAt: current.UpdatedAt,
	}
	encoded, _ := json.Marshal(legacy)
	root, _ := filepath.EvalSymlinks(t.TempDir())
	path := filepath.Join(root, "state", "policy.json")
	if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	migrated, changed, err := LoadAndMigrate(path, now)
	if err != nil || !changed || len(migrated.Git.Remotes) != 2 || migrated.Git.Remotes[0].Name != "origin" || migrated.Git.Remotes[1].Name != "remote-2" {
		t.Fatalf("migrated=%+v changed=%v error=%v", migrated.Git, changed, err)
	}
}

func TestPolicyMigrationRejectsUnknownFieldsAndUnsafeOrigin(t *testing.T) {
	project, _ := filepath.EvalSymlinks(t.TempDir())
	policyRoot, _ := filepath.EvalSymlinks(t.TempDir())
	directory := filepath.Join(policyRoot, "policy")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "policy.json")
	fixture := `{"schema_version":1,"project_id":"` + state.ProjectID(project) + `","project_root":"` + project + `","mode":"secure","manifest_sha256":"` + strings.Repeat("a", 64) + `","opencode":"1.18.16","apple_container":"1.2.2","agent_image":"sunaba-base:1.18.16-secure.1","cpus":1,"memory":"2G","disk_bytes":134217728,"session_ttl_seconds":3600,"allowed_models":["gpt-5"],"web_origins":["127.0.0.1"],"audit_retention_days":30,"created_at":"2026-08-10T00:00:00Z","unknown":true}`
	if err := os.WriteFile(path, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadAndMigrate(path, time.Now()); err == nil {
		t.Fatal("legacy policy with unknown field was migrated")
	}
	fixture = strings.Replace(fixture, `,"unknown":true`, "", 1)
	if err := os.WriteFile(path, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadAndMigrate(path, time.Now()); err == nil {
		t.Fatal("legacy policy with IP-literal Web origin was migrated")
	}
}
