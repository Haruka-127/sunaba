package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"sunaba/internal/modelcatalog"
	"sunaba/internal/modelgateway"
	"sunaba/internal/state"
	"sunaba/internal/webgateway"
)

func TestPolicyV6RoundTripIdentityBindingAndModelDefaults(t *testing.T) {
	project, _ := filepath.EvalSymlinks(t.TempDir())
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	policy, err := New(project, strings.Repeat("a", 64), "1.18.16", "1.2.2", "sunaba-base:1.18.16-secure.1", "secure", now)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Model.MaxRequests != modelgateway.DefaultMaxRequests || policy.Model.MaxConcurrent != modelgateway.DefaultMaxConcurrent || policy.Model.MaxRequestBytes != modelgateway.DefaultMaxRequestBytes || policy.Model.MaxResponseBytes != modelgateway.DefaultMaxResponseBytes {
		t.Fatalf("unexpected Model Gateway defaults: %+v", policy.Model)
	}
	if len(policy.Web.OriginPresets) != 1 || policy.Web.OriginPresets[0] != webgateway.CommonDevelopmentOriginPreset || len(policy.Web.OriginPresetSHA256) != 64 || policy.Web.Enabled {
		t.Fatalf("unexpected Web Gateway defaults: %+v", policy.Web)
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

func TestCompileExportPolicyPreservesConfiguredLimitsAndHardBounds(t *testing.T) {
	configured := ExportPolicy{MaxEntries: 321, MaxFileBytes: 128 << 20, MaxTotalBytes: 2 << 30}
	compiled, err := CompileExportPolicy(configured, []string{"vendor", ".git"})
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Snapshot.MaxEntries != configured.MaxEntries || compiled.Snapshot.MaxFileSize != configured.MaxFileBytes || compiled.Snapshot.MaxTotalSize != configured.MaxTotalBytes {
		t.Fatalf("compiled limits=%+v configured=%+v", compiled.Snapshot, configured)
	}
	if !reflect.DeepEqual(compiled.Snapshot.ProtectedPaths, []string{".git", ".sunaba", "vendor"}) || len(compiled.Digest) != 64 {
		t.Fatalf("compiled protected paths or digest are invalid: %+v", compiled)
	}
	changed, err := CompileExportPolicy(ExportPolicy{MaxEntries: 321, MaxFileBytes: 127 << 20, MaxTotalBytes: 2 << 30}, []string{"vendor"})
	if err != nil || changed.Digest == compiled.Digest {
		t.Fatalf("limit change did not change digest: changed=%+v error=%v", changed, err)
	}
	for _, invalid := range []ExportPolicy{
		{MaxEntries: MaximumExportEntries + 1, MaxFileBytes: 1, MaxTotalBytes: 1},
		{MaxEntries: 1, MaxFileBytes: MaximumExportFileBytes + 1, MaxTotalBytes: MaximumExportFileBytes + 1},
		{MaxEntries: 1, MaxFileBytes: 2, MaxTotalBytes: 1},
	} {
		if _, err := CompileExportPolicy(invalid, nil); err == nil {
			t.Fatalf("invalid export policy was compiled: %+v", invalid)
		}
	}
}

func TestPolicyRejectsWebQuotaAboveGatewayMaximum(t *testing.T) {
	project, _ := filepath.EvalSymlinks(t.TempDir())
	candidate, err := New(project, strings.Repeat("a", 64), "1.18.16", "1.2.2", "sunaba-base:test", "secure", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	candidate.Web.Enabled = true
	candidate.Web.Rules = []webgateway.OriginRule{{Host: "allowed.example", Port: 443, Category: "user", AllowConnect: true}}
	candidate.Web.CustomRules = append([]webgateway.OriginRule(nil), candidate.Web.Rules...)
	candidate.Web.OriginPresets = nil
	candidate.Web.OriginPresetSHA256 = ""
	candidate.Web.BlocklistManifest = filepath.Join(project, "blocklist.json")
	candidate.Web.BlocklistSHA256 = strings.Repeat("b", 64)
	candidate.Web.MaxConcurrent = webgateway.MaximumMaxConcurrent + 1
	if err := candidate.Validate(); err == nil {
		t.Fatal("oversized Web quota was accepted")
	}
}

func TestLegacyV1MigratesAtomicallyToStrictV6(t *testing.T) {
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
	if !strings.Contains(string(data), `"schema_version": 6`) || !strings.Contains(string(data), `"auth": "api_key"`) || strings.Contains(string(data), `"web_origins"`) {
		t.Fatalf("policy file was not atomically replaced with v6: %s", data)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(directory, ".sunaba-policy-*.tmp")); len(leftovers) != 0 {
		t.Fatalf("migration temporary files remained: %v", leftovers)
	}
}

func TestLegacyV5WebRulesMigrateWithoutExpandingAccess(t *testing.T) {
	project, _ := filepath.EvalSymlinks(t.TempDir())
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	legacy, err := New(project, strings.Repeat("f", 64), "1.18.16", "1.2.2", "sunaba-base:1.18.16-secure.1", "secure", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	legacyRule := webgateway.OriginRule{Host: "legacy.example", Port: 443, Category: "general", AllowConnect: true}
	migratedRule := legacyRule
	migratedRule.Category = "user"
	legacy.SchemaVersion = 5
	legacy.Web.Enabled = true
	legacy.Web.OriginPresets = nil
	legacy.Web.OriginPresetSHA256 = ""
	legacy.Web.CustomRules = nil
	legacy.Web.Rules = []webgateway.OriginRule{legacyRule}
	legacy.Web.BlocklistManifest = filepath.Join(project, "blocklist.json")
	legacy.Web.BlocklistSHA256 = strings.Repeat("1", 64)
	encoded, _ := json.Marshal(legacy)
	var legacyDocument map[string]any
	if err := json.Unmarshal(encoded, &legacyDocument); err != nil {
		t.Fatal(err)
	}
	legacyWeb := legacyDocument["web"].(map[string]any)
	delete(legacyWeb, "origin_presets")
	delete(legacyWeb, "origin_preset_sha256")
	delete(legacyWeb, "custom_rules")
	encoded, _ = json.Marshal(legacyDocument)
	root, _ := filepath.EvalSymlinks(t.TempDir())
	path := filepath.Join(root, "state", "policy.json")
	if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	migrated, changed, err := LoadAndMigrate(path, now)
	if err != nil || !changed || len(migrated.Web.OriginPresets) != 0 || !reflect.DeepEqual(migrated.Web.CustomRules, []webgateway.OriginRule{migratedRule}) || !reflect.DeepEqual(migrated.Web.Rules, []webgateway.OriginRule{migratedRule}) {
		t.Fatalf("migrated=%+v changed=%v error=%v", migrated.Web, changed, err)
	}
}

func TestLegacyV2MigratesStringRemotesToNamedV4Remotes(t *testing.T) {
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

func TestLegacyV3MigratesOnlyOldDefaultModelLimits(t *testing.T) {
	project, _ := filepath.EvalSymlinks(t.TempDir())
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	current, err := New(project, strings.Repeat("d", 64), "1.18.16", "1.2.2", "sunaba-base:1.18.16-secure.1", "secure", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	writeAndMigrate := func(t *testing.T, model ModelPolicy) ProjectPolicy {
		t.Helper()
		legacy := current
		legacy.SchemaVersion = 3
		legacy.Model = model
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
		if err != nil || !changed || migrated.SchemaVersion != CurrentSchemaVersion {
			t.Fatalf("migrated=%+v changed=%v error=%v", migrated, changed, err)
		}
		return migrated
	}
	t.Run("old defaults", func(t *testing.T) {
		migrated := writeAndMigrate(t, ModelPolicy{AllowedModels: []string{"gpt-5"}, MaxRequests: 100, MaxConcurrent: 2, MaxRequestBytes: 4 << 20, MaxResponseBytes: 16 << 20})
		if migrated.Model.MaxRequests != modelgateway.DefaultMaxRequests || migrated.Model.MaxConcurrent != modelgateway.DefaultMaxConcurrent || migrated.Model.MaxRequestBytes != modelgateway.DefaultMaxRequestBytes || migrated.Model.MaxResponseBytes != modelgateway.DefaultMaxResponseBytes {
			t.Fatalf("old defaults were not upgraded: %+v", migrated.Model)
		}
	})
	t.Run("custom limits", func(t *testing.T) {
		custom := ModelPolicy{AuthMode: modelcatalog.AuthAPIKey, AllowedModels: []string{"gpt-5"}, MaxRequests: 250, MaxConcurrent: 3, MaxRequestBytes: 8 << 20, MaxResponseBytes: 24 << 20}
		migrated := writeAndMigrate(t, custom)
		if !reflect.DeepEqual(migrated.Model, custom) {
			t.Fatalf("custom limits changed: got=%+v want=%+v", migrated.Model, custom)
		}
	})
}

func TestLegacyV4AddsAPIKeyAuthentication(t *testing.T) {
	project, _ := filepath.EvalSymlinks(t.TempDir())
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	legacy, err := New(project, strings.Repeat("e", 64), "1.18.16", "1.2.2", "sunaba-base:1.18.16-secure.1", "secure", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	legacy.SchemaVersion = 4
	encoded, _ := json.Marshal(legacy)
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	delete(document["model"].(map[string]any), "auth")
	encoded, _ = json.Marshal(document)
	root, _ := filepath.EvalSymlinks(t.TempDir())
	path := filepath.Join(root, "state", "policy.json")
	if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	migrated, changed, err := LoadAndMigrate(path, now)
	if err != nil || !changed || migrated.Model.AuthMode != modelcatalog.AuthAPIKey || migrated.SchemaVersion != CurrentSchemaVersion {
		t.Fatalf("migrated=%+v changed=%v error=%v", migrated.Model, changed, err)
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

func TestLoadReadOnlyMigratesOnlyInMemory(t *testing.T) {
	project, _ := filepath.EvalSymlinks(t.TempDir())
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	legacy, err := New(project, strings.Repeat("e", 64), "1.18.16", "1.2.2", "sunaba-base:1.18.16-secure.1", "secure", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	legacy.SchemaVersion = 4
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, migrated, err := LoadReadOnly(path, now)
	if err != nil || !migrated || loaded.SchemaVersion != CurrentSchemaVersion {
		t.Fatalf("loaded schema=%d migrated=%v error=%v", loaded.SchemaVersion, migrated, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, encoded) {
		t.Fatalf("read-only load modified policy: error=%v", err)
	}
}
