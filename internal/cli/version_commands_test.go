package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"sunaba/internal/dependency"
	"sunaba/internal/policy"
	"sunaba/internal/projectconfig"
	"sunaba/internal/state"
	"sunaba/internal/versionconfig"
)

func TestSetupConfigOnlyCreatesHostDeclarationWithoutLock(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	a := &app{
		store:   &state.Store{Root: filepath.Join(base, "data", "sunaba")},
		configs: &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")},
		output:  &output, errors: io.Discard,
	}
	if err := a.run(context.Background(), []string{"setup", "--config-only"}); err != nil {
		t.Fatal(err)
	}
	versions := &versionconfig.Store{Root: a.configs.Root}
	config, err := versions.LoadConfig()
	if err != nil || config.OpenCode.Strategy != "exact" || config.OpenCode.Value != "1.18.16" {
		t.Fatalf("config=%+v error=%v", config, err)
	}
	paths, _ := versions.Paths()
	if _, err := os.Lstat(paths.Lock); !os.IsNotExist(err) {
		t.Fatalf("config-only created an active lock: %v", err)
	}
	if info, err := os.Lstat(paths.Config); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("unsafe declaration info=%v error=%v", info, err)
	}
}

func TestProjectInitFailsClosedBeforeSetup(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	a := &app{
		store:   &state.Store{Root: filepath.Join(base, "data", "sunaba")},
		configs: &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")},
		output:  io.Discard, errors: io.Discard,
	}
	err := a.run(context.Background(), []string{"project", "init", project})
	if err == nil || !strings.Contains(err.Error(), "sunaba setup") {
		t.Fatalf("error=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(a.store.Root, "projects", state.ProjectID(project))); !os.IsNotExist(err) {
		t.Fatalf("project state was created before setup: %v", err)
	}
}

func TestSetupRejectsMismatchedLegacyGlobalVersionBeforeHostMutation(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	a := &app{
		store:   &state.Store{Root: filepath.Join(base, "data", "sunaba")},
		configs: &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")},
		runtime: &projectListRuntime{}, output: io.Discard, errors: io.Discard,
	}
	if err := a.store.SaveGlobal(state.GlobalConfig{ImageVersion: "1.17.0"}); err != nil {
		t.Fatal(err)
	}
	err := a.setup(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "cannot be migrated") {
		t.Fatalf("error=%v", err)
	}
	versions := &versionconfig.Store{Root: a.configs.Root}
	paths, _ := versions.Paths()
	if _, err := os.Lstat(paths.Lock); !os.IsNotExist(err) {
		t.Fatalf("mismatched legacy state created a lock: %v", err)
	}
}

func TestVersionsSetAndTrackDoNotChangeActiveLock(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	a := &app{
		store:   &state.Store{Root: filepath.Join(base, "data", "sunaba")},
		configs: &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")},
		output:  io.Discard, errors: io.Discard,
	}
	prepareTestSetup(t, a)
	versions := &versionconfig.Store{Root: a.configs.Root}
	before, err := versions.LoadLock()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.run(context.Background(), []string{"versions", "set", "1.99.0"}); err != nil {
		t.Fatal(err)
	}
	after, err := versions.LoadLock()
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("exact selection changed active lock: before=%+v after=%+v error=%v", before, after, err)
	}
	if err := a.run(context.Background(), []string{"versions", "track", "v1-stable"}); err != nil {
		t.Fatal(err)
	}
	config, err := versions.LoadConfig()
	if err != nil || config.OpenCode.Strategy != "channel" {
		t.Fatalf("config=%+v error=%v", config, err)
	}
	afterTrack, err := versions.LoadLock()
	if err != nil || !reflect.DeepEqual(afterTrack, before) {
		t.Fatalf("channel selection changed active lock: before=%+v after=%+v error=%v", before, afterTrack, err)
	}
}

func TestDependencyUpdateTransactionMigratesProjectLockAndGlobalState(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	projectRoot := filepath.Join(base, "project")
	if err := os.Mkdir(projectRoot, 0700); err != nil {
		t.Fatal(err)
	}
	a := &app{
		store:   &state.Store{Root: filepath.Join(base, "data", "sunaba")},
		configs: &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")},
		runtime: &projectListRuntime{}, output: io.Discard, errors: io.Discard,
	}
	prepareTestSetup(t, a)
	if err := a.run(context.Background(), []string{"project", "init", projectRoot}); err != nil {
		t.Fatal(err)
	}
	versions := &versionconfig.Store{Root: a.configs.Root}
	current, err := versions.LoadLock()
	if err != nil {
		t.Fatal(err)
	}
	projects, err := a.inventoryProjectsForUpdate(context.Background(), current.Manifest)
	if err != nil || len(projects) != 1 {
		t.Fatalf("projects=%+v error=%v", projects, err)
	}
	targetManifest := testUpdateManifest("1.19.0")
	target := versionconfig.Lock{SchemaVersion: 1, Generation: 2, ResolvedAt: time.Now().UTC(), Manifest: targetManifest}
	if err := a.commitDependencyUpdate(current, target, true, projects); err != nil {
		t.Fatal(err)
	}
	loadedLock, err := versions.LoadLock()
	if err != nil || loadedLock.Generation != 2 || loadedLock.Manifest.OpenCode.Version != "1.19.0" {
		t.Fatalf("lock=%+v error=%v", loadedLock, err)
	}
	active, err := a.store.LoadActiveDependency()
	if err != nil || active.Generation != 2 || active.OpenCodeVersion != "1.19.0" {
		t.Fatalf("active=%+v error=%v", active, err)
	}
	policyPath := filepath.Join(a.store.Root, "projects", state.ProjectID(projectRoot), "policy.json")
	loadedPolicy, _, err := policy.LoadReadOnly(policyPath, time.Now())
	if err != nil || loadedPolicy.Dependency.OpenCode != "1.19.0" || loadedPolicy.Dependency.AgentImage != targetManifest.AgentImage.Tag {
		t.Fatalf("policy=%+v error=%v", loadedPolicy.Dependency, err)
	}
	if _, err := os.Lstat(filepath.Join(a.store.Root, "updates", "apply-journal.json")); !os.IsNotExist(err) {
		t.Fatalf("committed transaction retained journal: %v", err)
	}
}

func TestDependencyUpdateRecoveryFollowsJournalDecision(t *testing.T) {
	for _, phase := range []string{"prepared", "commit-decided"} {
		t.Run(phase, func(t *testing.T) {
			base, _ := filepath.EvalSymlinks(t.TempDir())
			a := &app{
				store:   &state.Store{Root: filepath.Join(base, "data", "sunaba")},
				configs: &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")},
				output:  io.Discard, errors: io.Discard,
			}
			prepareTestSetup(t, a)
			versions := &versionconfig.Store{Root: a.configs.Root}
			source, err := versions.LoadLock()
			if err != nil {
				t.Fatal(err)
			}
			target := versionconfig.Lock{SchemaVersion: 1, Generation: 2, ResolvedAt: time.Now().UTC(), Manifest: testUpdateManifest("1.19.0")}
			journalPath := filepath.Join(a.store.Root, "updates", "apply-journal.json")
			if err := writePrivateJSON(journalPath, updateJournal{SchemaVersion: 1, Phase: phase, SourceActive: true, SourceLock: source, TargetLock: target}); err != nil {
				t.Fatal(err)
			}
			recovered, err := a.recoverDependencyUpdate()
			if err != nil || !recovered {
				t.Fatalf("recovered=%t error=%v", recovered, err)
			}
			loaded, err := versions.LoadLock()
			want := source.Manifest.OpenCode.Version
			if phase == "commit-decided" {
				want = target.Manifest.OpenCode.Version
			}
			if err != nil || loaded.Manifest.OpenCode.Version != want {
				t.Fatalf("lock version=%q want=%q error=%v", loaded.Manifest.OpenCode.Version, want, err)
			}
		})
	}
}

func testUpdateManifest(version string) dependency.Manifest {
	manifest := dependency.MustPinned()
	manifest.OpenCode.Version = version
	manifest.OpenCode.Host.URL = "https://github.com/anomalyco/opencode/releases/download/v" + version + "/" + manifest.OpenCode.Host.Artifact
	manifest.OpenCode.Guest.URL = "https://github.com/anomalyco/opencode/releases/download/v" + version + "/" + manifest.OpenCode.Guest.Artifact
	manifest.AgentImage.Tag = "sunaba-base:" + version + "-secure.1"
	manifest.Provenance.OpenCode.Tag = "v" + version
	manifest.Provenance.OpenCode.Commit = strings.Repeat("1", 40)
	return manifest
}
