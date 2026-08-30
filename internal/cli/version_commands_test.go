package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	"sunaba/internal/securefs"
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
	if err != nil || config.OpenCode.Strategy != "exact" || config.OpenCode.Value != dependency.OpenCodeVersion {
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

func TestLegacyBootstrapLockMigrationPreservesProjectState(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	projectRoot := filepath.Join(base, "project")
	if err := os.Mkdir(projectRoot, 0700); err != nil {
		t.Fatal(err)
	}
	a := &app{
		store:   &state.Store{Root: filepath.Join(base, "data", "sunaba")},
		configs: &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")},
		output:  io.Discard, errors: io.Discard,
	}
	if err := a.store.Init(); err != nil {
		t.Fatal(err)
	}
	versions, err := a.versionStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := versions.SaveConfig(versionconfig.BootstrapConfig()); err != nil {
		t.Fatal(err)
	}
	pinned := dependency.MustPinned()
	legacy := legacyVersionLock{
		SchemaVersion: versionconfig.SchemaVersion, Generation: 7,
		ResolvedAt: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC), Manifest: legacyManifestFromCurrent(pinned),
	}
	paths, _ := versions.Paths()
	if err := writePrivateJSON(paths.Lock, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := versions.LoadLock(); err == nil {
		t.Fatal("legacy lock unexpectedly passed the current lock schema")
	}
	if _, err := a.activeVersionLock(); !errors.Is(err, errLegacyDependencyMigrationRequired) || strings.Contains(err.Error(), "Bun build tool") {
		t.Fatalf("legacy lock classification error=%v", err)
	}
	for name, check := range map[string]func() error{
		"versions show": a.showVersions,
		"update check":  func() error { return a.updateCheck(context.Background()) },
		"update apply":  func() error { return a.updateApply(context.Background()) },
	} {
		if err := check(); !errors.Is(err, errLegacyDependencyMigrationRequired) || strings.Contains(err.Error(), "Bun build tool") {
			t.Fatalf("%s legacy lock error=%v", name, err)
		}
	}
	migrated, legacyDigest, legacyRaw, err := loadLegacyBootstrapLock(versions, pinned)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Generation != legacy.Generation || migrated.Manifest.Bun.Version == "" || migrated.Manifest.OpenTUI.Version == "" || migrated.Manifest.SunabaUI.SHA256 == "" {
		t.Fatalf("migrated lock=%+v", migrated)
	}
	legacyBinding := state.DependencyBinding{
		Generation: legacy.Generation, ManifestSHA256: legacyDigest,
		OpenCodeVersion: pinned.OpenCode.Version, AppleContainerVersion: pinned.AppleContainer.Version, AgentImage: pinned.AgentImage.Tag,
	}
	if err := a.store.SaveGlobal(state.GlobalConfig{SchemaVersion: 2, Active: &legacyBinding}); err != nil {
		t.Fatal(err)
	}
	projectPolicy, err := policy.New(projectRoot, legacyDigest, pinned.OpenCode.Version, pinned.AppleContainer.Version, pinned.AgentImage.Tag, "secure", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	projectState := filepath.Join(a.store.Root, "projects", projectPolicy.ProjectID)
	if err := os.Mkdir(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(projectState, "policy.json")
	if err := policy.Save(policyPath, projectPolicy); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"vm-state.sentinel", "pending-change-set.sentinel"} {
		if err := os.WriteFile(filepath.Join(projectState, name), []byte("preserve"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	target := versionconfig.Lock{
		SchemaVersion: versionconfig.SchemaVersion, Generation: legacy.Generation,
		ResolvedAt: time.Now().UTC(), Manifest: pinned,
	}
	if err := a.commitLegacyDependencyMigration(target, []updateProject{{Path: policyPath, Policy: projectPolicy}}, legacyDependencySource{Lock: legacyRaw, Binding: legacyBinding}); err != nil {
		t.Fatal(err)
	}
	loaded, err := versions.LoadLock()
	if err != nil || loaded.Manifest.SunabaUI.SHA256 != pinned.SunabaUI.SHA256 || loaded.Generation != legacy.Generation {
		t.Fatalf("lock=%+v error=%v", loaded, err)
	}
	currentDigest, err := dependency.ManifestDigest(pinned)
	if err != nil {
		t.Fatal(err)
	}
	active, err := a.store.LoadActiveDependency()
	if err != nil || active.ManifestSHA256 != currentDigest || active.Generation != legacy.Generation {
		t.Fatalf("active=%+v error=%v", active, err)
	}
	updatedPolicy, _, err := policy.LoadReadOnly(policyPath, time.Now())
	if err != nil || updatedPolicy.ProjectID != projectPolicy.ProjectID || updatedPolicy.ProjectRoot != projectPolicy.ProjectRoot || updatedPolicy.Dependency.ManifestSHA256 != currentDigest {
		t.Fatalf("Project policy=%+v error=%v", updatedPolicy, err)
	}
	for _, name := range []string{"vm-state.sentinel", "pending-change-set.sentinel"} {
		data, err := os.ReadFile(filepath.Join(projectState, name))
		if err != nil || string(data) != "preserve" {
			t.Fatalf("%s changed: %q error=%v", name, data, err)
		}
	}
}

func TestProtocolV1UIFullLockRequiresExactSetupMigration(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	a := &app{
		store: &state.Store{Root: filepath.Join(base, "data", "sunaba")}, configs: &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")},
		runtime: &projectListRuntime{}, output: io.Discard, errors: io.Discard,
	}
	if err := a.store.Init(); err != nil {
		t.Fatal(err)
	}
	versions, err := a.versionStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := versions.SaveConfig(versionconfig.BootstrapConfig()); err != nil {
		t.Fatal(err)
	}
	pinned := dependency.MustPinned()
	previous := versionconfig.Lock{
		SchemaVersion: versionconfig.SchemaVersion, Generation: 9, ResolvedAt: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC),
		Manifest: dependency.LegacySunabaUIV1Manifest(pinned),
	}
	paths, _ := versions.Paths()
	if err := writePrivateJSON(paths.Lock, previous); err != nil {
		t.Fatal(err)
	}
	if _, err := versions.LoadLock(); err == nil {
		t.Fatal("protocol-v1 sunaba-ui lock passed the protocol-v3 contract")
	}
	if _, err := a.activeVersionLock(); !errors.Is(err, errLegacyDependencyMigrationRequired) {
		t.Fatalf("old full UI lock classification error=%v", err)
	}
	migrated, previousDigest, _, err := loadLegacyBootstrapLock(versions, pinned)
	if err != nil || previousDigest == "" || migrated.Generation != previous.Generation || !reflect.DeepEqual(migrated.Manifest, pinned) {
		t.Fatalf("migrated=%+v digest=%q error=%v", migrated, previousDigest, err)
	}
	projectRoot := filepath.Join(base, "project")
	if err := os.Mkdir(projectRoot, 0700); err != nil {
		t.Fatal(err)
	}
	projectPolicy, err := policy.New(projectRoot, previousDigest, pinned.OpenCode.Version, pinned.AppleContainer.Version, pinned.AgentImage.Tag, "secure", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	projectState := filepath.Join(a.store.Root, "projects", projectPolicy.ProjectID)
	if err := os.Mkdir(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(projectState, "policy.json")
	if err := policy.Save(policyPath, projectPolicy); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.inventoryBootstrapProjectsForSetup(context.Background(), pinned, ""); err == nil {
		t.Fatal("protocol-v1 Project dependency passed without its verified migration source digest")
	}
	projects, migrationNeeded, err := a.inventoryBootstrapProjectsForSetup(context.Background(), pinned, previousDigest)
	if err != nil || len(projects) != 1 || !migrationNeeded {
		t.Fatalf("projects=%+v migrationNeeded=%t error=%v", projects, migrationNeeded, err)
	}
	projectPolicy.Dependency.ManifestSHA256 = strings.Repeat("f", 64)
	if err := policy.Save(policyPath, projectPolicy); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.inventoryBootstrapProjectsForSetup(context.Background(), pinned, previousDigest); err == nil {
		t.Fatal("modified protocol-v1 Project dependency was accepted for migration")
	}
	previous.Manifest.OpenTUI.Version = "0.5.8"
	if encoded, err := json.Marshal(previous); err != nil {
		t.Fatal(err)
	} else if _, _, err := decodeLegacyBootstrapLock(encoded, pinned); err == nil {
		t.Fatal("modified protocol-v1 dependency lock was accepted for migration")
	}
}

func TestPreviousProtocolV2ArtifactRequiresExactSetupMigration(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	a := &app{
		store: &state.Store{Root: filepath.Join(base, "data", "sunaba")}, configs: &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")},
		runtime: &projectListRuntime{}, output: io.Discard, errors: io.Discard,
	}
	if err := a.store.Init(); err != nil {
		t.Fatal(err)
	}
	versions, err := a.versionStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := versions.SaveConfig(versionconfig.BootstrapConfig()); err != nil {
		t.Fatal(err)
	}
	pinned := dependency.MustPinned()
	previous := versionconfig.Lock{
		SchemaVersion: versionconfig.SchemaVersion, Generation: 10, ResolvedAt: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC),
		Manifest: dependency.PreviousSunabaUIV2Manifest(pinned),
	}
	paths, _ := versions.Paths()
	if err := writePrivateJSON(paths.Lock, previous); err != nil {
		t.Fatal(err)
	}
	if _, err := a.activeVersionLock(); !errors.Is(err, errLegacyDependencyMigrationRequired) {
		t.Fatalf("previous protocol-v2 artifact classification error=%v", err)
	}
	setupLock, err := loadBootstrapLockState(versions, pinned)
	if err != nil || setupLock.Missing || setupLock.SourceManifestDigest == "" || setupLock.Lock.Generation != previous.Generation {
		t.Fatalf("setup lock=%+v error=%v", setupLock, err)
	}
	migrated, previousDigest, _, err := loadLegacyBootstrapLock(versions, pinned)
	if err != nil || previousDigest == "" || migrated.Generation != previous.Generation || !reflect.DeepEqual(migrated.Manifest, pinned) {
		t.Fatalf("migrated=%+v digest=%q error=%v", migrated, previousDigest, err)
	}
	legacyBinding := state.DependencyBinding{
		Generation: previous.Generation, ManifestSHA256: previousDigest,
		OpenCodeVersion: pinned.OpenCode.Version, AppleContainerVersion: pinned.AppleContainer.Version, AgentImage: pinned.AgentImage.Tag,
	}
	globalState := state.GlobalConfig{SchemaVersion: 2, Active: &legacyBinding}
	if err := validateBootstrapGlobalState(globalState, setupLock, pinned); err != nil {
		t.Fatalf("matching protocol-v2 global binding was rejected: %v", err)
	}
	changedBinding := legacyBinding
	changedBinding.ManifestSHA256 = strings.Repeat("e", 64)
	globalState.Active = &changedBinding
	if err := validateBootstrapGlobalState(globalState, setupLock, pinned); err == nil {
		t.Fatal("modified protocol-v2 global binding was accepted")
	}
	projectRoot := filepath.Join(base, "project")
	if err := os.Mkdir(projectRoot, 0700); err != nil {
		t.Fatal(err)
	}
	projectPolicy, err := policy.New(projectRoot, previousDigest, pinned.OpenCode.Version, pinned.AppleContainer.Version, pinned.AgentImage.Tag, "secure", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	projectState := filepath.Join(a.store.Root, "projects", projectPolicy.ProjectID)
	if err := os.Mkdir(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	if err := policy.Save(filepath.Join(projectState, "policy.json"), projectPolicy); err != nil {
		t.Fatal(err)
	}
	projects, migrationNeeded, err := a.inventoryBootstrapProjectsForSetup(context.Background(), pinned, previousDigest)
	if err != nil || len(projects) != 1 || !migrationNeeded {
		t.Fatalf("projects=%+v migrationNeeded=%t error=%v", projects, migrationNeeded, err)
	}
	previous.Manifest.SunabaUI.SHA256 = strings.Repeat("f", 64)
	if err := writePrivateJSON(paths.Lock, previous); err != nil {
		t.Fatal(err)
	}
	if _, err := a.activeVersionLock(); err == nil || errors.Is(err, errLegacyDependencyMigrationRequired) {
		t.Fatalf("modified protocol-v2 dependency lock classification error=%v", err)
	}
	if encoded, err := json.Marshal(previous); err != nil {
		t.Fatal(err)
	} else if _, _, err := decodeLegacyBootstrapLock(encoded, pinned); err == nil {
		t.Fatal("modified protocol-v2 dependency lock was accepted for migration")
	}
}

func TestPreviousProtocolV3ArtifactUsesTheSharedBootstrapMigration(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	versions := &versionconfig.Store{Root: filepath.Join(base, "config", "sunaba")}
	if err := versions.Init(); err != nil {
		t.Fatal(err)
	}
	pinned := dependency.MustPinned()
	previous := versionconfig.Lock{
		SchemaVersion: versionconfig.SchemaVersion, Generation: 11, ResolvedAt: time.Date(2026, 8, 30, 22, 34, 1, 0, time.UTC),
		Manifest: dependency.PreviousSunabaUIV3Manifest(pinned),
	}
	paths, err := versions.Paths()
	if err != nil {
		t.Fatal(err)
	}
	if err := writePrivateJSON(paths.Lock, previous); err != nil {
		t.Fatal(err)
	}
	lockState, err := loadBootstrapLockState(versions, pinned)
	if err != nil || lockState.SourceManifestDigest == "" || lockState.Lock.Generation != previous.Generation || lockState.Lock.Manifest.SunabaUI != pinned.SunabaUI {
		t.Fatalf("state=%+v error=%v", lockState, err)
	}
	encoded, err := json.Marshal(previous.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256(encoded)
	if lockState.SourceManifestDigest != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("source digest=%q want=%x", lockState.SourceManifestDigest, wantDigest)
	}
	legacyBinding := state.DependencyBinding{
		Generation: previous.Generation, ManifestSHA256: lockState.SourceManifestDigest,
		OpenCodeVersion: pinned.OpenCode.Version, AppleContainerVersion: pinned.AppleContainer.Version, AgentImage: pinned.AgentImage.Tag,
	}
	if err := validateBootstrapGlobalState(state.GlobalConfig{SchemaVersion: 2, Active: &legacyBinding}, lockState, lockState.Lock.Manifest); err != nil {
		t.Fatalf("matching protocol-v3 active binding was rejected: %v", err)
	}
	previous.Manifest.SunabaUI.Arch = "x64"
	encoded, err = json.Marshal(previous)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeLegacyBootstrapLock(encoded, pinned); err == nil || !strings.Contains(err.Error(), "known exact sunaba-ui") {
		t.Fatalf("changed protocol-v3 platform was accepted or misclassified: %v", err)
	}
}

func TestProtocolV3MigrationPreservesUpdatedOpenCodeIdentity(t *testing.T) {
	pinned := dependency.MustPinned()
	previousManifest := dependency.PreviousSunabaUIV3Manifest(pinned)
	previousManifest.OpenCode.Version = "1.99.0"
	previousManifest.OpenCode.Host.URL = "https://github.com/anomalyco/opencode/releases/download/v1.99.0/" + previousManifest.OpenCode.Host.Artifact
	previousManifest.OpenCode.Guest.URL = "https://github.com/anomalyco/opencode/releases/download/v1.99.0/" + previousManifest.OpenCode.Guest.Artifact
	previousManifest.AgentImage.Tag = "sunaba-base:1.99.0-secure.1"
	previousManifest.Provenance.OpenCode.Tag = "v1.99.0"
	previousManifest.Provenance.OpenCode.Commit = strings.Repeat("1", 40)
	previous := versionconfig.Lock{
		SchemaVersion: versionconfig.SchemaVersion, Generation: 12,
		ResolvedAt: time.Date(2026, 8, 30, 23, 0, 0, 0, time.UTC), Manifest: previousManifest,
	}
	encoded, err := json.Marshal(previous)
	if err != nil {
		t.Fatal(err)
	}
	migrated, sourceDigest, err := decodeLegacyBootstrapLock(encoded, pinned)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Manifest.OpenCode != previousManifest.OpenCode || migrated.Manifest.Provenance.OpenCode != previousManifest.Provenance.OpenCode || migrated.Manifest.SunabaUI != pinned.SunabaUI {
		t.Fatalf("updated OpenCode identity changed during UI migration: %+v", migrated.Manifest)
	}
	setupLock := bootstrapLockState{Lock: migrated, SourceManifestDigest: sourceDigest, SourceRaw: encoded}
	binding := state.DependencyBinding{
		Generation: previous.Generation, ManifestSHA256: sourceDigest,
		OpenCodeVersion: previousManifest.OpenCode.Version, AppleContainerVersion: previousManifest.AppleContainer.Version, AgentImage: previousManifest.AgentImage.Tag,
	}
	if err := validateBootstrapGlobalState(state.GlobalConfig{SchemaVersion: 2, Active: &binding}, setupLock, migrated.Manifest); err != nil {
		t.Fatalf("updated OpenCode active binding was rejected: %v", err)
	}
}

func TestEarlierProtocolV2ArtifactsRemainEligibleForExactSetupMigration(t *testing.T) {
	pinned := dependency.MustPinned()
	for name, manifest := range map[string]dependency.Manifest{
		"earlier": dependency.EarlierSunabaUIV2Manifest(pinned),
		"older":   dependency.OlderSunabaUIV2Manifest(pinned),
		"oldest":  dependency.OldestSunabaUIV2Manifest(pinned),
		"initial": dependency.InitialSunabaUIV2Manifest(pinned),
	} {
		t.Run(name, func(t *testing.T) {
			previous := versionconfig.Lock{
				SchemaVersion: versionconfig.SchemaVersion,
				Generation:    8,
				ResolvedAt:    time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC),
				Manifest:      manifest,
			}
			encoded, err := json.Marshal(previous)
			if err != nil {
				t.Fatal(err)
			}
			migrated, previousDigest, err := decodeLegacyBootstrapLock(encoded, pinned)
			if err != nil || previousDigest == "" || migrated.Generation != previous.Generation || !reflect.DeepEqual(migrated.Manifest, pinned) {
				t.Fatalf("migrated=%+v digest=%q error=%v", migrated, previousDigest, err)
			}
		})
	}

	previous := versionconfig.Lock{
		SchemaVersion: versionconfig.SchemaVersion,
		Generation:    8,
		ResolvedAt:    time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC),
		Manifest:      dependency.EarlierSunabaUIV2Manifest(pinned),
	}
	previous.Manifest.SunabaUI.SHA256 = strings.Repeat("f", 64)
	encoded, err := json.Marshal(previous)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeLegacyBootstrapLock(encoded, pinned); err == nil {
		t.Fatal("unknown protocol-v2 artifact was accepted for migration")
	}
}

func TestLegacyBootstrapLockMigrationRollsBackPreparedFailure(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	a := &app{
		store:   &state.Store{Root: filepath.Join(base, "data", "sunaba")},
		configs: &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")},
		output:  io.Discard, errors: io.Discard,
	}
	if err := a.store.Init(); err != nil {
		t.Fatal(err)
	}
	versions, err := a.versionStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := versions.SaveConfig(versionconfig.BootstrapConfig()); err != nil {
		t.Fatal(err)
	}
	pinned := dependency.MustPinned()
	legacy := legacyVersionLock{
		SchemaVersion: versionconfig.SchemaVersion, Generation: 9,
		ResolvedAt: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC), Manifest: legacyManifestFromCurrent(pinned),
	}
	paths, _ := versions.Paths()
	if err := writePrivateJSON(paths.Lock, legacy); err != nil {
		t.Fatal(err)
	}
	_, legacyDigest, legacyRaw, err := loadLegacyBootstrapLock(versions, pinned)
	if err != nil {
		t.Fatal(err)
	}
	legacyBinding := state.DependencyBinding{
		Generation: legacy.Generation, ManifestSHA256: legacyDigest,
		OpenCodeVersion: pinned.OpenCode.Version, AppleContainerVersion: pinned.AppleContainer.Version, AgentImage: pinned.AgentImage.Tag,
	}
	if err := a.store.SaveGlobal(state.GlobalConfig{SchemaVersion: 2, Active: &legacyBinding}); err != nil {
		t.Fatal(err)
	}

	projects := make([]updateProject, 0, 2)
	for index := 0; index < 2; index++ {
		projectRoot := filepath.Join(base, fmt.Sprintf("project-%d", index))
		if err := os.Mkdir(projectRoot, 0700); err != nil {
			t.Fatal(err)
		}
		projectPolicy, err := policy.New(projectRoot, legacyDigest, pinned.OpenCode.Version, pinned.AppleContainer.Version, pinned.AgentImage.Tag, "secure", time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		projectState := filepath.Join(a.store.Root, "projects", projectPolicy.ProjectID)
		if err := os.Mkdir(projectState, 0700); err != nil {
			t.Fatal(err)
		}
		policyPath := filepath.Join(projectState, "policy.json")
		if err := policy.Save(policyPath, projectPolicy); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(projectState, "vm-state.sentinel"), []byte("preserve"), 0600); err != nil {
			t.Fatal(err)
		}
		projects = append(projects, updateProject{Path: policyPath, Policy: projectPolicy})
	}
	target := versionconfig.Lock{
		SchemaVersion: versionconfig.SchemaVersion, Generation: legacy.Generation,
		ResolvedAt: time.Now().UTC(), Manifest: pinned,
	}
	injected := errors.New("injected Project save failure")
	err = a.commitDependencyUpdateInternal(target, target, true, projects, &legacyDependencySource{Lock: legacyRaw, Binding: legacyBinding}, func(index int, _ string) error {
		if index == 1 {
			return injected
		}
		return nil
	})
	if !errors.Is(err, injected) {
		t.Fatalf("error=%v", err)
	}
	restoredRaw, err := securefs.ReadOwnedRegular(paths.Lock, 1<<20)
	if err != nil || !bytes.Equal(restoredRaw, legacyRaw) {
		t.Fatalf("restored legacy lock differs: error=%v", err)
	}
	active, err := a.store.LoadActiveDependency()
	if err != nil || active != legacyBinding {
		t.Fatalf("active=%+v error=%v", active, err)
	}
	for _, project := range projects {
		loaded, _, err := policy.LoadReadOnly(project.Path, time.Now())
		if err != nil || loaded.ProjectID != project.Policy.ProjectID || loaded.ProjectRoot != project.Policy.ProjectRoot || loaded.Dependency.ManifestSHA256 != legacyDigest {
			t.Fatalf("Project policy=%+v error=%v", loaded, err)
		}
		sentinel, err := os.ReadFile(filepath.Join(filepath.Dir(project.Path), "vm-state.sentinel"))
		if err != nil || string(sentinel) != "preserve" {
			t.Fatalf("sentinel=%q error=%v", sentinel, err)
		}
	}
	journalPath := filepath.Join(a.store.Root, "updates", "apply-journal.json")
	if _, err := os.Lstat(journalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal was not removed: %v", err)
	}
}

func TestLegacyBootstrapLockMigrationRejectsChangedPinsAndNewFields(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	versions := &versionconfig.Store{Root: filepath.Join(base, "config", "sunaba")}
	if err := versions.SaveConfig(versionconfig.BootstrapConfig()); err != nil {
		t.Fatal(err)
	}
	paths, _ := versions.Paths()
	pinned := dependency.MustPinned()
	legacy := legacyVersionLock{
		SchemaVersion: versionconfig.SchemaVersion, Generation: 1,
		ResolvedAt: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC), Manifest: legacyManifestFromCurrent(pinned),
	}
	legacy.Manifest.OpenCode.Host.SHA256 = strings.Repeat("0", 64)
	if err := writePrivateJSON(paths.Lock, legacy); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := loadLegacyBootstrapLock(versions, pinned); err == nil {
		t.Fatal("legacy lock with changed OpenCode pin was migrated")
	}
	legacy.Manifest = legacyManifestFromCurrent(pinned)
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	encoded = bytes.Replace(encoded, []byte(`"provenance":`), []byte(`"bun":{},"provenance":`), 1)
	if err := os.WriteFile(paths.Lock, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := loadLegacyBootstrapLock(versions, pinned); err == nil {
		t.Fatal("lock mixing legacy and current fields was migrated")
	}
	a := &app{store: &state.Store{Root: filepath.Join(base, "data", "sunaba")}, configs: &projectconfig.Store{Root: versions.Root}}
	if _, err := a.activeVersionLock(); err == nil || errors.Is(err, errLegacyDependencyMigrationRequired) {
		t.Fatalf("mixed-format lock classification error=%v", err)
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
