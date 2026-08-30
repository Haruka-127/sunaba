package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/audit"
	"sunaba/internal/dependency"
	"sunaba/internal/gitgateway"
	"sunaba/internal/lease"
	"sunaba/internal/modelcatalog"
	"sunaba/internal/policy"
	"sunaba/internal/projectconfig"
	"sunaba/internal/recovery"
	"sunaba/internal/runtime"
	"sunaba/internal/session"
	"sunaba/internal/state"
	"sunaba/internal/testutil"
	"sunaba/internal/usersettings"
	"sunaba/internal/versionconfig"
	"sunaba/internal/webgateway"
	"sunaba/internal/workspace"
)

func prepareTestSetup(t *testing.T, a *app) {
	t.Helper()
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
	lock := versionconfig.Lock{SchemaVersion: 1, Generation: 1, ResolvedAt: time.Now().UTC(), Manifest: dependency.MustPinned()}
	if err := versions.SaveLock(lock); err != nil {
		t.Fatal(err)
	}
	binding, err := state.NewDependencyBinding(lock.Generation, lock.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.store.SaveActiveDependency(binding); err != nil {
		t.Fatal(err)
	}
}

func TestHelpDescribesCurrentSecureCLIAndOmitsPrototypeCommands(t *testing.T) {
	var output bytes.Buffer
	a := &app{output: &output}
	for _, args := range [][]string{
		{"help"},
		{"setup", "--help"},
		{"versions", "--help"},
		{"update", "--help"},
		{"project", "help"},
		{"project", "init", "--help"},
		{"credentials", "openai", "--help"},
		{"config", "--help"},
		{"git", "remote", "--help"},
		{"changes", "--help"},
		{"changes", "export", "--help"},
		{"up", "--help"},
		{"exec", "--help"},
		{"destroy", "--help"},
	} {
		if err := a.run(context.Background(), args); err != nil {
			t.Fatal(err)
		}
	}
	text := output.String()
	for _, expected := range []string{"setup", "--config-only", "doctor", "versions", "track", "v1-stable", "update", "check", "credentials", "openai", "[path]", "oauth", "api-key", "project", "init", "list", "config", "validate", "apply", "agent", "console", "exec", "--cwd", "remote", "add", "web", "approvals", "changes", "export", "--discard-external-git", "review", "destroy", "--project-id", "--mode", "secure", "dev", "never bind-mounted"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("help missing %q: %s", expected, text)
		}
	}
	for _, obsolete := range []string{"--no-firewall", "env set", "git set", "reset --full", "automatic approval"} {
		if strings.Contains(text, obsolete) {
			t.Fatalf("help retained obsolete prototype behavior %q", obsolete)
		}
	}
	parseOnly := &app{output: io.Discard, errors: io.Discard}
	err := parseOnly.run(context.Background(), []string{"changes", "export", "--discard-external-git", "--dir", filepath.Join(t.TempDir(), "missing")})
	if err == nil || strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("changes export discard flag was not parsed by the public command: %v", err)
	}
}

func TestCommandTreeRejectsPrefixesAliasesAndMisplacedOptions(t *testing.T) {
	a := &app{output: io.Discard, errors: io.Discard}
	for _, args := range [][]string{
		{"proj", "list"},
		{"git", "remote", "rm"},
		{"git", "set", "--remote", "https://git.example/project.git"},
		{"config", "apply", "--effective"},
		{"web", "refresh", "--origin", "https://example.com"},
		{"destroy", "--yes", "unexpected"},
		{"project", "init", "one", "two"},
		{"up", "--dir", ".", "--project-id", "0123456789ab"},
		{"project", "init", "--mode", "unsafe"},
		{"git", "remote", "add", "--name", "origin"},
		{"firewall", "enable", "--subnet", "192.0.2.0/24"},
		{"project", "list", "--json", "--json"},
	} {
		if err := a.run(context.Background(), args); err == nil {
			t.Errorf("command unexpectedly accepted: %v", args)
		}
	}
}

func TestRenderConfigComparisonShowsFieldAndLineDiffs(t *testing.T) {
	jsonDiff := renderConfigComparison([]byte(`{"session":{"ttl":10,"idle":5}}`), []byte(`{"session":{"ttl":20,"idle":5}}`))
	for _, expected := range []string{"@@ session.ttl @@", "- 10", "+ 20"} {
		if !strings.Contains(jsonDiff, expected) {
			t.Fatalf("JSON diff missing %q: %s", expected, jsonDiff)
		}
	}
	lineDiff := renderConfigComparison([]byte("common\nold\ntail\n"), []byte("common\nnew\ntail\n"))
	for _, expected := range []string{"  common", "- old", "+ new", "  tail"} {
		if !strings.Contains(lineDiff, expected) {
			t.Fatalf("line diff missing %q: %s", expected, lineDiff)
		}
	}
}

func TestVerboseIsPersistentButDoesNotComeFromEnvironment(t *testing.T) {
	store := &state.Store{Root: filepath.Join(t.TempDir(), "state")}
	seenVerbose := false
	a := &app{
		store: store, output: io.Discard, errors: io.Discard,
		runtimeFactory: func(verbose bool) runtime.Runtime {
			seenVerbose = verbose
			return &projectListRuntime{}
		},
	}
	t.Setenv("SUNABA_VERBOSE", "true")
	if err := a.run(context.Background(), []string{"project", "list", "--verbose"}); err != nil {
		t.Fatal(err)
	}
	if !seenVerbose {
		t.Fatal("persistent --verbose was not applied after the subcommand")
	}
	seenVerbose = true
	if err := a.run(context.Background(), []string{"project", "list"}); err != nil {
		t.Fatal(err)
	}
	if seenVerbose {
		t.Fatal("verbose was inherited from process state or environment")
	}
}

func TestProjectInitUsesGlobalAuthenticationDefaults(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "current-project")
	apiProject := filepath.Join(base, "api-project")
	for _, directory := range []string{project, apiProject} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(project); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previous); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
	store := &state.Store{Root: filepath.Join(base, "state")}
	a := &app{store: store, output: io.Discard, errors: io.Discard}
	prepareTestSetup(t, a)
	if err := a.run(context.Background(), []string{"project", "init", "--mode", "secure"}); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := policy.LoadAndMigrate(filepath.Join(store.Root, "projects", state.ProjectID(project), "policy.json"), time.Now())
	expectedOAuth, defaultsErr := modelcatalog.DefaultModels(modelcatalog.AuthOAuth)
	if err != nil || defaultsErr != nil || loaded.ProjectRoot != project || strings.Join(loaded.Model.AllowedModels, ",") != strings.Join(expectedOAuth, ",") {
		t.Fatalf("default Project policy=%+v error=%v defaults_error=%v", loaded, err, defaultsErr)
	}
	if err := a.run(context.Background(), []string{"model", "auth", "api-key"}); err != nil {
		t.Fatal(err)
	}
	if err := a.run(context.Background(), []string{"project", "init", apiProject}); err != nil {
		t.Fatal(err)
	}
	apiPolicy, _, err := policy.LoadAndMigrate(filepath.Join(store.Root, "projects", state.ProjectID(apiProject), "policy.json"), time.Now())
	expectedAPI, defaultsErr := modelcatalog.DefaultModels(modelcatalog.AuthAPIKey)
	if err != nil || defaultsErr != nil || strings.Join(apiPolicy.Model.AllowedModels, ",") != strings.Join(expectedAPI, ",") {
		t.Fatalf("API key Project policy=%+v error=%v defaults_error=%v", apiPolicy, err, defaultsErr)
	}
}

func TestProjectIDSelectsNormalReadAndMutationCommands(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(base, "state", "sunaba")}
	configs := &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")}
	a := &app{store: store, configs: configs, runtime: &projectListRuntime{}, output: io.Discard, errors: io.Discard}
	prepareTestSetup(t, a)
	if err := a.run(context.Background(), []string{"project", "init", project}); err != nil {
		t.Fatal(err)
	}
	projectID := state.ProjectID(project)
	for _, args := range [][]string{
		{"config", "path", "--project-id", projectID},
		{"config", "validate", "--project-id", projectID},
		{"model", "list", "--project-id", projectID},
		{"git", "remote", "list", "--project-id", projectID},
		{"status", "--project-id", projectID},
		{"down", "--project-id", projectID},
	} {
		if err := a.run(context.Background(), args); err != nil {
			t.Fatalf("command %v failed: %v", args, err)
		}
	}
	if err := a.run(context.Background(), []string{"model", "auth", "api-key"}); err != nil {
		t.Fatal(err)
	}
	settings, err := (&usersettings.Store{Root: configs.Root}).Load()
	if err != nil || settings.ModelAuth != modelcatalog.AuthAPIKey {
		t.Fatalf("global model auth=%+v error=%v", settings, err)
	}
	if err := a.run(context.Background(), []string{"status", "--dir", project, "--project-id", projectID}); err == nil {
		t.Fatal("normal command accepted both --dir and --project-id")
	}
}

func TestEveryPublicProjectCommandExposesProjectIDSelector(t *testing.T) {
	commands := [][]string{
		{"config", "path"}, {"config", "edit"}, {"config", "validate"}, {"config", "diff"}, {"config", "apply"}, {"config", "show"},
		{"model", "set"}, {"model", "list"},
		{"up"}, {"agent"}, {"git", "remote", "add"}, {"git", "remote", "remove"}, {"git", "remote", "list"}, {"git", "disable"},
		{"web", "enable"}, {"web", "refresh"}, {"web", "disable"}, {"shell"}, {"exec"}, {"doctor"}, {"status"},
		{"changes", "export"}, {"changes", "review"}, {"changes", "apply"}, {"approvals"}, {"recreate"}, {"down"}, {"destroy"},
	}
	for _, command := range commands {
		var output bytes.Buffer
		a := &app{output: &output, errors: io.Discard}
		args := append(append([]string(nil), command...), "--help")
		if err := a.run(context.Background(), args); err != nil {
			t.Fatalf("help %v failed: %v", command, err)
		}
		if !strings.Contains(output.String(), "--project-id") || !strings.Contains(output.String(), "--dir") {
			t.Errorf("Project selector missing from %v help: %s", command, output.String())
		}
	}
	for _, command := range [][]string{{"project", "init", "--help"}, {"project", "list", "--help"}, {"credentials", "--help"}, {"firewall", "--help"}} {
		var output bytes.Buffer
		a := &app{output: &output, errors: io.Discard}
		if err := a.run(context.Background(), command); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), "--project-id") {
			t.Errorf("non-Project selector command exposed --project-id: %v", command)
		}
	}
}

func TestDestroyByProjectIDWorksWithoutOriginalProjectDirectory(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(base, "state", "sunaba")}
	configs := &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")}
	var output bytes.Buffer
	a := &app{store: store, configs: configs, runtime: &projectListRuntime{}, output: &output, errors: &output}
	prepareTestSetup(t, a)
	if err := a.run(context.Background(), []string{"project", "init", project}); err != nil {
		t.Fatal(err)
	}
	projectID := state.ProjectID(project)
	projectState := filepath.Join(store.Root, "projects", projectID)
	configPaths, err := configs.ProjectPaths(projectID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(project); err != nil {
		t.Fatal(err)
	}
	if err := a.run(context.Background(), []string{"status", "--project-id", projectID}); err == nil {
		t.Fatal("normal Project operation accepted an ID whose Project root is missing")
	}
	if _, err := store.LookupProjectState(projectID); err != nil {
		t.Fatalf("failed normal operation changed Project state: %v", err)
	}
	output.Reset()
	if err := a.run(context.Background(), []string{"destroy", "--project-id", projectID, "--yes"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(projectState); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Project state remained: %v", err)
	}
	if _, err := os.Lstat(configPaths.Directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Project configuration remained: %v", err)
	}
	if !strings.Contains(output.String(), projectID) || !strings.Contains(output.String(), "Host Project files were not removed") {
		t.Fatalf("destroy output=%q", output.String())
	}
}

func TestDestroyByProjectIDRemovesSafeUnknownStateWithoutPolicyOrConfig(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(base, "state", "sunaba")}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	projectID := "0123456789ab"
	projectState := filepath.Join(store.Root, "projects", projectID)
	if err := os.Mkdir(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	configs := &projectconfig.Store{Root: filepath.Join(base, "missing-config", "sunaba")}
	a := &app{store: store, configs: configs, runtime: &projectListRuntime{}, output: io.Discard, errors: io.Discard}
	if err := a.run(context.Background(), []string{"down", "--project-id", projectID}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupProjectState(projectID); err != nil {
		t.Fatalf("down removed safe unknown Project state: %v", err)
	}
	if err := a.run(context.Background(), []string{"destroy", "--project-id", projectID, "--yes"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(projectState); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unknown Project state remained: %v", err)
	}
	if _, err := os.Lstat(configs.Root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destroy created a missing configuration root: %v", err)
	}
}

func TestDestroyProjectSelectorsRequireExactUnambiguousID(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(base, "state", "sunaba")}
	configs := &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")}
	a := &app{store: store, configs: configs, runtime: &projectListRuntime{}, output: io.Discard, errors: io.Discard}
	prepareTestSetup(t, a)
	if err := a.run(context.Background(), []string{"project", "init", project}); err != nil {
		t.Fatal(err)
	}
	projectID := state.ProjectID(project)
	for _, args := range [][]string{
		{"destroy", "--project-id", strings.ToUpper(projectID), "--yes"},
		{"destroy", "--project-id", projectID[:8], "--yes"},
		{"destroy", "--project-id", "abcdefabcdef", "--yes"},
		{"destroy", "--dir", project, "--project-id", projectID, "--yes"},
		{"destroy", "--project-id", projectID, "--project-id", projectID, "--yes"},
	} {
		if err := a.run(context.Background(), args); err == nil {
			t.Errorf("destroy unexpectedly accepted: %v", args)
		}
		if _, err := store.LookupProjectState(projectID); err != nil {
			t.Fatalf("rejected selector changed Project state: %v", err)
		}
	}
	pendingDirectory := filepath.Join(store.Root, "projects", projectID, "pending")
	if err := os.Mkdir(pendingDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pendingDirectory, "change.json"), []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.run(context.Background(), []string{"destroy", "--project-id", projectID, "--yes"}); err == nil || !strings.Contains(err.Error(), "pending Change Set") {
		t.Fatalf("pending Change Set was not protected: %v", err)
	}
	if _, err := store.LookupProjectState(projectID); err != nil {
		t.Fatalf("pending protection changed Project state: %v", err)
	}
}

func TestRecoveryByProjectIDRejectsMismatchedSupervisorIdentity(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(base, "state", "sunaba")}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	projectID := "0123456789ab"
	projectState := filepath.Join(store.Root, "projects", projectID)
	if err := os.Mkdir(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	runtimeBase := testutil.PrivateTempDir(t, "sunaba-destroy-identity-")
	controlled := &controlledSession{
		active: &fakeSessionControlTarget{}, projectID: "different-project", vmID: "vm",
		container: "sunaba-different-project-vm", runtimeRoot: filepath.Join(runtimeBase, "sunaba-vm-vm"),
		workspacePath: "/workspace/sunaba-vm", projectState: projectState, idleTimeout: 15 * time.Minute,
		lastActivity: time.Now(), state: "paused", exit: make(chan struct{}),
	}
	control, err := startApprovalControl(projectState, runtimeBase, nil, controlled)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	a := &app{store: store, runtime: &projectListRuntime{}, output: io.Discard, errors: io.Discard}
	for _, args := range [][]string{
		{"down", "--project-id", projectID},
		{"destroy", "--project-id", projectID, "--yes", "--discard-pending"},
	} {
		err = a.run(context.Background(), args)
		if err == nil || !strings.Contains(err.Error(), "identity does not match") {
			t.Fatalf("mismatched Supervisor was not rejected by %v: %v", args, err)
		}
	}
	if _, err := store.LookupProjectState(projectID); err != nil {
		t.Fatalf("identity rejection changed Project state: %v", err)
	}
}

type projectListRuntime struct {
	runtime.Runtime
	items    []runtime.Info
	err      error
	listHook func()
}

func (r *projectListRuntime) List(context.Context) ([]runtime.Info, error) {
	if r.listHook != nil {
		r.listHook()
	}
	return append([]runtime.Info(nil), r.items...), r.err
}

func TestUpModeHoldsConfigLockAcrossRuntimeBoundaryCheck(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(base, "state")}
	var output bytes.Buffer
	a := &app{store: store, output: &output, errors: &output}
	prepareTestSetup(t, a)
	if err := a.run(context.Background(), []string{"project", "init", project}); err != nil {
		t.Fatal(err)
	}
	projectID := state.ProjectID(project)
	var competingLockErr error
	fake := &projectListRuntime{
		items: []runtime.Info{{
			Name: "sunaba-" + projectID + "-vm123456", State: runtime.StateStopped,
			Labels: map[string]string{"dev.sunaba.owner": "sunaba-supervisor", "dev.sunaba.project": projectID, "dev.sunaba.vm": "vm123456", "dev.sunaba.mode": "secure"},
		}},
		listHook: func() {
			lock, err := store.AcquireConfigLock(projectID)
			competingLockErr = err
			if lock != nil {
				_ = lock.Close()
			}
		},
	}
	a.runtime = fake
	err = a.run(context.Background(), []string{"up", "--dir", project, "--mode", "dev"})
	if err == nil || !strings.Contains(err.Error(), "mode change requires export/recreate") {
		t.Fatalf("mode update did not reach guarded runtime check: %v", err)
	}
	if competingLockErr == nil || !strings.Contains(competingLockErr.Error(), "already being changed") {
		t.Fatalf("runtime check was outside config transaction lock: %v", competingLockErr)
	}
}

func TestProjectListFindsPausedSupervisorAndOwnedForegroundVM(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	store := &state.Store{Root: filepath.Join(base, "state")}
	secureProject := filepath.Join(base, "secure-project")
	devProject := filepath.Join(base, "dev-project")
	for _, project := range []string{secureProject, devProject} {
		if err := os.Mkdir(project, 0700); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	a := &app{store: store, output: &output, errors: &output, runtime: &projectListRuntime{}}
	prepareTestSetup(t, a)
	if err := a.run(context.Background(), []string{"project", "init", secureProject}); err != nil {
		t.Fatal(err)
	}
	if err := a.run(context.Background(), []string{"project", "init", devProject, "--mode", "dev"}); err != nil {
		t.Fatal(err)
	}
	secureID := state.ProjectID(secureProject)
	devID := state.ProjectID(devProject)
	vmID := "v" + strings.Repeat("1", 24)
	runtimeBase := testutil.PrivateTempDir(t, "sunaba-project-list-")
	controlled := &controlledSession{
		active: &fakeSessionControlTarget{}, projectID: secureID, vmID: vmID,
		container:   "sunaba-" + secureID + "-" + vmID,
		runtimeRoot: filepath.Join(runtimeBase, "sunaba-vm-"+vmID), workspacePath: "/workspace/sunaba-vm",
		projectState: filepath.Join(store.Root, "projects", secureID), idleTimeout: 15 * time.Minute, lastActivity: time.Now(), state: "paused", exit: make(chan struct{}),
	}
	control, err := startApprovalControl(controlled.projectState, runtimeBase, nil, controlled)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	a.runtime = &projectListRuntime{items: []runtime.Info{{
		Name: "sunaba-" + devID + "-sdev", State: runtime.StateRunning,
		Labels: map[string]string{"dev.sunaba.owner": "sunaba-supervisor", "dev.sunaba.project": devID, "dev.sunaba.vm": "sdev", "dev.sunaba.mode": "dev"},
	}, {
		Name: "sunaba-foreign-s1", State: runtime.StateRunning,
		Labels: map[string]string{"dev.sunaba.owner": "someone-else", "dev.sunaba.project": devID, "dev.sunaba.session": "s1"},
	}}}
	output.Reset()
	if err := a.run(context.Background(), []string{"project", "list", "--active"}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if !strings.Contains(text, secureID+"  secure  active      paused") || !strings.Contains(text, devID+"  dev     none        running") {
		t.Fatalf("active Project list=%q", text)
	}
	if strings.Contains(text, "ServerPassword") || strings.Contains(text, strings.Repeat("s", 32)) || strings.Contains(text, runtimeBase) {
		t.Fatalf("Project list leaked Supervisor secrets: %q", text)
	}
}

func TestProjectListReportsStaleWithoutMutatingLocatorAndEmitsJSON(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(base, "state")}
	var output bytes.Buffer
	a := &app{store: store, output: &output, errors: &output, runtime: &projectListRuntime{}}
	prepareTestSetup(t, a)
	if err := a.run(context.Background(), []string{"project", "init", project}); err != nil {
		t.Fatal(err)
	}
	projectID := state.ProjectID(project)
	projectState := filepath.Join(store.Root, "projects", projectID)
	runtimeBase := testutil.PrivateTempDir(t, "sunaba-project-list-stale-")
	locator := filepath.Join(projectState, approvalControlLocator)
	if err := writePrivateJSON(locator, approvalLocator{Version: 1, Socket: filepath.Join(runtimeBase, approvalControlSocket)}); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := a.run(context.Background(), []string{"project", "list", "--json"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"supervisor":"stale"`) || !strings.Contains(output.String(), `"project_id":"`+projectID+`"`) {
		t.Fatalf("JSON Project list=%q", output.String())
	}
	if _, err := os.Lstat(locator); err != nil {
		t.Fatalf("read-only list removed stale locator: %v", err)
	}
}

func TestGuestRelayRequiresLinuxAArch64ELF(t *testing.T) {
	header := make([]byte, 64)
	copy(header, []byte{0x7f, 'E', 'L', 'F'})
	header[4], header[5], header[6] = 2, 1, 1
	binary.LittleEndian.PutUint16(header[16:18], 2)
	binary.LittleEndian.PutUint16(header[18:20], 183)
	binary.LittleEndian.PutUint32(header[20:24], 1)
	binary.LittleEndian.PutUint16(header[52:54], 64)
	binary.LittleEndian.PutUint16(header[54:56], 56)
	binary.LittleEndian.PutUint16(header[58:60], 64)
	path := filepath.Join(t.TempDir(), "guest-relay")
	if err := os.WriteFile(path, header, 0700); err != nil {
		t.Fatal(err)
	}
	if err := validateGuestRelay(path); err != nil {
		t.Fatalf("valid ELF/AArch64 header rejected: %v", err)
	}
	if err := validateGuestRelay("/bin/sh"); err == nil {
		t.Fatal("host shell was accepted as the Linux/AArch64 guest relay")
	}
}

func TestHostGitAuthorizationUsesOnlyNonInteractiveCredentialHelper(t *testing.T) {
	bin := t.TempDir()
	git := filepath.Join(bin, "git")
	script := "#!/bin/sh\n" +
		"test \"$GIT_TERMINAL_PROMPT\" = 0 || exit 7\n" +
		"test \"$1 $2\" = \"credential fill\" || exit 8\n" +
		"cat >/dev/null\n" +
		"printf 'username=agent\\npassword=secret\\n'\n"
	if err := os.WriteFile(git, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	authorization, err := hostGitAuthorization(context.Background(), "https://git.example/repository.git")
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "Basic YWdlbnQ6c2VjcmV0" {
		t.Fatalf("unexpected authorization: %q", authorization)
	}
}

func TestEffectivePolicyLoadDoesNotRecoverWhileConfigurationWriterOwnsLock(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(base, "state")}
	var output bytes.Buffer
	a := &app{store: store, output: &output, errors: &output}
	prepareTestSetup(t, a)
	if err := a.run(context.Background(), []string{"project", "init", project}); err != nil {
		t.Fatal(err)
	}
	lock, err := store.AcquireConfigLock(state.ProjectID(project))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, _, _, err := a.loadEffectivePolicy(project); err == nil || !strings.Contains(err.Error(), "already being changed") {
		t.Fatalf("policy loader bypassed the configuration transaction lock: %v", err)
	}
}

func TestGitPolicyManagesMultipleNamedHTTPSRemotesAndRejectsCredentialURLs(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(base, "state")}
	var output bytes.Buffer
	a := &app{store: store, output: &output, errors: &output}
	prepareTestSetup(t, a)
	if err := a.run(context.Background(), []string{"project", "init", project}); err != nil {
		t.Fatal(err)
	}
	if err := a.run(context.Background(), []string{"git", "set", "--remote", "https://git.example/legacy.git", "--dir", project}); err == nil {
		t.Fatal("legacy single-remote command remained accepted")
	}
	if err := a.run(context.Background(), []string{"git", "remote", "add", "--dir", project, "--name", "origin", "--url", "https://git.example/team/repository.git"}); err != nil {
		t.Fatal(err)
	}
	if err := a.run(context.Background(), []string{"git", "remote", "add", "--dir", project, "--name", "upstream", "--url", "https://git.example/team/upstream.git"}); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := policy.LoadAndMigrate(filepath.Join(store.Root, "projects", state.ProjectID(project), "policy.json"), time.Now())
	if err != nil || len(loaded.Git.Remotes) != 2 || loaded.Git.Remotes[0].Name != "origin" || loaded.Git.Remotes[1].Name != "upstream" {
		t.Fatalf("policy=%+v error=%v", loaded.Git, err)
	}
	configStore, err := a.projectConfigStore()
	if err != nil {
		t.Fatal(err)
	}
	config, rules, err := configStore.Load(loaded.ProjectID)
	if err != nil || !projectconfig.Matches(config, rules, loaded) {
		t.Fatalf("Git CLI did not synchronize host configuration: config=%+v error=%v", config.Git, err)
	}
	output.Reset()
	if err := a.run(context.Background(), []string{"git", "remote", "list", "--dir", project}); err != nil || !strings.Contains(output.String(), "origin\thttps://git.example/team/repository.git") || !strings.Contains(output.String(), "upstream\thttps://git.example/team/upstream.git") {
		t.Fatalf("list output=%q error=%v", output.String(), err)
	}
	locator := filepath.Join(store.Root, "projects", state.ProjectID(project), approvalControlLocator)
	if err := os.WriteFile(locator, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := a.run(context.Background(), []string{"git", "disable", "--dir", project}); err != nil || !strings.Contains(output.String(), "active Session is unchanged") {
		t.Fatalf("next-Session policy mutation output=%q error=%v", output.String(), err)
	}
	if err := os.Remove(locator); err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{
		"http://git.example/repository.git",
		"https://token@git.example/repository.git",
		"https://git.example/repository.git?ref=main",
		"https://git.example/repository",
		"https://git.example:8443/repository.git",
	} {
		if err := a.run(context.Background(), []string{"git", "remote", "add", "--dir", project, "--name", "unsafe", "--url", unsafe}); err == nil {
			t.Fatalf("unsafe Git remote accepted: %s", unsafe)
		}
	}
}

func TestModelAuthenticationPolicySwitchesToOAuthCatalogDefault(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(base, "state")}
	var output bytes.Buffer
	a := &app{store: store, output: &output, errors: &output}
	prepareTestSetup(t, a)
	if err := a.run(context.Background(), []string{"project", "init", project}); err != nil {
		t.Fatal(err)
	}
	if err := a.run(context.Background(), []string{"model", "auth", "oauth"}); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := policy.LoadAndMigrate(filepath.Join(store.Root, "projects", state.ProjectID(project), "policy.json"), time.Now())
	expectedDefaults, defaultsErr := modelcatalog.DefaultModels(modelcatalog.AuthOAuth)
	if err != nil || defaultsErr != nil || strings.Join(loaded.Model.AllowedModels, ",") != strings.Join(expectedDefaults, ",") {
		t.Fatalf("model policy=%+v error=%v", loaded.Model, err)
	}
	if err := a.run(context.Background(), []string{"model", "set", "--dir", project, "--model", "gpt-5.5", "--model", "gpt-5.6-sol"}); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := a.run(context.Background(), []string{"model", "list", "--dir", project}); err != nil || !strings.Contains(output.String(), "gpt-5.6-sol\tallowed=true\tcontext=500000\tinput=372000") {
		t.Fatalf("model list=%q error=%v", output.String(), err)
	}
}

func TestProjectInitWithOAuthAllowsEntireCatalogByDefault(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(base, "state")}
	a := &app{store: store, output: io.Discard, errors: io.Discard}
	prepareTestSetup(t, a)
	if err := a.run(context.Background(), []string{"project", "init", project}); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := policy.LoadAndMigrate(filepath.Join(store.Root, "projects", state.ProjectID(project), "policy.json"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	expected, err := modelcatalog.DefaultModels(modelcatalog.AuthOAuth)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(loaded.Model.AllowedModels, ",") != strings.Join(expected, ",") {
		t.Fatalf("allowed models=%v want=%v", loaded.Model.AllowedModels, expected)
	}
}

func TestGitGatewayMuxKeepsNamedRemoteRoutesAndTokensSeparate(t *testing.T) {
	route := func(token, name string) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Header.Get("Authorization") != "Bearer "+token {
				http.Error(response, "unauthorized", http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(response, name)
		})
	}
	server := httptest.NewServer(newGitGatewayMux(map[string]http.Handler{
		"/origin.git":   route("origin-token", "origin"),
		"/upstream.git": route("upstream-token", "upstream"),
	}))
	defer server.Close()

	request := func(path, token string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body)
	}
	if status, body := request("/origin.git/info/refs", "origin-token"); status != http.StatusOK || body != "origin" {
		t.Fatalf("origin route status=%d body=%q", status, body)
	}
	if status, _ := request("/upstream.git/info/refs", "origin-token"); status != http.StatusUnauthorized {
		t.Fatalf("cross-remote token status=%d", status)
	}
	if status, body := request("/upstream.git/info/refs", "upstream-token"); status != http.StatusOK || body != "upstream" {
		t.Fatalf("upstream route status=%d body=%q", status, body)
	}
	if status, _ := request("/unknown.git/info/refs", "upstream-token"); status != http.StatusNotFound {
		t.Fatalf("unknown route status=%d", status)
	}
}

func TestCredentialParserKeepsSupportedSecretMaterialOutOfErrors(t *testing.T) {
	basic, err := parseGitCredential("protocol=https\nhost=git.example\nusername=user\npassword=secret-token\n")
	if err != nil || basic != "Basic dXNlcjpzZWNyZXQtdG9rZW4=" {
		t.Fatalf("authorization=%q error=%v", basic, err)
	}
	bearer, err := parseGitCredential("authtype=Bearer\ncredential=secret-bearer\n")
	if err != nil || bearer != "Bearer secret-bearer" {
		t.Fatalf("authorization=%q error=%v", bearer, err)
	}
	for _, malformed := range []string{
		"username=user\nusername=other\npassword=secret-value\n",
		"username=user\npassword=secret-value\x00\n",
		"username=user\n",
	} {
		_, err := parseGitCredential(malformed)
		if err == nil || strings.Contains(err.Error(), "secret-value") {
			t.Fatalf("malformed credential error=%v", err)
		}
	}
}

func TestWebOriginRulesAreExplicitOriginOnly(t *testing.T) {
	httpsRule, err := originRule("https://packages.example", true)
	if err != nil || httpsRule.Port != 443 || !httpsRule.AllowConnect || httpsRule.AllowHTTP || !httpsRule.IncludeSubdomains {
		t.Fatalf("HTTPS rule=%+v error=%v", httpsRule, err)
	}
	httpRule, err := originRule("http://archive.example/", false)
	if err != nil || httpRule.Port != 80 || !httpRule.AllowHTTP || httpRule.AllowConnect {
		t.Fatalf("HTTP rule=%+v error=%v", httpRule, err)
	}
	for _, unsafe := range []string{
		"https://127.0.0.1",
		"https://packages.example/path",
		"https://user@packages.example",
		"https://packages.example:444",
		"file:///etc/passwd",
	} {
		if _, err := originRule(unsafe, false); err == nil {
			t.Fatalf("unsafe Web origin accepted: %s", unsafe)
		}
	}
}

func TestPrivateWebArtifactRefusesSymlinkReplacement(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "blocklist.hosts")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateBytes(path, []byte("replacement")); err == nil {
		t.Fatal("symlink Web artifact was replaced")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "original" {
		t.Fatal("symlink target was modified")
	}
}

type fakePushBroker struct {
	pending   []gitgateway.PushRequest
	confirmed []string
}

type fakeSessionControlTarget struct {
	paused             int
	resumed            int
	destroyed          int
	exported           int
	commands           [][]string
	output             string
	exportErr          error
	discardExternalGit bool
}

func (f *fakeSessionControlTarget) Pause(context.Context) error { f.paused++; return nil }
func (f *fakeSessionControlTarget) ResumeWith(context.Context, session.Activation) error {
	f.resumed++
	return nil
}
func (f *fakeSessionControlTarget) StopAndExport(context.Context) (session.ExportResult, error) {
	f.exported++
	return session.ExportResult{}, f.exportErr
}
func (f *fakeSessionControlTarget) SetDiscardExternalGitForExport(discard bool) error {
	f.discardExternalGit = discard
	return nil
}

func TestSupervisorExpiryAllowsFreshSessionButRejectsExpiredShell(t *testing.T) {
	target := &fakeSessionControlTarget{}
	fresh := managedActivation{activation: session.Activation{SessionID: "fresh-session", ServerPassword: strings.Repeat("n", 32)}, expiresAt: time.Now().Add(time.Hour)}
	controlled := &controlledSession{
		active: target, projectID: "project", vmID: "vm", sessionID: "session", container: "sunaba-project-vm",
		runtimeRoot: "/private/tmp/sunaba-runtime-test/sunaba-vm-vm", workspacePath: "/workspace/sunaba-session",
		attachURL: "http://127.0.0.1:12345", projectState: "/private/tmp/project", serverPassword: strings.Repeat("s", 32),
		expiresAt: time.Now().Add(-time.Second), idleTimeout: 15 * time.Minute, lastActivity: time.Now(), state: "paused", exit: make(chan struct{}),
		activate: func(context.Context) (managedActivation, error) { return fresh, nil },
	}
	if err := controlled.resume(context.Background()); err != nil || target.resumed != 1 || controlled.sessionID != "fresh-session" {
		t.Fatalf("fresh resume error=%v resumed=%d session=%q", err, target.resumed, controlled.sessionID)
	}
	controlled.expiresAt = time.Now().Add(-time.Second)
	if _, err := controlled.shell(context.Background(), "true"); err == nil || len(target.commands) != 0 {
		t.Fatalf("expired shell error=%v commands=%v", err, target.commands)
	}
}

func TestSupervisorExecUsesExactArgvAndStructuredSanitizedOutput(t *testing.T) {
	target := &fakeSessionControlTarget{output: "safe\n\x1b]52;c;bad\a"}
	controlled := &controlledSession{
		active: target, expiresAt: time.Now().Add(time.Minute), state: "running", lastActivity: time.Now(),
	}
	result, err := controlled.exec(context.Background(), "sub/dir", []string{"printf", "%s", "$(host-command)"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"runuser", "-u", "sunaba-agent", "--", "/run/sunaba/exec-wrapper", "sub/dir", "printf", "%s", "$(host-command)"}
	if len(target.commands) != 1 || strings.Join(target.commands[0], "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("guest argv=%v want=%v", target.commands, want)
	}
	if !strings.ContainsRune(result.Stdout, '\x1b') || result.ExitCode != 0 {
		t.Fatalf("structured result=%+v", result)
	}
	if _, err := controlled.exec(context.Background(), "../escape", []string{"true"}); err == nil || len(target.commands) != 1 {
		t.Fatal("unsafe guest working directory reached runtime")
	}
}

func TestSupervisorHeartbeatExtendsIdleDeadline(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	clock := start
	target := &fakeSessionControlTarget{}
	controlled := &controlledSession{
		active: target, expiresAt: start.Add(time.Hour), idleTimeout: 10 * time.Second,
		lastActivity: start, now: func() time.Time { return clock }, deadlineChanged: make(chan struct{}, 1), deadlineRevision: 1, state: "running", exit: make(chan struct{}),
	}
	initial := controlled.deadlineSnapshot()
	if paused, err := controlled.pauseIfIdle(context.Background(), initial.revision, start.Add(9*time.Second)); err != nil || paused {
		t.Fatal("session expired before its idle deadline")
	}
	clock = clock.Add(8 * time.Second)
	if err := controlled.heartbeat(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-controlled.deadlineChanged:
	default:
		t.Fatal("heartbeat did not notify the idle deadline timer")
	}
	refreshed := controlled.deadlineSnapshot()
	if refreshed.revision == initial.revision || !refreshed.idleDeadline.Equal(start.Add(18*time.Second)) {
		t.Fatalf("refreshed deadline=%s revision=%d initial=%d", refreshed.idleDeadline, refreshed.revision, initial.revision)
	}
	if paused, err := controlled.pauseIfIdle(context.Background(), refreshed.revision, start.Add(17*time.Second)); err != nil || paused {
		t.Fatal("heartbeat did not extend the idle deadline")
	}
	if paused, err := controlled.pauseIfIdle(context.Background(), refreshed.revision, start.Add(18*time.Second)); err != nil || !paused || target.paused != 1 {
		t.Fatal("session remained active at the extended idle deadline")
	}
}

func TestSupervisorDeadlineTimersDisarmWhilePausedAndRejectStaleEvents(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	clock := start
	target := &fakeSessionControlTarget{}
	controlled := &controlledSession{
		active: target, expiresAt: start.Add(time.Hour), idleTimeout: 10 * time.Second, lastActivity: start,
		now: func() time.Time { return clock }, deadlineChanged: make(chan struct{}, 1), deadlineRevision: 1,
		state: "running", exit: make(chan struct{}), gitBroker: &rotatingPushBroker{},
		activate: func(context.Context) (managedActivation, error) {
			return managedActivation{
				activation: session.Activation{SessionID: "resumed", ServerPassword: strings.Repeat("r", 32)},
				expiresAt:  start.Add(2 * time.Hour), idleTimeout: 20 * time.Second,
			}, nil
		},
	}
	deadlines := newSessionDeadlineTimers()
	defer deadlines.disarm()
	initial := controlled.deadlineSnapshot()
	if err := deadlines.reconcile(initial, start); err != nil {
		t.Fatal(err)
	}
	if deadlines.idleC == nil || deadlines.expiryC == nil {
		t.Fatal("running session deadlines were not armed")
	}

	if err := controlled.pause(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-controlled.deadlineChanged:
	default:
		t.Fatal("pause did not notify the deadline owner")
	}
	if err := deadlines.reconcile(controlled.deadlineSnapshot(), clock); err != nil {
		t.Fatal(err)
	}
	if deadlines.idleC != nil || deadlines.expiryC != nil {
		t.Fatal("paused session retained an armed deadline timer")
	}

	clock = start.Add(time.Minute)
	if err := controlled.resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-controlled.deadlineChanged:
	default:
		t.Fatal("resume did not notify the deadline owner")
	}
	resumed := controlled.deadlineSnapshot()
	if err := deadlines.reconcile(resumed, clock); err != nil {
		t.Fatal(err)
	}
	if deadlines.idleC == nil || deadlines.expiryC == nil || deadlines.revision != resumed.revision {
		t.Fatal("resumed session deadlines were not rearmed")
	}
	if paused, err := controlled.pauseIfIdle(context.Background(), initial.revision, clock.Add(time.Hour)); err != nil || paused || target.paused != 1 {
		t.Fatalf("stale deadline affected resumed session: paused=%t count=%d error=%v", paused, target.paused, err)
	}
	if paused, err := controlled.pauseIfIdle(context.Background(), resumed.revision, clock.Add(20*time.Second)); err != nil || !paused || target.paused != 2 {
		t.Fatalf("current idle deadline did not pause once: paused=%t count=%d error=%v", paused, target.paused, err)
	}
	if paused, err := controlled.pauseIfIdle(context.Background(), resumed.revision, clock.Add(time.Hour)); err != nil || paused || target.paused != 2 {
		t.Fatalf("idle deadline paused more than once: paused=%t count=%d error=%v", paused, target.paused, err)
	}
	if err := deadlines.reconcile(controlled.deadlineSnapshot(), clock.Add(20*time.Second)); err != nil {
		t.Fatal(err)
	}
	if deadlines.idleC != nil || deadlines.expiryC != nil {
		t.Fatal("idle pause did not disarm deadline timers")
	}
}

func TestSupervisorAbsoluteExpiryPausesOnce(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	target := &fakeSessionControlTarget{}
	controlled := &controlledSession{
		active: target, expiresAt: start.Add(time.Minute), idleTimeout: time.Hour, lastActivity: start,
		deadlineChanged: make(chan struct{}, 1), deadlineRevision: 1, state: "running", exit: make(chan struct{}),
	}
	snapshot := controlled.deadlineSnapshot()
	if paused, err := controlled.pauseIfExpired(context.Background(), snapshot.revision, start.Add(time.Minute-time.Nanosecond)); err != nil || paused {
		t.Fatalf("session expired early: paused=%t error=%v", paused, err)
	}
	if paused, err := controlled.pauseIfExpired(context.Background(), snapshot.revision, start.Add(time.Minute)); err != nil || !paused || target.paused != 1 {
		t.Fatalf("absolute expiry did not pause once: paused=%t count=%d error=%v", paused, target.paused, err)
	}
	if paused, err := controlled.pauseIfExpired(context.Background(), snapshot.revision, start.Add(2*time.Minute)); err != nil || paused || target.paused != 1 {
		t.Fatalf("absolute expiry paused more than once: paused=%t count=%d error=%v", paused, target.paused, err)
	}
}

func TestSupervisorExportWithoutChangesDestroysPersistentVM(t *testing.T) {
	target := &fakeSessionControlTarget{}
	controlled := &controlledSession{
		active: target, projectID: "project", sessionID: "session", container: "sunaba-project-session",
		runtimeRoot: "/private/tmp/sunaba-runtime-test/sunaba-vm-vm", workspacePath: "/workspace/sunaba-session",
		attachURL: "http://127.0.0.1:12345", projectState: "/private/tmp/project", serverPassword: strings.Repeat("s", 32),
		expiresAt: time.Now().Add(time.Hour), idleTimeout: 15 * time.Minute, lastActivity: time.Now(), state: "paused", exit: make(chan struct{}),
	}
	if err := controlled.exportAndDestroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if target.exported != 1 || target.destroyed != 1 || controlled.state != "exported" {
		t.Fatalf("export lifecycle target=%+v state=%s", target, controlled.state)
	}
	select {
	case <-controlled.exit:
	default:
		t.Fatal("export did not signal supervisor exit")
	}
}

func TestSupervisorExportBindsExternalGitDiscardIntent(t *testing.T) {
	projectState, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	runtimeBase := testutil.PrivateTempDir(t, "sunaba-export-options-")
	target := &fakeSessionControlTarget{}
	controlled := &controlledSession{
		active: target, projectID: "project", sessionID: "session", container: "sunaba-project-session",
		runtimeRoot: filepath.Join(runtimeBase, "sunaba-vm-vm"), workspacePath: "/workspace/sunaba-session",
		projectState: projectState, expiresAt: time.Now().Add(time.Hour), idleTimeout: 15 * time.Minute,
		lastActivity: time.Now(), state: "paused", exit: make(chan struct{}),
	}
	control, err := startApprovalControl(projectState, runtimeBase, nil, controlled)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	client, err := openSupervisorClient(projectState)
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	if err := client.export(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if !target.discardExternalGit || target.exported != 1 || target.destroyed != 1 {
		t.Fatalf("discard=%t exported=%d destroyed=%d", target.discardExternalGit, target.exported, target.destroyed)
	}
}

func TestDevRecoveryPersistenceFailureNeverAuthorizesDestroy(t *testing.T) {
	projectState, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	target := &fakeSessionControlTarget{exportErr: &session.RecoveryRequiredError{Cause: errors.New("external Git unsafe")}}
	persistent := &session.Session{ProjectID: "0123456789ab", ProjectRoot: projectState, VMID: "vm123456", SessionID: "session1", Container: "sunaba-0123456789ab-vm123456", Root: "/invalid", WorkspacePath: "/workspace/sunaba-vm123456", Baseline: workspace.SnapshotManifest{Digest: strings.Repeat("a", 64), Root: projectState}, ExportPolicyDigest: strings.Repeat("b", 64)}
	controlled := &controlledSession{active: target, persistent: persistent, projectState: projectState, state: "running", exit: make(chan struct{})}
	if err := controlled.exportAndDestroy(context.Background()); err == nil || !controlled.recoveryRetained() {
		t.Fatalf("error=%v state=%s", err, controlled.state)
	}
	if target.destroyed != 0 {
		t.Fatal("recovery metadata failure authorized VM destruction")
	}
}

func TestExplicitDevRecoveryDiscardRequiresExactStoppedVMOwnership(t *testing.T) {
	storeRoot, _ := filepath.EvalSymlinks(t.TempDir())
	if err := os.Chmod(storeRoot, 0700); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: storeRoot}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	projectRoot, _ := filepath.EvalSymlinks(t.TempDir())
	const projectID, vmID, sessionID = "0123456789ab", "vm123456", "session1"
	projectState := filepath.Join(storeRoot, "projects", projectID)
	if err := os.MkdirAll(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	projectState, _ = filepath.EvalSymlinks(projectState)
	runtimeBase, err := recovery.NewRuntimeBase(projectState, vmID)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot := filepath.Join(runtimeBase, "sunaba-vm-"+vmID)
	if err := os.MkdirAll(filepath.Join(runtimeRoot, "snapshot"), 0700); err != nil {
		t.Fatal(err)
	}
	baseline, err := workspace.BuildSnapshotManifest(projectRoot, workspace.DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	container := "sunaba-" + projectID + "-" + vmID
	record := recovery.State{Version: recovery.Version, ProjectID: projectID, ProjectRoot: projectRoot, VMID: vmID, SessionID: sessionID, Container: container, RuntimeBase: runtimeBase, RuntimeRoot: runtimeRoot, WorkspacePath: "/workspace/sunaba-" + vmID, Baseline: baseline, ExportPolicyDigest: strings.Repeat("a", 64), Reason: "guard refused", CreatedAt: time.Now().UTC()}
	if err := recovery.Save(projectState, record); err != nil {
		t.Fatal(err)
	}
	locator := filepath.Join(projectState, approvalControlLocator)
	if err := writePrivateJSON(locator, approvalLocator{Version: 1, Socket: filepath.Join(runtimeBase, approvalControlSocket)}); err != nil {
		t.Fatal(err)
	}
	if err := removeRecoverySupervisorLocator(projectState); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(locator); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale recovery locator remained: %v", err)
	}
	fake := &discardRecoveryRuntime{info: runtime.Info{Name: container, State: runtime.StateStopped, Labels: map[string]string{"dev.sunaba.owner": "sunaba-supervisor", "dev.sunaba.project": projectID, "dev.sunaba.vm": vmID, "dev.sunaba.mode": "dev"}}}
	a := &app{store: store, runtime: fake, output: io.Discard, errors: io.Discard}
	fake.info.Labels["dev.sunaba.vm"] = "substituted"
	if err := a.discardDevRecovery(context.Background(), projectID, projectState); err == nil || fake.removed {
		t.Fatalf("substituted labels discard error=%v removed=%t", err, fake.removed)
	}
	fake.info.Labels["dev.sunaba.vm"] = vmID
	if err := a.discardDevRecovery(context.Background(), projectID, projectState); err != nil || !fake.removed {
		t.Fatalf("explicit discard error=%v removed=%t", err, fake.removed)
	}
	if _, err := os.Lstat(recovery.Path(projectState)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery record remained: %v", err)
	}
}

func TestExplicitDiscardRemovesUnrecordedStoppedSecureVM(t *testing.T) {
	storeRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(storeRoot, 0700); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: storeRoot}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	const vmID = "vm123456"
	projectID := state.ProjectID(storeRoot)
	projectState := filepath.Join(storeRoot, "projects", projectID)
	if err := os.MkdirAll(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	runtimeBase, err := recovery.NewSecureRuntimeBase(projectID, vmID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(runtimeBase, "sunaba-vm-"+vmID), 0700); err != nil {
		t.Fatal(err)
	}
	container := "sunaba-" + projectID + "-" + vmID
	fake := &discardRecoveryRuntime{info: runtime.Info{Name: container, State: runtime.StateStopped, Labels: map[string]string{
		"dev.sunaba.owner": "sunaba-supervisor", "dev.sunaba.project": projectID, "dev.sunaba.vm": vmID, "dev.sunaba.mode": "secure",
	}}}
	a := &app{store: store, runtime: fake, output: io.Discard, errors: io.Discard}
	if err := a.discardUnrecordedStoppedVMs(context.Background(), projectID); err != nil {
		t.Fatal(err)
	}
	if !fake.removed {
		t.Fatal("explicit discard did not remove the exact stopped VM")
	}
	if _, err := os.Lstat(runtimeBase); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("explicit discard left runtime state: %v", err)
	}
}

func TestFrozenSecureExportRecoveryRetriesTheSameChangeSet(t *testing.T) {
	storeRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(storeRoot, 0700); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: storeRoot}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	projectRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const vmID, sessionID = "vm123456", "session1"
	projectID := state.ProjectID(projectRoot)
	projectState := filepath.Join(storeRoot, "projects", projectID)
	if err := os.MkdirAll(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	runtimeBase, err := recovery.NewSecureRuntimeBase(projectID, vmID)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot := filepath.Join(runtimeBase, "sunaba-vm-"+vmID)
	snapshotRoot := filepath.Join(runtimeRoot, "snapshot")
	mergedRoot := filepath.Join(runtimeRoot, "sunaba-quarantine-"+sessionID, "sunaba-merged-"+sessionID)
	for _, directory := range []string{snapshotRoot, mergedRoot} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(mergedRoot, "result.txt"), []byte("retained\n"), 0600); err != nil {
		t.Fatal(err)
	}
	projectPolicy := policy.ProjectPolicy{
		ProjectID: projectID, ProjectRoot: projectRoot,
		Export:         policy.ExportPolicy{MaxEntries: 100_000, MaxFileBytes: 64 << 20, MaxTotalBytes: 1 << 30},
		ProtectedPaths: []string{".git", ".sunaba"},
	}
	compiled, err := policy.CompileExportPolicy(projectPolicy.Export, projectPolicy.ProtectedPaths)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := workspace.BuildSnapshotManifest(projectRoot, compiled.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := workspace.BuildSnapshotManifest(mergedRoot, compiled.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := workspace.BuildChangeSet(baseline, merged, compiled.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	container := "sunaba-" + projectID + "-" + vmID
	record := recovery.State{
		Version: recovery.Version, ProjectID: projectID, ProjectRoot: projectRoot, VMID: vmID, SessionID: sessionID,
		Container: container, RuntimeBase: runtimeBase, RuntimeRoot: runtimeRoot, WorkspacePath: "/workspace/sunaba-" + vmID,
		Mode: "secure", Baseline: baseline, ExportPolicyDigest: compiled.Digest,
		PendingExport: &recovery.PendingExport{MergedRoot: mergedRoot, MergedDigest: merged.Digest, ChangeSetDigest: changes.Digest},
		Reason:        "pending write failed", CreatedAt: time.Now().UTC(),
	}
	if err := recovery.Save(projectState, record); err != nil {
		t.Fatal(err)
	}
	active := &session.Session{
		ProjectID: projectID, ProjectRoot: projectRoot, VMID: vmID, SessionID: sessionID, Container: container,
		Baseline: baseline, SnapshotRoot: snapshotRoot, SnapshotPolicy: compiled.Snapshot,
		ExportPolicy: compiled.Export, ExportPolicyDigest: compiled.Digest,
	}
	if _, err := persistPending(projectState, active, session.ExportResult{MergedRoot: mergedRoot, Merged: merged, ChangeSet: changes}); err != nil {
		t.Fatal(err)
	}
	fake := &discardRecoveryRuntime{info: runtime.Info{Name: container, State: runtime.StateStopped, Labels: map[string]string{
		"dev.sunaba.owner": "sunaba-supervisor", "dev.sunaba.project": projectID, "dev.sunaba.vm": vmID, "dev.sunaba.mode": "secure",
	}}}
	recorder, err := audit.NewRecorder(filepath.Join(storeRoot, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	a := &app{store: store, runtime: fake, output: io.Discard, errors: io.Discard}
	if err := a.persistFrozenRecovery(context.Background(), projectState, record, compiled, recorder); err != nil {
		t.Fatal(err)
	}
	pending, err := loadPending(projectState, projectPolicy)
	if err != nil || pending.ChangeSet.Digest != changes.Digest || !fake.removed {
		t.Fatalf("pending=%+v removed=%t error=%v", pending.ChangeSet, fake.removed, err)
	}
	if _, err := os.Lstat(recovery.Path(projectState)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery record remained after retry: %v", err)
	}

	// Simulate a crash after the exact pending commit and VM removal but before
	// recovery metadata retirement. The next retry must retire the stale record
	// without requiring the missing VM.
	runtimeBase, err = recovery.NewSecureRuntimeBase(projectID, vmID)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot = filepath.Join(runtimeBase, "sunaba-vm-"+vmID)
	mergedRoot = filepath.Join(runtimeRoot, "sunaba-quarantine-"+sessionID, "sunaba-merged-"+sessionID)
	for _, directory := range []string{filepath.Join(runtimeRoot, "snapshot"), mergedRoot} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	record.RuntimeBase, record.RuntimeRoot = runtimeBase, runtimeRoot
	record.PendingExport.MergedRoot = mergedRoot
	if err := recovery.Save(projectState, record); err != nil {
		t.Fatal(err)
	}
	if err := a.persistFrozenRecovery(context.Background(), projectState, record, compiled, recorder); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(recovery.Path(projectState)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing-VM recovery record remained after retry: %v", err)
	}
}

type discardRecoveryRuntime struct {
	info    runtime.Info
	removed bool
}

func (f *discardRecoveryRuntime) Inspect(context.Context, string) (runtime.Info, error) {
	return f.info, nil
}
func (f *discardRecoveryRuntime) Remove(context.Context, string) error {
	f.removed = true
	return nil
}
func (f *discardRecoveryRuntime) ImageExists(context.Context, string) (bool, error) {
	return false, nil
}
func (f *discardRecoveryRuntime) BuildImage(context.Context, string, string, map[string]string) error {
	return nil
}
func (f *discardRecoveryRuntime) ContainerState(context.Context, string) (runtime.State, error) {
	if f.removed {
		return runtime.StateNotFound, nil
	}
	return f.info.State, nil
}
func (f *discardRecoveryRuntime) Create(context.Context, runtime.ContainerSpec) error { return nil }
func (f *discardRecoveryRuntime) CreateSecure(context.Context, runtime.ContainerSpec, runtime.SecureSessionPolicy) error {
	return nil
}
func (f *discardRecoveryRuntime) Start(context.Context, string) error                { return nil }
func (f *discardRecoveryRuntime) Stop(context.Context, string) error                 { return nil }
func (f *discardRecoveryRuntime) Exec(context.Context, string, bool, []string) error { return nil }
func (f *discardRecoveryRuntime) ExecOutput(context.Context, string, []string) (string, error) {
	return "", nil
}
func (f *discardRecoveryRuntime) CopyTo(context.Context, string, string, string) error { return nil }
func (f *discardRecoveryRuntime) Export(context.Context, string, string) error         { return nil }
func (f *discardRecoveryRuntime) IPAddress(context.Context, string) (string, error)    { return "", nil }
func (f *discardRecoveryRuntime) List(context.Context) ([]runtime.Info, error) {
	return []runtime.Info{f.info}, nil
}

func TestStaleSupervisorRecoveryRemovesOnlyBoundPrivateRuntime(t *testing.T) {
	projectState, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	runtimeBase, err := recovery.NewRuntimeBase(projectState, "vm123456")
	if err != nil {
		t.Fatal(err)
	}
	locator := filepath.Join(projectState, approvalControlLocator)
	if err := writePrivateJSON(locator, approvalLocator{Version: 1, Socket: filepath.Join(runtimeBase, approvalControlSocket)}); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleSupervisor(projectState); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{locator, runtimeBase} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale path remained %s: %v", path, err)
		}
	}
}

func TestStaleSecureSupervisorRecoveryAcceptsOnlyBoundShortRuntime(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const projectID, vmID = "0123456789ab", "vm123456"
	projectState := filepath.Join(root, projectID)
	if err := os.Mkdir(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	runtimeBase, err := recovery.NewSecureRuntimeBase(projectID, vmID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeBase) })
	locator := filepath.Join(projectState, approvalControlLocator)
	if err := writePrivateJSON(locator, approvalLocator{Version: 1, Socket: filepath.Join(runtimeBase, approvalControlSocket)}); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleSupervisor(projectState); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{locator, runtimeBase} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale secure path remained %s: %v", path, err)
		}
	}
}

func TestClosedSupervisorSocketIsRecognizedAsStale(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const projectID, vmID = "0123456789ab", "vm123456"
	projectState := filepath.Join(root, projectID)
	if err := os.Mkdir(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	runtimeBase, err := recovery.NewSecureRuntimeBase(projectID, vmID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeBase) })
	socket := filepath.Join(runtimeBase, approvalControlSocket)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(socket, 0600); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateJSON(filepath.Join(projectState, approvalControlLocator), approvalLocator{Version: 1, Socket: socket}); err != nil {
		t.Fatal(err)
	}
	if _, err := openSupervisorClient(projectState); !errors.Is(err, errStaleSupervisor) {
		t.Fatalf("closed Unix socket was not recognized as stale: %v", err)
	}
	if err := removeStaleSupervisor(projectState); err != nil {
		t.Fatal(err)
	}
}

func TestStaleSupervisorRecoveryRefusesExactHeldVMGuard(t *testing.T) {
	storeRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(storeRoot, 0700); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: storeRoot}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	const projectID, vmID = "0123456789ab", "vm123456"
	projectState := filepath.Join(storeRoot, "projects", projectID)
	if err := os.MkdirAll(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	runtimeBase, err := recovery.NewSecureRuntimeBase(projectID, vmID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeBase) })
	socket := filepath.Join(runtimeBase, approvalControlSocket)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(socket, 0600); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	locator := filepath.Join(projectState, approvalControlLocator)
	if err := writePrivateJSON(locator, approvalLocator{Version: 1, Socket: socket}); err != nil {
		t.Fatal(err)
	}
	guard, err := (&lease.Registry{Root: filepath.Join(storeRoot, "leases")}).AcquireGuard(vmID)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	container := "sunaba-" + projectID + "-" + vmID
	fake := &discardRecoveryRuntime{info: runtime.Info{Name: container, State: runtime.StateStopped, Labels: map[string]string{
		"dev.sunaba.owner": "sunaba-supervisor", "dev.sunaba.project": projectID, "dev.sunaba.vm": vmID, "dev.sunaba.mode": "secure",
	}}}
	a := &app{store: store, runtime: fake, output: io.Discard, errors: io.Discard}
	if err := a.recoverStaleSupervisor(context.Background(), projectState); err == nil || !strings.Contains(err.Error(), "live owner") {
		t.Fatalf("held VM guard did not block stale recovery: %v", err)
	}
	if _, err := os.Lstat(locator); err != nil {
		t.Fatalf("blocked stale recovery removed locator: %v", err)
	}
}

func (f *fakeSessionControlTarget) Destroy(context.Context) error { f.destroyed++; return nil }
func (f *fakeSessionControlTarget) ExecOutput(_ context.Context, command []string) (string, error) {
	f.commands = append(f.commands, append([]string(nil), command...))
	return f.output, nil
}

func (f *fakeSessionControlTarget) ExecCapture(_ context.Context, command []string, _, _ int64) (runtime.ExecResult, error) {
	f.commands = append(f.commands, append([]string(nil), command...))
	return runtime.ExecResult{Stdout: f.output, ExitCode: 0}, nil
}

func (b *fakePushBroker) Pending() []gitgateway.PushRequest {
	return append([]gitgateway.PushRequest(nil), b.pending...)
}

func (b *fakePushBroker) Confirm(nonce string, _ gitgateway.PushBinding) error {
	b.confirmed = append(b.confirmed, nonce)
	return nil
}

func (b *fakePushBroker) Reject(nonce string, _ gitgateway.PushBinding) error {
	b.confirmed = append(b.confirmed, "rejected:"+nonce)
	return nil
}

func TestApprovalsUseSeparatePrivateHostControlChannel(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	recorder, err := audit.NewRecorder(filepath.Join(root, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := gitgateway.NewPushApprovalManager(nil, recorder, "sunaba-project-session", "session")
	if err != nil {
		t.Fatal(err)
	}
	binding := gitgateway.PushBinding{
		ProjectID: "project", Repository: "repository", RemoteName: "origin", RemoteURL: "https://git.example/repository.git",
		Updates: []gitgateway.RefUpdate{{
			Ref: "refs/heads/main", Old: strings.Repeat("1", 40), New: strings.Repeat("2", 40),
		}},
	}
	request, err := manager.NewRequest(binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	broker := &fakePushBroker{pending: []gitgateway.PushRequest{request}}
	runtimeBase := testutil.PrivateTempDir(t, "sunaba-control-test-")
	control, err := startApprovalControl(root, runtimeBase, broker, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	var output bytes.Buffer
	a := &app{input: strings.NewReader("approve 1\n"), output: &output, errors: &output}
	approved, err := a.approveActivePushes(context.Background(), root)
	if err != nil || approved != 1 || len(broker.confirmed) != 1 || broker.confirmed[0] != request.Nonce {
		t.Fatalf("approved=%d confirmed=%v error=%v output=%s", approved, broker.confirmed, err, output.String())
	}
	if info, err := os.Lstat(filepath.Join(runtimeBase, approvalControlSocket)); err != nil || info.Mode().Perm() != 0600 || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("control socket info=%v error=%v", info, err)
	}
	broker.pending = []gitgateway.PushRequest{request}
	a.input = strings.NewReader("reject " + request.Digest[:12] + "\n")
	if processed, err := a.approveActivePushes(context.Background(), root); err != nil || processed != -1 || broker.confirmed[len(broker.confirmed)-1] != "rejected:"+request.Nonce {
		t.Fatalf("reject processed=%d confirmed=%v error=%v", processed, broker.confirmed, err)
	}
}

func TestSupervisorControlPausesResumesAndSanitizesShell(t *testing.T) {
	projectState, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	runtimeBase := testutil.PrivateTempDir(t, "sunaba-supervisor-test-")
	target := &fakeSessionControlTarget{output: "safe\n\x1b]52;c;evil\a\u202Ename\n"}
	controlled := &controlledSession{
		active: target, projectID: "project", vmID: "vm", sessionID: "session", container: "sunaba-project-vm",
		runtimeRoot: filepath.Join(runtimeBase, "sunaba-vm-vm"), workspacePath: "/workspace/sunaba-vm",
		attachURL: "http://127.0.0.1:12345", projectState: projectState, serverPassword: strings.Repeat("s", 32),
		expiresAt: time.Now().Add(time.Hour), idleTimeout: 15 * time.Minute, lastActivity: time.Now(), state: "running", exit: make(chan struct{}),
		activate: func(context.Context) (managedActivation, error) {
			return managedActivation{activation: session.Activation{SessionID: "new-session", ServerPassword: strings.Repeat("n", 32)}, expiresAt: time.Now().Add(time.Hour), modelUsage: func() (int64, int64) { return 2, 9 }}, nil
		},
		modelUsage: func() (int64, int64) { return 3, 10 },
	}
	control, err := startApprovalControl(projectState, runtimeBase, nil, controlled)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	client, err := openSupervisorClient(projectState)
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	approvalApp := &app{input: strings.NewReader(""), output: io.Discard, errors: io.Discard}
	if count, err := approvalApp.approveActivePushes(context.Background(), projectState); err != nil || count != 0 {
		t.Fatalf("Git-disabled supervisor approvals count=%d error=%v", count, err)
	}
	info, err := client.info(context.Background())
	if err != nil || info.State != "running" || info.Container != "sunaba-project-vm" {
		t.Fatalf("info=%+v error=%v", info, err)
	}
	if info.IdleSeconds != 900 || info.IdleDeadline.IsZero() || info.ModelUsed != 3 || info.ModelLimit != 10 {
		t.Fatalf("idle policy missing from supervisor info: %+v", info)
	}
	execResult, err := client.exec(context.Background(), ".", []string{"printf", "safe"})
	if err != nil || strings.ContainsRune(execResult.Stdout, '\x1b') || !strings.Contains(execResult.Stdout, "<U+001B>") {
		t.Fatalf("Supervisor exec result was not sanitized at the client boundary: result=%+v error=%v", execResult, err)
	}
	if err := client.operation(context.Background(), "heartbeat"); err != nil {
		t.Fatal(err)
	}
	if err := client.operation(context.Background(), "pause"); err != nil {
		t.Fatal(err)
	}
	paused, err := client.info(context.Background())
	if err != nil || paused.State != "paused" || paused.SessionID != "" || paused.AttachURL != "" || paused.ServerPassword != "" || !paused.ExpiresAt.IsZero() || paused.ModelUsed != 0 || paused.ModelLimit != 0 {
		t.Fatalf("paused Supervisor exposed revoked authority: info=%+v error=%v", paused, err)
	}
	if err := client.operation(context.Background(), "resume"); err != nil {
		t.Fatal(err)
	}
	rotated, err := client.info(context.Background())
	if err != nil || rotated.VMID != "vm" || rotated.Container != "sunaba-project-vm" || rotated.SessionID != "new-session" || rotated.ServerPassword == strings.Repeat("s", 32) || rotated.ModelUsed != 2 || rotated.ModelLimit != 9 {
		t.Fatalf("rotated session info=%+v error=%v", rotated, err)
	}
	output, err := client.shell(context.Background(), "printf test")
	if err != nil || !strings.Contains(output, "safe\n") || strings.ContainsAny(output, "\x1b\a\u202E") || !strings.Contains(output, "<U+001B>") {
		t.Fatalf("shell output=%q error=%v", output, err)
	}
	if len(target.commands) != 2 || target.commands[1][len(target.commands[1])-1] != "printf test" {
		t.Fatalf("shell command=%v", target.commands)
	}
	if err := client.operation(context.Background(), "destroy"); err != nil {
		t.Fatal(err)
	}
	if target.paused != 1 || target.resumed != 1 || target.destroyed != 1 {
		t.Fatalf("target lifecycle=%+v", target)
	}
	select {
	case <-controlled.exit:
	default:
		t.Fatal("destroy did not signal supervisor exit")
	}
}

func TestPendingChangePersistsVerifiedMergedViewAndDetectsTampering(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(root, "project")
	mergedSource := filepath.Join(root, "merged-source")
	projectState := filepath.Join(root, "state", "projects", "project")
	for _, directory := range []string{project, mergedSource, projectState} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(project, "file.txt"), []byte("before\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mergedSource, "file.txt"), []byte("after\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{filepath.Join(project, "excluded"), filepath.Join(mergedSource, "excluded")} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "legacy.txt"), []byte("legacy artifact\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	baseline, err := workspace.BuildSnapshotManifest(project, workspace.DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	merged, err := workspace.BuildSnapshotManifest(mergedSource, workspace.DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	changes, err := workspace.BuildChangeSet(baseline, merged, workspace.DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	testPolicy := policy.ProjectPolicy{ProjectID: "project", ProjectRoot: project, Export: policy.ExportPolicy{MaxEntries: 100_000, MaxFileBytes: 64 << 20, MaxTotalBytes: 1 << 30}, ProtectedPaths: []string{".git"}}
	compiled, err := policy.CompileExportPolicy(testPolicy.Export, testPolicy.ProtectedPaths)
	if err != nil {
		t.Fatal(err)
	}
	active := &session.Session{ProjectID: "project", ProjectRoot: project, SessionID: "session", Container: "sunaba-project-session", Baseline: baseline, SnapshotRoot: project, SnapshotPolicy: compiled.Snapshot, ExportPolicy: compiled.Export, ExportPolicyDigest: compiled.Digest}
	persisted, err := persistPending(projectState, active, session.ExportResult{MergedRoot: mergedSource, Merged: merged, ChangeSet: changes})
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Version != pendingChangeVersion || persisted.BaselineRoot != filepath.Join(projectState, "pending", "baseline") {
		t.Fatalf("pending baseline identity=%+v", persisted)
	}
	canonicalMergedRoot, err := filepath.EvalSymlinks(persisted.MergedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Merged.Root != canonicalMergedRoot {
		t.Fatalf("persisted Merged View root=%q, want %q", persisted.Merged.Root, canonicalMergedRoot)
	}
	if persisted.Merged.Root == merged.Root {
		t.Fatalf("persisted Merged View retained source root %q", merged.Root)
	}
	if state := pendingInventoryState(projectState, testPolicy.ProjectID); state != "yes" {
		t.Fatalf("persisted pending inventory state=%q", state)
	}
	loaded, err := loadPending(projectState, testPolicy)
	if err != nil || loaded.ChangeSet.Digest != persisted.ChangeSet.Digest {
		t.Fatalf("loaded=%+v error=%v", loaded, err)
	}
	legacyV3 := persisted
	legacyV3.Version = selfContainedPendingChangeVersion
	legacyV3.SnapshotPolicy = workspace.SnapshotPolicy{}
	legacyV3.ExportPolicy = workspace.ExportPolicy{}
	legacyV3.ExportPolicyDigest = "0675d7a2514d6c6031a7b40f0d4d0a1a095433549503c921a48bdf9370fe054f"
	if err := writePrivateJSON(filepath.Join(projectState, "pending", "change.json"), legacyV3); err != nil {
		t.Fatal(err)
	}
	legacyCurrentPolicy := testPolicy
	legacyCurrentPolicy.Snapshot.Exclude = []string{"excluded"}
	migrated, err := loadPending(projectState, legacyCurrentPolicy)
	if err != nil || migrated.ChangeSet.Digest != persisted.ChangeSet.Digest {
		t.Fatalf("pending v3 compatibility failed: loaded=%+v error=%v", migrated, err)
	}
	if _, err := buildPendingReview(migrated, legacyCurrentPolicy, workspace.ReviewOptions{StatOnly: true}, false); err != nil {
		t.Fatalf("pending v3 review incorrectly applied current Snapshot exclusions: %v", err)
	}
	if err := writePrivateJSON(filepath.Join(projectState, "pending", "change.json"), persisted); err != nil {
		t.Fatal(err)
	}
	stageRoot := filepath.Join(root, "stage")
	if _, err := workspace.CreateApprovedSnapshotSubset(loaded.MergedRoot, stageRoot, loaded.Merged, []string{"file.txt"}, compiled.Snapshot); err != nil {
		t.Fatalf("stage persisted Merged View: %v", err)
	}
	changedPolicy := testPolicy
	changedPolicy.Export.MaxFileBytes--
	if loadedAfterChange, err := loadPending(projectState, changedPolicy); err != nil || loadedAfterChange.ChangeSet.Digest != persisted.ChangeSet.Digest {
		t.Fatalf("self-contained pending Change Set did not survive an unrelated current policy change: loaded=%+v error=%v", loadedAfterChange, err)
	}
	if err := os.WriteFile(filepath.Join(loaded.BaselineRoot, "file.txt"), []byte("tampered baseline\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPending(projectState, testPolicy); err == nil || !strings.Contains(err.Error(), "baseline") {
		t.Fatalf("tampered pending baseline was accepted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(loaded.BaselineRoot, "file.txt"), []byte("before\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(loaded.MergedRoot, "file.txt"), []byte("tampered\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPending(projectState, testPolicy); err == nil {
		t.Fatal("tampered pending Merged View was accepted")
	}
	if err := removePending(projectState); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyPendingChangeRemainsReviewableWhenHostMatchesBaseline(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(root, "project")
	mergedSource := filepath.Join(root, "merged-source")
	projectState := filepath.Join(root, "state", "projects", "project")
	for _, directory := range []string{project, mergedSource, projectState} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(project, "file.txt"), []byte("before\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mergedSource, "file.txt"), []byte("after\n"), 0600); err != nil {
		t.Fatal(err)
	}
	policyValue := policy.ProjectPolicy{ProjectID: "project", ProjectRoot: project, Export: policy.ExportPolicy{MaxEntries: 100_000, MaxFileBytes: 64 << 20, MaxTotalBytes: 1 << 30}, ProtectedPaths: []string{".git"}}
	compiled, err := policy.CompileExportPolicy(policyValue.Export, policyValue.ProtectedPaths)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := workspace.BuildSnapshotManifest(project, compiled.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := workspace.BuildSnapshotManifest(mergedSource, compiled.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := workspace.BuildChangeSet(baseline, merged, compiled.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	active := &session.Session{ProjectID: "project", ProjectRoot: project, SessionID: "session", Container: "sunaba-project-session", Baseline: baseline, SnapshotRoot: project, SnapshotPolicy: compiled.Snapshot, ExportPolicy: compiled.Export, ExportPolicyDigest: compiled.Digest}
	persisted, err := persistPending(projectState, active, session.ExportResult{MergedRoot: mergedSource, Merged: merged, ChangeSet: changes})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(persisted.BaselineRoot); err != nil {
		t.Fatal(err)
	}
	persisted.Version = legacyPendingChangeVersion
	persisted.BaselineRoot = ""
	persisted.Baseline = baseline
	persisted.ExportPolicyDigest = "0675d7a2514d6c6031a7b40f0d4d0a1a095433549503c921a48bdf9370fe054f"
	if err := writePrivateJSON(filepath.Join(projectState, "pending", "change.json"), persisted); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadPending(projectState, policyValue)
	if err != nil {
		t.Fatal(err)
	}
	review, err := buildPendingReview(loaded, policyValue, workspace.ReviewOptions{Context: 1}, true)
	if err != nil || len(review.Items) != 1 || len(review.Items[0].Hunks) == 0 {
		t.Fatalf("legacy review=%+v error=%v", review, err)
	}
	if err := os.WriteFile(filepath.Join(project, "file.txt"), []byte("host changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	metadata, err := buildPendingReview(loaded, policyValue, workspace.ReviewOptions{Context: 1}, true)
	if err != nil || !metadata.BaselineMissing || metadata.Opaque != 1 || metadata.Items[0].OpaqueReason == "" {
		t.Fatalf("legacy metadata review=%+v error=%v", metadata, err)
	}
	if _, err := buildPendingReview(loaded, policyValue, workspace.ReviewOptions{Context: 1}, false); err == nil {
		t.Fatal("legacy apply review accepted a changed host baseline")
	}
	if state := pendingInventoryState(projectState, "project"); state != "yes" {
		t.Fatalf("legacy pending inventory=%q", state)
	}
}

func TestPruneProjectAuditUsesOnlyCurrentProjectRetentionAndRecordsResult(t *testing.T) {
	root := filepath.Join(t.TempDir(), "audit")
	recorder, err := audit.NewRecorder(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, projectID := range []string{"current", "other"} {
		directory := filepath.Join(root, projectID)
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "audit-20260101.jsonl"), []byte("fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	projectPolicy := policy.ProjectPolicy{ProjectID: "current", Audit: policy.AuditPolicy{RetentionDays: 7}}
	if err := pruneProjectAudit(recorder, projectPolicy, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "current", "audit-20260101.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired current Project audit remained: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "other", "audit-20260101.jsonl")); err != nil {
		t.Fatalf("other Project audit was changed: %v", err)
	}
	result, err := os.ReadFile(filepath.Join(root, "current", "audit-20260813.jsonl"))
	if err != nil || !bytes.Contains(result, []byte(`"action":"audit.prune"`)) || !bytes.Contains(result, []byte(`"removed":"1"`)) {
		t.Fatalf("prune result was not audited: %s error=%v", result, err)
	}
}

func TestProjectInitCreatesPinnedPolicyWithoutPrematureSnapshot(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(base, "data")
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "hello.txt"), []byte("hello\n"), 0600); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(data, "sunaba")}
	var output bytes.Buffer
	a := &app{store: store, output: &output, errors: &output}
	prepareTestSetup(t, a)
	if err := a.run(context.Background(), []string{"project", "init", project, "--mode", "dev"}); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(store.Root, "projects", state.ProjectID(project), "policy.json")
	loaded, migrated, err := policy.LoadAndMigrate(policyPath, time.Now())
	if err != nil || migrated || loaded.Mode != "dev" || loaded.Dependency.OpenCode != dependency.OpenCodeVersion {
		t.Fatalf("policy=%+v migrated=%v error=%v", loaded, migrated, err)
	}
	if _, err := os.Lstat(filepath.Join(store.Root, "projects", state.ProjectID(project), "initial-snapshot")); !os.IsNotExist(err) {
		t.Fatalf("project init created an unused snapshot: %v", err)
	}
	if !strings.Contains(output.String(), "snapshot preview") {
		t.Fatalf("project init did not explain first Snapshot approval: %q", output.String())
	}
}

func TestSnapshotPreviewApprovalIsDigestBoundAndProtectsNestedGit(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	project := filepath.Join(base, "project")
	if err := os.MkdirAll(filepath.Join(project, "nested", ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, ".env"), []byte("TOKEN=secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "nested", ".git", "config"), []byte("credential=secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(base, "state", "sunaba")}
	configs := &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")}
	var output bytes.Buffer
	a := &app{store: store, configs: configs, output: &output, errors: &output}
	prepareTestSetup(t, a)
	if err := a.run(context.Background(), []string{"project", "init", project}); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := a.run(context.Background(), []string{"snapshot", "preview", "--dir", project}); err != nil {
		t.Fatal(err)
	}
	preview := output.String()
	if !strings.Contains(preview, "Sensitive filename candidate: .env") || strings.Contains(preview, "credential=secret") || strings.Contains(preview, "nested/.git") {
		t.Fatalf("unsafe preview output: %q", preview)
	}
	var digest string
	for _, line := range strings.Split(preview, "\n") {
		if strings.HasPrefix(line, "Snapshot digest: ") {
			digest = strings.TrimPrefix(line, "Snapshot digest: ")
		}
	}
	if digest == "" {
		t.Fatalf("preview digest missing: %q", preview)
	}
	if err := a.run(context.Background(), []string{"snapshot", "approve", "--dir", project, "--digest", digest}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "new.txt"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.run(context.Background(), []string{"snapshot", "approve", "--dir", project, "--digest", digest}); err == nil || !strings.Contains(err.Error(), "digest changed") {
		t.Fatalf("stale digest approval was accepted: %v", err)
	}
}

func TestGitignoreImportOnlyAcceptsLiteralCandidates(t *testing.T) {
	candidates, skipped, err := parseGitignoreExclusionCandidates([]byte("# comment\n/node_modules/\nbuild/output\n*.key\n!important\n../escape\n"))
	if err != nil || strings.Join(candidates, ",") != "build/output,node_modules" || skipped != 3 {
		t.Fatalf("candidates=%v skipped=%d error=%v", candidates, skipped, err)
	}
}

func TestHostProjectConfigurationMustBeAppliedBeforeUse(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(base, "state", "sunaba")}
	configs := &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")}
	var output bytes.Buffer
	a := &app{store: store, configs: configs, output: &output, errors: &output}
	prepareTestSetup(t, a)
	if err := a.run(context.Background(), []string{"project", "init", project}); err != nil {
		t.Fatal(err)
	}
	projectID := state.ProjectID(project)
	config, rules, err := configs.Load(projectID)
	if err != nil {
		t.Fatal(err)
	}
	if config.Web.Enabled || len(config.Web.OriginPresets) != 1 || config.Web.OriginPresets[0] != webgateway.CommonDevelopmentOriginPreset || len(rules) != 0 {
		t.Fatalf("unexpected new Project Web defaults: config=%+v rules=%+v", config.Web, rules)
	}
	config.Mode = "dev"
	encoded, err := projectconfig.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	paths, _ := configs.ProjectPaths(projectID)
	if err := os.WriteFile(paths.Project, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := a.loadPolicy(project); err == nil || !strings.Contains(err.Error(), "unapplied") {
		t.Fatalf("unapplied configuration was usable: %v", err)
	}
	output.Reset()
	if err := a.run(context.Background(), []string{"config", "validate", "--dir", project}); err != nil || !strings.Contains(output.String(), "Valid host Project configuration") {
		t.Fatalf("validate output=%q error=%v", output.String(), err)
	}
	output.Reset()
	if err := a.run(context.Background(), []string{"config", "diff", "--dir", project}); err != nil || !strings.Contains(output.String(), "unapplied changes") {
		t.Fatalf("diff output=%q error=%v", output.String(), err)
	}
	output.Reset()
	if err := a.run(context.Background(), []string{"config", "apply", "--dir", project}); err != nil {
		t.Fatal(err)
	}
	loaded, _, _, err := a.loadPolicy(project)
	if err != nil || loaded.Mode != "dev" || !projectconfig.Matches(config, rules, loaded) {
		t.Fatalf("effective=%+v error=%v", loaded, err)
	}
	output.Reset()
	if err := a.run(context.Background(), []string{"config", "path", "--dir", project}); err != nil || !strings.Contains(output.String(), paths.WebOrigins) {
		t.Fatalf("path output=%q error=%v", output.String(), err)
	}
}

func TestConfigApplyClassifiesNextSessionAndRecreationChanges(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(base, "state", "sunaba")}
	configs := &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")}
	var output bytes.Buffer
	a := &app{store: store, configs: configs, output: &output, errors: &output}
	prepareTestSetup(t, a)
	if err := a.run(context.Background(), []string{"project", "init", project}); err != nil {
		t.Fatal(err)
	}
	projectID := state.ProjectID(project)
	projectState := filepath.Join(store.Root, "projects", projectID)
	locator := filepath.Join(projectState, approvalControlLocator)
	if err := os.WriteFile(locator, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	config, rules, err := configs.Load(projectID)
	if err != nil {
		t.Fatal(err)
	}
	config.Session.TTLSeconds++
	if err := configs.Save(projectID, config, rules); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := a.run(context.Background(), []string{"config", "diff", "--dir", project}); err != nil || !strings.Contains(output.String(), "Application (next-session): session") {
		t.Fatalf("next-Session diff output=%q error=%v", output.String(), err)
	}
	output.Reset()
	if err := a.run(context.Background(), []string{"config", "apply", "--dir", project}); err != nil || !strings.Contains(output.String(), "active Session is unchanged") {
		t.Fatalf("next-Session apply output=%q error=%v", output.String(), err)
	}
	config, rules, err = configs.Load(projectID)
	if err != nil {
		t.Fatal(err)
	}
	config.Resources.CPUs++
	if err := configs.Save(projectID, config, rules); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := a.run(context.Background(), []string{"config", "diff", "--dir", project}); err != nil || !strings.Contains(output.String(), "Application (recreate-required): resources") {
		t.Fatalf("recreate diff output=%q error=%v", output.String(), err)
	}
	if err := a.run(context.Background(), []string{"config", "apply", "--dir", project}); err == nil || !strings.Contains(err.Error(), "require VM recreation") {
		t.Fatalf("VM-bound configuration changed an existing VM: %v", err)
	}
}

func TestActivationPolicyReloadUsesNextSessionChangesAndRejectsVMBoundDrift(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(base, "state", "sunaba")}
	configs := &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")}
	a := &app{store: store, configs: configs, output: io.Discard, errors: io.Discard}
	prepareTestSetup(t, a)
	if err := a.run(context.Background(), []string{"project", "init", project}); err != nil {
		t.Fatal(err)
	}
	initial, policyPath, _, err := a.loadPolicy(project)
	if err != nil {
		t.Fatal(err)
	}
	next := initial
	next.Session.TTLSeconds++
	next.UpdatedAt = time.Now().UTC()
	if err := a.savePolicyAndConfig(policyPath, next); err != nil {
		t.Fatal(err)
	}
	loaded, err := a.reloadActivationPolicy(initial, policyPath)
	if err != nil || loaded.Session.TTLSeconds != next.Session.TTLSeconds {
		t.Fatalf("next Session policy=%+v error=%v", loaded.Session, err)
	}
	recreate := next
	recreate.Resources.CPUs++
	recreate.UpdatedAt = time.Now().Add(time.Second).UTC()
	if err := a.savePolicyAndConfig(policyPath, recreate); err != nil {
		t.Fatal(err)
	}
	if _, err := a.reloadActivationPolicy(initial, policyPath); err == nil || !strings.Contains(err.Error(), "VM-bound fields [resources]") {
		t.Fatalf("VM-bound policy drift was accepted: %v", err)
	}
}

func TestConfigApplyEnforcesAuditRetentionImmediately(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(base, "state", "sunaba")}
	configs := &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")}
	var output bytes.Buffer
	a := &app{store: store, configs: configs, output: &output, errors: &output}
	prepareTestSetup(t, a)
	if err := a.run(context.Background(), []string{"project", "init", project}); err != nil {
		t.Fatal(err)
	}
	projectID := state.ProjectID(project)
	auditDirectory := filepath.Join(store.Root, "audit", projectID)
	if err := os.MkdirAll(auditDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	oldLog := filepath.Join(auditDirectory, "audit-20200101.jsonl")
	if err := os.WriteFile(oldLog, []byte("fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	config, rules, err := configs.Load(projectID)
	if err != nil {
		t.Fatal(err)
	}
	config.Audit.RetentionDays = 1
	if err := configs.Save(projectID, config, rules); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := a.run(context.Background(), []string{"config", "apply", "--dir", project}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(oldLog); !errors.Is(err, os.ErrNotExist) || !strings.Contains(output.String(), "Application (immediate): audit") {
		t.Fatalf("old audit log remained or apply timing was omitted: output=%q error=%v", output.String(), err)
	}
}

func TestDetectedGitRemoteParserKeepsOnlyBoundedSafeHTTPSRemotes(t *testing.T) {
	data := []byte(strings.Join([]string{
		"remote.origin.url https://git.example/team/project.git",
		"remote.unsafe.url https://token@git.example/private.git",
		"remote.Bad_Name.url https://git.example/bad.git",
		"remote.duplicate.url https://git.example/team/project.git",
		"not-a-remote value",
	}, "\n"))
	remotes := parseDetectedGitRemotes(data)
	if len(remotes) != 1 || remotes[0].Name != "origin" || remotes[0].URL != "https://git.example/team/project.git" {
		t.Fatalf("unsafe detected remotes were not filtered: %+v", remotes)
	}
}

func TestInteractiveProjectConfigurationCancelsWithoutWritesThenAppliesGitGateway(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(base, "state", "sunaba")}
	configs := &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")}
	var output bytes.Buffer
	a := &app{store: store, configs: configs, output: &output, errors: &output}
	prepareTestSetup(t, a)
	if err := a.run(context.Background(), []string{"project", "init", project}); err != nil {
		t.Fatal(err)
	}
	projectID := state.ProjectID(project)
	paths, err := configs.ProjectPaths(projectID)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(store.Root, "projects", projectID, "policy.json")
	configBefore, err := os.ReadFile(paths.Project)
	if err != nil {
		t.Fatal(err)
	}
	policyBefore, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	a.input = strings.NewReader("\n\n\n\n\nn\n")
	output.Reset()
	if err := a.run(context.Background(), []string{"config", "edit", "--dir", project}); err != nil {
		t.Fatal(err)
	}
	configAfterCancel, _ := os.ReadFile(paths.Project)
	policyAfterCancel, _ := os.ReadFile(policyPath)
	if !bytes.Equal(configBefore, configAfterCancel) || !bytes.Equal(policyBefore, policyAfterCancel) || !strings.Contains(output.String(), "was not changed") {
		t.Fatalf("canceled wizard changed files or omitted result: %s", output.String())
	}

	a.input = strings.NewReader("\n\ny\n\norigin\nhttps://git.example/team/project.git\n\n\n\ny\n")
	output.Reset()
	if err := a.run(context.Background(), []string{"config", "edit", "--dir", project}); err != nil {
		t.Fatal(err)
	}
	loaded, _, _, err := a.loadPolicy(project)
	if err != nil {
		t.Fatal(err)
	}
	config, rules, err := configs.Load(projectID)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Git.Remotes) != 1 || loaded.Git.Remotes[0].Name != "origin" || !projectconfig.Matches(config, rules, loaded) {
		t.Fatalf("interactive configuration was not synchronized: policy=%+v config=%+v", loaded.Git, config.Git)
	}
	if !strings.Contains(output.String(), "Saved and applied") {
		t.Fatalf("success output missing: %s", output.String())
	}
}
