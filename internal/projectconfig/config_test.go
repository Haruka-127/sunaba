package projectconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/policy"
	"sunaba/internal/state"
)

func TestStoreKeepsEditableConfigurationOutsideProject(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	effective := testPolicy(t, project)
	config, rules := FromPolicy(effective)
	store := &Store{Root: filepath.Join(base, "host-config", "sunaba")}
	if err := store.Save(effective.ProjectID, config, rules); err != nil {
		t.Fatal(err)
	}
	paths, err := store.ProjectPaths(effective.ProjectID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(paths.Directory, project+string(filepath.Separator)) {
		t.Fatalf("configuration was placed inside the Project: %s", paths.Directory)
	}
	for _, path := range []string{store.Root, filepath.Join(store.Root, "projects"), paths.Directory} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Fatalf("unsafe directory %s: mode=%v error=%v", path, info.Mode(), err)
		}
	}
	for _, path := range []string{paths.Project, paths.WebOrigins} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatalf("unsafe file %s: mode=%v error=%v", path, info.Mode(), err)
		}
	}
	loaded, loadedRules, err := store.Load(effective.ProjectID)
	if err != nil || !Matches(loaded, loadedRules, effective) {
		t.Fatalf("loaded config=%+v rules=%+v error=%v", loaded, loadedRules, err)
	}
	if err := store.Remove(effective.ProjectID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(paths.Directory); !os.IsNotExist(err) {
		t.Fatalf("Project configuration directory was not removed: %v", err)
	}
	if _, err := os.Lstat(store.Root); err != nil {
		t.Fatalf("configuration root was removed with one Project: %v", err)
	}
}

func TestOriginsFileParsesStrictBoundedRulesWithLineNumbers(t *testing.T) {
	rules, err := ParseOrigins([]byte("# documentation\nhttps://docs.example\nhttp://packages.example include-subdomains\n"))
	if err != nil || len(rules) != 2 {
		t.Fatalf("rules=%+v error=%v", rules, err)
	}
	foundSubdomains := false
	for _, rule := range rules {
		if rule.Host == "packages.example" && rule.AllowHTTP && rule.Port == 80 && rule.IncludeSubdomains {
			foundSubdomains = true
		}
	}
	if !foundSubdomains {
		t.Fatalf("subdomain rule missing: %+v", rules)
	}
	for _, test := range []struct {
		name string
		data string
		want string
	}{
		{name: "path", data: "https://docs.example/private\n", want: "line 1"},
		{name: "empty port", data: "https://docs.example:\n", want: "line 1"},
		{name: "empty query", data: "https://docs.example?\n", want: "line 1"},
		{name: "option", data: "https://docs.example recursive\n", want: "line 1"},
		{name: "duplicate", data: "https://docs.example\nhttps://docs.example\n", want: "duplicate"},
		{name: "private address", data: "https://127.0.0.1\n", want: "line 1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseOrigins([]byte(test.data))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestCompileSeparatesDeclarativeAndGeneratedPolicyFields(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	effective := testPolicy(t, project)
	config, _ := FromPolicy(effective)
	config.Mode = "dev"
	config.Resources.CPUs = 4
	config.Git.Remotes = []policy.GitRemotePolicy{{Name: "origin", URL: "https://git.example/team/repository.git"}}
	compiled, err := Compile(config, nil, effective, "", "", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Mode != "dev" || compiled.Resources.CPUs != 4 || len(compiled.Git.Remotes) != 1 {
		t.Fatalf("declarative fields were not compiled: %+v", compiled)
	}
	if compiled.Dependency != effective.Dependency || !compiled.Git.PushApprovalRequired || strings.Join(compiled.ProtectedPaths, ",") != ".git" {
		t.Fatalf("generated security fields changed: %+v", compiled)
	}
	if !Matches(config, nil, compiled) {
		t.Fatal("compiled policy did not match its configuration")
	}
}

func TestStoreRejectsSymlinkedOriginFile(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	effective := testPolicy(t, project)
	config, rules := FromPolicy(effective)
	store := &Store{Root: filepath.Join(base, "config", "sunaba")}
	if err := store.Save(effective.ProjectID, config, rules); err != nil {
		t.Fatal(err)
	}
	paths, _ := store.ProjectPaths(effective.ProjectID)
	target := filepath.Join(base, "target")
	if err := os.WriteFile(target, []byte("# target\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(paths.WebOrigins); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, paths.WebOrigins); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(effective.ProjectID); err == nil {
		t.Fatal("symlinked origins file was accepted")
	}
}

func TestStoreRejectsUnknownConfigurationAndDoesNotFollowDirectorySymlink(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	effective := testPolicy(t, project)
	config, rules := FromPolicy(effective)
	store := &Store{Root: filepath.Join(base, "config", "sunaba")}
	if err := store.Save(effective.ProjectID, config, rules); err != nil {
		t.Fatal(err)
	}
	paths, _ := store.ProjectPaths(effective.ProjectID)
	data, err := os.ReadFile(paths.Project)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "\"schema_version\": 1,", "\"schema_version\": 1,\n  \"unknown\": true,", 1))
	if err := os.WriteFile(paths.Project, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(effective.ProjectID); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown configuration field was accepted: %v", err)
	}

	otherBase := filepath.Join(base, "other-config")
	otherStore := &Store{Root: filepath.Join(otherBase, "sunaba")}
	if err := os.Mkdir(otherBase, 0700); err != nil {
		t.Fatal(err)
	}
	if err := otherStore.Init(); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "symlink-target")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatal(err)
	}
	otherPaths, _ := otherStore.ProjectPaths(effective.ProjectID)
	if err := os.Symlink(target, otherPaths.Directory); err != nil {
		t.Fatal(err)
	}
	if err := otherStore.Save(effective.ProjectID, config, rules); err == nil {
		t.Fatal("symlinked Project configuration directory was accepted")
	}
	targetInfo, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if targetInfo.Mode().Perm() != 0755 {
		t.Fatalf("symlink target mode was modified: mode=%v", targetInfo.Mode())
	}
}

func testPolicy(t *testing.T, project string) policy.ProjectPolicy {
	t.Helper()
	effective, err := policy.New(project, strings.Repeat("a", 64), "1.18.16", "1.2.2", "sunaba-base:test", "secure", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if effective.ProjectID != state.ProjectID(project) {
		t.Fatal("unexpected Project ID")
	}
	return effective
}
