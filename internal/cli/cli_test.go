package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/policy"
	"sunaba/internal/session"
	"sunaba/internal/state"
	"sunaba/internal/workspace"
)

func TestHelpDescribesCurrentSecureCLIAndOmitsPrototypeCommands(t *testing.T) {
	var output bytes.Buffer
	a := &app{output: &output}
	usage(a.output)
	text := output.String()
	for _, expected := range []string{"project init", "agent", "changes export", "changes apply", "--mode secure|dev", "never bind-mounted"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("help missing %q: %s", expected, text)
		}
	}
	for _, obsolete := range []string{"--no-firewall", "env set", "reset --full", "automatic approval"} {
		if strings.Contains(text, obsolete) {
			t.Fatalf("help retained obsolete prototype behavior %q", obsolete)
		}
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
	active := &session.Session{ProjectID: "project", ProjectRoot: project, SessionID: "session", Container: "sunaba-project-session", Baseline: baseline}
	persisted, err := persistPending(projectState, active, session.ExportResult{MergedRoot: mergedSource, Merged: merged, ChangeSet: changes})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loadPending(projectState, project, "project")
	if err != nil || loaded.ChangeSet.Digest != persisted.ChangeSet.Digest {
		t.Fatalf("loaded=%+v error=%v", loaded, err)
	}
	if err := os.WriteFile(filepath.Join(loaded.MergedRoot, "file.txt"), []byte("tampered\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPending(projectState, project, "project"); err == nil {
		t.Fatal("tampered pending Merged View was accepted")
	}
	if err := removePending(projectState); err != nil {
		t.Fatal(err)
	}
}

func TestProjectInitCreatesPinnedPolicyAndSafeInitialSnapshot(t *testing.T) {
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
	if err := a.project(context.Background(), []string{"init", project, "--mode", "dev"}); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(store.Root, "projects", state.ProjectID(project), "policy.json")
	loaded, migrated, err := policy.LoadAndMigrate(policyPath, time.Now())
	if err != nil || migrated || loaded.Mode != "dev" || loaded.Dependency.OpenCode != "1.18.16" {
		t.Fatalf("policy=%+v migrated=%v error=%v", loaded, migrated, err)
	}
	if _, err := os.Lstat(filepath.Join(store.Root, "projects", state.ProjectID(project), "initial-snapshot", "hello.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "after.txt"), []byte("after\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(store.Root, "projects", state.ProjectID(project), "initial-snapshot", "after.txt")); !os.IsNotExist(err) {
		t.Fatalf("initial snapshot was not immutable: %v", err)
	}
}
