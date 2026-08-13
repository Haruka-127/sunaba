package apply

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"sunaba/internal/approval"
	"sunaba/internal/audit"
	"sunaba/internal/state"
	"sunaba/internal/workspace"
)

func TestApplyRequiresOneShotDigestBoundApproval(t *testing.T) {
	cfg := applyFixture(t)
	before := mustManifest(t, cfg.ProjectRoot)
	if _, err := Apply(cfg); err == nil {
		t.Fatal("apply without grant succeeded")
	}
	if after := mustManifest(t, cfg.ProjectRoot); after.Digest != before.Digest {
		t.Fatal("unapproved apply changed Project")
	}
	cfg.Grant = approve(t, cfg)
	result, err := Apply(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if result.Digest != cfg.Merged.Digest {
		t.Fatalf("result=%s merged=%s", result.Digest, cfg.Merged.Digest)
	}
	assertContent(t, filepath.Join(cfg.ProjectRoot, "modify.txt"), "after\n")
	assertContent(t, filepath.Join(cfg.ProjectRoot, "add.txt"), "added\n")
	assertContent(t, filepath.Join(cfg.ProjectRoot, "renamed.txt"), "rename\n")
	if _, err := os.Lstat(filepath.Join(cfg.ProjectRoot, "delete.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("delete remained: %v", err)
	}
	assertContent(t, filepath.Join(cfg.ProjectRoot, ".git", "config"), "host metadata\n")
	if _, err := Apply(cfg); err == nil {
		t.Fatal("approval grant was reusable")
	}
}

func TestApplyRejectsChangedHostBaselineBeforeConsumingGrant(t *testing.T) {
	cfg := applyFixture(t)
	cfg.Grant = approve(t, cfg)
	write(t, filepath.Join(cfg.ProjectRoot, "host-edit.txt"), "concurrent\n")
	if _, err := Apply(cfg); err == nil || !strings.Contains(err.Error(), "baseline changed") {
		t.Fatalf("baseline conflict error=%v", err)
	}
	assertContent(t, filepath.Join(cfg.ProjectRoot, "host-edit.txt"), "concurrent\n")
}

func TestApplyRequiresWritableAuditBeforeMutation(t *testing.T) {
	cfg := applyFixture(t)
	cfg.Grant = approve(t, cfg)
	before := mustManifest(t, cfg.ProjectRoot)
	if err := os.Chmod(cfg.Audit.Root, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(cfg); err == nil {
		t.Fatal("unwritable audit was accepted")
	}
	if after := mustManifest(t, cfg.ProjectRoot); after.Digest != before.Digest {
		t.Fatal("apply mutated Project before durable audit")
	}
}

func TestApplyRollsBackInjectedFailure(t *testing.T) {
	cfg := applyFixture(t)
	baseline := mustManifest(t, cfg.ProjectRoot)
	_, err := applyLocked(cfg, func(stage string) error {
		if strings.HasPrefix(stage, "install:") {
			return errors.New("injected failure")
		}
		return nil
	}, true)
	if err == nil {
		t.Fatal("injected failure was ignored")
	}
	if recovered := mustManifest(t, cfg.ProjectRoot); recovered.Digest != baseline.Digest {
		t.Fatalf("rollback digest=%s baseline=%s", recovered.Digest, baseline.Digest)
	}
}

func TestApplyRollsBackHostDiskPressure(t *testing.T) {
	cfg := applyFixture(t)
	baseline := mustManifest(t, cfg.ProjectRoot)
	_, err := applyLocked(cfg, func(stage string) error {
		if strings.HasPrefix(stage, "install:") {
			return unix.ENOSPC
		}
		return nil
	}, true)
	if !errors.Is(err, unix.ENOSPC) {
		t.Fatalf("disk pressure error=%v", err)
	}
	if recovered := mustManifest(t, cfg.ProjectRoot); recovered.Digest != baseline.Digest {
		t.Fatalf("disk pressure rollback digest=%s baseline=%s", recovered.Digest, baseline.Digest)
	}
	transactions := filepath.Join(cfg.ProjectRoot, ".sunaba", "transactions")
	entries, readErr := os.ReadDir(transactions)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("disk pressure transaction remained: entries=%v error=%v", entries, readErr)
	}
}

func TestApplyCleansTransactionBeforeJournalFailure(t *testing.T) {
	cfg := applyFixture(t)
	cfg.MergedRoot = filepath.Join(filepath.Dir(cfg.ProjectRoot), "missing-merged")
	if _, err := applyLocked(cfg, nil, true); err == nil {
		t.Fatal("missing Merged View was accepted")
	}
	transactions := filepath.Join(cfg.ProjectRoot, ".sunaba", "transactions")
	entries, err := os.ReadDir(transactions)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("pre-journal transaction remained: %v", entries)
	}
}

func TestRecoverLockedRollsBackProcessCrashJournal(t *testing.T) {
	cfg := applyFixture(t)
	baseline := mustManifest(t, cfg.ProjectRoot)
	_, err := applyLocked(cfg, func(stage string) error {
		if strings.HasPrefix(stage, "install:") {
			return errors.New("simulated process crash")
		}
		return nil
	}, false)
	if err == nil {
		t.Fatal("simulated crash did not interrupt apply")
	}
	if partial := mustManifest(t, cfg.ProjectRoot); partial.Digest == baseline.Digest {
		t.Fatal("simulated crash did not leave a partial transaction to recover")
	}
	if err := RecoverLocked(cfg.ProjectRoot, cfg.ProjectID, cfg.SnapshotPolicy); err != nil {
		t.Fatal(err)
	}
	if recovered := mustManifest(t, cfg.ProjectRoot); recovered.Digest != baseline.Digest {
		t.Fatalf("recovery digest=%s baseline=%s", recovered.Digest, baseline.Digest)
	}
	transactions := filepath.Join(cfg.ProjectRoot, ".sunaba", "transactions")
	entries, err := os.ReadDir(transactions)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("recovered transactions remain: %v", entries)
	}
}

func TestRecoverLockedAfterActualHolderProcessExit(t *testing.T) {
	cfg := applyFixture(t)
	baseline := mustManifest(t, cfg.ProjectRoot)
	payload := struct {
		ProjectRoot    string                     `json:"project_root"`
		ProjectID      string                     `json:"project_id"`
		MergedRoot     string                     `json:"merged_root"`
		Baseline       workspace.SnapshotManifest `json:"baseline"`
		Merged         workspace.SnapshotManifest `json:"merged"`
		ChangeSet      workspace.ChangeSet        `json:"change_set"`
		SnapshotPolicy workspace.SnapshotPolicy   `json:"snapshot_policy"`
	}{cfg.ProjectRoot, cfg.ProjectID, cfg.MergedRoot, cfg.Baseline, cfg.Merged, cfg.ChangeSet, cfg.SnapshotPolicy}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	payloadPath := filepath.Join(filepath.Dir(cfg.ProjectRoot), "crash-input.json")
	if err := os.WriteFile(payloadPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=TestApplyCrashHelperProcess")
	command.Env = append(os.Environ(), "SUNABA_APPLY_CRASH_HELPER=1", "SUNABA_APPLY_CRASH_INPUT="+payloadPath)
	if err := command.Run(); err == nil {
		t.Fatal("crash helper unexpectedly returned success")
	}
	if partial := mustManifest(t, cfg.ProjectRoot); partial.Digest == baseline.Digest {
		t.Fatal("crash helper did not leave a partial transaction")
	}
	if err := RecoverLocked(cfg.ProjectRoot, cfg.ProjectID, cfg.SnapshotPolicy); err != nil {
		t.Fatal(err)
	}
	if recovered := mustManifest(t, cfg.ProjectRoot); recovered.Digest != baseline.Digest {
		t.Fatalf("actual crash recovery=%s baseline=%s", recovered.Digest, baseline.Digest)
	}
}

func TestApplyCrashHelperProcess(t *testing.T) {
	if os.Getenv("SUNABA_APPLY_CRASH_HELPER") != "1" {
		return
	}
	encoded, err := os.ReadFile(os.Getenv("SUNABA_APPLY_CRASH_INPUT"))
	if err != nil {
		os.Exit(2)
	}
	var payload struct {
		ProjectRoot    string                     `json:"project_root"`
		ProjectID      string                     `json:"project_id"`
		MergedRoot     string                     `json:"merged_root"`
		Baseline       workspace.SnapshotManifest `json:"baseline"`
		Merged         workspace.SnapshotManifest `json:"merged"`
		ChangeSet      workspace.ChangeSet        `json:"change_set"`
		SnapshotPolicy workspace.SnapshotPolicy   `json:"snapshot_policy"`
	}
	if json.Unmarshal(encoded, &payload) != nil {
		os.Exit(3)
	}
	cfg := Config{ProjectRoot: payload.ProjectRoot, ProjectID: payload.ProjectID, MergedRoot: payload.MergedRoot, Baseline: payload.Baseline, Merged: payload.Merged, ChangeSet: payload.ChangeSet, SnapshotPolicy: payload.SnapshotPolicy}
	_, _ = applyLocked(cfg, func(stage string) error {
		if strings.HasPrefix(stage, "install:") {
			os.Exit(42)
		}
		return nil
	}, false)
	os.Exit(4)
}

func TestApplyRejectsSymlinkParentRace(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(filepath.Join(project, "dir"), 0700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(project, "dir", "file"), "before")
	cfg := fixtureFromProject(t, project, func(merged string) { write(t, filepath.Join(merged, "dir", "file"), "after") })
	cfg.Grant = approve(t, cfg)
	external := filepath.Join(root, "external")
	if err := os.Mkdir(external, 0700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(external, "file"), "outside")
	if err := os.Rename(filepath.Join(project, "dir"), filepath.Join(project, "original-dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(project, "dir")); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(cfg); err == nil {
		t.Fatal("symlink parent race was accepted")
	}
	assertContent(t, filepath.Join(external, "file"), "outside")
}

func applyFixture(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(project, "keep.txt"), "keep\n")
	write(t, filepath.Join(project, "modify.txt"), "before\n")
	write(t, filepath.Join(project, "delete.txt"), "delete\n")
	write(t, filepath.Join(project, "rename.txt"), "rename\n")
	write(t, filepath.Join(project, ".git", "config"), "host metadata\n")
	return fixtureFromProject(t, project, func(merged string) {
		write(t, filepath.Join(merged, "modify.txt"), "after\n")
		write(t, filepath.Join(merged, "add.txt"), "added\n")
		if err := os.Remove(filepath.Join(merged, "delete.txt")); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(merged, "rename.txt"), filepath.Join(merged, "renamed.txt")); err != nil {
			t.Fatal(err)
		}
	})
}

func fixtureFromProject(t *testing.T, project string, mutate func(string)) Config {
	t.Helper()
	root := filepath.Dir(project)
	baseline := mustManifest(t, project)
	mergedRoot := filepath.Join(root, "merged")
	if _, err := workspace.CreateProjectSnapshot(project, mergedRoot, workspace.DefaultSnapshotPolicy()); err != nil {
		t.Fatal(err)
	}
	mutate(mergedRoot)
	merged := mustManifest(t, mergedRoot)
	changeSet, err := workspace.BuildChangeSet(baseline, merged, workspace.DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := state.ResolveProjectPath(project)
	if err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(root, "state")}
	recorder, err := audit.NewRecorder(filepath.Join(store.Root, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		Store: store, ProjectRoot: canonical, ProjectID: state.ProjectID(canonical), Audit: recorder,
		MergedRoot: mergedRoot, Baseline: baseline, Merged: merged, ChangeSet: changeSet, Approvals: approval.NewManager(nil),
		SnapshotPolicy: workspace.DefaultSnapshotPolicy(),
	}
}

func approve(t *testing.T, cfg Config) *approval.Grant {
	t.Helper()
	binding := approval.Binding{ProjectID: cfg.ProjectID, BaselineDigest: cfg.Baseline.Digest, MergedDigest: cfg.Merged.Digest, ChangeSetDigest: cfg.ChangeSet.Digest}
	request, err := cfg.Approvals.NewRequest(binding, "test apply", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := cfg.Approvals.Confirm(request.Nonce, binding)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func mustManifest(t *testing.T, root string) workspace.SnapshotManifest {
	t.Helper()
	manifest, err := workspace.BuildSnapshotManifest(root, workspace.DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func write(t *testing.T, filename, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func assertContent(t *testing.T, filename, expected string) {
	t.Helper()
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != expected {
		t.Fatalf("%s=%q, want %q", filename, content, expected)
	}
}
