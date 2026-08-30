package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"sunaba/internal/dependency"
	"sunaba/internal/policy"
	"sunaba/internal/projectconfig"
	"sunaba/internal/state"
	hosttui "sunaba/internal/tui"
	"sunaba/internal/versionconfig"
	"sunaba/internal/workspace"
)

func TestTUIChangesUsesStructuredRowsWithoutLayoutNewlines(t *testing.T) {
	screen := workspace.ReviewScreen{
		Layout: workspace.ReviewLayoutSideBySide, Selected: 0,
		Files:      []workspace.ReviewFile{{Status: "A", Path: "test.txt"}},
		Unified:    []workspace.UnifiedReviewRow{{Kind: '@', Text: "@@ -0,0 +1,1 @@"}, {Kind: '+', NewLine: 1, Text: "test"}},
		SideBySide: []workspace.SideBySideReviewRow{{BeforeKind: '@', Before: "@@ -0,0", AfterKind: '@', After: "+1,1 @@"}, {AfterKind: '+', AfterLine: 1, After: "test"}},
	}
	model := reviewChangesView(screen, screen.Files, 1, 1, 0)
	view := hosttui.View{
		Version: hosttui.ProtocolVersion, Type: "view", ScreenID: "changes", Revision: 1,
		Binding: hosttui.Binding{ProcessID: 123, ProjectID: "project-1", Nonce: strings.Repeat("a", 64)},
		Title:   "Review", Actions: []hosttui.Action{noInputAction("file.0", "A test.txt"), noInputAction("apply-all", "Apply all changes"), noInputAction("back", "Back")}, Changes: model,
	}
	prepared, err := hosttui.PrepareView(view)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Fields == nil || len(prepared.Fields) != 0 || prepared.Changes.SelectedActionID != "file.0" || prepared.Changes.Unified[1].Text != "test" || prepared.Changes.SideBySide[1].After.Line != 1 || strings.Contains(prepared.Changes.Unified[1].Text, "\n") {
		t.Fatalf("structured Changes view=%+v", prepared.Changes)
	}
	if summary := reviewSummary(screen.Files); !strings.Contains(summary, "1 file") || !strings.Contains(summary, "1 added") {
		t.Fatalf("summary=%q", summary)
	} else if strings.Contains(summary, "0 modified") || !strings.Contains(summary, "no warnings") {
		t.Fatalf("summary includes zero-value noise or omits warning state: %q", summary)
	}
}

func TestUIExchangeDoesNotReportAuthorityInitiatedKillAsHelperFailure(t *testing.T) {
	eventErr := errors.New("read UI frame header: EOF")
	waitErr := errors.New("signal: killed")
	err := uiExchangeResultError(eventErr, waitErr, true)
	if err == nil || !strings.Contains(err.Error(), eventErr.Error()) || strings.Contains(err.Error(), waitErr.Error()) {
		t.Fatalf("authority-initiated kill error=%v", err)
	}
	err = uiExchangeResultError(eventErr, waitErr, false)
	if err == nil || !strings.Contains(err.Error(), eventErr.Error()) || !strings.Contains(err.Error(), waitErr.Error()) {
		t.Fatalf("natural helper failure error=%v", err)
	}
}

func TestTUIRejectsNonInteractiveTerminalBeforeStateAccess(t *testing.T) {
	a := &app{
		input: strings.NewReader(""), output: io.Discard, errors: io.Discard,
		terminalCheck: func(io.Reader, io.Writer) bool { return false },
	}
	err := a.tui(context.Background())
	if err == nil || !strings.Contains(err.Error(), "requires an interactive terminal") || !strings.Contains(err.Error(), "explicit subcommand") {
		t.Fatalf("non-TTY error=%v", err)
	}
}

func TestTUIHelperEnvironmentExcludesHostSecretsAndMutationInputs(t *testing.T) {
	got := uiHelperEnvironment([]string{
		"TERM=xterm-256color", "LANG=en_US.UTF-8", "NO_COLOR=1", "OPENAI_API_KEY=secret", "GITHUB_TOKEN=secret",
		"HTTPS_PROXY=https://proxy.example", "PATH=/untrusted", "HOME=/private/project", "TERM_PROGRAM=Apple_Terminal", "LC_ALL=bad\nvalue",
	})
	want := []string{"LANG=en_US.UTF-8", "NO_COLOR=1", "TERM=xterm-256color", "TERM_PROGRAM=Apple_Terminal"}
	if !slices.Equal(got, want) {
		t.Fatalf("helper environment=%v want=%v", got, want)
	}
}

func TestTUIProjectAutoSelectionUsesDeepestCanonicalRoot(t *testing.T) {
	base := tuiCanonicalTemp(t)
	outer := filepath.Join(base, "outer")
	inner := filepath.Join(outer, "inner")
	working := filepath.Join(inner, "src")
	if err := os.MkdirAll(working, 0700); err != nil {
		t.Fatal(err)
	}
	tuiChdir(t, working)
	projects := []tuiProject{
		{policy: policy.ProjectPolicy{ProjectRoot: outer}},
		{policy: policy.ProjectPolicy{ProjectRoot: inner}},
	}
	selected := currentTUIProject(projects)
	if selected == nil || selected.policy.ProjectRoot != inner {
		t.Fatalf("selected=%+v want deepest root %s", selected, inner)
	}
}

func TestTUIProjectSelectorUsesOnlyDisplayedExactSelection(t *testing.T) {
	base := tuiCanonicalTemp(t)
	store := &state.Store{Root: filepath.Join(base, "state", "sunaba")}
	first := tuiRegisterProject(t, store, filepath.Join(base, "projects", "alpha"))
	second := tuiRegisterProject(t, store, filepath.Join(base, "projects", "beta"))
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	tuiChdir(t, outside)

	called := 0
	a := &app{store: store, runtime: &projectListRuntime{}, input: strings.NewReader(""), output: io.Discard, errors: io.Discard}
	a.uiExchange = func(_ context.Context, projectID string, view hosttui.View) (hosttui.Event, error) {
		called++
		if projectID != "global" || view.ScreenID != "project-selector" || len(view.Fields) != 3 {
			t.Fatalf("selector project=%q view=%+v", projectID, view)
		}
		ids := make([]string, len(view.Actions))
		for index := range view.Actions {
			ids[index] = view.Actions[index].ID
		}
		if !slices.Equal(ids, []string{"select.0", "select.1", "register", "exit"}) {
			t.Fatalf("selector actions=%v", ids)
		}
		return tuiEvent(view, "select.1"), nil
	}
	selected, err := (&tuiCoordinator{app: a, width: 100}).chooseProject(context.Background())
	if err != nil || selected == nil || selected.policy.ProjectID != second.policy.ProjectID || selected.policy.ProjectID == first.policy.ProjectID || called != 1 {
		t.Fatalf("selected=%+v calls=%d error=%v", selected, called, err)
	}
}

func TestTUIProjectSelectorPagesWithoutAcceptingHiddenSelection(t *testing.T) {
	base := tuiCanonicalTemp(t)
	store := &state.Store{Root: filepath.Join(base, "state", "sunaba")}
	projects := make([]tuiProject, 0, hosttui.MaxActions)
	for index := 0; index < hosttui.MaxActions; index++ {
		projects = append(projects, tuiRegisterProject(t, store, filepath.Join(base, "projects", fmt.Sprintf("project-%02d", index))))
	}
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	tuiChdir(t, outside)

	call := 0
	a := &app{store: store, input: strings.NewReader(""), output: io.Discard, errors: io.Discard}
	a.uiExchange = func(_ context.Context, _ string, view hosttui.View) (hosttui.Event, error) {
		call++
		switch call {
		case 1:
			if len(view.Actions) != hosttui.MaxActions-1 || view.Actions[len(view.Actions)-3].ID != "next" {
				t.Fatalf("first page actions=%+v", view.Actions)
			}
			// A syntactically valid selection that is not on this page must be ignored.
			return tuiEvent(view, fmt.Sprintf("select.%d", hosttui.MaxActions-1)), nil
		case 2:
			return tuiEvent(view, "next"), nil
		case 3:
			if view.Actions[0].ID != fmt.Sprintf("select.%d", hosttui.MaxActions-4) || view.Actions[len(view.Actions)-3].ID != "previous" {
				t.Fatalf("second page actions=%+v", view.Actions)
			}
			return tuiEvent(view, fmt.Sprintf("select.%d", hosttui.MaxActions-1)), nil
		default:
			t.Fatalf("unexpected selector call %d", call)
			return hosttui.Event{}, nil
		}
	}
	selected, err := (&tuiCoordinator{app: a, width: 100}).chooseProject(context.Background())
	if err != nil || selected == nil || selected.policy.ProjectID != projects[len(projects)-1].policy.ProjectID || call != 3 {
		t.Fatalf("selected=%+v calls=%d error=%v", selected, call, err)
	}
}

func TestTUIHomeActionsFollowPendingChangeSetState(t *testing.T) {
	base := tuiCanonicalTemp(t)
	store := &state.Store{Root: filepath.Join(base, "state", "sunaba")}
	project := tuiRegisterProject(t, store, filepath.Join(base, "project"))
	a := &app{store: store, runtime: &projectListRuntime{}, input: strings.NewReader(""), output: io.Discard, errors: io.Discard}
	c := &tuiCoordinator{app: a, width: 100}

	assertActions := func(want []string) {
		t.Helper()
		a.uiExchange = func(_ context.Context, projectID string, view hosttui.View) (hosttui.Event, error) {
			if projectID != project.policy.ProjectID || view.ScreenID != "home" {
				t.Fatalf("Home binding=%q view=%+v", projectID, view)
			}
			got := make([]string, len(view.Actions))
			for index := range view.Actions {
				got[index] = view.Actions[index].ID
			}
			if !slices.Equal(got, want) {
				t.Fatalf("Home actions=%v want=%v", got, want)
			}
			return tuiEvent(view, "exit"), nil
		}
		if _, err := c.home(context.Background(), project); err != nil {
			t.Fatal(err)
		}
	}

	assertActions([]string{"start", "settings", "exit"})
	pendingRoot := filepath.Join(project.state, "pending")
	if err := os.Mkdir(pendingRoot, 0700); err != nil {
		t.Fatal(err)
	}
	pending := `{"version":4,"project_id":"` + project.policy.ProjectID + `"}`
	if err := os.WriteFile(filepath.Join(pendingRoot, "change.json"), []byte(pending), 0600); err != nil {
		t.Fatal(err)
	}
	assertActions([]string{"changes", "settings", "exit"})
}

func TestTUIHomeActionsMatchAuthorityState(t *testing.T) {
	tests := []struct {
		name     string
		record   projectListRecord
		pending  string
		recovery bool
		want     []string
	}{
		{name: "new", record: projectListRecord{Supervisor: "none", VM: "none"}, pending: "no", want: []string{"start", "settings", "exit"}},
		{name: "paused", record: projectListRecord{Supervisor: "active", VM: "paused"}, pending: "no", want: []string{"resume", "export", "settings", "exit"}},
		{name: "running", record: projectListRecord{Supervisor: "active", VM: "running"}, pending: "no", want: []string{"resume", "export", "settings", "exit"}},
		{name: "pending", record: projectListRecord{Supervisor: "none", VM: "none"}, pending: "yes", want: []string{"changes", "settings", "exit"}},
		{name: "failed", record: projectListRecord{Supervisor: "active", VM: "failed"}, pending: "no", want: []string{"settings", "recovery", "exit"}},
		{name: "unknown", record: projectListRecord{Supervisor: "none", VM: "unknown"}, pending: "no", want: []string{"settings", "recovery", "exit"}},
		{name: "retained recovery", record: projectListRecord{Supervisor: "none", VM: "stopped"}, pending: "no", recovery: true, want: []string{"settings", "recovery", "exit"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actions := tuiHomeActions(test.record, test.pending, test.recovery)
			got := make([]string, len(actions))
			for index := range actions {
				got[index] = actions[index].ID
			}
			if !slices.Equal(got, test.want) {
				t.Fatalf("actions=%v want=%v", got, test.want)
			}
		})
	}
}

func TestTUISetupDoesNotPersistBeforeContinue(t *testing.T) {
	base := tuiCanonicalTemp(t)
	store := &state.Store{Root: filepath.Join(base, "state", "sunaba")}
	configs := &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")}
	working := filepath.Join(base, "working")
	if err := os.Mkdir(working, 0700); err != nil {
		t.Fatal(err)
	}
	tuiChdir(t, working)

	setupViews := 0
	a := &app{store: store, configs: configs, input: strings.NewReader(""), output: io.Discard, errors: io.Discard}
	a.uiExchange = func(_ context.Context, _ string, view hosttui.View) (hosttui.Event, error) {
		if _, err := os.Lstat(store.Root); !os.IsNotExist(err) {
			t.Fatalf("Setup persisted state before Continue: %v", err)
		}
		if _, err := os.Lstat(configs.Root); !os.IsNotExist(err) {
			t.Fatalf("Setup persisted configuration before Continue: %v", err)
		}
		if view.ScreenID != "setup" {
			t.Fatalf("unexpected Setup view=%+v", view)
		}
		if view.Title == "Web access details" {
			return tuiEvent(view, "back"), nil
		}
		setupViews++
		if setupViews == 1 {
			return tuiEvent(view, "details"), nil
		}
		return tuiEvent(view, "exit"), nil
	}
	selected, err := (&tuiCoordinator{app: a, width: 100}).setupOrRegister(context.Background())
	if err != nil || selected != nil || setupViews != 2 {
		t.Fatalf("selected=%+v setupViews=%d error=%v", selected, setupViews, err)
	}
	if _, err := os.Lstat(store.Root); !os.IsNotExist(err) {
		t.Fatalf("canceled Setup persisted state: %v", err)
	}
	if _, err := os.Lstat(configs.Root); !os.IsNotExist(err) {
		t.Fatalf("canceled Setup persisted configuration: %v", err)
	}
}

func TestTUILegacyDependencyMigrationRequiresConfirmation(t *testing.T) {
	base := tuiCanonicalTemp(t)
	a := &app{
		store:   &state.Store{Root: filepath.Join(base, "state", "sunaba")},
		configs: &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")},
		input:   strings.NewReader(""), output: io.Discard, errors: io.Discard,
	}
	versions, err := a.versionStore()
	if err != nil {
		t.Fatal(err)
	}
	pinned := dependency.MustPinned()
	legacy := legacyVersionLock{
		SchemaVersion: versionconfig.SchemaVersion, Generation: 3,
		ResolvedAt: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC), Manifest: legacyManifestFromCurrent(pinned),
	}
	paths, _ := versions.Paths()
	if err := writePrivateJSON(paths.Lock, legacy); err != nil {
		t.Fatal(err)
	}

	setupCalls := 0
	a.setupRun = func(context.Context, bool) error {
		setupCalls++
		lock := versionconfig.Lock{SchemaVersion: versionconfig.SchemaVersion, Generation: legacy.Generation, ResolvedAt: time.Now().UTC(), Manifest: pinned}
		if err := versions.SaveLock(lock); err != nil {
			return err
		}
		binding, err := state.NewDependencyBinding(lock.Generation, lock.Manifest)
		if err != nil {
			return err
		}
		return a.store.SaveGlobal(state.GlobalConfig{SchemaVersion: 2, Active: &binding})
	}
	a.uiExchange = func(_ context.Context, projectID string, view hosttui.View) (hosttui.Event, error) {
		if projectID != "global" || view.ScreenID != "setup" || view.Title != "Dependency setup must be upgraded before opening a Project" || setupCalls != 0 {
			t.Fatalf("migration prompt project=%q view=%+v setupCalls=%d", projectID, view, setupCalls)
		}
		view.Binding = hosttui.Binding{ProcessID: 1, ProjectID: "global", Nonce: strings.Repeat("a", 64)}
		if _, err := hosttui.PrepareView(view); err != nil {
			t.Fatalf("migration prompt violates the production UI protocol: %v", err)
		}
		return tuiEvent(view, "continue"), nil
	}
	proceed, err := (&tuiCoordinator{app: a, width: 100}).migrateLegacyDependencies(context.Background())
	if err != nil || !proceed || setupCalls != 1 {
		t.Fatalf("proceed=%t setupCalls=%d error=%v", proceed, setupCalls, err)
	}
	if _, err := a.activeVersionLock(); err != nil {
		t.Fatalf("migrated lock is not active: %v", err)
	}
}

func TestTUILegacyDependencyMigrationExitDoesNotMutate(t *testing.T) {
	called := false
	a := &app{input: strings.NewReader(""), output: io.Discard, errors: io.Discard}
	a.setupRun = func(context.Context, bool) error {
		called = true
		return nil
	}
	a.uiExchange = func(_ context.Context, projectID string, view hosttui.View) (hosttui.Event, error) {
		if projectID != "global" || view.ScreenID != "setup" || view.Title != "Dependency setup must be upgraded before opening a Project" {
			t.Fatalf("migration prompt project=%q view=%+v", projectID, view)
		}
		return tuiEvent(view, "exit"), nil
	}
	proceed, err := (&tuiCoordinator{app: a, width: 100}).migrateLegacyDependencies(context.Background())
	if err != nil || proceed || called {
		t.Fatalf("proceed=%t setupCalled=%t error=%v", proceed, called, err)
	}
}

func TestTUIStartupRoutesLegacyDependencyLockToMigration(t *testing.T) {
	base := tuiCanonicalTemp(t)
	a := &app{
		store:   &state.Store{Root: filepath.Join(base, "state", "sunaba")},
		configs: &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")},
		input:   strings.NewReader(""), output: io.Discard, errors: io.Discard,
		terminalCheck: func(io.Reader, io.Writer) bool { return true },
	}
	versions, err := a.versionStore()
	if err != nil {
		t.Fatal(err)
	}
	pinned := dependency.MustPinned()
	legacy := legacyVersionLock{
		SchemaVersion: versionconfig.SchemaVersion, Generation: 4,
		ResolvedAt: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC), Manifest: legacyManifestFromCurrent(pinned),
	}
	paths, _ := versions.Paths()
	if err := writePrivateJSON(paths.Lock, legacy); err != nil {
		t.Fatal(err)
	}
	tuiRegisterProject(t, a.store, filepath.Join(base, "project"))

	exchanges := 0
	a.uiExchange = func(_ context.Context, projectID string, view hosttui.View) (hosttui.Event, error) {
		exchanges++
		if projectID != "global" || view.ScreenID != "setup" || view.Title != "Dependency setup must be upgraded before opening a Project" {
			t.Fatalf("startup bypassed migration prompt: project=%q view=%+v", projectID, view)
		}
		return tuiEvent(view, "exit"), nil
	}
	if err := a.tui(context.Background()); err != nil {
		t.Fatalf("TUI startup returned the legacy manifest validation error: %v", err)
	}
	if exchanges != 1 {
		t.Fatalf("migration prompt exchanges=%d", exchanges)
	}
}

func TestTUIHelperExitPrecedesOpenCodeAndReturnsToFreshHome(t *testing.T) {
	base := tuiCanonicalTemp(t)
	store := &state.Store{Root: filepath.Join(base, "state", "sunaba")}
	project := tuiRegisterProject(t, store, filepath.Join(base, "project"))
	configs := &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")}
	config, rules := projectconfig.FromPolicy(project.policy)
	if err := configs.Save(project.policy.ProjectID, config, rules); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project.policy.ProjectRoot, ".env"), []byte("TOKEN=not-rendered\n"), 0600); err != nil {
		t.Fatal(err)
	}

	order := make([]string, 0, 4)
	revisions := make([]uint64, 0, 2)
	homeCount := 0
	a := &app{store: store, configs: configs, input: strings.NewReader(""), output: io.Discard, errors: io.Discard}
	a.uiExchange = func(_ context.Context, projectID string, view hosttui.View) (hosttui.Event, error) {
		if projectID != project.policy.ProjectID {
			t.Fatalf("unexpected helper exchange project=%q view=%+v", projectID, view)
		}
		if view.ScreenID == "setup" {
			if view.Title != "Review and approve the Snapshot before Start" {
				t.Fatalf("unexpected Snapshot review=%+v", view)
			}
			fieldText := make(map[string]string, len(view.Fields))
			for _, field := range view.Fields {
				fieldText[field.ID] = field.Text
			}
			allFields := strings.Join(mapsValues(fieldText), " ")
			if fieldText["reason"] != "The first Snapshot has not been approved." || strings.Contains(fieldText["reason"], "snapshot preview") ||
				len(fieldText["digest"]) != 64 || !strings.Contains(fieldText["sensitive.0"], ".env") || strings.Contains(allFields, "TOKEN=") {
				t.Fatalf("unsafe or incomplete Snapshot review fields=%+v", view.Fields)
			}
			view.Binding = hosttui.Binding{ProcessID: 1, ProjectID: project.policy.ProjectID, Nonce: strings.Repeat("a", 64)}
			if _, err := hosttui.PrepareView(view); err != nil {
				t.Fatalf("Snapshot review violates the production UI protocol: %v", err)
			}
			order = append(order, "helper-snapshot-exited")
			return tuiEvent(view, "approve-start"), nil
		}
		if view.ScreenID != "home" {
			t.Fatalf("unexpected helper view=%+v", view)
		}
		homeCount++
		revisions = append(revisions, view.Revision)
		order = append(order, "helper-home-"+string(rune('0'+homeCount))+"-exited")
		if homeCount == 1 {
			return tuiEvent(view, "start"), nil
		}
		return tuiEvent(view, "exit"), nil
	}
	a.agentRun = func(_ context.Context, root string) error {
		if root != project.policy.ProjectRoot {
			t.Fatalf("OpenCode root=%q", root)
		}
		order = append(order, "opencode")
		return nil
	}
	if err := (&tuiCoordinator{app: a, width: 100}).projectLoop(context.Background(), project); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(order, []string{"helper-home-1-exited", "helper-snapshot-exited", "opencode", "helper-home-2-exited"}) {
		t.Fatalf("lifecycle order=%v", order)
	}
	if len(revisions) != 2 || revisions[0] == revisions[1] || revisions[1] <= revisions[0] {
		t.Fatalf("Home was not rebuilt with a fresh revision: %v", revisions)
	}
	_, projectState, compiled, manifest, err := a.snapshotManifest(project.policy.ProjectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifySnapshotApproval(projectState, compiled, manifest); err != nil {
		t.Fatalf("Snapshot review did not persist its exact approval: %v", err)
	}
	approvalPath := filepath.Join(projectState, snapshotApprovalFile)
	before, err := os.ReadFile(approvalPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project.policy.ProjectRoot, ".env"), []byte("TOKEN=changed-but-not-rendered\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a.uiExchange = func(_ context.Context, projectID string, view hosttui.View) (hosttui.Event, error) {
		if projectID != project.policy.ProjectID || view.ScreenID != "setup" || view.Fields[0].ID != "reason" || view.Fields[0].Text != "The host Project changed after the previous Snapshot approval." {
			t.Fatalf("changed Project did not require a new Snapshot review: project=%q view=%+v", projectID, view)
		}
		return tuiEvent(view, "back"), nil
	}
	approved, err := (&tuiCoordinator{app: a, width: 100}).ensureSnapshotApproval(context.Background(), project)
	if err != nil || approved {
		t.Fatalf("changed Snapshot approved=%t error=%v", approved, err)
	}
	after, err := os.ReadFile(approvalPath)
	if err != nil || string(after) != string(before) {
		t.Fatalf("Back mutated Snapshot approval: before=%q after=%q error=%v", before, after, err)
	}
}

func TestTUIFailureFlattensMultilineDiagnostics(t *testing.T) {
	a := &app{input: strings.NewReader(""), output: io.Discard, errors: io.Discard}
	a.uiExchange = func(_ context.Context, projectID string, view hosttui.View) (hosttui.Event, error) {
		if projectID != "project" || view.ScreenID != "recovery" {
			t.Fatalf("failure binding=%q view=%+v", projectID, view)
		}
		got := view.Fields[0].Text
		if strings.ContainsAny(got, "\r\n") || strings.Contains(got, "<U+000A>") || !strings.Contains(got, "first · second") {
			t.Fatalf("multiline failure was not flattened: %q", got)
		}
		view.Binding = hosttui.Binding{ProcessID: 1, ProjectID: projectID, Nonce: strings.Repeat("b", 64)}
		prepared, err := hosttui.PrepareView(view)
		if err != nil || !strings.Contains(prepared.Fields[0].Text, "<U+001B>") || strings.Contains(prepared.Fields[0].Text, "<U+000A>") {
			t.Fatalf("prepared failure=%+v error=%v", prepared.Fields[0], err)
		}
		return tuiEvent(view, "exit"), nil
	}
	exit, err := (&tuiCoordinator{app: a, width: 100}).failure(context.Background(), "project", errors.New("first\n\nsecond\x1b"), "preserved", "retry")
	if err != nil || !exit {
		t.Fatalf("exit=%t error=%v", exit, err)
	}
}

func mapsValues(values map[string]string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func tuiRegisterProject(t *testing.T, store *state.Store, root string) tuiProject {
	t.Helper()
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	manifest := dependency.MustPinned()
	digest, err := dependency.ManifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	projectPolicy, err := policy.New(canonical, digest, manifest.OpenCode.Version, manifest.AppleContainer.Version, manifest.AgentImage.Tag, "secure", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	projectState := filepath.Join(store.Root, "projects", projectPolicy.ProjectID)
	if err := os.Mkdir(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	if err := policy.Save(filepath.Join(projectState, "policy.json"), projectPolicy); err != nil {
		t.Fatal(err)
	}
	return tuiProject{policy: projectPolicy, state: projectState}
}

func tuiEvent(view hosttui.View, action string) hosttui.Event {
	return hosttui.Event{
		Version: hosttui.ProtocolVersion, Type: "event", ScreenID: view.ScreenID, Revision: view.Revision,
		Binding: view.Binding, Kind: hosttui.EventAction, ActionID: action,
		Size: hosttui.TerminalSize{Width: 100, Height: 40},
	}
}

func tuiCanonicalTemp(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func tuiChdir(t *testing.T, directory string) {
	t.Helper()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })
}
