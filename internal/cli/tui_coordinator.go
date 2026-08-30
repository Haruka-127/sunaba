package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"sunaba/internal/dependency"
	"sunaba/internal/openauth"
	"sunaba/internal/policy"
	"sunaba/internal/recovery"
	"sunaba/internal/runtime"
	"sunaba/internal/secretstore"
	"sunaba/internal/state"
	"sunaba/internal/terminal"
	hosttui "sunaba/internal/tui"
	"sunaba/internal/webgateway"
	"sunaba/internal/workspace"
)

type tuiProject struct {
	policy policy.ProjectPolicy
	state  string
}

type tuiCoordinator struct {
	app      *app
	revision atomic.Uint64
	width    int
	warning  string
}

func (a *app) tui(ctx context.Context) error {
	if !a.hasInteractiveTerminal() {
		return fmt.Errorf("sunaba without a subcommand requires an interactive terminal; use an explicit subcommand or JSON-capable command")
	}
	coordinator := &tuiCoordinator{app: a, width: 100}
	if _, err := a.activeVersionLock(); errors.Is(err, errLegacyDependencyMigrationRequired) {
		proceed, migrationErr := coordinator.migrateLegacyDependencies(ctx)
		if migrationErr != nil || !proceed {
			return migrationErr
		}
	}
	project, err := coordinator.chooseProject(ctx)
	if err != nil || project == nil {
		return err
	}
	return coordinator.projectLoop(ctx, *project)
}

func (a *app) runSetup(ctx context.Context, configOnly bool) error {
	if a.setupRun != nil {
		return a.setupRun(ctx, configOnly)
	}
	return a.setup(ctx, configOnly)
}

func (c *tuiCoordinator) migrateLegacyDependencies(ctx context.Context) (bool, error) {
	fields := []hosttui.TextField{
		{ID: "reason", Label: "Required update", Text: "The existing dependency lock uses an older exact managed TUI artifact contract."},
		{ID: "scope", Label: "Changes", Text: "The dependency lock, active binding, and registered Project dependency digests are migrated together."},
		{ID: "safety", Label: "Safety", Text: "Nothing is changed until Continue. Active Project operations or mismatched dependency state stop the migration."},
	}
	event, err := c.exchange(ctx, "global", c.view("setup", "Dependency setup must be upgraded before opening a Project", fields, []hosttui.Action{
		noInputAction("continue", "Continue"), noInputAction("exit", "Exit"),
	}))
	if err != nil {
		return false, err
	}
	if event.Kind != hosttui.EventAction || event.ActionID != "continue" {
		return false, nil
	}
	if err := c.app.runSetup(ctx, false); err != nil {
		return false, fmt.Errorf("migrate dependency setup: %w", err)
	}
	if _, err := c.app.activeVersionLock(); err != nil {
		return false, fmt.Errorf("validate migrated dependency setup: %w", err)
	}
	return true, nil
}

func (a *app) hasInteractiveTerminal() bool {
	if a.terminalCheck != nil {
		return a.terminalCheck(a.input, a.output)
	}
	input, inputOK := a.input.(*os.File)
	output, outputOK := a.output.(*os.File)
	return inputOK && outputOK && terminal.IsTTY(input) && terminal.IsTTY(output)
}

func (c *tuiCoordinator) view(screen, title string, fields []hosttui.TextField, actions []hosttui.Action) hosttui.View {
	if fields == nil {
		fields = []hosttui.TextField{}
	}
	if actions == nil {
		actions = []hosttui.Action{}
	}
	revision := c.revision.Add(1)
	return hosttui.View{Version: hosttui.ProtocolVersion, Type: "view", ScreenID: screen, Revision: revision, Title: title, Fields: fields, Actions: actions}
}

func noInputAction(id, label string) hosttui.Action {
	return hosttui.Action{ID: id, Label: label}
}

func inputAction(id, label string, masked bool, maximum int) hosttui.Action {
	return hosttui.Action{ID: id, Label: label, Input: hosttui.InputSpec{Allowed: true, Masked: masked, MaxBytes: maximum}}
}

func (c *tuiCoordinator) exchange(ctx context.Context, projectID string, view hosttui.View) (hosttui.Event, error) {
	event, err := c.app.exchangeUIView(ctx, projectID, view)
	if err != nil {
		return hosttui.Event{}, err
	}
	if event.Size.Width > 0 {
		c.width = event.Size.Width
	}
	if event.Kind == hosttui.EventTerminalError {
		return hosttui.Event{}, fmt.Errorf("sunaba UI terminal error: %s", event.Error)
	}
	return event, nil
}

func (a *app) exchangeUIView(ctx context.Context, projectID string, view hosttui.View) (hosttui.Event, error) {
	if a.uiExchange != nil {
		return a.uiExchange(ctx, projectID, view)
	}
	manifest, helper, err := a.uiHelper()
	if err != nil {
		return hosttui.Event{}, err
	}
	if err := hosttui.VerifyHelperExecutable(helper, hosttui.ArtifactPin{OS: manifest.SunabaUI.OS, Arch: manifest.SunabaUI.Arch, SHA256: manifest.SunabaUI.SHA256}); err != nil {
		return hosttui.Event{}, err
	}
	endpoint, err := hosttui.NewEndpoint(os.TempDir(), projectID)
	if err != nil {
		return hosttui.Event{}, err
	}
	defer endpoint.Close()
	spec := endpoint.LaunchSpec()
	command := exec.CommandContext(ctx, helper, "--socket", spec.Socket, "--project-id", spec.ProjectID, "--nonce", spec.Nonce)
	command.Stdin, command.Stdout, command.Stderr = a.input, a.output, a.errors
	command.Env = uiHelperEnvironment(os.Environ())
	command.Dir = endpoint.Directory
	if err := command.Start(); err != nil {
		return hosttui.Event{}, err
	}
	binding, err := endpoint.BindHelperPID(command.Process.Pid)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return hosttui.Event{}, err
	}
	view.Binding = binding
	view, err = hosttui.PrepareView(view)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return hosttui.Event{}, err
	}
	wait := make(chan error, 1)
	go func() {
		wait <- command.Wait()
		_ = endpoint.Close()
	}()
	event, eventErr := endpoint.ServeOnce(ctx, view)
	var waitErr error
	killedByAuthority := false
	if eventErr == nil {
		waitErr = <-wait
	} else {
		select {
		case waitErr = <-wait:
		case <-time.After(250 * time.Millisecond):
			if killErr := command.Process.Kill(); killErr == nil {
				killedByAuthority = true
			}
			waitErr = <-wait
		}
	}
	if err := uiExchangeResultError(eventErr, waitErr, killedByAuthority); err != nil {
		return hosttui.Event{}, err
	}
	return event, nil
}

func uiExchangeResultError(eventErr, waitErr error, killedByAuthority bool) error {
	if eventErr != nil {
		if waitErr != nil && !killedByAuthority {
			return errors.Join(fmt.Errorf("sunaba-ui did not return a complete event: %w", eventErr), fmt.Errorf("sunaba-ui exited unsuccessfully: %w", waitErr))
		}
		return fmt.Errorf("sunaba-ui did not return a complete event: %w", eventErr)
	}
	if waitErr != nil {
		return fmt.Errorf("sunaba-ui exited unsuccessfully: %w", waitErr)
	}
	return nil
}

func uiHelperEnvironment(environment []string) []string {
	allowed := map[string]struct{}{
		"COLORTERM": {}, "LANG": {}, "LC_ALL": {}, "LC_CTYPE": {}, "NO_COLOR": {}, "TERM": {}, "TERM_PROGRAM": {}, "TZ": {},
	}
	result := make([]string, 0, len(allowed))
	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if _, ok := allowed[name]; !found || !ok || len(value) > 4096 || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			continue
		}
		result = append(result, name+"="+value)
	}
	sort.Strings(result)
	return result
}

func (a *app) uiHelper() (dependency.Manifest, string, error) {
	manifest := dependency.MustPinned()
	if lock, err := a.activeVersionLock(); err == nil {
		manifest = lock.Manifest
		managed := filepath.Join(a.store.Root, "tools", "sunaba-ui", "v"+manifest.SunabaUI.Version, "sunaba-ui")
		if _, statErr := os.Lstat(managed); statErr == nil {
			return manifest, managed, nil
		}
	}
	helper, err := siblingExecutable("sunaba-ui")
	if err != nil {
		return dependency.Manifest{}, "", fmt.Errorf("bundled sunaba-ui is unavailable: %w", err)
	}
	return manifest, helper, nil
}

func (c *tuiCoordinator) chooseProject(ctx context.Context) (*tuiProject, error) {
	projects, err := c.projects()
	if err != nil {
		return nil, err
	}
	if current := currentTUIProject(projects); current != nil {
		return current, nil
	}
	if len(projects) == 0 {
		return c.setupOrRegister(ctx)
	}
	page := 0
	const pageSize = hosttui.MaxActions - 4
	for {
		start := page * pageSize
		if start >= len(projects) {
			page = 0
			start = 0
		}
		end := min(start+pageSize, len(projects))
		fields := make([]hosttui.TextField, 0, end-start+1)
		fields = append(fields, hosttui.TextField{ID: "page", Label: "Projects", Text: fmt.Sprintf("%d-%d of %d", start+1, end, len(projects))})
		actions := make([]hosttui.Action, 0, hosttui.MaxActions)
		for index := start; index < end; index++ {
			fields = append(fields, hosttui.TextField{ID: fmt.Sprintf("project.%d", index), Label: projects[index].policy.ProjectID, Text: projects[index].policy.ProjectRoot})
			actions = append(actions, noInputAction(fmt.Sprintf("select.%d", index), "Open "+projects[index].policy.ProjectRoot))
		}
		if start > 0 {
			actions = append(actions, noInputAction("previous", "Previous Projects"))
		}
		if end < len(projects) {
			actions = append(actions, noInputAction("next", "Next Projects"))
		}
		actions = append(actions, noInputAction("register", "Register current directory"), noInputAction("exit", "Exit"))
		event, err := c.exchange(ctx, "global", c.view("project-selector", "Select a registered Project", fields, actions))
		if err != nil {
			return nil, err
		}
		if event.Kind == hosttui.EventExit || event.Kind == hosttui.EventCancel || event.ActionID == "exit" {
			return nil, nil
		}
		if event.ActionID == "register" {
			if err := c.app.projectInit(ctx, ".", "secure"); err != nil {
				return nil, err
			}
			return c.projectForPath(".")
		}
		if event.ActionID == "previous" && start > 0 {
			page--
			continue
		}
		if event.ActionID == "next" && end < len(projects) {
			page++
			continue
		}
		var index int
		if _, err := fmt.Sscanf(event.ActionID, "select.%d", &index); err == nil && index >= start && index < end {
			selected := projects[index]
			return &selected, nil
		}
	}
}

func (c *tuiCoordinator) projects() ([]tuiProject, error) {
	states, err := c.app.store.ListProjectStates()
	if err != nil {
		return nil, err
	}
	projects := make([]tuiProject, 0, len(states))
	for _, item := range states {
		if item.Err != nil {
			return nil, fmt.Errorf("registered Project %s has unsafe state: %w; use 'sunaba project list' and the explicit recovery CLI", item.ProjectID, item.Err)
		}
		loaded, _, err := policy.LoadReadOnly(filepath.Join(item.Path, "policy.json"), nowUTC())
		if err != nil || loaded.ProjectID != item.ProjectID {
			return nil, fmt.Errorf("registered Project %s has invalid policy; use 'sunaba project list' and the explicit recovery CLI", item.ProjectID)
		}
		projects = append(projects, tuiProject{policy: loaded, state: item.Path})
	}
	sort.Slice(projects, func(i, j int) bool { return projects[i].policy.ProjectRoot < projects[j].policy.ProjectRoot })
	return projects, nil
}

func currentTUIProject(projects []tuiProject) *tuiProject {
	working, err := state.ResolveProjectPath(".")
	if err != nil {
		return nil
	}
	best := -1
	for index := range projects {
		root := projects[index].policy.ProjectRoot
		if working == root || strings.HasPrefix(working, root+string(filepath.Separator)) {
			if best < 0 || len(root) > len(projects[best].policy.ProjectRoot) {
				best = index
			}
		}
	}
	if best < 0 {
		return nil
	}
	selected := projects[best]
	return &selected
}

func (c *tuiCoordinator) projectForPath(path string) (*tuiProject, error) {
	root, err := state.ResolveProjectPath(path)
	if err != nil {
		return nil, err
	}
	loaded, _, projectState, err := c.app.loadPolicy(root)
	if err != nil {
		return nil, err
	}
	return &tuiProject{policy: loaded, state: projectState}, nil
}

func (c *tuiCoordinator) setupOrRegister(ctx context.Context) (*tuiProject, error) {
	setupComplete := false
	if _, err := c.app.activeVersionLock(); err == nil {
		setupComplete = true
	}
	if setupComplete {
		view := c.view("project-selector", "No Projects are registered", []hosttui.TextField{{ID: "current", Label: "Current directory", Text: mustCurrentDirectory()}}, []hosttui.Action{noInputAction("register", "Register current directory"), noInputAction("exit", "Exit")})
		event, err := c.exchange(ctx, "global", view)
		if err != nil || event.Kind != hosttui.EventAction || event.ActionID != "register" {
			return nil, err
		}
		if err := c.app.projectInit(ctx, ".", "secure"); err != nil {
			return nil, err
		}
		return c.projectForPath(".")
	}
	remotes := detectProjectGitRemotes(ctx, mustCurrentDirectory())
	remoteLimit := min(len(remotes), hosttui.MaxActions-3)
	fields := []hosttui.TextField{
		{ID: "mode", Label: "Execution mode", Text: "Secure"},
		{ID: "ai", Label: "AI connection", Text: "OAuth"},
		{ID: "web", Label: "Web access", Text: "Access to standard sites needed for development"},
	}
	for index, remote := range remotes[:remoteLimit] {
		fields = append(fields, hosttui.TextField{ID: fmt.Sprintf("remote.%d", index), Label: "Detected Git remote", Text: remote.Name + "  " + remote.URL})
	}
	if remoteLimit < len(remotes) {
		fields = append(fields, hosttui.TextField{ID: "remote.more", Label: "Additional Git remotes", Text: fmt.Sprintf("%d more can be configured later from Settings or the advanced CLI.", len(remotes)-remoteLimit)})
	}
	actions := []hosttui.Action{noInputAction("continue", "Continue without Git remote")}
	for index, remote := range remotes[:remoteLimit] {
		actions = append(actions, noInputAction(fmt.Sprintf("continue.%d", index), "Continue and add "+remote.Name))
	}
	actions = append(actions, noInputAction("details", "Details"), noInputAction("exit", "Exit"))
	for {
		event, err := c.exchange(ctx, "global", c.view("setup", "Review recommended settings. Nothing is saved until Continue.", fields, actions))
		if err != nil {
			return nil, err
		}
		if event.Kind != hosttui.EventAction || event.ActionID == "exit" {
			return nil, nil
		}
		if event.ActionID == "details" {
			rules, _, resolveErr := webgateway.ResolveOriginRules([]string{webgateway.CommonDevelopmentOriginPreset}, nil)
			if resolveErr != nil {
				return nil, resolveErr
			}
			exactOrigins := make([]string, len(rules))
			for index, rule := range rules {
				methods := make([]string, 0, 2)
				if rule.AllowHTTP {
					methods = append(methods, "HTTP")
				}
				if rule.AllowConnect {
					methods = append(methods, "HTTPS CONNECT")
				}
				exactOrigins[index] = fmt.Sprintf("%s:%d [%s]", rule.Host, rule.Port, strings.Join(methods, ", "))
				if rule.IncludeSubdomains {
					exactOrigins[index] += " (including subdomains)"
				}
			}
			detail := c.view("setup", "Web access details", []hosttui.TextField{
				{ID: "origins", Label: "Exact origins", Text: strings.Join(exactOrigins, "\n")},
				{ID: "connect", Label: "HTTPS CONNECT", Text: "Encrypted internal methods and upload contents cannot be inspected."},
				{ID: "quota", Label: "Quota", Text: "Requests, concurrency, upload, download, and total bytes are bounded."},
			}, []hosttui.Action{noInputAction("back", "Back")})
			if _, err := c.exchange(ctx, "global", detail); err != nil {
				return nil, err
			}
			continue
		}
		selected := -1
		if event.ActionID != "continue" {
			if _, err := fmt.Sscanf(event.ActionID, "continue.%d", &selected); err != nil || selected < 0 || selected >= remoteLimit {
				continue
			}
		}
		if err := c.app.runSetup(ctx, false); err != nil {
			return nil, err
		}
		if err := c.app.projectInit(ctx, ".", "secure"); err != nil {
			return nil, err
		}
		project, err := c.projectForPath(".")
		if err != nil {
			return nil, err
		}
		if err := c.app.webPolicy(ctx, "enable", project.policy.ProjectRoot, false, true, nil); err != nil {
			c.warning = "Recommended Web access could not be prepared: " + err.Error()
		}
		if selected >= 0 {
			remote := remotes[selected]
			if err := c.app.gitPolicy(ctx, "remote-add", project.policy.ProjectRoot, remote.Name, remote.URL); err != nil {
				return nil, err
			}
		}
		if err := c.app.modelAuth(ctx, "oauth"); err != nil {
			return nil, err
		}
		if err := openauth.NewManager().Login(ctx, c.app.output); err != nil {
			c.warning = appendWarning(c.warning, "OAuth was not completed. Configure AI connection from Settings before starting an Agent Session.")
		}
		return c.projectForPath(project.policy.ProjectRoot)
	}
}

func (c *tuiCoordinator) projectLoop(ctx context.Context, project tuiProject) error {
	for {
		refreshed, err := c.projectForPath(project.policy.ProjectRoot)
		if err != nil {
			return err
		}
		project = *refreshed
		event, err := c.home(ctx, project)
		if err != nil {
			return err
		}
		if event.Kind == hosttui.EventExit || event.Kind == hosttui.EventCancel || event.ActionID == "exit" {
			return nil
		}
		switch event.ActionID {
		case "start", "resume":
			if event.ActionID == "start" {
				approved, approvalErr := c.ensureSnapshotApproval(ctx, project)
				if approvalErr != nil {
					if exit, showErr := c.failure(ctx, project.policy.ProjectID, approvalErr, "No VM was created and the host Project was not changed.", "Return Home and review the Snapshot again. Use the advanced snapshot CLI only if the TUI review remains unavailable."); showErr != nil {
						return showErr
					} else if exit {
						return nil
					}
					continue
				}
				if !approved {
					continue
				}
			}
			// The one-shot helper has fully exited before authority starts OpenCode.
			runAgent := c.app.agent
			if c.app.agentRun != nil {
				runAgent = c.app.agentRun
			}
			if err := runAgent(ctx, project.policy.ProjectRoot); err != nil {
				if exit, showErr := c.failure(ctx, project.policy.ProjectID, err, "The host Project and any retained VM work were not automatically applied or destroyed.", "Return Home, review the status, then retry or open Recovery."); showErr != nil {
					return showErr
				} else if exit {
					return nil
				}
			}
		case "changes":
			if err := c.changes(ctx, project); err != nil {
				if exit, showErr := c.failure(ctx, project.policy.ProjectID, err, "The pending Change Set and host Project were not automatically discarded or partially applied.", "Return Home and review the same Change Set again."); showErr != nil {
					return showErr
				} else if exit {
					return nil
				}
			}
		case "export":
			pending, changed, exportErr := c.app.exportPendingChanges(ctx, project.policy, project.state, false)
			if exportErr != nil {
				if exit, showErr := c.failure(ctx, project.policy.ProjectID, exportErr, "The host Project was not changed and retained work was not automatically discarded.", "Return Home and retry export, or open Recovery if it remains unavailable."); showErr != nil {
					return showErr
				} else if exit {
					return nil
				}
				continue
			}
			if !changed {
				c.warning = "Export completed with no Project changes; the retained VM was removed."
				continue
			}
			if err := c.changesForPending(ctx, project, pending); err != nil {
				return err
			}
		case "settings":
			if err := c.settings(ctx, project); err != nil {
				if exit, showErr := c.failure(ctx, project.policy.ProjectID, err, "Existing Project state and credentials were retained; any completed setting change remains explicit.", "Return Home, inspect Settings, and retry the refused change."); showErr != nil {
					return showErr
				} else if exit {
					return nil
				}
			}
		case "recovery":
			if err := c.recovery(ctx, project); err != nil {
				if exit, showErr := c.failure(ctx, project.policy.ProjectID, err, "Recovery failure does not authorize automatic discard of retained work.", "Return Home and retry the safe export path or use the explicit recovery CLI."); showErr != nil {
					return showErr
				} else if exit {
					return nil
				}
			}
		}
	}
}

func (c *tuiCoordinator) home(ctx context.Context, project tuiProject) (hosttui.Event, error) {
	var containers map[string][]runtime.Info
	var runtimeErr error
	if c.app.runtime == nil {
		runtimeErr = errors.New("runtime inventory is unavailable")
	} else {
		items, err := c.app.runtime.List(ctx)
		runtimeErr = err
		containers = ownedProjectVMs(items)
	}
	record := c.app.projectListRecord(ctx, state.ProjectState{ProjectID: project.policy.ProjectID, Path: project.state}, containers, runtimeErr)
	pending := pendingInventoryState(project.state, project.policy.ProjectID)
	work := "Host Project is unchanged; VM workspace state is isolated."
	if pending == "yes" {
		work = "A pending Change Set is safely retained for review."
	} else if runtimeErr != nil || record.VM == "unknown" || record.Supervisor == "invalid" || record.Supervisor == "unavailable" {
		work = "Work safety cannot be confirmed from the current inventory; mutation is disabled."
	}
	fields := []hosttui.TextField{
		{ID: "project", Label: "Project", Text: project.policy.ProjectRoot},
		{ID: "session", Label: "VM and Agent Session", Text: record.VM + " / " + record.Supervisor},
		{ID: "work", Label: "Work safety", Text: work},
		{ID: "pending", Label: "Pending Change Set", Text: pending},
		{ID: "push", Label: "Git push approvals", Text: "During OpenCode, use sunaba approvals in a separate host terminal."},
	}
	if c.warning != "" {
		fields = append(fields, hosttui.TextField{ID: "warning", Label: "Warning", Text: singleLineTUIMessage(c.warning)})
		c.warning = ""
	}
	actions := tuiHomeActions(record, pending, recoveryExists(project.state))
	return c.exchange(ctx, project.policy.ProjectID, c.view("home", "Choose the recommended available action", fields, actions))
}

func (c *tuiCoordinator) ensureSnapshotApproval(ctx context.Context, project tuiProject) (bool, error) {
	projectPolicy, projectState, compiled, manifest, err := c.app.snapshotManifest(project.policy.ProjectRoot)
	if err != nil {
		return false, err
	}
	if projectPolicy.ProjectID != project.policy.ProjectID || projectState != project.state {
		return false, fmt.Errorf("Project identity changed while preparing the Snapshot review")
	}
	_, approvalErr := verifySnapshotApproval(projectState, compiled, manifest)
	if approvalErr == nil {
		return true, nil
	}
	preview := workspace.BuildSnapshotPreview(manifest)
	fields := []hosttui.TextField{
		{ID: "reason", Label: "Approval required", Text: snapshotApprovalTUIReason(approvalErr)},
		{ID: "digest", Label: "Exact Snapshot digest", Text: preview.Digest},
		{ID: "entries", Label: "Included metadata", Text: fmt.Sprintf("%d entries (%d files), %d total bytes", preview.EntryCount, preview.FileCount, preview.TotalSize)},
		{ID: "excluded", Label: "Excluded paths", Text: fmt.Sprintf("%d paths from the active host policy", len(compiled.Snapshot.ExcludedPaths))},
		{ID: "contents", Label: "Content disclosure", Text: "File contents, secret values, and per-file hashes are not displayed by this review."},
	}
	const largeLimit = 10
	for index, file := range preview.LargeFiles[:min(len(preview.LargeFiles), largeLimit)] {
		fields = append(fields, hosttui.TextField{ID: fmt.Sprintf("large.%d", index), Label: "Large file warning", Text: fmt.Sprintf("%s (%d bytes)", boundedTUIPath(file.Path), file.Size)})
	}
	if len(preview.LargeFiles) > largeLimit {
		fields = append(fields, hosttui.TextField{ID: "large.more", Label: "Additional large files", Text: fmt.Sprintf("%d more; use 'sunaba snapshot preview' for the bounded CLI list", len(preview.LargeFiles)-largeLimit)})
	}
	const sensitiveLimit = 20
	for index, path := range preview.SensitivePaths[:min(len(preview.SensitivePaths), sensitiveLimit)] {
		fields = append(fields, hosttui.TextField{ID: fmt.Sprintf("sensitive.%d", index), Label: "Sensitive filename warning", Text: boundedTUIPath(path)})
	}
	if len(preview.SensitivePaths) > sensitiveLimit {
		fields = append(fields, hosttui.TextField{ID: "sensitive.more", Label: "Additional sensitive filenames", Text: fmt.Sprintf("%d more; use 'sunaba snapshot preview' for the bounded CLI list", len(preview.SensitivePaths)-sensitiveLimit)})
	}
	view := c.view("setup", "Review and approve the Snapshot before Start", fields, []hosttui.Action{
		noInputAction("approve-start", "Approve and Start"), noInputAction("back", "Back to Home"),
	})
	event, exchangeErr := c.exchange(ctx, project.policy.ProjectID, view)
	if exchangeErr != nil {
		return false, exchangeErr
	}
	if event.Kind != hosttui.EventAction || event.ActionID != "approve-start" {
		return false, nil
	}
	if err := c.app.snapshotApprove(project.policy.ProjectRoot, preview.Digest); err != nil {
		return false, fmt.Errorf("approve displayed Snapshot: %w", err)
	}
	return true, nil
}

func snapshotApprovalTUIReason(err error) string {
	switch {
	case errors.Is(err, errSnapshotApprovalMissing):
		return "The first Snapshot has not been approved."
	case errors.Is(err, errSnapshotApprovalInvalid):
		return "The saved approval is invalid or belongs to a different exclusion policy."
	case errors.Is(err, errSnapshotApprovalChanged):
		return "The host Project changed after the previous Snapshot approval."
	default:
		return singleLineTUIMessage(err.Error())
	}
}

func boundedTUIPath(value string) string {
	const maximumBytes = 512
	if len(value) <= maximumBytes {
		return value
	}
	cut := maximumBytes
	for cut > 0 && !utf8.ValidString(value[:cut]) {
		cut--
	}
	return value[:cut] + "…"
}

func tuiHomeActions(record projectListRecord, pending string, hasRecovery bool) []hosttui.Action {
	actions := make([]hosttui.Action, 0, 6)
	if pending == "yes" {
		actions = append(actions, noInputAction("changes", "Review changes"))
	} else if !hasRecovery && record.Supervisor == "active" && (record.VM == "paused" || record.VM == "running") {
		actions = append(actions, noInputAction("resume", "Resume"), noInputAction("export", "Export and review changes"))
	} else if !hasRecovery && record.Supervisor == "none" && record.VM == "none" {
		actions = append(actions, noInputAction("start", "Start"))
	}
	actions = append(actions, noInputAction("settings", "Settings"))
	if hasRecovery || pending != "yes" && (record.VM != "none" || record.Supervisor != "none") && !(record.Supervisor == "active" && (record.VM == "paused" || record.VM == "running")) {
		actions = append(actions, noInputAction("recovery", "Recovery"))
	}
	return append(actions, noInputAction("exit", "Exit"))
}

func (c *tuiCoordinator) settings(ctx context.Context, project tuiProject) error {
	for {
		settingsStore, err := c.app.userSettingsStore()
		if err != nil {
			return err
		}
		settings, err := settingsStore.Load()
		if err != nil {
			return err
		}
		activeStatus := "Not configured"
		if (settings.ModelAuth == "api_key" && secretstore.OpenAIKeyExists(ctx) == nil) || (settings.ModelAuth == "oauth" && secretstore.CodexOAuthExists(ctx) == nil) {
			activeStatus = "Configured"
		}
		authLabel := "OAuth"
		if settings.ModelAuth == "api_key" {
			authLabel = "API key"
		}
		web := "Disabled"
		if project.policy.Web.Enabled {
			web = "Access to standard sites needed for development"
		}
		fields := []hosttui.TextField{
			{ID: "mode", Label: "Execution mode", Text: titleMode(project.policy.Mode)},
			{ID: "ai", Label: "AI connection", Text: authLabel + " · " + activeStatus},
			{ID: "web", Label: "Web access", Text: web},
			{ID: "git", Label: "Git remotes", Text: fmt.Sprintf("%d configured", len(project.policy.Git.Remotes))},
			{ID: "advanced", Label: "Advanced", Text: "Resources, quotas, TTL, Snapshot exclusions, and exact dependency locks are available through the advanced CLI."},
		}
		actions := []hosttui.Action{
			noInputAction("auth.change", "Change authentication method"),
			noInputAction("git.manage", "Manage Git remotes"),
		}
		if project.policy.Mode == "secure" {
			actions = append(actions, noInputAction("mode.dev", "Change execution mode to Development"))
		} else {
			actions = append(actions, noInputAction("mode.secure", "Change execution mode to Secure"))
		}
		if project.policy.Web.Enabled {
			actions = append(actions, noInputAction("web.disable", "Disable Web access"))
		} else {
			actions = append(actions, noInputAction("web.enable", "Enable recommended Web access"))
		}
		actions = append(actions, noInputAction("back", "Back"))
		event, err := c.exchange(ctx, project.policy.ProjectID, c.view("settings", "Project settings", fields, actions))
		if err != nil {
			return err
		}
		if event.Kind != hosttui.EventAction || event.ActionID == "back" {
			return nil
		}
		switch event.ActionID {
		case "auth.change":
			if err := c.settingsAuth(ctx, project.policy.ProjectID); err != nil {
				return err
			}
		case "git.manage":
			if err := c.settingsGit(ctx, project); err != nil {
				return err
			}
		case "mode.dev":
			if err := c.app.setProjectMode(ctx, project.policy.ProjectRoot, "dev"); err != nil {
				return err
			}
		case "mode.secure":
			if err := c.app.setProjectMode(ctx, project.policy.ProjectRoot, "secure"); err != nil {
				return err
			}
		case "web.enable":
			if err := c.app.webPolicy(ctx, "enable", project.policy.ProjectRoot, false, true, nil); err != nil {
				return err
			}
		case "web.disable":
			if err := c.app.webPolicy(ctx, "disable", project.policy.ProjectRoot, false, false, nil); err != nil {
				return err
			}
		}
		refreshed, err := c.projectForPath(project.policy.ProjectRoot)
		if err != nil {
			return err
		}
		project = *refreshed
	}
}

func (c *tuiCoordinator) settingsAuth(ctx context.Context, projectID string) error {
	settingsStore, err := c.app.userSettingsStore()
	if err != nil {
		return err
	}
	settings, err := settingsStore.Load()
	if err != nil {
		return err
	}
	apiStatus, oauthStatus := "Not configured", "Not configured"
	if secretstore.OpenAIKeyExists(ctx) == nil {
		apiStatus = "Configured"
	}
	if secretstore.CodexOAuthExists(ctx) == nil {
		oauthStatus = "Configured"
	}
	view := c.view("settings", "Change authentication method", []hosttui.TextField{
		{ID: "active", Label: "Current method", Text: string(settings.ModelAuth)},
		{ID: "oauth", Label: "OAuth", Text: oauthStatus},
		{ID: "api-key", Label: "API key", Text: apiStatus},
	}, []hosttui.Action{noInputAction("auth.oauth", "Use OAuth and reauthenticate"), inputAction("auth.api-key", "Use API key", true, hosttui.MaxInputBytes), noInputAction("back", "Back")})
	event, err := c.exchange(ctx, projectID, view)
	if err != nil || event.Kind != hosttui.EventAction || event.ActionID == "back" {
		return err
	}
	if event.ActionID == "auth.oauth" {
		if err := c.app.modelAuth(ctx, "oauth"); err != nil {
			return err
		}
		if err := openauth.NewManager().Login(ctx, c.app.output); err != nil {
			c.warning = "OAuth was not completed; the selected method has no automatic fallback."
		}
		return nil
	}
	if event.ActionID == "auth.api-key" {
		if err := secretstore.StoreOpenAIKey(ctx, event.Input); err != nil {
			return err
		}
		return c.app.modelAuth(ctx, "api-key")
	}
	return nil
}

func (c *tuiCoordinator) settingsGit(ctx context.Context, project tuiProject) error {
	detected := detectProjectGitRemotes(ctx, project.policy.ProjectRoot)
	configuredNames := make(map[string]struct{}, len(project.policy.Git.Remotes))
	configuredURLs := make(map[string]struct{}, len(project.policy.Git.Remotes))
	type remoteChoice struct {
		field  hosttui.TextField
		action hosttui.Action
	}
	choices := make([]remoteChoice, 0, len(project.policy.Git.Remotes)+len(detected))
	for index, remote := range project.policy.Git.Remotes {
		configuredNames[remote.Name] = struct{}{}
		configuredURLs[remote.URL] = struct{}{}
		choices = append(choices, remoteChoice{
			field:  hosttui.TextField{ID: fmt.Sprintf("configured.%d", index), Label: "Configured", Text: remote.Name + "  " + remote.URL},
			action: noInputAction(fmt.Sprintf("remove.%d", index), "Remove "+remote.Name),
		})
	}
	for index, remote := range detected {
		if _, ok := configuredNames[remote.Name]; ok {
			continue
		}
		if _, ok := configuredURLs[remote.URL]; ok {
			continue
		}
		choices = append(choices, remoteChoice{
			field:  hosttui.TextField{ID: fmt.Sprintf("detected.%d", index), Label: "Detected, not configured", Text: remote.Name + "  " + remote.URL},
			action: noInputAction(fmt.Sprintf("add.%d", index), "Add "+remote.Name),
		})
	}
	page := 0
	const pageSize = hosttui.MaxActions - 3
	for {
		start := page * pageSize
		if start >= len(choices) {
			page, start = 0, 0
		}
		end := min(start+pageSize, len(choices))
		fields := []hosttui.TextField{{ID: "git.page", Label: "Git remotes", Text: fmt.Sprintf("%d-%d of %d", min(start+1, len(choices)), end, len(choices))}}
		actions := make([]hosttui.Action, 0, hosttui.MaxActions)
		for _, choice := range choices[start:end] {
			fields = append(fields, choice.field)
			actions = append(actions, choice.action)
		}
		if start > 0 {
			actions = append(actions, noInputAction("git.previous", "Previous remotes"))
		}
		if end < len(choices) {
			actions = append(actions, noInputAction("git.next", "Next remotes"))
		}
		actions = append(actions, noInputAction("back", "Back"))
		event, err := c.exchange(ctx, project.policy.ProjectID, c.view("settings", "Git remotes are changed only after explicit selection", fields, actions))
		if err != nil || event.Kind != hosttui.EventAction || event.ActionID == "back" {
			return err
		}
		if event.ActionID == "git.previous" && start > 0 {
			page--
			continue
		}
		if event.ActionID == "git.next" && end < len(choices) {
			page++
			continue
		}
		var index int
		if _, err := fmt.Sscanf(event.ActionID, "add.%d", &index); err == nil && index >= 0 && index < len(detected) {
			remote := detected[index]
			return c.app.gitPolicy(ctx, "remote-add", project.policy.ProjectRoot, remote.Name, remote.URL)
		}
		if _, err := fmt.Sscanf(event.ActionID, "remove.%d", &index); err == nil && index >= 0 && index < len(project.policy.Git.Remotes) {
			return c.app.gitPolicy(ctx, "remote-remove", project.policy.ProjectRoot, project.policy.Git.Remotes[index].Name, "")
		}
	}
}

func (c *tuiCoordinator) changes(ctx context.Context, project tuiProject) error {
	pending, err := loadPending(project.state, project.policy)
	if err != nil {
		return err
	}
	return c.changesForPending(ctx, project, pending)
}

func (c *tuiCoordinator) changesForPending(ctx context.Context, project tuiProject, pending pendingChange) error {
	review, err := buildPendingReview(pending, project.policy, workspace.ReviewOptions{Context: workspace.DefaultReviewContext}, false)
	if err != nil {
		return err
	}
	selected := ""
	page := 0
	diffPage := 0
	initialDiffFocus := false
	initialDiffEnd := false
	for {
		screen, err := workspace.BuildReviewScreen(review, c.width, selected)
		if err != nil {
			return err
		}
		const pageSize = hosttui.MaxChangeFiles
		if page*pageSize >= len(screen.Files) {
			page = 0
		}
		start := page * pageSize
		end := min(start+pageSize, len(screen.Files))
		visible := screen.Files[start:end]
		diffRows := reviewDiffRows(screen)
		diffPages := reviewDiffPages(diffRows)
		if diffPage >= len(diffPages) {
			diffPage = 0
		}
		diffWindow := diffPages[diffPage]
		actions := make([]hosttui.Action, 0, hosttui.MaxActions)
		for index := start; index < end; index++ {
			file := screen.Files[index]
			actions = append(actions, noInputAction(fmt.Sprintf("file.%d", index), file.Status+" "+file.Path))
		}
		if page > 0 {
			actions = append(actions, noInputAction("page.prev", "Previous files"))
		}
		if end < len(screen.Files) {
			actions = append(actions, noInputAction("page.next", "Next files"))
		}
		if diffPage > 0 {
			actions = append(actions, noInputAction("diff.prev", "Previous diff page"))
		}
		if diffPage+1 < len(diffPages) {
			actions = append(actions, noInputAction("diff.next", "Next diff page"))
		}
		actions = append(actions, noInputAction("apply-all", "Apply all "+fileCountLabel(len(screen.Files))), noInputAction("back", "Keep pending and back"))
		view := c.view("changes", "Review the host-generated Change Set", nil, actions)
		view.Changes = reviewChangesView(screen, visible, page+1, (len(screen.Files)+pageSize-1)/pageSize, start, diffRows[diffWindow.start:diffWindow.end], diffWindow.start, len(diffRows), diffPage+1, len(diffPages), initialDiffFocus, initialDiffEnd)
		identity := pendingIdentity(pending)
		event, err := c.exchange(ctx, project.policy.ProjectID, view)
		if err != nil {
			return err
		}
		if event.Kind != hosttui.EventAction || event.ActionID == "back" {
			return nil
		}
		if event.ActionID == "diff.prev" {
			diffPage--
			initialDiffFocus = true
			initialDiffEnd = true
			continue
		}
		if event.ActionID == "diff.next" {
			diffPage++
			initialDiffFocus = true
			initialDiffEnd = false
			continue
		}
		if event.ActionID == "apply-all" {
			latest, err := loadPending(project.state, project.policy)
			if err != nil || pendingIdentity(latest) != identity {
				return fmt.Errorf("the pending Change Set changed after it was displayed; review it again")
			}
			confirm := c.view("changes", "Apply the reviewed Change Set?", []hosttui.TextField{
				{ID: "summary", Label: "Pending changes", Text: reviewSummary(screen.Files)},
				{ID: "scope", Label: "Apply scope", Text: "All files in this host-generated Change Set; partial apply is not performed."},
				{ID: "safety", Label: "Revalidation", Text: "Project baseline and Change Set identity are checked again immediately before apply."},
			}, []hosttui.Action{noInputAction("confirm-apply", "Confirm apply all "+fileCountLabel(len(screen.Files))), noInputAction("back", "Back to review")})
			confirmation, err := c.exchange(ctx, project.policy.ProjectID, confirm)
			if err != nil {
				return err
			}
			if confirmation.Kind != hosttui.EventAction || confirmation.ActionID != "confirm-apply" {
				continue
			}
			latest, err = loadPending(project.state, project.policy)
			if err != nil || pendingIdentity(latest) != identity {
				return fmt.Errorf("the pending Change Set changed after confirmation; review it again")
			}
			return c.app.applyPendingApproved(project.policy, project.state, latest, review)
		}
		if event.ActionID == "page.prev" {
			page--
			selected = screen.Files[max(0, start-pageSize)].Path
			diffPage = 0
			initialDiffFocus = false
			initialDiffEnd = false
			continue
		}
		if event.ActionID == "page.next" {
			page++
			selected = screen.Files[end].Path
			diffPage = 0
			initialDiffFocus = false
			initialDiffEnd = false
			continue
		}
		var index int
		if _, err := fmt.Sscanf(event.ActionID, "file.%d", &index); err == nil && index >= 0 && index < len(screen.Files) {
			selected = screen.Files[index].Path
			diffPage = 0
			initialDiffFocus = false
			initialDiffEnd = false
		}
	}
}

const maximumTUIDiffPageBytes = 64 << 10

type tuiDiffPage struct {
	start int
	end   int
}

func reviewDiffRows(screen workspace.ReviewScreen) []hosttui.DiffRow {
	rows := make([]hosttui.DiffRow, 0, len(screen.SideBySide))
	for _, row := range screen.SideBySide {
		if row.BeforeKind == '@' && row.AfterKind == '@' {
			empty := hosttui.DiffCell{Kind: "empty"}
			rows = append(rows, hosttui.DiffRow{Kind: "hunk", Header: row.Before + " " + row.After, Before: empty, After: empty})
			continue
		}
		canonical := hosttui.DiffRow{
			Kind:   "content",
			Before: hosttui.DiffCell{Kind: reviewCellKind(row.BeforeKind), Line: row.BeforeLine, Text: row.Before},
			After:  hosttui.DiffCell{Kind: reviewCellKind(row.AfterKind), Line: row.AfterLine, Text: row.After},
		}
		if canonical.Before.Kind == "context" && canonical.After.Kind == "context" && canonical.Before.Text == canonical.After.Text {
			canonical.After.Text = ""
		}
		if len(canonical.Before.Text)+len(canonical.After.Text) > hosttui.MaxTextBytes {
			empty := hosttui.DiffCell{Kind: "empty"}
			rows = append(rows,
				hosttui.DiffRow{Kind: "content", Before: canonical.Before, After: empty},
				hosttui.DiffRow{Kind: "content", Before: empty, After: canonical.After},
			)
			continue
		}
		rows = append(rows, canonical)
	}
	if screen.Item.OpaqueReason != "" && len(rows) == 0 {
		empty := hosttui.DiffCell{Kind: "empty"}
		rows = append(rows, hosttui.DiffRow{Kind: "hunk", Header: "Content not rendered: " + screen.Item.OpaqueReason, Before: empty, After: empty})
	}
	return rows
}

func reviewDiffPages(rows []hosttui.DiffRow) []tuiDiffPage {
	if len(rows) == 0 {
		return []tuiDiffPage{{}}
	}
	pages := make([]tuiDiffPage, 0, (len(rows)+hosttui.MaxDiffRows-1)/hosttui.MaxDiffRows)
	for start := 0; start < len(rows); {
		end := start
		bytes := 0
		for end < len(rows) && end-start < hosttui.MaxDiffRows {
			row := rows[end]
			rowBytes := len(row.Kind) + len(row.Header) + len(row.Before.Kind) + len(row.Before.Text) + len(row.After.Kind) + len(row.After.Text)
			if end > start && bytes+rowBytes > maximumTUIDiffPageBytes {
				break
			}
			bytes += rowBytes
			end++
		}
		pages = append(pages, tuiDiffPage{start: start, end: end})
		start = end
	}
	return pages
}

func reviewChangesView(screen workspace.ReviewScreen, visible []workspace.ReviewFile, page, pages, start int, rows []hosttui.DiffRow, diffStart, diffTotal, diffPage, diffPages int, initialDiffFocus, initialDiffEnd bool) *hosttui.ChangesView {
	files := make([]hosttui.ChangeFile, 0, len(visible))
	for offset, file := range visible {
		detail := ""
		if file.From != "" {
			detail = "from " + file.From
		}
		if len(file.Risks) > 0 {
			detail = strings.TrimSpace(detail + " RISK: " + strings.Join(file.Risks, ", "))
		}
		if file.OpaqueReason != "" {
			detail = strings.TrimSpace(detail + fmt.Sprintf(" type=%s size=%d sha256=%s reason=%s", file.Type, file.Size, file.SHA256, file.OpaqueReason))
		}
		files = append(files, hosttui.ChangeFile{ActionID: fmt.Sprintf("file.%d", start+offset), Status: file.Status, Path: file.Path, Detail: detail})
	}
	model := &hosttui.ChangesView{
		Summary: reviewSummary(screen.Files), Layout: "side-by-side", Page: page, Pages: pages,
		SelectedActionID: fmt.Sprintf("file.%d", screen.Selected), InitialFocus: "files", InitialDiffPosition: "start", Files: files,
		DiffStart: diffStart, DiffTotal: diffTotal, DiffPage: diffPage, DiffPages: diffPages,
		Rows: append([]hosttui.DiffRow{}, rows...),
	}
	if initialDiffFocus {
		model.InitialFocus = "diff"
	}
	if initialDiffEnd {
		model.InitialDiffPosition = "end"
	}
	return model
}

func reviewCellKind(kind byte) string {
	switch kind {
	case ' ':
		return "context"
	case '-':
		return "delete"
	case '+':
		return "add"
	default:
		return "empty"
	}
}

func reviewSummary(files []workspace.ReviewFile) string {
	counts := map[string]int{}
	risks := 0
	for _, file := range files {
		counts[file.Status]++
		if len(file.Risks) > 0 || file.OpaqueReason != "" {
			risks++
		}
	}
	parts := []string{fileCountLabel(len(files))}
	for _, item := range []struct {
		status string
		label  string
	}{{"A", "added"}, {"M", "modified"}, {"D", "deleted"}, {"R", "renamed"}} {
		if count := counts[item.status]; count > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", count, item.label))
		}
	}
	if risks == 0 {
		parts = append(parts, "no warnings")
	} else {
		parts = append(parts, fmt.Sprintf("%d with warnings", risks))
	}
	return strings.Join(parts, " · ")
}

func fileCountLabel(count int) string {
	if count == 1 {
		return "1 file"
	}
	return fmt.Sprintf("%d files", count)
}

func pendingIdentity(pending pendingChange) string {
	return pending.ProjectID + "\x00" + pending.Baseline.Digest + "\x00" + pending.Merged.Digest + "\x00" + pending.ChangeSet.Digest
}

func (c *tuiCoordinator) recovery(ctx context.Context, project tuiProject) error {
	fields := []hosttui.TextField{
		{ID: "delete", Label: "Recreate deletes", Text: "The retained isolated VM after an explicit export or discard decision."},
		{ID: "keep", Label: "Recreate keeps", Text: "The host Project, configuration, credentials, audit log, and pending Change Set."},
		{ID: "loss", Label: "Unrecoverable work", Text: "Unexported VM-only work is lost if discard is explicitly chosen."},
		{ID: "safe", Label: "Recommended safe action", Text: "Export changes first, review the Change Set, then recreate."},
	}
	actions := []hosttui.Action{noInputAction("export", "Export changes safely"), noInputAction("recreate", "Recreate after safe checks"), noInputAction("back", "Back")}
	event, err := c.exchange(ctx, project.policy.ProjectID, c.view("recovery", "Recovery confirmation", fields, actions))
	if err != nil || event.Kind != hosttui.EventAction || event.ActionID == "back" {
		return err
	}
	if event.ActionID == "export" {
		return c.app.changes(ctx, "export", project.policy.ProjectRoot, workspace.ReviewOptions{}, false)
	}
	if event.ActionID == "recreate" {
		return c.app.recreate(ctx, project.policy.ProjectRoot, false)
	}
	return nil
}

func (c *tuiCoordinator) failure(ctx context.Context, projectID string, cause error, preservation, next string) (bool, error) {
	view := c.view("recovery", "The requested action was refused or failed", []hosttui.TextField{
		{ID: "failure", Label: "Failure", Text: singleLineTUIMessage(cause.Error())},
		{ID: "preserved", Label: "Work preservation", Text: preservation},
		{ID: "next", Label: "Next action", Text: next},
	}, []hosttui.Action{noInputAction("back", "Back to Home"), noInputAction("exit", "Exit")})
	event, err := c.exchange(ctx, projectID, view)
	return event.ActionID == "exit" || event.Kind == hosttui.EventExit, err
}

func singleLineTUIMessage(value string) string {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == '\n' || r == '\r' })
	for index := range parts {
		parts[index] = strings.TrimSpace(parts[index])
	}
	if len(parts) == 0 {
		return "No additional diagnostics were provided."
	}
	return strings.Join(parts, " · ")
}

func recoveryExists(projectState string) bool {
	_, err := recovery.Load(projectState)
	return err == nil
}

func appendWarning(existing, addition string) string {
	if existing == "" {
		return addition
	}
	return existing + " " + addition
}

func titleMode(mode string) string {
	if mode == "secure" {
		return "Secure"
	}
	if mode == "dev" {
		return "Development"
	}
	return mode
}

func (a *app) setProjectMode(ctx context.Context, dir, mode string) error {
	if mode != "secure" && mode != "dev" {
		return fmt.Errorf("mode must be secure or dev")
	}
	projectPolicy, _, _, err := a.loadPolicy(dir)
	if err != nil {
		return err
	}
	configLock, err := a.store.AcquireConfigLock(projectPolicy.ProjectID)
	if err != nil {
		return err
	}
	defer configLock.Close()
	projectPolicy, path, projectState, err := a.loadPolicyLocked(dir)
	if err != nil {
		return err
	}
	if projectPolicy.Mode == mode {
		return nil
	}
	if err := refuseActivePolicyChange(projectState); err != nil {
		return err
	}
	items, err := a.runtime.List(ctx)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.Labels["dev.sunaba.owner"] == "sunaba-supervisor" && item.Labels["dev.sunaba.project"] == projectPolicy.ProjectID {
			return fmt.Errorf("mode change requires export/recreate of existing Project VM %s", item.Name)
		}
	}
	projectPolicy.Mode = mode
	projectPolicy.UpdatedAt = time.Now().UTC()
	return a.savePolicyAndConfigLocked(path, projectPolicy)
}

func mustCurrentDirectory() string {
	directory, err := state.ResolveProjectPath(".")
	if err != nil {
		return "."
	}
	return directory
}

func nowUTC() time.Time { return time.Now().UTC() }
