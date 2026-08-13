package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	urfavecli "github.com/urfave/cli/v3"
	"sunaba/internal/dependency"
	"sunaba/internal/image"
	"sunaba/internal/opencode"
	"sunaba/internal/policy"
	"sunaba/internal/state"
	"sunaba/internal/updater"
	"sunaba/internal/versionconfig"
)

func (a *app) versionStore() (*versionconfig.Store, error) {
	configs, err := a.projectConfigStore()
	if err != nil {
		return nil, err
	}
	store := &versionconfig.Store{Root: configs.Root}
	_, err = store.Paths()
	return store, err
}

func (a *app) activeVersionLock() (versionconfig.Lock, error) {
	store, err := a.versionStore()
	if err != nil {
		return versionconfig.Lock{}, err
	}
	lock, err := store.LoadLock()
	if errors.Is(err, os.ErrNotExist) {
		return lock, fmt.Errorf("sunaba setup has not completed; run 'sunaba setup'")
	}
	if err != nil {
		return lock, err
	}
	active, err := a.store.LoadActiveDependency()
	if err != nil {
		return lock, err
	}
	expected, err := state.NewDependencyBinding(lock.Generation, lock.Manifest)
	if err != nil {
		return lock, err
	}
	if active != expected {
		return lock, fmt.Errorf("active dependency state does not match versions.lock.json; run 'sunaba setup' to recover")
	}
	return lock, nil
}

func (a *app) requireActiveProjectDependency(projectPolicy policy.ProjectPolicy) (versionconfig.Lock, error) {
	lock, err := a.activeVersionLock()
	if err != nil {
		return lock, err
	}
	digest, err := dependency.ManifestDigest(lock.Manifest)
	if err != nil {
		return lock, err
	}
	want := policy.DependencyPolicy{
		ManifestSHA256: digest, OpenCode: lock.Manifest.OpenCode.Version,
		AppleContainer: lock.Manifest.AppleContainer.Version, AgentImage: lock.Manifest.AgentImage.Tag,
	}
	if projectPolicy.Dependency != want {
		return lock, fmt.Errorf("Project dependency is not the active OpenCode %s lock; stop all Projects and run 'sunaba update apply'", lock.Manifest.OpenCode.Version)
	}
	return lock, nil
}

func (a *app) setupCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name: "setup", Usage: "Initialize the host dependency lock and Agent image",
		Flags:  []urfavecli.Flag{&urfavecli.BoolFlag{Name: "config-only", Usage: "Create versions.json without validating or building dependencies"}},
		Action: rejectArguments(func(ctx context.Context, cmd *urfavecli.Command) error { return a.setup(ctx, cmd.Bool("config-only")) }),
	}
}

func (a *app) versionsCommand() *urfavecli.Command {
	return &urfavecli.Command{Name: "versions", Usage: "Manage the host-only dependency declaration", Commands: []*urfavecli.Command{
		{Name: "path", Usage: "Show version declaration and lock paths", Action: rejectArguments(func(context.Context, *urfavecli.Command) error {
			store, err := a.versionStore()
			if err != nil {
				return err
			}
			paths, err := store.Paths()
			if err != nil {
				return err
			}
			fmt.Fprintf(a.output, "declaration: %s\nlock: %s\n", paths.Config, paths.Lock)
			return nil
		})},
		{Name: "show", Usage: "Show the declaration and active lock", Action: rejectArguments(func(context.Context, *urfavecli.Command) error { return a.showVersions() })},
		{Name: "set", Usage: "Select an exact OpenCode v1 version", ArgsUsage: "<version>", Action: func(_ context.Context, cmd *urfavecli.Command) error {
			if cmd.NArg() != 1 {
				return fmt.Errorf("versions set requires one exact v1 version")
			}
			return a.setVersion("exact", cmd.Args().First())
		}},
		{Name: "track", Usage: "Track the v1-stable channel during explicit checks", ArgsUsage: "v1-stable", Action: func(_ context.Context, cmd *urfavecli.Command) error {
			if cmd.NArg() != 1 || cmd.Args().First() != "v1-stable" {
				return fmt.Errorf("versions track requires v1-stable")
			}
			return a.setVersion("channel", "v1-stable")
		}},
	}}
}

func (a *app) updateCommand() *urfavecli.Command {
	return &urfavecli.Command{Name: "update", Usage: "Check and explicitly apply OpenCode v1 updates", Commands: []*urfavecli.Command{
		{Name: "check", Usage: "Resolve and quarantine an update candidate", Action: rejectArguments(func(ctx context.Context, _ *urfavecli.Command) error { return a.updateCheck(ctx) })},
		{Name: "apply", Usage: "Apply the previously checked candidate", Action: rejectArguments(func(ctx context.Context, _ *urfavecli.Command) error { return a.updateApply(ctx) })},
	}}
}

func (a *app) updateCheck(ctx context.Context) error {
	operationLock, err := a.store.AcquireOperationReadLock()
	if err != nil {
		return err
	}
	defer operationLock.Close()
	versions, err := a.versionStore()
	if err != nil {
		return err
	}
	config, err := versions.LoadConfig()
	if err != nil {
		return err
	}
	current, err := versions.LoadLock()
	if errors.Is(err, os.ErrNotExist) {
		current = versionconfig.BootstrapLock()
	} else if err != nil {
		return err
	} else if current, err = a.activeVersionLock(); err != nil {
		return err
	}
	candidate, err := (updater.Service{}).Check(ctx, config, current, &updater.Store{State: a.store})
	if err != nil {
		return err
	}
	fmt.Fprintf(a.output, "Update candidate %s is ready: OpenCode %s -> %s (expires %s).\nInstall exact OpenCode %s on macOS, then run 'sunaba update apply'.\n", candidate.ID, current.Manifest.OpenCode.Version, candidate.Target.OpenCode.Version, candidate.ExpiresAt.Format(time.RFC3339), candidate.Target.OpenCode.Version)
	return nil
}

func (a *app) updateApply(ctx context.Context) error {
	operationLock, err := a.store.AcquireOperationLock()
	if err != nil {
		if errors.Is(err, state.ErrOperationLocked) {
			return fmt.Errorf("update apply requires all Project operations and Supervisors to stop")
		}
		return err
	}
	defer operationLock.Close()
	if recovered, err := a.recoverDependencyUpdate(); err != nil {
		return err
	} else if recovered {
		fmt.Fprintln(a.output, "Recovered the previous interrupted update transaction; revalidating the checked candidate.")
	}
	versions, err := a.versionStore()
	if err != nil {
		return err
	}
	config, err := versions.LoadConfig()
	if err != nil {
		return err
	}
	current, err := versions.LoadLock()
	sourceActive := true
	if errors.Is(err, os.ErrNotExist) {
		global, globalErr := a.store.LoadGlobal()
		if globalErr != nil {
			return globalErr
		}
		if global.SchemaVersion != 0 || global.Active != nil || global.ImageVersion != "" {
			return fmt.Errorf("existing global dependency state requires 'sunaba setup' migration before update apply")
		}
		sourceActive = false
		current = versionconfig.BootstrapLock()
	} else if err != nil {
		return err
	} else if current, err = a.activeVersionLock(); err != nil {
		return err
	}
	candidate, err := (&updater.Store{State: a.store}).Load()
	if err != nil {
		return fmt.Errorf("load checked update candidate: %w", err)
	}
	configDigest, _ := versionconfig.ConfigDigest(config)
	lockDigest, _ := versionconfig.LockDigest(current)
	if candidate.ConfigSHA256 != configDigest || candidate.CurrentLockSHA256 != lockDigest {
		return fmt.Errorf("version declaration or active lock changed after update check; run 'sunaba update check' again")
	}
	if !time.Now().UTC().Before(candidate.ExpiresAt) {
		return fmt.Errorf("update candidate expired; run 'sunaba update check' again")
	}
	if err := dependency.ValidateOpenCodeUpdateCandidate(current.Manifest, candidate.Target); err != nil {
		return err
	}
	if err := opencode.CheckPrerequisitesFor(ctx, candidate.Target); err != nil {
		return err
	}
	if err := verifyInstalledOpenCode(ctx, candidate.Target); err != nil {
		return err
	}
	projects, err := a.inventoryProjectsForUpdate(ctx, current.Manifest)
	if err != nil {
		return err
	}
	if err := image.BuildManifest(ctx, a.runtime, candidate.Target); err != nil {
		return err
	}
	latestConfig, err := versions.LoadConfig()
	if err != nil {
		return err
	}
	latestConfigDigest, _ := versionconfig.ConfigDigest(latestConfig)
	if latestConfigDigest != candidate.ConfigSHA256 {
		return fmt.Errorf("version declaration changed while building the candidate image; run 'sunaba update check' again")
	}
	nextGeneration := current.Generation + 1
	if !sourceActive {
		nextGeneration = 1
	}
	newLock := versionconfig.Lock{SchemaVersion: 1, Generation: nextGeneration, ResolvedAt: time.Now().UTC(), Manifest: candidate.Target}
	if err := a.commitDependencyUpdate(current, newLock, sourceActive, projects); err != nil {
		return err
	}
	fmt.Fprintf(a.output, "Applied OpenCode %s. %d Project policy file(s) now use generation %d.\n", candidate.Target.OpenCode.Version, len(projects), newLock.Generation)
	return nil
}

type updateProject struct {
	Path   string
	Policy policy.ProjectPolicy
}

func (a *app) inventoryProjectsForUpdate(ctx context.Context, current dependency.Manifest) ([]updateProject, error) {
	items, err := a.runtime.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if item.Labels["dev.sunaba.owner"] == "sunaba-supervisor" {
			return nil, fmt.Errorf("update apply requires every sunaba VM to be exported or destroyed; found %s", item.Name)
		}
	}
	states, err := a.store.ListProjectStates()
	if err != nil {
		return nil, err
	}
	currentDigest, err := dependency.ManifestDigest(current)
	if err != nil {
		return nil, err
	}
	want := policy.DependencyPolicy{ManifestSHA256: currentDigest, OpenCode: current.OpenCode.Version, AppleContainer: current.AppleContainer.Version, AgentImage: current.AgentImage.Tag}
	projects := make([]updateProject, 0, len(states))
	for _, projectState := range states {
		if projectState.Err != nil {
			return nil, projectState.Err
		}
		if _, err := os.Lstat(filepath.Join(projectState.Path, approvalControlLocator)); err == nil {
			return nil, fmt.Errorf("update apply requires the Supervisor for Project %s to be destroyed", projectState.ProjectID)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		path := filepath.Join(projectState.Path, "policy.json")
		loaded, _, err := policy.LoadReadOnly(path, time.Now())
		if err != nil || loaded.ProjectID != projectState.ProjectID || loaded.Dependency != want {
			return nil, fmt.Errorf("Project %s does not match the current dependency lock", projectState.ProjectID)
		}
		projects = append(projects, updateProject{Path: path, Policy: loaded})
	}
	return projects, nil
}

type updateJournal struct {
	SchemaVersion int                `json:"schema_version"`
	Phase         string             `json:"phase"`
	SourceActive  bool               `json:"source_active"`
	SourceLock    versionconfig.Lock `json:"source_lock"`
	TargetLock    versionconfig.Lock `json:"target_lock"`
	Projects      []string           `json:"project_policy_paths"`
}

func (a *app) commitDependencyUpdate(current, target versionconfig.Lock, sourceActive bool, projects []updateProject) (returnErr error) {
	updatesDirectory := filepath.Join(a.store.Root, "updates")
	if err := os.Mkdir(updatesDirectory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := verifyPrivateDirectory(updatesDirectory); err != nil {
		return fmt.Errorf("update transaction directory is unsafe: %w", err)
	}
	journalPath := filepath.Join(updatesDirectory, "apply-journal.json")
	if _, err := os.Lstat(journalPath); err == nil {
		return fmt.Errorf("an update apply journal already exists at %s; inspect and recover it before retrying", journalPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	paths := make([]string, 0, len(projects))
	for _, project := range projects {
		paths = append(paths, project.Path)
	}
	journal := updateJournal{SchemaVersion: 1, Phase: "prepared", SourceActive: sourceActive, SourceLock: current, TargetLock: target, Projects: paths}
	if err := writePrivateJSON(journalPath, journal); err != nil {
		return err
	}
	defer func() {
		if returnErr != nil && journal.Phase == "prepared" {
			for _, project := range projects {
				_ = policy.Save(project.Path, project.Policy)
			}
			if sourceActive {
				versions, _ := a.versionStore()
				_ = versions.SaveLock(current)
				binding, bindingErr := state.NewDependencyBinding(current.Generation, current.Manifest)
				if bindingErr == nil {
					_ = a.store.SaveActiveDependency(binding)
				}
			} else {
				_ = a.clearDependencyActivation()
			}
		}
	}()
	targetManifestDigest, err := dependency.ManifestDigest(target.Manifest)
	if err != nil {
		return err
	}
	for _, project := range projects {
		updated := project.Policy
		updated.Dependency = policy.DependencyPolicy{ManifestSHA256: targetManifestDigest, OpenCode: target.Manifest.OpenCode.Version, AppleContainer: target.Manifest.AppleContainer.Version, AgentImage: target.Manifest.AgentImage.Tag}
		updated.UpdatedAt = time.Now().UTC()
		if err := policy.Save(project.Path, updated); err != nil {
			return err
		}
	}
	commitJournal := journal
	commitJournal.Phase = "commit-decided"
	if err := writePrivateJSON(journalPath, commitJournal); err != nil {
		return err
	}
	journal = commitJournal
	versions, _ := a.versionStore()
	if err := versions.SaveLock(target); err != nil {
		return err
	}
	binding, err := state.NewDependencyBinding(target.Generation, target.Manifest)
	if err != nil {
		return err
	}
	if err := a.store.SaveActiveDependency(binding); err != nil {
		return err
	}
	if err := os.Remove(journalPath); err != nil {
		return err
	}
	return nil
}

func (a *app) recoverDependencyUpdate() (bool, error) {
	journalPath := filepath.Join(a.store.Root, "updates", "apply-journal.json")
	data, err := readOwnedPrivateFile(journalPath, 2<<20)
	if err != nil {
		if _, lstatErr := os.Lstat(journalPath); errors.Is(lstatErr, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	var journal updateJournal
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil || decoder.Decode(&struct{}{}) != io.EOF || journal.SchemaVersion != 1 || (journal.Phase != "prepared" && journal.Phase != "commit-decided") || journal.SourceLock.Validate() != nil || journal.TargetLock.Validate() != nil || len(journal.Projects) > 256 {
		return false, fmt.Errorf("update apply journal is invalid; refusing automatic recovery")
	}
	chosen := journal.SourceLock
	activate := journal.SourceActive
	if journal.Phase == "commit-decided" {
		chosen = journal.TargetLock
		activate = true
	}
	digest, err := dependency.ManifestDigest(chosen.Manifest)
	if err != nil {
		return false, err
	}
	for _, path := range journal.Projects {
		if filepath.Base(path) != "policy.json" || !filepath.IsAbs(path) || filepath.Clean(path) != path || !strings.HasPrefix(path, filepath.Join(a.store.Root, "projects")+string(filepath.Separator)) {
			return false, fmt.Errorf("update apply journal contains an unsafe Project policy path")
		}
		loaded, _, err := policy.LoadReadOnly(path, time.Now())
		if err != nil {
			return false, err
		}
		loaded.Dependency = policy.DependencyPolicy{ManifestSHA256: digest, OpenCode: chosen.Manifest.OpenCode.Version, AppleContainer: chosen.Manifest.AppleContainer.Version, AgentImage: chosen.Manifest.AgentImage.Tag}
		loaded.UpdatedAt = time.Now().UTC()
		if err := policy.Save(path, loaded); err != nil {
			return false, err
		}
	}
	if activate {
		versions, err := a.versionStore()
		if err != nil {
			return false, err
		}
		if err := versions.SaveLock(chosen); err != nil {
			return false, err
		}
		binding, err := state.NewDependencyBinding(chosen.Generation, chosen.Manifest)
		if err != nil {
			return false, err
		}
		if err := a.store.SaveActiveDependency(binding); err != nil {
			return false, err
		}
	} else if err := a.clearDependencyActivation(); err != nil {
		return false, err
	}
	if err := os.Remove(journalPath); err != nil {
		return false, err
	}
	return true, nil
}

func (a *app) clearDependencyActivation() error {
	versions, err := a.versionStore()
	if err != nil {
		return err
	}
	paths, err := versions.Paths()
	if err != nil {
		return err
	}
	for _, path := range []string{paths.Lock, filepath.Join(a.store.Root, "config.json")} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (a *app) setup(ctx context.Context, configOnly bool) error {
	operationLock, err := a.store.AcquireOperationLock()
	if err != nil {
		if errors.Is(err, state.ErrOperationLocked) {
			return fmt.Errorf("setup requires all Project operations and Supervisors to stop")
		}
		return err
	}
	defer operationLock.Close()
	if recovered, err := a.recoverDependencyUpdate(); err != nil {
		return err
	} else if recovered {
		fmt.Fprintln(a.output, "Recovered the previous interrupted dependency transaction before setup.")
	}
	versions, err := a.versionStore()
	if err != nil {
		return err
	}
	config, err := versions.LoadConfig()
	if errors.Is(err, os.ErrNotExist) {
		config = versionconfig.BootstrapConfig()
		if err := versions.SaveConfig(config); err != nil {
			return err
		}
		fmt.Fprintf(a.output, "Created %s with bootstrap OpenCode %s.\n", versionconfig.ConfigFile, dependency.OpenCodeVersion)
	} else if err != nil {
		return err
	}
	if configOnly {
		fmt.Fprintln(a.output, "Version declaration is ready. Run 'sunaba update check' and 'sunaba update apply' after selecting a version.")
		return nil
	}
	if config.OpenCode.Strategy != "exact" || config.OpenCode.Value != dependency.OpenCodeVersion {
		return fmt.Errorf("initial setup can apply bootstrap OpenCode %s only; run 'sunaba update check' and 'sunaba update apply' for %s", dependency.OpenCodeVersion, config.OpenCode.Value)
	}
	manifest := dependency.MustPinned()
	globalState, err := a.store.LoadGlobal()
	if err != nil {
		return err
	}
	if globalState.ImageVersion != "" && globalState.ImageVersion != manifest.OpenCode.Version {
		return fmt.Errorf("legacy global state uses OpenCode %s and cannot be migrated as bootstrap %s", globalState.ImageVersion, manifest.OpenCode.Version)
	}
	if globalState.Active != nil {
		if globalState.ImageVersion != "" || globalState.SchemaVersion != 2 {
			return fmt.Errorf("existing global dependency state is incomplete")
		}
		want, bindingErr := state.NewDependencyBinding(globalState.Active.Generation, manifest)
		if bindingErr != nil || *globalState.Active != want {
			return fmt.Errorf("existing global dependency does not match the bootstrap contract")
		}
	} else if globalState.SchemaVersion != 0 {
		return fmt.Errorf("existing global dependency state is incomplete")
	}
	if err := opencode.CheckPrerequisitesFor(ctx, manifest); err != nil {
		return err
	}
	if err := verifyInstalledOpenCode(ctx, manifest); err != nil {
		return err
	}
	if _, err := image.EnsureManifest(ctx, a.runtime, manifest); err != nil {
		return err
	}
	lock, lockErr := versions.LoadLock()
	alreadyActive := false
	if lockErr == nil {
		if lock.Manifest.OpenCode.Version != manifest.OpenCode.Version {
			return fmt.Errorf("an active non-bootstrap lock already exists; use 'sunaba update check' and 'sunaba update apply'")
		}
		if _, err := a.activeVersionLock(); err == nil {
			alreadyActive = true
		}
	} else if !errors.Is(lockErr, os.ErrNotExist) {
		return lockErr
	}
	generation := uint64(1)
	if lock.Generation > 0 {
		generation = lock.Generation
	}
	newLock := versionconfig.Lock{SchemaVersion: versionconfig.SchemaVersion, Generation: generation, ResolvedAt: time.Now().UTC(), Manifest: manifest}
	projects, migrationNeeded, err := a.inventoryBootstrapProjectsForSetup(ctx, manifest)
	if err != nil {
		return err
	}
	if alreadyActive && !migrationNeeded {
		fmt.Fprintf(a.output, "Setup is already complete with OpenCode %s.\n", manifest.OpenCode.Version)
		return nil
	}
	if err := a.commitDependencyUpdate(newLock, newLock, alreadyActive, projects); err != nil {
		return fmt.Errorf("commit setup dependency state: %w", err)
	}
	fmt.Fprintf(a.output, "Setup complete. OpenCode %s is locked for the host TUI and guest Agent image.\n", manifest.OpenCode.Version)
	return nil
}

func (a *app) inventoryBootstrapProjectsForSetup(ctx context.Context, manifest dependency.Manifest) ([]updateProject, bool, error) {
	items, err := a.runtime.List(ctx)
	if err != nil {
		return nil, false, err
	}
	for _, item := range items {
		if item.Labels["dev.sunaba.owner"] == "sunaba-supervisor" {
			return nil, false, fmt.Errorf("setup migration requires every existing sunaba VM to be exported or destroyed; found %s", item.Name)
		}
	}
	states, err := a.store.ListProjectStates()
	if err != nil {
		return nil, false, err
	}
	canonicalDigest, err := dependency.ManifestDigest(manifest)
	if err != nil {
		return nil, false, err
	}
	legacyDigest, err := dependency.ManifestSHA256()
	if err != nil {
		return nil, false, err
	}
	projects := make([]updateProject, 0, len(states))
	migrationNeeded := false
	for _, projectState := range states {
		if projectState.Err != nil {
			return nil, false, projectState.Err
		}
		if _, err := os.Lstat(filepath.Join(projectState.Path, approvalControlLocator)); err == nil {
			return nil, false, fmt.Errorf("setup migration requires the Supervisor for Project %s to be destroyed", projectState.ProjectID)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, false, err
		}
		path := filepath.Join(projectState.Path, "policy.json")
		loaded, _, err := policy.LoadReadOnly(path, time.Now())
		if err != nil || loaded.ProjectID != projectState.ProjectID || loaded.Dependency.OpenCode != manifest.OpenCode.Version || loaded.Dependency.AppleContainer != manifest.AppleContainer.Version || loaded.Dependency.AgentImage != manifest.AgentImage.Tag || (loaded.Dependency.ManifestSHA256 != canonicalDigest && loaded.Dependency.ManifestSHA256 != legacyDigest) {
			return nil, false, fmt.Errorf("Project %s does not match the bootstrap dependency contract", projectState.ProjectID)
		}
		migrationNeeded = migrationNeeded || loaded.Dependency.ManifestSHA256 != canonicalDigest
		projects = append(projects, updateProject{Path: path, Policy: loaded})
	}
	return projects, migrationNeeded, nil
}

func verifyInstalledOpenCode(ctx context.Context, manifest dependency.Manifest) error {
	binary, err := exec.LookPath("opencode")
	if err != nil {
		return fmt.Errorf("opencode CLI %s not found", manifest.OpenCode.Version)
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		return err
	}
	digest, err := fileSHA256(binary)
	if err != nil {
		return err
	}
	if digest != manifest.OpenCode.Host.ExecutableSHA256 {
		return fmt.Errorf("installed host OpenCode executable digest does not match official v%s artifact", manifest.OpenCode.Version)
	}
	version, err := opencode.HostVersion(ctx)
	if err != nil {
		return err
	}
	if strings.TrimPrefix(strings.TrimSpace(version), "v") != manifest.OpenCode.Version {
		return fmt.Errorf("installed host OpenCode is %s; expected exact %s", version, manifest.OpenCode.Version)
	}
	return nil
}

func (a *app) showVersions() error {
	store, err := a.versionStore()
	if err != nil {
		return err
	}
	config, err := store.LoadConfig()
	if err != nil {
		return err
	}
	result := struct {
		Declaration versionconfig.Config `json:"declaration"`
		Lock        *versionconfig.Lock  `json:"lock,omitempty"`
	}{Declaration: config}
	if lock, err := store.LoadLock(); err == nil {
		result.Lock = &lock
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	encoder := json.NewEncoder(a.output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func (a *app) setVersion(strategy, value string) error {
	operationLock, err := a.store.AcquireOperationReadLock()
	if err != nil {
		return err
	}
	defer operationLock.Close()
	store, err := a.versionStore()
	if err != nil {
		return err
	}
	if _, err := store.LoadConfig(); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("version declaration does not exist; run 'sunaba setup --config-only' first")
	} else if err != nil {
		return err
	}
	config := versionconfig.Config{SchemaVersion: versionconfig.SchemaVersion, OpenCode: versionconfig.Selection{Strategy: strategy, Value: value}}
	if err := store.SaveConfig(config); err != nil {
		return err
	}
	fmt.Fprintf(a.output, "Updated %s to %s %s. The active lock is unchanged; run 'sunaba update check'.\n", versionconfig.ConfigFile, strategy, value)
	return nil
}
