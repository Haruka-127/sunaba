package apply

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"

	"sunaba/internal/approval"
	"sunaba/internal/audit"
	"sunaba/internal/securefs"
	"sunaba/internal/state"
	"sunaba/internal/workspace"
)

type Config struct {
	Store          *state.Store
	ProjectRoot    string
	ProjectID      string
	MergedRoot     string
	Baseline       workspace.SnapshotManifest
	Merged         workspace.SnapshotManifest
	ChangeSet      workspace.ChangeSet
	Approvals      *approval.Manager
	Grant          *approval.Grant
	Audit          *audit.Recorder
	SnapshotPolicy workspace.SnapshotPolicy
}

type journalEntry struct {
	Path       string `json:"path"`
	BackupName string `json:"backup_name"`
	Original   bool   `json:"original"`
	Desired    bool   `json:"desired"`
}

type journal struct {
	Version         int            `json:"version"`
	ProjectID       string         `json:"project_id"`
	BaselineDigest  string         `json:"baseline_digest"`
	MergedDigest    string         `json:"merged_digest"`
	ChangeSetDigest string         `json:"change_set_digest"`
	Entries         []journalEntry `json:"entries"`
}

func Apply(cfg Config) (result workspace.SnapshotManifest, err error) {
	if err := validateConfig(cfg); err != nil {
		return workspace.SnapshotManifest{}, err
	}
	details := map[string]string{
		"baseline_digest": cfg.Baseline.Digest, "merged_digest": cfg.Merged.Digest, "change_set_digest": cfg.ChangeSet.Digest,
	}
	if err := cfg.Audit.Append(audit.BoundaryEvent{Category: "apply", Action: "changeset.apply", Outcome: "started", ProjectID: cfg.ProjectID, Details: details}); err != nil {
		return workspace.SnapshotManifest{}, err
	}
	defer func() {
		outcome := "success"
		finalDetails := details
		if err != nil {
			outcome = "rejected"
			finalDetails = map[string]string{
				"baseline_digest": cfg.Baseline.Digest, "merged_digest": cfg.Merged.Digest,
				"change_set_digest": cfg.ChangeSet.Digest, "reason": err.Error(),
			}
		}
		auditErr := cfg.Audit.Append(audit.BoundaryEvent{Category: "apply", Action: "changeset.apply", Outcome: outcome, ProjectID: cfg.ProjectID, Details: finalDetails})
		err = errors.Join(err, auditErr)
	}()
	lock, err := cfg.Store.AcquireProjectLock(cfg.ProjectRoot)
	if err != nil {
		return workspace.SnapshotManifest{}, err
	}
	defer lock.Close()
	if lock.ProjectID != cfg.ProjectID {
		return workspace.SnapshotManifest{}, fmt.Errorf("Project identity mismatch")
	}
	if err := RecoverLocked(cfg.ProjectRoot, cfg.ProjectID, cfg.SnapshotPolicy); err != nil {
		return workspace.SnapshotManifest{}, err
	}
	current, err := workspace.BuildSnapshotManifest(cfg.ProjectRoot, cfg.SnapshotPolicy)
	if err != nil || current.Digest != cfg.Baseline.Digest {
		return workspace.SnapshotManifest{}, fmt.Errorf("host baseline changed before apply")
	}
	actualMerged, err := workspace.BuildSnapshotManifest(cfg.MergedRoot, cfg.SnapshotPolicy)
	if err != nil || actualMerged.Digest != cfg.Merged.Digest {
		return workspace.SnapshotManifest{}, fmt.Errorf("Merged View does not match approved manifest")
	}
	rebuilt, err := workspace.BuildChangeSet(cfg.Baseline, cfg.Merged, cfg.SnapshotPolicy)
	if err != nil || rebuilt.Digest != cfg.ChangeSet.Digest {
		return workspace.SnapshotManifest{}, fmt.Errorf("Change Set does not match approved manifests")
	}
	binding := approval.Binding{ProjectID: cfg.ProjectID, BaselineDigest: cfg.Baseline.Digest, MergedDigest: cfg.Merged.Digest, ChangeSetDigest: cfg.ChangeSet.Digest}
	if err := cfg.Approvals.Consume(cfg.Grant, binding); err != nil {
		return workspace.SnapshotManifest{}, err
	}
	return applyLocked(cfg, nil, true)
}

func validateConfig(cfg Config) error {
	if cfg.Store == nil || cfg.Approvals == nil || cfg.Audit == nil || !filepath.IsAbs(cfg.ProjectRoot) || !filepath.IsAbs(cfg.MergedRoot) || cfg.ProjectID == "" {
		return fmt.Errorf("apply requires absolute roots, Project identity, store, approval manager, and host audit")
	}
	if filepath.Clean(cfg.Audit.Root) != filepath.Join(filepath.Clean(cfg.Store.Root), "audit") {
		return fmt.Errorf("apply audit must be under the state store")
	}
	return nil
}

func applyLocked(cfg Config, hook func(string) error, rollbackOnError bool) (result workspace.SnapshotManifest, err error) {
	transactionRoot, err := newTransactionRoot(cfg.ProjectRoot, cfg.ProjectID)
	if err != nil {
		return workspace.SnapshotManifest{}, err
	}
	journalReady := false
	defer func() {
		if err != nil && !journalReady {
			_ = removeTransactionRoot(transactionRoot, cfg.ProjectRoot)
		}
	}()
	backupRoot := filepath.Join(transactionRoot, "backup")
	if err := os.Mkdir(backupRoot, 0700); err != nil {
		return workspace.SnapshotManifest{}, err
	}
	affected := affectedRoots(cfg.ChangeSet)
	stageRoot := filepath.Join(transactionRoot, "stage")
	if _, err := workspace.CreateApprovedSnapshotSubset(cfg.MergedRoot, stageRoot, cfg.Merged, affected, cfg.SnapshotPolicy); err != nil {
		return workspace.SnapshotManifest{}, fmt.Errorf("stage approved Merged View: %w", err)
	}
	desired := make(map[string]struct{}, len(cfg.Merged.Entries))
	for _, entry := range cfg.Merged.Entries {
		desired[entry.Path] = struct{}{}
	}
	rootFD, err := openDirectory(cfg.ProjectRoot)
	if err != nil {
		return workspace.SnapshotManifest{}, err
	}
	defer unix.Close(rootFD)
	backupFD, err := openDirectory(backupRoot)
	if err != nil {
		return workspace.SnapshotManifest{}, err
	}
	defer unix.Close(backupFD)
	stageFD, err := openDirectory(stageRoot)
	if err != nil {
		return workspace.SnapshotManifest{}, err
	}
	defer unix.Close(stageFD)

	j := journal{Version: 1, ProjectID: cfg.ProjectID, BaselineDigest: cfg.Baseline.Digest, MergedDigest: cfg.Merged.Digest, ChangeSetDigest: cfg.ChangeSet.Digest}
	for index, entryPath := range affected {
		exists, err := relativeExists(rootFD, entryPath)
		if err != nil {
			return workspace.SnapshotManifest{}, err
		}
		_, wanted := desired[entryPath]
		j.Entries = append(j.Entries, journalEntry{Path: entryPath, BackupName: fmt.Sprintf("item-%06d", index), Original: exists, Desired: wanted})
	}
	journalPath := filepath.Join(transactionRoot, "journal.json")
	if err := writeJournal(journalPath, j); err != nil {
		return workspace.SnapshotManifest{}, err
	}
	journalReady = true
	defer func() {
		if err != nil && rollbackOnError {
			if rollbackErr := rollback(rootFD, backupFD, j); rollbackErr != nil {
				err = fmt.Errorf("apply failed: %v; rollback failed: %w", err, rollbackErr)
				return
			}
			_ = removeTransactionRoot(transactionRoot, cfg.ProjectRoot)
		}
	}()
	for _, item := range j.Entries {
		if item.Original {
			if err := renameRelative(rootFD, item.Path, backupFD, item.BackupName); err != nil {
				return workspace.SnapshotManifest{}, err
			}
		}
		if hook != nil {
			if err := hook("backup:" + item.Path); err != nil {
				return workspace.SnapshotManifest{}, err
			}
		}
		if item.Desired {
			if err := renameRelative(stageFD, item.Path, rootFD, item.Path); err != nil {
				return workspace.SnapshotManifest{}, err
			}
		}
		if hook != nil {
			if err := hook("install:" + item.Path); err != nil {
				return workspace.SnapshotManifest{}, err
			}
		}
	}
	result, err = workspace.BuildSnapshotManifest(cfg.ProjectRoot, cfg.SnapshotPolicy)
	if err != nil || result.Digest != cfg.Merged.Digest {
		return workspace.SnapshotManifest{}, fmt.Errorf("post-apply manifest mismatch")
	}
	if err := removeTransactionRoot(transactionRoot, cfg.ProjectRoot); err != nil {
		return workspace.SnapshotManifest{}, err
	}
	return result, nil
}

func RecoverLocked(projectRoot, projectID string, snapshotPolicy workspace.SnapshotPolicy) error {
	transactions := filepath.Join(projectRoot, ".sunaba", "transactions")
	entries, err := os.ReadDir(transactions)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	rootFD, err := openDirectory(projectRoot)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "sunaba-apply-") {
			return fmt.Errorf("unexpected transaction entry %q", entry.Name())
		}
		transactionRoot := filepath.Join(transactions, entry.Name())
		encoded, err := securefs.ReadOwnedRegular(filepath.Join(transactionRoot, "journal.json"), 64<<20)
		if err != nil {
			return fmt.Errorf("read recovery journal: %w", err)
		}
		var j journal
		if securefs.DecodeStrictJSON(encoded, &j) != nil || j.Version != 1 || j.ProjectID != projectID || len(j.Entries) > snapshotPolicy.MaxEntries {
			return fmt.Errorf("invalid recovery journal")
		}
		backupFD, err := openDirectory(filepath.Join(transactionRoot, "backup"))
		if err != nil {
			return err
		}
		if err := rollback(rootFD, backupFD, j); err != nil {
			unix.Close(backupFD)
			return err
		}
		unix.Close(backupFD)
		if err := removeTransactionRoot(transactionRoot, projectRoot); err != nil {
			return err
		}
	}
	return nil
}

func affectedRoots(changeSet workspace.ChangeSet) []string {
	set := make(map[string]struct{})
	for _, change := range changeSet.Changes {
		set[change.Path] = struct{}{}
		if change.From != "" {
			set[change.From] = struct{}{}
		}
	}
	paths := make([]string, 0, len(set))
	for entryPath := range set {
		paths = append(paths, entryPath)
	}
	sort.Slice(paths, func(i, j int) bool {
		leftDepth, rightDepth := strings.Count(paths[i], "/"), strings.Count(paths[j], "/")
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return paths[i] < paths[j]
	})
	result := make([]string, 0, len(paths))
	selected := make(map[string]struct{}, len(paths))
	for _, candidate := range paths {
		covered := false
		for parent := path.Dir(candidate); parent != "."; parent = path.Dir(parent) {
			if _, exists := selected[parent]; exists {
				covered = true
				break
			}
		}
		if !covered {
			result = append(result, candidate)
			selected[candidate] = struct{}{}
		}
	}
	return result
}

func newTransactionRoot(projectRoot, projectID string) (string, error) {
	managed := filepath.Join(projectRoot, ".sunaba")
	if err := ensurePrivateDirectory(managed); err != nil {
		return "", err
	}
	transactions := filepath.Join(managed, "transactions")
	if err := ensurePrivateDirectory(transactions); err != nil {
		return "", err
	}
	return os.MkdirTemp(transactions, "sunaba-apply-"+projectID+"-")
}

func ensurePrivateDirectory(directory string) error {
	return securefs.EnsureOwnedDir(directory)
}

func writeJournal(filename string, value journal) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return securefs.AtomicWriteOwned(filename, append(encoded, '\n'))
}

func rollback(rootFD, backupFD int, j journal) error {
	for index := len(j.Entries) - 1; index >= 0; index-- {
		item := j.Entries[index]
		if err := validateRelative(item.Path); err != nil || !strings.HasPrefix(item.BackupName, "item-") || strings.Contains(item.BackupName, "/") {
			return fmt.Errorf("unsafe recovery journal entry")
		}
		backupExists, err := relativeExists(backupFD, item.BackupName)
		if err != nil {
			return err
		}
		if backupExists {
			if err := removeRelative(rootFD, item.Path); err != nil {
				return err
			}
			if err := renameRelative(backupFD, item.BackupName, rootFD, item.Path); err != nil {
				return err
			}
		} else if !item.Original {
			if err := removeRelative(rootFD, item.Path); err != nil {
				return err
			}
		}
	}
	return nil
}

func openDirectory(directory string) (int, error) {
	return unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
}

func validateRelative(relative string) error {
	if relative == "" || path.Clean(relative) != relative || strings.HasPrefix(relative, "../") || strings.HasPrefix(relative, "/") || strings.ContainsRune(relative, '\x00') {
		return fmt.Errorf("unsafe apply path %q", relative)
	}
	first := strings.Split(relative, "/")[0]
	if strings.EqualFold(first, ".git") || strings.EqualFold(first, ".sunaba") {
		return fmt.Errorf("apply path targets Protected Path")
	}
	return nil
}

func openParent(rootFD int, relative string) (int, string, error) {
	if err := validateRelative(relative); err != nil {
		return -1, "", err
	}
	components := strings.Split(relative, "/")
	current, err := unix.Dup(rootFD)
	if err != nil {
		return -1, "", err
	}
	for _, component := range components[:len(components)-1] {
		next, err := unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		unix.Close(current)
		if err != nil {
			return -1, "", err
		}
		current = next
	}
	return current, components[len(components)-1], nil
}

func relativeExists(rootFD int, relative string) (bool, error) {
	parent, name, err := openParent(rootFD, relative)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	defer unix.Close(parent)
	var stat unix.Stat_t
	err = unix.Fstatat(parent, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	return err == nil, err
}

func renameRelative(sourceRoot int, source string, destinationRoot int, destination string) error {
	sourceParent, sourceName, err := openParent(sourceRoot, source)
	if err != nil {
		return err
	}
	defer unix.Close(sourceParent)
	destinationParent, destinationName, err := openParent(destinationRoot, destination)
	if err != nil {
		return err
	}
	defer unix.Close(destinationParent)
	return unix.Renameat(sourceParent, sourceName, destinationParent, destinationName)
}

func removeRelative(rootFD int, relative string) error {
	parent, name, err := openParent(rootFD, relative)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	return removeAt(parent, name)
}

func removeAt(parentFD int, name string) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return err
	}
	if uint32(stat.Mode)&uint32(unix.S_IFMT) != uint32(unix.S_IFDIR) {
		return unix.Unlinkat(parentFD, name, 0)
	}
	directoryFD, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	duplicate, err := unix.Dup(directoryFD)
	if err != nil {
		unix.Close(directoryFD)
		return err
	}
	directory := os.NewFile(uintptr(duplicate), name)
	names, err := directory.Readdirnames(-1)
	_ = directory.Close()
	if err != nil {
		unix.Close(directoryFD)
		return err
	}
	for _, child := range names {
		if err := removeAt(directoryFD, child); err != nil {
			unix.Close(directoryFD)
			return err
		}
	}
	unix.Close(directoryFD)
	return unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
}

func removeTransactionRoot(transactionRoot, projectRoot string) error {
	expected := filepath.Join(projectRoot, ".sunaba", "transactions")
	if filepath.Dir(transactionRoot) != expected || !strings.HasPrefix(filepath.Base(transactionRoot), "sunaba-apply-") {
		return fmt.Errorf("refusing to remove unowned transaction")
	}
	info, err := os.Lstat(transactionRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to remove unsafe transaction")
	}
	return os.RemoveAll(transactionRoot)
}
