package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"sunaba/internal/policy"
	"sunaba/internal/trustedui"
	"sunaba/internal/workspace"
)

const snapshotApprovalFile = "snapshot-approval.json"

type snapshotApproval struct {
	Version            int       `json:"version"`
	InitialDigest      string    `json:"initial_digest"`
	ExportPolicyDigest string    `json:"export_policy_digest"`
	ApprovedAt         time.Time `json:"approved_at"`
}

func (a *app) snapshotManifest(dir string) (policy.ProjectPolicy, string, policy.CompiledExportPolicy, workspace.SnapshotManifest, error) {
	projectPolicy, _, projectState, err := a.loadEffectivePolicy(dir)
	if err != nil {
		return policy.ProjectPolicy{}, "", policy.CompiledExportPolicy{}, workspace.SnapshotManifest{}, err
	}
	compiled, err := policy.CompileExportPolicy(projectPolicy.Export, projectPolicy.ProtectedPaths, projectPolicy.Snapshot.Exclude)
	if err != nil {
		return policy.ProjectPolicy{}, "", policy.CompiledExportPolicy{}, workspace.SnapshotManifest{}, err
	}
	manifest, err := workspace.BuildSnapshotManifest(projectPolicy.ProjectRoot, compiled.Snapshot)
	return projectPolicy, projectState, compiled, manifest, err
}

func (a *app) snapshotPreview(dir string) error {
	projectPolicy, _, compiled, manifest, err := a.snapshotManifest(dir)
	if err != nil {
		return err
	}
	preview := workspace.BuildSnapshotPreview(manifest)
	fmt.Fprintf(a.output, "Project: %s\nSnapshot digest: %s\nEntries: %d (files: %d)\nTotal bytes: %d\nExcluded paths: %d\n", projectPolicy.ProjectID, preview.Digest, preview.EntryCount, preview.FileCount, preview.TotalSize, len(compiled.Snapshot.ExcludedPaths))
	for _, file := range preview.LargeFiles {
		fmt.Fprintf(a.output, "Large file: %s (%d bytes)\n", trustedui.SanitizeTerminal(file.Path), file.Size)
	}
	for _, candidate := range preview.SensitivePaths {
		fmt.Fprintf(a.output, "Sensitive filename candidate: %s\n", trustedui.SanitizeTerminal(candidate))
	}
	if len(preview.SensitivePaths) > 0 {
		fmt.Fprintln(a.errors, "WARNING: files with secret-like names may be sent to the configured model provider if included.")
	}
	fmt.Fprintf(a.output, "Approve exactly this preview with: sunaba snapshot approve --digest %s\n", preview.Digest)
	return nil
}

func (a *app) snapshotApprove(dir, digest string) error {
	projectPolicy, projectState, compiled, manifest, err := a.snapshotManifest(dir)
	if err != nil {
		return err
	}
	if digest != manifest.Digest {
		return fmt.Errorf("snapshot digest changed or does not match the current preview")
	}
	approval := snapshotApproval{Version: 1, InitialDigest: digest, ExportPolicyDigest: compiled.Digest, ApprovedAt: time.Now().UTC()}
	if err := writePrivateJSON(filepath.Join(projectState, snapshotApprovalFile), approval); err != nil {
		return err
	}
	fmt.Fprintf(a.output, "Approved the first Snapshot for Project %s at digest %s.\n", projectPolicy.ProjectID, digest)
	return nil
}

func verifySnapshotApproval(projectState string, compiled policy.CompiledExportPolicy, manifest workspace.SnapshotManifest) (snapshotApproval, error) {
	data, err := readOwnedPrivateFile(filepath.Join(projectState, snapshotApprovalFile), 16<<10)
	if err != nil {
		return snapshotApproval{}, fmt.Errorf("first Snapshot is not approved; run 'sunaba snapshot preview' and approve its exact digest")
	}
	var approval snapshotApproval
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&approval); err != nil || decoder.Decode(&struct{}{}) != io.EOF || approval.Version != 1 || approval.ExportPolicyDigest != compiled.Digest || approval.ApprovedAt.IsZero() {
		return snapshotApproval{}, fmt.Errorf("Snapshot approval is invalid or belongs to a different exclusion policy; preview and approve again")
	}
	if approval.InitialDigest != manifest.Digest {
		return snapshotApproval{}, fmt.Errorf("Project changed after Snapshot approval; preview and approve the new digest")
	}
	return approval, nil
}

func (a *app) snapshotImportGitignore(dir string) error {
	projectPolicy, _, _, err := a.loadPolicy(dir)
	if err != nil {
		return err
	}
	data, err := readProjectRootFileNoFollow(projectPolicy.ProjectRoot, ".gitignore", 1<<20)
	if err != nil {
		return err
	}
	candidates, skipped, err := parseGitignoreExclusionCandidates(data)
	if err != nil {
		return err
	}
	store, err := a.projectConfigStore()
	if err != nil {
		return err
	}
	configLock, err := a.store.AcquireConfigLock(projectPolicy.ProjectID)
	if err != nil {
		return err
	}
	defer configLock.Close()
	config, rules, err := store.Load(projectPolicy.ProjectID)
	if err != nil {
		return err
	}
	config.Snapshot.Exclude = append(config.Snapshot.Exclude, candidates...)
	sort.Strings(config.Snapshot.Exclude)
	config.Snapshot.Exclude = compactStrings(config.Snapshot.Exclude)
	if err := store.Save(projectPolicy.ProjectID, config, rules); err != nil {
		return err
	}
	fmt.Fprintf(a.output, "Imported %d literal exclusion candidate(s); skipped %d wildcard, negated, or unsafe line(s). Review %s and run 'sunaba config apply'.\n", len(candidates), skipped, filepath.Join(store.Root, "projects", projectPolicy.ProjectID, "project.json"))
	return nil
}

func parseGitignoreExclusionCandidates(data []byte) ([]string, int, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var result []string
	skipped := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "!") || strings.ContainsAny(line, "*?[\\") {
			skipped++
			continue
		}
		line = strings.TrimPrefix(line, "/")
		line = strings.TrimSuffix(line, "/")
		if line == "" || path.Clean(line) != line || line == ".." || strings.HasPrefix(line, "../") || strings.ContainsRune(line, '\x00') {
			skipped++
			continue
		}
		result = append(result, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, err
	}
	sort.Strings(result)
	return compactStrings(result), skipped, nil
}

func compactStrings(values []string) []string {
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func readProjectRootFileNoFollow(root, name string, maximum int64) ([]byte, error) {
	if filepath.Base(name) != name {
		return nil, fmt.Errorf("invalid Project file name")
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	fd, err := unix.Openat(rootFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("Project has no %s", name)
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximum {
		return nil, fmt.Errorf("Project %s is not a bounded regular file", name)
	}
	return io.ReadAll(io.LimitReader(file, maximum+1))
}
