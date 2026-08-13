//go:build integration

package integration

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"sunaba/internal/dependency"
	sunabaruntime "sunaba/internal/runtime"
	"sunaba/internal/workspace"
)

func TestPhase0OverlayFreezeAndExportLayout(t *testing.T) {
	if os.Getenv("SUNABA_PHASE0_INTEGRATION") != "1" {
		t.Skip("set SUNABA_PHASE0_INTEGRATION=1 on the pinned macOS/Apple Container host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	runID := randomID(t)
	name := "sunaba-phase0-overlay-" + runID
	manifest := dependency.MustPinned()
	rt := sunabaruntime.NewAppleContainer(false)
	if state, err := rt.ContainerState(ctx, name); err != nil || state != sunabaruntime.StateNotFound {
		t.Fatalf("probe resource name is not unused: state=%s error=%v", state, err)
	}

	transactionRoot, err := os.MkdirTemp("/private/tmp", "sunaba-overlay-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(transactionRoot)
	if err := os.Chmod(transactionRoot, 0700); err != nil {
		t.Fatal(err)
	}
	projectRoot := filepath.Join(transactionRoot, "project")
	if err := os.Mkdir(projectRoot, 0700); err != nil {
		t.Fatal(err)
	}
	writeIntegrationFile(t, filepath.Join(projectRoot, "keep.txt"), "keep\n")
	writeIntegrationFile(t, filepath.Join(projectRoot, "modify.txt"), "before\n")
	writeIntegrationFile(t, filepath.Join(projectRoot, "delete.txt"), "delete\n")
	writeIntegrationFile(t, filepath.Join(projectRoot, "rename.txt"), "rename\n")
	writeIntegrationFile(t, filepath.Join(projectRoot, "opaque", "old.txt"), "old\n")
	writeIntegrationFile(t, filepath.Join(projectRoot, ".git", "config"), "credential=host-secret\n")
	external := filepath.Join(transactionRoot, "outside-secret")
	writeIntegrationFile(t, external, "must-not-copy\n")
	if err := os.Symlink(external, filepath.Join(projectRoot, "external-link")); err != nil {
		t.Fatal(err)
	}
	hostBefore, err := workspace.BuildSnapshotManifest(projectRoot, workspace.DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	snapshotPath := filepath.Join(transactionRoot, "snapshot")
	snapshot, err := workspace.CreateProjectSnapshot(projectRoot, snapshotPath, workspace.DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Digest != hostBefore.Digest {
		t.Fatalf("snapshot digest=%s, host=%s", snapshot.Digest, hostBefore.Digest)
	}

	spec := sunabaruntime.ContainerSpec{
		Name:       name,
		Image:      manifest.AgentImage.Tag,
		CPUs:       1,
		Memory:     "2G",
		Networks:   []string{"none"},
		NoDNS:      true,
		CapAdd:     []string{"ALL"},
		Entrypoint: "/bin/bash",
		Args:       []string{"-lc", "exec tail -f /dev/null"},
		Labels: map[string]string{
			"dev.sunaba.owner":  "integration-test",
			"dev.sunaba.test":   "phase0-overlay",
			"dev.sunaba.run-id": runID,
		},
	}
	if err := rt.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}
	defer cleanupContainer(t, ctx, rt, name, runID)
	if err := rt.Exec(ctx, name, false, []string{"mkdir", "-p", "/var/lib/sunaba"}); err != nil {
		t.Fatal(err)
	}
	if err := rt.CopyTo(ctx, name, snapshotPath, "/var/lib/sunaba/lower"); err != nil {
		t.Fatal(err)
	}
	setup := strings.Join([]string{
		"set -eu",
		"test ! -e /var/lib/sunaba/lower/.git",
		"test -L /var/lib/sunaba/lower/external-link",
		"test \"$(readlink /var/lib/sunaba/lower/external-link)\" = '" + external + "'",
		"mkdir -p /var/lib/sunaba/upper /var/lib/sunaba/work /workspace",
		"mount -t overlay overlay -o lowerdir=/var/lib/sunaba/lower,upperdir=/var/lib/sunaba/upper,workdir=/var/lib/sunaba/work /workspace",
		"printf 'after\\n' > /workspace/modify.txt",
		"printf 'added\\n' > /workspace/add.txt",
		"rm /workspace/delete.txt",
		"mv /workspace/rename.txt /workspace/renamed.txt",
		"ln -s keep.txt /workspace/new-link",
		"rm -rf /workspace/opaque",
		"mkdir /workspace/opaque",
		"printf 'new\\n' > /workspace/opaque/new.txt",
		"sync",
	}, "\n")
	if out, err := rt.ExecOutput(ctx, name, []string{"/bin/bash", "-lc", setup}); err != nil {
		t.Fatalf("configure overlay: %v: %s", err, out)
	}
	hostAfter, err := workspace.BuildSnapshotManifest(projectRoot, workspace.DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if hostAfter.Digest != hostBefore.Digest {
		t.Fatalf("guest overlay changed host Project: %s != %s", hostAfter.Digest, hostBefore.Digest)
	}
	if err := rt.Stop(ctx, name); err != nil {
		t.Fatal(err)
	}
	quarantine := filepath.Join(transactionRoot, "sunaba-quarantine-"+runID)
	if err := os.Mkdir(quarantine, 0700); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(quarantine, "rootfs.tar")
	if err := rt.Export(ctx, name, archive); err != nil {
		t.Fatal(err)
	}
	layout, err := inspectExportTar(archive, 100_000)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("export workspace entries: %+v", layout.WorkspaceEntries)
	if layout.OCI || !layout.FlatRootFS {
		t.Fatalf("unexpected Apple Container 1.2.2 export layout: %+v", layout)
	}
	frozen, err := workspace.ParseFrozenRootFS(archive, quarantine, snapshot, workspace.DefaultExportPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer frozen.Close()
	if frozen.Lower.Digest != snapshot.Digest {
		t.Fatalf("trusted lower changed: %s != %s", frozen.Lower.Digest, snapshot.Digest)
	}
	upper := make(map[string]workspace.OverlayEntry, len(frozen.Upper))
	for _, entry := range frozen.Upper {
		upper[entry.Path] = entry
	}
	if len(upper) != 7 {
		t.Fatalf("unexpected upper entries: %+v", frozen.Upper)
	}
	assertStagedContent(t, upper["add.txt"], "added\n")
	assertStagedContent(t, upper["modify.txt"], "after\n")
	if !upper["delete.txt"].Whiteout {
		t.Fatalf("delete whiteout was not recognized: %+v", upper["delete.txt"])
	}
	if upper["renamed.txt"].Redirect != "rename.txt" {
		t.Fatalf("rename redirect was not recognized: %+v", upper["renamed.txt"])
	}
	if !upper["renamed.txt"].Metacopy || upper["renamed.txt"].DataPath != "" || upper["renamed.txt"].SHA256 != snapshotEntry(t, snapshot, "rename.txt").SHA256 {
		t.Fatalf("rename metacopy does not reference trusted lower: %+v", upper["renamed.txt"])
	}
	if upper["new-link"].Type != workspace.TypeSymlink || upper["new-link"].LinkTarget != "keep.txt" {
		t.Fatalf("new symlink was not recognized: %+v", upper["new-link"])
	}
	if !upper["opaque"].Opaque || upper["opaque"].Type != workspace.TypeDirectory {
		t.Fatalf("opaque directory was not recognized: %+v", upper["opaque"])
	}
	assertStagedContent(t, upper["opaque/new.txt"], "new\n")
	mergedRoot := filepath.Join(quarantine, "sunaba-merged-"+runID)
	merged, err := workspace.MaterializeMergedView(snapshotPath, mergedRoot, snapshot, frozen, workspace.DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	assertIntegrationContent(t, filepath.Join(merged.Root, "keep.txt"), "keep\n")
	assertIntegrationContent(t, filepath.Join(merged.Root, "modify.txt"), "after\n")
	assertIntegrationContent(t, filepath.Join(merged.Root, "add.txt"), "added\n")
	assertIntegrationContent(t, filepath.Join(merged.Root, "renamed.txt"), "rename\n")
	assertIntegrationContent(t, filepath.Join(merged.Root, "opaque", "new.txt"), "new\n")
	if _, err := os.Lstat(filepath.Join(merged.Root, "delete.txt")); !os.IsNotExist(err) {
		t.Fatalf("merged delete.txt still exists: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(merged.Root, "rename.txt")); !os.IsNotExist(err) {
		t.Fatalf("merged rename.txt still exists: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(merged.Root, "opaque", "old.txt")); !os.IsNotExist(err) {
		t.Fatalf("opaque lower child still exists: %v", err)
	}
	mergedAgain, err := workspace.MaterializeMergedView(snapshotPath, filepath.Join(quarantine, "sunaba-merged-repeat-"+runID), snapshot, frozen, workspace.DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if mergedAgain.Manifest.Digest != merged.Manifest.Digest {
		t.Fatalf("merged reconstruction is not reproducible: %s != %s", mergedAgain.Manifest.Digest, merged.Manifest.Digest)
	}
	changeSet, err := workspace.BuildChangeSet(snapshot, merged.Manifest, workspace.DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	repeatedChangeSet, err := workspace.BuildChangeSet(snapshot, mergedAgain.Manifest, workspace.DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if changeSet.Digest != repeatedChangeSet.Digest {
		t.Fatalf("Change Set is not reproducible: %s != %s", changeSet.Digest, repeatedChangeSet.Digest)
	}
	wantChanges := map[string]workspace.ChangeKind{
		"add.txt": workspace.ChangeAdd, "delete.txt": workspace.ChangeDelete,
		"modify.txt": workspace.ChangeModify, "new-link": workspace.ChangeAdd,
		"opaque": workspace.ChangeModify, "opaque/new.txt": workspace.ChangeAdd,
		"opaque/old.txt": workspace.ChangeDelete, "renamed.txt": workspace.ChangeRename,
	}
	if len(changeSet.Changes) != len(wantChanges) {
		t.Fatalf("unexpected Change Set: %+v", changeSet.Changes)
	}
	for _, change := range changeSet.Changes {
		if change.Kind != wantChanges[change.Path] {
			t.Fatalf("unexpected change: %+v", change)
		}
		if change.Kind == workspace.ChangeRename && change.From != "rename.txt" {
			t.Fatalf("unexpected rename: %+v", change)
		}
	}
	if err := rt.Start(ctx, name); err != nil {
		t.Fatal(err)
	}
	if out, err := rt.ExecOutput(ctx, name, []string{"/bin/bash", "-lc", "printf 'tampered\\n' > /var/lib/sunaba/lower/keep.txt; sync"}); err != nil {
		t.Fatalf("tamper lower: %v: %s", err, out)
	}
	if err := rt.Stop(ctx, name); err != nil {
		t.Fatal(err)
	}
	tamperQuarantine := filepath.Join(transactionRoot, "sunaba-tamper-"+runID)
	if err := os.Mkdir(tamperQuarantine, 0700); err != nil {
		t.Fatal(err)
	}
	tamperArchive := filepath.Join(tamperQuarantine, "rootfs.tar")
	if err := rt.Export(ctx, name, tamperArchive); err != nil {
		t.Fatal(err)
	}
	if tampered, err := workspace.ParseFrozenRootFS(tamperArchive, tamperQuarantine, snapshot, workspace.DefaultExportPolicy()); err == nil {
		_ = tampered.Close()
		t.Fatal("guest root lower tampering was not detected")
	}
}

func snapshotEntry(t *testing.T, manifest workspace.SnapshotManifest, path string) workspace.SnapshotEntry {
	t.Helper()
	for _, entry := range manifest.Entries {
		if entry.Path == path {
			return entry
		}
	}
	t.Fatalf("snapshot entry %q not found", path)
	return workspace.SnapshotEntry{}
}

func assertStagedContent(t *testing.T, entry workspace.OverlayEntry, expected string) {
	t.Helper()
	content, err := os.ReadFile(entry.DataPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != expected {
		t.Fatalf("staged %q content=%q, want %q", entry.Path, content, expected)
	}
}

func assertIntegrationContent(t *testing.T, path, expected string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != expected {
		t.Fatalf("%s content=%q, want %q", path, content, expected)
	}
}

type exportLayout struct {
	OCI              bool
	FlatRootFS       bool
	EntryCount       int
	WorkspaceEntries []tarEntrySummary
}

type tarEntrySummary struct {
	Name     string
	Typeflag byte
	Mode     int64
	Size     int64
	Devmajor int64
	Devminor int64
	Linkname string
	PAXKeys  []string
}

func inspectExportTar(archive string, maximum int) (exportLayout, error) {
	file, err := os.Open(archive)
	if err != nil {
		return exportLayout{}, err
	}
	defer file.Close()
	reader := tar.NewReader(file)
	var layout exportLayout
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return exportLayout{}, err
		}
		clean := filepath.ToSlash(filepath.Clean(header.Name))
		if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
			return exportLayout{}, fmt.Errorf("unsafe outer archive path %q", header.Name)
		}
		layout.EntryCount++
		if layout.EntryCount > maximum {
			return exportLayout{}, fmt.Errorf("outer archive exceeds %d entries", maximum)
		}
		if clean == "oci-layout" || clean == "index.json" {
			layout.OCI = true
		}
		if clean == "var/lib/sunaba" {
			layout.FlatRootFS = true
		}
		if clean == "var/lib/sunaba" || strings.HasPrefix(clean, "var/lib/sunaba/") {
			paxKeys := make([]string, 0, len(header.PAXRecords))
			for key := range header.PAXRecords {
				paxKeys = append(paxKeys, strconv.QuoteToASCII(key))
			}
			sort.Strings(paxKeys)
			layout.WorkspaceEntries = append(layout.WorkspaceEntries, tarEntrySummary{
				Name: strconv.QuoteToASCII(clean), Typeflag: header.Typeflag, Mode: header.Mode, Size: header.Size,
				Devmajor: header.Devmajor, Devminor: header.Devminor, Linkname: strconv.QuoteToASCII(header.Linkname), PAXKeys: paxKeys,
			})
		}
	}
	return layout, nil
}

func writeIntegrationFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
