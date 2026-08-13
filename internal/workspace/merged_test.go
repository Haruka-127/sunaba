package workspace

import (
	"archive/tar"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaterializeMergedViewReconstructsOverlaySemantics(t *testing.T) {
	baseline := fixtureBaseline(t)
	archive, quarantine := writeRootFSFixture(t, append(baselineTarEntries(t),
		tarFixtureEntry{header: tar.Header{Name: upperPrefix, Typeflag: tar.TypeDir, Mode: 0755}},
		tarFixtureEntry{header: tar.Header{Name: upperPrefix + "/add.txt", Typeflag: tar.TypeReg, Mode: 0644, Size: 6}, data: "added\n"},
		tarFixtureEntry{header: tar.Header{Name: upperPrefix + "/delete.txt", Typeflag: tar.TypeLink, Linkname: "var/lib/sunaba/work/index/#3"}},
		tarFixtureEntry{header: tar.Header{Name: upperPrefix + "/renamed.txt", Typeflag: tar.TypeReg, Mode: 0600, Size: 7, PAXRecords: map[string]string{"SCHILY.xattr.trusted.overlay.redirect": "rename.txt", "SCHILY.xattr.trusted.overlay.metacopy": ""}}, data: "\x00\x00\x00\x00\x00\x00\x00"},
		tarFixtureEntry{header: tar.Header{Name: upperPrefix + "/new-link", Typeflag: tar.TypeSymlink, Mode: 0777, Linkname: "keep.txt"}},
	)...)
	frozen, err := ParseFrozenRootFS(archive, quarantine, baseline, DefaultExportPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer frozen.Close()
	destination := filepath.Join(quarantine, "sunaba-merged-test")
	view, err := MaterializeMergedView(baseline.Root, destination, baseline, frozen, DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if view.Root != destination || view.Manifest.Digest == baseline.Digest {
		t.Fatalf("view=%+v", view)
	}
	assertFileContent(t, filepath.Join(destination, "keep.txt"), "keep\n")
	assertFileContent(t, filepath.Join(destination, "add.txt"), "added\n")
	assertFileContent(t, filepath.Join(destination, "renamed.txt"), "rename\n")
	if _, err := os.Lstat(filepath.Join(destination, "delete.txt")); !os.IsNotExist(err) {
		t.Fatalf("deleted path still exists: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(destination, "rename.txt")); !os.IsNotExist(err) {
		t.Fatalf("redirect source still exists: %v", err)
	}
	target, err := os.Readlink(filepath.Join(destination, "new-link"))
	if err != nil || target != "keep.txt" {
		t.Fatalf("symlink target=%q error=%v", target, err)
	}
	assertFileContent(t, filepath.Join(baseline.Root, "delete.txt"), "delete\n")
}

func TestMaterializeMergedViewAppliesOpaqueDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "dir"), 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "dir", "old.txt"), "old\n")
	baseline, err := BuildSnapshotManifest(root, DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	quarantine := filepath.Join(t.TempDir(), "sunaba-quarantine")
	if err := os.Mkdir(quarantine, 0700); err != nil {
		t.Fatal(err)
	}
	frozen := FrozenExport{
		Lower: baseline,
		Upper: []OverlayEntry{
			{Path: "dir", Type: TypeDirectory, Mode: 0755, Opaque: true},
		},
	}
	view, err := MaterializeMergedView(root, filepath.Join(quarantine, "sunaba-merged-opaque"), baseline, frozen, DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Manifest.Entries) != 1 || view.Manifest.Entries[0].Path != "dir" {
		t.Fatalf("opaque view=%+v", view.Manifest.Entries)
	}
}

func TestMaterializeMergedViewRejectsFabricatedStagedPath(t *testing.T) {
	baseline := fixtureBaseline(t)
	quarantine := filepath.Join(t.TempDir(), "sunaba-quarantine")
	if err := os.Mkdir(quarantine, 0700); err != nil {
		t.Fatal(err)
	}
	frozen := FrozenExport{
		Lower: baseline,
		Upper: []OverlayEntry{{
			Path: "evil", Type: TypeFile, Mode: 0600, Size: 5,
			SHA256: baseline.Entries[1].SHA256, DataPath: filepath.Join(baseline.Root, "keep.txt"),
		}},
	}
	if _, err := MaterializeMergedView(baseline.Root, filepath.Join(quarantine, "sunaba-merged-evil"), baseline, frozen, DefaultSnapshotPolicy()); err == nil {
		t.Fatal("fabricated staged path was accepted")
	}
}

func TestFirstManifestDifferenceReportsFieldWithoutContent(t *testing.T) {
	expected := SnapshotManifest{Entries: []SnapshotEntry{{Path: "file.txt", Type: TypeFile, Mode: 0600, Size: 6, SHA256: "secret-digest"}}}
	actual := expected
	actual.Entries = append([]SnapshotEntry(nil), expected.Entries...)
	actual.Entries[0].Mode = 0644
	if got := firstManifestDifference(expected, actual); got != `path "file.txt" mode differs` {
		t.Fatalf("difference=%q", got)
	}
	if strings.Contains(firstManifestDifference(expected, actual), "secret-digest") {
		t.Fatal("diagnostic disclosed content-derived metadata")
	}
}

func TestRemoveMergedSubtreesHandlesSiblingPrefixesInOnePass(t *testing.T) {
	state := map[string]mergedEntry{
		"a": {}, "a/child": {}, "a-b": {}, "opaque": {}, "opaque/old": {}, "opaque-sibling": {},
	}
	removeMergedSubtrees(state, []mergedSubtreeDeletion{{root: "a", includeRoot: true}, {root: "opaque"}})
	for _, removed := range []string{"a", "a/child", "opaque/old"} {
		if _, exists := state[removed]; exists {
			t.Fatalf("deleted path remained: %s", removed)
		}
	}
	for _, retained := range []string{"a-b", "opaque", "opaque-sibling"} {
		if _, exists := state[retained]; !exists {
			t.Fatalf("sibling or opaque root was removed: %s", retained)
		}
	}
}

func TestApplyRedirectsRejectsEndpointAncestorDespiteLexicalSibling(t *testing.T) {
	baseline := map[string]SnapshotEntry{
		"a": {Path: "a", Type: TypeDirectory}, "a/child": {Path: "a/child", Type: TypeFile},
		"source": {Path: "source", Type: TypeDirectory}, "source/file": {Path: "source/file", Type: TypeFile},
	}
	state := make(map[string]mergedEntry, len(baseline))
	for entryPath, entry := range baseline {
		state[entryPath] = mergedEntry{manifest: entry, lowerPath: entryPath}
	}
	upper := []OverlayEntry{
		{Path: "a", Redirect: "source", Type: TypeDirectory},
		{Path: "a/child", Redirect: "unrelated", Type: TypeFile},
	}
	baseline["unrelated"] = SnapshotEntry{Path: "unrelated", Type: TypeFile}
	if err := applyRedirects(state, baseline, upper); err == nil {
		t.Fatal("overlapping redirect endpoints were accepted")
	}
}

func BenchmarkRemoveMergedSubtreesAdversarial(b *testing.B) {
	const entries = 100_000
	base := make(map[string]mergedEntry, entries)
	deletions := make([]mergedSubtreeDeletion, 0, entries/2)
	for index := 0; index < entries; index++ {
		entryPath := fmt.Sprintf("dir-%06d/file", index)
		base[entryPath] = mergedEntry{manifest: SnapshotEntry{Path: entryPath, Type: TypeFile}}
		if index%2 == 0 {
			deletions = append(deletions, mergedSubtreeDeletion{root: fmt.Sprintf("dir-%06d", index), includeRoot: true})
		}
	}
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		state := make(map[string]mergedEntry, len(base))
		for entryPath, entry := range base {
			state[entryPath] = entry
		}
		removeMergedSubtrees(state, deletions)
	}
}

func assertFileContent(t *testing.T, path, expected string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != expected {
		t.Fatalf("%s content=%q, want %q", path, content, expected)
	}
}
