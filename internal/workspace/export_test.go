package workspace

import (
	"archive/tar"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tarFixtureEntry struct {
	header tar.Header
	data   string
}

func TestParseFrozenRootFS(t *testing.T) {
	baseline := fixtureBaseline(t)
	archive, quarantine := writeRootFSFixture(t, append(baselineTarEntries(t),
		tarFixtureEntry{header: tar.Header{Name: upperPrefix, Typeflag: tar.TypeDir, Mode: 0755}},
		tarFixtureEntry{header: tar.Header{Name: upperPrefix + "/add.txt", Typeflag: tar.TypeReg, Mode: 0644, Size: 6}, data: "added\n"},
		tarFixtureEntry{header: tar.Header{Name: upperPrefix + "/delete.txt", Typeflag: tar.TypeLink, Linkname: "var/lib/sunaba/work/index/#3"}},
		tarFixtureEntry{header: tar.Header{Name: upperPrefix + "/renamed.txt", Typeflag: tar.TypeReg, Mode: 0600, Size: 7, PAXRecords: map[string]string{"SCHILY.xattr.trusted.overlay.redirect": "rename.txt", "SCHILY.xattr.trusted.overlay.metacopy": ""}}, data: "rename\n"},
	)...)
	export, err := ParseFrozenRootFS(archive, quarantine, baseline, DefaultExportPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer export.Close()
	if export.Lower.Digest != baseline.Digest || len(export.Upper) != 3 {
		t.Fatalf("export=%+v", export)
	}
	if !export.Upper[1].Whiteout || export.Upper[2].Redirect != "rename.txt" || !export.Upper[2].Metacopy {
		t.Fatalf("upper=%+v", export.Upper)
	}
	if export.Upper[2].DataPath != "" || export.Upper[2].SHA256 != baseline.Entries[2].SHA256 {
		t.Fatalf("metacopy did not reference trusted lower: %+v", export.Upper[2])
	}
	content, err := os.ReadFile(export.Upper[0].DataPath)
	if err != nil || string(content) != "added\n" {
		t.Fatalf("staged content=%q error=%v", content, err)
	}
}

func TestParseFrozenRootFSRecognizesObservedWhiteoutHardlinks(t *testing.T) {
	baseline := fixtureBaseline(t)
	for _, linkname := range []string{"var/lib/sunaba/work/index/#7", "var/lib/sunaba/work/work/#3"} {
		t.Run(linkname, func(t *testing.T) {
			archive, quarantine := writeRootFSFixture(t, append(baselineTarEntries(t),
				tarFixtureEntry{header: tar.Header{Name: upperPrefix, Typeflag: tar.TypeDir, Mode: 0755}},
				tarFixtureEntry{header: tar.Header{Name: upperPrefix + "/deleted.txt", Typeflag: tar.TypeLink, Linkname: linkname}},
			)...)
			parsed, err := ParseFrozenRootFS(archive, quarantine, baseline, DefaultExportPolicy())
			if err != nil {
				t.Fatal(err)
			}
			defer parsed.Close()
			if len(parsed.Upper) != 1 || !parsed.Upper[0].Whiteout {
				t.Fatalf("upper=%+v", parsed.Upper)
			}
		})
	}
}

func TestParseFrozenRootFSComputesDeletesFromSafeMergedExport(t *testing.T) {
	baseline := fixtureBaseline(t)
	entries := append(baselineTarEntries(t),
		tarFixtureEntry{header: tar.Header{Name: mergedPrefix, Typeflag: tar.TypeDir, Mode: 0700}},
		tarFixtureEntry{header: tar.Header{Name: mergedPrefix + "/keep.txt", Typeflag: tar.TypeReg, Mode: 0600, Size: 8}, data: "changed\n"},
		tarFixtureEntry{header: tar.Header{Name: mergedPrefix + "/rename.txt", Typeflag: tar.TypeReg, Mode: 0600, Size: 7}, data: "rename\n"},
		tarFixtureEntry{header: tar.Header{Name: mergedPrefix + "/add.txt", Typeflag: tar.TypeReg, Mode: 0600, Size: 6}, data: "added\n"},
	)
	archive, quarantine := writeRootFSFixture(t, entries...)
	parsed, err := ParseFrozenRootFS(archive, quarantine, baseline, DefaultExportPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Close()
	whiteout := false
	for _, entry := range parsed.Upper {
		if entry.Path == "delete.txt" && entry.Whiteout {
			whiteout = true
		}
	}
	if !whiteout {
		t.Fatalf("host did not compute delete from merged absence: %+v", parsed.Upper)
	}
	destination := filepath.Join(quarantine, "sunaba-merged-test")
	merged, err := MaterializeMergedView(baseline.Root, destination, baseline, parsed, DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	changes, err := BuildChangeSet(baseline, merged.Manifest, DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if len(changes.Changes) != 3 {
		t.Fatalf("changes=%+v", changes)
	}
}

func TestParseFrozenRootFSRejectsAttacks(t *testing.T) {
	baseline := fixtureBaseline(t)
	tests := []struct {
		name  string
		entry tarFixtureEntry
	}{
		{name: "path traversal", entry: tarFixtureEntry{header: tar.Header{Name: "../escape", Typeflag: tar.TypeReg}}},
		{name: "protected path", entry: tarFixtureEntry{header: tar.Header{Name: upperPrefix + "/.git/config", Typeflag: tar.TypeReg}}},
		{name: "hardlink", entry: tarFixtureEntry{header: tar.Header{Name: upperPrefix + "/link", Typeflag: tar.TypeLink, Linkname: lowerPrefix + "/keep.txt"}}},
		{name: "special file", entry: tarFixtureEntry{header: tar.Header{Name: upperPrefix + "/fifo", Typeflag: tar.TypeFifo}}},
		{name: "unknown xattr", entry: tarFixtureEntry{header: tar.Header{Name: upperPrefix + "/file", Typeflag: tar.TypeReg, PAXRecords: map[string]string{"SCHILY.xattr.user.evil": "x"}}}},
		{name: "protected redirect", entry: tarFixtureEntry{header: tar.Header{Name: upperPrefix + "/renamed", Typeflag: tar.TypeReg, PAXRecords: map[string]string{"SCHILY.xattr.trusted.overlay.redirect": ".git/config"}}}},
		{name: "absolute redirect", entry: tarFixtureEntry{header: tar.Header{Name: upperPrefix + "/renamed", Typeflag: tar.TypeReg, PAXRecords: map[string]string{"SCHILY.xattr.trusted.overlay.redirect": "/rename.txt"}}}},
		{name: "empty symlink", entry: tarFixtureEntry{header: tar.Header{Name: upperPrefix + "/link", Typeflag: tar.TypeSymlink}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			archive, quarantine := writeRootFSFixture(t, append(baselineTarEntries(t),
				tarFixtureEntry{header: tar.Header{Name: upperPrefix, Typeflag: tar.TypeDir, Mode: 0755}}, tc.entry,
			)...)
			if _, err := ParseFrozenRootFS(archive, quarantine, baseline, DefaultExportPolicy()); err == nil {
				t.Fatal("attack entry was accepted")
			}
			entries, err := os.ReadDir(quarantine)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), "sunaba-export-") {
					t.Fatalf("failed parse retained staging %q", entry.Name())
				}
			}
		})
	}
}

func TestParseFrozenMergedRootRejectsAttacks(t *testing.T) {
	baseline := fixtureBaseline(t)
	tests := []struct {
		name  string
		entry tarFixtureEntry
	}{
		{name: "protected path", entry: tarFixtureEntry{header: tar.Header{Name: mergedPrefix + "/.git/config", Typeflag: tar.TypeReg}}},
		{name: "hardlink", entry: tarFixtureEntry{header: tar.Header{Name: mergedPrefix + "/link", Typeflag: tar.TypeLink, Linkname: lowerPrefix + "/keep.txt"}}},
		{name: "special file", entry: tarFixtureEntry{header: tar.Header{Name: mergedPrefix + "/fifo", Typeflag: tar.TypeFifo}}},
		{name: "xattr", entry: tarFixtureEntry{header: tar.Header{Name: mergedPrefix + "/file", Typeflag: tar.TypeReg, PAXRecords: map[string]string{"SCHILY.xattr.user.evil": "x"}}}},
		{name: "empty symlink", entry: tarFixtureEntry{header: tar.Header{Name: mergedPrefix + "/link", Typeflag: tar.TypeSymlink}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			archive, quarantine := writeRootFSFixture(t, append(baselineTarEntries(t),
				tarFixtureEntry{header: tar.Header{Name: mergedPrefix, Typeflag: tar.TypeDir, Mode: 0700}}, tc.entry,
			)...)
			if _, err := ParseFrozenRootFS(archive, quarantine, baseline, DefaultExportPolicy()); err == nil {
				t.Fatal("merged attack entry was accepted")
			}
			entries, err := os.ReadDir(quarantine)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), "sunaba-export-") {
					t.Fatalf("failed merged parse retained staging %q", entry.Name())
				}
			}
		})
	}
}

func TestFrozenExportCloseRejectsArbitraryDirectory(t *testing.T) {
	directory := t.TempDir()
	export := FrozenExport{StagingDir: directory}
	if err := export.Close(); err == nil {
		t.Fatal("arbitrary staging directory was accepted")
	}
	if _, err := os.Stat(directory); err != nil {
		t.Fatalf("arbitrary directory was removed: %v", err)
	}
}

func TestParseFrozenRootFSRejectsDuplicateWorkspacePath(t *testing.T) {
	baseline := fixtureBaseline(t)
	entries := append(baselineTarEntries(t),
		tarFixtureEntry{header: tar.Header{Name: lowerPrefix + "/keep.txt", Typeflag: tar.TypeReg, Mode: 0600, Size: 5}, data: "keep\n"},
		tarFixtureEntry{header: tar.Header{Name: upperPrefix, Typeflag: tar.TypeDir, Mode: 0755}},
	)
	archive, quarantine := writeRootFSFixture(t, entries...)
	if _, err := ParseFrozenRootFS(archive, quarantine, baseline, DefaultExportPolicy()); err == nil {
		t.Fatal("duplicate workspace path was accepted")
	}
}

func TestValidateArchivePathAllowsOnlyCanonicalDirectorySlash(t *testing.T) {
	if got, err := validateArchivePath("boot/", tar.TypeDir); err != nil || got != "boot" {
		t.Fatalf("canonical directory path: got=%q error=%v", got, err)
	}
	for _, tc := range []struct {
		name     string
		typeflag byte
	}{
		{name: "boot/", typeflag: tar.TypeReg},
		{name: "boot//", typeflag: tar.TypeDir},
		{name: "../boot/", typeflag: tar.TypeDir},
	} {
		if _, err := validateArchivePath(tc.name, tc.typeflag); err == nil {
			t.Fatalf("unsafe path %q was accepted", tc.name)
		}
	}
}

func TestParseFrozenRootFSRejectsTamperedLower(t *testing.T) {
	baseline := fixtureBaseline(t)
	entries := baselineTarEntries(t)
	for index := range entries {
		if entries[index].header.Name == lowerPrefix+"/keep.txt" {
			entries[index].data = "evil\n"
			entries[index].header.Size = 5
		}
	}
	archive, quarantine := writeRootFSFixture(t, entries...)
	if _, err := ParseFrozenRootFS(archive, quarantine, baseline, DefaultExportPolicy()); err == nil {
		t.Fatal("tampered lower was accepted")
	}
}

func fixtureBaseline(t *testing.T) SnapshotManifest {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "keep.txt"), "keep\n")
	writeFile(t, filepath.Join(root, "delete.txt"), "delete\n")
	writeFile(t, filepath.Join(root, "rename.txt"), "rename\n")
	manifest, err := BuildSnapshotManifest(root, DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func baselineTarEntries(t *testing.T) []tarFixtureEntry {
	t.Helper()
	return []tarFixtureEntry{
		{header: tar.Header{Name: lowerPrefix, Typeflag: tar.TypeDir, Mode: 0700}},
		{header: tar.Header{Name: lowerPrefix + "/delete.txt", Typeflag: tar.TypeReg, Mode: 0600, Size: 7}, data: "delete\n"},
		{header: tar.Header{Name: lowerPrefix + "/keep.txt", Typeflag: tar.TypeReg, Mode: 0600, Size: 5}, data: "keep\n"},
		{header: tar.Header{Name: lowerPrefix + "/rename.txt", Typeflag: tar.TypeReg, Mode: 0600, Size: 7}, data: "rename\n"},
	}
}

func writeRootFSFixture(t *testing.T, entries ...tarFixtureEntry) (string, string) {
	t.Helper()
	root := t.TempDir()
	quarantine := filepath.Join(root, "sunaba-quarantine")
	if err := os.Mkdir(quarantine, 0700); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(quarantine, "rootfs.tar")
	file, err := os.OpenFile(archive, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	for _, entry := range entries {
		header := entry.header
		if err := writer.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if entry.data != "" {
			if _, err := writer.Write([]byte(entry.data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return archive, quarantine
}
