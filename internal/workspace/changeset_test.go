package workspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildChangeSetIsDeterministicAndInfersUniqueRename(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "delete.txt"), "delete\n")
	writeFile(t, filepath.Join(root, "modify.txt"), "before\n")
	writeFile(t, filepath.Join(root, "rename.txt"), "rename\n")
	baseline, err := BuildSnapshotManifest(root, DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "delete.txt")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "modify.txt"), "after\n")
	if err := os.Rename(filepath.Join(root, "rename.txt"), filepath.Join(root, "renamed.txt")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "add.txt"), "add\n")
	merged, err := BuildSnapshotManifest(root, DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	first, err := BuildChangeSet(baseline, merged, DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildChangeSet(baseline, merged, DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest || len(first.Changes) != 4 {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	want := map[string]ChangeKind{
		"add.txt": ChangeAdd, "delete.txt": ChangeDelete,
		"modify.txt": ChangeModify, "renamed.txt": ChangeRename,
	}
	for _, change := range first.Changes {
		if want[change.Path] != change.Kind {
			t.Fatalf("change=%+v", change)
		}
		if change.Kind == ChangeRename && change.From != "rename.txt" {
			t.Fatalf("rename=%+v", change)
		}
	}
}

func TestBuildChangeSetDoesNotGuessAmbiguousRename(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "one.txt"), "same\n")
	writeFile(t, filepath.Join(root, "two.txt"), "same\n")
	baseline, err := BuildSnapshotManifest(root, DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "one.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "two.txt")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "three.txt"), "same\n")
	writeFile(t, filepath.Join(root, "four.txt"), "same\n")
	merged, err := BuildSnapshotManifest(root, DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	changes, err := BuildChangeSet(baseline, merged, DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range changes.Changes {
		if change.Kind == ChangeRename {
			t.Fatalf("ambiguous rename was inferred: %+v", change)
		}
	}
}

func TestBuildChangeSetRejectsProtectedManifest(t *testing.T) {
	baseline := fixtureBaseline(t)
	entries := append([]SnapshotEntry(nil), baseline.Entries...)
	entries = append(entries, SnapshotEntry{Path: ".git", Type: TypeDirectory, Mode: 0700})
	malicious, err := finalizeSnapshotManifest(baseline.Root, entries, baseline.TotalSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildChangeSet(baseline, malicious, DefaultSnapshotPolicy()); err == nil {
		t.Fatal("Protected Path manifest was accepted")
	}
}

func TestCanonicalManifestRejectsNestedGitAndExcludedPaths(t *testing.T) {
	policy := DefaultSnapshotPolicy()
	policy.ExcludedPaths = []string{"cache"}
	for _, entryPath := range []string{"nested/.git/config", "cache/result.bin"} {
		entry := SnapshotEntry{Path: entryPath, Type: TypeFile, Mode: 0600, Size: 1, SHA256: strings.Repeat("a", 64)}
		manifest, err := finalizeSnapshotManifest("/snapshot", []SnapshotEntry{entry}, 1)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateCanonicalManifest(manifest, policy); err == nil {
			t.Fatalf("unsafe manifest path accepted: %s", entryPath)
		}
	}
}
