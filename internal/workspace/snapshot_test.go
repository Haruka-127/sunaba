package workspace

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSnapshotIsDeterministicAndDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(t.TempDir(), "secret")
	writeFile(t, external, "first")
	writeFile(t, filepath.Join(root, "z.txt"), "z")
	writeFile(t, filepath.Join(root, "dir", "a.txt"), "a")
	if err := os.Symlink(external, filepath.Join(root, "outside")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, ".git", "config"), "credential=secret")

	first, err := BuildSnapshotManifest(root, DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, external, "second")
	second, err := BuildSnapshotManifest(root, DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest {
		t.Fatalf("external symlink target affected digest: %s != %s", first.Digest, second.Digest)
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if first.Root != canonicalRoot {
		t.Fatalf("root=%q, want %q", first.Root, canonicalRoot)
	}
	if got := entryPaths(first); !equalStrings(got, []string{"dir", "dir/a.txt", "outside", "z.txt"}) {
		t.Fatalf("entries=%v", got)
	}
	outside := findEntry(t, first, "outside")
	if outside.Type != TypeSymlink || outside.LinkTarget != external || outside.SHA256 != "" {
		t.Fatalf("outside entry=%+v", outside)
	}
}

func TestFinalizedManifestDoesNotAliasCallerEntries(t *testing.T) {
	entries := []SnapshotEntry{{Path: "file.txt", Type: TypeFile, Mode: 0600, Size: 4, SHA256: strings.Repeat("a", 64)}}
	manifest, err := finalizeSnapshotManifest("/snapshot", entries, 4)
	if err != nil {
		t.Fatal(err)
	}
	entries[0].Mode = 0777
	if manifest.Entries[0].Mode != 0600 || !manifestDigestIsCanonical(manifest) {
		t.Fatalf("finalized manifest retained caller alias: %+v", manifest.Entries[0])
	}
}

func TestSnapshotRejectsSpecialFiles(t *testing.T) {
	root := t.TempDir()
	if err := unix.Mkfifo(filepath.Join(root, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildSnapshotManifest(root, DefaultSnapshotPolicy()); err == nil {
		t.Fatal("FIFO was accepted")
	}
}

func TestSnapshotEnforcesLimits(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "large"), "12345")
	policy := DefaultSnapshotPolicy()
	policy.MaxFileSize = 4
	if _, err := BuildSnapshotManifest(root, policy); err == nil {
		t.Fatal("oversized file was accepted")
	}
	policy = DefaultSnapshotPolicy()
	policy.MaxEntries = 1
	writeFile(t, filepath.Join(root, "second"), "x")
	if _, err := BuildSnapshotManifest(root, policy); err == nil {
		t.Fatal("too many entries were accepted")
	}
}

func TestSnapshotProtectsGitAtEveryDepthAndHonorsExplicitExclusions(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "nested", ".git", "config"), "secret")
	writeFile(t, filepath.Join(root, "nested", "src", "main.go"), "package main")
	writeFile(t, filepath.Join(root, "CACHE", "deep", "data"), "large")
	writeFile(t, filepath.Join(root, "vendor", "root.txt"), "excluded")
	writeFile(t, filepath.Join(root, "nested", "vendor", "kept.txt"), "kept")
	writeFile(t, filepath.Join(root, "keep.txt"), "keep")
	policy := DefaultSnapshotPolicy()
	policy.ExcludedPaths = []string{"cache"}
	policy.ProtectedPaths = append(policy.ProtectedPaths, "vendor")
	manifest, err := BuildSnapshotManifest(root, policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range manifest.Entries {
		lower := strings.ToLower(entry.Path)
		if strings.Contains(lower, "/.git") || lower == "cache" || strings.HasPrefix(lower, "cache/") || lower == "vendor" || strings.HasPrefix(lower, "vendor/") {
			t.Fatalf("protected/excluded path leaked into manifest: %s", entry.Path)
		}
	}
	if findEntry(t, manifest, "nested/vendor/kept.txt").Type != TypeFile {
		t.Fatal("custom root protected path unexpectedly applied at every depth")
	}
}

func TestSnapshotPreviewReportsMetadataWithoutHashesOrContents(t *testing.T) {
	manifest := SnapshotManifest{Digest: strings.Repeat("a", 64), TotalSize: LargeSnapshotFileBytes + 7, Entries: []SnapshotEntry{
		{Path: ".env.production", Type: TypeFile, Size: 7, SHA256: strings.Repeat("b", 64)},
		{Path: "build/archive.bin", Type: TypeFile, Size: LargeSnapshotFileBytes, SHA256: strings.Repeat("c", 64)},
	}}
	preview := BuildSnapshotPreview(manifest)
	if preview.EntryCount != 2 || preview.FileCount != 2 || len(preview.LargeFiles) != 1 || len(preview.SensitivePaths) != 1 {
		t.Fatalf("unexpected preview: %+v", preview)
	}
	encoded, err := json.Marshal(preview)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(strings.Repeat("b", 64))) || bytes.Contains(encoded, []byte(strings.Repeat("c", 64))) {
		t.Fatalf("preview leaked file digest: %s", encoded)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func entryPaths(manifest SnapshotManifest) []string {
	paths := make([]string, len(manifest.Entries))
	for i, entry := range manifest.Entries {
		paths[i] = entry.Path
	}
	return paths
}

func findEntry(t *testing.T, manifest SnapshotManifest, path string) SnapshotEntry {
	t.Helper()
	for _, entry := range manifest.Entries {
		if entry.Path == path {
			return entry
		}
	}
	t.Fatalf("entry %q not found", path)
	return SnapshotEntry{}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
