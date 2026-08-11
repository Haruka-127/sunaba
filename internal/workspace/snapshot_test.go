package workspace

import (
	"os"
	"path/filepath"
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
