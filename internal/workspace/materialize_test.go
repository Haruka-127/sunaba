package workspace

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreateProjectSnapshotMaterializesFixedCopy(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(t.TempDir(), "external")
	writeFile(t, external, "outside")
	writeFile(t, filepath.Join(root, "dir", "source.txt"), "approved")
	writeFile(t, filepath.Join(root, ".git", "config"), "secret")
	if err := os.Symlink(external, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "snapshot")
	manifest, err := CreateProjectSnapshot(root, destination, DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "dir", "source.txt"), "changed")
	content, err := os.ReadFile(filepath.Join(destination, "dir", "source.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "approved" {
		t.Fatalf("snapshot content=%q", content)
	}
	if _, err := os.Lstat(filepath.Join(destination, ".git")); !os.IsNotExist(err) {
		t.Fatalf("Protected Path copied: %v", err)
	}
	target, err := os.Readlink(filepath.Join(destination, "link"))
	if err != nil {
		t.Fatal(err)
	}
	if target != external {
		t.Fatalf("symlink target=%q", target)
	}
	verifyPolicy := DefaultSnapshotPolicy()
	verifyPolicy.ProtectedPaths = nil
	verified, err := BuildSnapshotManifest(destination, verifyPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Digest != manifest.Digest {
		t.Fatalf("snapshot digest=%s, want %s", verified.Digest, manifest.Digest)
	}
}

func TestCreateProjectSnapshotRejectsDestinationInsideProject(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "source"), "data")
	destination := filepath.Join(root, "snapshot")
	if _, err := CreateProjectSnapshot(root, destination, DefaultSnapshotPolicy()); err == nil {
		t.Fatal("snapshot inside Project root was accepted")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("unsafe destination was created: %v", err)
	}
}

func TestCreateProjectSnapshotRequiresUnusedDestination(t *testing.T) {
	root := t.TempDir()
	destination := t.TempDir()
	if _, err := CreateProjectSnapshot(root, destination, DefaultSnapshotPolicy()); err == nil {
		t.Fatal("existing snapshot destination was accepted")
	}
}
