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

func TestCreateApprovedSnapshotSubsetCopiesOnlyAffectedRoots(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "dir", "changed.txt"), "changed")
	writeFile(t, filepath.Join(root, "dir", "unaffected.txt"), "unaffected")
	writeFile(t, filepath.Join(root, "other", "unaffected.txt"), "unaffected")
	approved, err := BuildSnapshotManifest(root, DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "subset")
	staged, err := CreateApprovedSnapshotSubset(root, destination, approved, []string{"dir/changed.txt"}, DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if len(staged.Entries) != 2 || staged.Entries[0].Path != "dir" || staged.Entries[1].Path != "dir/changed.txt" {
		t.Fatalf("staged entries=%+v", staged.Entries)
	}
	for _, omitted := range []string{"dir/unaffected.txt", "other"} {
		if _, err := os.Lstat(filepath.Join(destination, omitted)); !os.IsNotExist(err) {
			t.Fatalf("unaffected path %q was staged: %v", omitted, err)
		}
	}
}

func TestCreateApprovedSnapshotSubsetRejectsChangedSource(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "changed.txt")
	writeFile(t, path, "approved")
	approved, err := BuildSnapshotManifest(root, DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, "tampered")
	destination := filepath.Join(t.TempDir(), "subset")
	if _, err := CreateApprovedSnapshotSubset(root, destination, approved, []string{"changed.txt"}, DefaultSnapshotPolicy()); err == nil {
		t.Fatal("changed approved source was staged")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("failed subset retained destination: %v", err)
	}
}
