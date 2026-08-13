package securefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteAndBoundedRead(t *testing.T) {
	root := privateTempDir(t)
	path := filepath.Join(root, "state.json")
	if err := AtomicWriteOwned(path, []byte("value")); err != nil {
		t.Fatal(err)
	}
	data, err := ReadOwnedRegular(path, 5)
	if err != nil || string(data) != "value" {
		t.Fatalf("data=%q error=%v", data, err)
	}
	if _, err := ReadOwnedRegular(path, 4); err == nil {
		t.Fatal("oversized private file was accepted")
	}
}

func TestReadOwnedRegularRejectsSymlink(t *testing.T) {
	root := privateTempDir(t)
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOwnedRegular(link, 64); err == nil {
		t.Fatal("private symlink was accepted")
	}
}

func TestAtomicWriteRejectsUnsafeExistingTarget(t *testing.T) {
	root := privateTempDir(t)
	path := filepath.Join(root, "state")
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteOwned(path, []byte("value")); err == nil {
		t.Fatal("unsafe existing target was replaced")
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	temporaryRoot, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(temporaryRoot, "sunaba-securefs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}
