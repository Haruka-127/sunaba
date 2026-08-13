package testutil

import (
	"os"
	"path/filepath"
)

type TB interface {
	Helper()
	Cleanup(func())
	Fatalf(string, ...any)
}

func PrivateTempDir(test TB, prefix string) string {
	test.Helper()
	base := os.TempDir()
	if info, err := os.Stat("/private/tmp"); err == nil && info.IsDir() {
		base = "/private/tmp"
	}
	canonical, err := filepath.EvalSymlinks(base)
	if err != nil {
		test.Fatalf("resolve temporary root: %v", err)
	}
	root, err := os.MkdirTemp(canonical, prefix)
	if err != nil {
		test.Fatalf("create private temporary directory: %v", err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		_ = os.RemoveAll(root)
		test.Fatalf("secure private temporary directory: %v", err)
	}
	test.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}
