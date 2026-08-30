package opencode

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"sunaba/internal/dependency"
)

func TestPrerequisitesRequireAppleContainerButNotGlobalOpenCode(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("platform prerequisite contract is darwin/arm64 only")
	}
	bin := t.TempDir()
	writeExecutable(t, filepath.Join(bin, "sw_vers"), "#!/bin/sh\nprintf '26.0.0\\n'\n")
	writeExecutable(t, filepath.Join(bin, "container"), "#!/bin/sh\nif test \"$1 $2\" = 'system status'; then printf 'running\\n'; else printf 'container 1.2.2\\n'; fi\n")
	t.Setenv("PATH", bin)
	if err := CheckPrerequisitesFor(context.Background(), dependency.MustPinned()); err != nil {
		t.Fatalf("managed-host prerequisites unexpectedly required global OpenCode: %v", err)
	}
	if err := os.Remove(filepath.Join(bin, "container")); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrerequisitesFor(context.Background(), dependency.MustPinned()); err == nil {
		t.Fatal("missing Apple Container CLI was accepted")
	}
}

func writeExecutable(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0700); err != nil {
		t.Fatal(err)
	}
}
