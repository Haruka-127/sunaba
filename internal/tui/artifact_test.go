package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sunaba/internal/dependency"
)

func TestVerifyHelperRejectsUnpinnedAndUnsafeArtifacts(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "sunaba-ui")
	if err := os.WriteFile(path, []byte("not a Mach-O"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := VerifyHelperExecutable(path, ArtifactPin{OS: "darwin", Arch: "arm64", SHA256: strings.Repeat("0", 64)}); err == nil {
		t.Fatal("unmatched artifact digest accepted")
	}
	link := filepath.Join(root, "linked-ui")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := VerifyHelperExecutable(link, ArtifactPin{OS: "darwin", Arch: "arm64", SHA256: strings.Repeat("0", 64)}); err == nil {
		t.Fatal("symlink artifact accepted")
	}
}

func TestBuiltStandaloneArtifactMatchesActiveLock(t *testing.T) {
	path := os.Getenv("SUNABA_UI_ARTIFACT")
	if path == "" {
		t.Skip("set SUNABA_UI_ARTIFACT from the project-local standalone build")
	}
	manifest := dependency.MustPinned()
	if err := VerifyHelperExecutable(path, ArtifactPin{OS: manifest.SunabaUI.OS, Arch: manifest.SunabaUI.Arch, SHA256: manifest.SunabaUI.SHA256}); err != nil {
		t.Fatal(err)
	}
}
