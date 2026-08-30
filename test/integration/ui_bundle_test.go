//go:build integration

package integration

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func copyBundledSunabaUI(t *testing.T, destinationDirectory string) {
	t.Helper()
	source, err := filepath.Abs(filepath.Join("..", "..", "bin", "sunaba-ui"))
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(source)
	if err != nil {
		t.Fatalf("open bundled sunaba-ui; run ./scripts/build-ui.sh before live integration: %v", err)
	}
	defer input.Close()
	destination := filepath.Join(destinationDirectory, "sunaba-ui")
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(destination, 0700); err != nil {
		t.Fatal(err)
	}
}
