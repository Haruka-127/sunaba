package image

import (
	"context"
	"strings"
	"testing"

	sunabaassets "sunaba/assets"
	"sunaba/internal/dependency"
)

func TestBuildRejectsUnpinnedVersion(t *testing.T) {
	if err := Build(context.Background(), nil, "2.0.0"); err == nil {
		t.Fatal("untrusted OpenCode version was accepted")
	}
}

func TestContainerfileVerifiesGuestArtifactDigest(t *testing.T) {
	data, err := sunabaassets.FS.ReadFile("Containerfile")
	if err != nil {
		t.Fatal(err)
	}
	containerfile := string(data)
	for _, required := range []string{"ARG OPENCODE_SHA256", "sha256sum -c -", "v${OPENCODE_VERSION}/opencode-linux-arm64.tar.gz"} {
		if !strings.Contains(containerfile, required) {
			t.Fatalf("Containerfile does not contain %q", required)
		}
	}
	if dependency.MustPinned().OpenCode.Guest.SHA256 == "" {
		t.Fatal("guest digest is empty")
	}
}
