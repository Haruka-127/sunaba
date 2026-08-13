package image

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sunabaassets "sunaba/assets"
	"sunaba/internal/dependency"
	"sunaba/internal/runtime"
)

func Tag(version string) string {
	return "sunaba-base:" + version + "-secure.1"
}

func EnsureManifest(ctx context.Context, rt runtime.Runtime, manifest dependency.Manifest) (string, error) {
	if err := dependency.ValidateRuntimeManifest(manifest); err != nil {
		return "", err
	}
	if rt == nil {
		return "", fmt.Errorf("container runtime is required")
	}
	exists, err := rt.ImageExists(ctx, manifest.AgentImage.Tag)
	if err != nil {
		return "", err
	}
	if !exists {
		if err := BuildManifest(ctx, rt, manifest); err != nil {
			return "", err
		}
	}
	return manifest.OpenCode.Version, nil
}

func Build(ctx context.Context, rt runtime.Runtime, version string) error {
	pinned := dependency.MustPinned()
	if version != pinned.OpenCode.Version {
		return fmt.Errorf("refusing to build unpinned OpenCode version %q; expected %s", version, pinned.OpenCode.Version)
	}
	return BuildManifest(ctx, rt, pinned)
}

func BuildManifest(ctx context.Context, rt runtime.Runtime, manifest dependency.Manifest) error {
	if err := dependency.ValidateRuntimeManifest(manifest); err != nil {
		return err
	}
	if rt == nil {
		return fmt.Errorf("container runtime is required")
	}
	buildInputs := make(map[string][]byte, 2)
	for _, name := range []string{"Containerfile", "entrypoint.sh"} {
		data, err := sunabaassets.FS.ReadFile(name)
		if err != nil {
			return err
		}
		buildInputs[name] = data
	}
	if err := verifyBuildInputProvenance(manifest, buildInputs); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "sunaba-image-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	for _, name := range []string{"Containerfile", "entrypoint.sh"} {
		b := buildInputs[name]
		mode := os.FileMode(0644)
		if strings.HasSuffix(name, ".sh") {
			mode = 0755
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, mode); err != nil {
			return err
		}
	}
	return rt.BuildImage(ctx, manifest.AgentImage.Tag, dir, map[string]string{
		"OPENCODE_VERSION": manifest.OpenCode.Version,
		"OPENCODE_SHA256":  manifest.OpenCode.Guest.SHA256,
	})
}

func verifyBuildInputProvenance(manifest dependency.Manifest, inputs map[string][]byte) error {
	if len(inputs) != 2 {
		return fmt.Errorf("Agent image build requires exactly two pinned inputs")
	}
	for name, data := range inputs {
		digest := sha256.Sum256(data)
		if manifest.Provenance.BuildInputs["assets/"+name] != hex.EncodeToString(digest[:]) {
			return fmt.Errorf("Agent image build input %q does not match dependency provenance", name)
		}
	}
	return nil
}
