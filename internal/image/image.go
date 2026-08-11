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
	"sunaba/internal/state"
)

func Tag(version string) string {
	pinned := dependency.MustPinned()
	if version == pinned.OpenCode.Version {
		return pinned.AgentImage.Tag
	}
	return "sunaba-base:" + version
}

func Ensure(ctx context.Context, rt runtime.Runtime, st *state.Store, explicit string) (string, error) {
	pinned := dependency.MustPinned()
	cfg, err := st.LoadGlobal()
	if err != nil {
		return "", err
	}
	if explicit != "" && explicit != pinned.OpenCode.Version {
		return "", fmt.Errorf("OpenCode version %q is not permitted; dependency contract pins %s", explicit, pinned.OpenCode.Version)
	}
	if cfg.ImageVersion != "" && cfg.ImageVersion != pinned.OpenCode.Version {
		return "", fmt.Errorf("configured OpenCode version %q differs from pinned dependency %s; recreate the image", cfg.ImageVersion, pinned.OpenCode.Version)
	}
	version := pinned.OpenCode.Version
	exists, err := rt.ImageExists(ctx, Tag(version))
	if err != nil {
		return "", err
	}
	if !exists {
		if err := Build(ctx, rt, version); err != nil {
			return "", err
		}
	}
	if cfg.ImageVersion != version {
		cfg.ImageVersion = version
		if err := st.SaveGlobal(cfg); err != nil {
			return "", err
		}
	}
	return version, nil
}

func Build(ctx context.Context, rt runtime.Runtime, version string) error {
	pinned := dependency.MustPinned()
	if version != pinned.OpenCode.Version {
		return fmt.Errorf("refusing to build unpinned OpenCode version %q; expected %s", version, pinned.OpenCode.Version)
	}
	buildInputs := make(map[string][]byte, 2)
	for _, name := range []string{"Containerfile", "entrypoint.sh"} {
		data, err := sunabaassets.FS.ReadFile(name)
		if err != nil {
			return err
		}
		buildInputs[name] = data
	}
	if err := verifyBuildInputProvenance(pinned, buildInputs); err != nil {
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
	return rt.BuildImage(ctx, Tag(version), dir, map[string]string{
		"OPENCODE_VERSION": version,
		"OPENCODE_SHA256":  pinned.OpenCode.Guest.SHA256,
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
