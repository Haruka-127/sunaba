package image

import (
	"context"
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
	dir, err := os.MkdirTemp("", "sunaba-image-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	for _, name := range []string{"Containerfile", "entrypoint.sh"} {
		b, err := sunabaassets.FS.ReadFile(name)
		if err != nil {
			return err
		}
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
