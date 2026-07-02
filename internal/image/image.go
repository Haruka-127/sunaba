package image

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	sunabaassets "sunaba/assets"
	"sunaba/internal/runtime"
	"sunaba/internal/state"
)

const repoLatestURL = "https://api.github.com/repos/anomalyco/opencode/releases/latest"

func Tag(version string) string {
	return "sunaba-base:" + version
}

func LatestVersion(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, repoLatestURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub latest release request failed: %s; pass --opencode-version explicitly", resp.Status)
	}
	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	version := strings.TrimPrefix(payload.TagName, "v")
	if version == "" {
		return "", fmt.Errorf("latest release response did not include tag_name")
	}
	return version, nil
}

func Ensure(ctx context.Context, rt runtime.Runtime, st *state.Store, explicit string) (string, error) {
	cfg, err := st.LoadGlobal()
	if err != nil {
		return "", err
	}
	version := explicit
	if version == "" {
		version = cfg.ImageVersion
	}
	if version == "" {
		version, err = LatestVersion(ctx)
		if err != nil {
			return "", err
		}
	}
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
	return rt.BuildImage(ctx, Tag(version), dir, map[string]string{"OPENCODE_VERSION": version})
}
