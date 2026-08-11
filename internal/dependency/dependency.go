package dependency

import (
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const (
	AppleContainerVersion = "1.2.2"
	OpenCodeVersion       = "1.18.16"
)

//go:embed manifest.json
var manifestFS embed.FS

type Artifact struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Artifact string `json:"artifact"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
}

type Manifest struct {
	SchemaVersion  int `json:"schema_version"`
	AppleContainer struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
	} `json:"apple_container"`
	BaseImage struct {
		Reference   string `json:"reference"`
		IndexSHA256 string `json:"index_sha256"`
	} `json:"base_image"`
	AgentImage struct {
		Tag string `json:"tag"`
	} `json:"agent_image"`
	OpenCode struct {
		Version string   `json:"version"`
		Host    Artifact `json:"host"`
		Guest   Artifact `json:"guest"`
	} `json:"opencode"`
}

func Pinned() (Manifest, error) {
	data, err := manifestFS.ReadFile("manifest.json")
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode dependency manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func MustPinned() Manifest {
	manifest, err := Pinned()
	if err != nil {
		panic(err)
	}
	return manifest
}

func (m Manifest) Validate() error {
	if m.SchemaVersion != 1 {
		return fmt.Errorf("unsupported dependency manifest schema %d", m.SchemaVersion)
	}
	if m.AppleContainer.Version != AppleContainerVersion {
		return fmt.Errorf("apple/container version %q does not match compiled contract %q", m.AppleContainer.Version, AppleContainerVersion)
	}
	if m.OpenCode.Version != OpenCodeVersion {
		return fmt.Errorf("OpenCode version %q does not match compiled contract %q", m.OpenCode.Version, OpenCodeVersion)
	}
	if !strings.HasSuffix(m.BaseImage.Reference, "@sha256:"+m.BaseImage.IndexSHA256) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(m.BaseImage.IndexSHA256) {
		return fmt.Errorf("base image must be pinned by a valid index SHA-256")
	}
	if m.AgentImage.Tag != "sunaba-base:"+OpenCodeVersion+"-secure.1" {
		return fmt.Errorf("unexpected agent image tag %q", m.AgentImage.Tag)
	}
	if strings.Contains(strings.ToLower(m.OpenCode.Host.URL), "latest") || strings.Contains(strings.ToLower(m.OpenCode.Guest.URL), "latest") {
		return fmt.Errorf("dependency URLs must not use latest")
	}
	if err := validateArtifact(m.OpenCode.Host, "darwin", "arm64", m.OpenCode.Version); err != nil {
		return fmt.Errorf("host OpenCode artifact: %w", err)
	}
	if err := validateArtifact(m.OpenCode.Guest, "linux", "arm64", m.OpenCode.Version); err != nil {
		return fmt.Errorf("guest OpenCode artifact: %w", err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(m.AppleContainer.Commit) {
		return fmt.Errorf("invalid apple/container commit %q", m.AppleContainer.Commit)
	}
	return nil
}

func validateArtifact(a Artifact, wantOS, wantArch, version string) error {
	if a.OS != wantOS || a.Arch != wantArch {
		return fmt.Errorf("platform is %s/%s, want %s/%s", a.OS, a.Arch, wantOS, wantArch)
	}
	if a.Artifact == "" || a.URL == "" {
		return fmt.Errorf("artifact name and URL are required")
	}
	if !strings.Contains(a.URL, "/v"+version+"/") || !strings.HasSuffix(a.URL, "/"+a.Artifact) {
		return fmt.Errorf("URL %q is not bound to v%s artifact %q", a.URL, version, a.Artifact)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(a.SHA256) {
		return fmt.Errorf("invalid SHA-256 %q", a.SHA256)
	}
	return nil
}
