package dependency

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

const (
	AppleContainerVersion = "1.2.2"
	AppleContainerCommit  = "0190097d06df0b9065f4c2d2c7873c649d81d493"
	OpenCodeVersion       = "1.18.16"
	OpenCodeCommit        = "a3647eb025c7615159d417dcc49fc39fdaeba65b"
	UrfaveCLIVersion      = "v3.10.1"
)

//go:embed manifest.json
var manifestFS embed.FS

type Artifact struct {
	OS               string `json:"os"`
	Arch             string `json:"arch"`
	Artifact         string `json:"artifact"`
	URL              string `json:"url"`
	SHA256           string `json:"sha256"`
	ExecutableSHA256 string `json:"executable_sha256,omitempty"`
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
	GoModules map[string]string `json:"go_modules"`
	OpenCode  struct {
		Version string   `json:"version"`
		Host    Artifact `json:"host"`
		Guest   Artifact `json:"guest"`
	} `json:"opencode"`
	Provenance Provenance `json:"provenance"`
}

type SourcePin struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Commit     string `json:"commit"`
}

type BaseImagePin struct {
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
}

type Provenance struct {
	AppleContainer SourcePin         `json:"apple_container"`
	OpenCode       SourcePin         `json:"opencode"`
	BaseImage      BaseImagePin      `json:"base_image"`
	BuildInputs    map[string]string `json:"build_inputs"`
}

type UpdateEvidence struct {
	ArtifactDigests  bool
	RuntimeVersion   bool
	Lifecycle        bool
	NetworkIsolation bool
	CopyExport       bool
	ResourceLimits   bool
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

func ManifestSHA256() (string, error) {
	data, err := manifestFS.ReadFile("manifest.json")
	if err != nil {
		return "", err
	}
	if _, err := Pinned(); err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func (m Manifest) Validate() error {
	if err := ValidateRuntimeManifest(m); err != nil {
		return err
	}
	if m.OpenCode.Version != OpenCodeVersion {
		return fmt.Errorf("OpenCode version %q does not match compiled bootstrap contract %q", m.OpenCode.Version, OpenCodeVersion)
	}
	if m.Provenance.OpenCode.Commit != OpenCodeCommit {
		return fmt.Errorf("OpenCode source commit does not match compiled bootstrap contract")
	}
	return nil
}

// ValidateRuntimeManifest validates an exact, host-resolved dependency lock.
// Unlike Manifest.Validate it does not require the embedded bootstrap OpenCode
// release, but it always restricts the runtime to an exact v1 release.
func ValidateRuntimeManifest(m Manifest) error {
	if m.SchemaVersion != 2 {
		return fmt.Errorf("unsupported dependency manifest schema %d", m.SchemaVersion)
	}
	if m.AppleContainer.Version != AppleContainerVersion {
		return fmt.Errorf("apple/container version %q does not match compiled contract %q", m.AppleContainer.Version, AppleContainerVersion)
	}
	if !regexp.MustCompile(`^1\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`).MatchString(m.OpenCode.Version) {
		return fmt.Errorf("OpenCode version %q must be an exact v1 semantic version", m.OpenCode.Version)
	}
	if !strings.HasSuffix(m.BaseImage.Reference, "@sha256:"+m.BaseImage.IndexSHA256) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(m.BaseImage.IndexSHA256) {
		return fmt.Errorf("base image must be pinned by a valid index SHA-256")
	}
	if m.AgentImage.Tag != "sunaba-base:"+m.OpenCode.Version+"-secure.1" {
		return fmt.Errorf("unexpected agent image tag %q", m.AgentImage.Tag)
	}
	if m.GoModules["golang.org/x/sys"] != "v0.30.0" {
		return fmt.Errorf("golang.org/x/sys must be pinned to v0.30.0")
	}
	if m.GoModules["github.com/urfave/cli/v3"] != UrfaveCLIVersion {
		return fmt.Errorf("github.com/urfave/cli/v3 must be pinned to %s", UrfaveCLIVersion)
	}
	if strings.Contains(strings.ToLower(m.OpenCode.Host.URL), "latest") || strings.Contains(strings.ToLower(m.OpenCode.Guest.URL), "latest") {
		return fmt.Errorf("dependency URLs must not use latest")
	}
	if err := validateArtifact(m.OpenCode.Host, "darwin", "arm64", m.OpenCode.Version); err != nil {
		return fmt.Errorf("host OpenCode artifact: %w", err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(m.OpenCode.Host.ExecutableSHA256) {
		return fmt.Errorf("host OpenCode executable SHA-256 is required")
	}
	if err := validateArtifact(m.OpenCode.Guest, "linux", "arm64", m.OpenCode.Version); err != nil {
		return fmt.Errorf("guest OpenCode artifact: %w", err)
	}
	if m.AppleContainer.Commit != AppleContainerCommit {
		return fmt.Errorf("apple/container commit %q does not match compiled contract", m.AppleContainer.Commit)
	}
	if err := validateProvenance(m); err != nil {
		return err
	}
	return nil
}

// ManifestDigest returns the deterministic SHA-256 of the JSON manifest.
func ManifestDigest(manifest Manifest) (string, error) {
	if err := ValidateRuntimeManifest(manifest); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func ValidateUpdateCandidate(current, candidate Manifest, evidence UpdateEvidence) error {
	if err := current.Validate(); err != nil {
		return fmt.Errorf("current dependency contract is invalid: %w", err)
	}
	if candidate.SchemaVersion != 2 || candidate.OpenCode.Version == "" || candidate.AppleContainer.Version == "" || candidate.OpenCode.Version == current.OpenCode.Version && candidate.AppleContainer.Version == current.AppleContainer.Version {
		return fmt.Errorf("dependency update candidate must change an exact version")
	}
	if strings.Contains(strings.ToLower(candidate.OpenCode.Version+candidate.AppleContainer.Version+candidate.AgentImage.Tag), "latest") {
		return fmt.Errorf("dependency update candidate must not use latest")
	}
	if err := validateCandidateSyntax(candidate); err != nil {
		return err
	}
	if !evidence.ArtifactDigests || !evidence.RuntimeVersion || !evidence.Lifecycle || !evidence.NetworkIsolation || !evidence.CopyExport || !evidence.ResourceLimits {
		return fmt.Errorf("dependency update candidate lacks required integration evidence")
	}
	return nil
}

// ValidateOpenCodeUpdateCandidate permits a host-resolved OpenCode-only v1
// update while requiring every platform and build input pin to remain exactly
// the same as the active manifest.
func ValidateOpenCodeUpdateCandidate(current, candidate Manifest) error {
	if err := ValidateRuntimeManifest(current); err != nil {
		return fmt.Errorf("current dependency contract is invalid: %w", err)
	}
	if err := ValidateRuntimeManifest(candidate); err != nil {
		return fmt.Errorf("OpenCode update candidate is invalid: %w", err)
	}
	if candidate.OpenCode.Version == current.OpenCode.Version {
		return fmt.Errorf("OpenCode %s is already the active exact version", current.OpenCode.Version)
	}
	if candidate.AppleContainer != current.AppleContainer || candidate.BaseImage != current.BaseImage ||
		!reflect.DeepEqual(candidate.GoModules, current.GoModules) ||
		candidate.Provenance.AppleContainer != current.Provenance.AppleContainer ||
		candidate.Provenance.BaseImage != current.Provenance.BaseImage ||
		!reflect.DeepEqual(candidate.Provenance.BuildInputs, current.Provenance.BuildInputs) {
		return fmt.Errorf("runtime OpenCode update must not change Apple Container, base image, Go modules, or Agent image build inputs")
	}
	return nil
}

func validateCandidateSyntax(m Manifest) error {
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(m.OpenCode.Version) || !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(m.AppleContainer.Version) {
		return fmt.Errorf("candidate versions must be exact semantic versions")
	}
	if !strings.HasSuffix(m.BaseImage.Reference, "@sha256:"+m.BaseImage.IndexSHA256) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(m.BaseImage.IndexSHA256) {
		return fmt.Errorf("candidate base image is not digest pinned")
	}
	if m.AgentImage.Tag != "sunaba-base:"+m.OpenCode.Version+"-secure.1" {
		return fmt.Errorf("candidate Agent image tag is not version bound")
	}
	if err := validateArtifact(m.OpenCode.Host, "darwin", "arm64", m.OpenCode.Version); err != nil {
		return err
	}
	if err := validateArtifact(m.OpenCode.Guest, "linux", "arm64", m.OpenCode.Version); err != nil {
		return err
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(m.OpenCode.Host.ExecutableSHA256) || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(m.AppleContainer.Commit) {
		return fmt.Errorf("candidate executable or source commit is not pinned")
	}
	return validateProvenance(m)
}

func validateProvenance(m Manifest) error {
	wantSources := []struct {
		pin        SourcePin
		repository string
		tag        string
		commit     string
	}{
		{m.Provenance.AppleContainer, "https://github.com/apple/container", m.AppleContainer.Version, m.AppleContainer.Commit},
		{m.Provenance.OpenCode, "https://github.com/anomalyco/opencode", "v" + m.OpenCode.Version, m.Provenance.OpenCode.Commit},
	}
	for _, source := range wantSources {
		if source.pin.Repository != source.repository || source.pin.Tag != source.tag || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(source.pin.Commit) || source.pin.Commit != source.commit {
			return fmt.Errorf("dependency source provenance is not repository/tag/commit bound")
		}
	}
	if m.Provenance.BaseImage.Registry != "docker.io" || m.Provenance.BaseImage.Repository != "library/debian" || m.Provenance.BaseImage.Digest != "sha256:"+m.BaseImage.IndexSHA256 {
		return fmt.Errorf("base image provenance does not match its OCI digest")
	}
	for _, input := range []string{"assets/Containerfile", "assets/entrypoint.sh"} {
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(m.Provenance.BuildInputs[input]) {
			return fmt.Errorf("build input %q is not digest pinned", input)
		}
	}
	if len(m.Provenance.BuildInputs) != 2 {
		return fmt.Errorf("unexpected build input provenance entries")
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
	wantURL := "https://github.com/anomalyco/opencode/releases/download/v" + version + "/" + a.Artifact
	if a.URL != wantURL {
		return fmt.Errorf("URL %q is not bound to v%s artifact %q", a.URL, version, a.Artifact)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(a.SHA256) {
		return fmt.Errorf("invalid SHA-256 %q", a.SHA256)
	}
	if a.ExecutableSHA256 != "" && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(a.ExecutableSHA256) {
		return fmt.Errorf("invalid executable SHA-256 %q", a.ExecutableSHA256)
	}
	return nil
}
