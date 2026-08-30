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
	"sync"
)

const (
	AppleContainerVersion    = "1.2.2"
	AppleContainerCommit     = "0190097d06df0b9065f4c2d2c7873c649d81d493"
	OpenCodeVersion          = "1.18.18"
	OpenCodeCommit           = "31406ccc51b4bd2a4e1e086b2bcaa5f7f804f26d"
	BunVersion               = "1.3.14"
	BunArchiveSHA256         = "d8b96221828ad6f97ac7ac0ab7e95872341af763001e8803e8267652c2652620"
	BunExecutableSHA256      = "e0c90ec15d33363e6b70713d56bc3b2c7585c17f40a0fe0f8fd9305901d4e233"
	OpenTUIVersion           = "0.5.9"
	OpenTUISHA256            = "d9c9b952ff39a79ed52a7f2cb364977d9859b55cdc346bdbfa55b3d4bff77940"
	OpenTUIIntegrity         = "sha512-d0EWYyp6djitu1N1R0o75NrLl4TxY3oJEmRNrX9vSKKC5/jriGQdSV6lJmwiB77O0cxtBnPzWztAV79vA1J2fA=="
	SunabaUIVersion          = "2"
	SunabaUISHA256           = "2a1670a64c2883458128fb85e9d9d26e77b16f29417205630c49c0ead8adc8a2"
	PreviousSunabaUIV2SHA256 = "e1e1e266d2e079d20cd10d1787ab2b869109bcc6ca2dcae639acf977cc8d7176"
	LegacySunabaUIVersion    = "1"
	LegacySunabaUISHA256     = "27ee3bc850a2bb9d822d9b9c3af977aec148c40e1250acf9199736b2eb8521c6"
	UrfaveCLIVersion         = "v3.10.1"
)

//go:embed manifest.json
var manifestFS embed.FS

var (
	v1VersionPattern      = regexp.MustCompile(`^1\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	exactVersionPattern   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	sha256Pattern         = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitPattern         = regexp.MustCompile(`^[0-9a-f]{40}$`)
	embeddedManifestValue = sync.OnceValues(loadEmbeddedManifest)
)

type Artifact struct {
	OS               string `json:"os"`
	Arch             string `json:"arch"`
	Artifact         string `json:"artifact"`
	URL              string `json:"url"`
	SHA256           string `json:"sha256"`
	ExecutableSHA256 string `json:"executable_sha256,omitempty"`
}

type BuildTool struct {
	Version string   `json:"version"`
	Host    Artifact `json:"host"`
}

type NPMDependency struct {
	Package   string `json:"package"`
	Version   string `json:"version"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Integrity string `json:"integrity"`
}

type StandaloneArtifact struct {
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	SHA256  string `json:"sha256"`
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
	Bun        BuildTool          `json:"bun"`
	OpenTUI    NPMDependency      `json:"opentui"`
	SunabaUI   StandaloneArtifact `json:"sunaba_ui"`
	Provenance Provenance         `json:"provenance"`
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
	value, err := embeddedManifestValue()
	return cloneManifest(value.manifest), err
}

type embeddedManifest struct {
	manifest Manifest
	digest   string
}

func loadEmbeddedManifest() (embeddedManifest, error) {
	data, err := manifestFS.ReadFile("manifest.json")
	if err != nil {
		return embeddedManifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return embeddedManifest{}, fmt.Errorf("decode dependency manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return embeddedManifest{}, err
	}
	digest := sha256.Sum256(data)
	return embeddedManifest{manifest: manifest, digest: hex.EncodeToString(digest[:])}, nil
}

func MustPinned() Manifest {
	manifest, err := Pinned()
	if err != nil {
		panic(err)
	}
	return manifest
}

func ManifestSHA256() (string, error) {
	value, err := embeddedManifestValue()
	return value.digest, err
}

func cloneManifest(manifest Manifest) Manifest {
	manifest.GoModules = cloneStringMap(manifest.GoModules)
	manifest.Provenance.BuildInputs = cloneStringMap(manifest.Provenance.BuildInputs)
	return manifest
}

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
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
	if err := ValidateCompiledUIContract(m); err != nil {
		return err
	}
	return nil
}

// ValidateCompiledUIContract keeps dynamic OpenCode locks bound to the exact
// UI build toolchain and standalone helper compiled into this sunaba release.
func ValidateCompiledUIContract(m Manifest) error {
	wantBun := BuildTool{Version: BunVersion, Host: Artifact{
		OS: "darwin", Arch: "arm64", Artifact: "bun-darwin-aarch64.zip",
		URL:    "https://github.com/oven-sh/bun/releases/download/bun-v" + BunVersion + "/bun-darwin-aarch64.zip",
		SHA256: BunArchiveSHA256, ExecutableSHA256: BunExecutableSHA256,
	}}
	wantOpenTUI := NPMDependency{
		Package: "@opentui/core", Version: OpenTUIVersion,
		URL:    "https://registry.npmjs.org/@opentui/core/-/core-" + OpenTUIVersion + ".tgz",
		SHA256: OpenTUISHA256, Integrity: OpenTUIIntegrity,
	}
	wantSunabaUI := StandaloneArtifact{Version: SunabaUIVersion, OS: "darwin", Arch: "arm64", SHA256: SunabaUISHA256}
	if m.Bun != wantBun || m.OpenTUI != wantOpenTUI || m.SunabaUI != wantSunabaUI {
		return fmt.Errorf("sunaba-ui build dependency does not match compiled bootstrap contract")
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
	if !v1VersionPattern.MatchString(m.OpenCode.Version) {
		return fmt.Errorf("OpenCode version %q must be an exact v1 semantic version", m.OpenCode.Version)
	}
	if !strings.HasSuffix(m.BaseImage.Reference, "@sha256:"+m.BaseImage.IndexSHA256) || !sha256Pattern.MatchString(m.BaseImage.IndexSHA256) {
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
	if err := validateUIArtifacts(m); err != nil {
		return err
	}
	if strings.Contains(strings.ToLower(m.OpenCode.Host.URL), "latest") || strings.Contains(strings.ToLower(m.OpenCode.Guest.URL), "latest") {
		return fmt.Errorf("dependency URLs must not use latest")
	}
	if err := validateArtifact(m.OpenCode.Host, "darwin", "arm64", m.OpenCode.Version); err != nil {
		return fmt.Errorf("host OpenCode artifact: %w", err)
	}
	if !sha256Pattern.MatchString(m.OpenCode.Host.ExecutableSHA256) {
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
	if candidate.Bun != current.Bun || candidate.OpenTUI != current.OpenTUI || candidate.SunabaUI != current.SunabaUI {
		return fmt.Errorf("dependency update candidate must not change the sunaba-ui toolchain without its dedicated release gate")
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
		candidate.Bun != current.Bun || candidate.OpenTUI != current.OpenTUI || candidate.SunabaUI != current.SunabaUI ||
		!reflect.DeepEqual(candidate.GoModules, current.GoModules) ||
		candidate.Provenance.AppleContainer != current.Provenance.AppleContainer ||
		candidate.Provenance.BaseImage != current.Provenance.BaseImage ||
		!reflect.DeepEqual(candidate.Provenance.BuildInputs, current.Provenance.BuildInputs) {
		return fmt.Errorf("runtime OpenCode update must not change Apple Container, base image, Go modules, or Agent image build inputs")
	}
	return nil
}

func validateUIArtifacts(m Manifest) error {
	if !exactVersionPattern.MatchString(m.Bun.Version) || m.Bun.Host.OS != "darwin" || m.Bun.Host.Arch != "arm64" || m.Bun.Host.Artifact != "bun-darwin-aarch64.zip" {
		return fmt.Errorf("Bun build tool must be an exact darwin/arm64 archive")
	}
	wantBunURL := "https://github.com/oven-sh/bun/releases/download/bun-v" + m.Bun.Version + "/" + m.Bun.Host.Artifact
	if m.Bun.Host.URL != wantBunURL || !sha256Pattern.MatchString(m.Bun.Host.SHA256) || !sha256Pattern.MatchString(m.Bun.Host.ExecutableSHA256) {
		return fmt.Errorf("Bun build tool is not version and digest pinned")
	}
	if m.OpenTUI.Package != "@opentui/core" || !exactVersionPattern.MatchString(m.OpenTUI.Version) || m.OpenTUI.URL != "https://registry.npmjs.org/@opentui/core/-/core-"+m.OpenTUI.Version+".tgz" || !sha256Pattern.MatchString(m.OpenTUI.SHA256) || !strings.HasPrefix(m.OpenTUI.Integrity, "sha512-") {
		return fmt.Errorf("OpenTUI package is not version and digest pinned")
	}
	if m.SunabaUI.Version != SunabaUIVersion || m.SunabaUI.OS != "darwin" || m.SunabaUI.Arch != "arm64" || !sha256Pattern.MatchString(m.SunabaUI.SHA256) {
		return fmt.Errorf("sunaba-ui standalone artifact is not platform and digest pinned")
	}
	return nil
}

// LegacySunabaUIV1Manifest returns the only full pre-protocol-v2 bootstrap
// manifest eligible for the explicit setup migration. Callers must compare
// the complete manifest; matching the old helper digest alone is insufficient.
func LegacySunabaUIV1Manifest(pinned Manifest) Manifest {
	pinned.SunabaUI.Version = LegacySunabaUIVersion
	pinned.SunabaUI.SHA256 = LegacySunabaUISHA256
	return pinned
}

// PreviousSunabaUIV2Manifest returns the only protocol-v2 bootstrap manifest
// built before response transport completion was awaited. Exact full-manifest
// comparison is required before setup may migrate its lock and Project policy.
func PreviousSunabaUIV2Manifest(pinned Manifest) Manifest {
	pinned.SunabaUI.SHA256 = PreviousSunabaUIV2SHA256
	return pinned
}

func validateCandidateSyntax(m Manifest) error {
	if !exactVersionPattern.MatchString(m.OpenCode.Version) || !exactVersionPattern.MatchString(m.AppleContainer.Version) {
		return fmt.Errorf("candidate versions must be exact semantic versions")
	}
	if !strings.HasSuffix(m.BaseImage.Reference, "@sha256:"+m.BaseImage.IndexSHA256) || !sha256Pattern.MatchString(m.BaseImage.IndexSHA256) {
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
	if !sha256Pattern.MatchString(m.OpenCode.Host.ExecutableSHA256) || !commitPattern.MatchString(m.AppleContainer.Commit) {
		return fmt.Errorf("candidate executable or source commit is not pinned")
	}
	if err := validateUIArtifacts(m); err != nil {
		return err
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
		if source.pin.Repository != source.repository || source.pin.Tag != source.tag || !commitPattern.MatchString(source.pin.Commit) || source.pin.Commit != source.commit {
			return fmt.Errorf("dependency source provenance is not repository/tag/commit bound")
		}
	}
	if m.Provenance.BaseImage.Registry != "docker.io" || m.Provenance.BaseImage.Repository != "library/debian" || m.Provenance.BaseImage.Digest != "sha256:"+m.BaseImage.IndexSHA256 {
		return fmt.Errorf("base image provenance does not match its OCI digest")
	}
	for _, input := range []string{"assets/Containerfile", "assets/entrypoint.sh"} {
		if !sha256Pattern.MatchString(m.Provenance.BuildInputs[input]) {
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
	if !sha256Pattern.MatchString(a.SHA256) {
		return fmt.Errorf("invalid SHA-256 %q", a.SHA256)
	}
	if a.ExecutableSHA256 != "" && !sha256Pattern.MatchString(a.ExecutableSHA256) {
		return fmt.Errorf("invalid executable SHA-256 %q", a.ExecutableSHA256)
	}
	return nil
}
