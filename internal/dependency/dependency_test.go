package dependency

import (
	"strconv"
	"strings"
	"testing"
)

func TestPinnedManifest(t *testing.T) {
	m, err := Pinned()
	if err != nil {
		t.Fatal(err)
	}
	if m.AppleContainer.Version != AppleContainerVersion {
		t.Fatalf("apple/container=%q", m.AppleContainer.Version)
	}
	if m.OpenCode.Version != OpenCodeVersion {
		t.Fatalf("OpenCode=%q", m.OpenCode.Version)
	}
	if m.OpenCode.Host.SHA256 == m.OpenCode.Guest.SHA256 {
		t.Fatal("host and guest artifacts unexpectedly have the same digest")
	}
	if m.OpenCode.Host.ExecutableSHA256 == "" {
		t.Fatal("host executable digest is not pinned")
	}
	if m.BaseImage.Reference == "" || m.AgentImage.Tag == "" {
		t.Fatal("image contract is incomplete")
	}
	if m.GoModules["github.com/urfave/cli/v3"] != UrfaveCLIVersion {
		t.Fatalf("urfave/cli=%q", m.GoModules["github.com/urfave/cli/v3"])
	}
	if m.Bun.Version != BunVersion || m.OpenTUI.Version != OpenTUIVersion || m.SunabaUI.SHA256 == "" {
		t.Fatalf("sunaba-ui dependency contract is incomplete: Bun=%q OpenTUI=%q artifact=%q", m.Bun.Version, m.OpenTUI.Version, m.SunabaUI.SHA256)
	}
}

func TestManifestRejectsUnpinnedUIBuildInputs(t *testing.T) {
	for name, mutate := range map[string]func(*Manifest){
		"Bun latest": func(m *Manifest) {
			m.Bun.Host.URL = "https://github.com/oven-sh/bun/releases/latest/download/bun-darwin-aarch64.zip"
		},
		"OpenTUI range":      func(m *Manifest) { m.OpenTUI.Version = "^0.5.9" },
		"OpenTUI digest":     func(m *Manifest) { m.OpenTUI.SHA256 = "" },
		"sunaba-ui platform": func(m *Manifest) { m.SunabaUI.Arch = "x64" },
	} {
		t.Run(name, func(t *testing.T) {
			manifest := MustPinned()
			mutate(&manifest)
			if err := ValidateRuntimeManifest(manifest); err == nil {
				t.Fatal("unpinned sunaba-ui dependency accepted")
			}
		})
	}
}

func TestBootstrapAndUpdateGateBindExactUIArtifact(t *testing.T) {
	manifest := MustPinned()
	manifest.SunabaUI.SHA256 = strings.Repeat("f", 64)
	if err := manifest.Validate(); err == nil {
		t.Fatal("bootstrap accepted a different sunaba-ui artifact")
	}
	current := MustPinned()
	candidate := current
	candidate.AppleContainer.Version = "1.2.3"
	candidate.AppleContainer.Commit = strings.Repeat("c", 40)
	candidate.Provenance.AppleContainer.Tag = candidate.AppleContainer.Version
	candidate.Provenance.AppleContainer.Commit = candidate.AppleContainer.Commit
	candidate.SunabaUI.SHA256 = strings.Repeat("f", 64)
	evidence := UpdateEvidence{ArtifactDigests: true, RuntimeVersion: true, Lifecycle: true, NetworkIsolation: true, CopyExport: true, ResourceLimits: true}
	if err := ValidateUpdateCandidate(current, candidate, evidence); err == nil {
		t.Fatal("generic dependency update changed sunaba-ui without a dedicated gate")
	}
}

func TestCompiledUIContractRejectsPreviousAndSubstitutedArtifacts(t *testing.T) {
	for name, manifest := range map[string]Manifest{
		"previous protocol-v3 artifact": PreviousSunabaUIV3Manifest(MustPinned()),
		"previous protocol-v2 artifact": PreviousSunabaUIV2Manifest(MustPinned()),
		"earlier protocol-v2 artifact":  EarlierSunabaUIV2Manifest(MustPinned()),
		"older protocol-v2 artifact":    OlderSunabaUIV2Manifest(MustPinned()),
		"oldest protocol-v2 artifact":   OldestSunabaUIV2Manifest(MustPinned()),
		"initial protocol-v2 artifact":  InitialSunabaUIV2Manifest(MustPinned()),
		"substituted artifact": func() Manifest {
			manifest := MustPinned()
			manifest.SunabaUI.SHA256 = strings.Repeat("f", 64)
			return manifest
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateCompiledUIContract(manifest); err == nil {
				t.Fatal("non-current UI artifact passed the compiled contract")
			}
		})
	}
	if err := ValidateCompiledUIContract(MustPinned()); err != nil {
		t.Fatalf("current UI artifact was rejected: %v", err)
	}
}

func TestKnownUIManifestMigrationPreservesVerifiedDynamicOpenCode(t *testing.T) {
	pinned := MustPinned()
	previous := PreviousSunabaUIV3Manifest(pinned)
	previous.OpenCode.Version = "1.99.0"
	previous.OpenCode.Host.URL = "https://github.com/anomalyco/opencode/releases/download/v1.99.0/" + previous.OpenCode.Host.Artifact
	previous.OpenCode.Guest.URL = "https://github.com/anomalyco/opencode/releases/download/v1.99.0/" + previous.OpenCode.Guest.Artifact
	previous.AgentImage.Tag = "sunaba-base:1.99.0-secure.1"
	previous.Provenance.OpenCode.Tag = "v1.99.0"
	previous.Provenance.OpenCode.Commit = strings.Repeat("1", 40)
	migrated, recognized, err := MigrateKnownUIManifest(previous, pinned)
	if err != nil || !recognized {
		t.Fatalf("recognized=%t error=%v", recognized, err)
	}
	if migrated.OpenCode != previous.OpenCode || migrated.Provenance.OpenCode != previous.Provenance.OpenCode || migrated.SunabaUI != pinned.SunabaUI {
		t.Fatalf("dynamic OpenCode identity changed during UI migration: %+v", migrated)
	}
	changed := previous
	changed.BaseImage.IndexSHA256 = strings.Repeat("e", 64)
	changed.BaseImage.Reference = "docker.io/library/debian:bookworm-slim@sha256:" + changed.BaseImage.IndexSHA256
	changed.Provenance.BaseImage.Digest = "sha256:" + changed.BaseImage.IndexSHA256
	if _, recognized, err := MigrateKnownUIManifest(changed, pinned); err == nil || recognized {
		t.Fatalf("changed platform input was migratable: recognized=%t error=%v", recognized, err)
	}
	unknown := previous
	unknown.SunabaUI.SHA256 = strings.Repeat("f", 64)
	if _, recognized, err := MigrateKnownUIManifest(unknown, pinned); err != nil || recognized {
		t.Fatalf("unknown UI artifact classification: recognized=%t error=%v", recognized, err)
	}
}

func TestMigratableBootstrapUIManifestsAreExactAndDistinct(t *testing.T) {
	pinned := MustPinned()
	history := MigratableBootstrapUIManifests(pinned)
	currentVersion, err := strconv.Atoi(pinned.SunabaUI.Version)
	if err != nil || len(history) == 0 || history[0].SunabaUI.Version != strconv.Itoa(currentVersion-1) {
		t.Fatalf("immediately previous UI generation is missing: current=%q history=%+v", pinned.SunabaUI.Version, history)
	}
	seen := map[StandaloneArtifact]bool{pinned.SunabaUI: true}
	for _, previous := range history {
		if seen[previous.SunabaUI] {
			t.Fatalf("duplicate migratable UI artifact: %+v", previous.SunabaUI)
		}
		seen[previous.SunabaUI] = true
		if err := ValidateCompiledUIContract(previous); err == nil {
			t.Fatalf("old UI artifact passed the current compiled contract: %+v", previous.SunabaUI)
		}
	}
}

func TestRuntimeManifestAcceptsAnotherExactV1Release(t *testing.T) {
	manifest := MustPinned()
	manifest.OpenCode.Version = "1.99.0"
	manifest.OpenCode.Host.URL = "https://github.com/anomalyco/opencode/releases/download/v1.99.0/" + manifest.OpenCode.Host.Artifact
	manifest.OpenCode.Guest.URL = "https://github.com/anomalyco/opencode/releases/download/v1.99.0/" + manifest.OpenCode.Guest.Artifact
	manifest.AgentImage.Tag = "sunaba-base:1.99.0-secure.1"
	manifest.Provenance.OpenCode.Tag = "v1.99.0"
	manifest.Provenance.OpenCode.Commit = strings.Repeat("1", 40)
	if err := ValidateRuntimeManifest(manifest); err != nil {
		t.Fatalf("dynamic v1 manifest rejected: %v", err)
	}
	if err := manifest.Validate(); err == nil {
		t.Fatal("dynamic manifest unexpectedly accepted as embedded bootstrap")
	}
	manifest.OpenCode.Version = "2.0.0"
	if err := ValidateRuntimeManifest(manifest); err == nil {
		t.Fatal("v2 manifest accepted")
	}
}

func TestOpenCodeUpdateCandidateKeepsPlatformPins(t *testing.T) {
	current := MustPinned()
	candidate := current
	candidate.OpenCode.Version = "1.99.0"
	candidate.OpenCode.Host.URL = "https://github.com/anomalyco/opencode/releases/download/v1.99.0/" + candidate.OpenCode.Host.Artifact
	candidate.OpenCode.Guest.URL = "https://github.com/anomalyco/opencode/releases/download/v1.99.0/" + candidate.OpenCode.Guest.Artifact
	candidate.AgentImage.Tag = "sunaba-base:1.99.0-secure.1"
	candidate.Provenance.OpenCode.Tag = "v1.99.0"
	candidate.Provenance.OpenCode.Commit = strings.Repeat("2", 40)
	if err := ValidateOpenCodeUpdateCandidate(current, candidate); err != nil {
		t.Fatal(err)
	}
	candidate.BaseImage.IndexSHA256 = strings.Repeat("3", 64)
	candidate.BaseImage.Reference = "docker.io/library/debian:bookworm-slim@sha256:" + candidate.BaseImage.IndexSHA256
	candidate.Provenance.BaseImage.Digest = "sha256:" + candidate.BaseImage.IndexSHA256
	if err := ValidateOpenCodeUpdateCandidate(current, candidate); err == nil {
		t.Fatal("OpenCode-only update changed the base image")
	}
}

func TestManifestPinsSourceAndBuildProvenance(t *testing.T) {
	m := MustPinned()
	if m.Provenance.OpenCode.Commit == "" || m.Provenance.AppleContainer.Commit != m.AppleContainer.Commit || m.Provenance.BaseImage.Digest != "sha256:"+m.BaseImage.IndexSHA256 {
		t.Fatalf("incomplete provenance: %+v", m.Provenance)
	}
	if digest, err := ManifestSHA256(); err != nil || len(digest) != 64 {
		t.Fatalf("manifest digest=%q error=%v", digest, err)
	}
}

func TestVersionUpdateRequiresEveryIntegrationEvidence(t *testing.T) {
	current := MustPinned()
	candidate := current
	candidate.AppleContainer.Version = "1.2.3"
	candidate.AppleContainer.Commit = strings.Repeat("c", 40)
	candidate.Provenance.AppleContainer.Tag = "1.2.3"
	candidate.Provenance.AppleContainer.Commit = candidate.AppleContainer.Commit
	complete := UpdateEvidence{ArtifactDigests: true, RuntimeVersion: true, Lifecycle: true, NetworkIsolation: true, CopyExport: true, ResourceLimits: true}
	if err := ValidateUpdateCandidate(current, candidate, complete); err != nil {
		t.Fatalf("complete update evidence was rejected: %v", err)
	}
	incomplete := complete
	incomplete.NetworkIsolation = false
	if err := ValidateUpdateCandidate(current, candidate, incomplete); err == nil {
		t.Fatal("Apple Container update without network isolation rerun was accepted")
	}
	candidate.Provenance.AppleContainer.Tag = "latest"
	if err := ValidateUpdateCandidate(current, candidate, complete); err == nil {
		t.Fatal("unbound candidate provenance was accepted")
	}
}

func TestManifestRejectsSourceCommitDrift(t *testing.T) {
	m := MustPinned()
	m.Provenance.OpenCode.Commit = strings.Repeat("d", 40)
	if err := m.Validate(); err == nil {
		t.Fatal("OpenCode source commit drift was accepted")
	}
	m = MustPinned()
	m.AppleContainer.Commit = strings.Repeat("e", 40)
	m.Provenance.AppleContainer.Commit = m.AppleContainer.Commit
	if err := m.Validate(); err == nil {
		t.Fatal("Apple Container source commit drift was accepted")
	}
}

func TestPinnedReturnsIndependentMaps(t *testing.T) {
	first := MustPinned()
	first.GoModules["golang.org/x/sys"] = "modified"
	first.Provenance.BuildInputs["opencode_version"] = "modified"
	second := MustPinned()
	if second.GoModules["golang.org/x/sys"] == "modified" || second.Provenance.BuildInputs["opencode_version"] == "modified" {
		t.Fatal("caller mutation changed the cached embedded manifest")
	}
}

func TestManifestRejectsLatestURL(t *testing.T) {
	m := MustPinned()
	m.OpenCode.Host.URL = "https://example.invalid/releases/latest/download/" + m.OpenCode.Host.Artifact
	if err := m.Validate(); err == nil {
		t.Fatal("latest URL was accepted")
	}
}

func TestManifestRejectsVersionDrift(t *testing.T) {
	m := MustPinned()
	m.OpenCode.Version = "2.0.0"
	if err := m.Validate(); err == nil {
		t.Fatal("version drift was accepted")
	}
	m = MustPinned()
	m.GoModules["github.com/urfave/cli/v3"] = "v3.10.0"
	if err := m.Validate(); err == nil {
		t.Fatal("urfave/cli version drift was accepted")
	}
}
