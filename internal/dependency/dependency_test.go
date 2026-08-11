package dependency

import "testing"

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
}
