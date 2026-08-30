package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"sunaba/internal/dependency"
	hosttui "sunaba/internal/tui"
)

type artifactRoundTripFunc func(*http.Request) (*http.Response, error)

func (function artifactRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestManagedOpenCodeDownloadsPinnedArchiveAndInstallsAtomically(t *testing.T) {
	stateRoot := managedArtifactTestRoot(t)
	manifest := dependency.MustPinned()
	executable := []byte("#!/bin/sh\nprintf '" + manifest.OpenCode.Version + "\\n'\n")
	archive := managedOpenCodeArchive(t, executable, false)
	manifest.OpenCode.Host.SHA256 = digestBytesForArtifactTest(archive)
	manifest.OpenCode.Host.ExecutableSHA256 = digestBytesForArtifactTest(executable)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/anomalyco/opencode/releases/download/v"+manifest.OpenCode.Version+"/"+manifest.OpenCode.Host.Artifact {
			t.Errorf("artifact path=%s", request.URL.Path)
		}
		response.Header().Set("Content-Length", stringLength(len(archive)))
		_, _ = response.Write(archive)
	}))
	client := rewriteArtifactClient(t, server)
	installer := dependencyArtifactInstaller{client: client}
	if err := installer.ensureOpenCode(context.Background(), stateRoot, manifest, ""); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(stateRoot, "tools", "opencode", "v"+manifest.OpenCode.Version)
	destination := filepath.Join(directory, "opencode")
	info, err := os.Lstat(destination)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0700 {
		t.Fatalf("managed OpenCode info=%v error=%v", info, err)
	}
	if digest, err := fileSHA256(destination); err != nil || digest != manifest.OpenCode.Host.ExecutableSHA256 {
		t.Fatalf("managed OpenCode digest=%q error=%v", digest, err)
	}
	server.Close()
	if err := installer.ensureOpenCode(context.Background(), stateRoot, manifest, ""); err != nil {
		t.Fatalf("valid managed install unexpectedly required another download: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(directory, ".*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("managed install retained temporary artifacts=%v error=%v", matches, err)
	}
}

func TestManagedOpenCodeRejectsArchiveExecutableAndVersionMismatch(t *testing.T) {
	baseManifest := dependency.MustPinned()
	validExecutable := []byte("#!/bin/sh\nprintf '" + baseManifest.OpenCode.Version + "\\n'\n")
	wrongVersionExecutable := []byte("#!/bin/sh\nprintf '1.99.0\\n'\n")
	for _, test := range []struct {
		name          string
		executable    []byte
		archiveDigest string
		execDigest    string
	}{
		{name: "archive-digest", executable: validExecutable, archiveDigest: strings.Repeat("0", 64), execDigest: digestBytesForArtifactTest(validExecutable)},
		{name: "executable-digest", executable: validExecutable, execDigest: strings.Repeat("0", 64)},
		{name: "version", executable: wrongVersionExecutable, execDigest: digestBytesForArtifactTest(wrongVersionExecutable)},
	} {
		t.Run(test.name, func(t *testing.T) {
			stateRoot := managedArtifactTestRoot(t)
			manifest := baseManifest
			archive := managedOpenCodeArchive(t, test.executable, false)
			manifest.OpenCode.Host.SHA256 = digestBytesForArtifactTest(archive)
			if test.archiveDigest != "" {
				manifest.OpenCode.Host.SHA256 = test.archiveDigest
			}
			manifest.OpenCode.Host.ExecutableSHA256 = test.execDigest
			archivePath := filepath.Join(stateRoot, "candidate.zip")
			if err := os.WriteFile(archivePath, archive, 0600); err != nil {
				t.Fatal(err)
			}
			directory, destination, err := managedArtifactPath(stateRoot, "opencode", "v"+manifest.OpenCode.Version, "opencode")
			if err != nil {
				t.Fatal(err)
			}
			if err := installManagedOpenCodeArchive(context.Background(), archivePath, directory, destination, manifest); err == nil {
				t.Fatal("invalid managed OpenCode artifact was accepted")
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatalf("invalid artifact changed managed destination: %v", err)
			}
		})
	}
}

func TestManagedOpenCodeRejectsDuplicateExecutable(t *testing.T) {
	stateRoot := managedArtifactTestRoot(t)
	manifest := dependency.MustPinned()
	executable := []byte("#!/bin/sh\nprintf '" + manifest.OpenCode.Version + "\\n'\n")
	archive := managedOpenCodeArchive(t, executable, true)
	manifest.OpenCode.Host.SHA256 = digestBytesForArtifactTest(archive)
	manifest.OpenCode.Host.ExecutableSHA256 = digestBytesForArtifactTest(executable)
	archivePath := filepath.Join(stateRoot, "candidate.zip")
	if err := os.WriteFile(archivePath, archive, 0600); err != nil {
		t.Fatal(err)
	}
	directory, destination, err := managedArtifactPath(stateRoot, "opencode", "v"+manifest.OpenCode.Version, "opencode")
	if err != nil {
		t.Fatal(err)
	}
	if err := installManagedOpenCodeArchive(context.Background(), archivePath, directory, destination, manifest); err == nil {
		t.Fatal("archive with duplicate OpenCode executables was accepted")
	}
}

func TestManagedOpenCodeRepairsUnsafeDestinationMetadata(t *testing.T) {
	manifest := dependency.MustPinned()
	executable := []byte("#!/bin/sh\nprintf '" + manifest.OpenCode.Version + "\\n'\n")
	archive := managedOpenCodeArchive(t, executable, false)
	manifest.OpenCode.Host.SHA256 = digestBytesForArtifactTest(archive)
	manifest.OpenCode.Host.ExecutableSHA256 = digestBytesForArtifactTest(executable)
	for _, test := range []struct {
		name    string
		prepare func(t *testing.T, directory, destination string)
	}{
		{name: "symlink", prepare: func(t *testing.T, directory, destination string) {
			target := filepath.Join(directory, "target")
			if err := os.WriteFile(target, executable, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, destination); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hardlink", prepare: func(t *testing.T, directory, destination string) {
			target := filepath.Join(directory, "target")
			if err := os.WriteFile(target, executable, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(target, destination); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "mode", prepare: func(t *testing.T, _ string, destination string) {
			if err := os.WriteFile(destination, executable, 0755); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			stateRoot := managedArtifactTestRoot(t)
			directory, destination, err := managedArtifactPath(stateRoot, "opencode", "v"+manifest.OpenCode.Version, "opencode")
			if err != nil {
				t.Fatal(err)
			}
			test.prepare(t, directory, destination)
			archivePath := filepath.Join(stateRoot, "candidate.zip")
			if err := os.WriteFile(archivePath, archive, 0600); err != nil {
				t.Fatal(err)
			}
			if err := (dependencyArtifactInstaller{}).ensureOpenCode(context.Background(), stateRoot, manifest, archivePath); err != nil {
				t.Fatal(err)
			}
			if err := verifyManagedExecutableMetadata(destination, maximumHostExecutableBytes); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestManagedSunabaUIInstallsVerifiedBundledSibling(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("sunaba-ui artifact contract is darwin/arm64")
	}
	stateRoot := managedArtifactTestRoot(t)
	source := filepath.Join(stateRoot, "bundled-sunaba-ui")
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	copyArtifactTestFile(t, testExecutable, source, 0700)
	digest, err := fileSHA256(source)
	if err != nil {
		t.Fatal(err)
	}
	manifest := dependency.MustPinned()
	manifest.SunabaUI.SHA256 = digest
	installer := dependencyArtifactInstaller{}
	if err := installer.ensureSunabaUI(stateRoot, manifest, source); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(stateRoot, "tools", "sunaba-ui", "v"+manifest.SunabaUI.Version, "sunaba-ui")
	if err := hosttui.VerifyHelperExecutable(destination, hosttui.ArtifactPin{OS: "darwin", Arch: "arm64", SHA256: digest}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("tampered"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := installer.ensureSunabaUI(stateRoot, manifest, source); err != nil {
		t.Fatalf("managed sunaba-ui was not atomically repaired: %v", err)
	}
}

func TestManagedArtifactPathRejectsSymlinkedToolDirectory(t *testing.T) {
	stateRoot := managedArtifactTestRoot(t)
	target := filepath.Join(stateRoot, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(stateRoot, "tools")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := managedArtifactPath(stateRoot, "opencode", "v1.2.3", "opencode"); err == nil {
		t.Fatal("symlinked managed tools directory was accepted")
	}
}

func managedOpenCodeArchive(t *testing.T, executable []byte, duplicate bool) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	writeEntry := func(name string) {
		header := &zip.FileHeader{Name: name}
		header.SetMode(0755)
		entry, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(executable); err != nil {
			t.Fatal(err)
		}
	}
	writeEntry("opencode")
	if duplicate {
		writeEntry("nested/opencode")
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func rewriteArtifactClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := server.Client().Transport
	return &http.Client{Transport: artifactRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		clone := request.Clone(request.Context())
		urlCopy := *request.URL
		urlCopy.Scheme, urlCopy.Host = target.Scheme, target.Host
		clone.URL = &urlCopy
		clone.Host = target.Host
		return transport.RoundTrip(clone)
	})}
}

func managedArtifactTestRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}

func digestBytesForArtifactTest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func copyArtifactTestFile(t *testing.T, source, destination string, mode os.FileMode) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
}

func stringLength(value int) string {
	return fmt.Sprintf("%d", value)
}
