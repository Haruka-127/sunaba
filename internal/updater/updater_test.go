package updater

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/dependency"
	"sunaba/internal/state"
	"sunaba/internal/versionconfig"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestCheckResolvesExactReleaseAndPersistsBoundCandidate(t *testing.T) {
	hostArchive := makeHostArchive(t, []byte("official-opencode-binary"))
	guestArchive := []byte("guest archive")
	commit := strings.Repeat("a", 40)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body []byte
		switch {
		case strings.Contains(request.URL.Path, "/releases/tags/v1.19.0"):
			body = []byte(`{"tag_name":"v1.19.0","draft":false,"prerelease":false,"assets":[{"name":"opencode-darwin-arm64.zip"},{"name":"opencode-linux-arm64.tar.gz"}]}`)
		case strings.Contains(request.URL.Path, "/git/ref/tags/v1.19.0"):
			body = []byte(`{"object":{"type":"commit","sha":"` + commit + `"}}`)
		case strings.HasSuffix(request.URL.Path, "opencode-darwin-arm64.zip"):
			body = hostArchive
		case strings.HasSuffix(request.URL.Path, "opencode-linux-arm64.tar.gz"):
			body = guestArchive
		default:
			t.Fatalf("unexpected request %s", request.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Header: make(http.Header), Request: request}, nil
	})}
	current := versionconfig.Lock{SchemaVersion: 1, Generation: 4, ResolvedAt: time.Now().UTC(), Manifest: dependency.MustPinned()}
	config := versionconfig.Config{SchemaVersion: 1, OpenCode: versionconfig.Selection{Strategy: "exact", Value: "1.19.0"}}
	store := &Store{State: &state.Store{Root: filepath.Join(t.TempDir(), "state")}}
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	candidate, err := (Service{Client: client, APIBase: "https://api.github.test/repos/anomalyco/opencode", Now: func() time.Time { return now }}).Check(context.Background(), config, current, store)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Target.OpenCode.Version != "1.19.0" || candidate.Target.Provenance.OpenCode.Commit != commit || candidate.ExpiresAt.Sub(candidate.CreatedAt) != 24*time.Hour {
		t.Fatalf("candidate=%+v", candidate)
	}
	loaded, err := store.Load()
	if err != nil || loaded.ID != candidate.ID || loaded.Target.OpenCode.Host.ExecutableSHA256 == "" {
		t.Fatalf("loaded=%+v error=%v", loaded, err)
	}
	root, _ := store.root()
	guestPath := filepath.Join(root, candidate.GuestArtifact.RelativePath)
	if err := os.WriteFile(guestPath, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "digest changed") {
		t.Fatalf("tampered quarantine artifact error=%v", err)
	}
}

func TestChannelChoosesHighestStableV1(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := `[
          {"tag_name":"v2.0.0","draft":false,"prerelease":false},
          {"tag_name":"v1.20.0","draft":false,"prerelease":true},
          {"tag_name":"v1.19.9","draft":false,"prerelease":false},
          {"tag_name":"v1.20.0","draft":false,"prerelease":false}
        ]`
		return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: request}, nil
	})}
	config := versionconfig.Config{SchemaVersion: 1, OpenCode: versionconfig.Selection{Strategy: "channel", Value: "v1-stable"}}
	version, _, err := (Service{Client: client, APIBase: "https://api.github.test"}).resolveRelease(context.Background(), config)
	if err != nil || version != "1.20.0" {
		t.Fatalf("version=%q error=%v", version, err)
	}
}

func TestCheckDoesNotCreateCandidateForActiveVersion(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := `{"tag_name":"v` + dependency.OpenCodeVersion + `","draft":false,"prerelease":false}`
		return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: request}, nil
	})}
	current := versionconfig.BootstrapLock()
	store := &Store{State: &state.Store{Root: filepath.Join(t.TempDir(), "state")}}
	_, err := (Service{Client: client, APIBase: "https://api.github.test"}).Check(context.Background(), versionconfig.BootstrapConfig(), current, store)
	if err == nil || !strings.Contains(err.Error(), "already the active") {
		t.Fatalf("error=%v", err)
	}
}

func updateCheckClient(t *testing.T, failGuest bool, hostArchive []byte) *http.Client {
	t.Helper()
	commit := strings.Repeat("a", 40)
	guestArchive := []byte("guest archive")
	return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body []byte
		status := http.StatusOK
		switch {
		case strings.Contains(request.URL.Path, "/releases/tags/v1.19.0"):
			body = []byte(`{"tag_name":"v1.19.0","draft":false,"prerelease":false,"assets":[{"name":"opencode-darwin-arm64.zip"},{"name":"opencode-linux-arm64.tar.gz"}]}`)
		case strings.Contains(request.URL.Path, "/git/ref/tags/v1.19.0"):
			body = []byte(`{"object":{"type":"commit","sha":"` + commit + `"}}`)
		case strings.HasSuffix(request.URL.Path, "opencode-darwin-arm64.zip"):
			body = hostArchive
		case strings.HasSuffix(request.URL.Path, "opencode-linux-arm64.tar.gz"):
			if failGuest {
				status = http.StatusInternalServerError
				body = []byte("boom")
			} else {
				body = guestArchive
			}
		default:
			t.Fatalf("unexpected request %s", request.URL)
		}
		return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Header: make(http.Header), Request: request}, nil
	})}
}

func artifactDirectories(t *testing.T, store *Store) []string {
	t.Helper()
	root, err := store.root()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "artifacts"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestCheckRemovesArtifactsOnFailureAndPrunesSupersededOnes(t *testing.T) {
	hostArchive := makeHostArchive(t, []byte("official-opencode-binary"))
	current := versionconfig.Lock{SchemaVersion: 1, Generation: 4, ResolvedAt: time.Now().UTC(), Manifest: dependency.MustPinned()}
	config := versionconfig.Config{SchemaVersion: 1, OpenCode: versionconfig.Selection{Strategy: "exact", Value: "1.19.0"}}
	store := &Store{State: &state.Store{Root: filepath.Join(t.TempDir(), "state")}}
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

	if _, err := (Service{Client: updateCheckClient(t, true, hostArchive), APIBase: "https://api.github.test/repos/anomalyco/opencode", Now: func() time.Time { return now }}).Check(context.Background(), config, current, store); err == nil {
		t.Fatal("expected guest download failure")
	}
	if names := artifactDirectories(t, store); len(names) != 0 {
		t.Fatalf("failed check leaked artifact directories: %v", names)
	}

	first, err := (Service{Client: updateCheckClient(t, false, hostArchive), APIBase: "https://api.github.test/repos/anomalyco/opencode", Now: func() time.Time { return now }}).Check(context.Background(), config, current, store)
	if err != nil {
		t.Fatal(err)
	}
	second, err := (Service{Client: updateCheckClient(t, false, hostArchive), APIBase: "https://api.github.test/repos/anomalyco/opencode", Now: func() time.Time { return now }}).Check(context.Background(), config, current, store)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == first.ID {
		t.Fatal("expected a fresh candidate ID for the second check")
	}
	if names := artifactDirectories(t, store); len(names) != 1 || names[0] != second.ID {
		t.Fatalf("superseded artifact directories were not pruned: %v", names)
	}
	loaded, err := store.Load()
	if err != nil || loaded.ID != second.ID {
		t.Fatalf("loaded=%+v error=%v", loaded, err)
	}
}

func TestClearAppliedRemovesCandidateAndArtifacts(t *testing.T) {
	hostArchive := makeHostArchive(t, []byte("official-opencode-binary"))
	current := versionconfig.Lock{SchemaVersion: 1, Generation: 4, ResolvedAt: time.Now().UTC(), Manifest: dependency.MustPinned()}
	config := versionconfig.Config{SchemaVersion: 1, OpenCode: versionconfig.Selection{Strategy: "exact", Value: "1.19.0"}}
	store := &Store{State: &state.Store{Root: filepath.Join(t.TempDir(), "state")}}
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	if _, err := (Service{Client: updateCheckClient(t, false, hostArchive), APIBase: "https://api.github.test/repos/anomalyco/opencode", Now: func() time.Time { return now }}).Check(context.Background(), config, current, store); err != nil {
		t.Fatal(err)
	}
	if err := store.ClearApplied(); err != nil {
		t.Fatal(err)
	}
	if names := artifactDirectories(t, store); len(names) != 0 {
		t.Fatalf("clear left artifact directories behind: %v", names)
	}
	root, _ := store.root()
	if _, err := os.Lstat(filepath.Join(root, "candidate.json")); !os.IsNotExist(err) {
		t.Fatalf("candidate.json still exists after ClearApplied: %v", err)
	}
	if err := store.ClearApplied(); err != nil {
		t.Fatalf("ClearApplied must be idempotent: %v", err)
	}
}

func makeHostArchive(t *testing.T, executable []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	header := &zip.FileHeader{Name: "opencode"}
	header.SetMode(0755)
	entry, err := writer.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(executable); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
