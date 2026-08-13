package updater

import (
	"archive/zip"
	"bytes"
	"context"
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
