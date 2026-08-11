package gitgateway

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReadGatewaySupportsStandardCloneFetchPullWithoutCredentialLeak(t *testing.T) {
	quarantine, _, second, _ := testBareRepository(t)
	gitPath, _ := exec.LookPath("git")
	upstreamRoot, _ := filepath.EvalSymlinks(t.TempDir())
	upstream := filepath.Join(upstreamRoot, "remote.git")
	testGit(t, gitPath, "", "clone", "--mirror", quarantine, upstream)
	testGit(t, gitPath, upstream, "symbolic-ref", "HEAD", "refs/heads/main")
	testGit(t, gitPath, upstream, "fetch", quarantine, second)
	authorization := "Basic " + base64.StdEncoding.EncodeToString([]byte("host:upstream-secret"))
	upstreamServer := newGitHTTPSServer(t, gitPath, upstreamRoot, authorization)
	defer upstreamServer.Close()
	const capabilityToken = "guest-capability-token-0123456789abcdef"
	capability, err := NewReadCapability(capabilityToken, "project", "vm", "session", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var events []ReadAuditEvent
	gateway, err := NewReadGateway(ReadConfig{
		UpstreamURL: upstreamServer.URL + "/remote.git", GuestRepositoryPath: "/repository.git",
		AuthorizationHeader: authorization, Capability: capability, HTTPClient: upstreamServer.Client(),
		Audit: func(event ReadAuditEvent) { mu.Lock(); events = append(events, event); mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	guestServer := httptest.NewServer(gateway)
	defer guestServer.Close()
	guestRoot := t.TempDir()
	repositoryURL := guestServer.URL + "/repository.git"
	extraHeader := "http.extraHeader=Authorization: Bearer " + capabilityToken
	testGit(t, gitPath, guestRoot, "-c", extraHeader, "clone", repositoryURL, "clone")
	clone := filepath.Join(guestRoot, "clone")
	actual := strings.TrimSpace(testGit(t, gitPath, clone, "rev-parse", "HEAD"))
	if actual == "" {
		t.Fatal("clone returned no HEAD")
	}
	testGit(t, gitPath, upstream, "update-ref", "refs/heads/main", second)
	testGit(t, gitPath, clone, "-c", extraHeader, "fetch", "origin")
	testGit(t, gitPath, clone, "-c", extraHeader, "pull", "--ff-only", "origin", "main")
	config, err := os.ReadFile(filepath.Join(clone, ".git", "config"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(config), "upstream-secret") || strings.Contains(string(config), authorization) {
		t.Fatal("upstream credential leaked into guest repository")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) == 0 {
		t.Fatal("Git read operations were not audited")
	}
	for _, event := range events {
		if event.Status < 200 || event.Status >= 300 || strings.Contains(event.Reason, "upstream-secret") {
			t.Fatalf("unexpected Git audit event: %+v", event)
		}
	}
}

func TestReadGatewayRejectsPushExpiredCapabilityAndUnknownRoutes(t *testing.T) {
	capability, _ := NewReadCapability("guest-capability-token-0123456789abcdef", "project", "vm", "session", time.Now().Add(-time.Second))
	gateway, err := NewReadGateway(ReadConfig{UpstreamURL: "https://example.invalid/repository.git", GuestRepositoryPath: "/repository.git", AuthorizationHeader: "Bearer host-secret", Capability: capability, Audit: func(ReadAuditEvent) {}})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/repository.git/info/refs?service=git-upload-pack", "/repository.git/info/refs?service=git-receive-pack", "/repository.git/git-receive-pack", "/other.git/info/refs?service=git-upload-pack"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer guest-capability-token-0123456789abcdef")
		response := httptest.NewRecorder()
		gateway.ServeHTTP(response, request)
		if path == "/repository.git/info/refs?service=git-upload-pack" {
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("expired capability status=%d", response.Code)
			}
		} else if response.Code != http.StatusNotFound {
			t.Fatalf("unsafe route %s status=%d", path, response.Code)
		}
	}
}
