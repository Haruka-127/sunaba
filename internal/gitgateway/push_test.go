package gitgateway

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/audit"
)

func TestPushExecutorTerminatesCredentialAndUsesExactObjectLease(t *testing.T) {
	quarantine, first, second, _ := testBareRepository(t)
	gitPath, _ := exec.LookPath("git")
	upstreamRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	upstream := filepath.Join(upstreamRoot, "remote.git")
	testGit(t, gitPath, "", "clone", "--mirror", quarantine, upstream)
	testGit(t, gitPath, upstream, "config", "http.receivepack", "true")
	authorization := "Basic " + base64.StdEncoding.EncodeToString([]byte("host:secret-token"))
	server := newGitHTTPSServer(t, gitPath, upstreamRoot, authorization)
	defer server.Close()
	certificate := writeTestCertificate(t, upstreamRoot, server.Certificate())
	recorder, err := audit.NewRecorder(filepath.Join(upstreamRoot, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	resolver := RepositoryResolver{
		GitPath: gitPath, RepositoryPath: quarantine, ProjectID: "project", Repository: "repository",
		RemoteName: "origin", RemoteURL: server.URL + "/remote.git",
	}
	manager, err := NewPushApprovalManager(nil, recorder, "vm", "session")
	if err != nil {
		t.Fatal(err)
	}
	proposed := []ProposedRefUpdate{{Ref: "refs/heads/main", Old: first, New: second}}
	binding, err := resolver.Resolve(context.Background(), proposed)
	if err != nil {
		t.Fatal(err)
	}
	request, err := manager.NewRequest(binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := manager.Confirm(request.Nonce, binding)
	if err != nil {
		t.Fatal(err)
	}
	executor := PushExecutor{
		Resolver: resolver, Approvals: manager, AuthorizationHeader: authorization,
		TLSCAInfoPath: certificate, Audit: recorder, VMID: "vm", SessionID: "session",
	}
	if err := executor.Execute(context.Background(), grant, proposed); err != nil {
		t.Fatal(err)
	}
	actual := strings.TrimSpace(testGit(t, gitPath, upstream, "rev-parse", "refs/heads/main"))
	if actual != second {
		t.Fatalf("upstream object=%s, want %s", actual, second)
	}
	if err := executor.Execute(context.Background(), grant, proposed); err == nil {
		t.Fatal("one-shot grant was accepted twice")
	}
	auditFiles, err := filepath.Glob(filepath.Join(upstreamRoot, "audit", "project", "audit-*.jsonl"))
	if err != nil || len(auditFiles) != 1 {
		t.Fatalf("audit files=%v error=%v", auditFiles, err)
	}
	auditBytes, err := os.ReadFile(auditFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(auditBytes), "secret-token") || strings.Contains(string(auditBytes), authorization) {
		t.Fatal("host Git credential leaked to audit")
	}
}

func TestPushExecutorRejectsUpstreamRaceWithConsumedGrant(t *testing.T) {
	quarantine, first, second, divergent := testBareRepository(t)
	gitPath, _ := exec.LookPath("git")
	upstreamRoot, _ := filepath.EvalSymlinks(t.TempDir())
	upstream := filepath.Join(upstreamRoot, "remote.git")
	testGit(t, gitPath, "", "clone", "--mirror", quarantine, upstream)
	testGit(t, gitPath, upstream, "config", "http.receivepack", "true")
	testGit(t, gitPath, upstream, "update-ref", "refs/heads/main", divergent)
	authorization := "Bearer host-secret"
	server := newGitHTTPSServer(t, gitPath, upstreamRoot, authorization)
	defer server.Close()
	recorder, _ := audit.NewRecorder(filepath.Join(upstreamRoot, "audit"))
	resolver := RepositoryResolver{GitPath: gitPath, RepositoryPath: quarantine, ProjectID: "project", Repository: "repository", RemoteName: "origin", RemoteURL: server.URL + "/remote.git"}
	manager, _ := NewPushApprovalManager(nil, recorder, "vm", "session")
	proposed := []ProposedRefUpdate{{Ref: "refs/heads/main", Old: first, New: second}}
	binding, _ := resolver.Resolve(context.Background(), proposed)
	request, _ := manager.NewRequest(binding, time.Minute)
	grant, _ := manager.Confirm(request.Nonce, binding)
	executor := PushExecutor{Resolver: resolver, Approvals: manager, AuthorizationHeader: authorization, TLSCAInfoPath: writeTestCertificate(t, upstreamRoot, server.Certificate()), Audit: recorder, VMID: "vm", SessionID: "session"}
	if err := executor.Execute(context.Background(), grant, proposed); err == nil {
		t.Fatal("upstream ref race was accepted")
	}
	actual := strings.TrimSpace(testGit(t, gitPath, upstream, "rev-parse", "refs/heads/main"))
	if actual != divergent {
		t.Fatalf("raced upstream was changed to %s", actual)
	}
	if err := executor.Execute(context.Background(), grant, proposed); err == nil {
		t.Fatal("failed push grant was reusable")
	}
}

func newGitHTTPSServer(t *testing.T, gitPath, projectRoot, authorization string) *httptest.Server {
	t.Helper()
	backend := &cgi.Handler{Path: gitPath, Args: []string{"http-backend"}, Env: []string{"GIT_PROJECT_ROOT=" + projectRoot, "GIT_HTTP_EXPORT_ALL=1"}, InheritEnv: []string{"PATH"}}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != authorization {
			response.Header().Set("WWW-Authenticate", `Basic realm="sunaba-test"`)
			http.Error(response, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		backend.ServeHTTP(response, request)
	})
	return httptest.NewTLSServer(handler)
}

func writeTestCertificate(t *testing.T, root string, certificate *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(root, "server-ca.pem")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
