package gitgateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/audit"
	corecapability "sunaba/internal/capability"
	"sunaba/internal/testutil"
)

func TestMain(m *testing.M) {
	if os.Getenv("SUNABA_GIT_HOOK_SOCKET") != "" {
		err := RunPreReceiveHook(os.Getenv("SUNABA_GIT_HOOK_SOCKET"), os.Getenv("SUNABA_GIT_HOOK_TOKEN"), os.Getenv("GIT_OBJECT_DIRECTORY"), os.Stdin, os.Stderr)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestStandardGitPushRequiresPendingApprovalAndExactRetry(t *testing.T) {
	quarantine, first, second, _ := testBareRepository(t)
	gitPath, _ := exec.LookPath("git")
	testGit(t, gitPath, quarantine, "symbolic-ref", "HEAD", "refs/heads/main")
	root, _ := filepath.EvalSymlinks(t.TempDir())
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	upstream := filepath.Join(root, "upstream.git")
	testGit(t, gitPath, "", "clone", "--mirror", quarantine, upstream)
	testGit(t, gitPath, upstream, "symbolic-ref", "HEAD", "refs/heads/main")
	testGit(t, gitPath, upstream, "config", "http.receivepack", "true")
	testGit(t, gitPath, upstream, "config", "receive.denyDeleteCurrent", "ignore")
	const upstreamAuthorization = "Bearer host-upstream-secret"
	upstreamServer := newGitHTTPSServer(t, gitPath, root, upstreamAuthorization)
	defer upstreamServer.Close()
	caPath := writeTestCertificate(t, root, upstreamServer.Certificate())
	recorder, err := audit.NewRecorder(filepath.Join(root, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewPushApprovalManager(nil, recorder, "vm", "session")
	if err != nil {
		t.Fatal(err)
	}
	resolver := RepositoryResolver{
		GitPath: gitPath, RepositoryPath: quarantine, ProjectID: "project", Repository: "repository",
		RemoteName: "origin", RemoteURL: upstreamServer.URL + "/upstream.git",
	}
	executor := PushExecutor{
		Resolver: resolver, Approvals: manager, AuthorizationHeader: upstreamAuthorization,
		TLSCAInfoPath: caPath, Audit: recorder, VMID: "vm", SessionID: "session",
	}
	hookToken := "host-hook-channel-token-0123456789abcdef"
	hookRoot := testutil.PrivateTempDir(t, "sunaba-git-hook-")
	hookSocket := filepath.Join(hookRoot, "hook.sock")
	brokerContext, cancelBroker := context.WithCancel(context.Background())
	defer cancelBroker()
	broker, err := StartHookBroker(brokerContext, hookSocket, hookToken, manager, executor, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	capabilityToken := "guest-git-capability-0123456789abcdef"
	capability, _ := NewReadCapability(capabilityToken, "project", "vm", "session", time.Now().Add(5*time.Minute))
	readGateway, err := NewReadGateway(ReadConfig{
		UpstreamURL: upstreamServer.URL + "/upstream.git", GuestRepositoryPath: "/repository.git",
		AuthorizationHeader: upstreamAuthorization, Capability: capability, HTTPClient: upstreamServer.Client(), Audit: func(ReadAuditEvent) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	testExecutable, err = filepath.EvalSymlinks(testExecutable)
	if err != nil {
		t.Fatal(err)
	}
	receiveGateway, err := NewReceiveGateway(ReceiveConfig{
		GitPath: gitPath, RepositoryPath: quarantine, GuestRepositoryPath: "/repository.git",
		HookHelperPath: testExecutable, HookSocketPath: hookSocket, HookToken: hookToken,
		Capability: capability, MaxRequestBytes: 64 << 20, MaxResponseBytes: 4 << 20, MaxConcurrent: 1,
		BeforeAdvertise: executor.Sync,
		Audit:           func(ReadAuditEvent) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	gatewayServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if strings.Contains(request.URL.RawQuery, "git-receive-pack") || strings.HasSuffix(request.URL.Path, "/git-receive-pack") {
			receiveGateway.ServeHTTP(response, request)
			return
		}
		readGateway.ServeHTTP(response, request)
	}))
	defer gatewayServer.Close()
	guestRoot := t.TempDir()
	extraHeader := "http.extraHeader=Authorization: Bearer " + capabilityToken
	testGit(t, gitPath, guestRoot, "-c", extraHeader, "clone", gatewayServer.URL+"/repository.git", "work")
	work := filepath.Join(guestRoot, "work")
	testGit(t, gitPath, work, "config", "user.name", "Sunaba Agent")
	testGit(t, gitPath, work, "config", "user.email", "agent@example.invalid")
	if err := os.WriteFile(filepath.Join(work, "agent-change"), []byte("approved\n"), 0600); err != nil {
		t.Fatal(err)
	}
	testGit(t, gitPath, work, "add", "agent-change")
	testGit(t, gitPath, work, "commit", "-m", "agent change")
	newObject := strings.TrimSpace(testGit(t, gitPath, work, "rev-parse", "HEAD"))
	if output, err := runGit(gitPath, work, "-c", extraHeader, "push", "origin", "HEAD:refs/heads/main"); err == nil || !strings.Contains(output, "approval pending") {
		t.Fatalf("first push output=%q error=%v", output, err)
	}
	if actual := strings.TrimSpace(testGit(t, gitPath, upstream, "rev-parse", "refs/heads/main")); actual != first {
		t.Fatalf("unapproved upstream changed to %s", actual)
	}
	pending := broker.Pending()
	if len(pending) != 1 || pending[0].Binding.Updates[0].New != newObject || pending[0].Binding.Updates[0].Force || pending[0].Binding.Updates[0].Delete {
		t.Fatalf("pending approval=%+v", pending)
	}
	if err := broker.Confirm(pending[0].Nonce, pending[0].Binding); err != nil {
		t.Fatal(err)
	}
	if output, err := runGit(gitPath, work, "-c", extraHeader, "push", "origin", "HEAD:refs/heads/main"); err != nil {
		t.Fatalf("approved retry output=%q error=%v", output, err)
	}
	for name, repository := range map[string]string{"upstream": upstream, "quarantine": quarantine} {
		if actual := strings.TrimSpace(testGit(t, gitPath, repository, "rev-parse", "refs/heads/main")); actual != newObject {
			t.Fatalf("%s object=%s, want %s", name, actual, newObject)
		}
	}
	config, _ := os.ReadFile(filepath.Join(work, ".git", "config"))
	if strings.Contains(string(config), "host-upstream-secret") || strings.Contains(string(config), upstreamAuthorization) {
		t.Fatal("upstream credential leaked into guest Git config")
	}
	testGit(t, gitPath, work, "checkout", "--orphan", "forced-history")
	testGit(t, gitPath, work, "rm", "-rf", ".")
	if err := os.WriteFile(filepath.Join(work, "forced"), []byte("replacement\n"), 0600); err != nil {
		t.Fatal(err)
	}
	testGit(t, gitPath, work, "add", "forced")
	testGit(t, gitPath, work, "commit", "-m", "forced history")
	forcedObject := strings.TrimSpace(testGit(t, gitPath, work, "rev-parse", "HEAD"))
	if output, err := runGit(gitPath, work, "-c", extraHeader, "push", "--force", "origin", "HEAD:refs/heads/main"); err == nil || !strings.Contains(output, "approval pending") {
		t.Fatalf("first force push output=%q error=%v", output, err)
	}
	pending = broker.Pending()
	if len(pending) != 1 || !pending[0].Binding.Updates[0].Force || pending[0].Binding.Updates[0].Delete || pending[0].Binding.Updates[0].New != forcedObject {
		t.Fatalf("force approval=%+v", pending)
	}
	if err := broker.Confirm(pending[0].Nonce, pending[0].Binding); err != nil {
		t.Fatal(err)
	}
	if output, err := runGit(gitPath, work, "-c", extraHeader, "push", "--force", "origin", "HEAD:refs/heads/main"); err != nil {
		t.Fatalf("approved force retry output=%q error=%v", output, err)
	}
	if output, err := runGit(gitPath, work, "-c", extraHeader, "push", "origin", "--delete", "main"); err == nil || !strings.Contains(output, "approval pending") {
		t.Fatalf("first delete push output=%q error=%v", output, err)
	}
	pending = broker.Pending()
	if len(pending) != 1 || pending[0].Binding.Updates[0].Force || !pending[0].Binding.Updates[0].Delete {
		t.Fatalf("delete approval=%+v", pending)
	}
	if err := broker.Confirm(pending[0].Nonce, pending[0].Binding); err != nil {
		t.Fatal(err)
	}
	if output, err := runGit(gitPath, work, "-c", extraHeader, "push", "origin", "--delete", "main"); err != nil {
		t.Fatalf("approved delete retry output=%q error=%v", output, err)
	}
	if _, err := runGit(gitPath, upstream, "show-ref", "--verify", "refs/heads/main"); err == nil {
		t.Fatal("approved ref delete did not reach upstream")
	}
	if err := broker.Close(); err != nil {
		t.Fatal(err)
	}
	if output, err := runGit(gitPath, work, "-c", extraHeader, "push", "origin", "HEAD:refs/heads/after-close"); err == nil || !strings.Contains(output, "approval broker is unavailable") {
		t.Fatalf("push after broker close output=%q error=%v", output, err)
	}
	if _, err := runGit(gitPath, upstream, "show-ref", "--verify", "refs/heads/after-close"); err == nil {
		t.Fatal("push succeeded after session hook channel closed")
	}
	_ = second
}

func TestReceiveGatewayRejectsSharedCapabilityAfterAuditFailure(t *testing.T) {
	capability, err := NewReadCapability(strings.Repeat("r", 32), "project", "vm", "session", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	gate, err := corecapability.NewGate(capability.authority, capability.ExpiresAt, capability.MaxRequests, 1)
	if err != nil {
		t.Fatal(err)
	}
	gateway := &ReceiveGateway{
		backend:   http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("revoked request reached backend") }),
		guestPath: "/repository.git", capability: capability, maxRequestBytes: 1024, maxResponseBytes: 1024,
		gate: gate, now: time.Now, beforeAdvertise: func(context.Context) error { return nil },
		audit: func(ReadAuditEvent) error { return fmt.Errorf("injected audit failure") },
	}
	first := httptest.NewRecorder()
	gateway.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/invalid", nil))
	second := httptest.NewRecorder()
	gateway.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/repository.git/info/refs?service=git-receive-pack", nil))
	if first.Code != http.StatusNotFound || second.Code != http.StatusServiceUnavailable {
		t.Fatalf("statuses=%d,%d", first.Code, second.Code)
	}
}

func runGit(gitPath, directory string, args ...string) (string, error) {
	command := exec.Command(gitPath, args...)
	command.Dir = directory
	command.Env = testGitEnvironment()
	output, err := command.CombinedOutput()
	return string(output), err
}
