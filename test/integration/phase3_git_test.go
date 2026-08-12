//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"sunaba/internal/audit"
	"sunaba/internal/dependency"
	"sunaba/internal/gitgateway"
	"sunaba/internal/modelgateway"
	"sunaba/internal/opencode"
	sunabaruntime "sunaba/internal/runtime"
	"sunaba/internal/session"
	"sunaba/internal/state"
	"sunaba/internal/trustedui"
)

func TestPhase3GitGatewayInAgentVM(t *testing.T) {
	if os.Getenv("SUNABA_PHASE3_INTEGRATION") != "1" {
		t.Skip("set SUNABA_PHASE3_INTEGRATION=1 on the pinned macOS/Apple Container host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	runID := randomID(t)
	runtimeBase, err := os.MkdirTemp("/private/tmp", "sunaba-phase3-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runtimeBase, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(runtimeBase)
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(runtimeBase, "source")
	project := filepath.Join(runtimeBase, "project")
	upstream := filepath.Join(runtimeBase, "upstream.git")
	upstream2 := filepath.Join(runtimeBase, "upstream2.git")
	quarantine := filepath.Join(runtimeBase, "origin.git")
	integrationGit(t, gitPath, "", "init", source)
	integrationGit(t, gitPath, source, "config", "user.name", "Sunaba Integration")
	integrationGit(t, gitPath, source, "config", "user.email", "sunaba@example.invalid")
	writeIntegrationFile(t, filepath.Join(source, "project.txt"), "baseline\n")
	integrationGit(t, gitPath, source, "add", "project.txt")
	integrationGit(t, gitPath, source, "commit", "-m", "baseline")
	integrationGit(t, gitPath, "", "clone", "--bare", source, upstream)
	integrationGit(t, gitPath, "", "clone", "--bare", source, upstream2)
	integrationGit(t, gitPath, upstream, "config", "http.receivepack", "true")
	integrationGit(t, gitPath, "", "clone", "--mirror", upstream, quarantine)
	if err := os.Chmod(quarantine, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	writeIntegrationFile(t, filepath.Join(project, "project.txt"), "baseline\n")
	upstreamSecret := "host-upstream-" + runID
	upstreamAuthorization := "Bearer " + upstreamSecret
	upstreamServer := integrationGitHTTPSServer(t, gitPath, runtimeBase, upstreamAuthorization)
	defer upstreamServer.Close()
	upstreamSecret2 := "host-upstream-two-" + runID
	upstreamAuthorization2 := "Bearer " + upstreamSecret2
	upstreamServer2 := integrationGitHTTPSServer(t, gitPath, runtimeBase, upstreamAuthorization2)
	defer upstreamServer2.Close()
	caPath := integrationServerCertificate(t, runtimeBase, upstreamServer.Certificate())
	projectID := state.ProjectID(project)
	sessionID := "p3a" + runID
	vmID := "sunaba-" + projectID + "-" + sessionID
	auditRecorder, err := audit.NewRecorder(filepath.Join(runtimeBase, "state", "audit"))
	if err != nil {
		t.Fatal(err)
	}
	auditErrors := make(chan error, 16)
	gitAudit := func(event gitgateway.ReadAuditEvent) {
		outcome := "allowed"
		if event.Status < 200 || event.Status >= 300 {
			outcome = "rejected"
		}
		if err := auditRecorder.Append(audit.BoundaryEvent{
			At: event.At, Category: "git", Action: "git." + event.Operation, Outcome: outcome,
			ProjectID: event.ProjectID, VMID: event.VMID, SessionID: event.SessionID,
			Details: map[string]string{"status": strconv.Itoa(event.Status), "request_bytes": strconv.FormatInt(event.RequestBytes, 10), "response_bytes": strconv.FormatInt(event.ResponseBytes, 10), "reason": event.Reason},
		}); err != nil {
			auditErrors <- err
		}
	}
	approvals, err := gitgateway.NewPushApprovalManager(nil, auditRecorder, vmID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	resolver := gitgateway.RepositoryResolver{
		GitPath: gitPath, RepositoryPath: quarantine, ProjectID: projectID, Repository: "origin",
		RemoteName: "origin", RemoteURL: upstreamServer.URL + "/upstream.git",
	}
	executor := gitgateway.PushExecutor{
		Resolver: resolver, Approvals: approvals, AuthorizationHeader: upstreamAuthorization,
		TLSCAInfoPath: caPath, Audit: auditRecorder, VMID: vmID, SessionID: sessionID,
	}
	hookToken, err := session.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	hookSocket := filepath.Join(runtimeBase, "git-hook.sock")
	brokerContext, cancelBroker := context.WithCancel(context.Background())
	defer cancelBroker()
	broker, err := gitgateway.StartHookBroker(brokerContext, hookSocket, hookToken, approvals, executor, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostHook := buildHostBinary(t, ctx, runtimeBase, "sunaba-git-hook", "./cmd/sunaba-git-hook")
	gitToken, err := session.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	gitToken2, err := session.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	gitCapability2, err := gitgateway.NewReadCapability(gitToken2, projectID, vmID, sessionID, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	gitCapability, err := gitgateway.NewReadCapability(gitToken, projectID, vmID, sessionID, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	readGateway2, err := gitgateway.NewReadGateway(gitgateway.ReadConfig{
		UpstreamURL: upstreamServer2.URL + "/upstream2.git", GuestRepositoryPath: "/upstream.git",
		AuthorizationHeader: upstreamAuthorization2, Capability: gitCapability2, HTTPClient: upstreamServer2.Client(), Audit: gitAudit,
	})
	if err != nil {
		t.Fatal(err)
	}
	readGateway, err := gitgateway.NewReadGateway(gitgateway.ReadConfig{
		UpstreamURL: upstreamServer.URL + "/upstream.git", GuestRepositoryPath: "/origin.git",
		AuthorizationHeader: upstreamAuthorization, Capability: gitCapability, HTTPClient: upstreamServer.Client(), Audit: gitAudit,
	})
	if err != nil {
		t.Fatal(err)
	}
	receiveGateway, err := gitgateway.NewReceiveGateway(gitgateway.ReceiveConfig{
		GitPath: gitPath, RepositoryPath: quarantine, GuestRepositoryPath: "/origin.git",
		HookHelperPath: hostHook, HookSocketPath: hookSocket, HookToken: hookToken, Capability: gitCapability,
		MaxRequestBytes: 64 << 20, MaxResponseBytes: 4 << 20, MaxConcurrent: 1,
		BeforeAdvertise: executor.Sync,
		Audit:           gitAudit,
	})
	if err != nil {
		t.Fatal(err)
	}
	gitHandler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/upstream.git/") {
			readGateway2.ServeHTTP(response, request)
			return
		}
		if !strings.HasPrefix(request.URL.Path, "/origin.git/") {
			http.NotFound(response, request)
			return
		}
		if strings.Contains(request.URL.RawQuery, "git-receive-pack") || strings.HasSuffix(request.URL.Path, "/git-receive-pack") {
			receiveGateway.ServeHTTP(response, request)
			return
		}
		readGateway.ServeHTTP(response, request)
	})
	modelToken, _ := session.NewSecret()
	serverPassword, _ := session.NewSecret()
	modelID := "gpt-5"
	modelCapability, err := modelgateway.NewCapability(modelToken, projectID, vmID, sessionID, []string{modelID}, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	modelHandler, err := modelgateway.New(modelgateway.Config{
		UpstreamBaseURL: "https://example.invalid", UpstreamAPIKey: "unused-host-key", Capability: modelCapability,
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := opencode.BuildModelGatewayConfig(opencode.ModelGatewayProviderConfig{
		BaseURL: "http://127.0.0.1:4141/v1", AllowedModels: []string{modelID},
		DefaultModel: modelID, TokenEnv: "SUNABA_MODEL_GATEWAY_TOKEN",
	})
	if err != nil {
		t.Fatal(err)
	}
	relay := buildLinuxBinary(t, ctx, runtimeBase, "sunaba-guest-relay", "./cmd/sunaba-guest-relay")
	cfg := session.Config{
		Store: &state.Store{Root: filepath.Join(runtimeBase, "state")}, Runtime: sunabaruntime.NewAppleContainer(false),
		ProjectRoot: project, RuntimeBase: runtimeBase, SessionID: sessionID,
		Image: dependency.MustPinned().AgentImage.Tag, CPUs: 1, Memory: "2G", DiskBytes: 128 << 20,
		ProcessMax: 512, FileSizeMax: 128 << 20, OpenFileMax: 4096,
		GuestRelayBinary: relay, ProviderConfig: provider, ModelGateway: modelHandler, ModelToken: modelToken,
		GitGateway: gitHandler, GitRemotes: []session.GitRemote{{Name: "origin", Token: gitToken}, {Name: "upstream", Token: gitToken2}}, GitGatewayClose: broker.Close,
		ServerPassword: serverPassword, LeaseTTL: 5 * time.Minute, Audit: auditRecorder,
	}
	active, err := session.Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	destroyed := false
	defer func() {
		if !destroyed {
			_ = active.Destroy(context.Background())
		}
	}()
	guestClone := "/var/lib/sunaba/overlay/git-clone"
	guestClone2 := "/var/lib/sunaba/overlay/git-clone-upstream"
	gitEnvironment := "set -a; . /run/sunaba/session.env; set +a; export HOME=/run/sunaba/home; export GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=http.http://127.0.0.1:4242/origin.git.extraHeader GIT_CONFIG_VALUE_0=\"Authorization: Bearer $SUNABA_GIT_GATEWAY_TOKEN_0\" GIT_CONFIG_KEY_1=http.http://127.0.0.1:4242/upstream.git.extraHeader GIT_CONFIG_VALUE_1=\"Authorization: Bearer $SUNABA_GIT_GATEWAY_TOKEN_1\"; git "
	cloneCommand := gitEnvironment + "clone http://127.0.0.1:4242/origin.git " + guestClone
	if output, err := cfg.Runtime.ExecOutput(ctx, active.Container, []string{"runuser", "-u", "sunaba-agent", "--", "/bin/bash", "-lc", cloneCommand}); err != nil {
		t.Fatalf("guest clone: %v: %s", err, output)
	}
	cloneCommand2 := gitEnvironment + "clone http://127.0.0.1:4242/upstream.git " + guestClone2
	if output, err := cfg.Runtime.ExecOutput(ctx, active.Container, []string{"runuser", "-u", "sunaba-agent", "--", "/bin/bash", "-lc", cloneCommand2}); err != nil {
		t.Fatalf("second guest clone: %v: %s", err, output)
	}
	crossTokenRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://sunaba/upstream.git/info/refs?service=git-upload-pack", nil)
	crossTokenRequest.Header.Set("Authorization", "Bearer "+gitToken)
	crossTokenResponse, err := unixHTTPClient(filepath.Join(active.Root, "git-gateway.sock")).Do(crossTokenRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = crossTokenResponse.Body.Close()
	if crossTokenResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cross-remote capability status=%d", crossTokenResponse.StatusCode)
	}
	if err := active.Pause(ctx); err != nil {
		t.Fatal(err)
	}
	pausedRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://sunaba/origin.git/info/refs?service=git-upload-pack", nil)
	pausedRequest.Header.Set("Authorization", "Bearer "+gitToken)
	pausedResponse, err := unixHTTPClient(filepath.Join(active.Root, "git-gateway.sock")).Do(pausedRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = pausedResponse.Body.Close()
	if pausedResponse.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("paused Git Gateway status=%d", pausedResponse.StatusCode)
	}
	if err := active.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	writeIntegrationFile(t, filepath.Join(source, "project.txt"), "fetched\n")
	integrationGit(t, gitPath, source, "commit", "-am", "host update")
	integrationGit(t, gitPath, source, "push", upstream, "HEAD:refs/heads/master")
	pullCommand := "cd " + guestClone + "; " + gitEnvironment + "pull --ff-only origin master"
	if output, err := cfg.Runtime.ExecOutput(ctx, active.Container, []string{"runuser", "-u", "sunaba-agent", "--", "/bin/bash", "-lc", pullCommand}); err != nil {
		t.Fatalf("guest fetch/pull: %v: %s", err, output)
	}
	guestCommit := "cd " + guestClone + "; git config user.name 'Sunaba Agent'; git config user.email agent@example.invalid; printf 'agent\\n' > agent.txt; git add agent.txt; git commit -m 'agent push'"
	if output, err := cfg.Runtime.ExecOutput(ctx, active.Container, []string{"runuser", "-u", "sunaba-agent", "--", "/bin/bash", "-lc", guestCommit}); err != nil {
		t.Fatalf("guest commit: %v: %s", err, output)
	}
	pushCommand := "cd " + guestClone + "; " + gitEnvironment + "push origin HEAD:refs/heads/master"
	if output, err := cfg.Runtime.ExecOutput(ctx, active.Container, []string{"runuser", "-u", "sunaba-agent", "--", "/bin/bash", "-lc", pushCommand}); err == nil || !strings.Contains(output+err.Error(), "approval pending") {
		t.Fatalf("unapproved guest push output=%q error=%v", output, err)
	}
	pending := broker.Pending()
	if len(pending) != 1 || pending[0].Binding.Updates[0].Force || pending[0].Binding.Updates[0].Delete {
		t.Fatalf("guest push pending=%+v", pending)
	}
	var trusted bytes.Buffer
	if err := trustedui.ConfirmPush(strings.NewReader(pending[0].Nonce+"\n"), &trusted, pending[0]); err != nil {
		t.Fatal(err)
	}
	if err := broker.Confirm(pending[0].Nonce, pending[0].Binding); err != nil {
		t.Fatal(err)
	}
	if output, err := cfg.Runtime.ExecOutput(ctx, active.Container, []string{"runuser", "-u", "sunaba-agent", "--", "/bin/bash", "-lc", pushCommand}); err != nil {
		t.Fatalf("approved guest push: %v: %s", err, output)
	}
	guestHead, err := cfg.Runtime.ExecOutput(ctx, active.Container, []string{"runuser", "-u", "sunaba-agent", "--", "git", "-C", guestClone, "rev-parse", "HEAD"})
	if err != nil {
		t.Fatal(err)
	}
	upstreamHead := strings.TrimSpace(integrationGit(t, gitPath, upstream, "rev-parse", "refs/heads/master"))
	if strings.TrimSpace(guestHead) != upstreamHead {
		t.Fatalf("approved guest object=%s upstream=%s", guestHead, upstreamHead)
	}
	credentialProbe := "! grep -R --binary-files=without-match -e " + upstreamSecret + " -e " + upstreamSecret2 + " /run/sunaba /var/lib/sunaba " + active.WorkspacePath
	if output, err := cfg.Runtime.ExecOutput(ctx, active.Container, []string{"/bin/bash", "-lc", credentialProbe}); err != nil {
		t.Fatalf("host Git credential visible in guest: %v: %s", err, output)
	}
	if err := active.Destroy(ctx); err != nil {
		t.Fatal(err)
	}
	destroyed = true
	revokedRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://sunaba/origin.git/info/refs?service=git-upload-pack", nil)
	revokedRequest.Header.Set("Authorization", "Bearer "+gitToken)
	if response, err := unixHTTPClient(filepath.Join(active.Root, "git-gateway.sock")).Do(revokedRequest); err == nil {
		_ = response.Body.Close()
		t.Fatal("Git Gateway socket remained reachable after session destroy")
	}
	auditFiles, _ := filepath.Glob(filepath.Join(runtimeBase, "state", "audit", projectID, "audit-*.jsonl"))
	if len(auditFiles) != 1 {
		t.Fatalf("Phase 3 audit files=%v", auditFiles)
	}
	auditBytes, _ := os.ReadFile(auditFiles[0])
	if bytes.Contains(auditBytes, []byte(upstreamAuthorization)) || bytes.Contains(auditBytes, []byte(upstreamAuthorization2)) || bytes.Contains(auditBytes, []byte(gitToken)) || bytes.Contains(auditBytes, []byte(gitToken2)) || bytes.Contains(auditBytes, []byte(hookToken)) {
		t.Fatal("Phase 3 audit contained a host or session secret")
	}
	for _, action := range []string{"git.clone_fetch", "git.push", "git.fetch.sync", "git.push.approval", "git.push.consume", "git.push.upstream", "git_gateway.started", "git_gateway.stopped"} {
		if !bytes.Contains(auditBytes, []byte(`"action":"`+action+`"`)) {
			t.Fatalf("Phase 3 audit missing %s", action)
		}
	}
	select {
	case err := <-auditErrors:
		t.Fatalf("Git Gateway audit append failed: %v", err)
	default:
	}
}

func integrationGitHTTPSServer(t *testing.T, gitPath, projectRoot, authorization string) *httptest.Server {
	t.Helper()
	backend := &cgi.Handler{Path: gitPath, Args: []string{"http-backend"}, Env: []string{"GIT_PROJECT_ROOT=" + projectRoot, "GIT_HTTP_EXPORT_ALL=1"}, InheritEnv: []string{"PATH"}, Stderr: io.Discard}
	return httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != authorization {
			response.Header().Set("WWW-Authenticate", `Basic realm="sunaba-integration"`)
			http.Error(response, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		backend.ServeHTTP(response, request)
	}))
}

func integrationServerCertificate(t *testing.T, root string, certificate *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(root, "upstream-ca.pem")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func buildHostBinary(t *testing.T, ctx context.Context, tempDir, name, pkg string) string {
	return buildHostBinaryWithLDFlags(t, ctx, tempDir, name, pkg, "")
}

func buildHostBinaryWithLDFlags(t *testing.T, ctx context.Context, tempDir, name, pkg, ldflags string) string {
	t.Helper()
	output := filepath.Join(tempDir, name)
	arguments := []string{"build", "-trimpath"}
	if ldflags != "" {
		arguments = append(arguments, "-ldflags", ldflags)
	}
	arguments = append(arguments, "-o", output, pkg)
	build := exec.CommandContext(ctx, "go", arguments...)
	build.Dir = repositoryRoot(t)
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOCACHE="+filepath.Join(tempDir, "host-go-cache"))
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build host %s: %v: %s", pkg, err, out)
	}
	return output
}

func integrationGit(t *testing.T, gitPath, directory string, args ...string) string {
	t.Helper()
	output, err := integrationGitResultIn(gitPath, directory, args...)
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
	return output
}

func integrationGitResultIn(gitPath, directory string, args ...string) (string, error) {
	command := exec.Command(gitPath, args...)
	command.Dir = directory
	command.Env = []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "LC_ALL=C", "PATH=/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}
	output, err := command.CombinedOutput()
	return string(output), err
}
