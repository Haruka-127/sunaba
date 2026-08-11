package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/audit"
	"sunaba/internal/gitgateway"
	"sunaba/internal/policy"
	"sunaba/internal/session"
	"sunaba/internal/state"
	"sunaba/internal/workspace"
)

func TestHelpDescribesCurrentSecureCLIAndOmitsPrototypeCommands(t *testing.T) {
	var output bytes.Buffer
	a := &app{output: &output}
	usage(a.output)
	text := output.String()
	for _, expected := range []string{"credentials openai", "project init", "agent", "git remote add", "git remote list", "web enable", "approvals", "changes export", "changes apply", "--mode secure|dev", "never bind-mounted"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("help missing %q: %s", expected, text)
		}
	}
	for _, obsolete := range []string{"--no-firewall", "env set", "git set", "reset --full", "automatic approval"} {
		if strings.Contains(text, obsolete) {
			t.Fatalf("help retained obsolete prototype behavior %q", obsolete)
		}
	}
}

func TestGuestRelayRequiresLinuxAArch64ELF(t *testing.T) {
	header := make([]byte, 64)
	copy(header, []byte{0x7f, 'E', 'L', 'F'})
	header[4], header[5], header[6] = 2, 1, 1
	binary.LittleEndian.PutUint16(header[16:18], 2)
	binary.LittleEndian.PutUint16(header[18:20], 183)
	binary.LittleEndian.PutUint32(header[20:24], 1)
	binary.LittleEndian.PutUint16(header[52:54], 64)
	binary.LittleEndian.PutUint16(header[54:56], 56)
	binary.LittleEndian.PutUint16(header[58:60], 64)
	path := filepath.Join(t.TempDir(), "guest-relay")
	if err := os.WriteFile(path, header, 0700); err != nil {
		t.Fatal(err)
	}
	if err := validateGuestRelay(path); err != nil {
		t.Fatalf("valid ELF/AArch64 header rejected: %v", err)
	}
	if err := validateGuestRelay("/bin/sh"); err == nil {
		t.Fatal("host shell was accepted as the Linux/AArch64 guest relay")
	}
}

func TestHostGitAuthorizationUsesOnlyNonInteractiveCredentialHelper(t *testing.T) {
	bin := t.TempDir()
	git := filepath.Join(bin, "git")
	script := "#!/bin/sh\n" +
		"test \"$GIT_TERMINAL_PROMPT\" = 0 || exit 7\n" +
		"test \"$1 $2\" = \"credential fill\" || exit 8\n" +
		"cat >/dev/null\n" +
		"printf 'username=agent\\npassword=secret\\n'\n"
	if err := os.WriteFile(git, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	authorization, err := hostGitAuthorization(context.Background(), "https://git.example/repository.git")
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "Basic YWdlbnQ6c2VjcmV0" {
		t.Fatalf("unexpected authorization: %q", authorization)
	}
}

func TestGitPolicyManagesMultipleNamedHTTPSRemotesAndRejectsCredentialURLs(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(base, "state")}
	var output bytes.Buffer
	a := &app{store: store, output: &output, errors: &output}
	if err := a.project(context.Background(), []string{"init", project}); err != nil {
		t.Fatal(err)
	}
	if err := a.gitPolicy(context.Background(), []string{"set", "--remote", "https://git.example/legacy.git", "--dir", project}); err == nil {
		t.Fatal("legacy single-remote command remained accepted")
	}
	if err := a.gitPolicy(context.Background(), []string{"remote", "add", "--dir", project, "--name", "origin", "--url", "https://git.example/team/repository.git"}); err != nil {
		t.Fatal(err)
	}
	if err := a.gitPolicy(context.Background(), []string{"remote", "add", "--dir", project, "--name", "upstream", "--url", "https://git.example/team/upstream.git"}); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := policy.LoadAndMigrate(filepath.Join(store.Root, "projects", state.ProjectID(project), "policy.json"), time.Now())
	if err != nil || len(loaded.Git.Remotes) != 2 || loaded.Git.Remotes[0].Name != "origin" || loaded.Git.Remotes[1].Name != "upstream" {
		t.Fatalf("policy=%+v error=%v", loaded.Git, err)
	}
	output.Reset()
	if err := a.gitPolicy(context.Background(), []string{"remote", "list", "--dir", project}); err != nil || !strings.Contains(output.String(), "origin\thttps://git.example/team/repository.git") || !strings.Contains(output.String(), "upstream\thttps://git.example/team/upstream.git") {
		t.Fatalf("list output=%q error=%v", output.String(), err)
	}
	locator := filepath.Join(store.Root, "projects", state.ProjectID(project), approvalControlLocator)
	if err := os.WriteFile(locator, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.gitPolicy(context.Background(), []string{"disable", "--dir", project}); err == nil || !strings.Contains(err.Error(), "cannot change") {
		t.Fatalf("active policy mutation error=%v", err)
	}
	if err := os.Remove(locator); err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{
		"http://git.example/repository.git",
		"https://token@git.example/repository.git",
		"https://git.example/repository.git?ref=main",
		"https://git.example/repository",
		"https://git.example:8443/repository.git",
	} {
		if err := a.gitPolicy(context.Background(), []string{"remote", "add", "--dir", project, "--name", "unsafe", "--url", unsafe}); err == nil {
			t.Fatalf("unsafe Git remote accepted: %s", unsafe)
		}
	}
}

func TestGitGatewayMuxKeepsNamedRemoteRoutesAndTokensSeparate(t *testing.T) {
	route := func(token, name string) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Header.Get("Authorization") != "Bearer "+token {
				http.Error(response, "unauthorized", http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(response, name)
		})
	}
	server := httptest.NewServer(newGitGatewayMux(map[string]http.Handler{
		"/origin.git":   route("origin-token", "origin"),
		"/upstream.git": route("upstream-token", "upstream"),
	}))
	defer server.Close()

	request := func(path, token string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body)
	}
	if status, body := request("/origin.git/info/refs", "origin-token"); status != http.StatusOK || body != "origin" {
		t.Fatalf("origin route status=%d body=%q", status, body)
	}
	if status, _ := request("/upstream.git/info/refs", "origin-token"); status != http.StatusUnauthorized {
		t.Fatalf("cross-remote token status=%d", status)
	}
	if status, body := request("/upstream.git/info/refs", "upstream-token"); status != http.StatusOK || body != "upstream" {
		t.Fatalf("upstream route status=%d body=%q", status, body)
	}
	if status, _ := request("/unknown.git/info/refs", "upstream-token"); status != http.StatusNotFound {
		t.Fatalf("unknown route status=%d", status)
	}
}

func TestCredentialParserKeepsSupportedSecretMaterialOutOfErrors(t *testing.T) {
	basic, err := parseGitCredential("protocol=https\nhost=git.example\nusername=user\npassword=secret-token\n")
	if err != nil || basic != "Basic dXNlcjpzZWNyZXQtdG9rZW4=" {
		t.Fatalf("authorization=%q error=%v", basic, err)
	}
	bearer, err := parseGitCredential("authtype=Bearer\ncredential=secret-bearer\n")
	if err != nil || bearer != "Bearer secret-bearer" {
		t.Fatalf("authorization=%q error=%v", bearer, err)
	}
	for _, malformed := range []string{
		"username=user\nusername=other\npassword=secret-value\n",
		"username=user\npassword=secret-value\x00\n",
		"username=user\n",
	} {
		_, err := parseGitCredential(malformed)
		if err == nil || strings.Contains(err.Error(), "secret-value") {
			t.Fatalf("malformed credential error=%v", err)
		}
	}
}

func TestWebOriginRulesAreExplicitOriginOnly(t *testing.T) {
	httpsRule, err := originRule("https://packages.example", true)
	if err != nil || httpsRule.Port != 443 || !httpsRule.AllowConnect || httpsRule.AllowHTTP || !httpsRule.IncludeSubdomains {
		t.Fatalf("HTTPS rule=%+v error=%v", httpsRule, err)
	}
	httpRule, err := originRule("http://archive.example/", false)
	if err != nil || httpRule.Port != 80 || !httpRule.AllowHTTP || httpRule.AllowConnect {
		t.Fatalf("HTTP rule=%+v error=%v", httpRule, err)
	}
	for _, unsafe := range []string{
		"https://127.0.0.1",
		"https://packages.example/path",
		"https://user@packages.example",
		"https://packages.example:444",
		"file:///etc/passwd",
	} {
		if _, err := originRule(unsafe, false); err == nil {
			t.Fatalf("unsafe Web origin accepted: %s", unsafe)
		}
	}
}

func TestPrivateWebArtifactRefusesSymlinkReplacement(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "blocklist.hosts")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateBytes(path, []byte("replacement")); err == nil {
		t.Fatal("symlink Web artifact was replaced")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "original" {
		t.Fatal("symlink target was modified")
	}
}

type fakePushBroker struct {
	pending   []gitgateway.PushRequest
	confirmed []string
}

type fakeSessionControlTarget struct {
	paused    int
	resumed   int
	destroyed int
	exported  int
	commands  [][]string
	output    string
}

func (f *fakeSessionControlTarget) Pause(context.Context) error  { f.paused++; return nil }
func (f *fakeSessionControlTarget) Resume(context.Context) error { f.resumed++; return nil }
func (f *fakeSessionControlTarget) StopAndExport(context.Context) (session.ExportResult, error) {
	f.exported++
	return session.ExportResult{}, nil
}

func TestSupervisorExpiryRejectsResumeAndShell(t *testing.T) {
	target := &fakeSessionControlTarget{}
	controlled := &controlledSession{
		active: target, projectID: "project", sessionID: "session", container: "sunaba-project-session",
		runtimeRoot: "/private/tmp/sunaba-runtime-test/sunaba-session-session", workspacePath: "/workspace/sunaba-session",
		attachURL: "http://127.0.0.1:12345", projectState: "/private/tmp/project", serverPassword: strings.Repeat("s", 32),
		expiresAt: time.Now().Add(-time.Second), idleTimeout: 15 * time.Minute, lastActivity: time.Now(), state: "paused", exit: make(chan struct{}),
	}
	if err := controlled.resume(context.Background()); err == nil || target.resumed != 0 {
		t.Fatalf("expired resume error=%v resumed=%d", err, target.resumed)
	}
	controlled.state = "running"
	if _, err := controlled.shell(context.Background(), "true"); err == nil || len(target.commands) != 0 {
		t.Fatalf("expired shell error=%v commands=%v", err, target.commands)
	}
}

func TestSupervisorHeartbeatExtendsIdleDeadline(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	controlled := &controlledSession{
		active: &fakeSessionControlTarget{}, expiresAt: clock.Add(time.Hour), idleTimeout: 10 * time.Second,
		lastActivity: clock, now: func() time.Time { return clock }, activity: make(chan struct{}, 1), state: "running", exit: make(chan struct{}),
	}
	if controlled.idleExpired(clock.Add(9 * time.Second)) {
		t.Fatal("session expired before its idle deadline")
	}
	clock = clock.Add(8 * time.Second)
	if err := controlled.heartbeat(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-controlled.activity:
	default:
		t.Fatal("heartbeat did not notify the idle deadline timer")
	}
	if delay := controlled.idleDelay(clock.Add(3 * time.Second)); delay != 7*time.Second {
		t.Fatalf("idle timer delay=%s", delay)
	}
	if controlled.idleExpired(clock.Add(9 * time.Second)) {
		t.Fatal("heartbeat did not extend the idle deadline")
	}
	if !controlled.idleExpired(clock.Add(10 * time.Second)) {
		t.Fatal("session remained active at the extended idle deadline")
	}
}

func TestSupervisorExportWithoutChangesDestroysPersistentVM(t *testing.T) {
	target := &fakeSessionControlTarget{}
	controlled := &controlledSession{
		active: target, projectID: "project", sessionID: "session", container: "sunaba-project-session",
		runtimeRoot: "/private/tmp/sunaba-runtime-test/sunaba-session-session", workspacePath: "/workspace/sunaba-session",
		attachURL: "http://127.0.0.1:12345", projectState: "/private/tmp/project", serverPassword: strings.Repeat("s", 32),
		expiresAt: time.Now().Add(time.Hour), idleTimeout: 15 * time.Minute, lastActivity: time.Now(), state: "paused", exit: make(chan struct{}),
	}
	if err := controlled.exportAndDestroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if target.exported != 1 || target.destroyed != 1 || controlled.state != "exported" {
		t.Fatalf("export lifecycle target=%+v state=%s", target, controlled.state)
	}
	select {
	case <-controlled.exit:
	default:
		t.Fatal("export did not signal supervisor exit")
	}
}

func TestStaleSupervisorRecoveryRemovesOnlyBoundPrivateRuntime(t *testing.T) {
	projectState, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	runtimeBase, err := os.MkdirTemp("/private/tmp", "sunaba-runtime-stale-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runtimeBase, 0700); err != nil {
		t.Fatal(err)
	}
	locator := filepath.Join(projectState, approvalControlLocator)
	if err := writePrivateJSON(locator, approvalLocator{Version: 1, Socket: filepath.Join(runtimeBase, approvalControlSocket)}); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleSupervisor(projectState); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{locator, runtimeBase} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale path remained %s: %v", path, err)
		}
	}
}
func (f *fakeSessionControlTarget) Destroy(context.Context) error { f.destroyed++; return nil }
func (f *fakeSessionControlTarget) ExecOutput(_ context.Context, command []string) (string, error) {
	f.commands = append(f.commands, append([]string(nil), command...))
	return f.output, nil
}

func (b *fakePushBroker) Pending() []gitgateway.PushRequest {
	return append([]gitgateway.PushRequest(nil), b.pending...)
}

func (b *fakePushBroker) Confirm(nonce string, _ gitgateway.PushBinding) error {
	b.confirmed = append(b.confirmed, nonce)
	return nil
}

func TestApprovalsUseSeparatePrivateHostControlChannel(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	recorder, err := audit.NewRecorder(filepath.Join(root, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := gitgateway.NewPushApprovalManager(nil, recorder, "sunaba-project-session", "session")
	if err != nil {
		t.Fatal(err)
	}
	binding := gitgateway.PushBinding{
		ProjectID: "project", Repository: "repository", RemoteName: "origin", RemoteURL: "https://git.example/repository.git",
		Updates: []gitgateway.RefUpdate{{
			Ref: "refs/heads/main", Old: strings.Repeat("1", 40), New: strings.Repeat("2", 40),
		}},
	}
	request, err := manager.NewRequest(binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	broker := &fakePushBroker{pending: []gitgateway.PushRequest{request}}
	runtimeBase, err := os.MkdirTemp("/private/tmp", "sunaba-control-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(runtimeBase)
	if err := os.Chmod(runtimeBase, 0700); err != nil {
		t.Fatal(err)
	}
	control, err := startApprovalControl(root, runtimeBase, broker, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	var output bytes.Buffer
	a := &app{input: strings.NewReader(request.Nonce + "\n"), output: &output, errors: &output}
	approved, err := a.approveActivePushes(context.Background(), root)
	if err != nil || approved != 1 || len(broker.confirmed) != 1 || broker.confirmed[0] != request.Nonce {
		t.Fatalf("approved=%d confirmed=%v error=%v output=%s", approved, broker.confirmed, err, output.String())
	}
	if info, err := os.Lstat(filepath.Join(runtimeBase, approvalControlSocket)); err != nil || info.Mode().Perm() != 0600 || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("control socket info=%v error=%v", info, err)
	}
}

func TestSupervisorControlPausesResumesAndSanitizesShell(t *testing.T) {
	projectState, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(projectState, 0700); err != nil {
		t.Fatal(err)
	}
	runtimeBase, err := os.MkdirTemp("/private/tmp", "sunaba-supervisor-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(runtimeBase)
	if err := os.Chmod(runtimeBase, 0700); err != nil {
		t.Fatal(err)
	}
	target := &fakeSessionControlTarget{output: "safe\n\x1b]52;c;evil\a\u202Ename\n"}
	controlled := &controlledSession{
		active: target, projectID: "project", sessionID: "session", container: "sunaba-project-session",
		runtimeRoot: filepath.Join(runtimeBase, "sunaba-session-session"), workspacePath: "/workspace/sunaba-session",
		attachURL: "http://127.0.0.1:12345", projectState: projectState, serverPassword: strings.Repeat("s", 32),
		expiresAt: time.Now().Add(time.Hour), idleTimeout: 15 * time.Minute, lastActivity: time.Now(), state: "running", exit: make(chan struct{}),
	}
	control, err := startApprovalControl(projectState, runtimeBase, nil, controlled)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	client, err := openSupervisorClient(projectState)
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	approvalApp := &app{input: strings.NewReader(""), output: io.Discard, errors: io.Discard}
	if count, err := approvalApp.approveActivePushes(context.Background(), projectState); err != nil || count != 0 {
		t.Fatalf("Git-disabled supervisor approvals count=%d error=%v", count, err)
	}
	info, err := client.info(context.Background())
	if err != nil || info.State != "running" || info.Container != "sunaba-project-session" {
		t.Fatalf("info=%+v error=%v", info, err)
	}
	if info.IdleSeconds != 900 || info.IdleDeadline.IsZero() {
		t.Fatalf("idle policy missing from supervisor info: %+v", info)
	}
	if err := client.operation(context.Background(), "heartbeat"); err != nil {
		t.Fatal(err)
	}
	if err := client.operation(context.Background(), "pause"); err != nil {
		t.Fatal(err)
	}
	if err := client.operation(context.Background(), "resume"); err != nil {
		t.Fatal(err)
	}
	output, err := client.shell(context.Background(), "printf test")
	if err != nil || !strings.Contains(output, "safe\n") || strings.ContainsAny(output, "\x1b\a\u202E") || !strings.Contains(output, "<U+001B>") {
		t.Fatalf("shell output=%q error=%v", output, err)
	}
	if len(target.commands) != 1 || target.commands[0][len(target.commands[0])-1] != "printf test" {
		t.Fatalf("shell command=%v", target.commands)
	}
	if err := client.operation(context.Background(), "destroy"); err != nil {
		t.Fatal(err)
	}
	if target.paused != 1 || target.resumed != 1 || target.destroyed != 1 {
		t.Fatalf("target lifecycle=%+v", target)
	}
	select {
	case <-controlled.exit:
	default:
		t.Fatal("destroy did not signal supervisor exit")
	}
}

func TestPendingChangePersistsVerifiedMergedViewAndDetectsTampering(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(root, "project")
	mergedSource := filepath.Join(root, "merged-source")
	projectState := filepath.Join(root, "state", "projects", "project")
	for _, directory := range []string{project, mergedSource, projectState} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(project, "file.txt"), []byte("before\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mergedSource, "file.txt"), []byte("after\n"), 0600); err != nil {
		t.Fatal(err)
	}
	baseline, err := workspace.BuildSnapshotManifest(project, workspace.DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	merged, err := workspace.BuildSnapshotManifest(mergedSource, workspace.DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	changes, err := workspace.BuildChangeSet(baseline, merged, workspace.DefaultSnapshotPolicy())
	if err != nil {
		t.Fatal(err)
	}
	active := &session.Session{ProjectID: "project", ProjectRoot: project, SessionID: "session", Container: "sunaba-project-session", Baseline: baseline}
	persisted, err := persistPending(projectState, active, session.ExportResult{MergedRoot: mergedSource, Merged: merged, ChangeSet: changes})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loadPending(projectState, project, "project")
	if err != nil || loaded.ChangeSet.Digest != persisted.ChangeSet.Digest {
		t.Fatalf("loaded=%+v error=%v", loaded, err)
	}
	if err := os.WriteFile(filepath.Join(loaded.MergedRoot, "file.txt"), []byte("tampered\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPending(projectState, project, "project"); err == nil {
		t.Fatal("tampered pending Merged View was accepted")
	}
	if err := removePending(projectState); err != nil {
		t.Fatal(err)
	}
}

func TestProjectInitCreatesPinnedPolicyAndSafeInitialSnapshot(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(base, "data")
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "hello.txt"), []byte("hello\n"), 0600); err != nil {
		t.Fatal(err)
	}
	store := &state.Store{Root: filepath.Join(data, "sunaba")}
	var output bytes.Buffer
	a := &app{store: store, output: &output, errors: &output}
	if err := a.project(context.Background(), []string{"init", project, "--mode", "dev"}); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(store.Root, "projects", state.ProjectID(project), "policy.json")
	loaded, migrated, err := policy.LoadAndMigrate(policyPath, time.Now())
	if err != nil || migrated || loaded.Mode != "dev" || loaded.Dependency.OpenCode != "1.18.16" {
		t.Fatalf("policy=%+v migrated=%v error=%v", loaded, migrated, err)
	}
	if _, err := os.Lstat(filepath.Join(store.Root, "projects", state.ProjectID(project), "initial-snapshot", "hello.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "after.txt"), []byte("after\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(store.Root, "projects", state.ProjectID(project), "initial-snapshot", "after.txt")); !os.IsNotExist(err) {
		t.Fatalf("initial snapshot was not immutable: %v", err)
	}
}
