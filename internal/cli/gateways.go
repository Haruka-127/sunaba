package cli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"sunaba/internal/audit"
	"sunaba/internal/boundedexec"
	"sunaba/internal/gitgateway"
	"sunaba/internal/policy"
	"sunaba/internal/securefs"
	"sunaba/internal/session"
	"sunaba/internal/webgateway"
)

type configuredGateways struct {
	gitHandler http.Handler
	gitRemotes []session.GitRemote
	gitClose   func() error
	gitBroker  pushApprovalBroker
	webHandler http.Handler
	webToken   string
	webClose   func() error
}

type configuredGitRemote struct {
	handler http.Handler
	remote  session.GitRemote
	close   func() error
	broker  *gitgateway.HookBroker
}

type multiPushBroker struct {
	brokers []*gitgateway.HookBroker
}

type rotatingPushBroker struct {
	mu      sync.RWMutex
	current pushApprovalBroker
}

func (b *rotatingPushBroker) Set(current pushApprovalBroker) {
	b.mu.Lock()
	b.current = current
	b.mu.Unlock()
}

func (b *rotatingPushBroker) Pending() []gitgateway.PushRequest {
	b.mu.RLock()
	current := b.current
	b.mu.RUnlock()
	if current == nil {
		return nil
	}
	return current.Pending()
}

func (b *rotatingPushBroker) Confirm(nonce string, binding gitgateway.PushBinding) error {
	b.mu.RLock()
	current := b.current
	b.mu.RUnlock()
	if current == nil {
		return fmt.Errorf("Git push approval is not pending")
	}
	return current.Confirm(nonce, binding)
}

func (b *rotatingPushBroker) Reject(nonce string, binding gitgateway.PushBinding) error {
	b.mu.RLock()
	current := b.current
	b.mu.RUnlock()
	if current == nil {
		return fmt.Errorf("Git push approval is not pending")
	}
	return current.Reject(nonce, binding)
}

func (b *multiPushBroker) Pending() []gitgateway.PushRequest {
	var pending []gitgateway.PushRequest
	for _, broker := range b.brokers {
		pending = append(pending, broker.Pending()...)
	}
	return pending
}

func (b *multiPushBroker) Confirm(nonce string, binding gitgateway.PushBinding) error {
	for _, broker := range b.brokers {
		for _, pending := range broker.Pending() {
			if pending.Nonce == nonce {
				return broker.Confirm(nonce, binding)
			}
		}
	}
	return fmt.Errorf("Git push approval is not pending")
}

func (b *multiPushBroker) Reject(nonce string, binding gitgateway.PushBinding) error {
	for _, broker := range b.brokers {
		for _, pending := range broker.Pending() {
			if pending.Nonce == nonce {
				return broker.Reject(nonce, binding)
			}
		}
	}
	return fmt.Errorf("Git push approval is not pending")
}

func (a *app) configureGateways(ctx context.Context, projectPolicy policy.ProjectPolicy, projectState, runtimeBase, vmID, sessionID string, expiresAt time.Time, recorder *audit.Recorder) (configuredGateways, error) {
	var configured configuredGateways
	if len(projectPolicy.Git.Remotes) > 0 {
		gitConfigured, err := a.configureGitGateways(ctx, projectPolicy, projectState, runtimeBase, vmID, sessionID, expiresAt, recorder)
		if err != nil {
			return configuredGateways{}, err
		}
		configured.gitHandler = gitConfigured.gitHandler
		configured.gitRemotes = gitConfigured.gitRemotes
		configured.gitClose = gitConfigured.gitClose
		configured.gitBroker = gitConfigured.gitBroker
	}
	if projectPolicy.Web.Enabled {
		gateway, token, err := configureWebGateway(projectPolicy, projectState, vmID, sessionID, expiresAt, recorder)
		if err != nil {
			if configured.gitClose != nil {
				_ = configured.gitClose()
			}
			return configuredGateways{}, err
		}
		configured.webHandler = gateway
		configured.webToken = token
		configured.webClose = func() error { gateway.Revoke(); return nil }
	}
	return configured, nil
}

func (a *app) configureGitGateways(ctx context.Context, projectPolicy policy.ProjectPolicy, projectState, runtimeBase, vmID, sessionID string, expiresAt time.Time, recorder *audit.Recorder) (configuredGateways, error) {
	configuredRemotes := make([]configuredGitRemote, 0, len(projectPolicy.Git.Remotes))
	routes := make(map[string]http.Handler, len(projectPolicy.Git.Remotes))
	brokers := make([]*gitgateway.HookBroker, 0, len(projectPolicy.Git.Remotes))
	guestRemotes := make([]session.GitRemote, 0, len(projectPolicy.Git.Remotes))
	closeConfigured := func() error {
		var closeErr error
		for index := len(configuredRemotes) - 1; index >= 0; index-- {
			if configuredRemotes[index].close != nil {
				closeErr = errors.Join(closeErr, configuredRemotes[index].close())
			}
		}
		return closeErr
	}
	for _, remote := range projectPolicy.Git.Remotes {
		configured, err := a.configureGitRemoteGateway(ctx, projectPolicy, remote, projectState, runtimeBase, vmID, sessionID, expiresAt, recorder)
		if err != nil {
			_ = closeConfigured()
			return configuredGateways{}, err
		}
		configuredRemotes = append(configuredRemotes, configured)
		routes["/"+remote.Name+".git"] = configured.handler
		guestRemotes = append(guestRemotes, configured.remote)
		brokers = append(brokers, configured.broker)
	}
	return configuredGateways{
		gitHandler: newGitGatewayMux(routes), gitRemotes: guestRemotes, gitClose: closeConfigured,
		gitBroker: &multiPushBroker{brokers: brokers},
	}, nil
}

func newGitGatewayMux(routes map[string]http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		for guestPath, route := range routes {
			if strings.HasPrefix(request.URL.Path, guestPath+"/") {
				route.ServeHTTP(response, request)
				return
			}
		}
		http.NotFound(response, request)
	})
}

func (a *app) configureGitRemoteGateway(ctx context.Context, projectPolicy policy.ProjectPolicy, remote policy.GitRemotePolicy, projectState, runtimeBase, vmID, sessionID string, expiresAt time.Time, recorder *audit.Recorder) (configuredGitRemote, error) {
	authorization, err := hostGitAuthorization(ctx, remote.URL)
	if err != nil {
		return configuredGitRemote{}, err
	}
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return configuredGitRemote{}, fmt.Errorf("host Git is required for the configured Git Gateway")
	}
	gitPath, err = filepath.Abs(gitPath)
	if err != nil {
		return configuredGitRemote{}, err
	}
	repository, err := ensureGitQuarantine(ctx, gitPath, projectState, remote.Name, remote.URL)
	if err != nil {
		return configuredGitRemote{}, err
	}
	approvals, err := gitgateway.NewPushApprovalManager(nil, recorder, vmID, sessionID)
	if err != nil {
		return configuredGitRemote{}, err
	}
	resolver := gitgateway.RepositoryResolver{
		GitPath: gitPath, RepositoryPath: repository, ProjectID: projectPolicy.ProjectID,
		Repository: remote.Name, RemoteName: remote.Name, RemoteURL: remote.URL,
	}
	executor := gitgateway.PushExecutor{
		Resolver: resolver, Approvals: approvals, AuthorizationHeader: authorization,
		Audit: recorder, VMID: vmID, SessionID: sessionID,
	}
	if err := executor.Sync(ctx); err != nil {
		return configuredGitRemote{}, err
	}
	hookToken, err := session.NewSecret()
	if err != nil {
		return configuredGitRemote{}, err
	}
	hookHelper, err := siblingExecutable("sunaba-git-hook")
	if err != nil {
		return configuredGitRemote{}, err
	}
	hookSocket := filepath.Join(runtimeBase, "git-hook-"+remote.Name+".sock")
	brokerContext, cancelBroker := context.WithCancel(context.Background())
	broker, err := gitgateway.StartHookBroker(brokerContext, hookSocket, hookToken, approvals, executor, 5*time.Minute, nil)
	if err != nil {
		cancelBroker()
		return configuredGitRemote{}, err
	}
	closeBroker := func() error {
		cancelBroker()
		return broker.Close()
	}
	gitToken, err := session.NewSecret()
	if err != nil {
		_ = closeBroker()
		return configuredGitRemote{}, err
	}
	capability, err := gitgateway.NewReadCapability(gitToken, projectPolicy.ProjectID, vmID, sessionID, expiresAt)
	if err != nil {
		_ = closeBroker()
		return configuredGitRemote{}, err
	}
	auditGit := func(event gitgateway.ReadAuditEvent) error {
		outcome := "success"
		if event.Status < http.StatusOK || event.Status >= http.StatusBadRequest {
			outcome = "rejected"
		}
		return recorder.Append(audit.BoundaryEvent{
			At: event.At, Category: "git", Action: "git." + event.Operation, Outcome: outcome,
			ProjectID: event.ProjectID, VMID: event.VMID, SessionID: event.SessionID,
			Details: map[string]string{
				"status": strconv.Itoa(event.Status), "request_bytes": strconv.FormatInt(event.RequestBytes, 10),
				"response_bytes": strconv.FormatInt(event.ResponseBytes, 10), "reason": event.Reason, "remote": remote.Name,
			},
		})
	}
	readGateway, err := gitgateway.NewReadGateway(gitgateway.ReadConfig{
		UpstreamURL: remote.URL, GuestRepositoryPath: "/" + remote.Name + ".git", AuthorizationHeader: authorization,
		Capability: capability, Audit: auditGit,
	})
	if err != nil {
		_ = closeBroker()
		return configuredGitRemote{}, err
	}
	receiveGateway, err := gitgateway.NewReceiveGateway(gitgateway.ReceiveConfig{
		GitPath: gitPath, RepositoryPath: repository, GuestRepositoryPath: "/" + remote.Name + ".git",
		HookHelperPath: hookHelper, HookSocketPath: hookSocket, HookToken: hookToken, Capability: capability,
		MaxRequestBytes: 64 << 20, MaxResponseBytes: 4 << 20, MaxConcurrent: 1,
		BeforeAdvertise: executor.Sync, Audit: auditGit,
	})
	if err != nil {
		_ = closeBroker()
		return configuredGitRemote{}, err
	}
	closeGateway := func() error {
		readGateway.Revoke()
		receiveGateway.Revoke()
		return closeBroker()
	}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if strings.Contains(request.URL.RawQuery, "git-receive-pack") || strings.HasSuffix(request.URL.Path, "/git-receive-pack") {
			receiveGateway.ServeHTTP(response, request)
			return
		}
		readGateway.ServeHTTP(response, request)
	})
	return configuredGitRemote{
		handler: handler, remote: session.GitRemote{Name: remote.Name, Token: gitToken},
		close: closeGateway, broker: broker,
	}, nil
}

func hostGitAuthorization(ctx context.Context, remote string) (string, error) {
	parsed, err := url.Parse(remote)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !strings.HasSuffix(parsed.Path, ".git") {
		return "", fmt.Errorf("the production Git Gateway requires a credential-free fixed HTTPS remote ending in .git")
	}
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return "", fmt.Errorf("host Git is required to obtain the configured upstream credential")
	}
	credentialContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(credentialContext, gitPath, "credential", "fill")
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	command.Stdin = strings.NewReader("protocol=https\nhost=" + parsed.Host + "\npath=" + strings.TrimPrefix(parsed.Path, "/") + "\n\n")
	result, err := boundedexec.Capture(command, boundedexec.Limits{StdoutBytes: 64 << 10, StderrBytes: 16 << 10})
	if err != nil {
		return "", fmt.Errorf("host Git credential lookup failed for the configured remote")
	}
	return parseGitCredential(string(result.Stdout))
}

func parseGitCredential(output string) (string, error) {
	fields := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok || key == "" || strings.ContainsAny(key+value, "\x00\r\n") {
			return "", fmt.Errorf("host Git credential helper returned an invalid response")
		}
		if _, exists := fields[key]; exists {
			return "", fmt.Errorf("host Git credential helper returned duplicate fields")
		}
		fields[key] = value
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("host Git credential helper response exceeded its bound")
	}
	if strings.EqualFold(fields["authtype"], "bearer") && fields["credential"] != "" {
		return "Bearer " + fields["credential"], nil
	}
	if fields["username"] == "" || fields["password"] == "" || strings.Contains(fields["username"], ":") {
		return "", fmt.Errorf("host Git credential helper did not provide a supported HTTPS credential")
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(fields["username"]+":"+fields["password"])), nil
}

func ensureGitQuarantine(ctx context.Context, gitPath, projectState, remoteName, remoteURL string) (string, error) {
	if err := policy.ValidateGitRemote(policy.GitRemotePolicy{Name: remoteName, URL: remoteURL}); err != nil {
		return "", err
	}
	digest := fileNameDigest(remoteURL)
	root := filepath.Join(projectState, "git")
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	remoteRoot := filepath.Join(root, "remote-"+digest[:16])
	if err := os.MkdirAll(remoteRoot, 0700); err != nil {
		return "", err
	}
	for _, directory := range []string{root, remoteRoot} {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
			return "", fmt.Errorf("host Git quarantine directory is unsafe")
		}
	}
	repository := filepath.Join(remoteRoot, remoteName+".git")
	if info, err := os.Lstat(repository); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
			return "", fmt.Errorf("host Git quarantine is unsafe")
		}
		return repository, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.Mkdir(repository, 0700); err != nil {
		return "", err
	}
	command := exec.CommandContext(ctx, gitPath, "init", "--bare", repository)
	command.Env = []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "LC_ALL=C", "PATH=/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}
	if err := command.Run(); err != nil {
		_ = os.RemoveAll(repository)
		return "", fmt.Errorf("initialize host Git quarantine: operation failed")
	}
	if err := os.Chmod(repository, 0700); err != nil {
		return "", err
	}
	return repository, nil
}

func fileNameDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func configureWebGateway(projectPolicy policy.ProjectPolicy, projectState, vmID, sessionID string, expiresAt time.Time, recorder *audit.Recorder) (*webgateway.Gateway, string, error) {
	manifestPath := filepath.Join(projectState, "web", "blocklist.json")
	dataPath := filepath.Join(projectState, "web", "blocklist.hosts")
	if projectPolicy.Web.BlocklistManifest != manifestPath {
		return nil, "", fmt.Errorf("Web blocklist manifest is not bound to this Project state")
	}
	manifestData, err := readOwnedPrivateFile(manifestPath, 1<<20)
	if err != nil {
		return nil, "", err
	}
	blocklistData, err := readOwnedPrivateFile(dataPath, 8<<20)
	if err != nil {
		return nil, "", err
	}
	manifest, err := webgateway.ParseBlocklistManifest(manifestData)
	if err != nil || manifest.SHA256 != projectPolicy.Web.BlocklistSHA256 {
		return nil, "", fmt.Errorf("Web blocklist manifest does not match Project policy")
	}
	snapshot, err := webgateway.LoadBlocklist(manifest, blocklistData, time.Now())
	if err != nil {
		return nil, "", err
	}
	webPolicy := webgateway.Policy{Rules: projectPolicy.Web.Rules, BlockedDomains: snapshot.Domains}
	policyDigest, err := webPolicy.Digest()
	if err != nil {
		return nil, "", err
	}
	token, err := session.NewSecret()
	if err != nil {
		return nil, "", err
	}
	capability, err := webgateway.NewCapability(token, projectPolicy.ProjectID, vmID, sessionID, policyDigest, expiresAt)
	if err != nil {
		return nil, "", err
	}
	capability.MaxRequests = projectPolicy.Web.MaxRequests
	capability.MaxConcurrent = projectPolicy.Web.MaxConcurrent
	capability.MaxConnectTime = time.Duration(projectPolicy.Web.MaxConnectSeconds) * time.Second
	capability.MaxUploadBytes = projectPolicy.Web.MaxUploadBytes
	capability.MaxDownloadBytes = projectPolicy.Web.MaxDownloadBytes
	capability.MaxTotalBytes = projectPolicy.Web.MaxTotalBytes
	gateway, err := webgateway.New(webgateway.Config{
		Policy: webPolicy, Capability: capability,
		Audit: func(event webgateway.AuditEvent) error {
			outcome := "rejected"
			if event.Allowed {
				outcome = "success"
			}
			return recorder.Append(audit.BoundaryEvent{
				At: event.At, Category: "web", Action: "web.request", Outcome: outcome,
				ProjectID: event.ProjectID, VMID: event.VMID, SessionID: event.SessionID,
				Details: map[string]string{
					"category": event.Category, "hostname": event.Hostname, "port": strconv.Itoa(int(event.Port)),
					"method": event.Method, "reason": event.Reason, "upload_bytes": strconv.FormatInt(event.UploadBytes, 10),
					"download_bytes": strconv.FormatInt(event.DownloadBytes, 10), "duration_ms": strconv.FormatInt(event.Duration.Milliseconds(), 10),
				},
			})
		},
	})
	return gateway, token, err
}

func readOwnedPrivateFile(path string, maximum int64) ([]byte, error) {
	data, err := securefs.ReadOwnedRegular(path, maximum)
	if err != nil || len(data) == 0 {
		return nil, fmt.Errorf("private policy artifact is unsafe: %s", filepath.Base(path))
	}
	return data, nil
}
