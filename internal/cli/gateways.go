package cli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"sunaba/internal/audit"
	"sunaba/internal/gitgateway"
	"sunaba/internal/policy"
	"sunaba/internal/session"
	"sunaba/internal/webgateway"
)

type configuredGateways struct {
	gitHandler http.Handler
	gitToken   string
	gitClose   func() error
	gitBroker  *gitgateway.HookBroker
	webHandler http.Handler
	webToken   string
	webClose   func() error
}

func (a *app) configureGateways(ctx context.Context, projectPolicy policy.ProjectPolicy, projectState, runtimeBase, vmID, sessionID string, expiresAt time.Time, recorder *audit.Recorder) (configuredGateways, error) {
	var configured configuredGateways
	if len(projectPolicy.Git.Remotes) > 1 {
		return configuredGateways{}, fmt.Errorf("the MVP Git Gateway supports exactly one fixed remote per Project")
	}
	if len(projectPolicy.Git.Remotes) == 1 {
		gitConfigured, err := a.configureGitGateway(ctx, projectPolicy, projectState, runtimeBase, vmID, sessionID, expiresAt, recorder)
		if err != nil {
			return configuredGateways{}, err
		}
		configured.gitHandler = gitConfigured.gitHandler
		configured.gitToken = gitConfigured.gitToken
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

func (a *app) configureGitGateway(ctx context.Context, projectPolicy policy.ProjectPolicy, projectState, runtimeBase, vmID, sessionID string, expiresAt time.Time, recorder *audit.Recorder) (configuredGateways, error) {
	remote := projectPolicy.Git.Remotes[0]
	authorization, err := hostGitAuthorization(ctx, remote)
	if err != nil {
		return configuredGateways{}, err
	}
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return configuredGateways{}, fmt.Errorf("host Git is required for the configured Git Gateway")
	}
	gitPath, err = filepath.Abs(gitPath)
	if err != nil {
		return configuredGateways{}, err
	}
	repository, err := ensureGitQuarantine(ctx, gitPath, projectState, remote)
	if err != nil {
		return configuredGateways{}, err
	}
	approvals, err := gitgateway.NewPushApprovalManager(nil, recorder, vmID, sessionID)
	if err != nil {
		return configuredGateways{}, err
	}
	resolver := gitgateway.RepositoryResolver{
		GitPath: gitPath, RepositoryPath: repository, ProjectID: projectPolicy.ProjectID,
		Repository: "repository", RemoteName: "origin", RemoteURL: remote,
	}
	executor := gitgateway.PushExecutor{
		Resolver: resolver, Approvals: approvals, AuthorizationHeader: authorization,
		Audit: recorder, VMID: vmID, SessionID: sessionID,
	}
	if err := executor.Sync(ctx); err != nil {
		return configuredGateways{}, err
	}
	hookToken, err := session.NewSecret()
	if err != nil {
		return configuredGateways{}, err
	}
	hookHelper, err := siblingExecutable("sunaba-git-hook")
	if err != nil {
		return configuredGateways{}, err
	}
	hookSocket := filepath.Join(runtimeBase, "git-hook.sock")
	brokerContext, cancelBroker := context.WithCancel(context.Background())
	broker, err := gitgateway.StartHookBroker(brokerContext, hookSocket, hookToken, approvals, executor, 5*time.Minute, nil)
	if err != nil {
		cancelBroker()
		return configuredGateways{}, err
	}
	closeBroker := func() error {
		cancelBroker()
		return broker.Close()
	}
	gitToken, err := session.NewSecret()
	if err != nil {
		_ = closeBroker()
		return configuredGateways{}, err
	}
	capability, err := gitgateway.NewReadCapability(gitToken, projectPolicy.ProjectID, vmID, sessionID, expiresAt)
	if err != nil {
		_ = closeBroker()
		return configuredGateways{}, err
	}
	auditGit := func(event gitgateway.ReadAuditEvent) {
		outcome := "success"
		if event.Status < http.StatusOK || event.Status >= http.StatusBadRequest {
			outcome = "rejected"
		}
		_ = recorder.Append(audit.BoundaryEvent{
			At: event.At, Category: "git", Action: "git." + event.Operation, Outcome: outcome,
			ProjectID: event.ProjectID, VMID: event.VMID, SessionID: event.SessionID,
			Details: map[string]string{
				"status": strconv.Itoa(event.Status), "request_bytes": strconv.FormatInt(event.RequestBytes, 10),
				"response_bytes": strconv.FormatInt(event.ResponseBytes, 10), "reason": event.Reason,
			},
		})
	}
	readGateway, err := gitgateway.NewReadGateway(gitgateway.ReadConfig{
		UpstreamURL: remote, GuestRepositoryPath: "/repository.git", AuthorizationHeader: authorization,
		Capability: capability, Audit: auditGit,
	})
	if err != nil {
		_ = closeBroker()
		return configuredGateways{}, err
	}
	receiveGateway, err := gitgateway.NewReceiveGateway(gitgateway.ReceiveConfig{
		GitPath: gitPath, RepositoryPath: repository, GuestRepositoryPath: "/repository.git",
		HookHelperPath: hookHelper, HookSocketPath: hookSocket, HookToken: hookToken, Capability: capability,
		MaxRequestBytes: 64 << 20, MaxResponseBytes: 4 << 20, MaxConcurrent: 1,
		BeforeAdvertise: executor.Sync, Audit: auditGit,
	})
	if err != nil {
		_ = closeBroker()
		return configuredGateways{}, err
	}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if strings.Contains(request.URL.RawQuery, "git-receive-pack") || strings.HasSuffix(request.URL.Path, "/git-receive-pack") {
			receiveGateway.ServeHTTP(response, request)
			return
		}
		readGateway.ServeHTTP(response, request)
	})
	return configuredGateways{gitHandler: handler, gitToken: gitToken, gitClose: closeBroker, gitBroker: broker}, nil
}

func hostGitAuthorization(ctx context.Context, remote string) (string, error) {
	parsed, err := url.Parse(remote)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !strings.HasSuffix(parsed.Path, ".git") {
		return "", fmt.Errorf("the production Git Gateway requires one credential-free fixed HTTPS remote ending in .git")
	}
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return "", fmt.Errorf("host Git is required to obtain the configured upstream credential")
	}
	command := exec.CommandContext(ctx, gitPath, "credential", "fill")
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=1")
	command.Stdin = strings.NewReader("protocol=https\nhost=" + parsed.Host + "\npath=" + strings.TrimPrefix(parsed.Path, "/") + "\n\n")
	var output strings.Builder
	command.Stdout = &boundedStringWriter{builder: &output, remaining: 64 << 10}
	command.Stderr = nil
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("host Git credential lookup failed for the configured remote")
	}
	return parseGitCredential(output.String())
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

type boundedStringWriter struct {
	builder   *strings.Builder
	remaining int
}

func (w *boundedStringWriter) Write(data []byte) (int, error) {
	if len(data) > w.remaining {
		return 0, fmt.Errorf("bounded output exceeded")
	}
	w.remaining -= len(data)
	return w.builder.Write(data)
}

func ensureGitQuarantine(ctx context.Context, gitPath, projectState, remote string) (string, error) {
	digest := fileNameDigest(remote)
	root := filepath.Join(projectState, "git")
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	repository := filepath.Join(root, "repository-"+digest[:16]+".git")
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
	info, err := os.Lstat(path)
	var stat unix.Stat_t
	statErr := unix.Lstat(path, &stat)
	canonical, canonicalErr := filepath.EvalSymlinks(path)
	if err != nil || statErr != nil || canonicalErr != nil || canonical != path || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > maximum || stat.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("private policy artifact is unsafe: %s", filepath.Base(path))
	}
	return os.ReadFile(path)
}
