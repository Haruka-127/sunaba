package gitgateway

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type ReceiveConfig struct {
	GitPath             string
	RepositoryPath      string
	GuestRepositoryPath string
	HookHelperPath      string
	HookSocketPath      string
	HookToken           string
	Capability          ReadCapability
	MaxRequestBytes     int64
	MaxResponseBytes    int64
	MaxConcurrent       int
	Audit               func(ReadAuditEvent)
	Now                 func() time.Time
}

type ReceiveGateway struct {
	backend          http.Handler
	guestPath        string
	capability       ReadCapability
	maxRequestBytes  int64
	maxResponseBytes int64
	semaphore        chan struct{}
	audit            func(ReadAuditEvent)
	now              func() time.Time
	mu               sync.Mutex
	requests         int
}

func NewReceiveGateway(config ReceiveConfig) (*ReceiveGateway, error) {
	repository, err := secureRepositoryPath(config.RepositoryPath)
	if err != nil {
		return nil, err
	}
	if config.GuestRepositoryPath != "/"+filepath.Base(repository) || !strings.HasSuffix(config.GuestRepositoryPath, ".git") {
		return nil, fmt.Errorf("Git receive guest path must exactly identify the host quarantine")
	}
	if len(config.HookToken) < 32 || !filepathIsPrivateSocketParent(config.HookSocketPath) || config.MaxRequestBytes <= 0 || config.MaxResponseBytes <= 0 || config.MaxConcurrent <= 0 {
		return nil, fmt.Errorf("Git receive gateway limits and hook channel are invalid")
	}
	capability := config.Capability
	if capability.MaxRequests <= 0 || capability.ExpiresAt.IsZero() || !gitIdentityPattern.MatchString(capability.ProjectID) || !gitIdentityPattern.MatchString(capability.VMID) || !gitIdentityPattern.MatchString(capability.SessionID) {
		return nil, fmt.Errorf("Git receive gateway capability is invalid")
	}
	gitPath := config.GitPath
	if gitPath == "" {
		gitPath, err = exec.LookPath("git")
		if err != nil {
			return nil, fmt.Errorf("locate host Git: %w", err)
		}
	}
	if err := installPreReceiveHook(repository, config.HookHelperPath, gitPath); err != nil {
		return nil, err
	}
	backend := &cgi.Handler{
		Path: gitPath, Args: []string{"http-backend"}, Dir: filepath.Dir(repository),
		Env: []string{
			"GIT_PROJECT_ROOT=" + filepath.Dir(repository),
			"GIT_HTTP_EXPORT_ALL=1",
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
			"SUNABA_GIT_HOOK_SOCKET=" + config.HookSocketPath,
			"SUNABA_GIT_HOOK_TOKEN=" + config.HookToken,
		},
		Stderr: io.Discard,
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &ReceiveGateway{
		backend: backend, guestPath: config.GuestRepositoryPath, capability: capability,
		maxRequestBytes: config.MaxRequestBytes, maxResponseBytes: config.MaxResponseBytes,
		semaphore: make(chan struct{}, config.MaxConcurrent), audit: config.Audit, now: now,
	}, nil
}

func (g *ReceiveGateway) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	event := ReadAuditEvent{ProjectID: g.capability.ProjectID, VMID: g.capability.VMID, SessionID: g.capability.SessionID, Operation: "push", At: g.now().UTC()}
	defer func() {
		if g.audit != nil {
			g.audit(event)
		}
	}()
	reject := func(status int, reason string) {
		event.Status, event.Reason = status, reason
		http.Error(response, http.StatusText(status), status)
	}
	if !g.route(request) {
		reject(http.StatusNotFound, "route_not_allowed")
		return
	}
	if !authorizedCapability(request.Header.Get("Authorization"), g.capability.tokenHash) || !g.now().Before(g.capability.ExpiresAt) {
		reject(http.StatusUnauthorized, "invalid_or_expired_capability")
		return
	}
	if request.ContentLength > g.maxRequestBytes {
		reject(http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	g.mu.Lock()
	if g.requests >= g.capability.MaxRequests {
		g.mu.Unlock()
		reject(http.StatusTooManyRequests, "request_quota_exceeded")
		return
	}
	g.requests++
	g.mu.Unlock()
	select {
	case g.semaphore <- struct{}{}:
		defer func() { <-g.semaphore }()
	default:
		reject(http.StatusTooManyRequests, "concurrency_exceeded")
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, g.maxRequestBytes)
	limited := &limitedResponseWriter{ResponseWriter: response, remaining: g.maxResponseBytes}
	g.backend.ServeHTTP(limited, request)
	event.Status = limited.status
	event.ResponseBytes = limited.written
	if limited.exceeded {
		event.Reason = "response_too_large"
	}
}

func (g *ReceiveGateway) route(request *http.Request) bool {
	return (request.Method == http.MethodGet && request.URL.Path == g.guestPath+"/info/refs" && request.URL.RawQuery == "service=git-receive-pack") ||
		(request.Method == http.MethodPost && request.URL.Path == g.guestPath+"/git-receive-pack" && request.URL.RawQuery == "")
}

func authorizedCapability(header string, expected [sha256.Size]byte) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	presented := sha256.Sum256([]byte(strings.TrimPrefix(header, prefix)))
	return subtle.ConstantTimeCompare(presented[:], expected[:]) == 1
}

type limitedResponseWriter struct {
	http.ResponseWriter
	remaining int64
	written   int64
	status    int
	exceeded  bool
}

func (w *limitedResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *limitedResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if int64(len(data)) > w.remaining {
		data = data[:w.remaining]
		w.exceeded = true
	}
	count, err := w.ResponseWriter.Write(data)
	w.remaining -= int64(count)
	w.written += int64(count)
	if w.exceeded && err == nil {
		err = fmt.Errorf("Git receive response exceeds limit")
	}
	return count, err
}

func installPreReceiveHook(repository, helperPath, gitPath string) error {
	if !filepath.IsAbs(helperPath) || filepath.Clean(helperPath) != helperPath || !filepath.IsAbs(gitPath) {
		return fmt.Errorf("Git hook helper and host Git paths must be absolute")
	}
	helperInfo, err := os.Lstat(helperPath)
	canonicalHelper, canonicalErr := filepath.EvalSymlinks(helperPath)
	if err != nil || canonicalErr != nil || canonicalHelper != helperPath || !helperInfo.Mode().IsRegular() || helperInfo.Mode()&0111 == 0 || helperInfo.Mode()&os.ModeSymlink != 0 || helperInfo.Size() <= 0 || helperInfo.Size() > 128<<20 {
		return fmt.Errorf("Git pre-receive helper must be a fixed executable regular file")
	}
	hooks := filepath.Join(repository, "sunaba-hooks")
	if err := os.Mkdir(hooks, 0700); err != nil {
		return fmt.Errorf("create private Git hooks directory: %w", err)
	}
	source, err := os.Open(helperPath)
	if err != nil {
		return err
	}
	defer source.Close()
	hookPath := filepath.Join(hooks, "pre-receive")
	fd, err := unix.Open(hookPath, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0700)
	if err != nil {
		return err
	}
	destination := os.NewFile(uintptr(fd), hookPath)
	_, copyErr := io.Copy(destination, source)
	syncErr := destination.Sync()
	closeErr := destination.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		return fmt.Errorf("install Git pre-receive helper")
	}
	runner := repositoryGit{binary: gitPath, repository: repository}
	if err := runner.run(context.Background(), "config", "core.hooksPath", hooks); err != nil {
		return fmt.Errorf("configure Git pre-receive hook")
	}
	if err := runner.run(context.Background(), "config", "http.receivepack", "true"); err != nil {
		return fmt.Errorf("enable fixed Git receive-pack endpoint")
	}
	if err := runner.run(context.Background(), "config", "receive.denyDeleteCurrent", "ignore"); err != nil {
		return fmt.Errorf("enable approved Git ref deletion")
	}
	return nil
}
