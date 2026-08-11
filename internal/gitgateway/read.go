package gitgateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

type ReadCapability struct {
	ProjectID        string
	VMID             string
	SessionID        string
	ExpiresAt        time.Time
	MaxRequests      int
	MaxConcurrent    int
	MaxRequestBytes  int64
	MaxResponseBytes int64
	tokenHash        [sha256.Size]byte
}

func NewReadCapability(token, projectID, vmID, sessionID string, expiresAt time.Time) (ReadCapability, error) {
	if len(token) < 32 || !gitIdentityPattern.MatchString(projectID) || !gitIdentityPattern.MatchString(vmID) || !gitIdentityPattern.MatchString(sessionID) || expiresAt.IsZero() {
		return ReadCapability{}, fmt.Errorf("Git Gateway read capability requires bound identities and a high-entropy token")
	}
	return ReadCapability{
		ProjectID: projectID, VMID: vmID, SessionID: sessionID, ExpiresAt: expiresAt,
		MaxRequests: 200, MaxConcurrent: 2, MaxRequestBytes: 4 << 20, MaxResponseBytes: 128 << 20,
		tokenHash: sha256.Sum256([]byte(token)),
	}, nil
}

type ReadAuditEvent struct {
	ProjectID     string
	VMID          string
	SessionID     string
	Operation     string
	Status        int
	RequestBytes  int64
	ResponseBytes int64
	Reason        string
	At            time.Time
}

type ReadConfig struct {
	UpstreamURL         string
	GuestRepositoryPath string
	AuthorizationHeader string
	Capability          ReadCapability
	HTTPClient          *http.Client
	Audit               func(ReadAuditEvent)
	Now                 func() time.Time
}

type ReadGateway struct {
	upstream      *url.URL
	guestPath     string
	authorization string
	capability    ReadCapability
	client        *http.Client
	audit         func(ReadAuditEvent)
	now           func() time.Time
	semaphore     chan struct{}
	mu            sync.Mutex
	requests      int
}

func NewReadGateway(config ReadConfig) (*ReadGateway, error) {
	upstream, err := url.Parse(config.UpstreamURL)
	if err != nil || upstream.Scheme != "https" || upstream.Host == "" || upstream.User != nil || upstream.RawQuery != "" || upstream.Fragment != "" || !strings.HasSuffix(upstream.Path, ".git") {
		return nil, fmt.Errorf("Git Gateway upstream must be a fixed credential-free HTTPS repository URL")
	}
	if config.GuestRepositoryPath == "" || !strings.HasPrefix(config.GuestRepositoryPath, "/") || path.Clean(config.GuestRepositoryPath) != config.GuestRepositoryPath || strings.Contains(config.GuestRepositoryPath, "..") || !strings.HasSuffix(config.GuestRepositoryPath, ".git") || containsControl(config.GuestRepositoryPath) {
		return nil, fmt.Errorf("Git Gateway guest repository path is invalid")
	}
	if config.AuthorizationHeader == "" || len(config.AuthorizationHeader) > 4096 || containsControl(config.AuthorizationHeader) || (!strings.HasPrefix(config.AuthorizationHeader, "Basic ") && !strings.HasPrefix(config.AuthorizationHeader, "Bearer ")) {
		return nil, fmt.Errorf("Git Gateway host authorization is invalid")
	}
	capability := config.Capability
	if capability.MaxRequests <= 0 || capability.MaxConcurrent <= 0 || capability.MaxRequestBytes <= 0 || capability.MaxResponseBytes <= 0 || capability.ExpiresAt.IsZero() || !gitIdentityPattern.MatchString(capability.ProjectID) || !gitIdentityPattern.MatchString(capability.VMID) || !gitIdentityPattern.MatchString(capability.SessionID) {
		return nil, fmt.Errorf("Git Gateway read capability limits are invalid")
	}
	client := config.HTTPClient
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		client = &http.Client{Transport: transport, Timeout: 5 * time.Minute}
	}
	clientCopy := *client
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &ReadGateway{
		upstream: upstream, guestPath: config.GuestRepositoryPath, authorization: config.AuthorizationHeader,
		capability: capability, client: &clientCopy, audit: config.Audit, now: now,
		semaphore: make(chan struct{}, capability.MaxConcurrent),
	}, nil
}

func (g *ReadGateway) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	event := ReadAuditEvent{ProjectID: g.capability.ProjectID, VMID: g.capability.VMID, SessionID: g.capability.SessionID, At: g.now().UTC()}
	defer func() {
		if g.audit != nil {
			g.audit(event)
		}
	}()
	reject := func(status int, reason string) {
		event.Status, event.Reason = status, reason
		http.Error(response, http.StatusText(status), status)
	}
	operation, suffix, ok := g.route(request)
	event.Operation = operation
	if !ok {
		reject(http.StatusNotFound, "route_not_allowed")
		return
	}
	if !g.authorized(request.Header.Get("Authorization")) || !g.now().Before(g.capability.ExpiresAt) {
		reject(http.StatusUnauthorized, "invalid_or_expired_capability")
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
	body, err := io.ReadAll(io.LimitReader(request.Body, g.capability.MaxRequestBytes+1))
	if err != nil || int64(len(body)) > g.capability.MaxRequestBytes {
		reject(http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	event.RequestBytes = int64(len(body))
	target := *g.upstream
	target.Path = strings.TrimSuffix(g.upstream.Path, "/") + suffix
	target.RawQuery = request.URL.RawQuery
	upstreamRequest, err := http.NewRequestWithContext(request.Context(), request.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		reject(http.StatusBadGateway, "upstream_request_failed")
		return
	}
	upstreamRequest.Header.Set("Authorization", g.authorization)
	upstreamRequest.Header.Set("User-Agent", "sunaba-git-gateway/1")
	for _, header := range []string{"Accept", "Content-Type", "Git-Protocol"} {
		if value := request.Header.Get(header); value != "" && len(value) <= 1024 && !containsControl(value) {
			upstreamRequest.Header.Set(header, value)
		}
	}
	upstreamResponse, err := g.client.Do(upstreamRequest)
	if err != nil {
		if request.Context().Err() != nil || errors.Is(err, context.Canceled) {
			event.Status, event.Reason = 499, "canceled"
			return
		}
		reject(http.StatusBadGateway, "upstream_unavailable")
		return
	}
	defer upstreamResponse.Body.Close()
	for _, header := range []string{"Content-Type", "Cache-Control", "Expires", "Pragma"} {
		if value := upstreamResponse.Header.Get(header); value != "" {
			response.Header().Set(header, value)
		}
	}
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(upstreamResponse.StatusCode)
	event.Status = upstreamResponse.StatusCode
	written, copyErr := copyGitResponse(response, upstreamResponse.Body, g.capability.MaxResponseBytes)
	event.ResponseBytes = written
	if copyErr != nil {
		event.Reason = "response_too_large_or_copy_failed"
	}
}

func (g *ReadGateway) route(request *http.Request) (string, string, bool) {
	if request.Method == http.MethodGet && request.URL.Path == g.guestPath+"/info/refs" && request.URL.RawQuery == "service=git-upload-pack" {
		return "clone_fetch", "/info/refs", true
	}
	if request.Method == http.MethodPost && request.URL.Path == g.guestPath+"/git-upload-pack" && request.URL.RawQuery == "" {
		return "clone_fetch", "/git-upload-pack", true
	}
	return "", "", false
}

func (g *ReadGateway) authorized(header string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	presented := sha256.Sum256([]byte(strings.TrimPrefix(header, prefix)))
	return subtle.ConstantTimeCompare(presented[:], g.capability.tokenHash[:]) == 1
}

func copyGitResponse(destination io.Writer, source io.Reader, maximum int64) (int64, error) {
	limited := &io.LimitedReader{R: source, N: maximum}
	written, err := io.Copy(destination, limited)
	if err != nil {
		return written, err
	}
	var extra [1]byte
	if count, readErr := source.Read(extra[:]); count != 0 || (readErr != nil && readErr != io.EOF) {
		return written, fmt.Errorf("Git Gateway response exceeds limit")
	}
	return written, nil
}
