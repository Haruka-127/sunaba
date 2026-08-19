package gitgateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync/atomic"
	"time"

	corecapability "sunaba/internal/capability"
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
	authority        *corecapability.Authority
	auditFailed      *atomic.Bool
}

func NewReadCapability(token, projectID, vmID, sessionID string, expiresAt time.Time) (ReadCapability, error) {
	authority, err := corecapability.NewAuthority(token, corecapability.Binding{ProjectID: projectID, VMID: vmID, SessionID: sessionID}, expiresAt)
	if err != nil {
		return ReadCapability{}, fmt.Errorf("Git Gateway read capability requires bound identities and a high-entropy token")
	}
	return ReadCapability{
		ProjectID: projectID, VMID: vmID, SessionID: sessionID, ExpiresAt: expiresAt,
		MaxRequests: 200, MaxConcurrent: 2, MaxRequestBytes: 4 << 20, MaxResponseBytes: 128 << 20,
		authority: authority, auditFailed: &atomic.Bool{},
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
	Audit               func(ReadAuditEvent) error
	Now                 func() time.Time
}

type ReadGateway struct {
	upstream      *url.URL
	guestPath     string
	authorization string
	capability    ReadCapability
	client        *http.Client
	audit         func(ReadAuditEvent) error
	now           func() time.Time
	gate          *corecapability.Gate
}

func (g *ReadGateway) Revoke() {
	if g != nil && g.gate != nil {
		g.gate.Revoke()
	}
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
	if config.Audit == nil {
		return nil, fmt.Errorf("Git Gateway requires a host audit sink")
	}
	capability := config.Capability
	binding := corecapability.Binding{ProjectID: capability.ProjectID, VMID: capability.VMID, SessionID: capability.SessionID}
	if capability.MaxRequests <= 0 || capability.MaxConcurrent <= 0 || capability.MaxRequestBytes <= 0 || capability.MaxResponseBytes <= 0 || capability.ExpiresAt.IsZero() || capability.auditFailed == nil || !capability.authority.Matches(binding) {
		return nil, fmt.Errorf("Git Gateway read capability limits are invalid")
	}
	gate, err := corecapability.NewGate(capability.authority, capability.ExpiresAt, capability.MaxRequests, capability.MaxConcurrent)
	if err != nil {
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
		gate: gate,
	}, nil
}

func (g *ReadGateway) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	event := ReadAuditEvent{ProjectID: g.capability.ProjectID, VMID: g.capability.VMID, SessionID: g.capability.SessionID, At: g.now().UTC()}
	defer func() {
		if err := g.audit(event); err != nil {
			g.capability.auditFailed.Store(true)
			g.gate.Revoke()
		}
	}()
	reject := func(status int, reason string) {
		event.Status, event.Reason = status, reason
		http.Error(response, http.StatusText(status), status)
	}
	if g.capability.auditFailed.Load() {
		reject(http.StatusServiceUnavailable, "audit_unavailable")
		return
	}
	operation, suffix, ok := g.route(request)
	event.Operation = operation
	if !ok {
		reject(http.StatusNotFound, "route_not_allowed")
		return
	}
	token, validHeader := bearerToken(request.Header.Get("Authorization"))
	if !validHeader {
		reject(http.StatusUnauthorized, "invalid_or_expired_capability")
		return
	}
	lease, status := g.gate.Admit(token, g.now())
	if status == corecapability.RequestQuotaExceeded {
		reject(http.StatusTooManyRequests, "request_quota_exceeded")
		return
	}
	if status == corecapability.ConcurrencyExceeded {
		reject(http.StatusTooManyRequests, "concurrency_exceeded")
		return
	}
	if status != corecapability.Admitted {
		reject(http.StatusUnauthorized, "invalid_or_expired_capability")
		return
	}
	defer lease.Release()
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

func bearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	return strings.TrimPrefix(header, prefix), true
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
