package modelgateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Capability struct {
	ProjectID        string
	VMID             string
	SessionID        string
	Model            string
	ExpiresAt        time.Time
	MaxRequests      int
	MaxConcurrent    int
	MaxRequestBytes  int64
	MaxResponseBytes int64
	tokenHash        [sha256.Size]byte
}

func NewCapability(token, projectID, vmID, sessionID, model string, expiresAt time.Time) (Capability, error) {
	if len(token) < 32 || projectID == "" || vmID == "" || sessionID == "" || model == "" || expiresAt.IsZero() {
		return Capability{}, fmt.Errorf("Model Gateway capability requires a high-entropy token and bound identities")
	}
	return Capability{
		ProjectID: projectID, VMID: vmID, SessionID: sessionID, Model: model, ExpiresAt: expiresAt,
		MaxRequests: 100, MaxConcurrent: 2, MaxRequestBytes: 4 << 20, MaxResponseBytes: 16 << 20,
		tokenHash: sha256.Sum256([]byte(token)),
	}, nil
}

type AuditEvent struct {
	ProjectID     string
	VMID          string
	SessionID     string
	Model         string
	Status        int
	RequestBytes  int64
	ResponseBytes int64
	Reason        string
	At            time.Time
}

type Config struct {
	UpstreamBaseURL string
	UpstreamAPIKey  string
	Capability      Capability
	HTTPClient      *http.Client
	Audit           func(AuditEvent)
	Now             func() time.Time
}

type Gateway struct {
	upstream   *url.URL
	apiKey     string
	capability Capability
	client     *http.Client
	audit      func(AuditEvent)
	now        func() time.Time
	semaphore  chan struct{}
	mu         sync.Mutex
	requests   int
}

func New(config Config) (*Gateway, error) {
	upstream, err := url.Parse(config.UpstreamBaseURL)
	if err != nil || (upstream.Scheme != "http" && upstream.Scheme != "https") || upstream.Host == "" || upstream.User != nil || upstream.RawQuery != "" || upstream.Fragment != "" {
		return nil, fmt.Errorf("Model Gateway upstream must be a fixed HTTP(S) base URL")
	}
	if config.UpstreamAPIKey == "" {
		return nil, fmt.Errorf("Model Gateway upstream API key is required")
	}
	capability := config.Capability
	if capability.MaxRequests <= 0 || capability.MaxConcurrent <= 0 || capability.MaxRequestBytes <= 0 || capability.MaxResponseBytes <= 0 || capability.Model == "" || capability.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("Model Gateway capability limits are invalid")
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
	return &Gateway{
		upstream: upstream, apiKey: config.UpstreamAPIKey, capability: capability,
		client: &clientCopy, audit: config.Audit, now: now,
		semaphore: make(chan struct{}, capability.MaxConcurrent),
	}, nil
}

func (g *Gateway) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	event := AuditEvent{
		ProjectID: g.capability.ProjectID, VMID: g.capability.VMID,
		SessionID: g.capability.SessionID, Model: g.capability.Model, At: g.now().UTC(),
	}
	defer func() {
		if g.audit != nil {
			g.audit(event)
		}
	}()
	reject := func(status int, reason string) {
		event.Status, event.Reason = status, reason
		http.Error(response, http.StatusText(status), status)
	}
	if request.Method != http.MethodPost || request.URL.Path != "/v1/responses" || request.URL.RawQuery != "" {
		reject(http.StatusNotFound, "route_not_allowed")
		return
	}
	if !g.authorized(request.Header.Get("Authorization")) {
		reject(http.StatusUnauthorized, "invalid_capability")
		return
	}
	if !g.now().Before(g.capability.ExpiresAt) {
		reject(http.StatusUnauthorized, "expired_capability")
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
	if err != nil {
		reject(http.StatusBadRequest, "request_read_failed")
		return
	}
	event.RequestBytes = int64(len(body))
	if int64(len(body)) > g.capability.MaxRequestBytes {
		reject(http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	var envelope struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if !json.Valid(body) || json.Unmarshal(body, &envelope) != nil || envelope.Model != g.capability.Model {
		reject(http.StatusForbidden, "model_not_allowed")
		return
	}
	upstreamURL := *g.upstream
	upstreamURL.Path = strings.TrimRight(g.upstream.Path, "/") + "/v1/responses"
	upstreamContext, cancelUpstream := context.WithCancel(request.Context())
	defer cancelUpstream()
	upstreamDone := make(chan struct{})
	if closeNotifier, ok := response.(http.CloseNotifier); ok {
		disconnected := closeNotifier.CloseNotify()
		go func() {
			select {
			case <-disconnected:
				cancelUpstream()
			case <-request.Context().Done():
				cancelUpstream()
			case <-upstreamDone:
			}
		}()
	}
	defer close(upstreamDone)
	upstreamRequest, err := http.NewRequestWithContext(upstreamContext, http.MethodPost, upstreamURL.String(), bytes.NewReader(body))
	if err != nil {
		reject(http.StatusBadGateway, "upstream_request_failed")
		return
	}
	upstreamRequest.Header.Set("Authorization", "Bearer "+g.apiKey)
	upstreamRequest.Header.Set("Content-Type", "application/json")
	upstreamRequest.Header.Set("User-Agent", "sunaba-model-gateway/1")
	upstreamResponse, err := g.client.Do(upstreamRequest)
	if err != nil {
		if errors.Is(err, context.Canceled) || request.Context().Err() != nil {
			event.Status, event.Reason = 499, "canceled"
			return
		}
		reject(http.StatusBadGateway, "upstream_unavailable")
		return
	}
	defer upstreamResponse.Body.Close()
	for _, header := range []string{"Content-Type", "Cache-Control", "X-Request-Id"} {
		if value := upstreamResponse.Header.Get(header); value != "" {
			response.Header().Set(header, value)
		}
	}
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(upstreamResponse.StatusCode)
	event.Status = upstreamResponse.StatusCode
	written, copyErr := copyLimitedResponse(response, upstreamResponse.Body, g.capability.MaxResponseBytes, envelope.Stream)
	event.ResponseBytes = written
	if copyErr != nil {
		if errors.Is(copyErr, errResponseLimit) {
			event.Reason = "response_too_large"
		} else if request.Context().Err() != nil {
			event.Reason = "canceled"
		} else {
			event.Reason = "response_copy_failed"
		}
	}
}

func (g *Gateway) authorized(header string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	presented := sha256.Sum256([]byte(strings.TrimPrefix(header, prefix)))
	return subtle.ConstantTimeCompare(presented[:], g.capability.tokenHash[:]) == 1
}

var errResponseLimit = errors.New("Model Gateway response limit exceeded")

func copyLimitedResponse(destination http.ResponseWriter, source io.Reader, maximum int64, stream bool) (int64, error) {
	buffer := make([]byte, 32<<10)
	var written int64
	for {
		read, readErr := source.Read(buffer)
		if read > 0 {
			remaining := maximum - written
			if remaining <= 0 {
				return written, errResponseLimit
			}
			toWrite := read
			if int64(toWrite) > remaining {
				toWrite = int(remaining)
			}
			count, writeErr := destination.Write(buffer[:toWrite])
			written += int64(count)
			if writeErr != nil {
				return written, writeErr
			}
			if stream {
				if flusher, ok := destination.(http.Flusher); ok {
					flusher.Flush()
				}
			}
			if toWrite != read {
				return written, errResponseLimit
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return written, nil
			}
			return written, readErr
		}
	}
}
