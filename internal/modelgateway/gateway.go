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
	"regexp"
	"strings"
	"sync"
	"time"

	"sunaba/internal/modelcatalog"
)

const (
	DefaultMaxRequests      = 1_000
	DefaultMaxConcurrent    = 4
	DefaultMaxRequestBytes  = 32 << 20
	DefaultMaxResponseBytes = 64 << 20
	MaximumMaxRequests      = 100_000
	MaximumMaxConcurrent    = 32
	MaximumMaxRequestBytes  = 128 << 20
	MaximumMaxResponseBytes = 256 << 20
)

var modelIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,255}$`)

type Capability struct {
	ProjectID        string
	VMID             string
	SessionID        string
	AllowedModels    []string
	ExpiresAt        time.Time
	MaxRequests      int
	MaxConcurrent    int
	MaxRequestBytes  int64
	MaxResponseBytes int64
	tokenHash        [sha256.Size]byte
}

func NewCapability(token, projectID, vmID, sessionID string, allowedModels []string, expiresAt time.Time) (Capability, error) {
	models, err := validateAllowedModels(allowedModels)
	if len(token) < 32 || projectID == "" || vmID == "" || sessionID == "" || err != nil || expiresAt.IsZero() {
		return Capability{}, fmt.Errorf("Model Gateway capability requires a high-entropy token and bound identities")
	}
	return Capability{
		ProjectID: projectID, VMID: vmID, SessionID: sessionID, AllowedModels: models, ExpiresAt: expiresAt,
		MaxRequests: DefaultMaxRequests, MaxConcurrent: DefaultMaxConcurrent,
		MaxRequestBytes: DefaultMaxRequestBytes, MaxResponseBytes: DefaultMaxResponseBytes,
		tokenHash: sha256.Sum256([]byte(token)),
	}, nil
}

func validateAllowedModels(models []string) ([]string, error) {
	if len(models) == 0 || len(models) > 32 {
		return nil, fmt.Errorf("Model Gateway requires between 1 and 32 allowed models")
	}
	result := make([]string, 0, len(models))
	seen := make(map[string]struct{}, len(models))
	for _, model := range models {
		if !modelIDPattern.MatchString(model) {
			return nil, fmt.Errorf("Model Gateway model ID is invalid")
		}
		if _, exists := seen[model]; exists {
			return nil, fmt.Errorf("Model Gateway model allowlist contains a duplicate")
		}
		seen[model] = struct{}{}
		result = append(result, model)
	}
	return result, nil
}

func ValidateAllowedModels(models []string) error {
	_, err := validateAllowedModels(models)
	return err
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
	AuthMode        modelcatalog.AuthMode
	OAuthTokens     OAuthTokenSource
	Capability      Capability
	HTTPClient      *http.Client
	Audit           func(AuditEvent)
	Now             func() time.Time
}

type OAuthAccess struct {
	Token     string
	AccountID string
}

type OAuthTokenSource interface {
	AccessToken(context.Context) (OAuthAccess, error)
}

type Gateway struct {
	upstream   *url.URL
	apiKey     string
	authMode   modelcatalog.AuthMode
	oauth      OAuthTokenSource
	capability Capability
	client     *http.Client
	audit      func(AuditEvent)
	now        func() time.Time
	semaphore  chan struct{}
	models     map[string]struct{}
	mu         sync.Mutex
	requests   int
}

func New(config Config) (*Gateway, error) {
	if config.AuthMode == "" {
		config.AuthMode = modelcatalog.AuthAPIKey
	}
	if err := modelcatalog.ValidateAuthMode(config.AuthMode); err != nil {
		return nil, err
	}
	upstream, err := url.Parse(config.UpstreamBaseURL)
	if err != nil || (upstream.Scheme != "http" && upstream.Scheme != "https") || upstream.Host == "" || upstream.User != nil || upstream.RawQuery != "" || upstream.Fragment != "" {
		return nil, fmt.Errorf("Model Gateway upstream must be a fixed HTTP(S) base URL")
	}
	if config.AuthMode == modelcatalog.AuthAPIKey && config.UpstreamAPIKey == "" {
		return nil, fmt.Errorf("Model Gateway upstream API key is required")
	}
	if config.AuthMode == modelcatalog.AuthOAuth && config.OAuthTokens == nil {
		return nil, fmt.Errorf("Model Gateway OAuth token source is required")
	}
	capability := config.Capability
	models, err := validateAllowedModels(capability.AllowedModels)
	if err != nil || capability.MaxRequests <= 0 || capability.MaxRequests > MaximumMaxRequests || capability.MaxConcurrent <= 0 || capability.MaxConcurrent > MaximumMaxConcurrent || capability.MaxRequestBytes <= 0 || capability.MaxRequestBytes > MaximumMaxRequestBytes || capability.MaxResponseBytes <= 0 || capability.MaxResponseBytes > MaximumMaxResponseBytes || capability.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("Model Gateway capability limits are invalid")
	}
	capability.AllowedModels = models
	modelSet := make(map[string]struct{}, len(models))
	for _, model := range models {
		modelSet[model] = struct{}{}
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
		upstream: upstream, apiKey: config.UpstreamAPIKey, authMode: config.AuthMode, oauth: config.OAuthTokens, capability: capability,
		client: &clientCopy, audit: config.Audit, now: now,
		semaphore: make(chan struct{}, capability.MaxConcurrent), models: modelSet,
	}, nil
}

func (g *Gateway) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	event := AuditEvent{
		ProjectID: g.capability.ProjectID, VMID: g.capability.VMID,
		SessionID: g.capability.SessionID, At: g.now().UTC(),
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
	if !json.Valid(body) || json.Unmarshal(body, &envelope) != nil {
		reject(http.StatusBadRequest, "invalid_request")
		return
	}
	event.Model = envelope.Model
	if _, allowed := g.models[envelope.Model]; !allowed {
		reject(http.StatusForbidden, "model_not_allowed")
		return
	}
	if g.authMode == modelcatalog.AuthOAuth {
		body, err = normalizeOAuthRequest(body)
		if err != nil {
			reject(http.StatusBadRequest, "invalid_oauth_request")
			return
		}
	}
	upstreamURL := *g.upstream
	upstreamPath := "/v1/responses"
	if g.authMode == modelcatalog.AuthOAuth {
		upstreamPath = "/responses"
	}
	upstreamURL.Path = strings.TrimRight(g.upstream.Path, "/") + upstreamPath
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
	if g.authMode == modelcatalog.AuthOAuth {
		access, tokenErr := g.oauth.AccessToken(upstreamContext)
		if tokenErr != nil || !safeHeaderValue(access.Token, 8, 32<<10) || !safeHeaderValue(access.AccountID, 8, 1024) {
			reject(http.StatusBadGateway, "oauth_credential_unavailable")
			return
		}
		upstreamRequest.Header.Set("Authorization", "Bearer "+access.Token)
		upstreamRequest.Header.Set("ChatGPT-Account-Id", access.AccountID)
		upstreamRequest.Header.Set("Originator", "sunaba")
	} else {
		upstreamRequest.Header.Set("Authorization", "Bearer "+g.apiKey)
	}
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

func safeHeaderValue(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] == 0x7f {
			return false
		}
	}
	return true
}

func normalizeOAuthRequest(body []byte) ([]byte, error) {
	var request map[string]json.RawMessage
	if err := json.Unmarshal(body, &request); err != nil {
		return nil, err
	}
	for _, field := range []string{"previous_response_id", "generate", "prompt_cache_retention", "safety_identifier", "stream_options"} {
		delete(request, field)
	}
	if instructions, exists := request["instructions"]; !exists || bytes.Equal(bytes.TrimSpace(instructions), []byte("null")) {
		request["instructions"] = json.RawMessage(`""`)
	}
	return json.Marshal(request)
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
