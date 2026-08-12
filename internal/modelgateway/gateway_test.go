package modelgateway

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"sunaba/internal/modelcatalog"
)

type staticOAuthSource struct {
	access OAuthAccess
	err    error
}

func (s staticOAuthSource) AccessToken(context.Context) (OAuthAccess, error) {
	return s.access, s.err
}

func TestGatewayUsesCodexOAuthEndpointHeadersAndRequestShape(t *testing.T) {
	var upstreamBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/backend-api/codex/responses" || request.Header.Get("Authorization") != "Bearer oauth-access-token" || request.Header.Get("ChatGPT-Account-Id") != "account-123" || request.Header.Get("Originator") != "sunaba" {
			t.Errorf("path=%q headers=%v", request.URL.Path, request.Header)
		}
		upstreamBody, _ = io.ReadAll(request.Body)
		_, _ = io.WriteString(response, `{}`)
	}))
	defer upstream.Close()
	gateway, err := New(Config{
		UpstreamBaseURL: upstream.URL + "/backend-api/codex", AuthMode: modelcatalog.AuthOAuth,
		OAuthTokens: staticOAuthSource{access: OAuthAccess{Token: "oauth-access-token", AccountID: "account-123"}},
		Capability:  testCapability(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway)
	defer server.Close()
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/responses", strings.NewReader(`{"model":"`+testModel+`","stream":false,"previous_response_id":"secret","stream_options":{"include_usage":true}}`))
	request.Header.Set("Authorization", "Bearer "+testToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || strings.Contains(string(upstreamBody), "previous_response_id") || strings.Contains(string(upstreamBody), "stream_options") || !strings.Contains(string(upstreamBody), `"instructions":""`) {
		t.Fatalf("status=%d upstream body=%s", response.StatusCode, upstreamBody)
	}
}

const (
	testToken = "gateway-token-0123456789abcdef0123456789abcdef"
	testKey   = "upstream-secret-key"
	testModel = "gpt-sunaba-test"
)

func TestGatewayPreservesResponsesStreamingAndToolEvents(t *testing.T) {
	var receivedAuthorization string
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		receivedAuthorization = request.Header.Get("Authorization")
		if request.URL.Path != "/api/v1/responses" {
			t.Errorf("upstream path=%q", request.URL.Path)
		}
		response.Header().Set("Content-Type", "text/event-stream")
		flusher := response.(http.Flusher)
		for _, event := range []string{
			`data: {"type":"response.output_text.delta","delta":"hello"}` + "\n\n",
			`data: {"type":"response.output_item.done","item":{"type":"function_call","name":"shell","arguments":"{}"}}` + "\n\n",
			`data: {"type":"response.completed","response":{"id":"resp_test"}}` + "\n\n",
		} {
			_, _ = io.WriteString(response, event)
			flusher.Flush()
		}
	}))
	defer upstream.Close()
	var events []AuditEvent
	gateway := testGateway(t, upstream.URL+"/api", func(event AuditEvent) { events = append(events, event) })
	server := httptest.NewServer(gateway)
	defer server.Close()
	request, err := http.NewRequest(http.MethodPost, server.URL+"/v1/responses", strings.NewReader(`{"model":"`+testModel+`","stream":true,"input":"hi","tools":[{"type":"function","name":"shell"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, expected := range []string{"response.output_text.delta", "function_call", "response.completed"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("stream=%q missing %q", text, expected)
		}
	}
	if receivedAuthorization != "Bearer "+testKey || strings.Contains(text, testKey) {
		t.Fatalf("upstream auth=%q response=%q", receivedAuthorization, text)
	}
	if len(events) != 1 || events[0].Status != http.StatusOK || events[0].ProjectID != "project" || events[0].ResponseBytes == 0 {
		t.Fatalf("audit events=%+v", events)
	}
}

func TestGatewayPreservesUpstreamErrorWithoutLeakingKey(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(response, `{"error":{"type":"rate_limit_error","message":"retry later"}}`)
	}))
	defer upstream.Close()
	server := httptest.NewServer(testGateway(t, upstream.URL, nil))
	defer server.Close()
	response := gatewayRequest(t, context.Background(), server.URL, testToken, testModel)
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(body), "rate_limit_error") || strings.Contains(string(body), testKey) {
		t.Fatalf("status=%d body=%q", response.StatusCode, body)
	}
}

func TestCapabilityUsesBoundedSessionDefaults(t *testing.T) {
	models := []string{testModel}
	capability, err := NewCapability(testToken, "project", "vm", "session", models, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	models[0] = "mutated"
	if capability.AllowedModels[0] != testModel || capability.MaxRequests != DefaultMaxRequests || capability.MaxConcurrent != DefaultMaxConcurrent || capability.MaxRequestBytes != DefaultMaxRequestBytes || capability.MaxResponseBytes != DefaultMaxResponseBytes {
		t.Fatalf("unexpected capability defaults: %+v", capability)
	}
	for _, mutate := range []func(*Capability){
		func(value *Capability) { value.MaxRequests = MaximumMaxRequests + 1 },
		func(value *Capability) { value.MaxConcurrent = MaximumMaxConcurrent + 1 },
		func(value *Capability) { value.MaxRequestBytes = MaximumMaxRequestBytes + 1 },
		func(value *Capability) { value.MaxResponseBytes = MaximumMaxResponseBytes + 1 },
	} {
		invalid := capability
		mutate(&invalid)
		if _, err := New(Config{UpstreamBaseURL: "https://api.openai.com", UpstreamAPIKey: testKey, Capability: invalid}); err == nil {
			t.Fatalf("overlarge capability was accepted: %+v", invalid)
		}
	}
}

func TestGatewayRejectsTokenAndModelBeforeUpstream(t *testing.T) {
	var calls int
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer upstream.Close()
	server := httptest.NewServer(testGateway(t, upstream.URL, nil))
	defer server.Close()
	for _, tc := range []struct {
		token string
		model string
		want  int
	}{
		{token: "wrong", model: testModel, want: http.StatusUnauthorized},
		{token: testToken, model: "other-model", want: http.StatusForbidden},
	} {
		response := gatewayRequest(t, context.Background(), server.URL, tc.token, tc.model)
		_ = response.Body.Close()
		if response.StatusCode != tc.want {
			t.Fatalf("status=%d, want %d", response.StatusCode, tc.want)
		}
	}
	if calls != 0 {
		t.Fatalf("rejected requests reached upstream %d times", calls)
	}
}

func TestGatewayAllowsEveryConfiguredModelAndAuditsRequestedModel(t *testing.T) {
	var calls int
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls++
		_, _ = io.WriteString(response, `{}`)
	}))
	defer upstream.Close()
	capability, err := NewCapability(testToken, "project", "vm", "session", []string{testModel, "gpt-sunaba-small"}, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	var events []AuditEvent
	gateway, err := New(Config{UpstreamBaseURL: upstream.URL, UpstreamAPIKey: testKey, Capability: capability, Audit: func(event AuditEvent) { events = append(events, event) }})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway)
	defer server.Close()
	for _, model := range capability.AllowedModels {
		response := gatewayRequest(t, context.Background(), server.URL, testToken, model)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("model=%q status=%d", model, response.StatusCode)
		}
	}
	if calls != 2 || len(events) != 2 || events[0].Model != testModel || events[1].Model != "gpt-sunaba-small" {
		t.Fatalf("calls=%d events=%+v", calls, events)
	}
}

func TestGatewayPropagatesCancellation(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "text/event-stream")
		response.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(response, "data: {\"type\":\"response.created\"}\n\n")
		response.(http.Flusher).Flush()
		close(started)
		select {
		case <-request.Context().Done():
			close(canceled)
		case <-release:
		}
	}))
	defer close(release)
	defer upstream.Close()
	server := httptest.NewServer(testGateway(t, upstream.URL, nil))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/responses", strings.NewReader(`{"model":"`+testModel+`","stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testToken)
	done := make(chan error, 1)
	go func() {
		response, err := http.DefaultClient.Do(request)
		if response != nil {
			_, copyErr := io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if err == nil {
				err = copyErr
			}
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("upstream request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled downstream request unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("downstream request did not cancel")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("upstream context was not canceled")
	}
}

func TestGatewayEnforcesConcurrency(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(response, `{}`)
	}))
	defer upstream.Close()
	capability := testCapability(t)
	capability.MaxConcurrent = 1
	gateway, err := New(Config{UpstreamBaseURL: upstream.URL, UpstreamAPIKey: testKey, Capability: capability})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway)
	defer server.Close()
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		response := gatewayRequest(t, context.Background(), server.URL, testToken, testModel)
		_ = response.Body.Close()
	}()
	<-started
	response := gatewayRequest(t, context.Background(), server.URL, testToken, testModel)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status=%d", response.StatusCode)
	}
	close(release)
	wait.Wait()
}

func TestGatewayEnforcesExpiryQuotaAndBodyLimits(t *testing.T) {
	var calls int
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = io.WriteString(response, `{}`)
	}))
	defer upstream.Close()

	expired := testCapability(t)
	expired.ExpiresAt = time.Unix(100, 0)
	expiredGateway, err := New(Config{
		UpstreamBaseURL: upstream.URL, UpstreamAPIKey: testKey, Capability: expired,
		Now: func() time.Time { return time.Unix(101, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	expiredServer := httptest.NewServer(expiredGateway)
	response := gatewayRequest(t, context.Background(), expiredServer.URL, testToken, testModel)
	_ = response.Body.Close()
	expiredServer.Close()
	if response.StatusCode != http.StatusUnauthorized || calls != 0 {
		t.Fatalf("expired status=%d upstream calls=%d", response.StatusCode, calls)
	}

	limited := testCapability(t)
	limited.MaxRequests = 1
	limited.MaxRequestBytes = 64
	limitedGateway, err := New(Config{UpstreamBaseURL: upstream.URL, UpstreamAPIKey: testKey, Capability: limited})
	if err != nil {
		t.Fatal(err)
	}
	limitedServer := httptest.NewServer(limitedGateway)
	defer limitedServer.Close()
	first := gatewayRequest(t, context.Background(), limitedServer.URL, testToken, testModel)
	_ = first.Body.Close()
	second := gatewayRequest(t, context.Background(), limitedServer.URL, testToken, testModel)
	_ = second.Body.Close()
	if first.StatusCode != http.StatusOK || second.StatusCode != http.StatusTooManyRequests || calls != 1 {
		t.Fatalf("quota statuses=%d,%d calls=%d", first.StatusCode, second.StatusCode, calls)
	}

	oversized := testCapability(t)
	oversized.MaxRequestBytes = 8
	oversizedGateway, err := New(Config{UpstreamBaseURL: upstream.URL, UpstreamAPIKey: testKey, Capability: oversized})
	if err != nil {
		t.Fatal(err)
	}
	oversizedServer := httptest.NewServer(oversizedGateway)
	defer oversizedServer.Close()
	tooLarge := gatewayRequest(t, context.Background(), oversizedServer.URL, testToken, testModel)
	_ = tooLarge.Body.Close()
	if tooLarge.StatusCode != http.StatusRequestEntityTooLarge || calls != 1 {
		t.Fatalf("oversized status=%d calls=%d", tooLarge.StatusCode, calls)
	}
}

func testGateway(t *testing.T, upstream string, audit func(AuditEvent)) *Gateway {
	t.Helper()
	gateway, err := New(Config{UpstreamBaseURL: upstream, UpstreamAPIKey: testKey, Capability: testCapability(t), Audit: audit})
	if err != nil {
		t.Fatal(err)
	}
	return gateway
}

func testCapability(t *testing.T) Capability {
	t.Helper()
	capability, err := NewCapability(testToken, "project", "vm", "session", []string{testModel}, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return capability
}

func gatewayRequest(t *testing.T, ctx context.Context, endpoint, token, model string) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/responses", strings.NewReader(fmt.Sprintf(`{"model":%q,"stream":false}`, model)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
