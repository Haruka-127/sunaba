package modelgateway

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func FuzzResponsesEnvelope(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"model":"gpt-test","stream":false,"input":"hello"}`),
		[]byte(`{"model":"other","stream":true}`),
		[]byte(`{"model":"gpt-test","stream":false,"input":"\ud800"}`),
		[]byte{0xff, 0x00, '{', '}'},
	} {
		f.Add(seed)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{"id":"response","object":"response"}`)
	}))
	defer upstream.Close()
	token := strings.Repeat("m", 32)
	capability, err := NewCapability(token, "project", "vm", "session", []string{"gpt-test"}, time.Now().Add(time.Hour))
	if err != nil {
		f.Fatal(err)
	}
	capability.MaxRequests = MaximumMaxRequests
	gateway, err := New(Config{UpstreamBaseURL: upstream.URL, UpstreamAPIKey: "host-only", Capability: capability, Audit: func(AuditEvent) error { return nil }})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 128<<10 {
			t.Skip()
		}
		request := httptest.NewRequest(http.MethodPost, "http://gateway/v1/responses", bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		gateway.ServeHTTP(response, request)
		if response.Code < 200 || response.Code > 599 {
			t.Fatalf("invalid HTTP status for arbitrary envelope: %d", response.Code)
		}
	})
}
