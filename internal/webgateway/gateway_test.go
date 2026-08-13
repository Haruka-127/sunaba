package webgateway

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type staticResolver map[string][]netip.Addr

func (r staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r[host]...), nil
}

func TestHTTPProxyAllowsOnlyBodylessReadsAndPinsDialedIP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Host != "allowed.example" {
			t.Errorf("unexpected upstream Host %q", request.Host)
		}
		if request.Header.Get("X-Sunaba-Hop") != "" {
			t.Errorf("dynamic request hop header reached upstream: %q", request.Header.Get("X-Sunaba-Hop"))
		}
		response.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(response, "safe response")
	}))
	defer upstream.Close()
	localAddress := strings.TrimPrefix(upstream.URL, "http://")
	var dialed string
	var eventsMu sync.Mutex
	var events []AuditEvent
	gateway, token := newTestGateway(t, Policy{Rules: []OriginRule{{Host: "allowed.example", Port: 80, Category: "general", AllowHTTP: true}}}, staticResolver{
		"allowed.example": {netip.MustParseAddr("93.184.216.34")},
	}, func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = address
		return (&net.Dialer{}).DialContext(ctx, network, localAddress)
	}, func(event AuditEvent) error {
		eventsMu.Lock()
		defer eventsMu.Unlock()
		events = append(events, event)
		return nil
	})
	server := httptest.NewServer(gateway)
	defer server.Close()
	client := proxyClient(t, server.URL, token)
	proxyRequest, _ := http.NewRequest(http.MethodGet, "http://allowed.example/private/path?secret=query", nil)
	proxyRequest.Header.Set("Connection", "X-Sunaba-Hop")
	proxyRequest.Header.Set("X-Sunaba-Hop", "remove-me")
	response, err := client.Do(proxyRequest)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "safe response" {
		t.Fatalf("unexpected proxy response status=%d body=%q", response.StatusCode, body)
	}
	if dialed != "93.184.216.34:80" {
		t.Fatalf("Gateway did not dial the validated IP: %q", dialed)
	}
	request, _ := http.NewRequest(http.MethodPost, "http://allowed.example/upload", strings.NewReader("secret-body"))
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("HTTP upload was not rejected: %d", response.StatusCode)
	}
	eventsMu.Lock()
	defer eventsMu.Unlock()
	if len(events) != 2 || !events[0].Allowed || events[1].Reason != "http_method_not_allowed" {
		t.Fatalf("unexpected audit events: %+v", events)
	}
	encoded := events[0].Hostname + events[0].Reason + events[1].Hostname + events[1].Reason
	for _, forbidden := range []string{"private/path", "secret=query", "secret-body"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("audit event leaked request content %q", forbidden)
		}
	}
}

func TestRemoveHopHeadersRemovesConnectionTokens(t *testing.T) {
	header := http.Header{
		"Connection":   {"keep-alive, X-First-Hop", "X-Second-Hop"},
		"Keep-Alive":   {"timeout=5"},
		"X-First-Hop":  {"first"},
		"X-Second-Hop": {"second"},
		"X-End-To-End": {"keep"},
	}
	removeHopHeaders(header)
	for _, removed := range []string{"Connection", "Keep-Alive", "X-First-Hop", "X-Second-Hop"} {
		if header.Get(removed) != "" {
			t.Fatalf("hop-by-hop header %s survived: %q", removed, header.Get(removed))
		}
	}
	if header.Get("X-End-To-End") != "keep" {
		t.Fatalf("end-to-end header was removed: %q", header.Get("X-End-To-End"))
	}
}

func TestDNSAndOriginPolicyFailClosed(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		addresses []netip.Addr
		want      string
		status    int
	}{
		{name: "private", host: "allowed.example", addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}, want: "resolved_address_not_public", status: http.StatusForbidden},
		{name: "metadata", host: "allowed.example", addresses: []netip.Addr{netip.MustParseAddr("169.254.169.254")}, want: "resolved_address_not_public", status: http.StatusForbidden},
		{name: "documentation", host: "allowed.example", addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, want: "resolved_address_not_public", status: http.StatusForbidden},
		{name: "mixed answer", host: "allowed.example", addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("127.0.0.1")}, want: "resolved_address_not_public", status: http.StatusForbidden},
		{name: "literal", host: "93.184.216.34", addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}, want: "invalid_target", status: http.StatusBadRequest},
		{name: "blocked subdomain", host: "sub.blocked.example", addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")}, want: "origin_not_allowed", status: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var event AuditEvent
			policy := Policy{
				Rules: []OriginRule{
					{Host: "allowed.example", Port: 80, Category: "general", AllowHTTP: true},
					{Host: "93.184.216.34.example", Port: 80, Category: "general", AllowHTTP: true},
					{Host: "blocked.example", Port: 80, Category: "general", AllowHTTP: true, IncludeSubdomains: true},
				},
				BlockedDomains: []string{"blocked.example"},
			}
			gateway, token := newTestGateway(t, policy, staticResolver{test.host: test.addresses}, func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("rejected target reached dial")
				return nil, nil
			}, func(observed AuditEvent) error { event = observed; return nil })
			server := httptest.NewServer(gateway)
			defer server.Close()
			response, err := proxyClient(t, server.URL, token).Get("http://" + test.host + "/hidden")
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != test.status || event.Reason != test.want {
				t.Fatalf("status=%d event=%+v", response.StatusCode, event)
			}
		})
	}
}

func TestCompiledPolicyIndexMatchesExactSubdomainAndLabelBoundaries(t *testing.T) {
	policy := Policy{
		Rules: []OriginRule{
			{Host: "example.com", Port: 80, Category: "general", AllowHTTP: true, IncludeSubdomains: true},
			{Host: "blocked.example", Port: 80, Category: "general", AllowHTTP: true, IncludeSubdomains: true},
		},
		BlockedDomains: []string{"blocked.example"},
	}
	beforeDigest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := policy.canonical()
	if err != nil {
		t.Fatal(err)
	}
	blocked, exact, suffix := compilePolicyIndex(canonical)
	gateway := &Gateway{policy: canonical, blockedDomains: blocked, exactRules: exact, suffixRules: suffix}
	tests := map[string]bool{
		"example.com": true, "sub.example.com": true, "deep.sub.example.com": true,
		"badexample.com": false, "example.com.evil": false,
		"blocked.example": false, "sub.blocked.example": false,
	}
	for host, want := range tests {
		if _, got := gateway.allowedRule(host, 80, false); got != want {
			t.Fatalf("host %q allowed=%t want=%t", host, got, want)
		}
	}
	afterDigest, err := gateway.policy.Digest()
	if err != nil || afterDigest != beforeDigest {
		t.Fatalf("compiled index changed canonical policy digest: before=%s after=%s error=%v", beforeDigest, afterDigest, err)
	}
}

func BenchmarkAllowedRuleWithLargeBlocklist(b *testing.B) {
	policy := Policy{Rules: []OriginRule{{Host: "safe.example", Port: 443, Category: "general", AllowConnect: true, IncludeSubdomains: true}}}
	policy.BlockedDomains = make([]string, 100_000)
	for index := range policy.BlockedDomains {
		policy.BlockedDomains[index] = fmt.Sprintf("blocked-%06d.example", index)
	}
	canonical, err := policy.canonical()
	if err != nil {
		b.Fatal(err)
	}
	blocked, exact, suffix := compilePolicyIndex(canonical)
	gateway := &Gateway{blockedDomains: blocked, exactRules: exact, suffixRules: suffix}
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, allowed := gateway.allowedRule("deep.sub.safe.example", 443, true); !allowed {
			b.Fatal("indexed rule lookup unexpectedly rejected host")
		}
	}
}

func TestConnectUsesAuthenticatedBoundedTunnel(t *testing.T) {
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamListener.Close()
	go func() {
		connection, acceptErr := upstreamListener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		_, _ = io.Copy(connection, connection)
	}()
	eventDone := make(chan AuditEvent, 1)
	gateway, token := newTestGateway(t, Policy{Rules: []OriginRule{{Host: "tls.example", Port: 443, Category: "general", AllowConnect: true}}}, staticResolver{
		"tls.example": {netip.MustParseAddr("93.184.216.34")},
	}, func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "93.184.216.34:443" {
			t.Errorf("unexpected CONNECT dial %q", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, upstreamListener.Addr().String())
	}, func(observed AuditEvent) error { eventDone <- observed; return nil })
	server := httptest.NewServer(gateway)
	serverAddress := strings.TrimPrefix(server.URL, "http://")
	connection, err := net.Dial("tcp", serverAddress)
	if err != nil {
		t.Fatal(err)
	}
	authorization := base64.StdEncoding.EncodeToString([]byte("sunaba:" + token))
	_, _ = io.WriteString(connection, "CONNECT tls.example:443 HTTP/1.1\r\nHost: tls.example:443\r\nProxy-Authorization: Basic "+authorization+"\r\n\r\n")
	reader := bufio.NewReader(connection)
	status, _ := reader.ReadString('\n')
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT failed: %q", status)
	}
	for {
		line, _ := reader.ReadString('\n')
		if line == "\r\n" {
			break
		}
	}
	_, _ = io.WriteString(connection, "tunnel-data")
	echo := make([]byte, len("tunnel-data"))
	if _, err := io.ReadFull(reader, echo); err != nil || string(echo) != "tunnel-data" {
		t.Fatalf("unexpected tunnel echo=%q error=%v", echo, err)
	}
	_ = connection.Close()
	server.Close()
	var event AuditEvent
	select {
	case event = <-eventDone:
	case <-time.After(2 * time.Second):
		t.Fatal("CONNECT audit event did not finish")
	}
	if !event.Allowed || event.Hostname != "tls.example" || event.UploadBytes == 0 || event.DownloadBytes == 0 {
		t.Fatalf("unexpected CONNECT audit event: %+v", event)
	}
}

func TestCapabilityExpiryRevocationAuthenticationAndQuota(t *testing.T) {
	now := time.Unix(1000, 0)
	policy := Policy{Rules: []OriginRule{{Host: "allowed.example", Port: 80, Category: "general", AllowHTTP: true}}}
	digest, _ := policy.Digest()
	capability, err := NewCapability(strings.Repeat("t", 32), "project", "vm", "session", digest, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	capability.MaxRequests = 1
	var events []AuditEvent
	gateway, err := New(Config{Policy: policy, Capability: capability, Resolver: staticResolver{"allowed.example": {netip.MustParseAddr("127.0.0.1")}}, Audit: func(event AuditEvent) error { events = append(events, event); return nil }, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway)
	defer server.Close()
	unauthorized, _ := http.Get(server.URL)
	_ = unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("missing proxy auth status=%d", unauthorized.StatusCode)
	}
	client := proxyClient(t, server.URL, strings.Repeat("t", 32))
	response, err := client.Get("http://allowed.example/")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected private resolution rejection, got %d", response.StatusCode)
	}
	response, _ = client.Get("http://allowed.example/")
	_ = response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("request quota not enforced: %d", response.StatusCode)
	}
	gateway.Revoke()
	response, _ = client.Get("http://allowed.example/")
	_ = response.Body.Close()
	if response.StatusCode != http.StatusProxyAuthRequired || events[len(events)-1].Reason != "capability_inactive" {
		t.Fatalf("revocation not enforced: status=%d events=%+v", response.StatusCode, events)
	}
}

func TestGatewayRejectsCapabilityLimitsOutsideProductBounds(t *testing.T) {
	policy := Policy{Rules: []OriginRule{{Host: "allowed.example", Port: 80, Category: "general", AllowHTTP: true}}}
	digest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	base, err := NewCapability(strings.Repeat("t", 32), "project", "vm", "session", digest, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Capability){
		"requests":     func(capability *Capability) { capability.MaxRequests = MaximumMaxRequests + 1 },
		"concurrent":   func(capability *Capability) { capability.MaxConcurrent = MaximumMaxConcurrent + 1 },
		"connect time": func(capability *Capability) { capability.MaxConnectTime = MaximumMaxConnectTime + time.Second },
		"upload":       func(capability *Capability) { capability.MaxUploadBytes = MaximumMaxUploadBytes + 1 },
		"download":     func(capability *Capability) { capability.MaxDownloadBytes = MaximumMaxDownloadBytes + 1 },
		"total":        func(capability *Capability) { capability.MaxTotalBytes = MaximumMaxTotalBytes + 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			capability := base
			mutate(&capability)
			if _, err := New(Config{Policy: policy, Capability: capability, Audit: func(AuditEvent) error { return nil }}); err == nil {
				t.Fatal("oversized capability was accepted")
			}
		})
	}
	maximum := base
	maximum.MaxRequests = MaximumMaxRequests
	maximum.MaxConcurrent = MaximumMaxConcurrent
	maximum.MaxConnectTime = MaximumMaxConnectTime
	maximum.MaxUploadBytes = MaximumMaxUploadBytes
	maximum.MaxDownloadBytes = MaximumMaxDownloadBytes
	maximum.MaxTotalBytes = MaximumMaxTotalBytes
	if _, err := New(Config{Policy: policy, Capability: maximum, Audit: func(AuditEvent) error { return nil }}); err != nil {
		t.Fatalf("maximum capability was rejected: %v", err)
	}
}

func TestAuditFailureRevokesWebGateway(t *testing.T) {
	policy := Policy{Rules: []OriginRule{{Host: "allowed.example", Port: 80, Category: "general", AllowHTTP: true}}}
	digest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	capability, err := NewCapability(strings.Repeat("t", 32), "project", "vm", "session", digest, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := New(Config{Policy: policy, Capability: capability, Audit: func(AuditEvent) error { return errors.New("injected audit failure") }})
	if err != nil {
		t.Fatal(err)
	}
	first := httptest.NewRecorder()
	gateway.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "http://allowed.example/", nil))
	second := httptest.NewRecorder()
	gateway.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "http://allowed.example/", nil))
	if first.Code != http.StatusProxyAuthRequired || second.Code != http.StatusServiceUnavailable {
		t.Fatalf("statuses=%d,%d", first.Code, second.Code)
	}
}

func TestPolicyNormalizationAndPublicAddressClassification(t *testing.T) {
	policy := Policy{Rules: []OriginRule{{Host: "EXAMPLE.COM.", Port: 443, Category: "general", AllowConnect: true}}}
	digest1, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	digest2, _ := (Policy{Rules: []OriginRule{{Host: "example.com", Port: 443, Category: "general", AllowConnect: true}}}).Digest()
	if digest1 != digest2 {
		t.Fatal("canonical equivalent policies have different digests")
	}
	for _, denied := range []string{"0.1.2.3", "100.64.0.1", "198.18.0.1", "203.0.113.1", "::1", "2001:db8::1", "fd00::1"} {
		if isPublicAddress(netip.MustParseAddr(denied)) {
			t.Errorf("special address accepted: %s", denied)
		}
	}
	for _, allowed := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		if !isPublicAddress(netip.MustParseAddr(allowed)) {
			t.Errorf("public address rejected: %s", allowed)
		}
	}
	if _, err := (Policy{Rules: []OriginRule{{Host: "éxample.com", Port: 443, Category: "general", AllowConnect: true}}}).Digest(); err == nil {
		t.Fatal("non-ASCII hostname accepted")
	}
}

func newTestGateway(t *testing.T, policy Policy, resolver Resolver, dial func(context.Context, string, string) (net.Conn, error), audit func(AuditEvent) error) (*Gateway, string) {
	t.Helper()
	token := strings.Repeat("w", 32)
	digest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	capability, err := NewCapability(token, "project", "vm", "session", digest, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := New(Config{Policy: policy, Capability: capability, Resolver: resolver, DialContext: dial, Audit: audit})
	if err != nil {
		t.Fatal(err)
	}
	return gateway, token
}

func proxyClient(t *testing.T, gatewayURL, token string) *http.Client {
	t.Helper()
	proxy, err := url.Parse(gatewayURL)
	if err != nil {
		t.Fatal(err)
	}
	proxy.User = url.UserPassword("sunaba", token)
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 5 * time.Second}
}
