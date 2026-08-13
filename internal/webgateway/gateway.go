package webgateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	corecapability "sunaba/internal/capability"
)

const (
	DefaultMaxRequests            = 500
	DefaultMaxConcurrent          = 4
	DefaultMaxConnectTime         = 2 * time.Minute
	DefaultMaxUploadBytes   int64 = 1 << 20
	DefaultMaxDownloadBytes int64 = 64 << 20
	DefaultMaxTotalBytes    int64 = 256 << 20
	MaximumMaxRequests            = 100_000
	MaximumMaxConcurrent          = 32
	MaximumMaxConnectTime         = 10 * time.Minute
	MaximumMaxUploadBytes   int64 = 64 << 20
	MaximumMaxDownloadBytes int64 = 1 << 30
	MaximumMaxTotalBytes    int64 = 4 << 30
)

type Limits struct {
	MaxRequests      int
	MaxConcurrent    int
	MaxConnectTime   time.Duration
	MaxUploadBytes   int64
	MaxDownloadBytes int64
	MaxTotalBytes    int64
}

func ValidateLimits(limits Limits) error {
	if limits.MaxRequests <= 0 || limits.MaxRequests > MaximumMaxRequests ||
		limits.MaxConcurrent <= 0 || limits.MaxConcurrent > MaximumMaxConcurrent ||
		limits.MaxConnectTime <= 0 || limits.MaxConnectTime > MaximumMaxConnectTime ||
		limits.MaxUploadBytes <= 0 || limits.MaxUploadBytes > MaximumMaxUploadBytes ||
		limits.MaxDownloadBytes <= 0 || limits.MaxDownloadBytes > MaximumMaxDownloadBytes ||
		limits.MaxTotalBytes <= 0 || limits.MaxTotalBytes > MaximumMaxTotalBytes ||
		limits.MaxUploadBytes > limits.MaxTotalBytes || limits.MaxDownloadBytes > limits.MaxTotalBytes {
		return fmt.Errorf("Web Gateway limits exceed the product resource boundary")
	}
	return nil
}

type OriginRule struct {
	Host              string `json:"host"`
	Port              uint16 `json:"port"`
	Category          string `json:"category"`
	AllowHTTP         bool   `json:"allow_http"`
	AllowConnect      bool   `json:"allow_connect"`
	IncludeSubdomains bool   `json:"include_subdomains"`
}

type Policy struct {
	Rules          []OriginRule `json:"rules"`
	BlockedDomains []string     `json:"blocked_domains,omitempty"`
}

func (p Policy) Digest() (string, error) {
	canonical, err := p.canonical()
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (p Policy) canonical() (Policy, error) {
	if len(p.Rules) == 0 || len(p.Rules) > 1024 || len(p.BlockedDomains) > 100_000 {
		return Policy{}, fmt.Errorf("Web Gateway policy requires bounded origin rules")
	}
	result := Policy{Rules: make([]OriginRule, len(p.Rules)), BlockedDomains: make([]string, len(p.BlockedDomains))}
	seenRules := make(map[string]struct{}, len(p.Rules))
	for index, rule := range p.Rules {
		host, err := normalizeHostname(rule.Host)
		if err != nil || rule.Port == 0 || rule.Category == "" || len(rule.Category) > 64 || (!rule.AllowHTTP && !rule.AllowConnect) {
			return Policy{}, fmt.Errorf("invalid Web Gateway origin rule")
		}
		for _, character := range rule.Category {
			if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' || character == '_') {
				return Policy{}, fmt.Errorf("invalid Web Gateway origin category")
			}
		}
		rule.Host = host
		key := fmt.Sprintf("%s:%d:%s:%t:%t:%t", host, rule.Port, rule.Category, rule.AllowHTTP, rule.AllowConnect, rule.IncludeSubdomains)
		if _, exists := seenRules[key]; exists {
			return Policy{}, fmt.Errorf("duplicate Web Gateway origin rule")
		}
		seenRules[key] = struct{}{}
		result.Rules[index] = rule
	}
	for index, domain := range p.BlockedDomains {
		normalized, err := normalizeHostname(domain)
		if err != nil {
			return Policy{}, fmt.Errorf("invalid Web Gateway blocked domain")
		}
		result.BlockedDomains[index] = normalized
	}
	sort.Slice(result.Rules, func(i, j int) bool {
		left, _ := json.Marshal(result.Rules[i])
		right, _ := json.Marshal(result.Rules[j])
		return string(left) < string(right)
	})
	sort.Strings(result.BlockedDomains)
	return result, nil
}

type Capability struct {
	ProjectID        string
	VMID             string
	SessionID        string
	PolicyDigest     string
	ExpiresAt        time.Time
	MaxRequests      int
	MaxConcurrent    int
	MaxConnectTime   time.Duration
	MaxUploadBytes   int64
	MaxDownloadBytes int64
	MaxTotalBytes    int64
	authority        *corecapability.Authority
}

func NewCapability(token, projectID, vmID, sessionID, policyDigest string, expiresAt time.Time) (Capability, error) {
	authority, authorityErr := corecapability.NewAuthority(token, corecapability.Binding{ProjectID: projectID, VMID: vmID, SessionID: sessionID}, expiresAt)
	if authorityErr != nil || len(policyDigest) != sha256.Size*2 {
		return Capability{}, fmt.Errorf("Web Gateway capability requires a high-entropy token and bound identities")
	}
	if _, err := hex.DecodeString(policyDigest); err != nil {
		return Capability{}, fmt.Errorf("Web Gateway policy digest is invalid")
	}
	return Capability{
		ProjectID: projectID, VMID: vmID, SessionID: sessionID, PolicyDigest: policyDigest, ExpiresAt: expiresAt,
		MaxRequests: DefaultMaxRequests, MaxConcurrent: DefaultMaxConcurrent, MaxConnectTime: DefaultMaxConnectTime,
		MaxUploadBytes: DefaultMaxUploadBytes, MaxDownloadBytes: DefaultMaxDownloadBytes, MaxTotalBytes: DefaultMaxTotalBytes,
		authority: authority,
	}, nil
}

type AuditEvent struct {
	ProjectID     string
	VMID          string
	SessionID     string
	Category      string
	Hostname      string
	Port          uint16
	Method        string
	Allowed       bool
	Reason        string
	UploadBytes   int64
	DownloadBytes int64
	Duration      time.Duration
	At            time.Time
}

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type Config struct {
	Policy      Policy
	Capability  Capability
	Resolver    Resolver
	DialContext func(context.Context, string, string) (net.Conn, error)
	Audit       func(AuditEvent) error
	Now         func() time.Time
}

type Gateway struct {
	policy         Policy
	blockedDomains map[string]struct{}
	exactRules     map[ruleLookup]indexedOriginRule
	suffixRules    map[ruleLookup]indexedOriginRule
	capability     Capability
	resolver       Resolver
	dial           func(context.Context, string, string) (net.Conn, error)
	audit          func(AuditEvent) error
	now            func() time.Time
	gate           *corecapability.Gate
	totalBytes     atomic.Int64
	auditFailed    atomic.Bool
}

type ruleLookup struct {
	host    string
	port    uint16
	connect bool
}

type indexedOriginRule struct {
	rule  OriginRule
	index int
}

func New(config Config) (*Gateway, error) {
	policy, err := config.Policy.canonical()
	if err != nil {
		return nil, err
	}
	digest, err := policy.Digest()
	if err != nil || digest != config.Capability.PolicyDigest {
		return nil, fmt.Errorf("Web Gateway capability policy digest does not match")
	}
	capability := config.Capability
	if err := ValidateLimits(Limits{
		MaxRequests: capability.MaxRequests, MaxConcurrent: capability.MaxConcurrent, MaxConnectTime: capability.MaxConnectTime,
		MaxUploadBytes: capability.MaxUploadBytes, MaxDownloadBytes: capability.MaxDownloadBytes, MaxTotalBytes: capability.MaxTotalBytes,
	}); err != nil || capability.ExpiresAt.IsZero() || !capability.authority.Matches(corecapability.Binding{ProjectID: capability.ProjectID, VMID: capability.VMID, SessionID: capability.SessionID}) {
		return nil, fmt.Errorf("Web Gateway capability limits are invalid")
	}
	gate, err := corecapability.NewGate(capability.authority, capability.ExpiresAt, capability.MaxRequests, capability.MaxConcurrent)
	if err != nil {
		return nil, fmt.Errorf("Web Gateway capability limits are invalid")
	}
	if config.Audit == nil {
		return nil, fmt.Errorf("Web Gateway requires a host audit sink")
	}
	resolver := config.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dial := config.DialContext
	if dial == nil {
		dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 15 * time.Second}
		dial = dialer.DialContext
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	blockedDomains, exactRules, suffixRules := compilePolicyIndex(policy)
	return &Gateway{
		policy: policy, blockedDomains: blockedDomains, exactRules: exactRules, suffixRules: suffixRules,
		capability: capability, resolver: resolver, dial: dial, audit: config.Audit, now: now,
		gate: gate,
	}, nil
}

func compilePolicyIndex(policy Policy) (map[string]struct{}, map[ruleLookup]indexedOriginRule, map[ruleLookup]indexedOriginRule) {
	blocked := make(map[string]struct{}, len(policy.BlockedDomains))
	for _, domain := range policy.BlockedDomains {
		blocked[domain] = struct{}{}
	}
	exact := make(map[ruleLookup]indexedOriginRule, len(policy.Rules)*2)
	suffix := make(map[ruleLookup]indexedOriginRule, len(policy.Rules)*2)
	for index, rule := range policy.Rules {
		for _, protocol := range []struct {
			connect bool
			allowed bool
		}{{connect: false, allowed: rule.AllowHTTP}, {connect: true, allowed: rule.AllowConnect}} {
			if !protocol.allowed {
				continue
			}
			key := ruleLookup{host: rule.Host, port: rule.Port, connect: protocol.connect}
			if _, exists := exact[key]; !exists {
				exact[key] = indexedOriginRule{rule: rule, index: index}
			}
			if rule.IncludeSubdomains {
				if _, exists := suffix[key]; !exists {
					suffix[key] = indexedOriginRule{rule: rule, index: index}
				}
			}
		}
	}
	return blocked, exact, suffix
}

func (g *Gateway) Revoke() { g.gate.Revoke() }

func (g *Gateway) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	started := g.now()
	event := AuditEvent{ProjectID: g.capability.ProjectID, VMID: g.capability.VMID, SessionID: g.capability.SessionID, Method: request.Method, At: started.UTC()}
	defer func() {
		event.Duration = g.now().Sub(started)
		if err := g.audit(event); err != nil {
			g.auditFailed.Store(true)
			g.gate.Revoke()
		}
	}()
	reject := func(status int, reason string) {
		event.Reason = reason
		http.Error(response, http.StatusText(status), status)
	}
	if g.auditFailed.Load() {
		reject(http.StatusServiceUnavailable, "audit_unavailable")
		return
	}
	token, validHeader := proxyToken(request.Header.Get("Proxy-Authorization"))
	if !validHeader {
		response.Header().Set("Proxy-Authenticate", `Basic realm="sunaba"`)
		reject(http.StatusProxyAuthRequired, "invalid_capability")
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
	if status == corecapability.Revoked || status == corecapability.Expired {
		reject(http.StatusProxyAuthRequired, "capability_inactive")
		return
	}
	if status != corecapability.Admitted {
		response.Header().Set("Proxy-Authenticate", `Basic realm="sunaba"`)
		reject(http.StatusProxyAuthRequired, "invalid_capability")
		return
	}
	defer lease.Release()
	if request.Method == http.MethodConnect {
		g.serveConnect(response, request, &event, reject)
		return
	}
	g.serveHTTP(response, request, &event, reject)
}

func (g *Gateway) serveHTTP(response http.ResponseWriter, request *http.Request, event *AuditEvent, reject func(int, string)) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		reject(http.StatusForbidden, "http_method_not_allowed")
		return
	}
	if request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
		reject(http.StatusRequestEntityTooLarge, "http_upload_not_allowed")
		return
	}
	if request.URL == nil || !request.URL.IsAbs() || request.URL.Scheme != "http" || request.URL.User != nil || request.URL.Fragment != "" {
		reject(http.StatusBadRequest, "absolute_http_url_required")
		return
	}
	host, port, err := splitTarget(request.URL.Host, 80)
	headerHost, headerPort, headerErr := splitTarget(request.Host, 80)
	if err != nil || headerErr != nil || host != mustNormalize(request.URL.Hostname()) || host != headerHost || port != headerPort {
		reject(http.StatusBadRequest, "invalid_target")
		return
	}
	rule, ok := g.allowedRule(host, port, false)
	event.Hostname, event.Port = host, port
	if !ok {
		reject(http.StatusForbidden, "origin_not_allowed")
		return
	}
	event.Category = rule.Category
	addresses, reason := g.resolvePublic(request.Context(), host)
	if reason != "" {
		reject(http.StatusForbidden, reason)
		return
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return g.dialAddresses(ctx, network, addresses, port)
	}
	outbound := request.Clone(request.Context())
	outbound.RequestURI = ""
	outbound.Host = hostWithPort(host, port, 80)
	outbound.Header = request.Header.Clone()
	removeHopHeaders(outbound.Header)
	outbound.Header.Del("Proxy-Authorization")
	upstream, err := transport.RoundTrip(outbound)
	if err != nil {
		reject(http.StatusBadGateway, "upstream_unavailable")
		return
	}
	defer upstream.Body.Close()
	removeHopHeaders(upstream.Header)
	for key, values := range upstream.Header {
		for _, value := range values {
			response.Header().Add(key, value)
		}
	}
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(upstream.StatusCode)
	event.Allowed = true
	if request.Method == http.MethodHead {
		return
	}
	written, copyErr := copyLimited(&totalQuotaWriter{destination: response, used: &g.totalBytes, maximum: g.capability.MaxTotalBytes}, upstream.Body, g.capability.MaxDownloadBytes)
	event.DownloadBytes = written
	if copyErr != nil {
		if errors.Is(copyErr, errTotalLimit) {
			event.Reason = "total_byte_quota_exceeded"
		} else {
			event.Reason = "download_quota_exceeded"
		}
		return
	}
}

func (g *Gateway) serveConnect(response http.ResponseWriter, request *http.Request, event *AuditEvent, reject func(int, string)) {
	if request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
		reject(http.StatusRequestEntityTooLarge, "connect_body_not_allowed")
		return
	}
	host, port, err := splitTarget(request.Host, 443)
	if err != nil || port != 443 {
		reject(http.StatusForbidden, "connect_target_not_allowed")
		return
	}
	rule, ok := g.allowedRule(host, port, true)
	event.Hostname, event.Port = host, port
	if !ok {
		reject(http.StatusForbidden, "origin_not_allowed")
		return
	}
	event.Category = rule.Category
	addresses, reason := g.resolvePublic(request.Context(), host)
	if reason != "" {
		reject(http.StatusForbidden, reason)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), g.capability.MaxConnectTime)
	defer cancel()
	upstream, err := g.dialAddresses(ctx, "tcp", addresses, port)
	if err != nil {
		reject(http.StatusBadGateway, "upstream_unavailable")
		return
	}
	defer upstream.Close()
	hijacker, ok := response.(http.Hijacker)
	if !ok {
		reject(http.StatusInternalServerError, "hijack_unavailable")
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	if buffered.Reader.Buffered() != 0 {
		event.Reason = "connect_pipelining_not_allowed"
		return
	}
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || buffered.Flush() != nil {
		return
	}
	event.Allowed = true
	deadline := g.now().Add(g.capability.MaxConnectTime)
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	type result struct {
		direction string
		bytes     int64
		err       error
	}
	results := make(chan result, 2)
	go func() {
		count, err := copyLimited(&totalQuotaWriter{destination: upstream, used: &g.totalBytes, maximum: g.capability.MaxTotalBytes}, client, g.capability.MaxUploadBytes)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		results <- result{direction: "upload", bytes: count, err: err}
	}()
	go func() {
		count, err := copyLimited(&totalQuotaWriter{destination: client, used: &g.totalBytes, maximum: g.capability.MaxTotalBytes}, upstream, g.capability.MaxDownloadBytes)
		if tcp, ok := client.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		results <- result{direction: "download", bytes: count, err: err}
	}()
	first := <-results
	_ = client.SetDeadline(time.Now())
	_ = upstream.SetDeadline(time.Now())
	second := <-results
	for _, completed := range []result{first, second} {
		if completed.direction == "upload" {
			event.UploadBytes = completed.bytes
		} else {
			event.DownloadBytes = completed.bytes
		}
	}
	if errors.Is(first.err, errByteLimit) || errors.Is(second.err, errByteLimit) {
		event.Reason = "tunnel_byte_quota_exceeded"
	}
	if errors.Is(first.err, errTotalLimit) || errors.Is(second.err, errTotalLimit) {
		event.Reason = "total_byte_quota_exceeded"
	}
	if first.err != nil && !isExpectedTunnelEnd(first.err) || second.err != nil && !isExpectedTunnelEnd(second.err) {
		event.Reason = "tunnel_closed"
	}
}

func proxyToken(header string) (string, bool) {
	if strings.HasPrefix(header, "Bearer ") {
		return strings.TrimPrefix(header, "Bearer "), true
	} else if strings.HasPrefix(header, "Basic ") {
		request := &http.Request{Header: http.Header{"Authorization": []string{header}}}
		_, password, ok := request.BasicAuth()
		if !ok {
			return "", false
		}
		return password, true
	}
	return "", false
}

func (g *Gateway) allowedRule(host string, port uint16, connect bool) (OriginRule, bool) {
	for suffix := host; ; {
		if _, blocked := g.blockedDomains[suffix]; blocked {
			return OriginRule{}, false
		}
		dot := strings.IndexByte(suffix, '.')
		if dot < 0 {
			break
		}
		suffix = suffix[dot+1:]
	}
	key := ruleLookup{host: host, port: port, connect: connect}
	best, matched := g.exactRules[key]
	for suffix := host; ; {
		key.host = suffix
		if candidate, exists := g.suffixRules[key]; exists && (!matched || candidate.index < best.index) {
			best, matched = candidate, true
		}
		dot := strings.IndexByte(suffix, '.')
		if dot < 0 {
			break
		}
		suffix = suffix[dot+1:]
	}
	if matched {
		return best.rule, true
	}
	return OriginRule{}, false
}

func (g *Gateway) resolvePublic(ctx context.Context, host string) ([]netip.Addr, string) {
	if _, err := netip.ParseAddr(host); err == nil {
		return nil, "ip_literal_not_allowed"
	}
	addresses, err := g.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 || len(addresses) > 32 {
		return nil, "dns_resolution_failed"
	}
	result := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !isPublicAddress(address) {
			return nil, "resolved_address_not_public"
		}
		if _, ok := seen[address]; !ok {
			seen[address] = struct{}{}
			result = append(result, address)
		}
	}
	return result, ""
}

func (g *Gateway) dialAddresses(ctx context.Context, network string, addresses []netip.Addr, port uint16) (net.Conn, error) {
	var errs []error
	for _, address := range addresses {
		connection, err := g.dial(ctx, network, net.JoinHostPort(address.String(), strconv.Itoa(int(port))))
		if err == nil {
			return connection, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func normalizeHostname(value string) (string, error) {
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if len(value) == 0 || len(value) > 253 || strings.ContainsAny(value, ":/%\\@[]") {
		return "", fmt.Errorf("invalid hostname")
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return "", fmt.Errorf("IP literals are not hostnames")
	}
	for _, character := range value {
		if character > 127 {
			return "", fmt.Errorf("hostname must be ASCII")
		}
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid hostname label")
		}
		for _, character := range label {
			if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-') {
				return "", fmt.Errorf("invalid hostname character")
			}
		}
	}
	return value, nil
}

func mustNormalize(value string) string {
	host, _ := normalizeHostname(value)
	return host
}

func splitTarget(value string, defaultPort uint16) (string, uint16, error) {
	host := value
	port := defaultPort
	if parsedHost, parsedPort, err := net.SplitHostPort(value); err == nil {
		host = parsedHost
		parsed, parseErr := strconv.ParseUint(parsedPort, 10, 16)
		if parseErr != nil || parsed == 0 {
			return "", 0, fmt.Errorf("invalid target port")
		}
		port = uint16(parsed)
	} else if strings.Contains(value, ":") {
		return "", 0, fmt.Errorf("target port is invalid")
	}
	normalized, err := normalizeHostname(host)
	return normalized, port, err
}

func hostWithPort(host string, port, defaultPort uint16) string {
	if port == defaultPort {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

var deniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
}

func isPublicAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range deniedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func removeHopHeaders(header http.Header) {
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
}

var errByteLimit = errors.New("Web Gateway byte limit exceeded")
var errTotalLimit = errors.New("Web Gateway total byte limit exceeded")

type totalQuotaWriter struct {
	destination io.Writer
	used        *atomic.Int64
	maximum     int64
}

func (w *totalQuotaWriter) Write(value []byte) (int, error) {
	for {
		used := w.used.Load()
		remaining := w.maximum - used
		if remaining <= 0 {
			return 0, errTotalLimit
		}
		allowed := len(value)
		if int64(allowed) > remaining {
			allowed = int(remaining)
		}
		if !w.used.CompareAndSwap(used, used+int64(allowed)) {
			continue
		}
		written, err := w.destination.Write(value[:allowed])
		if err != nil {
			return written, err
		}
		if written != allowed {
			return written, io.ErrShortWrite
		}
		if allowed != len(value) {
			return written, errTotalLimit
		}
		return written, nil
	}
}

func copyLimited(destination io.Writer, source io.Reader, maximum int64) (int64, error) {
	buffer := make([]byte, 32<<10)
	var written int64
	for {
		read, readErr := source.Read(buffer)
		if read > 0 {
			remaining := maximum - written
			if remaining <= 0 {
				return written, errByteLimit
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
			if count != toWrite {
				return written, io.ErrShortWrite
			}
			if toWrite != read {
				return written, errByteLimit
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

func isExpectedTunnelEnd(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}
