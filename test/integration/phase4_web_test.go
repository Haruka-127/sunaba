//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"sunaba/internal/audit"
	"sunaba/internal/dependency"
	"sunaba/internal/modelgateway"
	"sunaba/internal/opencode"
	sunabaruntime "sunaba/internal/runtime"
	"sunaba/internal/session"
	"sunaba/internal/state"
	"sunaba/internal/webgateway"
)

type phase4Resolver map[string][]netip.Addr

func (r phase4Resolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r[host]...), nil
}

func TestPhase4WebGatewayInAgentVM(t *testing.T) {
	if os.Getenv("SUNABA_PHASE4_INTEGRATION") != "1" {
		t.Skip("set SUNABA_PHASE4_INTEGRATION=1 on the pinned macOS/Apple Container host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	runtimeBase, err := os.MkdirTemp("/private/tmp", "sunaba-phase4-web-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runtimeBase, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(runtimeBase)
	project := filepath.Join(runtimeBase, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	writeIntegrationFile(t, filepath.Join(project, "README.md"), "phase4 web gateway\n")

	var observedMu sync.Mutex
	var observed []string
	webUpstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		observedMu.Lock()
		observed = append(observed, request.Method+" "+request.URL.Path+" "+request.UserAgent())
		observedMu.Unlock()
		switch request.URL.Path {
		case "/start":
			response.Header().Set("Location", "http://measure.invalid/final")
			response.WriteHeader(http.StatusFound)
		case "/cross-origin":
			response.Header().Set("Location", "http://not-allowed.invalid/final")
			response.WriteHeader(http.StatusFound)
		case "/final":
			_, _ = io.WriteString(response, "phase4 proxied content")
		default:
			http.NotFound(response, request)
		}
	}))
	defer webUpstream.Close()
	mcpCalled := make(chan struct{}, 1)
	tlsUpstream, testCAPEM := newPhase4TLSServer(t, []string{"example.com", "mcp.exa.ai"}, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Host == "mcp.exa.ai" && request.URL.Path == "/mcp" {
			body, _ := io.ReadAll(request.Body)
			if !strings.Contains(string(body), `"method":"tools/call"`) || !strings.Contains(string(body), `"name":"web_search_exa"`) {
				t.Errorf("unexpected OpenCode MCP request: %s", body)
			}
			select {
			case mcpCalled <- struct{}{}:
			default:
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"phase4 mock search result"}]}}`)
			return
		}
		_, _ = io.WriteString(response, "verified TLS tunnel")
	}))
	defer tlsUpstream.Close()

	modelID := "gpt-sunaba-phase4"
	toolCalled := make(chan struct{}, 1)
	desiredTool := "webfetch"
	var desiredToolMu sync.Mutex
	modelUpstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		if strings.Contains(string(body), `"type":"function_call_output"`) || strings.Contains(string(body), `"type": "function_call_output"`) {
			writeResponsesTextStream(response, modelID, "phase4 webfetch complete")
			return
		}
		select {
		case toolCalled <- struct{}{}:
		default:
		}
		desiredToolMu.Lock()
		tool := desiredTool
		desiredToolMu.Unlock()
		if tool == "websearch" {
			writeResponsesFunctionCallStream(response, modelID, "websearch", `{"query":"sunaba phase4 integration query","numResults":1,"type":"fast"}`)
			return
		}
		writeResponsesFunctionCallStream(response, modelID, "webfetch", `{"url":"http://measure.invalid/start","format":"text","timeout":5}`)
	}))
	defer modelUpstream.Close()

	runID := randomID(t)
	projectID := state.ProjectID(project)
	sessionID := "p4w" + runID
	vmID := "sunaba-" + projectID + "-" + sessionID
	modelToken, _ := session.NewSecret()
	webToken, _ := session.NewSecret()
	serverPassword, _ := session.NewSecret()
	expiresAt := time.Now().Add(5 * time.Minute)
	modelCapability, err := modelgateway.NewCapability(modelToken, projectID, vmID, sessionID, modelID, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	modelHandler, err := modelgateway.New(modelgateway.Config{UpstreamBaseURL: modelUpstream.URL, UpstreamAPIKey: "phase4-host-only-key", Capability: modelCapability})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := opencode.BuildModelGatewayConfig(opencode.ModelGatewayProviderConfig{
		BaseURL: "http://127.0.0.1:4141/v1", Model: modelID, TokenEnv: "SUNABA_MODEL_GATEWAY_TOKEN", ContextLimit: 200_000, OutputLimit: 32_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	auditRecorder, err := audit.NewRecorder(filepath.Join(runtimeBase, "state", "audit"))
	if err != nil {
		t.Fatal(err)
	}
	policy := webgateway.Policy{
		Rules: []webgateway.OriginRule{
			{Host: "measure.invalid", Port: 80, Category: "general", AllowHTTP: true},
			{Host: "private.invalid", Port: 80, Category: "general", AllowHTTP: true},
			{Host: "blocked.invalid", Port: 80, Category: "general", AllowHTTP: true},
			{Host: "example.com", Port: 443, Category: "general", AllowConnect: true},
			{Host: "mcp.exa.ai", Port: 443, Category: "search", AllowConnect: true},
		},
		BlockedDomains: []string{"blocked.invalid"},
	}
	policyDigest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	webCapability, err := webgateway.NewCapability(webToken, projectID, vmID, sessionID, policyDigest, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	auditErrors := make(chan error, 32)
	webGateway, err := webgateway.New(webgateway.Config{
		Policy: policy, Capability: webCapability,
		Resolver: phase4Resolver{
			"measure.invalid": {netip.MustParseAddr("93.184.216.34")},
			"private.invalid": {netip.MustParseAddr("169.254.169.254")},
			"blocked.invalid": {netip.MustParseAddr("93.184.216.34")},
			"example.com":     {netip.MustParseAddr("93.184.216.34")},
			"mcp.exa.ai":      {netip.MustParseAddr("1.1.1.1")},
		},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			target := strings.TrimPrefix(webUpstream.URL, "http://")
			if strings.HasSuffix(address, ":443") {
				target = strings.TrimPrefix(tlsUpstream.URL, "https://")
			}
			return (&net.Dialer{}).DialContext(ctx, network, target)
		},
		Audit: func(event webgateway.AuditEvent) error {
			outcome := "denied"
			if event.Allowed {
				outcome = "allowed"
			}
			err := auditRecorder.Append(audit.BoundaryEvent{
				Category: "gateway", Action: "web.request", Outcome: outcome,
				ProjectID: event.ProjectID, VMID: event.VMID, SessionID: event.SessionID,
				Details: map[string]string{
					"origin_category": event.Category, "hostname": event.Hostname, "port": strconv.Itoa(int(event.Port)),
					"method": event.Method, "reason": event.Reason, "upload_bytes": strconv.FormatInt(event.UploadBytes, 10),
					"download_bytes": strconv.FormatInt(event.DownloadBytes, 10), "duration_ms": strconv.FormatInt(event.Duration.Milliseconds(), 10),
				},
			})
			if err != nil {
				auditErrors <- err
			}
			return err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	relay := buildLinuxBinary(t, ctx, runtimeBase, "sunaba-guest-relay", "./cmd/sunaba-guest-relay")
	cfg := session.Config{
		Store: &state.Store{Root: filepath.Join(runtimeBase, "state")}, Runtime: sunabaruntime.NewAppleContainer(false),
		ProjectRoot: project, RuntimeBase: runtimeBase, SessionID: sessionID,
		Image: dependency.MustPinned().AgentImage.Tag, CPUs: 1, Memory: "2G", DiskBytes: 128 << 20,
		ProcessMax: 512, FileSizeMax: 128 << 20, OpenFileMax: 4096,
		GuestRelayBinary: relay, ProviderConfig: provider, ModelGateway: modelHandler, ModelToken: modelToken,
		WebGateway: webGateway, WebToken: webToken, WebGatewayClose: func() error { webGateway.Revoke(); return nil },
		ServerPassword: serverPassword, LeaseTTL: 5 * time.Minute, Audit: auditRecorder,
	}
	active, err := session.Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	destroyed := false
	defer func() {
		if !destroyed {
			_ = active.Destroy(context.Background())
		}
	}()

	guestProxyEnvironment := "set -a; . /run/sunaba/session.env; set +a; export HTTP_PROXY=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343 HTTPS_PROXY=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343 http_proxy=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343 https_proxy=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343 NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost APT_CONFIG=/run/sunaba/apt-proxy.conf; "
	runGuest := func(command string) (string, error) {
		return cfg.Runtime.ExecOutput(ctx, active.Container, []string{"runuser", "-u", "sunaba-agent", "--", "/bin/bash", "-lc", guestProxyEnvironment + command})
	}
	if output, err := runGuest("curl --silent --show-error --fail --location --max-time 10 http://measure.invalid/start"); err != nil || strings.TrimSpace(output) != "phase4 proxied content" {
		t.Fatalf("curl through Web Gateway: %v %q", err, output)
	}
	if output, err := runGuest("wget -qO- -T 10 http://measure.invalid/final"); err != nil || strings.TrimSpace(output) != "phase4 proxied content" {
		t.Fatalf("wget through Web Gateway: %v %q", err, output)
	}
	aptCommand := "mkdir -p /tmp/sunaba-p4-apt/lists/partial /tmp/sunaba-p4-apt/cache/archives/partial; printf 'deb [trusted=yes] http://measure.invalid/debian stable main\\n' >/tmp/sunaba-p4.list; apt-get -o Dir::Etc::sourcelist=/tmp/sunaba-p4.list -o Dir::Etc::sourceparts=- -o Dir::State::lists=/tmp/sunaba-p4-apt/lists -o Dir::Cache=/tmp/sunaba-p4-apt/cache -o Debug::NoLocking=1 -o Acquire::Retries=0 -o Acquire::http::Timeout=2 update"
	if output, err := runGuest(aptCommand); err != nil {
		t.Logf("synthetic apt repository stopped after exercising metadata requests: error=%v output=%s", err, output)
	}

	caPath := filepath.Join(runtimeBase, "phase4-ca.pem")
	if err := os.WriteFile(caPath, testCAPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Runtime.CopyTo(ctx, active.Container, caPath, "/run/sunaba/phase4-ca.pem"); err != nil {
		t.Fatal(err)
	}
	if output, err := runGuest("curl --silent --show-error --fail --max-time 10 --cacert /run/sunaba/phase4-ca.pem https://example.com/"); err != nil || strings.TrimSpace(output) != "verified TLS tunnel" {
		t.Fatalf("verified TLS CONNECT tunnel: %v %q", err, output)
	}

	attackCommands := []string{
		"! curl --silent --show-error --fail --max-time 5 http://private.invalid/latest/meta-data/",
		"! curl --silent --show-error --fail --max-time 5 http://blocked.invalid/payload",
		"! curl --silent --show-error --fail --max-time 5 http://93.184.216.34/direct",
		"! curl --silent --show-error --fail --max-time 5 --data secret-upload http://measure.invalid/upload",
		"! curl --silent --show-error --fail --location --max-time 5 http://measure.invalid/cross-origin",
	}
	for _, command := range attackCommands {
		if output, err := runGuest(command); err != nil {
			t.Fatalf("Web attack was not rejected command=%q error=%v output=%q", command, err, output)
		}
	}
	message := exerciseOpenCodeResponses(t, ctx, filepath.Join(active.Root, "attach.sock"), serverPassword, modelID)
	if !strings.Contains(message, "phase4 webfetch complete") {
		t.Fatalf("OpenCode webfetch did not complete through Web Gateway: %s", message)
	}
	select {
	case <-toolCalled:
	case <-time.After(5 * time.Second):
		t.Fatal("mock model did not issue webfetch")
	}
	desiredToolMu.Lock()
	desiredTool = "websearch"
	desiredToolMu.Unlock()
	searchProfile := "/tmp/sunaba-p4-search"
	searchCommand := "mkdir -p " + searchProfile + "/home " + searchProfile + "/config " + searchProfile + "/data; exec env HOME=" + searchProfile + "/home XDG_CONFIG_HOME=" + searchProfile + "/config XDG_DATA_HOME=" + searchProfile + "/data OPENCODE_CONFIG=/run/sunaba/opencode.json OPENCODE_DISABLE_AUTOUPDATE=1 OPENCODE_DISABLE_MODELS_FETCH=1 OPENCODE_DISABLE_LSP_DOWNLOAD=1 OPENCODE_DISABLE_DEFAULT_PLUGINS=1 OPENCODE_ENABLE_EXA=1 OPENCODE_WEBSEARCH_PROVIDER=exa NODE_EXTRA_CA_CERTS=/run/sunaba/phase4-ca.pem opencode run --model sunaba/" + modelID + " 'run websearch once'"
	if output, err := runGuest(searchCommand); err != nil || !strings.Contains(output, "phase4 webfetch complete") {
		t.Fatalf("OpenCode websearch through Web Gateway: %v %q", err, output)
	}
	select {
	case <-mcpCalled:
	case <-time.After(5 * time.Second):
		t.Fatal("OpenCode websearch did not reach the mock Exa MCP endpoint")
	}

	webClient := unixHTTPClient(filepath.Join(active.Root, "web-gateway.sock"))
	if err := active.Pause(ctx); err != nil {
		t.Fatal(err)
	}
	pausedRequest, _ := http.NewRequest(http.MethodGet, "http://measure.invalid/final", nil)
	pausedRequest.Header.Set("Proxy-Authorization", "Bearer "+webToken)
	pausedResponse, err := webClient.Do(pausedRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = pausedResponse.Body.Close()
	if pausedResponse.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("paused Web Gateway status=%d", pausedResponse.StatusCode)
	}
	if err := active.Resume(ctx); err != nil {
		t.Fatal(err)
	}

	result, err := active.StopAndExport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertArchiveHasNoSecrets(t, result.Archive, "phase4-host-only-key", modelToken, webToken, serverPassword)
	if err := active.Destroy(ctx); err != nil {
		t.Fatal(err)
	}
	destroyed = true
	select {
	case auditErr := <-auditErrors:
		t.Fatalf("Web audit append failed: %v", auditErr)
	default:
	}
	observedMu.Lock()
	observedTraffic := strings.Join(observed, "\n")
	observedMu.Unlock()
	for _, want := range []string{"GET /start", "GET /final", "Debian APT-HTTP"} {
		if !strings.Contains(observedTraffic, want) {
			t.Fatalf("missing upstream traffic %q:\n%s", want, observedTraffic)
		}
	}
	auditFiles, _ := filepath.Glob(filepath.Join(auditRecorder.Root, projectID, "audit-*.jsonl"))
	if len(auditFiles) != 1 {
		t.Fatalf("unexpected audit files: %v", auditFiles)
	}
	encodedAudit, err := os.ReadFile(auditFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"action":"web.request"`, `"hostname":"measure.invalid"`, `"reason":"resolved_address_not_public"`, `"reason":"http_method_not_allowed"`} {
		if !strings.Contains(string(encodedAudit), want) {
			t.Errorf("Web audit missing %s", want)
		}
	}
	for _, forbidden := range []string{"latest/meta-data", "secret-upload", "cross-origin", "sunaba phase4 integration query", webToken} {
		if strings.Contains(string(encodedAudit), forbidden) {
			t.Fatalf("Web audit leaked request content %q", forbidden)
		}
	}
	t.Logf("Phase 4 Web Gateway gate passed for %s", fmt.Sprintf("%s/%s", projectID, sessionID))
}

func newPhase4TLSServer(t *testing.T, dnsNames []string, handler http.Handler) (*httptest.Server, []byte) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sunaba phase4 test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: dnsNames[0]}, DNSNames: dnsNames,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCertificate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	return server, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}
