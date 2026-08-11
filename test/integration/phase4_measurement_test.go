//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
)

type measuredWebRequest struct {
	Method    string
	Scheme    string
	Host      string
	Path      string
	UserAgent string
	BodyBytes int
}

func TestPhase4MeasureWebClients(t *testing.T) {
	if os.Getenv("SUNABA_PHASE4_MEASUREMENT") != "1" {
		t.Skip("set SUNABA_PHASE4_MEASUREMENT=1 on the pinned macOS/Apple Container host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	runtimeBase, err := os.MkdirTemp("/private/tmp", "sunaba-phase4-measure-")
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
	writeIntegrationFile(t, filepath.Join(project, "README.md"), "phase4 measurement\n")
	var requestMu sync.Mutex
	var measured []measuredWebRequest
	proxy := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(request.Body, 1<<20))
		scheme := request.URL.Scheme
		host := request.URL.Host
		if request.Method == http.MethodConnect {
			scheme, host = "https", request.Host
		}
		requestMu.Lock()
		measured = append(measured, measuredWebRequest{Method: request.Method, Scheme: scheme, Host: host, Path: request.URL.Path, UserAgent: request.UserAgent(), BodyBytes: len(body)})
		requestMu.Unlock()
		if request.Method == http.MethodConnect {
			http.Error(response, "measurement CONNECT stop", http.StatusBadGateway)
			return
		}
		if request.URL.Path == "/start" {
			response.Header().Set("Location", "http://measure.invalid/final")
			response.WriteHeader(http.StatusFound)
			return
		}
		if request.URL.Path == "/final" {
			response.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(response, "measured web content")
			return
		}
		http.NotFound(response, request)
	})
	var toolMu sync.Mutex
	desiredTool := ""
	modelID := "gpt-sunaba-measure"
	modelUpstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		if strings.Contains(string(body), `"type":"function_call_output"`) || strings.Contains(string(body), `"type": "function_call_output"`) {
			writeResponsesTextStream(response, modelID, "measurement complete")
			return
		}
		toolMu.Lock()
		tool := desiredTool
		toolMu.Unlock()
		switch tool {
		case "webfetch":
			writeResponsesFunctionCallStream(response, modelID, "webfetch", `{"url":"http://measure.invalid/start","format":"text","timeout":5}`)
		case "websearch":
			writeResponsesFunctionCallStream(response, modelID, "websearch", `{"query":"sunaba phase4 measurement","numResults":1,"type":"fast"}`)
		default:
			writeResponsesTextStream(response, modelID, "no tool")
		}
	}))
	defer modelUpstream.Close()
	runID := randomID(t)
	projectID := state.ProjectID(project)
	sessionID := "p4m" + runID
	vmID := "sunaba-" + projectID + "-" + sessionID
	modelToken, _ := session.NewSecret()
	serverPassword, _ := session.NewSecret()
	proxyToken, _ := session.NewSecret()
	modelCapability, err := modelgateway.NewCapability(modelToken, projectID, vmID, sessionID, modelID, time.Now().Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	modelHandler, err := modelgateway.New(modelgateway.Config{UpstreamBaseURL: modelUpstream.URL, UpstreamAPIKey: "measurement-key", Capability: modelCapability})
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
	relay := buildLinuxBinary(t, ctx, runtimeBase, "sunaba-guest-relay", "./cmd/sunaba-guest-relay")
	cfg := session.Config{
		Store: &state.Store{Root: filepath.Join(runtimeBase, "state")}, Runtime: sunabaruntime.NewAppleContainer(false),
		ProjectRoot: project, RuntimeBase: runtimeBase, SessionID: sessionID,
		Image: dependency.MustPinned().AgentImage.Tag, CPUs: 1, Memory: "2G", DiskBytes: 128 << 20,
		ProcessMax: 512, FileSizeMax: 128 << 20, OpenFileMax: 4096,
		GuestRelayBinary: relay, ProviderConfig: provider, ModelGateway: modelHandler, ModelToken: modelToken,
		GitGateway: proxy, GitToken: proxyToken, GitGatewayClose: func() error { return nil },
		ServerPassword: serverPassword, LeaseTTL: 4 * time.Minute, Audit: auditRecorder,
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
	commands := []string{
		"curl --silent --show-error --location --max-time 5 --proxy http://127.0.0.1:4242 http://measure.invalid/start",
		"wget -qO- -e use_proxy=yes -e http_proxy=http://127.0.0.1:4242 http://measure.invalid/start",
		"curl --silent --show-error --max-time 5 --proxy http://127.0.0.1:4242 --data measurement-upload http://measure.invalid/upload",
		"curl --silent --show-error --max-time 5 --proxy http://127.0.0.1:4242 https://measure.invalid/start",
		"printf 'deb [trusted=yes] http://measure.invalid/debian stable main\\n' >/run/sunaba/measure.list; apt-get -o Dir::Etc::sourcelist=/run/sunaba/measure.list -o Dir::Etc::sourceparts=- -o Acquire::http::Proxy=http://127.0.0.1:4242 -o Acquire::Retries=0 -o Acquire::http::Timeout=2 update",
	}
	for _, command := range commands {
		output, commandErr := cfg.Runtime.ExecOutput(ctx, active.Container, []string{"/bin/bash", "-lc", command})
		t.Logf("measurement command=%q output=%q error=%v", command, output, commandErr)
	}
	toolMu.Lock()
	desiredTool = "webfetch"
	toolMu.Unlock()
	runMeasuredOpenCode(t, ctx, cfg.Runtime, active.Container, active.WorkspacePath, "webfetch", false)
	toolMu.Lock()
	desiredTool = "websearch"
	toolMu.Unlock()
	runMeasuredOpenCode(t, ctx, cfg.Runtime, active.Container, active.WorkspacePath, "websearch", true)
	installed, err := cfg.Runtime.ExecOutput(ctx, active.Container, []string{"/bin/bash", "-lc", "for tool in apt-get npm pip pip3 go cargo; do if command -v $tool >/dev/null; then printf '%s=present\\n' $tool; else printf '%s=absent\\n' $tool; fi; done"})
	if err != nil {
		t.Fatal(err)
	}
	if err := active.Destroy(ctx); err != nil {
		t.Fatal(err)
	}
	destroyed = true
	requestMu.Lock()
	observed := append([]measuredWebRequest(nil), measured...)
	requestMu.Unlock()
	encoded, _ := json.MarshalIndent(struct {
		Requests []measuredWebRequest `json:"requests"`
		Tools    string               `json:"installed_tools"`
	}{Requests: observed, Tools: installed}, "", "  ")
	t.Logf("Phase 4 measurement:\n%s", encoded)
	assertMeasuredWebTraffic(t, observed, installed)
}

func runMeasuredOpenCode(t *testing.T, ctx context.Context, runtime sunabaruntime.Runtime, container, workspace, tool string, enableSearch bool) {
	t.Helper()
	directory := "/run/sunaba/measure-" + tool
	setup := "mkdir -p " + directory + "/config " + directory + "/data " + directory + "/home; chown -R 1000:1000 " + directory
	if output, err := runtime.ExecOutput(ctx, container, []string{"/bin/bash", "-lc", setup}); err != nil {
		t.Fatalf("prepare OpenCode %s measurement: %v: %s", tool, err, output)
	}
	searchEnvironment := ""
	if enableSearch {
		searchEnvironment = " OPENCODE_ENABLE_EXA=1 OPENCODE_WEBSEARCH_PROVIDER=exa"
	}
	command := "set -a; . /run/sunaba/session.env; set +a; exec env HOME=" + directory + "/home XDG_CONFIG_HOME=" + directory + "/config XDG_DATA_HOME=" + directory + "/data HTTP_PROXY=http://127.0.0.1:4242 HTTPS_PROXY=http://127.0.0.1:4242 http_proxy=http://127.0.0.1:4242 https_proxy=http://127.0.0.1:4242 NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost OPENCODE_CONFIG=/run/sunaba/opencode.json OPENCODE_DISABLE_AUTOUPDATE=1 OPENCODE_DISABLE_MODELS_FETCH=1 OPENCODE_DISABLE_LSP_DOWNLOAD=1 OPENCODE_DISABLE_DEFAULT_PLUGINS=1" + searchEnvironment + " opencode run --model sunaba/gpt-sunaba-measure 'run the " + tool + " tool once'"
	_, _ = runtime.ExecOutput(ctx, container, []string{"runuser", "-u", "sunaba-agent", "--", "/bin/bash", "-lc", "cd " + workspace + "; " + command})
}

func assertMeasuredWebTraffic(t *testing.T, requests []measuredWebRequest, installed string) {
	t.Helper()
	has := func(match func(measuredWebRequest) bool) bool {
		for _, request := range requests {
			if match(request) {
				return true
			}
		}
		return false
	}
	checks := map[string]bool{
		"HTTP GET":       has(func(r measuredWebRequest) bool { return r.Method == http.MethodGet && r.Host == "measure.invalid" }),
		"redirect final": has(func(r measuredWebRequest) bool { return r.Path == "/final" }),
		"HTTP upload":    has(func(r measuredWebRequest) bool { return r.Method == http.MethodPost && r.BodyBytes > 0 }),
		"HTTPS CONNECT": has(func(r measuredWebRequest) bool {
			return r.Method == http.MethodConnect && strings.HasPrefix(r.Host, "measure.invalid:443")
		}),
		"apt metadata": has(func(r measuredWebRequest) bool {
			return strings.Contains(r.UserAgent, "Debian APT-HTTP") || strings.Contains(r.Path, "/debian/dists/")
		}),
		"OpenCode fetch": has(func(r measuredWebRequest) bool {
			return r.Path == "/start" && strings.Contains(r.UserAgent, "Mozilla/5.0")
		}),
		"websearch Exa": has(func(r measuredWebRequest) bool {
			return r.Method == http.MethodConnect && strings.HasPrefix(r.Host, "mcp.exa.ai:443")
		}),
	}
	for name, ok := range checks {
		if !ok {
			t.Errorf("missing measured behavior %s: %+v", name, requests)
		}
	}
	for _, expected := range []string{"apt-get=present", "npm=absent", "pip=absent", "go=absent", "cargo=absent"} {
		if !strings.Contains(installed, expected) {
			t.Errorf("unexpected exact base-image tool inventory, missing %q: %s", expected, installed)
		}
	}
}
