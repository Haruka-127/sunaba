//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"sunaba/internal/attachrelay"
	"sunaba/internal/dependency"
	"sunaba/internal/modelgateway"
	"sunaba/internal/opencode"
	sunabaruntime "sunaba/internal/runtime"
)

func TestPhase0SecureNetworkAndGatewayTransport(t *testing.T) {
	if os.Getenv("SUNABA_PHASE0_INTEGRATION") != "1" {
		t.Skip("set SUNABA_PHASE0_INTEGRATION=1 on the pinned macOS/Apple Container host")
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Fatalf("requires darwin/arm64, got %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	runID := randomID(t)
	name := "sunaba-phase0-network-" + runID
	manifest := dependency.MustPinned()
	rt := sunabaruntime.NewAppleContainer(false)
	if state, err := rt.ContainerState(ctx, name); err != nil || state != sunabaruntime.StateNotFound {
		t.Fatalf("probe resource name is not unused: state=%s error=%v", state, err)
	}

	tempDir := filepath.Join("/private/tmp", "sunaba-session-"+runID)
	if err := os.Mkdir(tempDir, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	socketPath := filepath.Join(tempDir, "model-gateway.sock")
	attachSocketPath := filepath.Join(tempDir, "attach.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socketPath, 0600); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	nonce := "gateway-" + runID
	modelID := "gpt-sunaba-test"
	modelToken := "model-" + runID + "-" + strings.Repeat("t", 32)
	upstreamKey := "upstream-" + runID
	upstreamRequest := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer "+upstreamKey {
			http.Error(w, "invalid upstream request", http.StatusUnauthorized)
			return
		}
		select {
		case upstreamRequest <- struct{}{}:
		default:
		}
		writeResponsesTextStream(w, modelID, "hello from gateway")
	}))
	defer upstream.Close()
	capability, err := modelgateway.NewCapability(modelToken, "phase0-project-a", name, runID, modelID, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	modelGateway, err := modelgateway.New(modelgateway.Config{
		UpstreamBaseURL: upstream.URL, UpstreamAPIKey: upstreamKey, Capability: capability,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			_, _ = fmt.Fprint(w, nonce)
			return
		}
		modelGateway.ServeHTTP(w, r)
	})}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(listener) }()
	defer func() {
		_ = server.Close()
		<-serverDone
	}()
	otherRoot := filepath.Join("/private/tmp", "sunaba-session-other-"+runID)
	if err := os.Mkdir(otherRoot, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(otherRoot)
	otherSocketPath := filepath.Join(otherRoot, "model-gateway.sock")
	otherListener, err := net.Listen("unix", otherSocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer otherListener.Close()
	if err := os.Chmod(otherSocketPath, 0600); err != nil {
		t.Fatal(err)
	}
	policy := sunabaruntime.SecureSessionPolicy{
		ProjectID: "phase0-project-a", SessionID: runID,
		Image: manifest.AgentImage.Tag, SessionRoot: tempDir,
	}
	policyDigest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}

	spec := sunabaruntime.ContainerSpec{
		Name:       name,
		Image:      manifest.AgentImage.Tag,
		CPUs:       1,
		Memory:     "2G",
		Networks:   []string{"none"},
		NoDNS:      true,
		CapAdd:     []string{"ALL"},
		Entrypoint: "/bin/bash",
		Args:       []string{"-lc", "exec tail -f /dev/null"},
		Mounts: []sunabaruntime.Mount{{
			Type: "socket", Source: socketPath, Target: sunabaruntime.SecureGatewayGuestPath,
		}},
		Sockets: []sunabaruntime.PublishedSocket{{
			HostPath: attachSocketPath, GuestPath: sunabaruntime.SecureAttachGuestPath,
		}},
		Labels: map[string]string{
			"dev.sunaba.owner":         "sunaba-supervisor",
			"dev.sunaba.test":          "phase0-network",
			"dev.sunaba.run-id":        runID,
			"dev.sunaba.version":       manifest.AppleContainer.Version,
			"dev.sunaba.project":       policy.ProjectID,
			"dev.sunaba.session":       policy.SessionID,
			"dev.sunaba.mode":          "secure",
			"dev.sunaba.policy-digest": policyDigest,
		},
	}
	if err := rt.CreateSecure(ctx, spec, policy); err != nil {
		t.Fatal(err)
	}
	defer cleanupContainer(t, ctx, rt, name, runID)

	probeBinary := buildLinuxBinary(t, ctx, tempDir, "netprobe", "./test/fixtures/netprobe")
	if err := rt.CopyTo(ctx, name, probeBinary, "/tmp/sunaba-netprobe"); err != nil {
		t.Fatal(err)
	}
	if err := rt.Exec(ctx, name, false, []string{"chmod", "0700", "/tmp/sunaba-netprobe"}); err != nil {
		t.Fatal(err)
	}
	if out, err := rt.ExecOutput(ctx, name, []string{"/tmp/sunaba-netprobe"}); err != nil {
		t.Fatalf("secure network invariant failed: %v\n%s", err, out)
	} else {
		t.Logf("network evidence:\n%s", out)
	}

	out, err := rt.ExecOutput(ctx, name, []string{
		"curl", "--fail", "--silent", "--show-error", "--unix-socket", "/run/sunaba/model-gateway.sock", "http://localhost/health",
	})
	if err != nil {
		t.Fatalf("Project/VM socket transport failed: %v", err)
	}
	if strings.TrimSpace(out) != nonce {
		t.Fatalf("gateway response=%q, want %q", out, nonce)
	}
	if out, err := rt.ExecOutput(ctx, name, []string{
		"/bin/bash", "-lc", "test ! -e /run/sunaba/other-project.sock && ! curl --max-time 1 --unix-socket /run/sunaba/other-project.sock http://localhost/health",
	}); err != nil {
		t.Fatalf("other Project socket was reachable: %v: %s", err, out)
	}

	guestRelay := buildLinuxBinary(t, ctx, tempDir, "sunaba-guest-relay", "./cmd/sunaba-guest-relay")
	if err := rt.CopyTo(ctx, name, guestRelay, "/tmp/sunaba-guest-relay"); err != nil {
		t.Fatal(err)
	}
	providerConfig, err := opencode.BuildModelGatewayConfig(opencode.ModelGatewayProviderConfig{
		BaseURL: "http://127.0.0.1:4141/v1", Model: modelID, TokenEnv: "SUNABA_MODEL_GATEWAY_TOKEN",
		ContextLimit: 200_000, OutputLimit: 32_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	providerConfigPath := filepath.Join(tempDir, "opencode.json")
	if err := os.WriteFile(providerConfigPath, providerConfig, 0600); err != nil {
		t.Fatal(err)
	}
	if err := rt.CopyTo(ctx, name, providerConfigPath, "/tmp/sunaba-model-config.json"); err != nil {
		t.Fatal(err)
	}
	password := "phase0-" + runID + "-" + strings.Repeat("x", 32)
	startServer := strings.Join([]string{
		"mkdir -p /tmp/sunaba-opencode/home /tmp/sunaba-opencode/config /tmp/sunaba-opencode/data /tmp/sunaba-opencode/project /run/sunaba",
		"chmod 0700 /tmp/sunaba-opencode/home /tmp/sunaba-opencode/config /tmp/sunaba-opencode/data /tmp/sunaba-opencode/project /run/sunaba /tmp/sunaba-guest-relay",
		"cp /tmp/sunaba-model-config.json /tmp/sunaba-opencode/config/opencode.json",
		"chmod 0600 /tmp/sunaba-opencode/config/opencode.json",
		"cd /tmp/sunaba-opencode/project",
		"nohup /tmp/sunaba-guest-relay --tcp-listen 127.0.0.1:4141 --unix-target /run/sunaba/model-gateway.sock >/tmp/sunaba-opencode/model-relay.log 2>&1 &",
		"nohup env HOME=/tmp/sunaba-opencode/home XDG_CONFIG_HOME=/tmp/sunaba-opencode/config XDG_DATA_HOME=/tmp/sunaba-opencode/data OPENCODE_CONFIG=/tmp/sunaba-opencode/config/opencode.json OPENCODE_SERVER_PASSWORD=" + password + " SUNABA_MODEL_GATEWAY_TOKEN=" + modelToken + " OPENCODE_DISABLE_AUTOUPDATE=1 OPENCODE_DISABLE_MODELS_FETCH=1 OPENCODE_DISABLE_LSP_DOWNLOAD=1 opencode serve --pure --hostname 127.0.0.1 --port 4096 --mdns=false >/tmp/sunaba-opencode/server.log 2>&1 &",
		"nohup /tmp/sunaba-guest-relay --listen /run/sunaba/attach.sock --target 127.0.0.1:4096 >/tmp/sunaba-opencode/relay.log 2>&1 &",
	}, "\n")
	if err := rt.Exec(ctx, name, false, []string{"/bin/bash", "-lc", startServer}); err != nil {
		t.Fatal(err)
	}
	health := waitForUnixHealth(t, ctx, attachSocketPath, password)
	if health.Version != dependency.OpenCodeVersion {
		t.Fatalf("guest server version=%q, want %q", health.Version, dependency.OpenCodeVersion)
	}
	unauthorized, err := unixHTTPClient(attachSocketPath).Get("http://sunaba/global/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("health without basic auth returned %s", unauthorized.Status)
	}
	message := exerciseOpenCodeResponses(t, ctx, attachSocketPath, password, modelID)
	if !strings.Contains(message, "hello from gateway") {
		t.Fatalf("OpenCode response did not contain mock text: %s", message)
	}
	select {
	case <-upstreamRequest:
	case <-time.After(5 * time.Second):
		t.Fatal("OpenCode request did not reach the fixed Model Gateway upstream")
	}
	connected := make(chan struct{})
	eventStream := make(chan struct{})
	rejectedEvent := make(chan struct{})
	var connectedOnce, eventStreamOnce, rejectedOnce sync.Once
	relayCtx, stopRelay := context.WithCancel(ctx)
	relayURL, relayDone, err := (attachrelay.Relay{
		UnixSocketPath: attachSocketPath, Username: "opencode", Password: password,
		OnConnect: func() { connectedOnce.Do(func() { close(connected) }) },
		OnRequest: func(_ string, path string) {
			if path == "/event" || path == "/global/event" {
				eventStreamOnce.Do(func() { close(eventStream) })
			}
		},
		OnReject: func(reason string) {
			if reason == "unsafe_tui_command" {
				rejectedOnce.Do(func() { close(rejectedEvent) })
			}
		},
	}).ListenAndServe(relayCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		stopRelay()
		if err := <-relayDone; err != nil {
			t.Errorf("stop Local Attach Relay: %v", err)
		}
	}()
	repository := repositoryRoot(t)
	managedToolDir := filepath.Join(repository, "bin", "tools", "opencode", "v"+dependency.OpenCodeVersion)
	tuiCommand, err := opencode.BuildHostTUICommand(ctx, opencode.HostTUIConfig{
		Binary: filepath.Join(managedToolDir, "opencode"), ManagedToolDir: managedToolDir,
		SessionRoot: tempDir, ServerURL: relayURL,
		GuestWorkspace: "/workspace/sunaba-" + runID, Password: password,
		ExpectedExecutableSHA256: manifest.OpenCode.Host.ExecutableSHA256,
	}, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	probeCtx, stopTUI := context.WithCancel(ctx)
	scriptArgs := append([]string{"-q", "/dev/null", tuiCommand.Path}, tuiCommand.Args[1:]...)
	scriptCommand := exec.CommandContext(probeCtx, "script", scriptArgs...)
	scriptCommand.Dir, scriptCommand.Env = tuiCommand.Dir, tuiCommand.Env
	var tuiOutput bytes.Buffer
	scriptCommand.Stdout, scriptCommand.Stderr = &tuiOutput, &tuiOutput
	inputReader, inputWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	scriptCommand.Stdin = inputReader
	if err := scriptCommand.Start(); err != nil {
		_ = inputReader.Close()
		_ = inputWriter.Close()
		t.Fatal(err)
	}
	tuiDone := make(chan error, 1)
	go func() { tuiDone <- scriptCommand.Wait() }()
	select {
	case <-connected:
	case err := <-tuiDone:
		stopTUI()
		_ = inputReader.Close()
		_ = inputWriter.Close()
		t.Fatalf("managed Host TUI exited before attach: %v: %q", err, tuiOutput.String())
	case <-time.After(15 * time.Second):
		stopTUI()
		_ = inputReader.Close()
		_ = inputWriter.Close()
		t.Fatalf("managed Host TUI did not reach Local Attach Relay: %q", tuiOutput.String())
	}
	select {
	case <-eventStream:
	case err := <-tuiDone:
		t.Fatalf("managed Host TUI exited before event stream: %v: %q", err, tuiOutput.String())
	case <-time.After(15 * time.Second):
		t.Fatalf("managed Host TUI did not open an event stream: %q", tuiOutput.String())
	}
	attackCommand := "curl --fail --silent --user opencode:" + password + " --header 'Content-Type: application/json' --data '{\"command\":\"editor.open\"}' http://127.0.0.1:4096/tui/execute-command"
	if out, err := rt.ExecOutput(ctx, name, []string{"/bin/bash", "-lc", attackCommand}); err != nil {
		t.Fatalf("emit malicious TUI event: %v: %s", err, out)
	}
	select {
	case <-rejectedEvent:
	case err := <-tuiDone:
		t.Fatalf("managed Host TUI exited during malicious event probe: %v: %q", err, tuiOutput.String())
	case <-time.After(5 * time.Second):
		t.Fatalf("Local Attach Relay did not reject external editor event: %q", tuiOutput.String())
	}
	stopTUI()
	_ = inputReader.Close()
	_ = inputWriter.Close()
	select {
	case <-tuiDone:
	case <-time.After(5 * time.Second):
		t.Fatal("managed Host TUI did not stop after probe cancellation")
	}
}

func exerciseOpenCodeResponses(t *testing.T, ctx context.Context, socketPath, password, modelID string) string {
	t.Helper()
	client := unixHTTPClient(socketPath)
	sessionBody := postOpenCodeJSON(t, ctx, client, password, "/session", `{}`)
	var session struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(sessionBody, &session); err != nil || session.ID == "" {
		t.Fatalf("create OpenCode session response=%s error=%v", sessionBody, err)
	}
	payload, err := json.Marshal(map[string]any{
		"model": map[string]string{"providerID": opencode.ModelGatewayProviderID, "modelID": modelID},
		"agent": "build",
		"parts": []map[string]string{{"type": "text", "text": "Reply with the mock response."}},
	})
	if err != nil {
		t.Fatal(err)
	}
	messageBody := postOpenCodeJSON(t, ctx, client, password, "/session/"+session.ID+"/message", string(payload))
	return string(messageBody)
}

func postOpenCodeJSON(t *testing.T, ctx context.Context, client *http.Client, password, path, payload string) []byte {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://sunaba"+path, strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("opencode", password)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		t.Fatalf("OpenCode %s returned %s: %s", path, response.Status, body)
	}
	return body
}

func writeResponsesTextStream(w http.ResponseWriter, modelID, text string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	message := map[string]any{
		"id": "msg_sunaba", "type": "message", "status": "completed", "role": "assistant",
		"content": []any{map[string]any{"type": "output_text", "text": text, "annotations": []any{}, "logprobs": []any{}}},
	}
	baseResponse := map[string]any{
		"id": "resp_sunaba", "object": "response", "created_at": time.Now().Unix(), "status": "completed",
		"background": false, "error": nil, "incomplete_details": nil, "instructions": nil,
		"max_output_tokens": nil, "max_tool_calls": nil, "model": modelID, "output": []any{message},
		"parallel_tool_calls": true, "previous_response_id": nil, "prompt_cache_key": nil,
		"reasoning": map[string]any{"effort": nil, "summary": nil}, "safety_identifier": nil,
		"service_tier": "default", "store": false, "temperature": 1,
		"text":        map[string]any{"format": map[string]any{"type": "text"}, "verbosity": "medium"},
		"tool_choice": "auto", "tools": []any{}, "top_logprobs": 0, "top_p": 1, "truncation": "disabled",
		"usage": map[string]any{
			"input_tokens": 8, "input_tokens_details": map[string]any{"cached_tokens": 0},
			"output_tokens": 4, "output_tokens_details": map[string]any{"reasoning_tokens": 0}, "total_tokens": 12,
		},
	}
	events := []map[string]any{
		{"type": "response.created", "sequence_number": 0, "response": map[string]any{
			"id": "resp_sunaba", "object": "response", "created_at": time.Now().Unix(), "status": "in_progress",
			"error": nil, "incomplete_details": nil, "instructions": nil, "model": modelID, "output": []any{},
			"parallel_tool_calls": true, "reasoning": map[string]any{"effort": nil, "summary": nil},
			"store": false, "temperature": 1, "text": map[string]any{"format": map[string]any{"type": "text"}},
			"tool_choice": "auto", "tools": []any{}, "top_p": 1, "truncation": "disabled", "usage": nil,
		}},
		{"type": "response.output_item.added", "sequence_number": 1, "output_index": 0, "item": map[string]any{"id": "msg_sunaba", "type": "message", "status": "in_progress", "role": "assistant", "content": []any{}}},
		{"type": "response.content_part.added", "sequence_number": 2, "item_id": "msg_sunaba", "output_index": 0, "content_index": 0, "part": map[string]any{"type": "output_text", "text": "", "annotations": []any{}, "logprobs": []any{}}},
		{"type": "response.output_text.delta", "sequence_number": 3, "item_id": "msg_sunaba", "output_index": 0, "content_index": 0, "delta": text, "logprobs": []any{}},
		{"type": "response.output_text.done", "sequence_number": 4, "item_id": "msg_sunaba", "output_index": 0, "content_index": 0, "text": text, "logprobs": []any{}},
		{"type": "response.content_part.done", "sequence_number": 5, "item_id": "msg_sunaba", "output_index": 0, "content_index": 0, "part": map[string]any{"type": "output_text", "text": text, "annotations": []any{}, "logprobs": []any{}}},
		{"type": "response.output_item.done", "sequence_number": 6, "output_index": 0, "item": message},
		{"type": "response.completed", "sequence_number": 7, "response": baseResponse},
	}
	flusher, _ := w.(http.Flusher)
	for _, event := range events {
		_, _ = fmt.Fprintf(w, "event: %s\n", event["type"])
		_, _ = io.WriteString(w, "data: ")
		_ = json.NewEncoder(w).Encode(event)
		_, _ = io.WriteString(w, "\n")
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func buildLinuxBinary(t *testing.T, ctx context.Context, tempDir, name, pkg string) string {
	t.Helper()
	output := filepath.Join(tempDir, name)
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", output, pkg)
	build.Dir = repositoryRoot(t)
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0", "GOCACHE="+filepath.Join(tempDir, "go-cache"))
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v: %s", pkg, err, out)
	}
	return output
}

func waitForUnixHealth(t *testing.T, ctx context.Context, socketPath, password string) opencode.Health {
	t.Helper()
	client := unixHTTPClient(socketPath)
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://sunaba/global/health", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("opencode", password)
		resp, err := client.Do(req)
		if err == nil {
			var health opencode.Health
			decodeErr := json.NewDecoder(resp.Body).Decode(&health)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && decodeErr == nil {
				return health
			}
			lastErr = fmt.Errorf("status=%s decode=%v", resp.Status, decodeErr)
		} else {
			lastErr = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("reverse attach health did not become ready: %v", lastErr)
	return opencode.Health{}
}

func unixHTTPClient(socketPath string) *http.Client {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	}}
	return &http.Client{Transport: transport, Timeout: time.Second}
}

func cleanupContainer(t *testing.T, ctx context.Context, rt *sunabaruntime.AppleContainer, name, runID string) {
	t.Helper()
	state, err := rt.ContainerState(ctx, name)
	if err != nil {
		t.Errorf("inspect cleanup target: %v", err)
		return
	}
	if state == sunabaruntime.StateNotFound {
		return
	}
	info, err := rt.Inspect(ctx, name)
	if err != nil {
		t.Errorf("inspect cleanup target identity: %v", err)
		return
	}
	owner := info.Labels["dev.sunaba.owner"]
	if info.Name != name || (owner != "integration-test" && owner != "sunaba-supervisor") || info.Labels["dev.sunaba.run-id"] != runID {
		t.Errorf("refusing cleanup of mismatched resource: name=%q labels=%v", info.Name, info.Labels)
		return
	}
	if state == sunabaruntime.StateRunning {
		if err := rt.Stop(ctx, name); err != nil {
			t.Errorf("stop cleanup target: %v", err)
			return
		}
	}
	if err := rt.Remove(ctx, name); err != nil {
		t.Errorf("remove cleanup target: %v", err)
	}
}

func randomID(t *testing.T) string {
	t.Helper()
	data := make([]byte, 6)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(data)
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}
