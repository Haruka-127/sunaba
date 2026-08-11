//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"sunaba/internal/dependency"
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

	tempDir, err := os.MkdirTemp("/private/tmp", "sunaba-p0-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	if err := os.Chmod(tempDir, 0700); err != nil {
		t.Fatal(err)
	}
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
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		_, _ = fmt.Fprint(w, nonce)
	})}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(listener) }()
	defer func() {
		_ = server.Close()
		<-serverDone
	}()

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
			Type: "socket", Source: socketPath, Target: "/run/sunaba/model-gateway.sock",
		}},
		Sockets: []sunabaruntime.PublishedSocket{{
			HostPath: attachSocketPath, GuestPath: "/run/sunaba/attach.sock",
		}},
		Labels: map[string]string{
			"dev.sunaba.owner":   "integration-test",
			"dev.sunaba.test":    "phase0-network",
			"dev.sunaba.run-id":  runID,
			"dev.sunaba.version": manifest.AppleContainer.Version,
		},
	}
	if err := rt.Create(ctx, spec); err != nil {
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

	guestRelay := buildLinuxBinary(t, ctx, tempDir, "sunaba-guest-relay", "./cmd/sunaba-guest-relay")
	if err := rt.CopyTo(ctx, name, guestRelay, "/tmp/sunaba-guest-relay"); err != nil {
		t.Fatal(err)
	}
	password := "phase0-" + runID
	startServer := strings.Join([]string{
		"mkdir -p /tmp/sunaba-opencode/home /tmp/sunaba-opencode/config /tmp/sunaba-opencode/data /tmp/sunaba-opencode/project /run/sunaba",
		"chmod 0700 /tmp/sunaba-opencode/home /tmp/sunaba-opencode/config /tmp/sunaba-opencode/data /tmp/sunaba-opencode/project /run/sunaba /tmp/sunaba-guest-relay",
		"cd /tmp/sunaba-opencode/project",
		"nohup env HOME=/tmp/sunaba-opencode/home XDG_CONFIG_HOME=/tmp/sunaba-opencode/config XDG_DATA_HOME=/tmp/sunaba-opencode/data OPENCODE_SERVER_PASSWORD=" + password + " OPENCODE_DISABLE_AUTOUPDATE=1 OPENCODE_DISABLE_MODELS_FETCH=1 OPENCODE_DISABLE_LSP_DOWNLOAD=1 opencode serve --pure --hostname 127.0.0.1 --port 4096 --mdns=false >/tmp/sunaba-opencode/server.log 2>&1 &",
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
	if info.Name != name || info.Labels["dev.sunaba.owner"] != "integration-test" || info.Labels["dev.sunaba.run-id"] != runID {
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
