//go:build integration

package integration

import (
	"context"
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
	"sunaba/internal/devnetwork"
	sunabaruntime "sunaba/internal/runtime"
)

func TestDevSessionNetworkBoundary(t *testing.T) {
	if os.Getenv("SUNABA_DEV_INTEGRATION") != "1" {
		t.Skip("set SUNABA_DEV_INTEGRATION=1 after authorizing the documented sudo sunaba firewall operation")
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Fatalf("requires darwin/arm64, got %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	runID := randomID(t)
	temp := filepath.Join("/private/tmp", "sunaba-dev-integration-"+runID)
	if err := os.Mkdir(temp, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(temp)
	repository := repositoryRoot(t)
	sunabaBinary := filepath.Join(temp, "sunaba")
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", sunabaBinary, "./cmd/sunaba")
	build.Dir = repository
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build firewall entrypoint: %v: %s", err, output)
	}

	manager := devnetwork.NewManager()
	dev, err := manager.Create(ctx, "dev"+runID, "session"+runID)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := manager.Create(ctx, "peer"+runID, "session"+runID)
	if err != nil {
		_ = manager.Delete(context.Background(), dev)
		t.Fatal(err)
	}
	defer func() {
		if err := manager.Delete(context.Background(), peer); err != nil {
			t.Errorf("delete peer network: %v", err)
		}
		if err := manager.Delete(context.Background(), dev); err != nil {
			t.Errorf("delete dev network: %v", err)
		}
	}()

	firewallEnabled := false
	defer func() {
		if firewallEnabled {
			if output, err := exec.Command("sudo", "-n", sunabaBinary, "firewall", "disable").CombinedOutput(); err != nil {
				t.Errorf("disable dev firewall: %v: %s", err, output)
			}
		}
	}()
	enable := exec.CommandContext(ctx, "sudo", "-n", sunabaBinary, "firewall", "enable", "--subnet", dev.IPv4Subnet, "--gateway", dev.IPv4Gateway, "--ipv6-subnet", dev.IPv6Subnet)
	if output, err := enable.CombinedOutput(); err != nil {
		t.Fatalf("enable verified dev firewall (authorize sudo first): %v: %s", err, output)
	}
	firewallEnabled = true

	rt := sunabaruntime.NewAppleContainer(false)
	peerName := "sunaba-dev-peer-" + runID
	if err := rt.Create(ctx, sunabaruntime.ContainerSpec{
		Name: peerName, Image: dependency.MustPinned().AgentImage.Tag, CPUs: 1, Memory: "1G", Networks: []string{peer.Name},
		Entrypoint: "/bin/bash", Args: []string{"-lc", "exec tail -f /dev/null"},
		Labels: map[string]string{"dev.sunaba.owner": "integration-test", "dev.sunaba.run-id": runID, "dev.sunaba.test": "dev-peer"},
	}); err != nil {
		t.Fatal(err)
	}
	defer cleanupContainer(t, context.Background(), rt, peerName, runID)
	startPerlHTTP(t, ctx, rt, peerName, 38642)
	peerIP, err := rt.IPAddress(ctx, peerName)
	if err != nil {
		t.Fatal(err)
	}

	sessionRoot := filepath.Join(temp, "sunaba-session-session"+runID)
	if err := os.Mkdir(sessionRoot, 0700); err != nil {
		t.Fatal(err)
	}
	gatewayPath := filepath.Join(sessionRoot, "model-gateway.sock")
	gatewayListener, err := net.Listen("unix", gatewayPath)
	if err != nil {
		t.Fatal(err)
	}
	defer gatewayListener.Close()
	if err := os.Chmod(gatewayPath, 0600); err != nil {
		t.Fatal(err)
	}
	projectID, sessionID := "dev"+runID, "session"+runID
	name := "sunaba-" + projectID + "-" + sessionID
	policy := sunabaruntime.SecureSessionPolicy{
		ProjectID: projectID, SessionID: sessionID, Mode: "dev", NetworkName: dev.Name,
		Image: dependency.MustPinned().AgentImage.Tag, SessionRoot: sessionRoot,
		CPUs: 1, Memory: "1G", DiskBytes: 128 << 20, ProcessMax: 64, FileSizeMax: 128 << 20, OpenFileMax: 1024,
	}
	digest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	spec := sunabaruntime.ContainerSpec{
		Name: name, Image: policy.Image, CPUs: 1, Memory: "1G",
		Ulimits:  map[string]sunabaruntime.RLimit{"nproc": {Soft: 64, Hard: 64}, "fsize": {Soft: 128 << 20, Hard: 128 << 20}, "nofile": {Soft: 1024, Hard: 1024}},
		Networks: []string{dev.Name}, CapAdd: []string{"SYS_ADMIN"}, Entrypoint: "/bin/bash", Args: []string{"-lc", "exec tail -f /dev/null"},
		Mounts:  []sunabaruntime.Mount{{Type: "socket", Source: gatewayPath, Target: sunabaruntime.SecureGatewayGuestPath}},
		Sockets: []sunabaruntime.PublishedSocket{{HostPath: filepath.Join(sessionRoot, "attach.sock"), GuestPath: sunabaruntime.SecureAttachGuestPath}},
		Labels: map[string]string{
			"dev.sunaba.owner": "sunaba-supervisor", "dev.sunaba.project": projectID, "dev.sunaba.session": sessionID,
			"dev.sunaba.mode": "dev", "dev.sunaba.policy-digest": digest, "dev.sunaba.run-id": runID,
		},
	}
	if err := rt.CreateSecure(ctx, spec, policy); err != nil {
		t.Fatal(err)
	}
	defer cleanupContainer(t, context.Background(), rt, name, runID)
	startPerlHTTP(t, ctx, rt, name, 38642)

	hostListener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hostListener.Close()
	hostServer := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { _, _ = response.Write([]byte("host")) })}
	go hostServer.Serve(hostListener)
	defer hostServer.Close()
	hostPort := hostListener.Addr().(*net.TCPAddr).Port

	probe := strings.Join([]string{
		"set -eu",
		"test \"$(curl --fail --silent --show-error --max-time 15 https://example.com | wc -c)\" -gt 0",
		"getent hosts example.com >/dev/null",
		fmt.Sprintf("! curl --fail --silent --max-time 2 http://%s:%d/", dev.IPv4Gateway, hostPort),
		fmt.Sprintf("! curl --fail --silent --max-time 2 http://%s:38642/", peerIP),
		"! curl --fail --silent --max-time 2 http://169.254.169.254/",
	}, "\n")
	if output, err := rt.ExecOutput(ctx, name, []string{"/bin/bash", "-lc", probe}); err != nil {
		t.Fatalf("dev egress/host/LAN/other-VM boundary failed: %v: %s", err, output)
	}

	devIP, err := rt.IPAddress(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	if response, err := client.Get("http://" + net.JoinHostPort(devIP, "38642") + "/"); err == nil {
		_ = response.Body.Close()
		t.Fatal("unsolicited host-to-dev-VM inbound connection succeeded")
	}

	quiesce := exec.CommandContext(ctx, "sudo", "-n", sunabaBinary, "firewall", "quiesce", "--subnet", dev.IPv4Subnet, "--gateway", dev.IPv4Gateway, "--ipv6-subnet", dev.IPv6Subnet)
	if output, err := quiesce.CombinedOutput(); err != nil {
		t.Fatalf("quiesce verified dev firewall (authorize sudo first): %v: %s", err, output)
	}
	quiescedProbe := strings.Join([]string{
		"set -eu",
		"! curl --fail --silent --max-time 3 https://example.com/",
		"! curl --fail --silent --max-time 3 http://1.1.1.1/cdn-cgi/trace",
		fmt.Sprintf("! curl --fail --silent --max-time 2 http://%s:%d/", dev.IPv4Gateway, hostPort),
		fmt.Sprintf("! curl --fail --silent --max-time 2 http://%s:38642/", peerIP),
	}, "\n")
	if output, err := rt.ExecOutput(ctx, name, []string{"/bin/bash", "-lc", quiescedProbe}); err != nil {
		t.Fatalf("running dev VM retained egress after quiesce: %v: %s", err, output)
	}

	if err := rt.Stop(ctx, name); err != nil {
		t.Fatal(err)
	}
	if state, err := rt.ContainerState(ctx, name); err != nil || state != sunabaruntime.StateStopped {
		t.Fatalf("dev session end did not revoke egress by stopping VM: state=%s error=%v", state, err)
	}
}

func startPerlHTTP(t *testing.T, ctx context.Context, rt *sunabaruntime.AppleContainer, name string, port int) {
	t.Helper()
	script := fmt.Sprintf(`nohup perl -MIO::Socket::INET -e '$s=IO::Socket::INET->new(LocalPort=>%d,Listen=>5,Reuse=>1) or die; while($c=$s->accept){print $c "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok";close$c}' >/tmp/sunaba-http.log 2>&1 &`, port)
	if output, err := rt.ExecOutput(ctx, name, []string{"/bin/bash", "-lc", script}); err != nil {
		t.Fatalf("start probe listener: %v: %s", err, output)
	}
}
