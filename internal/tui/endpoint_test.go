package tui

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEndpointOwnerOnlySingleConnectionAndCleanup(t *testing.T) {
	// macOS commonly returns TMPDIR with a trailing slash. Passing the platform
	// value unchanged is the production path and must not be rejected merely for
	// that representation.
	root := os.TempDir()
	if filepath.Clean(root) == root {
		root += string(filepath.Separator)
	}
	endpoint, err := NewEndpoint(root, "project-1")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := endpoint.BindHelperPID(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	directory := endpoint.Directory
	defer endpoint.Close()
	if info, err := os.Stat(directory); err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("directory mode=%v error=%v", info.Mode(), err)
	}
	if info, err := os.Stat(endpoint.Socket); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("socket mode=%v error=%v", info.Mode(), err)
	}
	view := testView(t)
	view.Binding = binding
	result := make(chan error, 1)
	go func() {
		_, serveErr := endpoint.ServeOnce(context.Background(), view)
		result <- serveErr
	}()
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: endpoint.Socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	var received View
	if err := ReadFrame(connection, &received); err != nil {
		t.Fatal(err)
	}
	if second, err := net.DialTimeout("unix", endpoint.Socket, 50*time.Millisecond); err == nil {
		second.Close()
		t.Fatal("second UI connection succeeded")
	}
	event := testEvent(view)
	if err := WriteFrame(connection, event); err != nil {
		t.Fatal(err)
	}
	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if err := endpoint.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatalf("temporary directory remains: %v", err)
	}
}

func TestEndpointNormalizesOnlyWithinOSTemporaryBoundary(t *testing.T) {
	if _, err := NewEndpoint("relative/temp", "project-1"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative temporary root error=%v", err)
	}
	nonTemporary := filepath.Join(filepath.Dir(filepath.Clean(os.TempDir())), "sunaba-not-temp")
	if _, err := NewEndpoint(nonTemporary, "project-1"); err == nil || !strings.Contains(err.Error(), "OS temporary") {
		t.Fatalf("non-temporary root error=%v", err)
	}
}

func TestEndpointRejectsPeerProcessAndProtocolViolation(t *testing.T) {
	root, err := shortTempRoot(t)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := NewEndpoint(root, "project-1")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := endpoint.BindHelperPID(os.Getpid() + 100000)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	view := testView(t)
	view.Binding = binding
	result := make(chan error, 1)
	go func() {
		_, serveErr := endpoint.ServeOnce(context.Background(), view)
		result <- serveErr
	}()
	connection, err := net.Dial("unix", endpoint.Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := <-result; err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("peer identity error=%v", err)
	}
}

func TestEndpointBindsActualStartedProcessPID(t *testing.T) {
	if os.Getenv("SUNABA_TUI_HELPER_TEST") == "1" {
		testEndpointHelperProcess(t)
		return
	}
	root, err := shortTempRoot(t)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := NewEndpoint(root, "project-real")
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	spec := endpoint.LaunchSpec()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestEndpointBindsActualStartedProcessPID$")
	command.Env = append(os.Environ(),
		"SUNABA_TUI_HELPER_TEST=1",
		"SUNABA_TUI_SOCKET="+spec.Socket,
		"SUNABA_TUI_PROJECT="+spec.ProjectID,
		"SUNABA_TUI_NONCE="+spec.Nonce,
	)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	binding, err := endpoint.BindHelperPID(command.Process.Pid)
	if err != nil {
		_ = command.Process.Kill()
		t.Fatal(err)
	}
	if _, err := endpoint.BindHelperPID(command.Process.Pid); err == nil {
		t.Fatal("process binding was mutable")
	}
	view := testView(t)
	view.Binding = binding
	event, serveErr := endpoint.ServeOnce(context.Background(), view)
	waitErr := command.Wait()
	if serveErr != nil || waitErr != nil || event.Kind != EventExit {
		t.Fatalf("event=%+v serve=%v wait=%v", event, serveErr, waitErr)
	}
}

func testEndpointHelperProcess(t *testing.T) {
	socket := os.Getenv("SUNABA_TUI_SOCKET")
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	var view View
	if err := ReadFrame(connection, &view); err != nil {
		t.Fatal(err)
	}
	if view.Binding.ProcessID != os.Getpid() || view.Binding.ProjectID != os.Getenv("SUNABA_TUI_PROJECT") || view.Binding.Nonce != os.Getenv("SUNABA_TUI_NONCE") {
		t.Fatalf("view was not bound to this process: %+v", view.Binding)
	}
	event := testEvent(view)
	event.Kind = EventExit
	event.ActionID = ""
	if err := WriteFrame(connection, event); err != nil {
		t.Fatal(err)
	}
	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
}

func TestEndpointSeparatesStartupAndUserDecisionTimeouts(t *testing.T) {
	root, err := shortTempRoot(t)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := NewEndpoint(root, "project-timeout")
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	if endpoint.startupTimeout >= endpoint.decisionTimeout || endpoint.decisionTimeout < 10*time.Minute || endpoint.frameTimeout >= endpoint.startupTimeout {
		t.Fatalf("timeouts are not separated: startup=%s decision=%s frame=%s", endpoint.startupTimeout, endpoint.decisionTimeout, endpoint.frameTimeout)
	}
	if _, err := endpoint.BindHelperPID(os.Getpid()); err != nil {
		t.Fatal(err)
	}
	endpoint.startupTimeout = 20 * time.Millisecond
	view := testView(t)
	view.Binding, _ = endpoint.BoundIdentity()
	started := time.Now()
	if _, err := endpoint.ServeOnce(context.Background(), view); err == nil || time.Since(started) > time.Second {
		t.Fatalf("startup timeout error=%v elapsed=%s", err, time.Since(started))
	}
}

func shortTempRoot(t *testing.T) (string, error) {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "sui-test-")
	if err != nil {
		return "", err
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return filepath.EvalSymlinks(root)
}
