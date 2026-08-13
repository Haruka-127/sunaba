package guestrelay

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sunaba/internal/testutil"
)

func TestRelay(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	socket := filepath.Join(t.TempDir(), "relay.sock")
	done := make(chan error, 1)
	go func() { done <- (Relay{SocketPath: socket, Target: tcpListener.Addr().String()}).Serve(ctx) }()
	waitForSocket(t, socket)

	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 5)
	if _, err := io.ReadFull(conn, buffer); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if string(buffer) != "probe" {
		t.Fatalf("response=%q", buffer)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTCPToUnixRelay(t *testing.T) {
	root := testutil.PrivateTempDir(t, "sunaba-guest-relay-")
	unixListener, err := net.Listen("unix", filepath.Join(root, "gateway.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer unixListener.Close()
	go func() {
		for {
			connection, err := unixListener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	reserved, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserved.Addr().String()
	_ = reserved.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- (TCPToUnixRelay{ListenAddress: address, SocketPath: unixListener.Addr().String()}).Serve(ctx)
	}()
	var connection net.Conn
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		connection, err = net.DialTimeout("tcp4", address, 20*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if connection == nil {
		t.Fatalf("TCP relay did not listen: %v", err)
	}
	if _, err := connection.Write([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 5)
	if _, err := io.ReadFull(connection, buffer); err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if string(buffer) != "probe" {
		t.Fatalf("response=%q", buffer)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRelayRejectsConnectionsAboveLimit(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := tcpListener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socket := filepath.Join(testutil.PrivateTempDir(t, "sunaba-bounded-relay-"), "bounded-relay.sock")
	done := make(chan error, 1)
	go func() {
		done <- (Relay{
			SocketPath: socket, Target: tcpListener.Addr().String(), MaxConnections: 1,
			DialTimeout: time.Second, IdleTimeout: time.Second,
		}).Serve(ctx)
	}()
	waitForSocketFile(t, socket)

	first, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	var target net.Conn
	select {
	case target = <-accepted:
		defer target.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not establish the first target connection")
	}

	second, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := second.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection above relay limit remained open")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRelaySettingsRejectUnboundedValues(t *testing.T) {
	if _, err := relaySettingsFor(maximumMaxConnections+1, time.Second, time.Second); err == nil {
		t.Fatal("excessive connection limit was accepted")
	}
	if _, err := relaySettingsFor(1, maximumDialTimeout+time.Second, time.Second); err == nil {
		t.Fatal("excessive dial timeout was accepted")
	}
	if _, err := relaySettingsFor(1, time.Second, maximumIdleTimeout+time.Second); err == nil {
		t.Fatal("excessive idle timeout was accepted")
	}
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", path, 10*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket %s did not become ready", path)
}

func waitForSocketFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket %s did not become ready", path)
}
