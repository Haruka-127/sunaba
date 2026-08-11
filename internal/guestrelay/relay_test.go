package guestrelay

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
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
	root, err := os.MkdirTemp("/private/tmp", "sunaba-guest-relay-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
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
