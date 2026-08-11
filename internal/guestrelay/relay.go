package guestrelay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
)

type Relay struct {
	SocketPath string
	Target     string
}

type TCPToUnixRelay struct {
	ListenAddress string
	SocketPath    string
}

func (r TCPToUnixRelay) Serve(ctx context.Context) error {
	host, _, err := net.SplitHostPort(r.ListenAddress)
	if err != nil || host != "127.0.0.1" || r.SocketPath == "" {
		return fmt.Errorf("TCP-to-Unix relay requires an explicit guest 127.0.0.1 listener and Unix socket target")
	}
	info, err := os.Lstat(r.SocketPath)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("TCP-to-Unix target is not a Unix socket")
	}
	listener, err := net.Listen("tcp4", r.ListenAddress)
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go forwardConnection(connection, "unix", r.SocketPath)
	}
}

func (r Relay) Serve(ctx context.Context) error {
	if r.SocketPath == "" || r.Target == "" {
		return fmt.Errorf("socket path and target are required")
	}
	if err := os.Remove(r.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", r.SocketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(r.SocketPath)
	if err := os.Chmod(r.SocketPath, 0600); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go r.forward(conn)
	}
}

func (r Relay) forward(source net.Conn) {
	forwardConnection(source, "tcp", r.Target)
}

func forwardConnection(source net.Conn, network, address string) {
	defer source.Close()
	target, err := net.Dial(network, address)
	if err != nil {
		return
	}
	defer target.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	copyHalf := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if closer, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
	}
	go copyHalf(target, source)
	go copyHalf(source, target)
	wg.Wait()
}
