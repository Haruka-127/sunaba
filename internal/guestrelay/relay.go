package guestrelay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const (
	defaultMaxConnections = 32
	maximumMaxConnections = 256
	defaultDialTimeout    = 5 * time.Second
	maximumDialTimeout    = 30 * time.Second
	defaultIdleTimeout    = 5 * time.Minute
	maximumIdleTimeout    = 30 * time.Minute
)

type Relay struct {
	SocketPath     string
	Target         string
	MaxConnections int
	DialTimeout    time.Duration
	IdleTimeout    time.Duration
}

type TCPToUnixRelay struct {
	ListenAddress  string
	SocketPath     string
	MaxConnections int
	DialTimeout    time.Duration
	IdleTimeout    time.Duration
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
	settings, err := relaySettingsFor(r.MaxConnections, r.DialTimeout, r.IdleTimeout)
	if err != nil {
		return err
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
	return serveConnections(ctx, listener, settings, "unix", r.SocketPath)
}

func (r Relay) Serve(ctx context.Context) error {
	if r.SocketPath == "" || r.Target == "" {
		return fmt.Errorf("socket path and target are required")
	}
	settings, err := relaySettingsFor(r.MaxConnections, r.DialTimeout, r.IdleTimeout)
	if err != nil {
		return err
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
	return serveConnections(ctx, listener, settings, "tcp", r.Target)
}

type relaySettings struct {
	maxConnections int
	dialTimeout    time.Duration
	idleTimeout    time.Duration
}

func relaySettingsFor(maxConnections int, dialTimeout, idleTimeout time.Duration) (relaySettings, error) {
	if maxConnections == 0 {
		maxConnections = defaultMaxConnections
	}
	if dialTimeout == 0 {
		dialTimeout = defaultDialTimeout
	}
	if idleTimeout == 0 {
		idleTimeout = defaultIdleTimeout
	}
	if maxConnections < 1 || maxConnections > maximumMaxConnections || dialTimeout < time.Millisecond || dialTimeout > maximumDialTimeout || idleTimeout < time.Millisecond || idleTimeout > maximumIdleTimeout {
		return relaySettings{}, fmt.Errorf("relay resource limits are invalid")
	}
	return relaySettings{maxConnections: maxConnections, dialTimeout: dialTimeout, idleTimeout: idleTimeout}, nil
}

func serveConnections(ctx context.Context, listener net.Listener, settings relaySettings, network, address string) error {
	semaphore := make(chan struct{}, settings.maxConnections)
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case semaphore <- struct{}{}:
			go func() {
				defer func() { <-semaphore }()
				forwardConnection(ctx, connection, network, address, settings)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func forwardConnection(ctx context.Context, source net.Conn, network, address string, settings relaySettings) {
	defer source.Close()
	target, err := (&net.Dialer{Timeout: settings.dialTimeout}).DialContext(ctx, network, address)
	if err != nil {
		return
	}
	defer target.Close()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = source.Close()
			_ = target.Close()
		case <-done:
		}
	}()
	defer close(done)
	sourceWithDeadline := idleConnection{Conn: source, timeout: settings.idleTimeout}
	targetWithDeadline := idleConnection{Conn: target, timeout: settings.idleTimeout}
	var wg sync.WaitGroup
	wg.Add(2)
	copyHalf := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if closer, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
	}
	go copyHalf(targetWithDeadline, sourceWithDeadline)
	go copyHalf(sourceWithDeadline, targetWithDeadline)
	wg.Wait()
}

type idleConnection struct {
	net.Conn
	timeout time.Duration
}

func (connection idleConnection) Read(value []byte) (int, error) {
	if err := connection.SetReadDeadline(time.Now().Add(connection.timeout)); err != nil {
		return 0, err
	}
	return connection.Conn.Read(value)
}

func (connection idleConnection) Write(value []byte) (int, error) {
	if err := connection.SetWriteDeadline(time.Now().Add(connection.timeout)); err != nil {
		return 0, err
	}
	return connection.Conn.Write(value)
}

func (connection idleConnection) CloseWrite() error {
	if closer, ok := connection.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return nil
}
