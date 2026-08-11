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
	defer source.Close()
	target, err := net.Dial("tcp", r.Target)
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
