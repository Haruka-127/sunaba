package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"sunaba/internal/guestrelay"
)

func main() {
	listen := flag.String("listen", "", "guest Unix socket path")
	target := flag.String("target", "127.0.0.1:4096", "guest loopback TCP target")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := (guestrelay.Relay{SocketPath: *listen, Target: *target}).Serve(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
