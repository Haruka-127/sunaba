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
	tcpListen := flag.String("tcp-listen", "", "guest loopback TCP address")
	unixTarget := flag.String("unix-target", "", "mounted host Unix socket path")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	if *tcpListen != "" || *unixTarget != "" {
		if *listen != "" || *tcpListen == "" || *unixTarget == "" {
			fmt.Fprintln(os.Stderr, "use either --listen/--target or --tcp-listen/--unix-target")
			os.Exit(2)
		}
		err = (guestrelay.TCPToUnixRelay{ListenAddress: *tcpListen, SocketPath: *unixTarget}).Serve(ctx)
	} else {
		err = (guestrelay.Relay{SocketPath: *listen, Target: *target}).Serve(ctx)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
