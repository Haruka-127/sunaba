package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type result struct {
	Name    string `json:"name"`
	Blocked bool   `json:"blocked"`
	Detail  string `json:"detail,omitempty"`
}

func main() {
	results := []result{
		noNonLoopbackInterface(),
		dialBlocked("public-ipv4", "tcp4", "1.1.1.1:443"),
		dialBlocked("public-ipv6", "tcp6", "[2606:4700:4700::1111]:443"),
		dialBlocked("host-default-gateway", "tcp4", "192.168.64.1:53"),
		dialBlocked("other-vm", "tcp4", "192.168.64.2:4096"),
		dialBlocked("private", "tcp4", "10.0.0.1:443"),
		dialBlocked("link-local-metadata", "tcp4", "169.254.169.254:80"),
		udpBlocked(),
		dnsBlocked(),
		rawICMPBlocked(),
	}
	failed := false
	encoder := json.NewEncoder(os.Stdout)
	for _, item := range results {
		if !item.Blocked {
			failed = true
		}
		if err := encoder.Encode(item); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if failed {
		os.Exit(1)
	}
}

func noNonLoopbackInterface() result {
	interfaces, err := net.Interfaces()
	if err != nil {
		return result{Name: "interfaces", Detail: err.Error()}
	}
	var unexpected []string
	for _, intf := range interfaces {
		if intf.Flags&net.FlagLoopback == 0 && intf.Flags&net.FlagUp != 0 {
			unexpected = append(unexpected, intf.Name)
		}
	}
	return result{Name: "interfaces", Blocked: len(unexpected) == 0, Detail: strings.Join(unexpected, ",")}
}

func dialBlocked(name, network, address string) result {
	conn, err := net.DialTimeout(network, address, 750*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return result{Name: name, Detail: "connection succeeded"}
	}
	return result{Name: name, Blocked: true, Detail: err.Error()}
}

func udpBlocked() result {
	conn, err := net.DialTimeout("udp4", "1.1.1.1:53", 750*time.Millisecond)
	if err != nil {
		return result{Name: "udp", Blocked: true, Detail: err.Error()}
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(750 * time.Millisecond))
	_, err = conn.Write([]byte{0})
	if err != nil {
		return result{Name: "udp", Blocked: true, Detail: err.Error()}
	}
	return result{Name: "udp", Detail: "datagram write succeeded"}
}

func dnsBlocked() result {
	resolver := net.Resolver{PreferGo: true}
	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	_, err := resolver.LookupHost(ctx, "example.com")
	if err != nil {
		return result{Name: "external-dns", Blocked: true, Detail: err.Error()}
	}
	return result{Name: "external-dns", Detail: "lookup succeeded"}
}

func rawICMPBlocked() result {
	conn, err := net.DialIP("ip4:icmp", nil, &net.IPAddr{IP: net.ParseIP("1.1.1.1")})
	if err != nil {
		return result{Name: "raw-icmp", Blocked: true, Detail: err.Error()}
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(750 * time.Millisecond))
	_, err = conn.Write([]byte{8, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		return result{Name: "raw-icmp", Blocked: true, Detail: err.Error()}
	}
	return result{Name: "raw-icmp", Detail: "raw packet write succeeded"}
}
