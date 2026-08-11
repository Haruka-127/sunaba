package devnetwork

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCreateVerifyDeleteExactOwnedNetwork(t *testing.T) {
	const name = "sunaba-project-session1-net"
	exists := false
	manager := &Manager{run: func(_ context.Context, command string, args ...string) ([]byte, error) {
		joined := command + " " + strings.Join(args, " ")
		if strings.Contains(joined, "network inspect") {
			if !exists {
				return nil, fmt.Errorf("not found")
			}
			return []byte(`[{
                "configuration":{"name":"` + name + `","mode":"nat","plugin":"container-network-vmnet","labels":{"dev.sunaba.owner":"sunaba-supervisor","dev.sunaba.project":"project","dev.sunaba.session":"session1","dev.sunaba.mode":"dev"}},
                "id":"` + name + `","status":{"ipv4Subnet":"192.168.65.0/24","ipv4Gateway":"192.168.65.1","ipv6Subnet":"fd00:65::/64"}}]`), nil
		}
		if strings.Contains(joined, "network create") {
			exists = true
			return []byte(name), nil
		}
		if strings.Contains(joined, "network delete") {
			exists = false
			return []byte(name), nil
		}
		return nil, fmt.Errorf("unexpected command: %s", joined)
	}}
	network, err := manager.Create(context.Background(), "project", "session1")
	if err != nil {
		t.Fatal(err)
	}
	if network.Name != name || network.IPv4Gateway != "192.168.65.1" {
		t.Fatalf("network=%+v", network)
	}
	if err := manager.Verify(context.Background(), network); err != nil {
		t.Fatal(err)
	}
	if err := manager.Delete(context.Background(), network); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteRejectsChangedOwnership(t *testing.T) {
	manager := &Manager{run: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(`[{
            "configuration":{"name":"sunaba-project-session1-net","mode":"nat","plugin":"container-network-vmnet","labels":{"dev.sunaba.owner":"someone-else","dev.sunaba.project":"project","dev.sunaba.session":"session1","dev.sunaba.mode":"dev"}},
            "id":"sunaba-project-session1-net","status":{"ipv4Subnet":"192.168.65.0/24","ipv4Gateway":"192.168.65.1","ipv6Subnet":"fd00:65::/64"}}]`), nil
	}}
	err := manager.Delete(context.Background(), Network{Name: "sunaba-project-session1-net", ProjectID: "project", SessionID: "session1", IPv4Subnet: "192.168.65.0/24", IPv4Gateway: "192.168.65.1", IPv6Subnet: "fd00:65::/64"})
	if err == nil || !strings.Contains(err.Error(), "owner") {
		t.Fatalf("error=%v", err)
	}
}

func TestDevBoundaryLockSerializesDirectEgress(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	first, err := acquireExclusiveLock(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireExclusiveLock(root); err == nil || !strings.Contains(err.Error(), "another dev session") {
		t.Fatalf("second lock error=%v", err)
	}
	if err := unix.Flock(int(first.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := acquireExclusiveLock(root)
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Close()
}
