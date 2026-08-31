package devnetwork

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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

func fakeNetworkJSON(name, projectID, sessionID string) string {
	return `[{
        "configuration":{"name":"` + name + `","mode":"nat","plugin":"container-network-vmnet","labels":{"dev.sunaba.owner":"sunaba-supervisor","dev.sunaba.project":"` + projectID + `","dev.sunaba.session":"` + sessionID + `","dev.sunaba.mode":"dev"}},
        "id":"` + name + `","status":{"ipv4Subnet":"192.168.65.0/24","ipv4Gateway":"192.168.65.1","ipv6Subnet":"fd00:65::/64"}}]`
}

func TestCreateRemovesNetworkWhenVerificationFails(t *testing.T) {
	const name = "sunaba-project-session1-net"
	created, deleted := false, false
	manager := &Manager{run: func(_ context.Context, command string, args ...string) ([]byte, error) {
		joined := command + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "network inspect"):
			if !created {
				return nil, fmt.Errorf("not found")
			}
			return []byte(`invalid schema`), nil
		case strings.Contains(joined, "network create"):
			created = true
			return []byte(name), nil
		case strings.Contains(joined, "network delete"):
			deleted = true
			return []byte(name), nil
		}
		return nil, fmt.Errorf("unexpected command: %s", joined)
	}}
	_, err := manager.Create(context.Background(), "project", "session1")
	if err == nil || !strings.Contains(err.Error(), "verify newly created dev network") {
		t.Fatalf("error=%v", err)
	}
	if !deleted {
		t.Fatal("failed create left the created network behind")
	}
}

func TestReclaimStaleNetworkDeletesJournaledOrphan(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	const stale = "sunaba-oldproject-oldsession-net"
	if err := writeOwnerJournal(root, stale); err != nil {
		t.Fatal(err)
	}
	deleted := false
	manager := &Manager{run: func(_ context.Context, command string, args ...string) ([]byte, error) {
		joined := command + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "network inspect") && strings.Contains(joined, stale):
			if deleted {
				return nil, fmt.Errorf("not found")
			}
			return []byte(fakeNetworkJSON(stale, "oldproject", "oldsession")), nil
		case strings.Contains(joined, "network delete"):
			deleted = true
			return []byte(stale), nil
		}
		return nil, fmt.Errorf("unexpected command: %s", joined)
	}}
	if err := reclaimStaleNetwork(context.Background(), manager, root, "sunaba-project-session1-net"); err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("journaled stale network was not deleted")
	}
	if _, err := os.Lstat(filepath.Join(root, ownerJournalFile)); !os.IsNotExist(err) {
		t.Fatalf("journal still exists after reclaim: %v", err)
	}
}

func TestReclaimStaleNetworkKeepsTargetAndMissingNetwork(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	const target = "sunaba-project-session1-net"
	if err := writeOwnerJournal(root, target); err != nil {
		t.Fatal(err)
	}
	manager := &Manager{run: func(_ context.Context, command string, _ ...string) ([]byte, error) {
		return nil, fmt.Errorf("unexpected command: %s", command)
	}}
	if err := reclaimStaleNetwork(context.Background(), manager, root, target); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, ownerJournalFile)); err != nil {
		t.Fatal("journal for the adopted target must be kept")
	}

	const missing = "sunaba-goneproject-gonesession-net"
	if err := writeOwnerJournal(root, missing); err != nil {
		t.Fatal(err)
	}
	manager = &Manager{run: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return nil, fmt.Errorf("not found")
	}}
	if err := reclaimStaleNetwork(context.Background(), manager, root, target); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, ownerJournalFile)); !os.IsNotExist(err) {
		t.Fatal("journal for a vanished network must be cleared")
	}
}

func TestReclaimStaleNetworkRefusesForeignJournalEntry(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ownerJournalFile), []byte(`{"name":"not-ours"}`), 0600); err != nil {
		t.Fatal(err)
	}
	manager := &Manager{run: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return nil, fmt.Errorf("unexpected command")
	}}
	if err := reclaimStaleNetwork(context.Background(), manager, root, "sunaba-project-session1-net"); err == nil || !strings.Contains(err.Error(), "journal is invalid") {
		t.Fatalf("error=%v", err)
	}
}
