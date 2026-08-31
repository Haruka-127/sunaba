package devnetwork

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"sunaba/internal/firewall"
	"sunaba/internal/securefs"
)

const (
	ownerLabel       = "sunaba-supervisor"
	ownerJournalFile = "dev-network-owner.json"
)

var identityPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

var networkNamePattern = regexp.MustCompile(`^sunaba-[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}-[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}-net$`)

type Network struct {
	Name        string
	ProjectID   string
	SessionID   string
	IPv4Subnet  string
	IPv4Gateway string
	IPv6Subnet  string
}

type commandRunner func(context.Context, string, ...string) ([]byte, error)

type Manager struct {
	run commandRunner
}

type Boundary struct {
	Network   Network
	manager   *Manager
	lock      *os.File
	stateRoot string
	closed    bool
}

func Activate(ctx context.Context, stateRoot, projectID, sessionID string) (_ *Boundary, err error) {
	return activateWithManager(ctx, NewManager(), stateRoot, projectID, sessionID, false)
}

// ActivateQuiesced recreates an owned network while the retained VM is
// stopped, then installs deny-all rules before returning it to the caller.
func ActivateQuiesced(ctx context.Context, stateRoot, projectID, sessionID string) (_ *Boundary, err error) {
	return activateWithManager(ctx, NewManager(), stateRoot, projectID, sessionID, true)
}

// RecoverQuiesced adopts an exact previously-owned boundary after a process
// crash. If the earlier owner already deleted it, only the global dev lock is
// held; frozen host-side recovery never creates or attaches a new network.
func RecoverQuiesced(ctx context.Context, stateRoot, projectID, sessionID string) (_ *Boundary, err error) {
	lock, err := acquireExclusiveLock(stateRoot)
	if err != nil {
		return nil, err
	}
	boundary := &Boundary{manager: NewManager(), lock: lock, stateRoot: stateRoot}
	defer func() {
		if err != nil {
			_ = boundary.Close(context.Background())
		}
	}()
	name, err := networkName(projectID, sessionID)
	if err != nil {
		return nil, err
	}
	if err := reclaimStaleNetwork(ctx, boundary.manager, stateRoot, name); err != nil {
		return nil, err
	}
	if err := writeOwnerJournal(stateRoot, name); err != nil {
		return nil, err
	}
	boundary.Network, err = boundary.manager.inspect(ctx, name)
	if errors.Is(err, errNotFound) {
		return boundary, nil
	}
	if err != nil {
		return nil, err
	}
	if boundary.Network.ProjectID != projectID || boundary.Network.SessionID != sessionID {
		return nil, fmt.Errorf("existing dev network ownership labels do not match recovery")
	}
	if err := boundary.Quiesce(ctx); err != nil {
		return nil, err
	}
	return boundary, nil
}

func activateWithManager(ctx context.Context, manager *Manager, stateRoot, projectID, sessionID string, quiesced bool) (_ *Boundary, err error) {
	lock, err := acquireExclusiveLock(stateRoot)
	if err != nil {
		return nil, err
	}
	boundary := &Boundary{manager: manager, lock: lock, stateRoot: stateRoot}
	defer func() {
		if err != nil {
			_ = boundary.Close(context.Background())
		}
	}()
	name, err := networkName(projectID, sessionID)
	if err != nil {
		return nil, err
	}
	// The exclusive flock proves no other dev boundary is live, so every
	// journaled network other than the target is an orphan from a partial
	// create or a crashed supervisor and must be reclaimed before a new
	// network permanently consumes another vmnet subnet.
	if err := reclaimStaleNetwork(ctx, manager, stateRoot, name); err != nil {
		return nil, err
	}
	// Journal the intended owner before creating so a crash between create
	// and use still leaves a durable reference for the next activate.
	if err := writeOwnerJournal(stateRoot, name); err != nil {
		return nil, err
	}
	boundary.Network, err = manager.Create(ctx, projectID, sessionID)
	if err != nil {
		return nil, err
	}
	if quiesced {
		if err := boundary.Quiesce(ctx); err != nil {
			return nil, err
		}
	} else {
		if err := boundary.Verify(ctx); err != nil {
			return nil, err
		}
	}
	return boundary, nil
}

func (b *Boundary) Verify(ctx context.Context) error {
	if b == nil || b.closed || b.lock == nil {
		return fmt.Errorf("dev network boundary is not active")
	}
	if err := b.manager.Verify(ctx, b.Network); err != nil {
		return err
	}
	return firewall.Enable(ctx, firewall.Network{Subnet: b.Network.IPv4Subnet, Gateway: b.Network.IPv4Gateway, IPv6Subnet: b.Network.IPv6Subnet})
}

func (b *Boundary) Quiesce(ctx context.Context) error {
	if b == nil || b.closed || b.lock == nil {
		return fmt.Errorf("dev network boundary is not active")
	}
	if err := b.manager.Verify(ctx, b.Network); err != nil {
		return err
	}
	return firewall.Quiesce(ctx, firewall.Network{Subnet: b.Network.IPv4Subnet, Gateway: b.Network.IPv4Gateway, IPv6Subnet: b.Network.IPv6Subnet})
}

func (b *Boundary) Close(ctx context.Context) error {
	if b == nil || b.closed {
		return nil
	}
	b.closed = true
	var closeErr error
	if b.Network.Name != "" {
		var networkErr error
		if err := b.manager.Delete(ctx, b.Network); err != nil && !errors.Is(err, errNotFound) {
			networkErr = err
		}
		// The owner journal is only cleared once nothing references the
		// network anymore; otherwise the next activate reclaims it.
		if networkErr == nil && b.stateRoot != "" {
			networkErr = clearOwnerJournal(b.stateRoot)
		}
		closeErr = errors.Join(closeErr, firewall.Disable(ctx), networkErr)
	}
	if b.lock != nil {
		closeErr = errors.Join(closeErr, unix.Flock(int(b.lock.Fd()), unix.LOCK_UN), b.lock.Close())
		b.lock = nil
	}
	return closeErr
}

func acquireExclusiveLock(stateRoot string) (*os.File, error) {
	if !filepath.IsAbs(stateRoot) {
		return nil, fmt.Errorf("dev network lock requires an absolute state root")
	}
	if err := os.MkdirAll(stateRoot, 0700); err != nil {
		return nil, err
	}
	root, err := filepath.EvalSymlinks(stateRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve dev network state root: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return nil, fmt.Errorf("dev network state root must be a private real directory")
	}
	path := filepath.Join(root, "dev-network.lock")
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0777 != 0600 {
		file.Close()
		return nil, fmt.Errorf("dev network lock must be a private current-user regular file")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("another dev session owns the host firewall boundary")
		}
		return nil, err
	}
	return file, nil
}

func NewManager() *Manager {
	return &Manager{run: runCommand}
}

func (m *Manager) Create(ctx context.Context, projectID, sessionID string) (Network, error) {
	name, err := networkName(projectID, sessionID)
	if err != nil {
		return Network{}, err
	}
	if _, err := m.inspect(ctx, name); err == nil {
		return Network{}, fmt.Errorf("refusing to reuse existing dev network %q", name)
	} else if !errors.Is(err, errNotFound) {
		return Network{}, err
	}
	if _, err := m.run(ctx, "container", "network", "create",
		"--label", "dev.sunaba.owner="+ownerLabel,
		"--label", "dev.sunaba.project="+projectID,
		"--label", "dev.sunaba.session="+sessionID,
		"--label", "dev.sunaba.mode=dev", name); err != nil {
		return Network{}, fmt.Errorf("create dev network %q: %w", name, err)
	}
	network, err := m.inspect(ctx, name)
	if err != nil {
		return Network{}, errors.Join(fmt.Errorf("verify newly created dev network %q: %w", name, err), m.removeCreatedNetwork(ctx, name))
	}
	if network.ProjectID != projectID || network.SessionID != sessionID {
		return Network{}, errors.Join(fmt.Errorf("new dev network ownership labels do not match"), m.removeCreatedNetwork(ctx, name))
	}
	return network, nil
}

// removeCreatedNetwork deletes a network this process just created after its
// verification failed, so a partial create cannot leak the vmnet subnet.
func (m *Manager) removeCreatedNetwork(ctx context.Context, name string) error {
	if _, err := m.run(ctx, "container", "network", "delete", name); err != nil {
		return fmt.Errorf("remove failed dev network %q: %w", name, err)
	}
	return nil
}

// ownerJournal durably records the one dev network the current global-lock
// owner created so a later activate can reclaim it after a crash.
type ownerJournal struct {
	Name string `json:"name"`
}

func writeOwnerJournal(stateRoot, name string) error {
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot || !networkNamePattern.MatchString(name) || len(name) > 127 {
		return fmt.Errorf("dev network ownership journal path is invalid")
	}
	data, err := json.Marshal(ownerJournal{Name: name})
	if err != nil {
		return err
	}
	return securefs.AtomicWriteOwned(filepath.Join(stateRoot, ownerJournalFile), append(data, '\n'))
}

func clearOwnerJournal(stateRoot string) error {
	if err := os.Remove(filepath.Join(stateRoot, ownerJournalFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// reclaimStaleNetwork deletes the network recorded in the owner journal when
// it is not the exact network the caller is about to own. Deletion is guarded
// by inspect's ownership-label checks and Delete's full identity validation.
func reclaimStaleNetwork(ctx context.Context, manager *Manager, stateRoot, keep string) error {
	journalPath := filepath.Join(stateRoot, ownerJournalFile)
	data, err := securefs.ReadOwnedRegular(journalPath, 4096)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read dev network ownership journal: %w", err)
	}
	var journal ownerJournal
	if securefs.DecodeStrictJSON(data, &journal) != nil || !networkNamePattern.MatchString(journal.Name) || len(journal.Name) > 127 {
		return fmt.Errorf("dev network ownership journal is invalid")
	}
	if journal.Name == keep {
		return nil
	}
	network, err := manager.inspect(ctx, journal.Name)
	if errors.Is(err, errNotFound) {
		return os.Remove(journalPath)
	}
	if err != nil {
		return fmt.Errorf("inspect stale dev network %q: %w", journal.Name, err)
	}
	if err := manager.Delete(ctx, network); err != nil && !errors.Is(err, errNotFound) {
		return fmt.Errorf("reclaim stale dev network %q: %w", journal.Name, err)
	}
	return os.Remove(journalPath)
}

func networkName(projectID, sessionID string) (string, error) {
	if !identityPattern.MatchString(projectID) || !identityPattern.MatchString(sessionID) {
		return "", fmt.Errorf("dev network requires safe Project and session identities")
	}
	name := "sunaba-" + projectID + "-" + sessionID + "-net"
	if len(name) > 127 {
		return "", fmt.Errorf("dev network name is too long")
	}
	return name, nil
}

func (m *Manager) Verify(ctx context.Context, expected Network) error {
	if err := expected.validate(); err != nil {
		return err
	}
	actual, err := m.inspect(ctx, expected.Name)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("dev network configuration or ownership changed")
	}
	return nil
}

func (m *Manager) Delete(ctx context.Context, expected Network) error {
	if err := m.Verify(ctx, expected); err != nil {
		return fmt.Errorf("refusing to delete unverified dev network: %w", err)
	}
	if _, err := m.run(ctx, "container", "network", "delete", expected.Name); err != nil {
		return fmt.Errorf("delete dev network %q: %w", expected.Name, err)
	}
	if _, err := m.inspect(ctx, expected.Name); !errors.Is(err, errNotFound) {
		return fmt.Errorf("dev network %q still exists after deletion", expected.Name)
	}
	return nil
}

var errNotFound = errors.New("network not found")

func (m *Manager) inspect(ctx context.Context, name string) (Network, error) {
	out, err := m.run(ctx, "container", "network", "inspect", name)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") || strings.Contains(strings.ToLower(err.Error()), "does not exist") {
			return Network{}, errNotFound
		}
		return Network{}, fmt.Errorf("inspect dev network %q: %w", name, err)
	}
	var payload []struct {
		Configuration struct {
			Name   string            `json:"name"`
			Mode   string            `json:"mode"`
			Plugin string            `json:"plugin"`
			Labels map[string]string `json:"labels"`
		} `json:"configuration"`
		ID     string `json:"id"`
		Status struct {
			IPv4Subnet  string `json:"ipv4Subnet"`
			IPv4Gateway string `json:"ipv4Gateway"`
			IPv6Subnet  string `json:"ipv6Subnet"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out, &payload); err != nil || len(payload) != 1 {
		return Network{}, fmt.Errorf("dev network inspect returned an invalid schema")
	}
	item := payload[0]
	if item.ID != name || item.Configuration.Name != name || item.Configuration.Mode != "nat" || item.Configuration.Plugin != "container-network-vmnet" || item.Configuration.Labels["dev.sunaba.owner"] != ownerLabel || item.Configuration.Labels["dev.sunaba.mode"] != "dev" {
		return Network{}, fmt.Errorf("dev network identity, implementation, or owner does not match")
	}
	network := Network{Name: name, ProjectID: item.Configuration.Labels["dev.sunaba.project"], SessionID: item.Configuration.Labels["dev.sunaba.session"], IPv4Subnet: strings.ReplaceAll(item.Status.IPv4Subnet, `\/`, "/"), IPv4Gateway: item.Status.IPv4Gateway, IPv6Subnet: strings.ReplaceAll(item.Status.IPv6Subnet, `\/`, "/")}
	if err := network.validate(); err != nil {
		return Network{}, err
	}
	return network, nil
}

func (n Network) validate() error {
	if !identityPattern.MatchString(n.ProjectID) || !identityPattern.MatchString(n.SessionID) || n.Name != "sunaba-"+n.ProjectID+"-"+n.SessionID+"-net" {
		return fmt.Errorf("dev network identity is invalid")
	}
	ipv4, subnet4, err := net.ParseCIDR(n.IPv4Subnet)
	if err != nil || ipv4.To4() == nil || subnet4.String() != n.IPv4Subnet || !subnet4.Contains(net.ParseIP(n.IPv4Gateway)) {
		return fmt.Errorf("dev network IPv4 allocation is invalid")
	}
	ipv6, subnet6, err := net.ParseCIDR(n.IPv6Subnet)
	if err != nil || ipv6.To4() != nil || subnet6.String() != n.IPv6Subnet {
		return fmt.Errorf("dev network IPv6 allocation is invalid")
	}
	return nil
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	commandContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(commandContext, name, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}
