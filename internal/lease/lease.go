package lease

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type State string

const (
	Active  State = "active"
	Paused  State = "paused"
	Revoked State = "revoked"
)

var ErrInactive = errors.New("session lease is inactive or expired")
var identityPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

type Record struct {
	Version   int       `json:"version"`
	ProjectID string    `json:"project_id"`
	VMID      string    `json:"vm_id"`
	SessionID string    `json:"session_id"`
	Use       string    `json:"use"`
	State     State     `json:"state"`
	ExpiresAt time.Time `json:"expires_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Registry struct {
	Root string
	Now  func() time.Time
	mu   sync.Mutex
}

func (r *Registry) Register(projectID, vmID, sessionID, use string, ttl time.Duration) (Record, error) {
	return r.register(projectID, vmID, sessionID, use, Active, ttl)
}

func (r *Registry) RegisterPaused(projectID, vmID, sessionID, use string, ttl time.Duration) (Record, error) {
	return r.register(projectID, vmID, sessionID, use, Paused, ttl)
}

func (r *Registry) register(projectID, vmID, sessionID, use string, initial State, ttl time.Duration) (Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.validate(); err != nil {
		return Record{}, err
	}
	if !validIdentity(projectID) || !validIdentity(vmID) || !validIdentity(sessionID) || !validIdentity(use) || (initial != Active && initial != Paused) || ttl <= 0 || ttl > 24*time.Hour {
		return Record{}, fmt.Errorf("invalid session lease identity or lifetime")
	}
	if err := r.ensureDirectory(); err != nil {
		return Record{}, err
	}
	filename := r.filename(sessionID)
	if _, err := os.Lstat(filename); err == nil {
		return Record{}, fmt.Errorf("session lease identity already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Record{}, err
	}
	now := r.now().UTC()
	record := Record{Version: 1, ProjectID: projectID, VMID: vmID, SessionID: sessionID, Use: use, State: initial, ExpiresAt: now.Add(ttl), UpdatedAt: now}
	return record, r.write(record)
}

func (r *Registry) Load(sessionID string) (Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.load(sessionID)
}

func (r *Registry) ValidateActive(projectID, vmID, sessionID, use string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, err := r.load(sessionID)
	if err != nil || record.ProjectID != projectID || record.VMID != vmID || record.Use != use || record.State != Active || !r.now().Before(record.ExpiresAt) {
		return ErrInactive
	}
	return nil
}

func (r *Registry) Pause(sessionID string) (Record, error) {
	return r.transition(sessionID, Active, Paused)
}

func (r *Registry) Activate(sessionID string) (Record, error) {
	return r.transition(sessionID, Paused, Active)
}

func (r *Registry) Revoke(sessionID string) (Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, err := r.load(sessionID)
	if err != nil {
		return Record{}, err
	}
	if record.State == Revoked {
		return record, nil
	}
	record.State, record.UpdatedAt = Revoked, r.now().UTC()
	return record, r.write(record)
}

func (r *Registry) transition(sessionID string, from, to State) (Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, err := r.load(sessionID)
	if err != nil {
		return Record{}, err
	}
	if record.State != from || !r.now().Before(record.ExpiresAt) {
		return Record{}, ErrInactive
	}
	record.State, record.UpdatedAt = to, r.now().UTC()
	return record, r.write(record)
}

func (r *Registry) load(sessionID string) (Record, error) {
	if err := r.validate(); err != nil || !validIdentity(sessionID) {
		return Record{}, fmt.Errorf("invalid lease registry or session identity")
	}
	encoded, err := readLeaseFile(r.filename(sessionID))
	if err != nil {
		return Record{}, err
	}
	var record Record
	if json.Unmarshal(encoded, &record) != nil || record.Version != 1 || record.SessionID != sessionID || !validIdentity(record.ProjectID) || !validIdentity(record.VMID) || !validIdentity(record.Use) || record.ExpiresAt.IsZero() {
		return Record{}, fmt.Errorf("invalid persisted session lease")
	}
	return record, nil
}

func (r *Registry) write(record Record) error {
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	filename := r.filename(record.SessionID)
	temporary, err := os.CreateTemp(filepath.Dir(filename), ".sunaba-lease-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(encoded, '\n')); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(filename))
	if err != nil {
		return err
	}
	err = directory.Sync()
	_ = directory.Close()
	return err
}

func (r *Registry) ensureDirectory() error {
	if err := os.MkdirAll(r.Root, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(r.Root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("lease registry must be a mode 0700 directory")
	}
	return nil
}

func (r *Registry) validate() error {
	if r == nil || !filepath.IsAbs(r.Root) {
		return fmt.Errorf("lease registry root must be absolute")
	}
	return nil
}

func (r *Registry) filename(sessionID string) string { return filepath.Join(r.Root, sessionID+".json") }
func (r *Registry) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}
func validIdentity(value string) bool { return identityPattern.MatchString(value) }

func readLeaseFile(filename string) ([]byte, error) {
	fd, err := unix.Open(filename, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filename)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open lease file")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0600 || stat.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("lease file must be a mode 0600 regular file owned by the current user")
	}
	return io.ReadAll(io.LimitReader(file, 1<<20))
}
