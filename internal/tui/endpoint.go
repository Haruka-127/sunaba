package tui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	HelperStartupTimeout = 15 * time.Second
	UserDecisionTimeout  = 15 * time.Minute
	FrameIOTimeout       = 5 * time.Second
)

type Endpoint struct {
	Directory string
	Socket    string
	Binding   Binding

	listener        *net.UnixListener
	mu              sync.Mutex
	project         string
	nonce           string
	bound           bool
	accepted        bool
	closed          bool
	startupTimeout  time.Duration
	decisionTimeout time.Duration
	frameTimeout    time.Duration
}

type LaunchSpec struct {
	Socket    string
	ProjectID string
	Nonce     string
}

func newNonce() (string, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("create UI nonce: %w", err)
	}
	return hex.EncodeToString(nonce[:]), nil
}

// NewEndpoint creates an owner-only, one-connection socket beneath tempRoot.
// Callers should normally pass os.TempDir(); platform APIs may return that path
// with a trailing separator, so normalize it before enforcing the OS-temp
// boundary. An explicit root keeps tests and lifecycle ownership bounded.
func NewEndpoint(tempRoot, projectID string) (*Endpoint, error) {
	if len(projectID) == 0 || len(projectID) > 128 || hasUnsafeInput(projectID) {
		return nil, errors.New("invalid UI Project binding")
	}
	if !filepath.IsAbs(tempRoot) {
		return nil, errors.New("UI temporary root must be absolute")
	}
	tempRoot = filepath.Clean(tempRoot)
	canonicalRoot, err := filepath.EvalSymlinks(tempRoot)
	if err != nil || !filepath.IsAbs(canonicalRoot) || !isOSTemporaryRoot(canonicalRoot) {
		return nil, errors.New("UI temporary root must be a canonical OS temporary directory")
	}
	tempRoot = canonicalRoot
	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp(tempRoot, "sunaba-ui-")
	if err != nil {
		return nil, fmt.Errorf("create UI temporary directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	if err := os.Chmod(directory, 0700); err != nil {
		cleanup()
		return nil, err
	}
	if err := validatePrivateDirectory(directory); err != nil {
		cleanup()
		return nil, err
	}
	socket := filepath.Join(directory, "ui.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("listen on UI socket: %w", err)
	}
	if err := os.Chmod(socket, 0600); err != nil {
		_ = listener.Close()
		cleanup()
		return nil, err
	}
	var socketStat unix.Stat_t
	if info, statErr := os.Lstat(socket); statErr != nil || unix.Lstat(socket, &socketStat) != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 || socketStat.Uid != uint32(os.Geteuid()) {
		_ = listener.Close()
		cleanup()
		return nil, errors.New("UI socket is not owner-only")
	}
	return &Endpoint{
		Directory: directory, Socket: socket, project: projectID, nonce: nonce, listener: listener,
		startupTimeout: HelperStartupTimeout, decisionTimeout: UserDecisionTimeout, frameTimeout: FrameIOTimeout,
	}, nil
}

func isOSTemporaryRoot(root string) bool {
	candidates := []string{os.TempDir(), "/tmp", "/private/tmp"}
	for _, candidate := range candidates {
		canonical, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		canonical = filepath.Clean(canonical)
		if root == canonical || len(root) > len(canonical) && root[:len(canonical)] == canonical && root[len(canonical)] == filepath.Separator {
			return true
		}
	}
	return false
}

// LaunchSpec is safe to obtain before process creation. BindHelperPID must be
// called with cmd.Process.Pid immediately after a successful Start.
func (e *Endpoint) LaunchSpec() LaunchSpec {
	if e == nil {
		return LaunchSpec{}
	}
	return LaunchSpec{Socket: e.Socket, ProjectID: e.project, Nonce: e.nonce}
}

// BindHelperPID is single-assignment. This resolves the launcher circularity:
// the socket and nonce exist before Start, while the kernel PID is fixed after.
func (e *Endpoint) BindHelperPID(pid int) (Binding, error) {
	if e == nil || pid <= 0 {
		return Binding{}, errors.New("invalid sunaba-ui process ID")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.bound || e.accepted || e.closed {
		return Binding{}, errors.New("sunaba-ui process binding is already fixed")
	}
	e.Binding = Binding{ProcessID: pid, ProjectID: e.project, Nonce: e.nonce}
	if err := e.Binding.validate(); err != nil {
		return Binding{}, err
	}
	e.bound = true
	return e.Binding, nil
}

func (e *Endpoint) BoundIdentity() (Binding, error) {
	if e == nil {
		return Binding{}, errors.New("UI endpoint is not initialized")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.bound {
		return Binding{}, errors.New("sunaba-ui process ID is not bound")
	}
	return e.Binding, nil
}

func validatePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	var stat unix.Stat_t
	if err != nil || unix.Lstat(path, &stat) != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("UI temporary directory is not owner-only")
	}
	return nil
}

// ServeOnce exchanges exactly one view and one event. It closes the listening
// socket as soon as the first connection is accepted, preventing connection
// replacement while the user is deciding.
func (e *Endpoint) ServeOnce(ctx context.Context, view View) (event Event, resultErr error) {
	if e == nil || e.listener == nil {
		return Event{}, errors.New("UI endpoint is not initialized")
	}
	defer func() { resultErr = errors.Join(resultErr, e.Close()) }()
	if view.Binding != e.Binding {
		return Event{}, errors.New("UI view is not bound to this endpoint")
	}
	if err := view.Validate(); err != nil {
		return Event{}, err
	}
	e.mu.Lock()
	if !e.bound {
		e.mu.Unlock()
		return Event{}, errors.New("sunaba-ui process ID is not bound")
	}
	if e.accepted || e.closed {
		e.mu.Unlock()
		return Event{}, errors.New("UI endpoint permits only one connection")
	}
	e.accepted = true
	e.mu.Unlock()

	deadline := time.Now().Add(e.startupTimeout)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	if err := e.listener.SetDeadline(deadline); err != nil {
		return Event{}, err
	}
	connection, err := e.listener.AcceptUnix()
	_ = e.listener.Close()
	_ = os.Remove(e.Socket)
	if err != nil {
		return Event{}, fmt.Errorf("accept sunaba-ui: %w", err)
	}
	defer connection.Close()
	if err := verifyPeer(connection, e.Binding.ProcessID); err != nil {
		return Event{}, err
	}
	frameDeadline := time.Now().Add(e.frameTimeout)
	if value, ok := ctx.Deadline(); ok && value.Before(frameDeadline) {
		frameDeadline = value
	}
	if err := connection.SetDeadline(frameDeadline); err != nil {
		return Event{}, err
	}
	if err := WriteFrame(connection, view); err != nil {
		return Event{}, fmt.Errorf("send UI view: %w", err)
	}
	waitDeadline := time.Now().Add(e.decisionTimeout)
	if value, ok := ctx.Deadline(); ok && value.Before(waitDeadline) {
		waitDeadline = value
	}
	event, err = readSingleEventFromConn(connection, waitDeadline, e.frameTimeout)
	if err != nil {
		return Event{}, err
	}
	if err := event.ValidateFor(view); err != nil {
		return Event{}, err
	}
	return event, nil
}

// Close is idempotent and removes only this endpoint's exact socket and
// temporary directory.
func (e *Endpoint) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.mu.Unlock()
	var errs []error
	if e.listener != nil {
		if err := e.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	if e.Socket != "" {
		if err := os.Remove(e.Socket); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if e.Directory != "" {
		if err := os.Remove(e.Directory); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
