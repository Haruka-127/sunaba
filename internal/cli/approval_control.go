package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"sunaba/internal/gitgateway"
	"sunaba/internal/recovery"
	"sunaba/internal/runtime"
	"sunaba/internal/session"
	"sunaba/internal/trustedui"
)

const approvalControlSocket = "approval-control.sock"
const approvalControlLocator = "active-approval-control.json"

type approvalControl struct {
	path     string
	locator  string
	listener net.Listener
	server   *http.Server
	done     chan error
}

type approvalLocator struct {
	Version int    `json:"version"`
	Socket  string `json:"socket"`
}

type pushApprovalBroker interface {
	Pending() []gitgateway.PushRequest
	Confirm(string, gitgateway.PushBinding) error
	Reject(string, gitgateway.PushBinding) error
}

type pushDecisionRequest struct {
	Nonce   string                 `json:"nonce"`
	Binding gitgateway.PushBinding `json:"binding"`
}

type supervisorInfo struct {
	Version        int       `json:"version"`
	ProjectID      string    `json:"project_id"`
	VMID           string    `json:"vm_id"`
	SessionID      string    `json:"session_id"`
	Container      string    `json:"container"`
	RuntimeRoot    string    `json:"runtime_root"`
	WorkspacePath  string    `json:"workspace_path"`
	AttachURL      string    `json:"attach_url"`
	ServerPassword string    `json:"server_password"`
	State          string    `json:"state"`
	ExpiresAt      time.Time `json:"expires_at"`
	IdleSeconds    int64     `json:"idle_seconds"`
	IdleDeadline   time.Time `json:"idle_deadline"`
	ModelUsed      int64     `json:"model_used"`
	ModelLimit     int64     `json:"model_limit"`
}

type shellRequest struct {
	Command string `json:"command"`
}

type shellResponse struct {
	Output string `json:"output"`
}

type execRequest struct {
	Directory string   `json:"directory"`
	Arguments []string `json:"arguments"`
}

type exportRequest struct {
	DiscardExternalGit bool `json:"discard_external_git"`
}

type execResponse struct {
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	ExitCode        int    `json:"exit_code"`
	TimedOut        bool   `json:"timed_out"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
}

type sessionControlTarget interface {
	Pause(context.Context) error
	ResumeWith(context.Context, session.Activation) error
	StopAndExport(context.Context) (session.ExportResult, error)
	SetDiscardExternalGitForExport(bool) error
	Destroy(context.Context) error
	ExecOutput(context.Context, []string) (string, error)
	ExecCapture(context.Context, []string, int64, int64) (runtime.ExecResult, error)
}

type controlledSession struct {
	active           sessionControlTarget
	persistent       *session.Session
	projectID        string
	vmID             string
	sessionID        string
	container        string
	runtimeRoot      string
	workspacePath    string
	attachURL        string
	projectState     string
	serverPassword   string
	expiresAt        time.Time
	idleTimeout      time.Duration
	lastActivity     time.Time
	now              func() time.Time
	deadlineChanged  chan struct{}
	deadlineRevision uint64
	mu               sync.Mutex
	state            string
	exit             chan struct{}
	exitOnce         sync.Once
	activate         func(context.Context) (managedActivation, error)
	gitBroker        *rotatingPushBroker
	modelUsage       func() (int64, int64)
}

func newControlledSession(active *session.Session, projectState string, initial managedActivation, idleTimeout time.Duration, activate func(context.Context) (managedActivation, error), broker *rotatingPushBroker) (*controlledSession, error) {
	if active == nil || projectState == "" || len(initial.activation.ServerPassword) < 32 || initial.expiresAt.IsZero() || idleTimeout < time.Second || activate == nil || broker == nil {
		return nil, fmt.Errorf("supervisor session control is incomplete")
	}
	now := time.Now
	return &controlledSession{
		active: active, persistent: active, projectID: active.ProjectID, vmID: active.VMID, sessionID: active.SessionID, container: active.Container,
		runtimeRoot: active.Root, workspacePath: active.WorkspacePath, attachURL: active.AttachURL,
		projectState: projectState, serverPassword: initial.activation.ServerPassword, expiresAt: initial.expiresAt,
		idleTimeout: idleTimeout, lastActivity: now(), now: now, deadlineChanged: make(chan struct{}, 1), deadlineRevision: 1, state: "running", exit: make(chan struct{}),
		activate: activate, gitBroker: broker,
		modelUsage: initial.modelUsage,
	}, nil
}

func (s *controlledSession) info() supervisorInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	info := supervisorInfo{
		Version: 2, ProjectID: s.projectID, VMID: s.vmID, SessionID: s.sessionID, Container: s.container,
		RuntimeRoot: s.runtimeRoot, WorkspacePath: s.workspacePath, AttachURL: s.attachURL, ServerPassword: s.serverPassword,
		State: s.state, ExpiresAt: s.expiresAt, IdleSeconds: int64(s.idleTimeout / time.Second), IdleDeadline: s.lastActivity.Add(s.idleTimeout),
	}
	if s.state == "running" && s.modelUsage != nil {
		info.ModelUsed, info.ModelLimit = s.modelUsage()
	}
	if s.state != "running" {
		info.SessionID, info.AttachURL, info.ServerPassword, info.ExpiresAt = "", "", "", time.Time{}
	}
	return info
}

func (s *controlledSession) pause(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == "paused" {
		return nil
	}
	if s.state != "running" {
		return fmt.Errorf("supervisor session is not running")
	}
	return s.pauseLocked(ctx)
}

func (s *controlledSession) pauseLocked(ctx context.Context) error {
	if err := s.active.Pause(ctx); err != nil {
		s.state = "failed"
		s.notifyDeadlineChangedLocked()
		return err
	}
	s.state = "paused"
	s.sessionID, s.serverPassword = "", ""
	s.expiresAt = time.Time{}
	if s.gitBroker != nil {
		s.gitBroker.Set(nil)
	}
	s.notifyDeadlineChangedLocked()
	return nil
}

func (s *controlledSession) resume(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == "running" {
		return nil
	}
	if s.state != "paused" {
		return fmt.Errorf("supervisor session is not resumable")
	}
	if s.activate == nil {
		return fmt.Errorf("Agent Session activation factory is unavailable")
	}
	activation, err := s.activate(ctx)
	if err != nil {
		return err
	}
	if err := s.active.ResumeWith(ctx, activation.activation); err != nil {
		s.state = "failed"
		s.notifyDeadlineChangedLocked()
		return err
	}
	if s.persistent != nil {
		s.attachURL = s.persistent.AttachURL
	}
	s.sessionID = activation.activation.SessionID
	s.serverPassword = activation.activation.ServerPassword
	s.expiresAt = activation.expiresAt
	if activation.idleTimeout >= time.Second {
		s.idleTimeout = activation.idleTimeout
	}
	s.modelUsage = activation.modelUsage
	if s.gitBroker != nil {
		s.gitBroker.Set(activation.gitBroker)
	}
	s.lastActivity = s.currentTime()
	s.state = "running"
	s.notifyDeadlineChangedLocked()
	return nil
}

func (s *controlledSession) heartbeat() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.currentTime()
	if s.state != "running" || !now.Before(s.expiresAt) {
		return fmt.Errorf("Agent Session is not active")
	}
	s.touchLocked(now)
	return nil
}

type sessionDeadlineSnapshot struct {
	state        string
	revision     uint64
	expiresAt    time.Time
	idleDeadline time.Time
}

func (s *controlledSession) deadlineSnapshot() sessionDeadlineSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sessionDeadlineSnapshot{
		state: s.state, revision: s.deadlineRevision, expiresAt: s.expiresAt,
		idleDeadline: s.lastActivity.Add(s.idleTimeout),
	}
}

func (s *controlledSession) pauseIfIdle(ctx context.Context, revision uint64, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deadlineRevision != revision || s.state != "running" || s.idleTimeout < time.Second || now.Before(s.lastActivity.Add(s.idleTimeout)) {
		return false, nil
	}
	return true, s.pauseLocked(ctx)
}

func (s *controlledSession) pauseIfExpired(ctx context.Context, revision uint64, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deadlineRevision != revision || s.state != "running" || s.expiresAt.IsZero() || now.Before(s.expiresAt) {
		return false, nil
	}
	return true, s.pauseLocked(ctx)
}

func (s *controlledSession) currentTime() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *controlledSession) touchLocked(now time.Time) {
	s.lastActivity = now
	s.notifyDeadlineChangedLocked()
}

func (s *controlledSession) notifyDeadlineChangedLocked() {
	s.deadlineRevision++
	if s.deadlineChanged != nil {
		select {
		case s.deadlineChanged <- struct{}{}:
		default:
		}
	}
}

func (s *controlledSession) exportAndDestroy(ctx context.Context) error {
	return s.exportAndDestroyWithOptions(ctx, false)
}

func (s *controlledSession) exportAndDestroyWithOptions(ctx context.Context, discardExternalGit bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == "destroyed" || s.state == "exported" {
		return fmt.Errorf("supervisor session is already closed")
	}
	if err := s.active.SetDiscardExternalGitForExport(discardExternalGit); err != nil {
		return err
	}
	result, err := s.active.StopAndExport(ctx)
	if err != nil {
		var recoveryRequired *session.RecoveryRequiredError
		if errors.As(err, &recoveryRequired) && s.persistent != nil {
			// Export refusal irrevocably transfers this path away from automatic
			// destruction, even if host metadata persistence itself reports an
			// error. Losing the record must never authorize losing guest state.
			s.state = "recovery"
			s.notifyDeadlineChangedLocked()
			s.signalExit()
			record := s.persistent.RecoveryState(recoveryRequired.Cause.Error())
			if saveErr := recovery.Save(s.projectState, record); saveErr != nil {
				return errors.Join(err, fmt.Errorf("persist stopped dev VM recovery ownership: %w", saveErr))
			}
			// The durable record becomes the owner before process-scoped locks are
			// released. No later cleanup error may turn this into VM destruction.
			if detachErr := s.persistent.DetachForRecovery(ctx); detachErr != nil {
				return errors.Join(err, fmt.Errorf("release stopped dev VM to recovery ownership: %w", detachErr))
			}
			return err
		}
		s.state = "failed"
		s.notifyDeadlineChangedLocked()
		return err
	}
	if len(result.ChangeSet.Changes) > 0 {
		if s.persistent == nil {
			return fmt.Errorf("supervisor cannot persist an unbound Change Set")
		}
		if _, err := persistPending(s.projectState, s.persistent, result); err != nil {
			if !s.persistent.SupportsFrozenRecovery() {
				s.state = "failed"
				s.notifyDeadlineChangedLocked()
				return err
			}
			s.state = "recovery"
			s.notifyDeadlineChangedLocked()
			s.signalExit()
			record := s.persistent.RecoveryStateWithPendingExport(err.Error(), result)
			saveErr := recovery.Save(s.projectState, record)
			// StopAndExport has already stopped the VM, but a successful export
			// only quiesces (rather than closes) the dev network. Always transfer
			// the stopped VM out of process ownership, even if the recovery record
			// itself could not be written. Cleanup treats an unrecorded stopped dev
			// VM as fail-closed, so a metadata failure cannot authorize deletion.
			retainErr := s.persistent.RetainForRecovery(ctx)
			if saveErr != nil {
				return errors.Join(err, fmt.Errorf("persist frozen export recovery ownership: %w", saveErr), retainErr)
			}
			return errors.Join(err, retainErr)
		}
	}
	if err := s.active.Destroy(ctx); err != nil {
		s.state = "failed"
		s.notifyDeadlineChangedLocked()
		return err
	}
	s.state = "exported"
	s.notifyDeadlineChangedLocked()
	s.signalExit()
	return nil
}

func (s *controlledSession) destroy(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == "destroyed" || s.state == "exported" {
		return nil
	}
	if err := s.active.Destroy(ctx); err != nil {
		s.state = "failed"
		s.notifyDeadlineChangedLocked()
		return err
	}
	s.state = "destroyed"
	s.notifyDeadlineChangedLocked()
	s.signalExit()
	return nil
}

func (s *controlledSession) shell(ctx context.Context, command string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.currentTime().Before(s.expiresAt) {
		return "", fmt.Errorf("Agent Session capability expired")
	}
	if s.state != "running" {
		return "", fmt.Errorf("guest shell requires a running Agent Session")
	}
	if command == "" || len(command) > 16<<10 || strings.IndexByte(command, 0) >= 0 {
		return "", fmt.Errorf("guest shell command is invalid")
	}
	s.touchLocked(s.currentTime())
	outer := "runuser -u sunaba-agent -- /run/sunaba/shell-wrapper \"$1\" 2>&1 | head -c 1048576; status=${PIPESTATUS[0]}; printf '\\n[SUNABA_EXIT=%d]\\n' \"$status\"; exit 0"
	output, err := s.active.ExecOutput(ctx, []string{"/bin/bash", "-lc", outer, "sunaba-shell", command})
	return trustedui.SanitizeTerminal(output), err
}

func (s *controlledSession) exec(ctx context.Context, directory string, arguments []string) (execResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.currentTime().Before(s.expiresAt) || s.state != "running" {
		return execResponse{}, fmt.Errorf("guest exec requires an active Agent Session")
	}
	if directory == "" {
		directory = "."
	}
	if filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == ".." || strings.HasPrefix(directory, "../") || len(directory) > 4096 || strings.IndexByte(directory, 0) >= 0 || len(arguments) == 0 || len(arguments) > 256 {
		return execResponse{}, fmt.Errorf("guest exec directory or argv is invalid")
	}
	for _, argument := range arguments {
		if len(argument) > 16<<10 || strings.IndexByte(argument, 0) >= 0 {
			return execResponse{}, fmt.Errorf("guest exec argv is invalid")
		}
	}
	s.touchLocked(s.currentTime())
	command := append([]string{"runuser", "-u", "sunaba-agent", "--", "/run/sunaba/exec-wrapper", directory}, arguments...)
	result, err := s.active.ExecCapture(ctx, command, 1<<20, 1<<20)
	if err != nil {
		return execResponse{}, err
	}
	return execResponse{
		Stdout: result.Stdout, Stderr: result.Stderr, ExitCode: result.ExitCode,
		TimedOut: result.TimedOut, StdoutTruncated: result.StdoutTruncated, StderrTruncated: result.StderrTruncated,
	}, nil
}

func (s *controlledSession) signalExit() { s.exitOnce.Do(func() { close(s.exit) }) }

func (s *controlledSession) recoveryRetained() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state == "recovery"
}

func startApprovalControl(projectState, runtimeBase string, broker pushApprovalBroker, controlled *controlledSession) (*approvalControl, error) {
	if broker == nil && controlled == nil {
		return nil, nil
	}
	if err := verifyPrivateDirectory(projectState); err != nil {
		return nil, err
	}
	if err := verifyPrivateDirectory(runtimeBase); err != nil {
		return nil, err
	}
	path := filepath.Join(runtimeBase, approvalControlSocket)
	if info, err := os.Lstat(path); err == nil {
		var stat unix.Stat_t
		if unix.Lstat(path, &stat) != nil || info.Mode()&os.ModeSocket == 0 || stat.Uid != uint32(os.Geteuid()) {
			return nil, fmt.Errorf("approval control path is unsafe")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/push/pending", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if broker == nil {
			_, _ = response.Write([]byte("[]\n"))
			return
		}
		_ = json.NewEncoder(response).Encode(broker.Pending())
	})
	mux.HandleFunc("POST /v1/push/confirm", func(response http.ResponseWriter, request *http.Request) {
		if broker == nil {
			http.NotFound(response, request)
			return
		}
		decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
		decoder.DisallowUnknownFields()
		var confirmation pushDecisionRequest
		if decoder.Decode(&confirmation) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		if err := broker.Confirm(confirmation.Nonce, confirmation.Binding); err != nil {
			http.Error(response, http.StatusText(http.StatusConflict), http.StatusConflict)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/push/reject", func(response http.ResponseWriter, request *http.Request) {
		if broker == nil {
			http.NotFound(response, request)
			return
		}
		decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
		decoder.DisallowUnknownFields()
		var decision pushDecisionRequest
		if decoder.Decode(&decision) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		if err := broker.Reject(decision.Nonce, decision.Binding); err != nil {
			http.Error(response, http.StatusText(http.StatusConflict), http.StatusConflict)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	})
	if controlled != nil {
		mux.HandleFunc("GET /v1/session", func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(controlled.info())
		})
		for path, operation := range map[string]func(context.Context) error{
			"/v1/session/pause": controlled.pause, "/v1/session/resume": controlled.resume,
			"/v1/session/destroy": controlled.destroy,
		} {
			operation := operation
			mux.HandleFunc("POST "+path, func(response http.ResponseWriter, request *http.Request) {
				if err := operation(request.Context()); err != nil {
					http.Error(response, err.Error(), http.StatusConflict)
					return
				}
				response.WriteHeader(http.StatusNoContent)
			})
		}
		mux.HandleFunc("POST /v1/session/export", func(response http.ResponseWriter, request *http.Request) {
			decoder := json.NewDecoder(io.LimitReader(request.Body, 4<<10))
			decoder.DisallowUnknownFields()
			var options exportRequest
			if decoder.Decode(&options) != nil || decoder.Decode(&struct{}{}) != io.EOF {
				http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
			if err := controlled.exportAndDestroyWithOptions(request.Context(), options.DiscardExternalGit); err != nil {
				http.Error(response, err.Error(), http.StatusConflict)
				return
			}
			response.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("POST /v1/session/heartbeat", func(response http.ResponseWriter, _ *http.Request) {
			if err := controlled.heartbeat(); err != nil {
				http.Error(response, err.Error(), http.StatusConflict)
				return
			}
			response.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("POST /v1/session/shell", func(response http.ResponseWriter, request *http.Request) {
			decoder := json.NewDecoder(io.LimitReader(request.Body, 32<<10))
			decoder.DisallowUnknownFields()
			var shell shellRequest
			if decoder.Decode(&shell) != nil || decoder.Decode(&struct{}{}) != io.EOF {
				http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
			output, err := controlled.shell(request.Context(), shell.Command)
			if err != nil {
				http.Error(response, err.Error(), http.StatusConflict)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(shellResponse{Output: output})
		})
		mux.HandleFunc("POST /v1/session/exec", func(response http.ResponseWriter, request *http.Request) {
			decoder := json.NewDecoder(io.LimitReader(request.Body, 4<<20))
			decoder.DisallowUnknownFields()
			var execution execRequest
			if decoder.Decode(&execution) != nil || decoder.Decode(&struct{}{}) != io.EOF {
				http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
			result, err := controlled.exec(request.Context(), execution.Directory, execution.Arguments)
			if err != nil {
				http.Error(response, err.Error(), http.StatusConflict)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(result)
		})
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second}
	locator := filepath.Join(projectState, approvalControlLocator)
	if err := writePrivateJSON(locator, approvalLocator{Version: 1, Socket: path}); err != nil {
		listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	control := &approvalControl{path: path, locator: locator, listener: listener, server: server, done: make(chan error, 1)}
	go func() {
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		control.done <- err
		close(control.done)
	}()
	return control, nil
}

func (c *approvalControl) Close() error {
	if c == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := c.server.Shutdown(ctx)
	select {
	case doneErr := <-c.done:
		err = errors.Join(err, doneErr)
	case <-ctx.Done():
		err = errors.Join(err, ctx.Err())
	}
	if removeErr := os.Remove(c.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		err = errors.Join(err, removeErr)
	}
	if data, readErr := readOwnedPrivateFile(c.locator, 4096); readErr == nil {
		var locator approvalLocator
		if json.Unmarshal(data, &locator) == nil && locator.Version == 1 && locator.Socket == c.path {
			if removeErr := os.Remove(c.locator); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				err = errors.Join(err, removeErr)
			}
		}
	}
	return err
}

func verifyPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	var stat unix.Stat_t
	canonical, canonicalErr := filepath.EvalSymlinks(path)
	if err != nil || unix.Lstat(path, &stat) != nil || canonicalErr != nil || canonical != path || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("Project state directory is unsafe")
	}
	return nil
}

func (a *app) approveActivePushes(ctx context.Context, projectState string) (int, error) {
	locatorPath := filepath.Join(projectState, approvalControlLocator)
	data, err := readOwnedPrivateFile(locatorPath, 4096)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		if _, lstatErr := os.Lstat(locatorPath); errors.Is(lstatErr, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	var locator approvalLocator
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&locator) != nil || decoder.Decode(&struct{}{}) != io.EOF || locator.Version != 1 || filepath.Base(locator.Socket) != approvalControlSocket || !filepath.IsAbs(locator.Socket) || filepath.Clean(locator.Socket) != locator.Socket || verifyPrivateDirectory(filepath.Dir(locator.Socket)) != nil {
		return 0, fmt.Errorf("active approval control locator is unsafe")
	}
	path := locator.Socket
	info, err := os.Lstat(path)
	var stat unix.Stat_t
	if err != nil || unix.Lstat(path, &stat) != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 || stat.Uid != uint32(os.Geteuid()) {
		return 0, fmt.Errorf("active approval control socket is unsafe")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://sunaba/v1/push/pending", nil)
	response, err := client.Do(request)
	if err != nil {
		return 0, fmt.Errorf("active Agent Session approval control is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("active Agent Session rejected the approval query")
	}
	decoder = json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	decoder.DisallowUnknownFields()
	var pending []gitgateway.PushRequest
	if decoder.Decode(&pending) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(pending) > 128 {
		return 0, fmt.Errorf("active Agent Session returned invalid approval data")
	}
	if len(pending) == 0 {
		return 0, nil
	}
	for _, item := range pending {
		if err := gitgateway.ValidatePushRequest(item); err != nil {
			return 0, fmt.Errorf("active Agent Session returned an invalid push binding")
		}
	}
	index, decision, err := trustedui.SelectPush(a.input, a.output, pending)
	if err != nil {
		return 0, err
	}
	if decision == "skip" {
		return -1, nil
	}
	item := pending[index]
	body, err := json.Marshal(pushDecisionRequest{Nonce: item.Nonce, Binding: item.Binding})
	if err != nil {
		return 0, err
	}
	endpoint := "/v1/push/confirm"
	if decision == "reject" {
		endpoint = "/v1/push/reject"
	}
	confirm, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://sunaba"+endpoint, bytes.NewReader(body))
	confirm.Header.Set("Content-Type", "application/json")
	confirmed, err := client.Do(confirm)
	if err != nil {
		return 0, fmt.Errorf("send Git push decision to active Agent Session: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(confirmed.Body, 4096))
	_ = confirmed.Body.Close()
	if confirmed.StatusCode != http.StatusNoContent {
		return 0, fmt.Errorf("Git push approval expired or changed before confirmation")
	}
	if decision == "reject" {
		fmt.Fprintln(a.output, "Rejected the selected Git push request.")
		return -1, nil
	}
	return 1, nil
}
