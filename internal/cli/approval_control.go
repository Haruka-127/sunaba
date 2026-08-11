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
}

type pushConfirmRequest struct {
	Nonce   string                 `json:"nonce"`
	Binding gitgateway.PushBinding `json:"binding"`
}

type supervisorInfo struct {
	Version        int       `json:"version"`
	ProjectID      string    `json:"project_id"`
	SessionID      string    `json:"session_id"`
	Container      string    `json:"container"`
	RuntimeRoot    string    `json:"runtime_root"`
	WorkspacePath  string    `json:"workspace_path"`
	AttachURL      string    `json:"attach_url"`
	ServerPassword string    `json:"server_password"`
	State          string    `json:"state"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type shellRequest struct {
	Command string `json:"command"`
}

type shellResponse struct {
	Output string `json:"output"`
}

type sessionControlTarget interface {
	Pause(context.Context) error
	Resume(context.Context) error
	StopAndExport(context.Context) (session.ExportResult, error)
	Destroy(context.Context) error
	ExecOutput(context.Context, []string) (string, error)
}

type controlledSession struct {
	active         sessionControlTarget
	persistent     *session.Session
	projectID      string
	sessionID      string
	container      string
	runtimeRoot    string
	workspacePath  string
	attachURL      string
	projectState   string
	serverPassword string
	expiresAt      time.Time
	mu             sync.Mutex
	state          string
	exit           chan struct{}
	exitOnce       sync.Once
}

func newControlledSession(active *session.Session, projectState, serverPassword string, expiresAt time.Time) (*controlledSession, error) {
	if active == nil || projectState == "" || len(serverPassword) < 32 || expiresAt.IsZero() {
		return nil, fmt.Errorf("supervisor session control is incomplete")
	}
	return &controlledSession{
		active: active, persistent: active, projectID: active.ProjectID, sessionID: active.SessionID, container: active.Container,
		runtimeRoot: active.Root, workspacePath: active.WorkspacePath, attachURL: active.AttachURL,
		projectState: projectState, serverPassword: serverPassword, expiresAt: expiresAt, state: "running", exit: make(chan struct{}),
	}, nil
}

func (s *controlledSession) info() supervisorInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return supervisorInfo{
		Version: 1, ProjectID: s.projectID, SessionID: s.sessionID, Container: s.container,
		RuntimeRoot: s.runtimeRoot, WorkspacePath: s.workspacePath, AttachURL: s.attachURL, ServerPassword: s.serverPassword,
		State: s.state, ExpiresAt: s.expiresAt,
	}
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
	if err := s.active.Pause(ctx); err != nil {
		s.state = "failed"
		return err
	}
	s.state = "paused"
	return nil
}

func (s *controlledSession) resume(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !time.Now().Before(s.expiresAt) {
		return fmt.Errorf("Agent Session capability expired; export or recreate the stopped VM")
	}
	if s.state == "running" {
		return nil
	}
	if s.state != "paused" {
		return fmt.Errorf("supervisor session is not resumable")
	}
	if err := s.active.Resume(ctx); err != nil {
		s.state = "failed"
		return err
	}
	if s.persistent != nil {
		s.attachURL = s.persistent.AttachURL
	}
	s.state = "running"
	return nil
}

func (s *controlledSession) exportAndDestroy(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == "destroyed" || s.state == "exported" {
		return fmt.Errorf("supervisor session is already closed")
	}
	result, err := s.active.StopAndExport(ctx)
	if err != nil {
		s.state = "failed"
		return err
	}
	if len(result.ChangeSet.Changes) > 0 {
		if s.persistent == nil {
			return fmt.Errorf("supervisor cannot persist an unbound Change Set")
		}
		if _, err := persistPending(s.projectState, s.persistent, result); err != nil {
			s.state = "failed"
			return err
		}
	}
	if err := s.active.Destroy(ctx); err != nil {
		s.state = "failed"
		return err
	}
	s.state = "exported"
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
		return err
	}
	s.state = "destroyed"
	s.signalExit()
	return nil
}

func (s *controlledSession) shell(ctx context.Context, command string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !time.Now().Before(s.expiresAt) {
		return "", fmt.Errorf("Agent Session capability expired")
	}
	if s.state != "running" {
		return "", fmt.Errorf("guest shell requires a running Agent Session")
	}
	if command == "" || len(command) > 16<<10 || strings.IndexByte(command, 0) >= 0 {
		return "", fmt.Errorf("guest shell command is invalid")
	}
	outer := "runuser -u sunaba-agent -- /run/sunaba/shell-wrapper \"$1\" 2>&1 | head -c 1048576; status=${PIPESTATUS[0]}; printf '\\n[SUNABA_EXIT=%d]\\n' \"$status\"; exit 0"
	output, err := s.active.ExecOutput(ctx, []string{"/bin/bash", "-lc", outer, "sunaba-shell", command})
	return trustedui.SanitizeTerminal(output), err
}

func (s *controlledSession) signalExit() { s.exitOnce.Do(func() { close(s.exit) }) }

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
		var confirmation pushConfirmRequest
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
	if controlled != nil {
		mux.HandleFunc("GET /v1/session", func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(controlled.info())
		})
		for path, operation := range map[string]func(context.Context) error{
			"/v1/session/pause": controlled.pause, "/v1/session/resume": controlled.resume,
			"/v1/session/export": controlled.exportAndDestroy, "/v1/session/destroy": controlled.destroy,
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
	approved := 0
	for _, item := range pending {
		if err := gitgateway.ValidatePushRequest(item); err != nil {
			return approved, fmt.Errorf("active Agent Session returned an invalid push binding")
		}
		if err := trustedui.ConfirmPush(a.input, a.output, item); err != nil {
			return approved, err
		}
		body, err := json.Marshal(pushConfirmRequest{Nonce: item.Nonce, Binding: item.Binding})
		if err != nil {
			return approved, err
		}
		confirm, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://sunaba/v1/push/confirm", bytes.NewReader(body))
		confirm.Header.Set("Content-Type", "application/json")
		confirmed, err := client.Do(confirm)
		if err != nil {
			return approved, fmt.Errorf("send Git push approval to active Agent Session: %w", err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(confirmed.Body, 4096))
		_ = confirmed.Body.Close()
		if confirmed.StatusCode != http.StatusNoContent {
			return approved, fmt.Errorf("Git push approval expired or changed before confirmation")
		}
		approved++
	}
	return approved, nil
}
