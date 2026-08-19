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
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"sunaba/internal/trustedui"
)

var errNoSupervisor = errors.New("no active Project supervisor")
var errStaleSupervisor = errors.New("stale Project supervisor")

type supervisorClient struct {
	socket string
	client *http.Client
}

func openSupervisorClient(projectState string) (*supervisorClient, error) {
	locatorPath := filepath.Join(projectState, approvalControlLocator)
	data, err := readOwnedPrivateFile(locatorPath, 4096)
	if err != nil {
		if _, lstatErr := os.Lstat(locatorPath); errors.Is(lstatErr, os.ErrNotExist) {
			return nil, errNoSupervisor
		}
		return nil, err
	}
	var locator approvalLocator
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&locator) != nil || decoder.Decode(&struct{}{}) != io.EOF || locator.Version != 1 || filepath.Base(locator.Socket) != approvalControlSocket || !filepath.IsAbs(locator.Socket) || filepath.Clean(locator.Socket) != locator.Socket || verifyPrivateDirectory(filepath.Dir(locator.Socket)) != nil {
		return nil, fmt.Errorf("active supervisor locator is unsafe")
	}
	info, err := os.Lstat(locator.Socket)
	var stat unix.Stat_t
	if errors.Is(err, os.ErrNotExist) {
		return nil, errStaleSupervisor
	}
	if err != nil || unix.Lstat(locator.Socket, &stat) != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 || stat.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("active supervisor socket is unavailable or unsafe")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", locator.Socket)
	}}
	return &supervisorClient{socket: locator.Socket, client: &http.Client{Transport: transport}}, nil
}

func (c *supervisorClient) close() {
	if c == nil {
		return
	}
	if transport, ok := c.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (c *supervisorClient) info(ctx context.Context) (supervisorInfo, error) {
	response, err := c.request(ctx, http.MethodGet, "/v1/session", nil)
	if err != nil {
		return supervisorInfo{}, err
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	decoder.DisallowUnknownFields()
	var info supervisorInfo
	if decoder.Decode(&info) != nil || decoder.Decode(&struct{}{}) != io.EOF || info.Version != 2 || info.ProjectID == "" || info.VMID == "" || info.Container != "sunaba-"+info.ProjectID+"-"+info.VMID || !filepath.IsAbs(info.RuntimeRoot) || filepath.Base(info.RuntimeRoot) != "sunaba-vm-"+info.VMID || filepath.Dir(info.RuntimeRoot) != filepath.Dir(c.socket) || !filepath.IsAbs(info.WorkspacePath) || info.IdleSeconds < 1 || info.IdleDeadline.IsZero() {
		return supervisorInfo{}, fmt.Errorf("active supervisor returned invalid session identity")
	}
	if info.State == "running" && (info.SessionID == "" || info.AttachURL == "" || len(info.ServerPassword) < 32 || info.ExpiresAt.IsZero()) {
		return supervisorInfo{}, fmt.Errorf("active supervisor returned incomplete Agent Session authority")
	}
	if info.ModelUsed < 0 || info.ModelLimit < 0 || info.ModelUsed > info.ModelLimit {
		return supervisorInfo{}, fmt.Errorf("active supervisor returned invalid model quota usage")
	}
	if info.State == "paused" && (info.SessionID != "" || info.AttachURL != "" || info.ServerPassword != "" || !info.ExpiresAt.IsZero()) {
		return supervisorInfo{}, fmt.Errorf("paused Project VM exposed revoked Agent Session authority")
	}
	return info, nil
}

func (c *supervisorClient) operation(ctx context.Context, operation string) error {
	switch operation {
	case "pause", "resume", "export", "destroy", "heartbeat":
	default:
		return fmt.Errorf("invalid supervisor operation")
	}
	response, err := c.request(ctx, http.MethodPost, "/v1/session/"+operation, http.NoBody)
	if err != nil {
		return err
	}
	return response.Body.Close()
}

func (c *supervisorClient) shell(ctx context.Context, command string) (string, error) {
	encoded, err := json.Marshal(shellRequest{Command: command})
	if err != nil {
		return "", err
	}
	response, err := c.request(ctx, http.MethodPost, "/v1/session/shell", bytes.NewReader(encoded))
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(response.Body, 2<<20))
	decoder.DisallowUnknownFields()
	var shell shellResponse
	if decoder.Decode(&shell) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(shell.Output) > 2<<20 {
		return "", fmt.Errorf("active supervisor returned invalid shell output")
	}
	return trustedui.SanitizeTerminal(shell.Output), nil
}

func (c *supervisorClient) exec(ctx context.Context, directory string, arguments []string) (execResponse, error) {
	encoded, err := json.Marshal(execRequest{Directory: directory, Arguments: arguments})
	if err != nil {
		return execResponse{}, err
	}
	response, err := c.request(ctx, http.MethodPost, "/v1/session/exec", bytes.NewReader(encoded))
	if err != nil {
		return execResponse{}, err
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16<<20))
	decoder.DisallowUnknownFields()
	var result execResponse
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF || result.ExitCode < -1 || len(result.Stdout) > 1<<20 || len(result.Stderr) > 1<<20 {
		return execResponse{}, fmt.Errorf("active supervisor returned invalid exec result")
	}
	result.Stdout = trustedui.SanitizeTerminal(result.Stdout)
	result.Stderr = trustedui.SanitizeTerminal(result.Stderr)
	return result, nil
}

func (c *supervisorClient) request(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, method, "http://sunaba"+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("active Project supervisor is unavailable")
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return response, nil
	}
	message, _ := io.ReadAll(io.LimitReader(response.Body, 32<<10))
	_ = response.Body.Close()
	return nil, fmt.Errorf("supervisor rejected %s: %s", path, trustedui.SanitizeTerminal(string(message)))
}

func (a *app) ensureSupervisor(ctx context.Context, projectRoot, projectState string) (*supervisorClient, supervisorInfo, error) {
	if client, err := openSupervisorClient(projectState); err == nil {
		info, infoErr := client.info(ctx)
		if infoErr == nil {
			return client, info, nil
		}
		client.close()
		return nil, supervisorInfo{}, infoErr
	} else if errors.Is(err, errStaleSupervisor) {
		if err := a.cleanupOrphans(ctx); err != nil {
			return nil, supervisorInfo{}, err
		}
		if err := removeStaleSupervisor(projectState); err != nil {
			return nil, supervisorInfo{}, err
		}
	} else if !errors.Is(err, errNoSupervisor) {
		return nil, supervisorInfo{}, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, supervisorInfo{}, err
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return nil, supervisorInfo{}, err
	}
	logFile, err := openSupervisorLog(filepath.Join(projectState, "supervisor-startup.log"))
	if err != nil {
		return nil, supervisorInfo{}, err
	}
	command := exec.Command(executable, "_supervisor", "--dir", projectRoot)
	command.Env = os.Environ()
	command.Stdin = nil
	command.Stdout = logFile
	command.Stderr = logFile
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		logFile.Close()
		return nil, supervisorInfo{}, err
	}
	_ = logFile.Close()
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	startup, cancel := context.WithTimeout(ctx, 35*time.Minute)
	defer cancel()
	for {
		select {
		case waitErr := <-done:
			return nil, supervisorInfo{}, errors.Join(fmt.Errorf("Project supervisor exited during startup: %s", readSupervisorLog(projectState)), waitErr)
		case <-startup.Done():
			_ = command.Process.Signal(syscall.SIGTERM)
			return nil, supervisorInfo{}, fmt.Errorf("Project supervisor startup did not complete: %w", startup.Err())
		case <-ticker.C:
			client, err := openSupervisorClient(projectState)
			if err != nil {
				continue
			}
			info, err := client.info(startup)
			if err == nil {
				return client, info, nil
			}
			client.close()
		}
	}
}

func removeStaleSupervisor(projectState string) error {
	locatorPath := filepath.Join(projectState, approvalControlLocator)
	data, err := readOwnedPrivateFile(locatorPath, 4096)
	if err != nil {
		return err
	}
	var locator approvalLocator
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&locator) != nil || decoder.Decode(&struct{}{}) != io.EOF || locator.Version != 1 || filepath.Base(locator.Socket) != approvalControlSocket || !filepath.IsAbs(locator.Socket) || filepath.Clean(locator.Socket) != locator.Socket {
		return fmt.Errorf("stale supervisor locator is unsafe")
	}
	if _, err := os.Lstat(locator.Socket); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("refusing to recover a supervisor whose control socket still exists")
	}
	runtimeBase := filepath.Dir(locator.Socket)
	if !strings.HasPrefix(filepath.Base(runtimeBase), "sunaba-runtime-") || verifyPrivateDirectory(runtimeBase) != nil {
		return fmt.Errorf("stale supervisor runtime directory is unsafe")
	}
	if err := os.Remove(locatorPath); err != nil {
		return err
	}
	return os.RemoveAll(runtimeBase)
}

func (a *app) recoverStaleSupervisor(ctx context.Context, projectState string) error {
	if err := a.cleanupOrphans(ctx); err != nil {
		return err
	}
	return removeStaleSupervisor(projectState)
}

func waitSupervisorGone(ctx context.Context, projectState string) error {
	locator := filepath.Join(projectState, approvalControlLocator)
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Lstat(locator); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("supervisor did not release its control locator: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func openSupervisorLog(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0600 || stat.Uid != uint32(os.Geteuid()) {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("supervisor startup log is unsafe")
	}
	return os.NewFile(uintptr(fd), path), nil
}

func readSupervisorLog(projectState string) string {
	data, err := readOwnedPrivateFile(filepath.Join(projectState, "supervisor-startup.log"), 1<<20)
	if err != nil {
		return "no bounded startup diagnostics"
	}
	return trustedui.SanitizeTerminal(string(data))
}
