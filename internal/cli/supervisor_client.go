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

	"sunaba/internal/audit"
	"sunaba/internal/cleanup"
	"sunaba/internal/lease"
	"sunaba/internal/recovery"
	"sunaba/internal/trustedui"
	"sunaba/internal/unixsocket"
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
	if decoder.Decode(&locator) != nil || decoder.Decode(&struct{}{}) != io.EOF || locator.Version != 1 || filepath.Base(locator.Socket) != approvalControlSocket || unixsocket.ValidatePath(locator.Socket) != nil || verifyPrivateDirectory(filepath.Dir(locator.Socket)) != nil {
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
	probe, err := net.DialTimeout("unix", locator.Socket, 250*time.Millisecond)
	if err != nil {
		return nil, errStaleSupervisor
	}
	_ = probe.Close()
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
	if operation == "export" {
		return c.export(ctx, false)
	}
	response, err := c.request(ctx, http.MethodPost, "/v1/session/"+operation, http.NoBody)
	if err != nil {
		return err
	}
	return response.Body.Close()
}

func (c *supervisorClient) export(ctx context.Context, discardExternalGit bool) error {
	encoded, err := json.Marshal(exportRequest{DiscardExternalGit: discardExternalGit})
	if err != nil {
		return err
	}
	response, err := c.request(ctx, http.MethodPost, "/v1/session/export", bytes.NewReader(encoded))
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
		if retained, recoveryErr := recovery.Load(projectState); recoveryErr == nil {
			return nil, supervisorInfo{}, fmt.Errorf("stopped %s VM requires recovery before Supervisor restart", retained.RuntimeMode())
		} else if _, statErr := os.Lstat(recovery.Path(projectState)); statErr == nil || !errors.Is(statErr, os.ErrNotExist) {
			return nil, supervisorInfo{}, fmt.Errorf("export recovery metadata is unsafe: %w", recoveryErr)
		}
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
	return removeStaleSupervisorWithPreserve(projectState, false)
}

func removeRecoverySupervisorLocator(projectState string) error {
	if _, err := os.Lstat(filepath.Join(projectState, approvalControlLocator)); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return removeStaleSupervisorWithPreserve(projectState, true)
}

func removeStaleSupervisorWithPreserve(projectState string, preserveRuntime bool) error {
	locatorPath, runtimeBase, _, err := staleSupervisorPaths(projectState)
	if err != nil {
		return err
	}
	if err := os.Remove(locatorPath); err != nil {
		return err
	}
	if preserveRuntime {
		return nil
	}
	return os.RemoveAll(runtimeBase)
}

func staleSupervisorPaths(projectState string) (locatorPath, runtimeBase, vmID string, _ error) {
	locatorPath = filepath.Join(projectState, approvalControlLocator)
	data, err := readOwnedPrivateFile(locatorPath, 4096)
	if err != nil {
		return "", "", "", err
	}
	var locator approvalLocator
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&locator) != nil || decoder.Decode(&struct{}{}) != io.EOF || locator.Version != 1 || filepath.Base(locator.Socket) != approvalControlSocket || !filepath.IsAbs(locator.Socket) || filepath.Clean(locator.Socket) != locator.Socket {
		return "", "", "", fmt.Errorf("stale supervisor locator is unsafe")
	}
	if info, socketErr := os.Lstat(locator.Socket); socketErr == nil {
		var stat unix.Stat_t
		if unix.Lstat(locator.Socket, &stat) != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 || stat.Uid != uint32(os.Geteuid()) {
			return "", "", "", fmt.Errorf("stale supervisor socket is unsafe")
		}
		probe, dialErr := net.DialTimeout("unix", locator.Socket, 250*time.Millisecond)
		if dialErr == nil {
			_ = probe.Close()
			return "", "", "", fmt.Errorf("refusing to recover a supervisor whose control socket is still active")
		}
	} else if !errors.Is(socketErr, os.ErrNotExist) {
		return "", "", "", socketErr
	}
	runtimeBase = filepath.Dir(locator.Socket)
	projectID := filepath.Base(projectState)
	baseName := filepath.Base(runtimeBase)
	type runtimeCandidate struct {
		prefix   string
		expected func(string) string
	}
	candidates := []runtimeCandidate{
		{prefix: "sunaba-d-", expected: func(candidate string) string { return recovery.RuntimeBase(projectState, candidate) }},
		{prefix: "dev-recovery-", expected: func(candidate string) string { return recovery.LegacyRuntimeBase(projectState, candidate) }},
		{prefix: "sunaba-s-", expected: func(candidate string) string { return recovery.SecureRuntimeBase(projectID, candidate) }},
		{prefix: "sunaba-recovery-" + projectID + "-", expected: func(candidate string) string { return recovery.LegacySecureRuntimeBase(projectID, candidate) }},
	}
	expected := ""
	for _, candidate := range candidates {
		if !strings.HasPrefix(baseName, candidate.prefix) {
			continue
		}
		vmID = strings.TrimPrefix(baseName, candidate.prefix)
		expected = candidate.expected(vmID)
		break
	}
	if vmID == "" || expected == "" || runtimeBase != expected || verifyPrivateDirectory(runtimeBase) != nil {
		return "", "", "", fmt.Errorf("stale supervisor runtime directory is unsafe")
	}
	return locatorPath, runtimeBase, vmID, nil
}

func (a *app) recoverStaleSupervisor(ctx context.Context, projectState string) error {
	_, _, vmID, err := staleSupervisorPaths(projectState)
	if err != nil {
		return err
	}
	recorder, err := audit.NewRecorder(filepath.Join(a.store.Root, "audit"))
	if err != nil {
		return err
	}
	result, err := cleanup.Run(ctx, cleanup.Config{Store: a.store, Runtime: a.runtime, Audit: recorder})
	if err != nil {
		return err
	}
	projectID := filepath.Base(projectState)
	expectedContainer := "sunaba-" + projectID + "-" + vmID
	for _, kept := range result.Kept {
		if kept != expectedContainer {
			continue
		}
		guard, guardErr := (&lease.Registry{Root: filepath.Join(a.store.Root, "leases")}).AcquireGuard(vmID)
		if errors.Is(guardErr, lease.ErrGuardHeld) {
			return fmt.Errorf("refusing stale Supervisor recovery while the exact VM still has a live owner")
		}
		if guardErr != nil {
			return guardErr
		}
		_ = guard.Close()
	}
	for _, refused := range result.Refused {
		if refused != expectedContainer {
			return fmt.Errorf("refused to mutate unrelated resource while recovering stale Supervisor: %s", refused)
		}
	}
	preserveRuntime := false
	items, err := a.runtime.List(ctx)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.Labels["dev.sunaba.owner"] == "sunaba-supervisor" && item.Labels["dev.sunaba.project"] == projectID && item.Labels["dev.sunaba.vm"] == vmID {
			preserveRuntime = true
			break
		}
	}
	return removeStaleSupervisorWithPreserve(projectState, preserveRuntime)
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
