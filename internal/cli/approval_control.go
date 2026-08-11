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
	"time"

	"golang.org/x/sys/unix"

	"sunaba/internal/gitgateway"
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

func startApprovalControl(projectState, runtimeBase string, broker pushApprovalBroker) (*approvalControl, error) {
	if broker == nil {
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
		_ = json.NewEncoder(response).Encode(broker.Pending())
	})
	mux.HandleFunc("POST /v1/push/confirm", func(response http.ResponseWriter, request *http.Request) {
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
