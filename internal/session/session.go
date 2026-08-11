package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sunaba/internal/attachrelay"
	"sunaba/internal/dependency"
	"sunaba/internal/opencode"
	"sunaba/internal/runtime"
	"sunaba/internal/state"
	"sunaba/internal/workspace"
)

var sessionIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{5,63}$`)
var secretPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{32,256}$`)

type Event struct {
	Type      string
	ProjectID string
	SessionID string
	Detail    string
	At        time.Time
}

type Config struct {
	Store            *state.Store
	Runtime          runtime.Runtime
	ProjectRoot      string
	RuntimeBase      string
	SessionID        string
	Image            string
	CPUs             int
	Memory           string
	GuestRelayBinary string
	ProviderConfig   []byte
	ModelGateway     http.Handler
	ModelToken       string
	ServerPassword   string
	OnEvent          func(Event)
}

type Session struct {
	ProjectID     string
	ProjectRoot   string
	SessionID     string
	Root          string
	Container     string
	WorkspacePath string
	AttachURL     string
	Baseline      workspace.SnapshotManifest
	SnapshotRoot  string

	cfg           Config
	projectLock   *state.ProjectLock
	gatewayServer *http.Server
	gatewayDone   chan error
	gatewayActive atomic.Bool
	attachCancel  context.CancelFunc
	attachDone    <-chan error
	vmCreated     bool
	paused        bool
	closeOnce     sync.Once
	closeErr      error
}

type ExportResult struct {
	Archive    string
	MergedRoot string
	Merged     workspace.SnapshotManifest
	ChangeSet  workspace.ChangeSet
}

func Start(ctx context.Context, cfg Config) (_ *Session, err error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	projectLock, err := cfg.Store.AcquireProjectLock(cfg.ProjectRoot)
	if err != nil {
		return nil, err
	}
	s := &Session{
		ProjectID: projectLock.ProjectID, ProjectRoot: projectLock.ProjectRoot,
		SessionID: cfg.SessionID, cfg: cfg, projectLock: projectLock,
	}
	defer func() {
		if err != nil {
			if s.vmCreated {
				cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				_ = s.Destroy(cleanup)
			} else {
				_ = s.Close()
			}
			_ = s.removeFailedRoot()
		}
	}()
	s.Root = filepath.Join(cfg.RuntimeBase, "sunaba-session-"+cfg.SessionID)
	s.Container = "sunaba-" + s.ProjectID + "-" + cfg.SessionID
	s.WorkspacePath = "/workspace/sunaba-" + cfg.SessionID
	if err := makeNewPrivateDirectory(s.Root); err != nil {
		return nil, err
	}
	s.SnapshotRoot = filepath.Join(s.Root, "snapshot")
	s.Baseline, err = workspace.CreateProjectSnapshot(s.ProjectRoot, s.SnapshotRoot, workspace.DefaultSnapshotPolicy())
	if err != nil {
		return nil, err
	}
	s.emit("snapshot.created", s.Baseline.Digest)
	if err := s.startGateway(); err != nil {
		return nil, err
	}
	policy := runtime.SecureSessionPolicy{ProjectID: s.ProjectID, SessionID: s.SessionID, Image: cfg.Image, SessionRoot: s.Root}
	policyDigest, err := policy.Digest()
	if err != nil {
		return nil, err
	}
	spec := runtime.ContainerSpec{
		Name: s.Container, Image: cfg.Image, CPUs: cfg.CPUs, Memory: cfg.Memory,
		Networks: []string{"none"}, NoDNS: true, CapAdd: []string{"SYS_ADMIN"},
		Entrypoint: "/bin/bash", Args: []string{"-lc", "exec tail -f /dev/null"},
		Mounts:  []runtime.Mount{{Type: "socket", Source: filepath.Join(s.Root, "model-gateway.sock"), Target: runtime.SecureGatewayGuestPath}},
		Sockets: []runtime.PublishedSocket{{HostPath: filepath.Join(s.Root, "attach.sock"), GuestPath: runtime.SecureAttachGuestPath}},
		Labels: map[string]string{
			"dev.sunaba.owner": "sunaba-supervisor", "dev.sunaba.project": s.ProjectID,
			"dev.sunaba.session": s.SessionID, "dev.sunaba.mode": "secure",
			"dev.sunaba.policy-digest": policyDigest,
		},
	}
	if err := cfg.Runtime.CreateSecure(ctx, spec, policy); err != nil {
		return nil, err
	}
	s.vmCreated = true
	s.emit("vm.created", s.Container)
	if err := s.configureGuest(ctx); err != nil {
		return nil, err
	}
	if err := s.startAttachRelay(ctx); err != nil {
		return nil, err
	}
	health, err := opencode.WaitHealth(ctx, s.AttachURL, cfg.ServerPassword, 60*time.Second)
	if err != nil {
		return nil, err
	}
	if health.Version != dependency.OpenCodeVersion {
		return nil, fmt.Errorf("OpenCode server version %q does not match pinned Host TUI %q", health.Version, dependency.OpenCodeVersion)
	}
	s.emit("session.ready", health.Version)
	return s, nil
}

func validateConfig(cfg Config) error {
	if cfg.Store == nil || cfg.Runtime == nil || !filepath.IsAbs(cfg.Store.Root) {
		return fmt.Errorf("secure session requires an absolute state store and runtime")
	}
	if !filepath.IsAbs(cfg.RuntimeBase) {
		return fmt.Errorf("secure session requires an absolute ephemeral runtime base")
	}
	runtimeBase, err := os.Lstat(cfg.RuntimeBase)
	if err != nil || !runtimeBase.IsDir() || runtimeBase.Mode().Perm() != 0700 {
		return fmt.Errorf("secure session runtime base must be a mode 0700 directory")
	}
	if !sessionIDPattern.MatchString(cfg.SessionID) || cfg.Image != dependency.MustPinned().AgentImage.Tag || cfg.CPUs <= 0 || cfg.Memory == "" {
		return fmt.Errorf("secure session identity, pinned image, and resources are required")
	}
	if !filepath.IsAbs(cfg.GuestRelayBinary) || len(cfg.ProviderConfig) == 0 || !json.Valid(cfg.ProviderConfig) || cfg.ModelGateway == nil {
		return fmt.Errorf("secure session requires the guest relay, provider config, and Model Gateway")
	}
	info, err := os.Lstat(cfg.GuestRelayBinary)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("guest relay must be a regular file")
	}
	if !secretPattern.MatchString(cfg.ModelToken) || !secretPattern.MatchString(cfg.ServerPassword) || cfg.ModelToken == cfg.ServerPassword {
		return fmt.Errorf("session secrets must be distinct high-entropy URL-safe values")
	}
	if cfg.OnEvent == nil {
		return fmt.Errorf("secure session requires a host audit event sink")
	}
	return nil
}

func NewSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (s *Session) startGateway() error {
	path := filepath.Join(s.Root, "model-gateway.sock")
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("Model Gateway path was replaced with a non-socket")
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		return err
	}
	s.gatewayActive.Store(true)
	gatedGateway := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !s.gatewayActive.Load() {
			http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		s.cfg.ModelGateway.ServeHTTP(response, request)
	})
	s.gatewayServer = &http.Server{Handler: gatedGateway, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	done := make(chan error, 1)
	server := s.gatewayServer
	s.gatewayDone = done
	go func() {
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		done <- err
		close(done)
	}()
	s.emit("model_gateway.started", "")
	return nil
}

func (s *Session) Pause(ctx context.Context) error {
	if !s.vmCreated || s.paused {
		return fmt.Errorf("session is not in a resumable running state")
	}
	if err := s.stopAttach(ctx); err != nil {
		return err
	}
	s.gatewayActive.Store(false)
	if err := s.cfg.Runtime.Stop(ctx, s.Container); err != nil {
		return err
	}
	if current, err := s.cfg.Runtime.ContainerState(ctx, s.Container); err != nil || current != runtime.StateStopped {
		return fmt.Errorf("session VM did not stop: state=%s error=%v", current, err)
	}
	s.paused = true
	s.emit("session.paused", "")
	return nil
}

func (s *Session) Resume(ctx context.Context) (err error) {
	if !s.vmCreated || !s.paused {
		return fmt.Errorf("session is not paused")
	}
	if s.gatewayServer == nil {
		return fmt.Errorf("paused session lost its fixed Model Gateway listener")
	}
	s.gatewayActive.Store(true)
	defer func() {
		if err != nil {
			s.gatewayActive.Store(false)
			_ = s.stopAttach(context.Background())
		}
	}()
	if err := s.cfg.Runtime.Start(ctx, s.Container); err != nil {
		return err
	}
	if err := s.resumeGuest(ctx); err != nil {
		return err
	}
	if err := s.startAttachRelay(ctx); err != nil {
		return err
	}
	health, err := opencode.WaitHealth(ctx, s.AttachURL, s.cfg.ServerPassword, 60*time.Second)
	if err != nil {
		return err
	}
	if health.Version != dependency.OpenCodeVersion {
		return fmt.Errorf("resumed OpenCode version %q does not match pinned version", health.Version)
	}
	s.paused = false
	s.emit("session.resumed", health.Version)
	return nil
}

func (s *Session) resumeGuest(ctx context.Context) error {
	resume := strings.Join([]string{
		"set -eu",
		"if ! grep -Fqs ' " + s.WorkspacePath + " ' /proc/mounts; then mount -t overlay overlay -o lowerdir=/var/lib/sunaba/lower,upperdir=/var/lib/sunaba/upper,workdir=/var/lib/sunaba/work " + s.WorkspacePath + "; fi",
		"test -d /var/lib/sunaba/repository",
		"nohup /run/sunaba/guest-relay --tcp-listen 127.0.0.1:4141 --unix-target /run/sunaba/model-gateway.sock >/run/sunaba/model-relay.log 2>&1 &",
		"nohup /run/sunaba/guest-relay --listen /run/sunaba/attach.sock --target 127.0.0.1:4096 >/run/sunaba/attach-relay.log 2>&1 &",
		"nohup /bin/bash -lc 'set -a; . /run/sunaba/session.env; set +a; ulimit -u 512; ulimit -f 2097152; cd " + s.WorkspacePath + "; exec env HOME=/run/sunaba/home XDG_CONFIG_HOME=/run/sunaba/config XDG_DATA_HOME=/run/sunaba/data GIT_DIR=/var/lib/sunaba/repository GIT_WORK_TREE=" + s.WorkspacePath + " OPENCODE_CONFIG=/run/sunaba/opencode.json OPENCODE_DISABLE_AUTOUPDATE=1 OPENCODE_DISABLE_MODELS_FETCH=1 OPENCODE_DISABLE_LSP_DOWNLOAD=1 opencode serve --hostname 127.0.0.1 --port 4096 --mdns=false' >/run/sunaba/server.log 2>&1 &",
	}, "\n")
	if out, err := s.cfg.Runtime.ExecOutput(ctx, s.Container, []string{"/bin/bash", "-lc", resume}); err != nil {
		return fmt.Errorf("resume secure guest services: %w: %s", err, out)
	}
	return nil
}

func (s *Session) configureGuest(ctx context.Context) error {
	if err := s.cfg.Runtime.Exec(ctx, s.Container, false, []string{"mkdir", "-p", "/var/lib/sunaba", "/run/sunaba"}); err != nil {
		return err
	}
	providerPath := filepath.Join(s.Root, "opencode.json")
	if err := os.WriteFile(providerPath, s.cfg.ProviderConfig, 0600); err != nil {
		return err
	}
	envPath := filepath.Join(s.Root, "session.env")
	environment := "OPENCODE_SERVER_PASSWORD=" + s.cfg.ServerPassword + "\nSUNABA_MODEL_GATEWAY_TOKEN=" + s.cfg.ModelToken + "\n"
	if err := os.WriteFile(envPath, []byte(environment), 0600); err != nil {
		return err
	}
	for _, copy := range [][2]string{
		{s.SnapshotRoot, "/var/lib/sunaba/lower"},
		{s.cfg.GuestRelayBinary, "/run/sunaba/guest-relay"},
		{providerPath, "/run/sunaba/opencode.json"},
		{envPath, "/run/sunaba/session.env"},
	} {
		if err := s.cfg.Runtime.CopyTo(ctx, s.Container, copy[0], copy[1]); err != nil {
			return err
		}
	}
	setup := strings.Join([]string{
		"set -eu",
		"chmod 0700 /run/sunaba/guest-relay",
		"chmod 0600 /run/sunaba/session.env /run/sunaba/opencode.json",
		"mkdir -p /var/lib/sunaba/upper /var/lib/sunaba/work " + s.WorkspacePath + " /run/sunaba/home /run/sunaba/config /run/sunaba/data",
		"mount -t overlay overlay -o lowerdir=/var/lib/sunaba/lower,upperdir=/var/lib/sunaba/upper,workdir=/var/lib/sunaba/work " + s.WorkspacePath,
		"cd " + s.WorkspacePath,
		"git init -q --bare /var/lib/sunaba/repository",
		"git --git-dir=/var/lib/sunaba/repository --work-tree=" + s.WorkspacePath + " config user.name sunaba-baseline",
		"git --git-dir=/var/lib/sunaba/repository --work-tree=" + s.WorkspacePath + " config user.email sunaba@localhost",
		"git --git-dir=/var/lib/sunaba/repository --work-tree=" + s.WorkspacePath + " config core.hooksPath /dev/null",
		"git --git-dir=/var/lib/sunaba/repository --work-tree=" + s.WorkspacePath + " add -A && git --git-dir=/var/lib/sunaba/repository --work-tree=" + s.WorkspacePath + " commit -qm 'sunaba synthetic baseline' --no-verify || true",
		"nohup /run/sunaba/guest-relay --tcp-listen 127.0.0.1:4141 --unix-target /run/sunaba/model-gateway.sock >/run/sunaba/model-relay.log 2>&1 &",
		"nohup /run/sunaba/guest-relay --listen /run/sunaba/attach.sock --target 127.0.0.1:4096 >/run/sunaba/attach-relay.log 2>&1 &",
		"nohup /bin/bash -lc 'set -a; . /run/sunaba/session.env; set +a; ulimit -u 512; ulimit -f 2097152; cd " + s.WorkspacePath + "; exec env HOME=/run/sunaba/home XDG_CONFIG_HOME=/run/sunaba/config XDG_DATA_HOME=/run/sunaba/data GIT_DIR=/var/lib/sunaba/repository GIT_WORK_TREE=" + s.WorkspacePath + " OPENCODE_CONFIG=/run/sunaba/opencode.json OPENCODE_DISABLE_AUTOUPDATE=1 OPENCODE_DISABLE_MODELS_FETCH=1 OPENCODE_DISABLE_LSP_DOWNLOAD=1 opencode serve --hostname 127.0.0.1 --port 4096 --mdns=false' >/run/sunaba/server.log 2>&1 &",
	}, "\n")
	if out, err := s.cfg.Runtime.ExecOutput(ctx, s.Container, []string{"/bin/bash", "-lc", setup}); err != nil {
		return fmt.Errorf("configure secure guest: %w: %s", err, out)
	}
	return nil
}

func (s *Session) startAttachRelay(ctx context.Context) error {
	socket := filepath.Join(s.Root, "attach.sock")
	deadline := time.Now().Add(15 * time.Second)
	for {
		if info, err := os.Lstat(socket); err == nil && info.Mode()&os.ModeSocket != 0 {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("secure attach socket did not appear")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	relayCtx, cancel := context.WithCancel(ctx)
	url, done, err := (attachrelay.Relay{UnixSocketPath: socket, Username: "opencode", Password: s.cfg.ServerPassword}).ListenAndServe(relayCtx)
	if err != nil {
		cancel()
		return err
	}
	s.attachCancel, s.attachDone, s.AttachURL = cancel, done, url
	s.emit("attach_relay.started", url)
	return nil
}

func (s *Session) StopAndExport(ctx context.Context) (ExportResult, error) {
	if err := s.stopChannels(ctx); err != nil {
		return ExportResult{}, err
	}
	containerState, err := s.cfg.Runtime.ContainerState(ctx, s.Container)
	if err != nil {
		return ExportResult{}, err
	}
	if containerState == runtime.StateRunning {
		if err := s.cfg.Runtime.Stop(ctx, s.Container); err != nil {
			return ExportResult{}, err
		}
	}
	s.paused = true
	if stopped, err := s.cfg.Runtime.ContainerState(ctx, s.Container); err != nil || stopped != runtime.StateStopped {
		return ExportResult{}, fmt.Errorf("VM is not frozen: state=%s error=%v", stopped, err)
	}
	quarantine := filepath.Join(s.Root, "sunaba-quarantine-"+s.SessionID)
	if err := makeNewPrivateDirectory(quarantine); err != nil {
		return ExportResult{}, err
	}
	archive := filepath.Join(quarantine, "rootfs.tar")
	if err := s.cfg.Runtime.Export(ctx, s.Container, archive); err != nil {
		return ExportResult{}, err
	}
	frozen, err := workspace.ParseFrozenRootFS(archive, quarantine, s.Baseline, workspace.DefaultExportPolicy())
	if err != nil {
		return ExportResult{}, err
	}
	defer frozen.Close()
	mergedRoot := filepath.Join(quarantine, "sunaba-merged-"+s.SessionID)
	merged, err := workspace.MaterializeMergedView(s.SnapshotRoot, mergedRoot, s.Baseline, frozen, workspace.DefaultSnapshotPolicy())
	if err != nil {
		return ExportResult{}, err
	}
	current, err := workspace.BuildSnapshotManifest(s.ProjectRoot, workspace.DefaultSnapshotPolicy())
	if err != nil || current.Digest != s.Baseline.Digest {
		return ExportResult{}, fmt.Errorf("host Project baseline changed during session")
	}
	changeSet, err := workspace.BuildChangeSet(s.Baseline, merged.Manifest, workspace.DefaultSnapshotPolicy())
	if err != nil {
		return ExportResult{}, err
	}
	s.emit("changeset.created", changeSet.Digest)
	return ExportResult{Archive: archive, MergedRoot: merged.Root, Merged: merged.Manifest, ChangeSet: changeSet}, nil
}

func (s *Session) Destroy(ctx context.Context) error {
	if err := s.stopChannels(ctx); err != nil {
		return err
	}
	info, err := s.cfg.Runtime.Inspect(ctx, s.Container)
	if err == nil {
		if info.Labels["dev.sunaba.owner"] != "sunaba-supervisor" || info.Labels["dev.sunaba.project"] != s.ProjectID || info.Labels["dev.sunaba.session"] != s.SessionID {
			return fmt.Errorf("refusing to remove container without matching ownership labels")
		}
		if info.State == runtime.StateRunning {
			if err := s.cfg.Runtime.Stop(ctx, s.Container); err != nil {
				return err
			}
		}
		if err := s.cfg.Runtime.Remove(ctx, s.Container); err != nil {
			return err
		}
		s.vmCreated = false
		s.paused = false
	} else if current, stateErr := s.cfg.Runtime.ContainerState(ctx, s.Container); stateErr != nil || current != runtime.StateNotFound {
		return fmt.Errorf("inspect owned container before removal: %w", err)
	}
	s.emit("vm.destroyed", s.Container)
	return s.Close()
}

func (s *Session) stopChannels(ctx context.Context) error {
	if err := s.stopAttach(ctx); err != nil {
		return err
	}
	s.gatewayActive.Store(false)
	if s.gatewayServer != nil {
		shutdown, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := s.gatewayServer.Shutdown(shutdown)
		cancel()
		if err != nil {
			return err
		}
		if s.gatewayDone != nil {
			if err := <-s.gatewayDone; err != nil {
				return err
			}
		}
		s.gatewayServer, s.gatewayDone = nil, nil
		s.emit("model_gateway.stopped", "")
	}
	return nil
}

func (s *Session) stopAttach(ctx context.Context) error {
	if s.attachCancel != nil {
		s.attachCancel()
		if s.attachDone != nil {
			select {
			case err := <-s.attachDone:
				if err != nil {
					return err
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		s.attachCancel, s.attachDone = nil, nil
		s.emit("attach_relay.stopped", "")
	}
	return nil
}

func (s *Session) Close() error {
	if s.vmCreated {
		return fmt.Errorf("refusing to release Project lock while the session VM still exists; call Destroy")
	}
	s.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.stopChannels(ctx); err != nil {
			s.closeErr = err
		}
		for _, secret := range []string{"session.env"} {
			if err := os.Remove(filepath.Join(s.Root, secret)); err != nil && !errors.Is(err, os.ErrNotExist) && s.closeErr == nil {
				s.closeErr = err
			}
		}
		if s.projectLock != nil {
			if err := s.projectLock.Close(); err != nil && s.closeErr == nil {
				s.closeErr = err
			}
		}
	})
	return s.closeErr
}

func (s *Session) emit(eventType, detail string) {
	if s.cfg.OnEvent != nil {
		s.cfg.OnEvent(Event{Type: eventType, ProjectID: s.ProjectID, SessionID: s.SessionID, Detail: detail, At: time.Now().UTC()})
	}
}

func makeNewPrivateDirectory(path string) error {
	if !filepath.IsAbs(path) || !strings.HasPrefix(filepath.Base(path), "sunaba-") {
		return fmt.Errorf("session transaction directory must be an absolute unused sunaba-* path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("session transaction directory must be mode 0700")
	}
	return nil
}

func (s *Session) removeFailedRoot() error {
	if s.Root == "" || filepath.Dir(s.Root) != s.cfg.RuntimeBase || filepath.Base(s.Root) != "sunaba-session-"+s.SessionID {
		return fmt.Errorf("refusing to remove unowned failed session root")
	}
	info, err := os.Lstat(s.Root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to remove unsafe failed session root")
	}
	return os.RemoveAll(s.Root)
}
