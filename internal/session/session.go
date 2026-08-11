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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sunaba/internal/approval"
	"sunaba/internal/attachrelay"
	"sunaba/internal/audit"
	"sunaba/internal/dependency"
	"sunaba/internal/lease"
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
	DiskBytes        int64
	ProcessMax       int64
	FileSizeMax      int64
	OpenFileMax      int64
	GuestRelayBinary string
	ProviderConfig   []byte
	ModelGateway     http.Handler
	ModelToken       string
	GitGateway       http.Handler
	GitToken         string
	GitGatewayClose  func() error
	WebGateway       http.Handler
	WebToken         string
	WebGatewayClose  func() error
	ServerPassword   string
	LeaseTTL         time.Duration
	Audit            *audit.Recorder
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

	cfg              Config
	projectLock      *state.ProjectLock
	leaseRegistry    *lease.Registry
	leaseGuard       *lease.Guard
	leaseCreated     bool
	gatewayServer    *http.Server
	gatewayDone      chan error
	gitGatewayServer *http.Server
	gitGatewayDone   chan error
	webGatewayServer *http.Server
	webGatewayDone   chan error
	gatewayActive    atomic.Bool
	attachCancel     context.CancelFunc
	attachDone       <-chan error
	vmCreated        bool
	paused           bool
	closeOnce        sync.Once
	gitCloseOnce     sync.Once
	webCloseOnce     sync.Once
	closeErr         error
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
	s.leaseRegistry = &lease.Registry{Root: filepath.Join(cfg.Store.Root, "leases")}
	if _, err := s.leaseRegistry.RegisterPaused(s.ProjectID, s.Container, s.SessionID, "model", cfg.LeaseTTL); err != nil {
		return nil, err
	}
	s.leaseCreated = true
	s.leaseGuard, err = s.leaseRegistry.AcquireGuard(s.SessionID)
	if err != nil {
		return nil, err
	}
	if err := s.emit("capability.issued", "paused"); err != nil {
		return nil, err
	}
	if err := makeNewPrivateDirectory(s.Root); err != nil {
		return nil, err
	}
	s.SnapshotRoot = filepath.Join(s.Root, "snapshot")
	s.Baseline, err = workspace.CreateProjectSnapshot(s.ProjectRoot, s.SnapshotRoot, workspace.DefaultSnapshotPolicy())
	if err != nil {
		return nil, err
	}
	if err := s.emit("snapshot.created", s.Baseline.Digest); err != nil {
		return nil, err
	}
	if err := s.startGateway(); err != nil {
		return nil, err
	}
	policy := runtime.SecureSessionPolicy{
		ProjectID: s.ProjectID, SessionID: s.SessionID, Image: cfg.Image, SessionRoot: s.Root,
		CPUs: cfg.CPUs, Memory: cfg.Memory, DiskBytes: cfg.DiskBytes,
		ProcessMax: cfg.ProcessMax, FileSizeMax: cfg.FileSizeMax, OpenFileMax: cfg.OpenFileMax,
		GitGateway: cfg.GitGateway != nil, WebGateway: cfg.WebGateway != nil,
	}
	policyDigest, err := policy.Digest()
	if err != nil {
		return nil, err
	}
	mounts := []runtime.Mount{{Type: "socket", Source: filepath.Join(s.Root, "model-gateway.sock"), Target: runtime.SecureGatewayGuestPath}}
	if cfg.GitGateway != nil {
		mounts = append(mounts, runtime.Mount{Type: "socket", Source: filepath.Join(s.Root, "git-gateway.sock"), Target: runtime.SecureGitGatewayGuestPath})
	}
	if cfg.WebGateway != nil {
		mounts = append(mounts, runtime.Mount{Type: "socket", Source: filepath.Join(s.Root, "web-gateway.sock"), Target: runtime.SecureWebGatewayGuestPath})
	}
	spec := runtime.ContainerSpec{
		Name: s.Container, Image: cfg.Image, CPUs: cfg.CPUs, Memory: cfg.Memory,
		Ulimits: map[string]runtime.RLimit{
			"nproc":  {Soft: cfg.ProcessMax, Hard: cfg.ProcessMax},
			"fsize":  {Soft: cfg.FileSizeMax, Hard: cfg.FileSizeMax},
			"nofile": {Soft: cfg.OpenFileMax, Hard: cfg.OpenFileMax},
		},
		Networks: []string{"none"}, NoDNS: true, CapAdd: []string{"SYS_ADMIN"},
		Entrypoint: "/bin/bash", Args: []string{"-lc", "exec tail -f /dev/null"},
		Mounts:  mounts,
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
	if err := s.emit("vm.created", s.Container); err != nil {
		return nil, err
	}
	if err := s.configureGuest(ctx); err != nil {
		return nil, err
	}
	if err := s.startAttachRelay(ctx); err != nil {
		return nil, err
	}
	health, err := opencode.WaitHealth(ctx, s.AttachURL, cfg.ServerPassword, 60*time.Second)
	if err != nil {
		serverLog, _ := cfg.Runtime.ExecOutput(ctx, s.Container, []string{"/bin/bash", "-lc", "tail -n 80 /run/sunaba/server.log 2>/dev/null || true"})
		return nil, fmt.Errorf("%w; guest server log: %s", err, approval.SanitizeText(serverLog))
	}
	if health.Version != dependency.OpenCodeVersion {
		return nil, fmt.Errorf("OpenCode server version %q does not match pinned Host TUI %q", health.Version, dependency.OpenCodeVersion)
	}
	if err := s.verifyGuestResources(ctx); err != nil {
		return nil, err
	}
	if _, err := s.leaseRegistry.Activate(s.SessionID); err != nil {
		return nil, err
	}
	if err := s.emit("capability.activated", "model"); err != nil {
		return nil, err
	}
	if cfg.GitGateway != nil {
		if err := s.emit("capability.activated", "git"); err != nil {
			return nil, err
		}
	}
	if cfg.WebGateway != nil {
		if err := s.emit("capability.activated", "web"); err != nil {
			return nil, err
		}
	}
	if err := s.emit("session.ready", health.Version); err != nil {
		return nil, err
	}
	s.gatewayActive.Store(true)
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
	if _, err := parseMemoryBytes(cfg.Memory); err != nil {
		return err
	}
	if cfg.DiskBytes < 64<<20 || cfg.DiskBytes > 8<<30 || cfg.ProcessMax < 16 || cfg.ProcessMax > 4096 || cfg.FileSizeMax != cfg.DiskBytes || cfg.OpenFileMax < 256 || cfg.OpenFileMax > 1<<20 {
		return fmt.Errorf("secure session disk, process, file size, and open-file limits are invalid")
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
	if (cfg.GitGateway == nil) != (cfg.GitToken == "") || (cfg.GitGateway == nil) != (cfg.GitGatewayClose == nil) || (cfg.GitGateway != nil && (!secretPattern.MatchString(cfg.GitToken) || cfg.GitToken == cfg.ModelToken || cfg.GitToken == cfg.ServerPassword)) {
		return fmt.Errorf("optional Git Gateway requires a distinct high-entropy capability")
	}
	if (cfg.WebGateway == nil) != (cfg.WebToken == "") || (cfg.WebGateway == nil) != (cfg.WebGatewayClose == nil) || (cfg.WebGateway != nil && (!secretPattern.MatchString(cfg.WebToken) || cfg.WebToken == cfg.ModelToken || cfg.WebToken == cfg.ServerPassword || cfg.WebToken == cfg.GitToken)) {
		return fmt.Errorf("optional Web Gateway requires a distinct high-entropy capability")
	}
	if cfg.Audit == nil || filepath.Clean(cfg.Audit.Root) != filepath.Join(filepath.Clean(cfg.Store.Root), "audit") {
		return fmt.Errorf("secure session requires its host audit recorder under the state store")
	}
	if cfg.LeaseTTL <= 0 || cfg.LeaseTTL > 24*time.Hour {
		return fmt.Errorf("secure session requires a bounded lease lifetime")
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
	server, done, err := s.startUnixGateway("model-gateway.sock", s.cfg.ModelGateway)
	if err != nil {
		return err
	}
	s.gatewayServer, s.gatewayDone = server, done
	if err := s.emit("model_gateway.started", ""); err != nil {
		return err
	}
	if s.cfg.GitGateway != nil {
		server, done, err = s.startUnixGateway("git-gateway.sock", s.cfg.GitGateway)
		if err != nil {
			return err
		}
		s.gitGatewayServer, s.gitGatewayDone = server, done
		if err := s.emit("git_gateway.started", ""); err != nil {
			return err
		}
	}
	if s.cfg.WebGateway != nil {
		server, done, err = s.startUnixGateway("web-gateway.sock", s.cfg.WebGateway)
		if err != nil {
			return err
		}
		s.webGatewayServer, s.webGatewayDone = server, done
		if err := s.emit("web_gateway.started", ""); err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) startUnixGateway(name string, handler http.Handler) (*http.Server, chan error, error) {
	path := filepath.Join(s.Root, name)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, nil, fmt.Errorf("Gateway path was replaced with a non-socket")
		}
		if err := os.Remove(path); err != nil {
			return nil, nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, nil, err
	}
	s.gatewayActive.Store(false)
	gatedGateway := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !s.gatewayActive.Load() || s.leaseRegistry.ValidateActive(s.ProjectID, s.Container, s.SessionID, "model") != nil {
			http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(response, request)
	})
	server := &http.Server{Handler: gatedGateway, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	done := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		done <- err
		close(done)
	}()
	return server, done, nil
}

func (s *Session) Pause(ctx context.Context) error {
	if !s.vmCreated || s.paused {
		return fmt.Errorf("session is not in a resumable running state")
	}
	var pauseErr error
	pauseErr = errors.Join(pauseErr, s.stopAttach(ctx))
	s.gatewayActive.Store(false)
	if _, err := s.leaseRegistry.Pause(s.SessionID); err != nil {
		return errors.Join(pauseErr, err)
	}
	s.paused = true
	if err := s.emit("capability.paused", "model"); err != nil {
		pauseErr = errors.Join(pauseErr, err)
	}
	if s.cfg.GitGateway != nil {
		if err := s.emit("capability.paused", "git"); err != nil {
			pauseErr = errors.Join(pauseErr, err)
		}
	}
	if s.cfg.WebGateway != nil {
		if err := s.emit("capability.paused", "web"); err != nil {
			pauseErr = errors.Join(pauseErr, err)
		}
	}
	if err := s.cfg.Runtime.Stop(ctx, s.Container); err != nil {
		return errors.Join(pauseErr, err)
	}
	if current, err := s.cfg.Runtime.ContainerState(ctx, s.Container); err != nil || current != runtime.StateStopped {
		return errors.Join(pauseErr, fmt.Errorf("session VM did not stop: state=%s error=%v", current, err))
	}
	return errors.Join(pauseErr, s.emit("session.paused", ""))
}

func (s *Session) Resume(ctx context.Context) (err error) {
	if !s.vmCreated || !s.paused {
		return fmt.Errorf("session is not paused")
	}
	if s.gatewayServer == nil {
		return fmt.Errorf("paused session lost its fixed Model Gateway listener")
	}
	s.gatewayActive.Store(false)
	leaseActivated := false
	defer func() {
		if err != nil {
			s.gatewayActive.Store(false)
			if leaseActivated {
				_, _ = s.leaseRegistry.Pause(s.SessionID)
			}
			_ = s.stopAttach(context.Background())
		}
	}()
	current, stateErr := s.cfg.Runtime.ContainerState(ctx, s.Container)
	if stateErr != nil {
		return stateErr
	}
	if current == runtime.StateStopped {
		if err := s.cfg.Runtime.Start(ctx, s.Container); err != nil {
			return err
		}
	} else if current != runtime.StateRunning {
		return fmt.Errorf("paused session VM is not resumable: state=%s", current)
	}
	if err := s.resumeGuest(ctx); err != nil {
		return err
	}
	if err := s.startAttachRelay(ctx); err != nil {
		return err
	}
	health, err := opencode.WaitHealth(ctx, s.AttachURL, s.cfg.ServerPassword, 60*time.Second)
	if err != nil {
		serverLog, _ := s.cfg.Runtime.ExecOutput(ctx, s.Container, []string{"/bin/bash", "-lc", "tail -n 80 /run/sunaba/server.log 2>/dev/null || true"})
		return fmt.Errorf("%w; guest server log: %s", err, approval.SanitizeText(serverLog))
	}
	if health.Version != dependency.OpenCodeVersion {
		return fmt.Errorf("resumed OpenCode version %q does not match pinned version", health.Version)
	}
	if err := s.verifyGuestResources(ctx); err != nil {
		return err
	}
	if _, err := s.leaseRegistry.Activate(s.SessionID); err != nil {
		return err
	}
	leaseActivated = true
	if err := s.emit("capability.activated", "model"); err != nil {
		return err
	}
	if s.cfg.GitGateway != nil {
		if err := s.emit("capability.activated", "git"); err != nil {
			return err
		}
	}
	if s.cfg.WebGateway != nil {
		if err := s.emit("capability.activated", "web"); err != nil {
			return err
		}
	}
	if err := s.emit("session.resumed", health.Version); err != nil {
		return err
	}
	s.gatewayActive.Store(true)
	s.paused = false
	leaseActivated = false
	return nil
}

func (s *Session) resumeGuest(ctx context.Context) error {
	commands := []string{
		"set -eu",
		"if ! grep -Fqs ' /var/lib/sunaba/overlay ' /proc/mounts; then mount -o loop,nosuid,nodev /var/lib/sunaba/overlay.img /var/lib/sunaba/overlay; fi",
		"if ! grep -Fqs ' " + s.WorkspacePath + " ' /proc/mounts; then mount -t overlay overlay -o lowerdir=/var/lib/sunaba/lower,upperdir=/var/lib/sunaba/overlay/upper,workdir=/var/lib/sunaba/overlay/work " + s.WorkspacePath + "; fi",
		"test -d /var/lib/sunaba/repository",
		"nohup /run/sunaba/guest-relay --tcp-listen 127.0.0.1:4141 --unix-target /run/sunaba/model-gateway.sock >/run/sunaba/model-relay.log 2>&1 &",
	}
	if s.cfg.GitGateway != nil {
		commands = append(commands, "nohup /run/sunaba/guest-relay --tcp-listen 127.0.0.1:4242 --unix-target /run/sunaba/git-gateway.sock >/run/sunaba/git-relay.log 2>&1 &")
	}
	if s.cfg.WebGateway != nil {
		commands = append(commands, "nohup /run/sunaba/guest-relay --tcp-listen 127.0.0.1:4343 --unix-target /run/sunaba/web-gateway.sock >/run/sunaba/web-relay.log 2>&1 &")
	}
	commands = append(commands,
		"nohup /run/sunaba/guest-relay --listen /run/sunaba/attach.sock --target 127.0.0.1:4096 >/run/sunaba/attach-relay.log 2>&1 &",
		s.guestServerCommand(),
	)
	resume := strings.Join(commands, "\n")
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
	if s.cfg.GitGateway != nil {
		environment += "SUNABA_GIT_GATEWAY_TOKEN=" + s.cfg.GitToken + "\n"
	}
	if s.cfg.WebGateway != nil {
		environment += "SUNABA_WEB_GATEWAY_TOKEN=" + s.cfg.WebToken + "\n"
	}
	if err := os.WriteFile(envPath, []byte(environment), 0600); err != nil {
		return err
	}
	copies := [][2]string{
		{s.SnapshotRoot, "/var/lib/sunaba/lower"},
		{s.cfg.GuestRelayBinary, "/run/sunaba/guest-relay"},
		{providerPath, "/run/sunaba/opencode.json"},
		{envPath, "/run/sunaba/session.env"},
	}
	if s.cfg.WebGateway != nil {
		aptConfigPath := filepath.Join(s.Root, "apt-proxy.conf")
		proxyURL := "http://sunaba:" + s.cfg.WebToken + "@127.0.0.1:4343"
		aptConfig := "Acquire::http::Proxy \"" + proxyURL + "\";\nAcquire::https::Proxy \"" + proxyURL + "\";\nAcquire::Retries \"0\";\n"
		if err := os.WriteFile(aptConfigPath, []byte(aptConfig), 0600); err != nil {
			return err
		}
		copies = append(copies, [2]string{aptConfigPath, "/run/sunaba/apt-proxy.conf"})
	}
	for _, copy := range copies {
		if err := s.cfg.Runtime.CopyTo(ctx, s.Container, copy[0], copy[1]); err != nil {
			return err
		}
	}
	commands := []string{
		"set -eu",
		"chmod 0700 /run/sunaba/guest-relay",
		"getent group sunaba-agent >/dev/null || groupadd -g 1000 sunaba-agent",
		"id sunaba-agent >/dev/null 2>&1 || useradd -u 1000 -g sunaba-agent -M -d /run/sunaba/home -s /bin/bash sunaba-agent",
		"chmod 0400 /run/sunaba/session.env /run/sunaba/opencode.json",
		"chown 1000:1000 /run/sunaba/session.env /run/sunaba/opencode.json",
		"mkdir -p " + s.WorkspacePath + " /run/sunaba/home /run/sunaba/config /run/sunaba/data /var/lib/sunaba/overlay",
		fmt.Sprintf("truncate -s %d /var/lib/sunaba/overlay.img", s.cfg.DiskBytes),
		"mkfs.ext4 -q -F -m 0 /var/lib/sunaba/overlay.img",
		"mount -o loop,nosuid,nodev /var/lib/sunaba/overlay.img /var/lib/sunaba/overlay",
		"mkdir -p /var/lib/sunaba/overlay/upper /var/lib/sunaba/overlay/work /var/lib/sunaba/overlay/repository",
		"ln -s overlay/repository /var/lib/sunaba/repository",
		"chown -R 1000:1000 /var/lib/sunaba/lower /var/lib/sunaba/overlay /run/sunaba/home /run/sunaba/config /run/sunaba/data",
		"mount -t overlay overlay -o lowerdir=/var/lib/sunaba/lower,upperdir=/var/lib/sunaba/overlay/upper,workdir=/var/lib/sunaba/overlay/work " + s.WorkspacePath,
		"cd " + s.WorkspacePath,
		"runuser -u sunaba-agent -- git init -q --bare /var/lib/sunaba/repository",
		"runuser -u sunaba-agent -- git --git-dir=/var/lib/sunaba/repository --work-tree=" + s.WorkspacePath + " config user.name sunaba-baseline",
		"runuser -u sunaba-agent -- git --git-dir=/var/lib/sunaba/repository --work-tree=" + s.WorkspacePath + " config user.email sunaba@localhost",
		"runuser -u sunaba-agent -- git --git-dir=/var/lib/sunaba/repository --work-tree=" + s.WorkspacePath + " config core.hooksPath /dev/null",
		"runuser -u sunaba-agent -- git --git-dir=/var/lib/sunaba/repository --work-tree=" + s.WorkspacePath + " add -A && runuser -u sunaba-agent -- git --git-dir=/var/lib/sunaba/repository --work-tree=" + s.WorkspacePath + " commit -qm 'sunaba synthetic baseline' --no-verify || true",
		"nohup /run/sunaba/guest-relay --tcp-listen 127.0.0.1:4141 --unix-target /run/sunaba/model-gateway.sock >/run/sunaba/model-relay.log 2>&1 &",
	}
	if s.cfg.GitGateway != nil {
		commands = append(commands,
			"runuser -u sunaba-agent -- git --git-dir=/var/lib/sunaba/repository config remote.origin.url http://127.0.0.1:4242/repository.git",
			"nohup /run/sunaba/guest-relay --tcp-listen 127.0.0.1:4242 --unix-target /run/sunaba/git-gateway.sock >/run/sunaba/git-relay.log 2>&1 &",
		)
	}
	if s.cfg.WebGateway != nil {
		commands = append(commands,
			"chmod 0400 /run/sunaba/apt-proxy.conf",
			"chown 1000:1000 /run/sunaba/apt-proxy.conf",
			"nohup /run/sunaba/guest-relay --tcp-listen 127.0.0.1:4343 --unix-target /run/sunaba/web-gateway.sock >/run/sunaba/web-relay.log 2>&1 &",
		)
	}
	commands = append(commands,
		"nohup /run/sunaba/guest-relay --listen /run/sunaba/attach.sock --target 127.0.0.1:4096 >/run/sunaba/attach-relay.log 2>&1 &",
		s.guestServerCommand(),
	)
	setup := strings.Join(commands, "\n")
	if out, err := s.cfg.Runtime.ExecOutput(ctx, s.Container, []string{"/bin/bash", "-lc", setup}); err != nil {
		return fmt.Errorf("configure secure guest: %w: %s", err, out)
	}
	return nil
}

func (s *Session) guestServerCommand() string {
	gitEnvironment := ""
	if s.cfg.GitGateway != nil {
		gitEnvironment = " GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=http.http://127.0.0.1:4242/.extraHeader GIT_CONFIG_VALUE_0=\"Authorization: Bearer $SUNABA_GIT_GATEWAY_TOKEN\""
	}
	webEnvironment := ""
	if s.cfg.WebGateway != nil {
		webEnvironment = " HTTP_PROXY=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343 HTTPS_PROXY=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343 http_proxy=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343 https_proxy=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343 NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost APT_CONFIG=/run/sunaba/apt-proxy.conf"
	}
	return "nohup runuser -u sunaba-agent -- /bin/bash -lc 'set -a; . /run/sunaba/session.env; set +a; cd " + s.WorkspacePath + "; exec env HOME=/run/sunaba/home XDG_CONFIG_HOME=/run/sunaba/config XDG_DATA_HOME=/run/sunaba/data GIT_DIR=/var/lib/sunaba/repository GIT_WORK_TREE=" + s.WorkspacePath + gitEnvironment + webEnvironment + " OPENCODE_CONFIG=/run/sunaba/opencode.json OPENCODE_DISABLE_AUTOUPDATE=1 OPENCODE_DISABLE_MODELS_FETCH=1 OPENCODE_DISABLE_LSP_DOWNLOAD=1 OPENCODE_DISABLE_DEFAULT_PLUGINS=1 opencode serve --hostname 127.0.0.1 --port 4096 --mdns=false' >/run/sunaba/server.log 2>&1 &"
}

func (s *Session) verifyGuestResources(ctx context.Context) error {
	probe := strings.Join([]string{
		"set -eu",
		"pid=$(pgrep -u 1000 -f 'opencode serve' | head -n 1)",
		"test -n \"$pid\"",
		"echo cpu=$(getconf _NPROCESSORS_ONLN)",
		"awk '/MemTotal:/{print \"memory_kb=\" $2}' /proc/meminfo",
		"echo disk=$(df -B1 --output=size /var/lib/sunaba/overlay | tail -n 1 | tr -d ' ')",
		"awk '/^Uid:/{print \"uid=\" $2}' /proc/$pid/status",
		"awk '$1==\"Max\" && $2==\"processes\"{print \"nproc=\" $(NF-1)}' /proc/$pid/limits",
		"awk '$1==\"Max\" && $2==\"file\" && $3==\"size\"{print \"fsize=\" $(NF-2)}' /proc/$pid/limits",
		"awk '$1==\"Max\" && $2==\"open\" && $3==\"files\"{print \"nofile=\" $(NF-1)}' /proc/$pid/limits",
	}, "\n")
	out, err := s.cfg.Runtime.ExecOutput(ctx, s.Container, []string{"/bin/bash", "-lc", probe})
	if err != nil {
		return fmt.Errorf("probe secure guest resources: %w: %s", err, approval.SanitizeText(out))
	}
	values := make(map[string]int64)
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		key, raw, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("invalid guest resource probe output")
		}
		value, parseErr := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if parseErr != nil {
			return fmt.Errorf("invalid guest resource probe value")
		}
		values[key] = value
	}
	memoryBytes, err := parseMemoryBytes(s.cfg.Memory)
	if err != nil {
		return err
	}
	guestMemoryCeiling := memoryBytes + (128 << 20)
	if values["cpu"] < int64(s.cfg.CPUs) || values["cpu"] > int64(s.cfg.CPUs+1) || values["memory_kb"] <= 0 || values["memory_kb"]<<10 > guestMemoryCeiling || values["disk"] <= 0 || values["disk"] > s.cfg.DiskBytes || values["uid"] != 1000 || values["nproc"] != s.cfg.ProcessMax || values["fsize"] != s.cfg.FileSizeMax || values["nofile"] != s.cfg.OpenFileMax {
		return fmt.Errorf("secure guest resource limits do not match host policy: %v", values)
	}
	return s.emit("resource.probe", fmt.Sprintf("cpu=%d,memory=%d,disk=%d,nproc=%d,fsize=%d,nofile=%d", s.cfg.CPUs, memoryBytes, s.cfg.DiskBytes, s.cfg.ProcessMax, s.cfg.FileSizeMax, s.cfg.OpenFileMax))
}

func parseMemoryBytes(value string) (int64, error) {
	match := regexp.MustCompile(`^([1-9][0-9]*)([KMGTP]?)$`).FindStringSubmatch(strings.ToUpper(value))
	if match == nil {
		return 0, fmt.Errorf("invalid memory limit %q", value)
	}
	amount, _ := strconv.ParseInt(match[1], 10, 64)
	if match[2] == "" {
		return amount, nil
	}
	powers := map[string]uint{"K": 10, "M": 20, "G": 30, "T": 40, "P": 50}
	if amount > (1<<62)>>powers[match[2]] {
		return 0, fmt.Errorf("memory limit overflows")
	}
	return amount << powers[match[2]], nil
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
	if err := s.emit("attach_relay.started", url); err != nil {
		cancel()
		return err
	}
	return nil
}

func (s *Session) StopAndExport(ctx context.Context) (ExportResult, error) {
	if err := s.stopChannels(ctx); err != nil {
		return ExportResult{}, err
	}
	if s.leaseCreated {
		if _, err := s.leaseRegistry.Revoke(s.SessionID); err != nil {
			return ExportResult{}, err
		}
		s.leaseCreated = false
		if err := s.emit("capability.revoked", "export"); err != nil {
			return ExportResult{}, err
		}
	}
	containerState, err := s.cfg.Runtime.ContainerState(ctx, s.Container)
	if err != nil {
		return ExportResult{}, err
	}
	if containerState == runtime.StateStopped {
		if err := s.cfg.Runtime.Start(ctx, s.Container); err != nil {
			return ExportResult{}, err
		}
	} else if containerState != runtime.StateRunning {
		return ExportResult{}, fmt.Errorf("session VM cannot be frozen from state %s", containerState)
	}
	if err := s.prepareGuestExport(ctx); err != nil {
		return ExportResult{}, err
	}
	if err := s.cfg.Runtime.Stop(ctx, s.Container); err != nil {
		return ExportResult{}, err
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
	if err := s.emit("changeset.created", changeSet.Digest); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Archive: archive, MergedRoot: merged.Root, Merged: merged.Manifest, ChangeSet: changeSet}, nil
}

func (s *Session) prepareGuestExport(ctx context.Context) error {
	script := strings.Join([]string{
		"set -eu",
		"pkill -TERM -u 1000 -f '.*' 2>/dev/null || true",
		"pkill -TERM guest-relay 2>/dev/null || true",
		"sleep 1",
		"pkill -KILL -u 1000 -f '.*' 2>/dev/null || true",
		"pkill -KILL guest-relay 2>/dev/null || true",
		"rm -f /run/sunaba/session.env /run/sunaba/apt-proxy.conf",
		"rm -rf /var/lib/sunaba/merged-export",
		"mkdir -p /var/lib/sunaba/merged-export",
		"cp -a --preserve=all " + s.WorkspacePath + "/. /var/lib/sunaba/merged-export/",
		"if grep -Fqs ' " + s.WorkspacePath + " ' /proc/mounts; then for attempt in $(seq 1 50); do umount " + s.WorkspacePath + " 2>/dev/null && break; sleep 0.1; done; fi",
		"! grep -Fqs ' " + s.WorkspacePath + " ' /proc/mounts",
		"if ! grep -Fqs ' /var/lib/sunaba/overlay ' /proc/mounts; then mount -o loop,nosuid,nodev /var/lib/sunaba/overlay.img /var/lib/sunaba/overlay; fi",
		"rm -rf /var/lib/sunaba/upper /var/lib/sunaba/work",
		"mkdir -p /var/lib/sunaba/upper /var/lib/sunaba/work",
		"cp -a --preserve=all /var/lib/sunaba/overlay/upper/. /var/lib/sunaba/upper/",
		"sync",
		"umount /var/lib/sunaba/overlay",
		"rm -f /var/lib/sunaba/overlay.img",
	}, "\n")
	if out, err := s.cfg.Runtime.ExecOutput(ctx, s.Container, []string{"/bin/bash", "-lc", script}); err != nil {
		return fmt.Errorf("freeze bounded guest overlay for export: %w: %s", err, out)
	}
	return s.emit("workspace.frozen", "bounded-overlay")
}

func (s *Session) Destroy(ctx context.Context) error {
	var destroyErr error
	if err := s.stopChannels(ctx); err != nil {
		destroyErr = errors.Join(destroyErr, err)
	}
	if s.leaseCreated {
		if _, err := s.leaseRegistry.Revoke(s.SessionID); err != nil {
			destroyErr = errors.Join(destroyErr, err)
		} else {
			s.leaseCreated = false
			if err := s.emit("capability.revoked", "destroy"); err != nil {
				destroyErr = errors.Join(destroyErr, err)
			}
		}
	}
	info, err := s.cfg.Runtime.Inspect(ctx, s.Container)
	if err == nil {
		if info.Labels["dev.sunaba.owner"] != "sunaba-supervisor" || info.Labels["dev.sunaba.project"] != s.ProjectID || info.Labels["dev.sunaba.session"] != s.SessionID {
			return errors.Join(destroyErr, fmt.Errorf("refusing to remove container without matching ownership labels"))
		}
		if info.State == runtime.StateRunning {
			if err := s.cfg.Runtime.Stop(ctx, s.Container); err != nil {
				return errors.Join(destroyErr, err)
			}
		}
		if err := s.cfg.Runtime.Remove(ctx, s.Container); err != nil {
			return errors.Join(destroyErr, err)
		}
		s.vmCreated = false
		s.paused = false
	} else if current, stateErr := s.cfg.Runtime.ContainerState(ctx, s.Container); stateErr != nil || current != runtime.StateNotFound {
		return errors.Join(destroyErr, fmt.Errorf("inspect owned container before removal: %w", err))
	}
	if err := s.emit("vm.destroyed", s.Container); err != nil {
		destroyErr = errors.Join(destroyErr, err)
	}
	return errors.Join(destroyErr, s.Close())
}

func (s *Session) stopChannels(ctx context.Context) error {
	var stopErr error
	stopErr = errors.Join(stopErr, s.stopAttach(ctx))
	s.gatewayActive.Store(false)
	stopErr = errors.Join(stopErr, s.stopUnixGateway(ctx, &s.webGatewayServer, &s.webGatewayDone, "web_gateway.stopped"))
	if s.cfg.WebGatewayClose != nil {
		s.webCloseOnce.Do(func() { stopErr = errors.Join(stopErr, s.cfg.WebGatewayClose()) })
	}
	stopErr = errors.Join(stopErr, s.stopUnixGateway(ctx, &s.gitGatewayServer, &s.gitGatewayDone, "git_gateway.stopped"))
	if s.cfg.GitGatewayClose != nil {
		s.gitCloseOnce.Do(func() { stopErr = errors.Join(stopErr, s.cfg.GitGatewayClose()) })
	}
	stopErr = errors.Join(stopErr, s.stopUnixGateway(ctx, &s.gatewayServer, &s.gatewayDone, "model_gateway.stopped"))
	return stopErr
}

func (s *Session) stopUnixGateway(ctx context.Context, server **http.Server, done *chan error, event string) error {
	if *server == nil {
		return nil
	}
	var stopErr error
	shutdown, cancel := context.WithTimeout(ctx, 3*time.Second)
	stopErr = errors.Join(stopErr, (*server).Shutdown(shutdown))
	cancel()
	if *done != nil {
		stopErr = errors.Join(stopErr, <-*done)
	}
	*server, *done = nil, nil
	return errors.Join(stopErr, s.emit(event, ""))
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
		return s.emit("attach_relay.stopped", "")
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
		for _, secret := range []string{"session.env", "apt-proxy.conf"} {
			if err := os.Remove(filepath.Join(s.Root, secret)); err != nil && !errors.Is(err, os.ErrNotExist) && s.closeErr == nil {
				s.closeErr = err
			}
		}
		if s.leaseCreated && s.leaseRegistry != nil {
			if _, err := s.leaseRegistry.Revoke(s.SessionID); err != nil && s.closeErr == nil {
				s.closeErr = err
			} else if err == nil {
				s.leaseCreated = false
				if auditErr := s.emit("capability.revoked", "close"); auditErr != nil && s.closeErr == nil {
					s.closeErr = auditErr
				}
			}
		}
		if s.leaseGuard != nil {
			if err := s.leaseGuard.Close(); err != nil && s.closeErr == nil {
				s.closeErr = err
			}
			s.leaseGuard = nil
		}
		if s.projectLock != nil {
			if err := s.projectLock.Close(); err != nil && s.closeErr == nil {
				s.closeErr = err
			}
		}
	})
	return s.closeErr
}

func (s *Session) emit(eventType, detail string) error {
	category := strings.SplitN(eventType, ".", 2)[0]
	details := map[string]string(nil)
	if detail != "" {
		details = map[string]string{"value": detail}
	}
	if err := s.cfg.Audit.Append(audit.BoundaryEvent{
		Category: category, Action: eventType, Outcome: "success", ProjectID: s.ProjectID,
		VMID: s.Container, SessionID: s.SessionID, Details: details,
	}); err != nil {
		return fmt.Errorf("append host audit event %s: %w", eventType, err)
	}
	if s.cfg.OnEvent != nil {
		s.cfg.OnEvent(Event{Type: eventType, ProjectID: s.ProjectID, SessionID: s.SessionID, Detail: detail, At: time.Now().UTC()})
	}
	return nil
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
