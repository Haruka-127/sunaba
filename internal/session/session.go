package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"sunaba/internal/externalgit"
	"sunaba/internal/lease"
	"sunaba/internal/opencode"
	"sunaba/internal/recovery"
	"sunaba/internal/runtime"
	"sunaba/internal/state"
	"sunaba/internal/unixsocket"
	"sunaba/internal/workspace"
)

var sessionIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{5,63}$`)
var secretPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{32,256}$`)
var gitRemoteNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
var exportPolicyDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var memoryLimitPattern = regexp.MustCompile(`^([1-9][0-9]*)([KMGTP]?)$`)

const guestResourceProbeBegin = "SUNABA_RESOURCE_PROBE_BEGIN"
const guestResourceProbeEnd = "SUNABA_RESOURCE_PROBE_END"

type GitRemote struct {
	Name  string
	Token string
}

type Event struct {
	Type      string
	ProjectID string
	SessionID string
	Detail    string
	At        time.Time
}

type Config struct {
	Store              *state.Store
	Runtime            runtime.Runtime
	ProjectRoot        string
	RuntimeBase        string
	VMID               string
	SessionID          string
	Mode               string
	DevNetworkName     string
	DevNetworkVerify   func(context.Context) error
	DevNetworkQuiesce  func(context.Context) error
	DevNetworkClose    func(context.Context) error
	Image              string
	CPUs               int
	Memory             string
	DiskBytes          int64
	ProcessMax         int64
	FileSizeMax        int64
	OpenFileMax        int64
	GuestRelayBinary   string
	ProviderConfig     []byte
	ModelGateway       http.Handler
	ModelGatewayClose  func() error
	ModelToken         string
	ModelAuth          ModelAuthSnapshot
	GitGateway         http.Handler
	GitRemotes         []GitRemote
	GitGatewayClose    func() error
	WebGateway         http.Handler
	WebToken           string
	WebGatewayClose    func() error
	ServerPassword     string
	LeaseTTL           time.Duration
	Audit              *audit.Recorder
	OnEvent            func(Event)
	SnapshotPolicy     workspace.SnapshotPolicy
	ApprovedSnapshot   workspace.SnapshotManifest
	ExportPolicy       workspace.ExportPolicy
	ExportPolicyDigest string
}

type RecoveryConfig struct {
	Store              *state.Store
	Runtime            runtime.Runtime
	Record             recovery.State
	Audit              *audit.Recorder
	SnapshotPolicy     workspace.SnapshotPolicy
	ExportPolicy       workspace.ExportPolicy
	ExportPolicyDigest string
	DevNetworkName     string
	DevNetworkQuiesce  func(context.Context) error
	DevNetworkClose    func(context.Context) error
	DiscardExternalGit bool
	GitGateway         bool
	WebGateway         bool
}

// Activation contains authority that is valid for exactly one Agent Session.
// A Project VM may outlive many Activations, but a revoked Activation is never
// resumed.
type Activation struct {
	SessionID         string
	ProviderConfig    []byte
	ModelGateway      http.Handler
	ModelGatewayClose func() error
	ModelToken        string
	ModelAuth         ModelAuthSnapshot
	GitGateway        http.Handler
	GitRemotes        []GitRemote
	GitGatewayClose   func() error
	WebGateway        http.Handler
	WebToken          string
	WebGatewayClose   func() error
	ServerPassword    string
	LeaseTTL          time.Duration
}

type Session struct {
	ProjectID          string
	ProjectRoot        string
	VMID               string
	SessionID          string
	Root               string
	Container          string
	WorkspacePath      string
	AttachURL          string
	Baseline           workspace.SnapshotManifest
	SnapshotRoot       string
	SnapshotPolicy     workspace.SnapshotPolicy
	ExportPolicy       workspace.ExportPolicy
	ExportPolicyDigest string
	modelAuth          ModelAuthSnapshot

	cfg                Config
	lifecycleContext   context.Context
	projectLock        *state.ProjectLock
	leaseRegistry      *lease.Registry
	vmGuard            *lease.Guard
	leaseCreated       bool
	gatewayServer      *http.Server
	gatewayDone        chan error
	gitGatewayServer   *http.Server
	gitGatewayDone     chan error
	webGatewayServer   *http.Server
	webGatewayDone     chan error
	gatewayActive      atomic.Bool
	attachCancel       context.CancelFunc
	attachDone         <-chan error
	vmCreated          bool
	paused             bool
	closeOnce          sync.Once
	modelCloseOnce     sync.Once
	gitCloseOnce       sync.Once
	webCloseOnce       sync.Once
	devCloseOnce       sync.Once
	discardExternalGit bool
	closeErr           error
}

type ExportResult struct {
	Archive    string
	MergedRoot string
	Merged     workspace.SnapshotManifest
	ChangeSet  workspace.ChangeSet
}

// RecoveryRequiredError reports that export was refused and the dev VM has
// already been stripped of capabilities, stopped, and disconnected. The
// caller must persist its recovery ownership before releasing the VM guard.
type RecoveryRequiredError struct{ Cause error }

func (e *RecoveryRequiredError) Error() string {
	return "dev export was refused; the stopped VM must be retained for explicit recovery: " + e.Cause.Error()
}

func (e *RecoveryRequiredError) Unwrap() error { return e.Cause }

func Start(ctx context.Context, cfg Config) (_ *Session, err error) {
	if cfg.Mode == "" {
		cfg.Mode = "secure"
	}
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	projectLock, err := cfg.Store.AcquireProjectLock(cfg.ProjectRoot)
	if err != nil {
		return nil, err
	}
	s := &Session{
		ProjectID: projectLock.ProjectID, ProjectRoot: projectLock.ProjectRoot,
		VMID: cfg.VMID, SessionID: cfg.SessionID, cfg: cfg, lifecycleContext: ctx, projectLock: projectLock,
		SnapshotPolicy: cfg.SnapshotPolicy, ExportPolicy: cfg.ExportPolicy, ExportPolicyDigest: cfg.ExportPolicyDigest,
		modelAuth: cloneModelAuthSnapshot(cfg.ModelAuth),
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
	s.Root = filepath.Join(cfg.RuntimeBase, "sunaba-vm-"+cfg.VMID)
	s.Container = "sunaba-" + s.ProjectID + "-" + cfg.VMID
	s.WorkspacePath = "/workspace/sunaba-" + cfg.VMID
	s.leaseRegistry = &lease.Registry{Root: filepath.Join(cfg.Store.Root, "leases")}
	s.vmGuard, err = s.leaseRegistry.AcquireGuard(cfg.VMID)
	if err != nil {
		return nil, err
	}
	if _, err := s.leaseRegistry.RegisterPaused(s.ProjectID, s.Container, s.SessionID, "model", cfg.LeaseTTL); err != nil {
		return nil, err
	}
	s.leaseCreated = true
	if err := s.emit("capability.issued", "paused"); err != nil {
		return nil, err
	}
	if err := makeNewPrivateDirectory(s.Root); err != nil {
		return nil, err
	}
	s.SnapshotRoot = filepath.Join(s.Root, "snapshot")
	if cfg.ApprovedSnapshot.Digest != "" {
		s.Baseline, err = workspace.CreateApprovedProjectSnapshot(s.ProjectRoot, s.SnapshotRoot, cfg.ApprovedSnapshot, cfg.SnapshotPolicy)
	} else {
		s.Baseline, err = workspace.CreateProjectSnapshot(s.ProjectRoot, s.SnapshotRoot, cfg.SnapshotPolicy)
	}
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
		ProjectID: s.ProjectID, VMID: s.VMID, Mode: cfg.Mode, NetworkName: cfg.DevNetworkName, Image: cfg.Image, SessionRoot: s.Root,
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
	networks, noDNS := []string{"none"}, true
	if cfg.Mode == "dev" {
		if err := cfg.DevNetworkVerify(ctx); err != nil {
			return nil, fmt.Errorf("dev network boundary verification failed: %w", err)
		}
		networks, noDNS = []string{cfg.DevNetworkName}, false
	}
	spec := runtime.ContainerSpec{
		Name: s.Container, Image: cfg.Image, CPUs: cfg.CPUs, Memory: cfg.Memory,
		Ulimits: map[string]runtime.RLimit{
			"nproc":  {Soft: cfg.ProcessMax, Hard: cfg.ProcessMax},
			"fsize":  {Soft: cfg.FileSizeMax, Hard: cfg.FileSizeMax},
			"nofile": {Soft: cfg.OpenFileMax, Hard: cfg.OpenFileMax},
		},
		Networks: networks, NoDNS: noDNS, Init: true, CapAdd: []string{"SYS_ADMIN"},
		Entrypoint: "/bin/bash", Args: []string{"-lc", "exec tail -f /dev/null"},
		Mounts:  mounts,
		Sockets: []runtime.PublishedSocket{{HostPath: filepath.Join(s.Root, "attach.sock"), GuestPath: runtime.SecureAttachGuestPath}},
		Labels: map[string]string{
			"dev.sunaba.owner": "sunaba-supervisor", "dev.sunaba.project": s.ProjectID,
			"dev.sunaba.vm": s.VMID, "dev.sunaba.mode": cfg.Mode,
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

// AdoptRecovery acquires process ownership of an exact stopped VM. It does
// not create or resume an Agent Session and therefore issues no capability.
func AdoptRecovery(ctx context.Context, cfg RecoveryConfig) (_ *Session, err error) {
	record := cfg.Record
	if cfg.Store == nil || cfg.Runtime == nil || cfg.Audit == nil || record.Version != recovery.Version || record.ProjectRoot == "" || record.ExportPolicyDigest != cfg.ExportPolicyDigest || !filepath.IsAbs(record.RuntimeBase) || record.RuntimeRoot != filepath.Join(record.RuntimeBase, "sunaba-vm-"+record.VMID) {
		return nil, fmt.Errorf("dev recovery configuration is incomplete")
	}
	projectLock, err := cfg.Store.AcquireProjectLock(record.ProjectRoot)
	if err != nil {
		return nil, err
	}
	s := newRecoverySession(ctx, cfg, projectLock)
	rejected := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
	})
	s.cfg = Config{
		Store: cfg.Store, Runtime: cfg.Runtime, ProjectRoot: record.ProjectRoot, RuntimeBase: record.RuntimeBase,
		VMID: record.VMID, SessionID: record.SessionID, Mode: record.RuntimeMode(), Audit: cfg.Audit,
		SnapshotPolicy: cfg.SnapshotPolicy, ExportPolicy: cfg.ExportPolicy, ExportPolicyDigest: cfg.ExportPolicyDigest,
		DevNetworkName: cfg.DevNetworkName, DevNetworkQuiesce: cfg.DevNetworkQuiesce, DevNetworkClose: cfg.DevNetworkClose,
	}
	s.discardExternalGit = cfg.DiscardExternalGit
	if cfg.GitGateway {
		s.cfg.GitGateway = rejected
	}
	if cfg.WebGateway {
		s.cfg.WebGateway = rejected
	}
	defer func() {
		if err != nil {
			s.vmCreated = false
			_ = s.Close()
		}
	}()
	if projectLock.ProjectID != record.ProjectID || projectLock.ProjectRoot != record.ProjectRoot {
		return nil, fmt.Errorf("dev recovery Project identity changed")
	}
	s.leaseRegistry = &lease.Registry{Root: filepath.Join(cfg.Store.Root, "leases")}
	s.vmGuard, err = s.leaseRegistry.AcquireGuard(record.VMID)
	if err != nil {
		return nil, err
	}
	info, err := cfg.Runtime.Inspect(ctx, record.Container)
	if err != nil {
		return nil, err
	}
	if info.Name != record.Container || info.State != runtime.StateStopped || info.Labels["dev.sunaba.owner"] != "sunaba-supervisor" || info.Labels["dev.sunaba.project"] != record.ProjectID || info.Labels["dev.sunaba.vm"] != record.VMID || info.Labels["dev.sunaba.mode"] != record.RuntimeMode() {
		return nil, fmt.Errorf("stopped recovery VM ownership does not match its record")
	}
	actual, err := workspace.BuildSnapshotManifest(s.SnapshotRoot, cfg.SnapshotPolicy)
	if err != nil || actual.Digest != record.Baseline.Digest {
		return nil, fmt.Errorf("dev recovery baseline no longer matches its record")
	}
	return s, nil
}

func newRecoverySession(ctx context.Context, cfg RecoveryConfig, projectLock *state.ProjectLock) *Session {
	record := cfg.Record
	return &Session{
		ProjectID: record.ProjectID, ProjectRoot: record.ProjectRoot, VMID: record.VMID, SessionID: record.SessionID,
		Root: record.RuntimeRoot, Container: record.Container, WorkspacePath: record.WorkspacePath,
		Baseline: record.Baseline, SnapshotRoot: filepath.Join(record.RuntimeRoot, "snapshot"), SnapshotPolicy: cfg.SnapshotPolicy,
		ExportPolicy: cfg.ExportPolicy, ExportPolicyDigest: cfg.ExportPolicyDigest,
		projectLock: projectLock, lifecycleContext: ctx, vmCreated: true, paused: true,
	}
}

func validateConfig(cfg Config) error {
	if err := validateModelAuthSnapshot(cfg.ModelAuth); err != nil {
		return err
	}
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
	if !sessionIDPattern.MatchString(cfg.VMID) || !sessionIDPattern.MatchString(cfg.SessionID) || cfg.VMID == cfg.SessionID || cfg.Image != dependency.MustPinned().AgentImage.Tag || cfg.CPUs <= 0 || cfg.Memory == "" {
		return fmt.Errorf("secure session identity, pinned image, and resources are required")
	}
	if cfg.Mode != "secure" && cfg.Mode != "dev" {
		return fmt.Errorf("session mode must be secure or dev")
	}
	if cfg.Mode == "secure" && (cfg.DevNetworkName != "" || cfg.DevNetworkVerify != nil || cfg.DevNetworkQuiesce != nil || cfg.DevNetworkClose != nil) {
		return fmt.Errorf("secure session must not accept a direct-egress network")
	}
	if cfg.Mode == "dev" {
		if cfg.DevNetworkName == "" || cfg.DevNetworkVerify == nil || cfg.DevNetworkQuiesce == nil || cfg.DevNetworkClose == nil {
			return fmt.Errorf("dev session requires an owned, verified, revocable network boundary")
		}
	}
	if _, err := parseMemoryBytes(cfg.Memory); err != nil {
		return err
	}
	if cfg.DiskBytes < 64<<20 || cfg.DiskBytes > 8<<30 || cfg.ProcessMax < 16 || cfg.ProcessMax > 4096 || cfg.FileSizeMax != cfg.DiskBytes || cfg.OpenFileMax < 256 || cfg.OpenFileMax > 1<<20 {
		return fmt.Errorf("secure session disk, process, file size, and open-file limits are invalid")
	}
	if !filepath.IsAbs(cfg.GuestRelayBinary) || len(cfg.ProviderConfig) == 0 || !json.Valid(cfg.ProviderConfig) || cfg.ModelGateway == nil || cfg.ModelGatewayClose == nil {
		return fmt.Errorf("secure session requires the guest relay, provider config, and Model Gateway")
	}
	info, err := os.Lstat(cfg.GuestRelayBinary)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("guest relay must be a regular file")
	}
	if !secretPattern.MatchString(cfg.ModelToken) || !secretPattern.MatchString(cfg.ServerPassword) || cfg.ModelToken == cfg.ServerPassword {
		return fmt.Errorf("session secrets must be distinct high-entropy URL-safe values")
	}
	if (cfg.GitGateway == nil) != (len(cfg.GitRemotes) == 0) || (cfg.GitGateway == nil) != (cfg.GitGatewayClose == nil) || !validGitRemoteConfig(cfg.GitRemotes, cfg.ModelToken, cfg.ServerPassword) {
		return fmt.Errorf("optional Git Gateway requires a distinct high-entropy capability")
	}
	if (cfg.WebGateway == nil) != (cfg.WebToken == "") || (cfg.WebGateway == nil) != (cfg.WebGatewayClose == nil) || (cfg.WebGateway != nil && (!secretPattern.MatchString(cfg.WebToken) || cfg.WebToken == cfg.ModelToken || cfg.WebToken == cfg.ServerPassword || gitTokenExists(cfg.GitRemotes, cfg.WebToken))) {
		return fmt.Errorf("optional Web Gateway requires a distinct high-entropy capability")
	}
	if cfg.Audit == nil || filepath.Clean(cfg.Audit.Root) != filepath.Join(filepath.Clean(cfg.Store.Root), "audit") {
		return fmt.Errorf("secure session requires its host audit recorder under the state store")
	}
	if cfg.LeaseTTL <= 0 || cfg.LeaseTTL > 24*time.Hour {
		return fmt.Errorf("secure session requires a bounded lease lifetime")
	}
	if cfg.SnapshotPolicy.MaxDepth <= 0 || cfg.SnapshotPolicy.MaxEntries <= 0 || cfg.SnapshotPolicy.MaxFileSize <= 0 ||
		cfg.SnapshotPolicy.MaxTotalSize < cfg.SnapshotPolicy.MaxFileSize || cfg.SnapshotPolicy.MaxSymlinkSize <= 0 ||
		cfg.ExportPolicy.Workspace.MaxEntries != cfg.SnapshotPolicy.MaxEntries ||
		!exportPolicyDigestPattern.MatchString(cfg.ExportPolicyDigest) {
		return fmt.Errorf("secure session requires a compiled export policy")
	}
	return nil
}

func activationFromConfig(cfg Config) Activation {
	return Activation{
		SessionID: cfg.SessionID, ProviderConfig: cfg.ProviderConfig, ModelGateway: cfg.ModelGateway, ModelGatewayClose: cfg.ModelGatewayClose,
		ModelToken: cfg.ModelToken, GitGateway: cfg.GitGateway, GitRemotes: cfg.GitRemotes,
		GitGatewayClose: cfg.GitGatewayClose, WebGateway: cfg.WebGateway, WebToken: cfg.WebToken,
		WebGatewayClose: cfg.WebGatewayClose, ServerPassword: cfg.ServerPassword, LeaseTTL: cfg.LeaseTTL,
		ModelAuth: cloneModelAuthSnapshot(cfg.ModelAuth),
	}
}

func validateActivation(activation Activation) error {
	if err := validateModelAuthSnapshot(activation.ModelAuth); err != nil {
		return err
	}
	if !sessionIDPattern.MatchString(activation.SessionID) || len(activation.ProviderConfig) == 0 || !json.Valid(activation.ProviderConfig) || activation.ModelGateway == nil || activation.ModelGatewayClose == nil {
		return fmt.Errorf("Agent Session activation identity and Model Gateway are required")
	}
	if !secretPattern.MatchString(activation.ModelToken) || !secretPattern.MatchString(activation.ServerPassword) || activation.ModelToken == activation.ServerPassword {
		return fmt.Errorf("Agent Session secrets must be distinct high-entropy URL-safe values")
	}
	if (activation.GitGateway == nil) != (len(activation.GitRemotes) == 0) || (activation.GitGateway == nil) != (activation.GitGatewayClose == nil) || !validGitRemoteConfig(activation.GitRemotes, activation.ModelToken, activation.ServerPassword) {
		return fmt.Errorf("optional Git Gateway requires a distinct high-entropy capability")
	}
	if (activation.WebGateway == nil) != (activation.WebToken == "") || (activation.WebGateway == nil) != (activation.WebGatewayClose == nil) || (activation.WebGateway != nil && (!secretPattern.MatchString(activation.WebToken) || activation.WebToken == activation.ModelToken || activation.WebToken == activation.ServerPassword || gitTokenExists(activation.GitRemotes, activation.WebToken))) {
		return fmt.Errorf("optional Web Gateway requires a distinct high-entropy capability")
	}
	if activation.LeaseTTL <= 0 || activation.LeaseTTL > 24*time.Hour {
		return fmt.Errorf("Agent Session requires a bounded lease lifetime")
	}
	return nil
}

func validGitRemoteConfig(remotes []GitRemote, modelToken, serverPassword string) bool {
	if len(remotes) > 16 {
		return false
	}
	names := make(map[string]struct{}, len(remotes))
	tokens := make(map[string]struct{}, len(remotes))
	for _, remote := range remotes {
		if !gitRemoteNamePattern.MatchString(remote.Name) || !secretPattern.MatchString(remote.Token) || remote.Token == modelToken || remote.Token == serverPassword {
			return false
		}
		if _, exists := names[remote.Name]; exists {
			return false
		}
		if _, exists := tokens[remote.Token]; exists {
			return false
		}
		names[remote.Name] = struct{}{}
		tokens[remote.Token] = struct{}{}
	}
	return true
}

func gitTokenExists(remotes []GitRemote, token string) bool {
	for _, remote := range remotes {
		if remote.Token == token {
			return true
		}
	}
	return false
}

func NewSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// ExecOutput runs a supervisor-selected command in an existing session VM. The
// caller must still treat all returned bytes as untrusted terminal data.
func (s *Session) ExecOutput(ctx context.Context, command []string) (string, error) {
	if !s.vmCreated || len(command) == 0 {
		return "", fmt.Errorf("session VM is not available")
	}
	return s.cfg.Runtime.ExecOutput(ctx, s.Container, command)
}

// ExecCapture runs a bounded argv command in the existing VM. The production
// runtime must support structured capture; no shell-string fallback is used.
func (s *Session) ExecCapture(ctx context.Context, command []string, stdoutLimit, stderrLimit int64) (runtime.ExecResult, error) {
	if !s.vmCreated || len(command) == 0 {
		return runtime.ExecResult{}, fmt.Errorf("session VM is not available")
	}
	capturer, ok := s.cfg.Runtime.(interface {
		ExecCapture(context.Context, string, []string, int64, int64) (runtime.ExecResult, error)
	})
	if !ok {
		return runtime.ExecResult{}, fmt.Errorf("runtime does not support structured guest exec")
	}
	return capturer.ExecCapture(ctx, s.Container, command, stdoutLimit, stderrLimit)
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
	if err := unixsocket.ValidatePath(path); err != nil {
		return nil, nil, fmt.Errorf("Gateway socket path: %w", err)
	}
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
	pauseErr = errors.Join(pauseErr, s.stopChannels(ctx))
	if _, err := s.leaseRegistry.Revoke(s.SessionID); err != nil {
		return errors.Join(pauseErr, err)
	}
	s.leaseCreated = false
	s.paused = true
	if err := s.emit("capability.revoked", "pause"); err != nil {
		pauseErr = errors.Join(pauseErr, err)
	}
	if err := s.cfg.Runtime.Stop(ctx, s.Container); err != nil {
		return errors.Join(pauseErr, err)
	}
	if current, err := s.cfg.Runtime.ContainerState(ctx, s.Container); err != nil || current != runtime.StateStopped {
		return errors.Join(pauseErr, fmt.Errorf("session VM did not stop: state=%s error=%v", current, err))
	}
	return errors.Join(pauseErr, s.emit("session.paused", ""))
}

// ResumeWith starts a new Agent Session in the existing Project VM.
func (s *Session) ResumeWith(ctx context.Context, activation Activation) (err error) {
	if !s.vmCreated || !s.paused {
		return fmt.Errorf("session is not paused")
	}
	if err := validateActivation(activation); err != nil {
		return err
	}
	if activation.SessionID == s.SessionID {
		return fmt.Errorf("refusing to reuse a revoked Agent Session identity")
	}
	s.SessionID = activation.SessionID
	s.cfg.SessionID = activation.SessionID
	s.cfg.ProviderConfig = append([]byte(nil), activation.ProviderConfig...)
	s.cfg.ModelGateway, s.cfg.ModelGatewayClose, s.cfg.ModelToken = activation.ModelGateway, activation.ModelGatewayClose, activation.ModelToken
	s.modelAuth = cloneModelAuthSnapshot(activation.ModelAuth)
	s.cfg.ModelAuth = cloneModelAuthSnapshot(activation.ModelAuth)
	s.cfg.GitGateway, s.cfg.GitRemotes, s.cfg.GitGatewayClose = activation.GitGateway, append([]GitRemote(nil), activation.GitRemotes...), activation.GitGatewayClose
	s.cfg.WebGateway, s.cfg.WebToken, s.cfg.WebGatewayClose = activation.WebGateway, activation.WebToken, activation.WebGatewayClose
	s.cfg.ServerPassword, s.cfg.LeaseTTL = activation.ServerPassword, activation.LeaseTTL
	s.modelCloseOnce, s.gitCloseOnce, s.webCloseOnce = sync.Once{}, sync.Once{}, sync.Once{}
	s.gatewayActive.Store(false)
	leaseActivated := false
	defer func() {
		if err != nil {
			s.gatewayActive.Store(false)
			if leaseActivated || s.leaseCreated {
				_, _ = s.leaseRegistry.Revoke(s.SessionID)
				s.leaseCreated = false
			}
			_ = s.stopChannels(context.Background())
			if current, stateErr := s.cfg.Runtime.ContainerState(context.Background(), s.Container); stateErr == nil && current == runtime.StateRunning {
				_ = s.cfg.Runtime.Stop(context.Background(), s.Container)
			}
			s.paused = true
		}
	}()
	if _, err := s.leaseRegistry.RegisterPaused(s.ProjectID, s.Container, s.SessionID, "model", s.cfg.LeaseTTL); err != nil {
		return err
	}
	s.leaseCreated = true
	if err := s.emit("capability.issued", "paused"); err != nil {
		return err
	}
	if err := s.startGateway(); err != nil {
		return err
	}
	current, stateErr := s.cfg.Runtime.ContainerState(ctx, s.Container)
	if stateErr != nil {
		return stateErr
	}
	if s.cfg.Mode == "dev" {
		if err := s.cfg.DevNetworkVerify(ctx); err != nil {
			return fmt.Errorf("dev network boundary verification failed before resume: %w", err)
		}
	}
	if current == runtime.StateStopped {
		if err := s.cfg.Runtime.Start(ctx, s.Container); err != nil {
			return err
		}
	} else if current != runtime.StateRunning {
		return fmt.Errorf("paused session VM is not resumable: state=%s", current)
	}
	// /run is guest tmpfs and is empty after a real VM stop/start. Recreate
	// session inputs from the in-memory Config instead of persisting secrets in
	// the container root filesystem.
	if err := s.restoreGuestRuntimeInputs(ctx); err != nil {
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
		serverLog, _ := s.cfg.Runtime.ExecOutput(ctx, s.Container, []string{"/bin/bash", "-lc", "tail -n 80 /run/sunaba/server.log 2>/dev/null || true"})
		return fmt.Errorf("%w; guest server log: %s", err, approval.SanitizeText(serverLog))
	}
	if health.Version != dependency.OpenCodeVersion {
		return fmt.Errorf("resumed OpenCode version %q does not match pinned version", health.Version)
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
	if err := s.emit("session.started", health.Version); err != nil {
		return err
	}
	s.gatewayActive.Store(true)
	s.paused = false
	leaseActivated = false
	return nil
}

// Resume is intentionally rejected because resuming with the previous
// capability would extend revoked authority. Call ResumeWith with a freshly
// generated Activation.
func (s *Session) Resume(context.Context) error {
	return fmt.Errorf("a fresh Agent Session activation is required")
}

func (s *Session) resumeGuest(ctx context.Context) error {
	commands := []string{
		"set -eu",
	}
	commands = append(commands, s.guestRuntimeInputPermissionCommands()...)
	commands = append(commands,
		"if ! grep -Fqs ' /var/lib/sunaba/overlay ' /proc/mounts; then mount -o loop,nosuid,nodev /var/lib/sunaba/overlay.img /var/lib/sunaba/overlay; fi",
		"if ! grep -Fqs ' "+s.WorkspacePath+" ' /proc/mounts; then mount -t overlay overlay -o lowerdir=/var/lib/sunaba/lower,upperdir=/var/lib/sunaba/overlay/upper,workdir=/var/lib/sunaba/overlay/work "+s.WorkspacePath+"; fi",
		"test -d /var/lib/sunaba/repository",
		"nohup /run/sunaba/guest-relay --tcp-listen 127.0.0.1:4141 --unix-target /run/sunaba/model-gateway.sock >/run/sunaba/model-relay.log 2>&1 &",
	)
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
	commands = append(commands, guestResourceProbeCommands()...)
	resume := strings.Join(commands, "\n")
	out, err := s.cfg.Runtime.ExecOutput(ctx, s.Container, []string{"/bin/bash", "-lc", resume})
	if err != nil {
		return fmt.Errorf("resume secure guest services: %w: %s", err, out)
	}
	return s.validateGuestResources(out)
}

func (s *Session) configureGuest(ctx context.Context) error {
	if err := s.restoreGuestRuntimeInputs(ctx); err != nil {
		return err
	}
	if err := s.cfg.Runtime.CopyTo(ctx, s.Container, s.SnapshotRoot, "/var/lib/sunaba/lower"); err != nil {
		return err
	}
	commands := []string{
		"set -eu",
		"getent group sunaba-agent >/dev/null || groupadd -g 1000 sunaba-agent",
		"id sunaba-agent >/dev/null 2>&1 || useradd -u 1000 -g sunaba-agent -M -d /run/sunaba/home -s /bin/bash sunaba-agent",
	}
	commands = append(commands, s.guestRuntimeInputPermissionCommands()...)
	commands = append(commands,
		"mkdir -p "+s.WorkspacePath+" /run/sunaba/home /run/sunaba/config /run/sunaba/data /var/lib/sunaba/overlay",
		fmt.Sprintf("truncate -s %d /var/lib/sunaba/overlay.img", s.cfg.DiskBytes),
		"mkfs.ext4 -q -F -m 0 /var/lib/sunaba/overlay.img",
		"mount -o loop,nosuid,nodev /var/lib/sunaba/overlay.img /var/lib/sunaba/overlay",
		"mkdir -p /var/lib/sunaba/overlay/upper /var/lib/sunaba/overlay/work /var/lib/sunaba/overlay/repository",
		"ln -s overlay/repository /var/lib/sunaba/repository",
		"chown -R 1000:1000 /var/lib/sunaba/lower /var/lib/sunaba/overlay /run/sunaba/home /run/sunaba/config /run/sunaba/data",
		"mount -t overlay overlay -o lowerdir=/var/lib/sunaba/lower,upperdir=/var/lib/sunaba/overlay/upper,workdir=/var/lib/sunaba/overlay/work "+s.WorkspacePath,
		"cd "+s.WorkspacePath,
		"runuser -u sunaba-agent -- git init -q --bare /var/lib/sunaba/repository",
		"runuser -u sunaba-agent -- git --git-dir=/var/lib/sunaba/repository --work-tree="+s.WorkspacePath+" config user.name sunaba-baseline",
		"runuser -u sunaba-agent -- git --git-dir=/var/lib/sunaba/repository --work-tree="+s.WorkspacePath+" config user.email sunaba@localhost",
		"runuser -u sunaba-agent -- git --git-dir=/var/lib/sunaba/repository --work-tree="+s.WorkspacePath+" config core.hooksPath /dev/null",
		"runuser -u sunaba-agent -- git --git-dir=/var/lib/sunaba/repository --work-tree="+s.WorkspacePath+" add -A && runuser -u sunaba-agent -- git --git-dir=/var/lib/sunaba/repository --work-tree="+s.WorkspacePath+" commit -qm 'sunaba synthetic baseline' --no-verify || true",
		"nohup /run/sunaba/guest-relay --tcp-listen 127.0.0.1:4141 --unix-target /run/sunaba/model-gateway.sock >/run/sunaba/model-relay.log 2>&1 &",
	)
	if s.cfg.GitGateway != nil {
		for _, remote := range s.cfg.GitRemotes {
			commands = append(commands, "runuser -u sunaba-agent -- git --git-dir=/var/lib/sunaba/repository config remote."+remote.Name+".url http://127.0.0.1:4242/"+remote.Name+".git")
		}
		commands = append(commands, "nohup /run/sunaba/guest-relay --tcp-listen 127.0.0.1:4242 --unix-target /run/sunaba/git-gateway.sock >/run/sunaba/git-relay.log 2>&1 &")
	}
	if s.cfg.WebGateway != nil {
		commands = append(commands,
			"nohup /run/sunaba/guest-relay --tcp-listen 127.0.0.1:4343 --unix-target /run/sunaba/web-gateway.sock >/run/sunaba/web-relay.log 2>&1 &",
		)
	}
	commands = append(commands,
		"nohup /run/sunaba/guest-relay --listen /run/sunaba/attach.sock --target 127.0.0.1:4096 >/run/sunaba/attach-relay.log 2>&1 &",
		s.guestServerCommand(),
	)
	commands = append(commands, guestResourceProbeCommands()...)
	setup := strings.Join(commands, "\n")
	out, err := s.cfg.Runtime.ExecOutput(ctx, s.Container, []string{"/bin/bash", "-lc", setup})
	if err != nil {
		return fmt.Errorf("configure secure guest: %w: %s", err, out)
	}
	return s.validateGuestResources(out)
}

func (s *Session) guestRuntimeInputPermissionCommands() []string {
	commands := []string{
		"chown 0:1000 /run/sunaba",
		"chmod 0710 /run/sunaba",
		"chown 0:0 /run/sunaba/guest-relay",
		"chmod 0700 /run/sunaba/guest-relay",
		"chown 1000:1000 /run/sunaba/session.env /run/sunaba/opencode.json /run/sunaba/shell-wrapper /run/sunaba/exec-wrapper",
		"chmod 0400 /run/sunaba/session.env /run/sunaba/opencode.json",
		"chmod 0500 /run/sunaba/shell-wrapper /run/sunaba/exec-wrapper",
	}
	if s.cfg.WebGateway != nil {
		commands = append(commands,
			"chown 1000:1000 /run/sunaba/apt-proxy.conf",
			"chmod 0400 /run/sunaba/apt-proxy.conf",
		)
	}
	return commands
}

func (s *Session) restoreGuestRuntimeInputs(ctx context.Context) (err error) {
	bundleRoot := filepath.Join(s.Root, "session-input-bundle")
	bundlePath := filepath.Join(bundleRoot, "sunaba")
	if err := os.Mkdir(bundleRoot, 0700); err != nil {
		return fmt.Errorf("create host session input bundle: %w", err)
	}
	if err := os.Mkdir(bundlePath, 0700); err != nil {
		_ = os.Remove(bundleRoot)
		return fmt.Errorf("create private host session input directory: %w", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(bundleRoot); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove copied host session input bundle: %w", removeErr))
		}
	}()
	providerPath := filepath.Join(bundlePath, "opencode.json")
	envPath := filepath.Join(bundlePath, "session.env")
	shellWrapperPath := filepath.Join(bundlePath, "shell-wrapper")
	execWrapperPath := filepath.Join(bundlePath, "exec-wrapper")
	relayPath := filepath.Join(bundlePath, "guest-relay")
	if err := copyPrivateRegularFile(s.cfg.GuestRelayBinary, relayPath, 0700); err != nil {
		return fmt.Errorf("stage guest relay: %w", err)
	}
	if err := os.WriteFile(providerPath, s.cfg.ProviderConfig, 0600); err != nil {
		return err
	}
	environment := "OPENCODE_SERVER_PASSWORD=" + s.cfg.ServerPassword + "\nSUNABA_MODEL_GATEWAY_TOKEN=" + s.cfg.ModelToken + "\n"
	if s.cfg.GitGateway != nil {
		for index, remote := range s.cfg.GitRemotes {
			environment += fmt.Sprintf("SUNABA_GIT_GATEWAY_TOKEN_%d=%s\n", index, remote.Token)
		}
	}
	if s.cfg.WebGateway != nil {
		environment += "SUNABA_WEB_GATEWAY_TOKEN=" + s.cfg.WebToken + "\n"
	}
	if err := os.WriteFile(envPath, []byte(environment), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(shellWrapperPath, []byte(s.guestShellWrapper()), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(execWrapperPath, []byte(s.guestExecWrapper()), 0600); err != nil {
		return err
	}
	if s.cfg.WebGateway != nil {
		aptConfigPath := filepath.Join(bundlePath, "apt-proxy.conf")
		proxyURL := "http://sunaba:" + s.cfg.WebToken + "@127.0.0.1:4343"
		aptConfig := "Acquire::http::Proxy \"" + proxyURL + "\";\nAcquire::https::Proxy \"" + proxyURL + "\";\nAcquire::Retries \"0\";\n"
		if err := os.WriteFile(aptConfigPath, []byte(aptConfig), 0600); err != nil {
			return err
		}
	}
	if err := s.cfg.Runtime.CopyTo(ctx, s.Container, bundlePath, "/run/"); err != nil {
		return fmt.Errorf("copy guest session input bundle: %w", err)
	}
	return nil
}

func copyPrivateRegularFile(source, target string, mode os.FileMode) (err error) {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("source is not a regular file")
	}
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := output.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	return output.Chmod(mode)
}

func (s *Session) guestServerCommand() string {
	gitEnvironment := s.guestGitEnvironment()
	webEnvironment := ""
	if s.cfg.WebGateway != nil {
		webEnvironment = " HTTP_PROXY=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343 HTTPS_PROXY=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343 http_proxy=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343 https_proxy=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343 NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost APT_CONFIG=/run/sunaba/apt-proxy.conf"
	}
	return "nohup /bin/bash -lc 'set -a; . /run/sunaba/session.env; set +a; cd " + s.WorkspacePath + "; exec env HOME=/run/sunaba/home XDG_CONFIG_HOME=/run/sunaba/config XDG_DATA_HOME=/run/sunaba/data GIT_DIR=/var/lib/sunaba/repository GIT_WORK_TREE=" + s.WorkspacePath + gitEnvironment + webEnvironment + " OPENCODE_CONFIG=/run/sunaba/opencode.json OPENCODE_DISABLE_AUTOUPDATE=1 OPENCODE_DISABLE_MODELS_FETCH=1 OPENCODE_DISABLE_LSP_DOWNLOAD=1 OPENCODE_DISABLE_DEFAULT_PLUGINS=1 opencode serve --hostname 127.0.0.1 --port 4096 --mdns=false' >/run/sunaba/server.log 2>&1 & echo $! >/run/sunaba/server.pid"
}

func (s *Session) guestShellWrapper() string {
	gitEnvironment := s.guestGitEnvironment()
	webEnvironment := ""
	if s.cfg.WebGateway != nil {
		webEnvironment = " HTTP_PROXY=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343 HTTPS_PROXY=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343 http_proxy=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343 https_proxy=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343 NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost APT_CONFIG=/run/sunaba/apt-proxy.conf"
	}
	return "#!/bin/bash\nset -eu\nset -a\n. /run/sunaba/session.env\nset +a\ncd " + s.WorkspacePath + "\nexec env " + s.guestCommandEnvironment(gitEnvironment, webEnvironment) + " /bin/bash -lc \"$1\"\n"
}

func (s *Session) guestExecWrapper() string {
	gitEnvironment := s.guestGitEnvironment()
	webEnvironment := ""
	if s.cfg.WebGateway != nil {
		webEnvironment = " HTTP_PROXY=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343 HTTPS_PROXY=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343 http_proxy=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343 https_proxy=http://sunaba:$SUNABA_WEB_GATEWAY_TOKEN@127.0.0.1:4343 NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost APT_CONFIG=/run/sunaba/apt-proxy.conf"
	}
	return "#!/bin/bash\nset -eu\nset -a\n. /run/sunaba/session.env\nset +a\nrelative=$1\nshift\ncd -- " + s.WorkspacePath + "/\"$relative\"\nexec env " + s.guestCommandEnvironment(gitEnvironment, webEnvironment) + " \"$@\"\n"
}

func (s *Session) guestCommandEnvironment(gitEnvironment, webEnvironment string) string {
	return "HOME=/run/sunaba/home XDG_CONFIG_HOME=/run/sunaba/config XDG_DATA_HOME=/run/sunaba/data GIT_DIR=/var/lib/sunaba/repository GIT_WORK_TREE=" + s.WorkspacePath + gitEnvironment + webEnvironment
}

func (s *Session) guestGitEnvironment() string {
	if s.cfg.GitGateway == nil {
		return ""
	}
	environment := fmt.Sprintf(" GIT_CONFIG_COUNT=%d", len(s.cfg.GitRemotes))
	for index, remote := range s.cfg.GitRemotes {
		environment += fmt.Sprintf(" GIT_CONFIG_KEY_%d=http.http://127.0.0.1:4242/%s.git.extraHeader GIT_CONFIG_VALUE_%d=\"Authorization: Bearer $SUNABA_GIT_GATEWAY_TOKEN_%d\"", index, remote.Name, index, index)
	}
	return environment
}

func guestResourceProbeCommands() []string {
	return []string{
		"pid=''",
		"for attempt in $(seq 1 200); do pid=$(cat /run/sunaba/server.pid 2>/dev/null || true); test -n \"$pid\" && test -r /proc/$pid/status && break; sleep 0.01; done",
		"test -n \"$pid\" && test -r /proc/$pid/status",
		"echo " + guestResourceProbeBegin,
		"echo cpu=$(getconf _NPROCESSORS_ONLN)",
		"awk '/MemTotal:/{print \"memory_kb=\" $2}' /proc/meminfo",
		"echo disk=$(df -B1 --output=size /var/lib/sunaba/overlay | tail -n 1 | tr -d ' ')",
		"awk '/^Uid:/{print \"uid=\" $2}' /proc/$pid/status",
		"awk '$1==\"Max\" && $2==\"processes\"{print \"nproc=\" $(NF-1)}' /proc/$pid/limits",
		"awk '$1==\"Max\" && $2==\"file\" && $3==\"size\"{print \"fsize=\" $(NF-2)}' /proc/$pid/limits",
		"awk '$1==\"Max\" && $2==\"open\" && $3==\"files\"{print \"nofile=\" $(NF-1)}' /proc/$pid/limits",
		"echo " + guestResourceProbeEnd,
	}
}

func (s *Session) validateGuestResources(out string) error {
	begin := strings.Index(out, guestResourceProbeBegin+"\n")
	end := strings.Index(out, "\n"+guestResourceProbeEnd)
	if begin < 0 || end < 0 || end <= begin {
		return fmt.Errorf("invalid guest resource probe framing")
	}
	out = out[begin+len(guestResourceProbeBegin)+1 : end]
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
	if values["cpu"] < int64(s.cfg.CPUs) || values["cpu"] > int64(s.cfg.CPUs+1) || values["memory_kb"] <= 0 || values["memory_kb"]<<10 > guestMemoryCeiling || values["disk"] <= 0 || values["disk"] > s.cfg.DiskBytes || values["uid"] != 0 || values["nproc"] != s.cfg.ProcessMax || values["fsize"] != s.cfg.FileSizeMax || values["nofile"] != s.cfg.OpenFileMax {
		return fmt.Errorf("secure guest resource limits do not match host policy: %v", values)
	}
	return s.emit("resource.probe", fmt.Sprintf("cpu=%d,memory=%d,disk=%d,nproc=%d,fsize=%d,nofile=%d", s.cfg.CPUs, memoryBytes, s.cfg.DiskBytes, s.cfg.ProcessMax, s.cfg.FileSizeMax, s.cfg.OpenFileMax))
}

func parseMemoryBytes(value string) (int64, error) {
	match := memoryLimitPattern.FindStringSubmatch(strings.ToUpper(value))
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
	relayCtx, cancel := context.WithCancel(s.lifecycleContext)
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
	if s.cfg.Mode == "dev" {
		if err := s.cfg.DevNetworkQuiesce(ctx); err != nil {
			s.gatewayActive.Store(false)
			pauseErr := error(nil)
			if !s.paused {
				pauseErr = s.Pause(ctx)
			}
			return ExportResult{}, errors.Join(fmt.Errorf("quiesce dev egress before export: %w", err), pauseErr)
		}
		if err := s.emit("dev_network.quiesced", s.cfg.DevNetworkName); err != nil {
			return ExportResult{}, err
		}
	}
	s.gatewayActive.Store(false)
	if err := s.stopAttach(ctx); err != nil {
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
		if err := s.startRevokedGatewaysForExport(); err != nil {
			return ExportResult{}, err
		}
		if err := s.cfg.Runtime.Start(ctx, s.Container); err != nil {
			return ExportResult{}, fmt.Errorf("start paused session VM for export: %w", err)
		}
		if err := s.mountPausedWorkspaceForExport(ctx); err != nil {
			return ExportResult{}, err
		}
	} else if containerState != runtime.StateRunning {
		return ExportResult{}, fmt.Errorf("session VM cannot be frozen from state %s", containerState)
	}
	if !s.discardExternalGit {
		if err := externalgit.CheckBeforeExport(ctx, s.cfg.Runtime, s.Container, s.WorkspacePath); err != nil {
			if s.cfg.Mode == "dev" {
				return ExportResult{}, &RecoveryRequiredError{Cause: errors.Join(err, s.stopDevForRecovery(ctx))}
			}
			return ExportResult{}, err
		}
	}
	if err := s.stopChannels(ctx); err != nil {
		return ExportResult{}, err
	}
	if err := s.prepareGuestExport(ctx); err != nil {
		return ExportResult{}, err
	}
	if err := s.cfg.Runtime.Stop(ctx, s.Container); err != nil {
		return ExportResult{}, fmt.Errorf("stop session VM for frozen export: %w", err)
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
		return ExportResult{}, fmt.Errorf("export frozen session root filesystem: %w", err)
	}
	frozen, err := workspace.ParseFrozenRootFS(archive, quarantine, s.Baseline, s.cfg.ExportPolicy)
	if err != nil {
		return ExportResult{}, err
	}
	defer frozen.Close()
	mergedRoot := filepath.Join(quarantine, "sunaba-merged-"+s.SessionID)
	merged, err := workspace.MaterializeMergedView(s.SnapshotRoot, mergedRoot, s.Baseline, frozen, s.cfg.SnapshotPolicy)
	if err != nil {
		return ExportResult{}, err
	}
	current, err := workspace.BuildSnapshotManifest(s.ProjectRoot, s.cfg.SnapshotPolicy)
	if err != nil || current.Digest != s.Baseline.Digest {
		return ExportResult{}, fmt.Errorf("host Project baseline changed during session")
	}
	changeSet, err := workspace.BuildChangeSet(s.Baseline, merged.Manifest, s.cfg.SnapshotPolicy)
	if err != nil {
		return ExportResult{}, err
	}
	if err := s.emit("changeset.created", changeSet.Digest); err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Archive: archive, MergedRoot: merged.Root, Merged: merged.Manifest, ChangeSet: changeSet}, nil
}

func (s *Session) stopDevForRecovery(ctx context.Context) error {
	var recoveryErr error
	s.gatewayActive.Store(false)
	recoveryErr = errors.Join(recoveryErr, s.stopChannels(ctx))
	if s.leaseCreated {
		if _, err := s.leaseRegistry.Revoke(s.SessionID); err != nil {
			recoveryErr = errors.Join(recoveryErr, err)
		} else {
			s.leaseCreated = false
			recoveryErr = errors.Join(recoveryErr, s.emit("capability.revoked", "dev-recovery"))
		}
	}
	current, err := s.cfg.Runtime.ContainerState(ctx, s.Container)
	if err != nil {
		recoveryErr = errors.Join(recoveryErr, err)
	} else if current == runtime.StateRunning {
		recoveryErr = errors.Join(recoveryErr, s.cfg.Runtime.Stop(ctx, s.Container))
	} else if current != runtime.StateStopped {
		recoveryErr = errors.Join(recoveryErr, fmt.Errorf("recovery VM has unsupported state %s", current))
	}
	s.paused = true
	current, err = s.cfg.Runtime.ContainerState(ctx, s.Container)
	if err != nil || current != runtime.StateStopped {
		recoveryErr = errors.Join(recoveryErr, fmt.Errorf("recovery VM is not stopped: state=%s error=%v", current, err))
	}
	recoveryErr = errors.Join(recoveryErr, s.closeDevNetwork(ctx))
	if emitErr := s.emit("session.recovery_retained", "export-refused"); emitErr != nil {
		recoveryErr = errors.Join(recoveryErr, emitErr)
	}
	return recoveryErr
}

func (s *Session) RecoveryState(reason string) recovery.State {
	return recovery.State{
		Version: recovery.Version, ProjectID: s.ProjectID, ProjectRoot: s.ProjectRoot, VMID: s.VMID,
		SessionID: s.SessionID, Container: s.Container, RuntimeBase: s.cfg.RuntimeBase, RuntimeRoot: s.Root,
		WorkspacePath: s.WorkspacePath, Baseline: s.Baseline, ExportPolicyDigest: s.ExportPolicyDigest,
		Mode:       s.cfg.Mode,
		GitGateway: s.cfg.GitGateway != nil, WebGateway: s.cfg.WebGateway != nil,
		Reason: reason, CreatedAt: time.Now().UTC(),
	}
}

func (s *Session) SupportsFrozenRecovery() bool {
	return s != nil && (s.cfg.Mode == "dev" || s.cfg.Mode == "secure")
}

func (s *Session) SetDiscardExternalGitForExport(discard bool) error {
	if s == nil {
		return fmt.Errorf("session export policy is unavailable")
	}
	s.discardExternalGit = discard
	return nil
}

func (s *Session) RecoveryStateWithPendingExport(reason string, result ExportResult) recovery.State {
	state := s.RecoveryState(reason)
	state.PendingExport = &recovery.PendingExport{
		MergedRoot:      result.MergedRoot,
		MergedDigest:    result.Merged.Digest,
		ChangeSetDigest: result.ChangeSet.Digest,
	}
	return state
}

// DetachForRecovery releases process-scoped locks only after the host recovery
// record is durable. It never removes the stopped VM or its runtime root.
func (s *Session) DetachForRecovery(ctx context.Context) error {
	current, err := s.cfg.Runtime.ContainerState(ctx, s.Container)
	if err != nil || current != runtime.StateStopped {
		return fmt.Errorf("refusing to detach a recovery VM that is not stopped: state=%s error=%v", current, err)
	}
	if (s.cfg.Mode != "dev" && s.cfg.Mode != "secure") || s.leaseCreated || s.gatewayActive.Load() {
		return fmt.Errorf("refusing to detach an active session for recovery")
	}
	if err := s.closeDevNetwork(ctx); err != nil {
		return err
	}
	s.vmCreated = false
	return s.Close()
}

func (s *Session) RetainForRecovery(ctx context.Context) error {
	return errors.Join(s.stopDevForRecovery(ctx), s.DetachForRecovery(ctx))
}

func (s *Session) startRevokedGatewaysForExport() error {
	rejected := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
	})
	server, done, err := s.startUnixGateway("model-gateway.sock", rejected)
	if err != nil {
		return err
	}
	s.gatewayServer, s.gatewayDone = server, done
	if s.cfg.GitGateway != nil {
		server, done, err = s.startUnixGateway("git-gateway.sock", rejected)
		if err != nil {
			return err
		}
		s.gitGatewayServer, s.gitGatewayDone = server, done
	}
	if s.cfg.WebGateway != nil {
		server, done, err = s.startUnixGateway("web-gateway.sock", rejected)
		if err != nil {
			return err
		}
		s.webGatewayServer, s.webGatewayDone = server, done
	}
	return nil
}

func (s *Session) mountPausedWorkspaceForExport(ctx context.Context) error {
	script := strings.Join([]string{
		"set -eu",
		"test -d /var/lib/sunaba/lower",
		"test -f /var/lib/sunaba/overlay.img",
		"if ! grep -Fqs ' /var/lib/sunaba/overlay ' /proc/mounts; then mount -o loop,nosuid,nodev /var/lib/sunaba/overlay.img /var/lib/sunaba/overlay; fi",
		"if ! grep -Fqs ' " + s.WorkspacePath + " ' /proc/mounts; then mount -t overlay overlay -o lowerdir=/var/lib/sunaba/lower,upperdir=/var/lib/sunaba/overlay/upper,workdir=/var/lib/sunaba/overlay/work " + s.WorkspacePath + "; fi",
		"grep -Fqs ' " + s.WorkspacePath + " ' /proc/mounts",
	}, "\n")
	if out, err := s.cfg.Runtime.ExecOutput(ctx, s.Container, []string{"/bin/bash", "-lc", script}); err != nil {
		return fmt.Errorf("remount paused workspace for export: %w: %s", err, approval.SanitizeText(out))
	}
	return nil
}

func (s *Session) prepareGuestExport(ctx context.Context) error {
	script := strings.Join([]string{
		"set -eu",
		"server_pid=$(cat /run/sunaba/server.pid 2>/dev/null || true)",
		"test -z \"$server_pid\" || kill -TERM \"$server_pid\" 2>/dev/null || true",
		"pkill -TERM -u 1000 -f '.*' 2>/dev/null || true",
		"pkill -TERM guest-relay 2>/dev/null || true",
		"for attempt in $(seq 1 50); do if { test -z \"$server_pid\" || ! kill -0 \"$server_pid\" 2>/dev/null; } && ! pgrep -u 1000 -f '.*' >/dev/null && ! pgrep guest-relay >/dev/null; then break; fi; sleep 0.02; done",
		"test -z \"$server_pid\" || kill -KILL \"$server_pid\" 2>/dev/null || true",
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
		if info.Labels["dev.sunaba.owner"] != "sunaba-supervisor" || info.Labels["dev.sunaba.project"] != s.ProjectID || info.Labels["dev.sunaba.vm"] != s.VMID {
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
	if err := s.closeDevNetwork(ctx); err != nil {
		destroyErr = errors.Join(destroyErr, err)
	}
	return errors.Join(destroyErr, s.Close())
}

func (s *Session) closeDevNetwork(ctx context.Context) error {
	if s.cfg.Mode != "dev" || s.cfg.DevNetworkClose == nil {
		return nil
	}
	var closeErr error
	s.devCloseOnce.Do(func() {
		closeErr = s.cfg.DevNetworkClose(ctx)
		if closeErr == nil {
			closeErr = s.emit("dev_network.revoked", s.cfg.DevNetworkName)
		}
	})
	return closeErr
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
	if s.cfg.ModelGatewayClose != nil {
		s.modelCloseOnce.Do(func() { stopErr = errors.Join(stopErr, s.cfg.ModelGatewayClose()) })
	}
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
		if err := s.closeDevNetwork(ctx); err != nil && s.closeErr == nil {
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
		if s.vmGuard != nil {
			if err := s.vmGuard.Close(); err != nil && s.closeErr == nil {
				s.closeErr = err
			}
			s.vmGuard = nil
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
	if s.Root == "" || filepath.Dir(s.Root) != s.cfg.RuntimeBase || filepath.Base(s.Root) != "sunaba-vm-"+s.VMID {
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
