package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

const (
	SecureGatewayGuestPath    = "/run/sunaba/model-gateway.sock"
	SecureGitGatewayGuestPath = "/run/sunaba/git-gateway.sock"
	SecureWebGatewayGuestPath = "/run/sunaba/web-gateway.sock"
	SecureAttachGuestPath     = "/run/sunaba/attach.sock"
)

var secureIdentityPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

type SecureSessionPolicy struct {
	ProjectID   string `json:"project_id"`
	SessionID   string `json:"session_id"`
	Mode        string `json:"mode"`
	NetworkName string `json:"network_name,omitempty"`
	Image       string `json:"image"`
	SessionRoot string `json:"session_root"`
	CPUs        int    `json:"cpus"`
	Memory      string `json:"memory"`
	DiskBytes   int64  `json:"disk_bytes"`
	ProcessMax  int64  `json:"process_max"`
	FileSizeMax int64  `json:"file_size_max"`
	OpenFileMax int64  `json:"open_file_max"`
	GitGateway  bool   `json:"git_gateway"`
	WebGateway  bool   `json:"web_gateway"`
}

func (p SecureSessionPolicy) Digest() (string, error) {
	canonical, err := p.canonical()
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (p SecureSessionPolicy) canonical() (SecureSessionPolicy, error) {
	if !secureIdentityPattern.MatchString(p.ProjectID) || !secureIdentityPattern.MatchString(p.SessionID) {
		return SecureSessionPolicy{}, fmt.Errorf("secure Project and session identities must be explicit safe identifiers")
	}
	if p.Image == "" {
		return SecureSessionPolicy{}, fmt.Errorf("secure session image is required")
	}
	if p.Mode == "" {
		p.Mode = "secure"
	}
	if p.Mode != "secure" && p.Mode != "dev" {
		return SecureSessionPolicy{}, fmt.Errorf("session mode must be secure or dev")
	}
	wantNetwork := ""
	if p.Mode == "dev" {
		wantNetwork = "sunaba-" + p.ProjectID + "-" + p.SessionID + "-net"
	}
	if p.NetworkName != wantNetwork {
		return SecureSessionPolicy{}, fmt.Errorf("session network does not match mode and identity")
	}
	if p.CPUs <= 0 || p.Memory == "" || p.DiskBytes < 64<<20 || p.ProcessMax <= 0 || p.FileSizeMax != p.DiskBytes || p.OpenFileMax <= 0 {
		return SecureSessionPolicy{}, fmt.Errorf("secure session resource policy is invalid")
	}
	if !filepath.IsAbs(p.SessionRoot) || filepath.Base(p.SessionRoot) != "sunaba-session-"+p.SessionID {
		return SecureSessionPolicy{}, fmt.Errorf("secure session root must be an absolute session-bound sunaba directory")
	}
	info, err := os.Lstat(p.SessionRoot)
	if err != nil {
		return SecureSessionPolicy{}, fmt.Errorf("inspect secure session root: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return SecureSessionPolicy{}, fmt.Errorf("secure session root must be a mode 0700 directory")
	}
	canonicalRoot, err := filepath.EvalSymlinks(p.SessionRoot)
	if err != nil {
		return SecureSessionPolicy{}, err
	}
	p.SessionRoot = canonicalRoot
	return p, nil
}

func ValidateSecureSessionSpec(spec ContainerSpec, policy SecureSessionPolicy) error {
	canonical, err := policy.canonical()
	if err != nil {
		return err
	}
	digest, err := canonical.Digest()
	if err != nil {
		return err
	}
	if !secureIdentityPattern.MatchString(spec.Name) || len(spec.Name) < len("sunaba-") || spec.Name[:len("sunaba-")] != "sunaba-" {
		return fmt.Errorf("secure container name must be a safe sunaba-* identity")
	}
	if spec.Image != canonical.Image || spec.CPUs != canonical.CPUs || spec.Memory != canonical.Memory {
		return fmt.Errorf("secure image and resource limits must match host policy")
	}
	wantLimits := map[string]RLimit{
		"fsize":  {Soft: canonical.FileSizeMax, Hard: canonical.FileSizeMax},
		"nofile": {Soft: canonical.OpenFileMax, Hard: canonical.OpenFileMax},
		"nproc":  {Soft: canonical.ProcessMax, Hard: canonical.ProcessMax},
	}
	if len(spec.Ulimits) != len(wantLimits) {
		return fmt.Errorf("secure session requires exact hard process and file limits")
	}
	for name, expected := range wantLimits {
		if spec.Ulimits[name] != expected {
			return fmt.Errorf("secure session limit %q does not match host policy", name)
		}
	}
	if canonical.Mode == "secure" && (len(spec.Networks) != 1 || spec.Networks[0] != "none" || !spec.NoDNS) {
		return fmt.Errorf("secure session requires exactly --network none and --no-dns")
	}
	if canonical.Mode == "dev" && (len(spec.Networks) != 1 || spec.Networks[0] != canonical.NetworkName || spec.NoDNS) {
		return fmt.Errorf("dev session requires its exact dedicated network with DNS enabled")
	}
	if len(spec.EnvFiles) != 0 {
		return fmt.Errorf("secure session does not accept environment files")
	}
	if len(spec.Env) != 0 {
		return fmt.Errorf("secure session secrets and environment are copied after VM creation")
	}
	if len(spec.CapAdd) != 1 || spec.CapAdd[0] != "SYS_ADMIN" || len(spec.CapDrop) != 0 {
		return fmt.Errorf("secure session requires only SYS_ADMIN for its guest-local OverlayFS")
	}
	if spec.Entrypoint != "/bin/bash" || len(spec.Args) != 2 || spec.Args[0] != "-lc" || spec.Args[1] != "exec tail -f /dev/null" || spec.Workdir != "" || spec.ReadOnly {
		return fmt.Errorf("secure session bootstrap command does not match host policy")
	}
	wantMounts := 1
	if canonical.GitGateway {
		wantMounts = 2
	}
	if canonical.WebGateway {
		wantMounts++
	}
	if len(spec.Mounts) != wantMounts {
		return fmt.Errorf("secure session Gateway socket mount count does not match policy")
	}
	gatewayPath := filepath.Join(canonical.SessionRoot, "model-gateway.sock")
	mount := spec.Mounts[0]
	if mount.Type != "socket" || mount.Source != gatewayPath || mount.Target != SecureGatewayGuestPath || mount.ReadOnly {
		return fmt.Errorf("secure session Gateway mount does not match Project/session policy")
	}
	if err := validateHostUnixSocket(gatewayPath); err != nil {
		return err
	}
	if canonical.GitGateway {
		gitGatewayPath := filepath.Join(canonical.SessionRoot, "git-gateway.sock")
		gitMount := spec.Mounts[1]
		if gitMount.Type != "socket" || gitMount.Source != gitGatewayPath || gitMount.Target != SecureGitGatewayGuestPath || gitMount.ReadOnly {
			return fmt.Errorf("secure session Git Gateway mount does not match Project/session policy")
		}
		if err := validateHostUnixSocket(gitGatewayPath); err != nil {
			return err
		}
	}
	if canonical.WebGateway {
		webGatewayPath := filepath.Join(canonical.SessionRoot, "web-gateway.sock")
		webMount := spec.Mounts[wantMounts-1]
		if webMount.Type != "socket" || webMount.Source != webGatewayPath || webMount.Target != SecureWebGatewayGuestPath || webMount.ReadOnly {
			return fmt.Errorf("secure session Web Gateway mount does not match Project/session policy")
		}
		if err := validateHostUnixSocket(webGatewayPath); err != nil {
			return err
		}
	}
	if len(spec.Sockets) != 1 {
		return fmt.Errorf("secure session requires exactly one Project-bound attach socket")
	}
	attachPath := filepath.Join(canonical.SessionRoot, "attach.sock")
	if spec.Sockets[0].HostPath != attachPath || spec.Sockets[0].GuestPath != SecureAttachGuestPath {
		return fmt.Errorf("secure session attach socket does not match Project/session policy")
	}
	if _, err := os.Lstat(attachPath); err == nil {
		return fmt.Errorf("secure attach socket path already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	requiredLabels := map[string]string{
		"dev.sunaba.owner":         "sunaba-supervisor",
		"dev.sunaba.project":       canonical.ProjectID,
		"dev.sunaba.session":       canonical.SessionID,
		"dev.sunaba.mode":          canonical.Mode,
		"dev.sunaba.policy-digest": digest,
	}
	for key, expected := range requiredLabels {
		if spec.Labels[key] != expected {
			return fmt.Errorf("secure session label %q does not match host policy", key)
		}
	}
	return nil
}

func validateHostUnixSocket(socketPath string) error {
	info, err := os.Lstat(socketPath)
	if err != nil {
		return fmt.Errorf("inspect Gateway socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		return fmt.Errorf("Gateway endpoint must be a mode 0600 Unix socket")
	}
	return nil
}

func (r *AppleContainer) CreateSecure(ctx context.Context, spec ContainerSpec, policy SecureSessionPolicy) error {
	if err := ValidateSecureSessionSpec(spec, policy); err != nil {
		return fmt.Errorf("secure session configuration rejected: %w", err)
	}
	return r.Create(ctx, spec)
}
