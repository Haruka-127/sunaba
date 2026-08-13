package opencode

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sunaba/internal/dependency"
	"sunaba/internal/securefs"
)

type HostTUIConfig struct {
	Binary                   string
	ManagedToolDir           string
	VerifiedExecutable       *VerifiedHostTUIExecutable
	SessionRoot              string
	ServerURL                string
	GuestWorkspace           string
	Password                 string
	ExpectedExecutableSHA256 string
}

// VerifiedHostTUIExecutable is an opaque, short-lived proof that the pinned
// Host TUI executable passed its digest and version checks. Callers cannot
// construct one without running VerifyHostTUIExecutable.
type VerifiedHostTUIExecutable struct {
	binary         string
	managedToolDir string
	info           os.FileInfo
}

func VerifyHostTUIExecutable(ctx context.Context, managedToolDir, binary, expectedDigest string) (*VerifiedHostTUIExecutable, error) {
	return VerifyHostTUIExecutableVersion(ctx, managedToolDir, binary, expectedDigest, dependency.OpenCodeVersion)
}

func VerifyHostTUIExecutableVersion(ctx context.Context, managedToolDir, binary, expectedDigest, expectedVersion string) (*VerifiedHostTUIExecutable, error) {
	if !filepath.IsAbs(managedToolDir) || !filepath.IsAbs(binary) {
		return nil, fmt.Errorf("managed tool directory and OpenCode binary must be absolute")
	}
	canonicalTools, err := filepath.EvalSymlinks(managedToolDir)
	if err != nil {
		return nil, err
	}
	canonicalBinary, err := filepath.EvalSymlinks(binary)
	if err != nil {
		return nil, err
	}
	relativeBinary, err := filepath.Rel(canonicalTools, canonicalBinary)
	if err != nil || relativeBinary == "." || relativeBinary == ".." || strings.HasPrefix(relativeBinary, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("OpenCode binary must be inside the managed tool directory")
	}
	info, err := os.Lstat(canonicalBinary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return nil, fmt.Errorf("managed OpenCode binary is not executable")
	}
	if err := verifyExecutableDigest(canonicalBinary, expectedDigest); err != nil {
		return nil, err
	}
	versionCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(versionCtx, canonicalBinary, "--version").Output()
	if err != nil {
		return nil, fmt.Errorf("read managed OpenCode version: %w", err)
	}
	if err := validateOpenCodeVersionFor(string(output), expectedVersion); err != nil {
		return nil, err
	}
	verifiedInfo, err := os.Lstat(canonicalBinary)
	if err != nil || !sameExecutable(info, verifiedInfo) {
		return nil, fmt.Errorf("managed OpenCode binary changed during verification")
	}
	return &VerifiedHostTUIExecutable{binary: canonicalBinary, managedToolDir: canonicalTools, info: verifiedInfo}, nil
}

func (v *VerifiedHostTUIExecutable) currentBinary() (string, error) {
	if v == nil || v.binary == "" || v.managedToolDir == "" || v.info == nil {
		return "", fmt.Errorf("verified Host TUI executable is missing")
	}
	info, err := os.Lstat(v.binary)
	if err != nil || !sameExecutable(v.info, info) {
		return "", fmt.Errorf("managed OpenCode binary changed after verification")
	}
	return v.binary, nil
}

func sameExecutable(before, after os.FileInfo) bool {
	return before != nil && after != nil && os.SameFile(before, after) &&
		before.Mode() == after.Mode() && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

func BuildHostTUICommand(ctx context.Context, cfg HostTUIConfig, hostEnvironment []string) (*exec.Cmd, error) {
	canonicalSession, binary, err := validateHostTUIConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	tuiRoot := filepath.Join(canonicalSession, "host-tui")
	for _, directory := range []string{
		tuiRoot,
		filepath.Join(tuiRoot, "home"),
		filepath.Join(tuiRoot, "config"),
		filepath.Join(tuiRoot, "data"),
		filepath.Join(tuiRoot, "state"),
		filepath.Join(tuiRoot, "cache"),
	} {
		if err := ensurePrivateDirectory(directory); err != nil {
			return nil, err
		}
	}
	args := []string{"attach", cfg.ServerURL, "--dir", cfg.GuestWorkspace, "--pure"}
	command := exec.CommandContext(ctx, binary, args...)
	command.Dir = tuiRoot
	command.Env = isolatedHostTUIEnvironment(hostEnvironment, tuiRoot, cfg.Password)
	return command, nil
}

func validateHostTUIConfig(ctx context.Context, cfg HostTUIConfig) (sessionRoot, binary string, err error) {
	if !filepath.IsAbs(cfg.SessionRoot) || !strings.HasPrefix(filepath.Base(cfg.SessionRoot), "sunaba-session-") {
		return "", "", fmt.Errorf("Host TUI session root must be an absolute sunaba-session-* directory")
	}
	info, err := os.Lstat(cfg.SessionRoot)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return "", "", fmt.Errorf("Host TUI session root must be a mode 0700 directory")
	}
	sessionRoot, err = filepath.EvalSymlinks(cfg.SessionRoot)
	if err != nil {
		return "", "", err
	}
	verified := cfg.VerifiedExecutable
	if verified == nil {
		verified, err = VerifyHostTUIExecutable(ctx, cfg.ManagedToolDir, cfg.Binary, cfg.ExpectedExecutableSHA256)
		if err != nil {
			return "", "", err
		}
	}
	binary, err = verified.currentBinary()
	if err != nil {
		return "", "", err
	}
	parsedURL, err := url.Parse(cfg.ServerURL)
	if err != nil || parsedURL.Scheme != "http" || parsedURL.User != nil || parsedURL.Path != "" || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return "", "", fmt.Errorf("Host TUI server URL must be a plain loopback HTTP origin")
	}
	host, port, err := net.SplitHostPort(parsedURL.Host)
	if err != nil || host != "127.0.0.1" || port == "" {
		return "", "", fmt.Errorf("Host TUI server URL must use 127.0.0.1 and an explicit port")
	}
	if !filepath.IsAbs(cfg.GuestWorkspace) || !strings.HasPrefix(cfg.GuestWorkspace, "/workspace/sunaba-") {
		return "", "", fmt.Errorf("guest workspace must be an absolute session-unique /workspace/sunaba-* path")
	}
	if _, err := os.Lstat(cfg.GuestWorkspace); err == nil {
		return "", "", fmt.Errorf("guest workspace path unexpectedly exists on the host")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", err
	}
	if len(cfg.Password) < 32 || strings.ContainsAny(cfg.Password, "\r\n\x00") {
		return "", "", fmt.Errorf("Host TUI server password must be a high-entropy session secret")
	}
	return sessionRoot, binary, nil
}

func verifyExecutableDigest(binary, expected string) error {
	expectedBytes, err := hex.DecodeString(expected)
	if err != nil || len(expectedBytes) != sha256.Size {
		return fmt.Errorf("managed OpenCode executable digest is invalid")
	}
	file, err := os.Open(binary)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(hash.Sum(nil), expectedBytes) != 1 {
		return fmt.Errorf("managed OpenCode executable digest does not match dependency contract")
	}
	return nil
}

func ensurePrivateDirectory(directory string) error {
	return securefs.EnsureOwnedDir(directory)
}

func isolatedHostTUIEnvironment(hostEnvironment []string, tuiRoot, password string) []string {
	environment := make([]string, 0, 24)
	for _, key := range []string{"PATH", "TERM", "COLORTERM", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "SHELL"} {
		if value := environmentValue(hostEnvironment, key); value != "" {
			environment = append(environment, key+"="+value)
		}
	}
	values := map[string]string{
		"HOME":                             filepath.Join(tuiRoot, "home"),
		"XDG_CONFIG_HOME":                  filepath.Join(tuiRoot, "config"),
		"XDG_DATA_HOME":                    filepath.Join(tuiRoot, "data"),
		"XDG_STATE_HOME":                   filepath.Join(tuiRoot, "state"),
		"XDG_CACHE_HOME":                   filepath.Join(tuiRoot, "cache"),
		"OPENCODE_CONFIG":                  filepath.Join(tuiRoot, "config", "opencode.json"),
		"OPENCODE_CONFIG_DIR":              filepath.Join(tuiRoot, "config"),
		"OPENCODE_TUI_CONFIG":              filepath.Join(tuiRoot, "config", "tui.json"),
		"OPENCODE_DISABLE_PROJECT_CONFIG":  "1",
		"OPENCODE_DISABLE_DEFAULT_PLUGINS": "1",
		"OPENCODE_DISABLE_AUTOUPDATE":      "1",
		"OPENCODE_DISABLE_MODELS_FETCH":    "1",
		"OPENCODE_DISABLE_LSP_DOWNLOAD":    "1",
		"OPENCODE_SERVER_USERNAME":         "opencode",
		"OPENCODE_SERVER_PASSWORD":         password,
		"EDITOR":                           "/usr/bin/false",
		"VISUAL":                           "/usr/bin/false",
		"NO_PROXY":                         "127.0.0.1,localhost",
		"no_proxy":                         "127.0.0.1,localhost",
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := values[key]
		environment = append(environment, key+"="+value)
	}
	return environment
}
