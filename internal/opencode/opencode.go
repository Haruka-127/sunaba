package opencode

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"sunaba/internal/dependency"
)

type Health struct {
	Version string `json:"version"`
}

func CheckPrerequisites(ctx context.Context) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("sunaba requires macOS with apple/container; current OS is %s", runtime.GOOS)
	}
	if runtime.GOARCH != "arm64" {
		return fmt.Errorf("sunaba requires Apple silicon (darwin/arm64); current arch is %s", runtime.GOARCH)
	}
	macVersion, err := commandOutput(ctx, 10*time.Second, "sw_vers", "-productVersion")
	if err != nil {
		return fmt.Errorf("cannot determine macOS version: %w", err)
	}
	if CompareVersion(macVersion, "26.0.0") < 0 {
		return fmt.Errorf("sunaba requires macOS 26 or later; current version is %s", macVersion)
	}
	if _, err := exec.LookPath("container"); err != nil {
		return fmt.Errorf("container CLI not found. Install apple/container, then run 'container system start'")
	}
	if _, err := exec.LookPath("opencode"); err != nil {
		return fmt.Errorf("opencode CLI %s not found", dependency.OpenCodeVersion)
	}
	hostVersion, err := HostVersion(ctx)
	if err != nil {
		return fmt.Errorf("cannot determine host OpenCode version: %w", err)
	}
	if err := validateOpenCodeVersion(hostVersion); err != nil {
		return err
	}
	containerVersionOutput, err := commandOutput(ctx, 10*time.Second, "container", "--version")
	if err != nil {
		return fmt.Errorf("cannot determine apple/container version: %w", err)
	}
	if err := validateAppleContainerVersion(containerVersionOutput); err != nil {
		return err
	}
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, "container", "system", "status").CombinedOutput()
	if err != nil || !strings.Contains(strings.ToLower(string(out)), "running") {
		return fmt.Errorf("container system is not running. Run 'container system start'")
	}
	return nil
}

func validateAppleContainerVersion(output string) error {
	containerVersion := firstSemanticVersion(output)
	if containerVersion == "" {
		return fmt.Errorf("cannot parse apple/container version from %q", output)
	}
	if CompareVersion(containerVersion, dependency.AppleContainerVersion) != 0 {
		return fmt.Errorf("sunaba requires exact apple/container %s; current version is %s", dependency.AppleContainerVersion, containerVersion)
	}
	return nil
}

func validateOpenCodeVersion(output string) error {
	version := strings.TrimPrefix(strings.TrimSpace(output), "v")
	if version != dependency.OpenCodeVersion {
		return fmt.Errorf("sunaba requires exact OpenCode %s for host TUI and guest server; current host version is %s", dependency.OpenCodeVersion, version)
	}
	return nil
}

func commandOutput(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(c, name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s failed: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func HostVersion(ctx context.Context) (string, error) {
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, "opencode", "--version").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func WaitHealth(ctx context.Context, url, password string, max time.Duration) (Health, error) {
	deadline, cancel := context.WithTimeout(ctx, max)
	defer cancel()
	// A published guest socket can accept a connection before OpenCode begins
	// listening behind it. Bound each readiness probe separately so that one
	// half-open startup connection cannot consume most of the overall deadline.
	client := DirectHTTPClient(200 * time.Millisecond)
	if transport, ok := client.Transport.(*http.Transport); ok {
		defer transport.CloseIdleConnections()
	}
	delay := 25 * time.Millisecond
	var last error
	for {
		h, err := getHealth(deadline, client, url, password)
		if err == nil {
			return h, nil
		}
		last = err
		timer := time.NewTimer(delay)
		select {
		case <-deadline.Done():
			timer.Stop()
			return Health{}, fmt.Errorf("server health did not become ready: %w", last)
		case <-timer.C:
		}
		if delay < 100*time.Millisecond {
			delay *= 2
			if delay > 100*time.Millisecond {
				delay = 100 * time.Millisecond
			}
		}
	}
}

func GetHealth(ctx context.Context, url, password string) (Health, error) {
	client := DirectHTTPClient(10 * time.Second)
	if transport, ok := client.Transport.(*http.Transport); ok {
		defer transport.CloseIdleConnections()
	}
	return getHealth(ctx, client, url, password)
}

func getHealth(ctx context.Context, client *http.Client, url, password string) (Health, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(url, "/")+"/global/health", nil)
	if err != nil {
		return Health{}, err
	}
	req.SetBasicAuth("opencode", password)
	resp, err := client.Do(req)
	if err != nil {
		return Health{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Health{}, fmt.Errorf("health returned %s", resp.Status)
	}
	var h Health
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return Health{}, err
	}
	return h, nil
}

// DirectHTTPClient returns a client for host-to-VM communication. These
// requests carry the server password and must never be sent through a proxy
// configured in the host environment.
func DirectHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{Timeout: timeout, Transport: transport}
}

func environmentValue(env []string, key string) string {
	prefix := key + "="
	for i := len(env) - 1; i >= 0; i-- {
		if strings.HasPrefix(env[i], prefix) {
			return strings.TrimPrefix(env[i], prefix)
		}
	}
	return ""
}
