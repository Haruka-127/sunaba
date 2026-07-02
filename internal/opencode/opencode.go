package opencode

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
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
	if _, err := exec.LookPath("container"); err != nil {
		return fmt.Errorf("container CLI not found. Install apple/container, then run 'container system start'")
	}
	if _, err := exec.LookPath("opencode"); err != nil {
		return fmt.Errorf("opencode CLI not found. Install OpenCode CLI; desktop app is not sufficient")
	}
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, "container", "system", "status").CombinedOutput()
	if err != nil || !strings.Contains(strings.ToLower(string(out)), "running") {
		return fmt.Errorf("container system is not running. Run 'container system start'")
	}
	return nil
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
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	var last error
	for {
		h, err := GetHealth(deadline, url, password)
		if err == nil {
			return h, nil
		}
		last = err
		select {
		case <-deadline.Done():
			return Health{}, fmt.Errorf("server health did not become ready: %w", last)
		case <-t.C:
		}
	}
}

func GetHealth(ctx context.Context, url, password string) (Health, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(url, "/")+"/global/health", nil)
	if err != nil {
		return Health{}, err
	}
	req.SetBasicAuth("opencode", password)
	client := &http.Client{Timeout: 10 * time.Second}
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

func Attach(ctx context.Context, url, dir, password string) error {
	cmd := exec.CommandContext(ctx, "opencode", "attach", url, "--dir", dir)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "OPENCODE_SERVER_PASSWORD="+password, "OPENCODE_SERVER_USERNAME=opencode")
	return cmd.Run()
}
