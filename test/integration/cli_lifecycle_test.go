//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/projectconfig"
	"sunaba/internal/state"
)

func TestPublicCLIPersistentSupervisorAndSanitizedConsole(t *testing.T) {
	if os.Getenv("SUNABA_CLI_INTEGRATION") != "1" {
		t.Skip("set SUNABA_CLI_INTEGRATION=1 on the pinned macOS/Apple Container host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	runtimeBase, err := os.MkdirTemp("/private/tmp", "sunaba-cli-integration-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runtimeBase, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(runtimeBase)
	project := filepath.Join(runtimeBase, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	writeIntegrationFile(t, filepath.Join(project, "baseline.txt"), "baseline\n")
	sunaba := buildHostBinary(t, ctx, runtimeBase, "sunaba", "./cmd/sunaba")
	copyBundledSunabaUI(t, runtimeBase)
	_ = buildHostBinary(t, ctx, runtimeBase, "sunaba-git-hook", "./cmd/sunaba-git-hook")
	_ = buildLinuxBinary(t, ctx, runtimeBase, "sunaba-guest-relay", "./cmd/sunaba-guest-relay")
	xdg := filepath.Join(runtimeBase, "data")
	environment := append(os.Environ(), "XDG_DATA_HOME="+xdg, "XDG_CONFIG_HOME="+filepath.Join(runtimeBase, "config"))
	runSunaba := func(input string, args ...string) (string, error) {
		command := exec.CommandContext(ctx, sunaba, args...)
		command.Env = environment
		command.Stdin = strings.NewReader(input)
		output, err := command.CombinedOutput()
		return string(output), err
	}
	if output, err := runSunaba("", "setup"); err != nil {
		t.Fatalf("setup: %v: %s", err, output)
	}
	if output, err := runSunaba("host-only-integration-placeholder-key\n", "credentials", "openai", "api-key", "set"); err != nil {
		t.Fatalf("credential setup: %v: %s", err, output)
	}
	if output, err := runSunaba("", "model", "auth", "api-key"); err != nil {
		t.Fatalf("global model auth setup: %v: %s", err, output)
	}
	if output, err := runSunaba("", "project", "init", project, "--mode", "secure"); err != nil {
		t.Fatalf("project init: %v: %s", err, output)
	}
	projectID := state.ProjectID(project)
	up, err := runSunaba("", "up", "--project-id", projectID)
	if err != nil || !strings.Contains(up, "prepared and paused in secure mode") {
		t.Fatalf("up error=%v output=%s", err, up)
	}
	projectState := filepath.Join(xdg, "sunaba", "projects", projectID)
	locator := filepath.Join(projectState, "active-approval-control.json")
	cleaned := false
	defer func() {
		if !cleaned {
			_, _ = runSunaba("", "destroy", "--project-id", projectID, "--yes", "--discard-pending")
		}
	}()
	status, err := runSunaba("", "status", "--project-id", projectID)
	if err != nil || !strings.Contains(status, "=paused/secure") {
		t.Fatalf("paused status after up error=%v output=%s", err, status)
	}
	firstShell := "printf persistent > persistent.txt\nprintf '\\033]52;c;evil\\a\\n'\n"
	first, err := runSunaba(firstShell, "console", "--project-id", projectID)
	if err != nil {
		t.Fatalf("first shell: %v: %s", err, first)
	}
	if strings.ContainsAny(first, "\x1b\a") || !strings.Contains(first, "<U+001B>") || !strings.Contains(first, "[SUNABA_EXIT=0]") {
		t.Fatalf("shell terminal sanitizer output=%q", first)
	}
	paused, err := runSunaba("", "status", "--dir", project)
	if err != nil || !strings.Contains(paused, "=paused/secure") {
		t.Fatalf("paused status error=%v output=%s", err, paused)
	}
	configStore := &projectconfig.Store{Root: filepath.Join(runtimeBase, "config", "sunaba")}
	config, rules, err := configStore.Load(projectID)
	if err != nil {
		t.Fatal(err)
	}
	config.Session.TTLSeconds++
	if err := configStore.Save(projectID, config, rules); err != nil {
		t.Fatal(err)
	}
	configApplied, err := runSunaba("", "config", "apply", "--project-id", projectID)
	if err != nil || !strings.Contains(configApplied, "Application (next-session): session") || !strings.Contains(configApplied, "active Session is unchanged") {
		t.Fatalf("paused next-Session config apply error=%v output=%s", err, configApplied)
	}
	second, err := runSunaba("cat persistent.txt\n", "console", "--dir", project)
	if err != nil || !strings.Contains(second, "persistent") {
		t.Fatalf("persistent shell state error=%v output=%s", err, second)
	}
	exported, err := runSunaba("", "changes", "export", "--project-id", projectID)
	if err != nil || !strings.Contains(exported, "persistent.txt") || !strings.Contains(exported, "Change Set:") {
		t.Fatalf("CLI export error=%v output=%s", err, exported)
	}
	config, rules, err = configStore.Load(projectID)
	if err != nil {
		t.Fatal(err)
	}
	config.Model.MaxRequests--
	if err := configStore.Save(projectID, config, rules); err != nil {
		t.Fatal(err)
	}
	configApplied, err = runSunaba("", "config", "apply", "--project-id", projectID)
	if err != nil || !strings.Contains(configApplied, "Application (next-session): model") {
		t.Fatalf("pending Change Set blocked unrelated config apply error=%v output=%s", err, configApplied)
	}
	reviewed, err := runSunaba("", "changes", "review", "--project-id", projectID)
	if err != nil || !strings.Contains(reviewed, "SUNABA HOST CHANGE SET REVIEW") || !strings.Contains(reviewed, "+persistent") {
		t.Fatalf("CLI review error=%v output=%s", err, reviewed)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Lstat(locator); errors.Is(err, os.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("supervisor locator remained after export")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := os.RemoveAll(project); err != nil {
		t.Fatal(err)
	}
	if output, err := runSunaba("", "destroy", "--project-id", projectID, "--yes", "--discard-pending"); err != nil {
		t.Fatalf("destroy: %v: %s", err, output)
	}
	cleaned = true
	if _, err := os.Lstat(projectState); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Project state remained after destroy: %v", err)
	}
}
