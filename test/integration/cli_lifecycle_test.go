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

	"sunaba/internal/state"
)

func TestPublicCLIPersistentSupervisorAndSanitizedShell(t *testing.T) {
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
	fakeSecurity := filepath.Join(runtimeBase, "security")
	writeIntegrationFile(t, fakeSecurity, "#!/bin/sh\ncase \"$1\" in\n  login-keychain) printf '\"%s\"\\n' '"+filepath.Join(runtimeBase, "login.keychain-db")+"' ;;\n  find-generic-password) printf '%s\\n' 'host-only-integration-placeholder-key' ;;\n  *) exit 2 ;;\nesac\n")
	if err := os.Chmod(fakeSecurity, 0700); err != nil {
		t.Fatal(err)
	}
	sunaba := buildHostBinaryWithLDFlags(t, ctx, runtimeBase, "sunaba", "./cmd/sunaba", "-X sunaba/internal/secretstore.commandPath="+fakeSecurity)
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
	first, err := runSunaba(firstShell, "shell", "--project-id", projectID)
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
	second, err := runSunaba("cat persistent.txt\n", "shell", "--dir", project)
	if err != nil || !strings.Contains(second, "persistent") {
		t.Fatalf("persistent shell state error=%v output=%s", err, second)
	}
	exported, err := runSunaba("", "changes", "export", "--project-id", projectID)
	if err != nil || !strings.Contains(exported, "persistent.txt") || !strings.Contains(exported, "Change Set:") {
		t.Fatalf("CLI export error=%v output=%s", err, exported)
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
