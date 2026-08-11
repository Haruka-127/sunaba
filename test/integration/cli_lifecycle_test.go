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
	sunaba := buildHostBinary(t, ctx, runtimeBase, "sunaba", "./cmd/sunaba")
	_ = buildHostBinary(t, ctx, runtimeBase, "sunaba-git-hook", "./cmd/sunaba-git-hook")
	_ = buildLinuxBinary(t, ctx, runtimeBase, "sunaba-guest-relay", "./cmd/sunaba-guest-relay")
	xdg := filepath.Join(runtimeBase, "data")
	environment := append(os.Environ(), "XDG_DATA_HOME="+xdg, "OPENAI_API_KEY=host-only-integration-placeholder")
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
	logPath := filepath.Join(runtimeBase, "supervisor-process.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	supervisor := exec.Command(sunaba, "_supervisor", "--dir", project)
	supervisor.Env = environment
	supervisor.Stdin = nil
	supervisor.Stdout = logFile
	supervisor.Stderr = logFile
	if err := supervisor.Start(); err != nil {
		logFile.Close()
		t.Fatal(err)
	}
	_ = logFile.Close()
	supervisorDone := make(chan error, 1)
	go func() { supervisorDone <- supervisor.Wait() }()
	projectState := filepath.Join(xdg, "sunaba", "projects", state.ProjectID(project))
	locator := filepath.Join(projectState, "active-approval-control.json")
	deadline := time.Now().Add(3 * time.Minute)
	for {
		if _, err := os.Lstat(locator); err == nil {
			break
		}
		select {
		case err := <-supervisorDone:
			logData, _ := os.ReadFile(logPath)
			t.Fatalf("supervisor startup: %v: %s", err, logData)
		default:
		}
		if time.Now().After(deadline) {
			_ = supervisor.Process.Signal(os.Interrupt)
			logData, _ := os.ReadFile(logPath)
			t.Fatalf("supervisor locator timeout: %s", logData)
		}
		time.Sleep(100 * time.Millisecond)
	}
	cleaned := false
	defer func() {
		if !cleaned {
			_, _ = runSunaba("", "destroy", "--dir", project, "--yes", "--discard-pending")
			_ = supervisor.Process.Signal(os.Interrupt)
		}
	}()
	status, err := runSunaba("", "status", "--dir", project)
	if err != nil || !strings.Contains(status, "=running/secure") {
		t.Fatalf("running status error=%v output=%s", err, status)
	}
	firstShell := "printf persistent > persistent.txt\nprintf '\\033]52;c;evil\\a\\n'\n"
	first, err := runSunaba(firstShell, "shell", "--dir", project)
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
	exported, err := runSunaba("", "changes", "export", "--dir", project)
	if err != nil || !strings.Contains(exported, "persistent.txt") || !strings.Contains(exported, "Change Set:") {
		t.Fatalf("CLI export error=%v output=%s", err, exported)
	}
	select {
	case err := <-supervisorDone:
		if err != nil {
			t.Fatalf("supervisor exit after export: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("supervisor did not exit after export")
	}
	if output, err := runSunaba("", "destroy", "--dir", project, "--yes", "--discard-pending"); err != nil {
		t.Fatalf("destroy: %v: %s", err, output)
	}
	cleaned = true
	if _, err := os.Lstat(projectState); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Project state remained after destroy: %v", err)
	}
}
