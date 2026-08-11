//go:build integration

package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLiveOpenAIThroughAgentVM(t *testing.T) {
	if os.Getenv("SUNABA_LIVE_OPENAI") != "1" {
		t.Skip("set SUNABA_LIVE_OPENAI=1 to authorize one billable OpenAI request through the macOS Keychain and an Agent VM")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	runtimeBase, err := os.MkdirTemp("/private/tmp", "sunaba-live-openai-")
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
	writeIntegrationFile(t, filepath.Join(project, "README.md"), "live OpenAI integration fixture\n")
	sunaba := buildHostBinary(t, ctx, runtimeBase, "sunaba", "./cmd/sunaba")
	_ = buildLinuxBinary(t, ctx, runtimeBase, "sunaba-guest-relay", "./cmd/sunaba-guest-relay")
	_ = buildHostBinary(t, ctx, runtimeBase, "sunaba-git-hook", "./cmd/sunaba-git-hook")
	environment := append(os.Environ(), "XDG_DATA_HOME="+filepath.Join(runtimeBase, "data"))
	runSunaba := func(input string, args ...string) (string, error) {
		command := exec.CommandContext(ctx, sunaba, args...)
		command.Env = environment
		command.Stdin = strings.NewReader(input)
		output, runErr := command.CombinedOutput()
		return string(output), runErr
	}
	if output, err := runSunaba("", "credentials", "openai", "status"); err != nil {
		t.Fatalf("OpenAI Keychain credential is required: %v: %s", err, output)
	}
	if output, err := runSunaba("", "project", "init", project, "--mode", "secure"); err != nil {
		t.Fatalf("project init: %v: %s", err, output)
	}
	cleaned := false
	defer func() {
		if !cleaned {
			_, _ = runSunaba("", "destroy", "--dir", project, "--yes", "--discard-pending")
		}
	}()
	if output, err := runSunaba("", "up", "--dir", project); err != nil {
		t.Fatalf("up: %v: %s", err, output)
	}
	request := `curl --silent --show-error --fail-with-body http://127.0.0.1:4141/v1/responses -H "Content-Type: application/json" -H "Authorization: Bearer $SUNABA_MODEL_GATEWAY_TOKEN" -d '{"model":"gpt-5","input":"Reply with exactly SUNABA_LIVE_OK.","max_output_tokens":256}'`
	output, err := runSunaba(request+"\n", "shell", "--dir", project)
	if err != nil || !strings.Contains(output, "SUNABA_LIVE_OK") || !strings.Contains(output, `"status":"completed"`) {
		t.Fatalf("live OpenAI response contract failed: %v: %s", err, output)
	}
	if output, err := runSunaba("", "destroy", "--dir", project, "--yes", "--discard-pending"); err != nil {
		t.Fatalf("destroy: %v: %s", err, output)
	}
	cleaned = true
}
