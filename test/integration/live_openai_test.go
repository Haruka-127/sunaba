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

	"sunaba/internal/secretstore"
)

func TestLiveOpenAIThroughAgentVM(t *testing.T) {
	if os.Getenv("SUNABA_LIVE_OPENAI") != "1" {
		t.Skip("set SUNABA_LIVE_OPENAI=1 to authorize one billable OpenAI request through the host credential file and an Agent VM")
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
	key, err := secretstore.LoadOpenAIKey(ctx)
	if err != nil {
		t.Fatalf("a real API key in the host credential file is required before the live gate: %v", err)
	}
	sunaba := buildHostBinary(t, ctx, runtimeBase, "sunaba", "./cmd/sunaba")
	copyBundledSunabaUI(t, runtimeBase)
	_ = buildLinuxBinary(t, ctx, runtimeBase, "sunaba-guest-relay", "./cmd/sunaba-guest-relay")
	_ = buildHostBinary(t, ctx, runtimeBase, "sunaba-git-hook", "./cmd/sunaba-git-hook")
	environment := append(os.Environ(), "XDG_DATA_HOME="+filepath.Join(runtimeBase, "data"), "XDG_CONFIG_HOME="+filepath.Join(runtimeBase, "config"))
	runSunaba := func(input string, args ...string) (string, error) {
		command := exec.CommandContext(ctx, sunaba, args...)
		command.Env = environment
		command.Stdin = strings.NewReader(input)
		output, runErr := command.CombinedOutput()
		return string(output), runErr
	}
	if output, err := runSunaba(key+"\n", "credentials", "openai", "api-key", "set"); err != nil {
		t.Fatalf("copy real API key into isolated host credential state: %v: %s", err, output)
	}
	key = ""
	if output, err := runSunaba("", "model", "auth", "api-key"); err != nil {
		t.Fatalf("select global API key authentication: %v: %s", err, output)
	}
	if output, err := runSunaba("", "setup"); err != nil {
		t.Fatalf("setup: %v: %s", err, output)
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
	output, err := runSunaba(request+"\n", "console", "--dir", project)
	if err != nil || !strings.Contains(output, "SUNABA_LIVE_OK") || !strings.Contains(output, `"status":"completed"`) {
		t.Fatalf("live OpenAI response contract failed: %v: %s", err, output)
	}
	if output, err := runSunaba("", "destroy", "--dir", project, "--yes", "--discard-pending"); err != nil {
		t.Fatalf("destroy: %v: %s", err, output)
	}
	cleaned = true
}
