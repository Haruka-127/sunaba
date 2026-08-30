package configwizard

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/policy"
	"sunaba/internal/projectconfig"
	"sunaba/internal/webgateway"
)

func TestWizardConfiguresGitGatewayAndAppliesOnlyAfterConfirmation(t *testing.T) {
	config, rules := testConfig(t)
	input := strings.NewReader("\n\ny\n\norigin\nhttps://git.example/team/project.git\n\n\n\ny\n")
	var output bytes.Buffer
	result, err := Run(input, &output, config, rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Config.Git.Remotes) != 1 || result.Config.Git.Remotes[0].Name != "origin" || result.Config.Git.Remotes[0].URL != "https://git.example/team/project.git" {
		t.Fatalf("unexpected Git configuration: %+v", result.Config.Git)
	}
	if !strings.Contains(output.String(), "Use the Git Gateway?") || !strings.Contains(output.String(), "each push requires host approval") {
		t.Fatalf("wizard output did not describe Git configuration: %s", output.String())
	}
}

func TestWizardOffersDetectedProjectRemoteWithoutAutomaticallyEnablingIt(t *testing.T) {
	config, rules := testConfig(t)
	suggested := policy.GitRemotePolicy{Name: "origin", URL: "https://git.example/team/detected.git"}
	input := strings.NewReader("\n\ny\n\n\n\n\ny\n")
	var output bytes.Buffer
	result, err := RunWithOptions(input, &output, config, rules, Options{SuggestedGitRemotes: []policy.GitRemotePolicy{suggested}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Config.Git.Remotes) != 1 || result.Config.Git.Remotes[0] != suggested {
		t.Fatalf("detected remote was not explicitly selected: %+v", result.Config.Git.Remotes)
	}
	if !strings.Contains(output.String(), "detected in the Project") {
		t.Fatalf("detected remote prompt missing: %s", output.String())
	}
}

func TestWizardCancelAndEOFReturnNoCandidate(t *testing.T) {
	config, rules := testConfig(t)
	for _, input := range []string{"q\n", "\n\n\n\n\nn\n", ""} {
		var output bytes.Buffer
		result, err := Run(strings.NewReader(input), &output, config, rules)
		if !errors.Is(err, ErrCanceled) {
			t.Fatalf("input=%q result=%+v error=%v", input, result, err)
		}
		if result.Config.ProjectRoot != "" || result.Rules != nil {
			t.Fatalf("canceled wizard returned a candidate: %+v", result)
		}
	}
}

func TestWizardRequiresExplicitDevConfirmationAndFixedCatalogModels(t *testing.T) {
	config, rules := testConfig(t)
	// Select dev but reject its warning, then choose the first and second
	// displayed OAuth catalog models. Authentication itself is not a Project
	// wizard choice.
	input := strings.NewReader("2\nn\ny\n1,2\n\n\n\ny\n")
	var output bytes.Buffer
	result, err := Run(input, &output, config, rules)
	if err != nil {
		t.Fatal(err)
	}
	if result.Config.Mode != "secure" {
		t.Fatalf("dev mode was selected without confirmation: %s", result.Config.Mode)
	}
	if len(result.Config.Model.AllowedModels) != 2 {
		t.Fatalf("unexpected Model configuration: %+v", result.Config.Model)
	}
	if !strings.Contains(output.String(), "does not guarantee prevention of data exfiltration") || !strings.Contains(output.String(), "Allowed models") || strings.Contains(output.String(), "authentication method") {
		t.Fatalf("wizard warning/catalog output missing: %s", output.String())
	}
}

func TestWizardConfiguresExplicitWebOriginAndShowsTunnelLimit(t *testing.T) {
	config, rules := testConfig(t)
	input := strings.NewReader("\n\n\ny\nn\n\nhttps://docs.example\ny\n\n\ny\n")
	var output bytes.Buffer
	result, err := Run(input, &output, config, rules)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Config.Web.Enabled || len(result.Rules) != 1 || result.Rules[0].Host != "docs.example" || !result.Rules[0].IncludeSubdomains {
		t.Fatalf("unexpected Web configuration: enabled=%t rules=%+v", result.Config.Web.Enabled, result.Rules)
	}
	if !strings.Contains(output.String(), "without TLS termination") || !strings.Contains(output.String(), "uploaded content inside it cannot be identified or guaranteed") {
		t.Fatalf("Web tunnel warning missing: %s", output.String())
	}
}

func TestWizardEnablesBuiltInWebPresetWithoutRequiringCustomOrigin(t *testing.T) {
	config, rules := testConfig(t)
	input := strings.NewReader(strings.Join([]string{"", "", "", "y", "", "", "", "y"}, "\n") + "\n")
	var output bytes.Buffer
	result, err := Run(input, &output, config, rules)
	if err != nil {
		t.Fatal(err)
	}
	resolved, _, err := projectconfig.ResolveWebRules(result.Config, result.Rules)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Config.Web.Enabled || len(result.Config.Web.OriginPresets) != 1 || result.Config.Web.OriginPresets[0] != webgateway.CommonDevelopmentOriginPreset || len(result.Rules) != 0 || len(resolved) == 0 {
		t.Fatalf("unexpected preset Web configuration: config=%+v custom=%+v resolved=%d", result.Config.Web, result.Rules, len(resolved))
	}
	if !strings.Contains(output.String(), "broad allowlist") || !strings.Contains(output.String(), "resolved=") {
		t.Fatalf("preset warning or summary missing: %s", output.String())
	}
}

func TestAdvancedWizardEditsBoundedResources(t *testing.T) {
	config, _ := testConfig(t)
	scanner := bufio.NewScanner(strings.NewReader("4\n" + strings.Repeat("\n", 14)))
	scanner.Buffer(make([]byte, 256), maximumInputLine)
	w := &wizard{scanner: scanner, output: &bytes.Buffer{}}
	if err := w.advanced(&config); err != nil {
		t.Fatal(err)
	}
	if config.Resources.CPUs != 4 || config.Resources.FileSizeMax != config.Resources.DiskBytes {
		t.Fatalf("advanced resource settings were not applied safely: %+v", config.Resources)
	}
}

func TestAdvancedWizardRejectsWebQuotaAboveGatewayMaximum(t *testing.T) {
	config, _ := testConfig(t)
	config.Web.Enabled = true
	input := strings.Repeat("\n", 12) + "33\n"
	scanner := bufio.NewScanner(strings.NewReader(input))
	scanner.Buffer(make([]byte, 256), maximumInputLine)
	w := &wizard{scanner: scanner, output: &bytes.Buffer{}}
	if err := w.advanced(&config); err == nil {
		t.Fatal("oversized Web concurrency was accepted")
	}
}

func TestWizardRejectsOversizedAndTerminalControlInput(t *testing.T) {
	config, rules := testConfig(t)
	oversized := strings.Repeat("a", maximumInputLine+1) + "\n"
	if _, err := Run(strings.NewReader(oversized), &bytes.Buffer{}, config, rules); err == nil {
		t.Fatal("oversized input was accepted")
	}
	if _, err := Run(strings.NewReader("\x1b[31m\n"), &bytes.Buffer{}, config, rules); err == nil {
		t.Fatal("terminal control input was accepted")
	}
}

func testConfig(t *testing.T) (projectconfig.Config, []webgateway.OriginRule) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	effective, err := policy.New(project, strings.Repeat("a", 64), "1.18.16", "1.2.2", "sunaba-base:test", "secure", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return projectconfig.FromPolicy(effective)
}
