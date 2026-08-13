package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/policy"
	"sunaba/internal/projectconfig"
	"sunaba/internal/securefs"
)

func TestPersistConfigAndPolicyRollsBackEveryFileBoundary(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	projectRoot := filepath.Join(base, "project")
	if err := os.Mkdir(projectRoot, 0700); err != nil {
		t.Fatal(err)
	}
	effective, err := policy.New(projectRoot, strings.Repeat("a", 64), "1.18.16", "1.2.2", "sunaba-base:test", "secure", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	configStore := &projectconfig.Store{Root: filepath.Join(base, "config", "sunaba")}
	projectState := filepath.Join(base, "state", effective.ProjectID)
	policyPath := filepath.Join(projectState, "policy.json")
	config, rules := projectconfig.FromPolicy(effective)
	if err := persistConfigAndPolicy(configStore, projectState, policyPath, config, rules, effective); err != nil {
		t.Fatal(err)
	}

	updated := effective
	updated.Session.TTLSeconds++
	updatedConfig, updatedRules := projectconfig.FromPolicy(updated)
	for failAt := 0; failAt < 3; failAt++ {
		err := persistConfigAndPolicyWithOptions(configStore, projectState, policyPath, updatedConfig, updatedRules, updated, securefs.TransactionOptions{BeforeReplace: func(index int, _ string) error {
			if index == failAt {
				return errors.New("injected replace failure")
			}
			return nil
		}})
		if err == nil {
			t.Fatalf("replacement %d failure was ignored", failAt)
		}
		loadedPolicy, _, err := policy.LoadReadOnly(policyPath, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		loadedConfig, loadedRules, err := configStore.Load(effective.ProjectID)
		if err != nil || loadedPolicy.Session.TTLSeconds != effective.Session.TTLSeconds || !projectconfig.Matches(loadedConfig, loadedRules, effective) {
			t.Fatalf("replacement %d left mixed state: policy=%+v config=%+v rules=%+v error=%v", failAt, loadedPolicy, loadedConfig, loadedRules, err)
		}
	}
}
