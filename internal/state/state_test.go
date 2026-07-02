package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProjectID(t *testing.T) {
	id := ProjectID("/Users/alice/work/myapp")
	if len(id) != 12 {
		t.Fatalf("len=%d", len(id))
	}
	if id != ProjectID("/Users/alice/work/myapp") {
		t.Fatal("ProjectID is not stable")
	}
}

func TestEnvRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "env")
	in := map[string]string{"GITHUB_TOKEN": "github_pat_xxx", "SUNABA_TEST": "abc"}
	if err := WriteEnvFile(path, in); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("mode=%v", st.Mode().Perm())
	}
	got, err := ReadEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range in {
		if got[k] != v {
			t.Fatalf("%s=%q", k, got[k])
		}
	}
}

func TestInvalidEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "env")
	if err := os.WriteFile(path, []byte("1BAD=x\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEnvFile(path); err == nil {
		t.Fatal("expected invalid env error")
	}
}

func TestEffectiveFirewallDisabled(t *testing.T) {
	tests := []struct {
		name    string
		global  string
		project string
		want    bool
	}{
		{name: "default enabled", want: false},
		{name: "global disabled", global: FirewallDisabled, want: true},
		{name: "project disabled", project: FirewallDisabled, want: true},
		{name: "project enabled overrides global disabled", global: FirewallDisabled, project: FirewallEnabled, want: false},
		{name: "project inherit uses global", global: FirewallDisabled, project: FirewallInherit, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EffectiveFirewallDisabled(GlobalConfig{FirewallMode: tt.global}, ProjectConfig{FirewallMode: tt.project})
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
