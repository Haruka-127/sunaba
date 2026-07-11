package firewall

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestAnchorBlockIdempotent(t *testing.T) {
	base := "set skip on lo0\n"
	once := EnsureAnchorBlock(base)
	twice := EnsureAnchorBlock(once)
	if once != twice {
		t.Fatalf("not idempotent:\n%s\n---\n%s", once, twice)
	}
	if strings.Count(twice, beginMarker) != 1 {
		t.Fatal("duplicate marker")
	}
	removed := RemoveAnchorBlock(twice)
	if strings.Contains(removed, "sunaba") {
		t.Fatalf("not removed: %s", removed)
	}
	if !HasAnchorBlock(once) {
		t.Fatalf("expected anchor block to be detected:\n%s", once)
	}
	if HasAnchorBlock(base) {
		t.Fatal("unexpected anchor block detection")
	}
}

func TestGenerateRules(t *testing.T) {
	got := GenerateRules(Network{Interface: "bridge100", Subnet: "192.168.64.0/24", Gateway: "192.168.64.1"})
	for _, want := range []string{
		"pass in quick",
		"port 53",
		"flags A/A",
		"block drop in quick on bridge100 inet from 192.168.64.0/24 to self",
		"block drop in quick on bridge100 inet6 from any to self",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %s", want, got)
		}
	}
	if strings.Index(got, "flags A/A") > strings.Index(got, "block drop") {
		t.Fatalf("ACK pass rule must precede block rule:\n%s", got)
	}
}

func TestGeneratedRulesAcceptedByPF(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("pfctl is only available on macOS")
	}
	path := filepath.Join(t.TempDir(), "sunaba.rules")
	rules := GenerateRules(Network{Interface: "bridge100", Subnet: "192.168.64.0/24", Gateway: "192.168.64.1"})
	if err := os.WriteFile(path, []byte(rules), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/sbin/pfctl", "-a", "sunaba", "-nf", path).CombinedOutput()
	if err != nil {
		t.Fatalf("pfctl rejected generated rules: %v: %s", err, out)
	}
}

func TestValidateNetwork(t *testing.T) {
	valid := Network{Interface: "bridge100", Subnet: "192.168.64.0/24", Gateway: "192.168.64.1"}
	if err := ValidateNetwork(valid); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []Network{
		{Interface: "bridge100\nblock all", Subnet: valid.Subnet, Gateway: valid.Gateway},
		{Interface: valid.Interface, Subnet: "anything", Gateway: valid.Gateway},
		{Interface: valid.Interface, Subnet: valid.Subnet, Gateway: "anything"},
	} {
		if err := ValidateNetwork(invalid); err == nil {
			t.Fatalf("accepted invalid network: %#v", invalid)
		}
	}
}

func TestParseLivePFStateRequiresAllLayers(t *testing.T) {
	n := Network{Interface: "bridge100", Subnet: "192.168.64.0/24", Gateway: "192.168.64.1"}
	rules := GenerateRules(n)
	liveRules := strings.ReplaceAll(rules, "to self", "to 192.168.98.150")
	loaded := parseLivePFState("Status: Enabled", `anchor "sunaba" all`, liveRules, rules, n)
	if !loaded.loaded() {
		t.Fatalf("unexpected state: %#v", loaded)
	}
	missingMain := parseLivePFState("Status: Enabled", "pass all", liveRules, rules, n)
	if missingMain.MainAnchor {
		t.Fatalf("detached anchor reported as attached: %#v", missingMain)
	}
	if parseLivePFState("Status: Disabled", `anchor "sunaba" all`, liveRules, rules, n).Enabled {
		t.Fatal("disabled pf reported as enabled")
	}
	missingIPv6Rules := "block drop in quick on bridge100 inet from 192.168.64.0/24 to self\n"
	missingIPv6 := parseLivePFState("Status: Enabled", `anchor "sunaba" all`,
		strings.ReplaceAll(missingIPv6Rules, "to self", "to 192.168.98.150"), missingIPv6Rules, n)
	if missingIPv6.loaded() || !missingIPv6.IPv4Block || missingIPv6.IPv6Block {
		t.Fatalf("missing IPv6 block reported as loaded: %#v", missingIPv6)
	}
	staleLive := parseLivePFState("Status: Enabled", `anchor "sunaba" all`,
		strings.ReplaceAll(missingIPv6Rules, "to self", "to 192.168.98.150"), rules, n)
	if staleLive.loaded() || !staleLive.IPv4Block || staleLive.IPv6Block {
		t.Fatalf("stale live rules reported as loaded: %#v", staleLive)
	}
	staleFile := parseLivePFState("Status: Enabled", `anchor "sunaba" all`, liveRules, missingIPv6Rules, n)
	if staleFile.loaded() || !staleFile.IPv4Block || staleFile.IPv6Block {
		t.Fatalf("stale configured rules reported as loaded: %#v", staleFile)
	}
	wrongNetwork := Network{Interface: "bridge101", Subnet: "192.168.65.0/24", Gateway: "192.168.65.1"}
	stale := parseLivePFState("Status: Enabled", `anchor "sunaba" all`, liveRules, rules, wrongNetwork)
	if stale.loaded() || stale.IPv4Block || stale.IPv6Block {
		t.Fatalf("stale rules reported as loaded: %#v", stale)
	}
}

func TestWriteValidatedFileDoesNotReplaceOnValidationFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pf.conf")
	if err := os.WriteFile(path, []byte("original\n"), 0644); err != nil {
		t.Fatal(err)
	}
	err := writeValidatedFile(path, []byte("invalid\n"), 0644, func(string) error {
		return os.ErrInvalid
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
	b, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(b) != "original\n" {
		t.Fatalf("file changed after failed validation: %q", b)
	}
}

func TestSudoRerunArgs(t *testing.T) {
	tests := []struct {
		name   string
		action string
		argv   []string
		want   []string
	}{
		{
			name:   "from up without extra args",
			action: "enable",
			argv:   []string{"sunaba", "up"},
			want:   []string{"/tmp/sunaba", "firewall", "enable"},
		},
		{
			name:   "from up with flags does not leak up args",
			action: "enable",
			argv:   []string{"sunaba", "up", "--dir", "/tmp/project"},
			want:   []string{"/tmp/sunaba", "firewall", "enable"},
		},
		{
			name:   "from firewall command preserves firewall args",
			action: "status",
			argv:   []string{"sunaba", "--verbose", "firewall", "status", "--debug"},
			want:   []string{"/tmp/sunaba", "firewall", "status", "--debug"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sudoRerunArgs("/tmp/sunaba", tt.action, tt.argv)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}
