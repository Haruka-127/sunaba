package firewall

import (
	"reflect"
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
	for _, want := range []string{"pass in quick", "port 53", "flags A/A", "block drop", "to self"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %s", want, got)
		}
	}
	if strings.Index(got, "flags A/A") > strings.Index(got, "block drop") {
		t.Fatalf("ACK pass rule must precede block rule:\n%s", got)
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
