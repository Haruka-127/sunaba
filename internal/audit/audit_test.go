package audit

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSSE(t *testing.T) {
	input := "event: x\ndata: {\"a\":1}\n\n:data ignored\ndata: hello\ndata: world\n\n"
	var got []string
	err := ParseSSE(bufio.NewScanner(strings.NewReader(input)), func(b []byte) error {
		got = append(got, string(b))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "{\"a\":1}" || got[1] != "hello\nworld" {
		t.Fatalf("got %#v", got)
	}
}

func TestAuditCommandMatchesProject(t *testing.T) {
	if !auditCommandMatches("/tmp/sunaba _audit --project abc123", "abc123") {
		t.Fatal("expected matching audit command")
	}
	if auditCommandMatches("/tmp/sunaba _audit --project other", "abc123") {
		t.Fatal("matched a different project")
	}
	if auditCommandMatches("/tmp/unrelated --project abc123", "abc123") {
		t.Fatal("matched an unrelated process")
	}
}

func TestRemovePIDIfOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.pid")
	if err := os.WriteFile(path, []byte("123\n"), 0600); err != nil {
		t.Fatal(err)
	}
	removePIDIfOwner(path, 456)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("removed another process's pid file: %v", err)
	}
	removePIDIfOwner(path, 123)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("pid file still exists: %v", err)
	}
}
