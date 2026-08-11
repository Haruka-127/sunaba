package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPruneRemovesOnlyExpiredValidatedAuditLogs(t *testing.T) {
	root := filepath.Join(t.TempDir(), "audit")
	recorder, err := NewRecorder(root)
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"audit-20260101.jsonl", "audit-20260805.jsonl", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(project, name), []byte("fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := recorder.Prune(7*24*time.Hour, time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC))
	if err != nil || removed != 1 {
		t.Fatalf("removed=%d error=%v", removed, err)
	}
	if _, err := os.Lstat(filepath.Join(project, "audit-20260101.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("expired audit log remained: %v", err)
	}
	for _, name := range []string{"audit-20260805.jsonl", "notes.txt"} {
		if _, err := os.Lstat(filepath.Join(project, name)); err != nil {
			t.Fatalf("retained file %s missing: %v", name, err)
		}
	}
}

func TestPruneRefusesSymlinkAuditLog(t *testing.T) {
	root := filepath.Join(t.TempDir(), "audit")
	recorder, err := NewRecorder(root)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(project, "audit-20200101.jsonl")); err != nil {
		t.Fatal(err)
	}
	if _, err := recorder.Prune(24*time.Hour, time.Now()); err == nil {
		t.Fatal("symlink audit log was not rejected")
	}
	outside, _ := os.ReadFile(target)
	if string(outside) != "outside" {
		t.Fatal("retention followed an audit symlink")
	}
}
