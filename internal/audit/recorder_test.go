package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRecorderDurablyAppendsConcurrentSanitizedEvents(t *testing.T) {
	root := filepath.Join(t.TempDir(), "audit")
	recorder, err := NewRecorder(root)
	if err != nil {
		t.Fatal(err)
	}
	recorder.Now = func() time.Time { return time.Date(2026, 8, 11, 1, 2, 3, 0, time.UTC) }
	const count = 32
	var wait sync.WaitGroup
	errors := make(chan error, count)
	for i := 0; i < count; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errors <- recorder.Append(BoundaryEvent{Category: "session", Action: "gateway.request", Outcome: "allowed", ProjectID: "project", VMID: "vm", SessionID: "session", Details: map[string]string{"reason": "guest\x1b]8;;fake\a\ntext"}})
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	filename := filepath.Join(root, "project", "audit-20260811.jsonl")
	info, err := os.Stat(filename)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("audit mode=%v error=%v", info.Mode(), err)
	}
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	seen := 0
	for scanner.Scan() {
		var event BoundaryEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		if event.Version != 1 || strings.ContainsAny(event.Details["reason"], "\x1b\n\a") || !strings.Contains(event.Details["reason"], "<U+001B>") {
			t.Fatalf("unsafe event=%+v", event)
		}
		seen++
	}
	if err := scanner.Err(); err != nil || seen != count {
		t.Fatalf("records=%d error=%v", seen, err)
	}
}

func TestRecorderRejectsSensitiveKeysAndUnsafeFilesystemObjects(t *testing.T) {
	root := filepath.Join(t.TempDir(), "audit")
	recorder, err := NewRecorder(root)
	if err != nil {
		t.Fatal(err)
	}
	event := BoundaryEvent{Category: "gateway", Action: "request", Outcome: "allowed", ProjectID: "project", Details: map[string]string{"token": "secret"}}
	if err := recorder.Append(event); err == nil {
		t.Fatal("sensitive audit detail was accepted")
	}
	projectDir := filepath.Join(root, "project")
	if err := os.Mkdir(projectDir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(projectDir, "audit-20260811.jsonl")
	if err := os.Symlink(target, log); err != nil {
		t.Fatal(err)
	}
	recorder.Now = func() time.Time { return time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC) }
	event.Details = map[string]string{"reason": "safe"}
	if err := recorder.Append(event); err == nil {
		t.Fatal("symlink audit log was accepted")
	}
}
