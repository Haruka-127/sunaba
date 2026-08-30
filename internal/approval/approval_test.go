package approval

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/audit"
)

func TestApprovalBindsDigestsAndIsOneShot(t *testing.T) {
	now := time.Unix(100, 0)
	manager := NewManager(func() time.Time { return now })
	binding := testBinding()
	request, err := manager.NewRequest(binding, "add evil\x1b]52;c;x\a\n\u202e.txt", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{"\x1b", "\a", "\u202e"} {
		if strings.Contains(request.Display, unsafe) {
			t.Fatalf("approval display retained unsafe text %q: %q", unsafe, request.Display)
		}
	}
	if !strings.Contains(request.Display, "<U+001B>") || !strings.Contains(request.Display, "<U+000A>") || !strings.Contains(request.Display, "<U+202E>") {
		t.Fatalf("approval display=%q", request.Display)
	}
	if strings.Contains(request.Display, request.Nonce) {
		t.Fatalf("approval display exposed internal nonce: %q", request.Display)
	}
	wrong := binding
	wrong.ChangeSetDigest = strings.Repeat("f", 64)
	if _, err := manager.Confirm(request.Nonce, wrong); err == nil {
		t.Fatal("digest substitution was accepted")
	}
	request, err = manager.NewRequest(binding, "safe", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := manager.Confirm(request.Nonce, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Consume(grant, binding); err != nil {
		t.Fatal(err)
	}
	if err := manager.Consume(grant, binding); err == nil {
		t.Fatal("approval grant was reusable")
	}
}

func TestApprovalExpiresAndConsumesNonceOnFailure(t *testing.T) {
	now := time.Unix(100, 0)
	manager := NewManager(func() time.Time { return now })
	request, err := manager.NewRequest(testBinding(), "safe", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if _, err := manager.Confirm(request.Nonce, testBinding()); err == nil {
		t.Fatal("expired approval was accepted")
	}
	now = time.Unix(100, 0)
	if _, err := manager.Confirm(request.Nonce, testBinding()); err == nil {
		t.Fatal("failed approval nonce was reusable")
	}
}

func TestAuditedApprovalRecordsBindingsWithoutSummaryContent(t *testing.T) {
	recorder, err := audit.NewRecorder(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewAuditedManager(nil, recorder, "project", "vm", "session")
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding()
	request, err := manager.NewRequest(binding, "secret summary content", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := manager.Confirm(request.Nonce, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Consume(grant, binding); err != nil {
		t.Fatal(err)
	}
	logs, err := filepath.Glob(filepath.Join(recorder.Root, "project", "audit-*.jsonl"))
	if err != nil || len(logs) != 1 {
		t.Fatalf("logs=%v error=%v", logs, err)
	}
	encoded, err := os.ReadFile(logs[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"approval.request", "approval.confirm", "approval.consume"} {
		if !strings.Contains(string(encoded), `"action":"`+action+`"`) {
			t.Fatalf("audit missing %s: %s", action, encoded)
		}
	}
	if strings.Contains(string(encoded), "secret summary content") || !strings.Contains(string(encoded), request.Nonce) {
		t.Fatalf("audit summary/nonce policy violated: %s", encoded)
	}
}

func testBinding() Binding {
	return Binding{ProjectID: "project", BaselineDigest: strings.Repeat("a", 64), MergedDigest: strings.Repeat("b", 64), ChangeSetDigest: strings.Repeat("c", 64)}
}
