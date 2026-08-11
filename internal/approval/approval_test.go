package approval

import (
	"strings"
	"testing"
	"time"
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

func testBinding() Binding {
	return Binding{ProjectID: "project", BaselineDigest: strings.Repeat("a", 64), MergedDigest: strings.Repeat("b", 64), ChangeSetDigest: strings.Repeat("c", 64)}
}
