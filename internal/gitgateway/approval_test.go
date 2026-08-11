package gitgateway

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/audit"
)

func TestPushApprovalBindsObjectsForceDeleteAndIsOneShot(t *testing.T) {
	recorder, err := audit.NewRecorder(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewPushApprovalManager(nil, recorder, "vm", "session")
	if err != nil {
		t.Fatal(err)
	}
	binding := pushBinding()
	request, err := manager.NewRequest(binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	substituted := binding
	substituted.Updates = append([]RefUpdate(nil), binding.Updates...)
	substituted.Updates[0].New = strings.Repeat("d", 40)
	if _, err := manager.Confirm(request.Nonce, substituted); !errors.Is(err, ErrPushApprovalInvalid) {
		t.Fatalf("object substitution error=%v", err)
	}
	request, err = manager.NewRequest(binding, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := manager.Confirm(request.Nonce, binding)
	if err != nil {
		t.Fatal(err)
	}
	changed := binding
	changed.Updates = append([]RefUpdate(nil), binding.Updates...)
	changed.Updates[0].Force = true
	if err := manager.Consume(grant, changed); !errors.Is(err, ErrPushApprovalInvalid) {
		t.Fatalf("force substitution error=%v", err)
	}
	request, _ = manager.NewRequest(binding, time.Minute)
	grant, _ = manager.Confirm(request.Nonce, binding)
	if err := manager.Consume(grant, binding); err != nil {
		t.Fatal(err)
	}
	if err := manager.Consume(grant, binding); !errors.Is(err, ErrPushApprovalInvalid) {
		t.Fatal("push grant was reusable")
	}
}

func TestPushApprovalRejectsCredentialRemoteAndInconsistentDelete(t *testing.T) {
	recorder, _ := audit.NewRecorder(filepath.Join(t.TempDir(), "audit"))
	manager, _ := NewPushApprovalManager(nil, recorder, "vm", "session")
	binding := pushBinding()
	binding.RemoteURL = "https://token@example.com/repo.git"
	if _, err := manager.NewRequest(binding, time.Minute); err == nil {
		t.Fatal("credential-bearing remote was accepted")
	}
	binding = pushBinding()
	binding.Updates[0].Delete = true
	if _, err := manager.NewRequest(binding, time.Minute); err == nil {
		t.Fatal("inconsistent delete was accepted")
	}
}

func pushBinding() PushBinding {
	return PushBinding{
		ProjectID: "project", Repository: "origin-repository", RemoteName: "origin", RemoteURL: "HTTPS://Example.COM/repo.git",
		Updates: []RefUpdate{{Ref: "refs/heads/main", Old: strings.Repeat("a", 40), New: strings.Repeat("b", 40)}},
	}
}
