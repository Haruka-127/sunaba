package capability

import (
	"strings"
	"testing"
	"time"
)

func TestGateEnforcesTokenExpiryQuotaConcurrencyAndRevoke(t *testing.T) {
	now := time.Now()
	authority, err := NewAuthority(strings.Repeat("t", 32), Binding{ProjectID: "project", VMID: "vm", SessionID: "session"}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	gate, err := NewGate(authority, now.Add(time.Minute), 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, status := gate.Admit("wrong", now); status != InvalidToken {
		t.Fatalf("invalid token status=%v", status)
	}
	first, status := gate.Admit(strings.Repeat("t", 32), now)
	if status != Admitted {
		t.Fatalf("first admission status=%v", status)
	}
	if _, status := gate.Admit(strings.Repeat("t", 32), now); status != ConcurrencyExceeded {
		t.Fatalf("concurrent admission status=%v", status)
	}
	first.Release()
	second, status := gate.Admit(strings.Repeat("t", 32), now)
	if status != Admitted {
		t.Fatalf("second admission status=%v", status)
	}
	second.Release()
	if _, status := gate.Admit(strings.Repeat("t", 32), now); status != RequestQuotaExceeded {
		t.Fatalf("quota admission status=%v", status)
	}
	if used, limit := gate.Usage(); used != 3 || limit != 3 {
		t.Fatalf("usage=%d/%d", used, limit)
	}
	gate.Revoke()
	if _, status := gate.Admit(strings.Repeat("t", 32), now); status != Revoked {
		t.Fatalf("revoked admission status=%v", status)
	}
}

func TestAuthorityRejectsNonCanonicalIdentity(t *testing.T) {
	_, err := NewAuthority(strings.Repeat("t", 32), Binding{ProjectID: "project\n", VMID: "vm", SessionID: "session"}, time.Now().Add(time.Minute))
	if err == nil {
		t.Fatal("unsafe identity was accepted")
	}
}
