package lease

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLeasePersistsTransitionsAndExpiry(t *testing.T) {
	now := time.Unix(100, 0)
	root := filepath.Join(t.TempDir(), "leases")
	registry := &Registry{Root: root, Now: func() time.Time { return now }}
	record, err := registry.Register("project", "vm", "session", "model", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != Active || registry.ValidateActive("project", "vm", "session", "model") != nil {
		t.Fatalf("active record=%+v", record)
	}
	if _, err := registry.Pause("session"); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(registry.ValidateActive("project", "vm", "session", "model"), ErrInactive) {
		t.Fatal("paused lease remained active")
	}
	reloaded := &Registry{Root: root, Now: func() time.Time { return now }}
	if record, err := reloaded.Load("session"); err != nil || record.State != Paused {
		t.Fatalf("reloaded record=%+v error=%v", record, err)
	}
	if _, err := reloaded.Activate("session"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if !errors.Is(reloaded.ValidateActive("project", "vm", "session", "model"), ErrInactive) {
		t.Fatal("expired lease remained active")
	}
	if _, err := reloaded.Revoke("session"); err != nil {
		t.Fatal(err)
	}
	if _, err := reloaded.Activate("session"); err == nil {
		t.Fatal("revoked lease was reactivated")
	}
	info, err := os.Stat(filepath.Join(root, "session.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("lease file mode=%v error=%v", info.Mode(), err)
	}
}

func TestLeaseRejectsIdentitySubstitutionAndSymlinkRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "leases")
	registry := &Registry{Root: root}
	if _, err := registry.Register("project", "vm", "session", "model", time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, identity := range [][4]string{{"other", "vm", "session", "model"}, {"project", "other", "session", "model"}, {"project", "vm", "session", "git"}} {
		if err := registry.ValidateActive(identity[0], identity[1], identity[2], identity[3]); !errors.Is(err, ErrInactive) {
			t.Fatalf("substitution=%v error=%v", identity, err)
		}
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "leases")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Registry{Root: link}).Register("project", "vm", "other", "model", time.Minute); err == nil {
		t.Fatal("symlink lease registry was accepted")
	}
}

func TestRegisterPausedNeverCreatesAnInitiallyActiveLease(t *testing.T) {
	registry := &Registry{Root: filepath.Join(t.TempDir(), "leases")}
	record, err := registry.RegisterPaused("project", "vm", "session", "model", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != Paused || !errors.Is(registry.ValidateActive("project", "vm", "session", "model"), ErrInactive) {
		t.Fatalf("initial record=%+v", record)
	}
}

func TestGuardDetectsLiveSupervisorAndReleasesOnClose(t *testing.T) {
	registry := &Registry{Root: filepath.Join(t.TempDir(), "leases")}
	if _, err := registry.RegisterPaused("project", "vm", "session", "model", time.Minute); err != nil {
		t.Fatal(err)
	}
	first, err := registry.AcquireGuard("session")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&Registry{Root: registry.Root}).AcquireGuard("session"); !errors.Is(err, ErrGuardHeld) {
		t.Fatalf("second guard error=%v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := (&Registry{Root: registry.Root}).AcquireGuard("session")
	if err != nil {
		t.Fatalf("released guard remained held: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}
