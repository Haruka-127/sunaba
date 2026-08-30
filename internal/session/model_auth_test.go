package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sunaba/internal/modelcatalog"
	"sunaba/internal/usersettings"
)

func TestLoadModelAuthSnapshotUsesFreshOAuthAndRejectsIncompatibleAllowlist(t *testing.T) {
	store := authSettingsStore(t)
	snapshot, err := LoadModelAuthSnapshot(store, []string{"gpt-5.5"})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Mode != modelcatalog.AuthOAuth || len(snapshot.Models) != 1 || snapshot.Models[0].Limit.Input != 272_000 {
		t.Fatalf("OAuth snapshot=%+v", snapshot)
	}
	if _, err := LoadModelAuthSnapshot(store, []string{"gpt-5"}); err == nil || !strings.Contains(err.Error(), "gpt-5") || !strings.Contains(err.Error(), "sunaba model set") {
		t.Fatalf("incompatible allowlist error=%v", err)
	}
}

func TestModelAuthSnapshotDoesNotFallbackAndExistingSnapshotIsImmutable(t *testing.T) {
	store := authSettingsStore(t)
	if err := store.SetModelAuth(modelcatalog.AuthOAuth); err != nil {
		t.Fatal(err)
	}
	active, err := LoadModelAuthSnapshot(store, []string{"gpt-5.5"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetModelAuth(modelcatalog.AuthAPIKey); err != nil {
		t.Fatal(err)
	}
	running := &Session{modelAuth: cloneModelAuthSnapshot(active)}
	next, err := LoadModelAuthSnapshot(store, []string{"gpt-5.5"})
	if err != nil {
		t.Fatal(err)
	}
	if active.Mode != modelcatalog.AuthOAuth || active.Models[0].Cost.Input != 0 {
		t.Fatalf("active snapshot changed after settings update: %+v", active)
	}
	if got := running.ModelAuthentication(); got.Mode != modelcatalog.AuthOAuth || got.Models[0].Cost.Input != 0 {
		t.Fatalf("active Session authority changed after settings update: %+v", got)
	}
	if next.Mode != modelcatalog.AuthAPIKey || next.Models[0].Cost.Input == 0 {
		t.Fatalf("next snapshot did not use API key metadata: %+v", next)
	}
	// OAuth is configured here; gpt-5 must be rejected even though the API-key
	// catalog and credential path could support it.
	if err := store.SetModelAuth(modelcatalog.AuthOAuth); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadModelAuthSnapshot(store, []string{"gpt-5"}); err == nil {
		t.Fatal("Session snapshot fell back from OAuth to API key")
	}
}

func TestSnapshotValidationRejectsForgedAuthenticationMetadata(t *testing.T) {
	snapshot, err := SnapshotModelAuth(usersettings.Default(), []string{"gpt-5.5"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Models[0].Limit.Input++
	if err := validateModelAuthSnapshot(snapshot); err == nil {
		t.Fatal("forged authentication-specific model metadata was accepted")
	}
}

func authSettingsStore(t *testing.T) *usersettings.Store {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "config"), 0700); err != nil {
		t.Fatal(err)
	}
	return &usersettings.Store{Root: filepath.Join(base, "config", "sunaba")}
}
