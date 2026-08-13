package versionconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sunaba/internal/dependency"
)

func TestConfigValidation(t *testing.T) {
	for _, config := range []Config{
		BootstrapConfig(),
		{SchemaVersion: 1, OpenCode: Selection{Strategy: "exact", Value: "1.99.0"}},
		{SchemaVersion: 1, OpenCode: Selection{Strategy: "channel", Value: "v1-stable"}},
	} {
		if err := config.Validate(); err != nil {
			t.Fatalf("valid config rejected: %v", err)
		}
	}
	for _, value := range []string{"latest", "2.0.0", "v1.18.16", "1.01.0"} {
		config := Config{SchemaVersion: 1, OpenCode: Selection{Strategy: "exact", Value: value}}
		if err := config.Validate(); err == nil {
			t.Fatalf("invalid exact version %q accepted", value)
		}
	}
}

func TestStoreRoundTripAndRejectsUnsafeFile(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "sunaba")
	store := &Store{Root: root}
	config := BootstrapConfig()
	if err := store.SaveConfig(config); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadConfig()
	if err != nil || loaded != config {
		t.Fatalf("loaded config=%+v error=%v", loaded, err)
	}
	lock := Lock{SchemaVersion: 1, Generation: 1, ResolvedAt: time.Now().UTC().Truncate(time.Second), Manifest: dependency.MustPinned()}
	if err := store.SaveLock(lock); err != nil {
		t.Fatal(err)
	}
	loadedLock, err := store.LoadLock()
	if err != nil || loadedLock.Generation != 1 || loadedLock.Manifest.OpenCode.Version != dependency.OpenCodeVersion {
		t.Fatalf("loaded lock=%+v error=%v", loadedLock, err)
	}
	paths, _ := store.Paths()
	if err := os.Chmod(paths.Config, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadConfig(); err == nil || !strings.Contains(err.Error(), "mode 0600") {
		t.Fatalf("unsafe mode error=%v", err)
	}
}

func TestStoreRejectsUnknownFieldsAndTrailingData(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "sunaba")
	store := &Store{Root: root}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	paths, _ := store.Paths()
	for _, content := range []string{
		`{"schema_version":1,"opencode":{"strategy":"exact","value":"1.18.16"},"extra":true}`,
		`{"schema_version":1,"opencode":{"strategy":"exact","value":"1.18.16"}} {}`,
	} {
		if err := os.WriteFile(paths.Config, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadConfig(); err == nil {
			t.Fatalf("unsafe JSON accepted: %s", content)
		}
	}
}
