package usersettings

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sunaba/internal/modelcatalog"
)

func TestFreshSettingsDefaultToOAuthWithoutWriting(t *testing.T) {
	store := testStore(t)
	settings, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if settings != Default() || settings.ModelAuth != modelcatalog.AuthOAuth {
		t.Fatalf("fresh settings=%+v", settings)
	}
	paths, _ := store.Paths()
	if _, err := os.Lstat(paths.Settings); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read created global settings: %v", err)
	}
}

func TestStoreRoundTripsStrictOwnerOnlySettings(t *testing.T) {
	store := testStore(t)
	if err := store.SetModelAuth(modelcatalog.AuthAPIKey); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil || loaded.ModelAuth != modelcatalog.AuthAPIKey {
		t.Fatalf("loaded=%+v error=%v", loaded, err)
	}
	paths, _ := store.Paths()
	for _, path := range []string{paths.Directory} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Fatalf("unsafe directory %s mode=%v error=%v", path, info.Mode(), err)
		}
	}
	for _, path := range []string{paths.Settings, paths.Lock} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatalf("unsafe file %s mode=%v error=%v", path, info.Mode(), err)
		}
	}
	encoded, err := os.ReadFile(paths.Settings)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "api_key_value") || !strings.Contains(string(encoded), `"model_auth": "api_key"`) {
		t.Fatalf("unexpected settings JSON: %s", encoded)
	}
}

func TestStoreRejectsMalformedUnknownTrailingAndUnsafeSettings(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
	}{
		{"unknown", `{"schema_version":1,"model_auth":"oauth","extra":true}`},
		{"trailing", `{"schema_version":1,"model_auth":"oauth"} {}`},
		{"mode", `{"schema_version":1,"model_auth":"automatic"}`},
		{"control", "{\"schema_version\":1,\"model_auth\":\"oauth\\u000a\"}"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := testStore(t)
			if err := store.Save(Default()); err != nil {
				t.Fatal(err)
			}
			paths, _ := store.Paths()
			if err := os.WriteFile(paths.Settings, []byte(test.data), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Load(); err == nil {
				t.Fatalf("invalid settings were accepted: %s", test.data)
			}
		})
	}

	t.Run("malformed replacement", func(t *testing.T) {
		store := testStore(t)
		if err := store.Save(Default()); err != nil {
			t.Fatal(err)
		}
		paths, _ := store.Paths()
		if err := os.WriteFile(paths.Settings, []byte(`{"schema_version":1,"model_auth":"oauth","unknown":true}`), 0600); err != nil {
			t.Fatal(err)
		}
		if err := store.SetModelAuth(modelcatalog.AuthAPIKey); err == nil {
			t.Fatal("invalid existing settings were overwritten")
		}
	})

	t.Run("mode", func(t *testing.T) {
		store := testStore(t)
		if err := store.Save(Default()); err != nil {
			t.Fatal(err)
		}
		paths, _ := store.Paths()
		if err := os.Chmod(paths.Settings, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(); err == nil {
			t.Fatal("mode 0644 settings were accepted")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		store := testStore(t)
		if err := store.Save(Default()); err != nil {
			t.Fatal(err)
		}
		paths, _ := store.Paths()
		target := filepath.Join(filepath.Dir(paths.Directory), "other-settings.json")
		if err := os.WriteFile(target, []byte(`{"schema_version":1,"model_auth":"oauth"}`), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(paths.Settings); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, paths.Settings); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(); err == nil {
			t.Fatal("symlink settings were accepted")
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		store := testStore(t)
		if err := store.Save(Default()); err != nil {
			t.Fatal(err)
		}
		paths, _ := store.Paths()
		link := filepath.Join(paths.Directory, "settings-copy.json")
		if err := os.Link(paths.Settings, link); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(); err == nil {
			t.Fatal("hard-linked settings were accepted")
		}
		if err := store.Save(Default()); err == nil {
			t.Fatal("hard-linked settings were replaced")
		}
	})
}

func TestConcurrentSettingsWritersLeaveOneCompleteDocument(t *testing.T) {
	store := testStore(t)
	errorsOut := make(chan error, 20)
	for index := 0; index < cap(errorsOut); index++ {
		mode := modelcatalog.AuthOAuth
		if index%2 == 0 {
			mode = modelcatalog.AuthAPIKey
		}
		go func() { errorsOut <- store.SetModelAuth(mode) }()
	}
	for index := 0; index < cap(errorsOut); index++ {
		if err := <-errorsOut; err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ModelAuth != modelcatalog.AuthOAuth && loaded.ModelAuth != modelcatalog.AuthAPIKey {
		t.Fatalf("corrupt concurrent result: %+v", loaded)
	}
}

func testStore(t *testing.T) *Store {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &Store{Root: filepath.Join(base, "config", "sunaba")}
}
