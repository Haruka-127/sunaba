package secretstore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const testAPIKey = "sk-test-0123456789abcdef0123456789"

func TestCredentialStorePreservesIndependentCredentials(t *testing.T) {
	_, path := prepareCredentialStore(t)
	firstOAuth := testOAuth("first")
	if err := StoreCodexOAuth(context.Background(), firstOAuth); err != nil {
		t.Fatal(err)
	}
	if err := StoreOpenAIKey(context.Background(), testAPIKey); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadOpenAIKey(context.Background()); err != nil || got != testAPIKey {
		t.Fatalf("API key length=%d error=%v", len(got), err)
	}
	if got, err := LoadCodexOAuth(context.Background()); err != nil || got != firstOAuth {
		t.Fatalf("OAuth=%+v error=%v", got, err)
	}
	secondOAuth := testOAuth("second")
	if err := StoreCodexOAuth(context.Background(), secondOAuth); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadOpenAIKey(context.Background()); err != nil || got != testAPIKey {
		t.Fatalf("OAuth update changed API key length=%d error=%v", len(got), err)
	}
	if err := DeleteCodexOAuth(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadOpenAIKey(context.Background()); err != nil || got != testAPIKey {
		t.Fatalf("OAuth delete changed API key length=%d error=%v", len(got), err)
	}
	if err := StoreCodexOAuth(context.Background(), firstOAuth); err != nil {
		t.Fatal(err)
	}
	if err := DeleteOpenAIKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadCodexOAuth(context.Background()); err != nil || got != firstOAuth {
		t.Fatalf("API key delete changed OAuth=%+v error=%v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("credential file mode=%v error=%v", info.Mode(), err)
	}
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil || stat.Nlink != 1 {
		t.Fatalf("credential file links=%d error=%v", stat.Nlink, err)
	}
	directory := filepath.Dir(path)
	lockPath := filepath.Join(directory, credentialLockName)
	for _, expected := range []struct {
		path string
		mode os.FileMode
	}{
		{directory, 0700},
		{lockPath, 0600},
	} {
		info, err := os.Stat(expected.path)
		if err != nil || info.Mode().Perm() != expected.mode {
			t.Fatalf("%s mode=%v error=%v", filepath.Base(expected.path), info.Mode(), err)
		}
		var stat syscall.Stat_t
		if err := syscall.Stat(expected.path, &stat); err != nil || stat.Uid != uint32(os.Geteuid()) || (expected.path == lockPath && stat.Nlink != 1) {
			t.Fatalf("%s owner=%d links=%d error=%v", filepath.Base(expected.path), stat.Uid, stat.Nlink, err)
		}
	}
}

func TestCredentialStoreUsesXDGDataHomeAndHomeFallback(t *testing.T) {
	for _, useXDG := range []bool{true, false} {
		t.Run(map[bool]string{true: "xdg", false: "home"}[useXDG], func(t *testing.T) {
			root := canonicalTempDir(t)
			if useXDG {
				t.Setenv("XDG_DATA_HOME", root)
			} else {
				t.Setenv("XDG_DATA_HOME", "")
				t.Setenv("HOME", root)
			}
			if err := StoreOpenAIKey(context.Background(), testAPIKey); err != nil {
				t.Fatal(err)
			}
			base := root
			if !useXDG {
				base = filepath.Join(root, ".local", "share")
			}
			path := filepath.Join(base, "sunaba", credentialDirectoryName, credentialFileName)
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("credential path %s: %v", path, err)
			}
		})
	}
	t.Setenv("XDG_DATA_HOME", "relative/path")
	if err := StoreOpenAIKey(context.Background(), testAPIKey); err == nil {
		t.Fatal("relative XDG_DATA_HOME was accepted")
	}
}

func TestCredentialStoreNormalizesAbsoluteXDGDataHome(t *testing.T) {
	root := canonicalTempDir(t)
	t.Setenv("XDG_DATA_HOME", root+string(filepath.Separator)+".")
	if err := StoreOpenAIKey(context.Background(), testAPIKey); err != nil {
		t.Fatalf("normalized XDG_DATA_HOME: %v", err)
	}
	path := filepath.Join(root, "sunaba", credentialDirectoryName, credentialFileName)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("credential path %s: %v", path, err)
	}
}

func TestUpdateCodexOAuthPreservesAPIKey(t *testing.T) {
	prepareCredentialStore(t)
	if err := StoreOpenAIKey(context.Background(), testAPIKey); err != nil {
		t.Fatal(err)
	}
	if err := StoreCodexOAuth(context.Background(), testOAuth("old")); err != nil {
		t.Fatal(err)
	}
	updated, err := UpdateCodexOAuth(context.Background(), func(current CodexOAuthCredential) (CodexOAuthCredential, error) {
		if current.RefreshToken != "refresh-token-old" {
			t.Fatalf("rotation loaded wrong credential")
		}
		return testOAuth("new"), nil
	})
	if err != nil || updated != testOAuth("new") {
		t.Fatalf("updated=%+v error=%v", updated, err)
	}
	if got, err := LoadOpenAIKey(context.Background()); err != nil || got != testAPIKey {
		t.Fatalf("rotation changed API key length=%d error=%v", len(got), err)
	}
}

func TestCredentialFileStrictJSONAndBounds(t *testing.T) {
	_, path := prepareCredentialStore(t)
	cases := map[string][]byte{
		"unknown":  []byte(`{"version":1,"unknown":true}`),
		"trailing": []byte(`{"version":1} {}`),
		"version":  []byte(`{"version":2}`),
		"control":  []byte("{\"version\":1,\"api_key\":\"sk-01234567890123456789\\u0000\"}"),
		"c1":       []byte("{\"version\":1,\"api_key\":\"sk-01234567890123456789\\u0085\"}"),
		"unicode":  []byte("{\"version\":1,\"api_key\":\"sk-01234567890123456789日本語\"}"),
		"space":    []byte("{\"version\":1,\"api_key\":\"sk-0123456789 123456789\"}"),
		"nested":   []byte(`{"version":1,"oauth":{"access_token":"access-token-value","refresh_token":"refresh-token-value","id_token":"identity-token-value","account_id":"account-id-value","expires_at":1800000000,"unknown":true}}`),
		"oversize": []byte(strings.Repeat(" ", maximumCredentialBytes+1)),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadOpenAIKey(context.Background()); err == nil {
				t.Fatal("invalid credential document was accepted")
			}
		})
	}
}

func TestCredentialStoreRejectsUnsafeDirectory(t *testing.T) {
	root, _ := prepareCredentialStore(t)
	directory, err := credentialDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if err := StoreOpenAIKey(context.Background(), testAPIKey); err == nil {
		t.Fatal("unsafe credential directory was accepted")
	}
	if err := os.RemoveAll(filepath.Join(root, "sunaba")); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "sunaba")); err != nil {
		t.Fatal(err)
	}
	if err := StoreOpenAIKey(context.Background(), testAPIKey); err == nil {
		t.Fatal("symlinked credential directory was accepted")
	}
}

func TestCredentialStoreRejectsUnsafeCredentialFile(t *testing.T) {
	_, path := prepareCredentialStore(t)
	valid := mustCredentialJSON(t)
	tests := []struct {
		name  string
		setup func(t *testing.T)
	}{
		{name: "mode", setup: func(t *testing.T) { writeMode(t, path, valid, 0644) }},
		{name: "symlink", setup: func(t *testing.T) {
			target := path + ".target"
			writeMode(t, target, valid, 0600)
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hardlink", setup: func(t *testing.T) {
			writeMode(t, path, valid, 0600)
			if err := os.Link(path, path+".alias"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "directory", setup: func(t *testing.T) {
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "fifo", setup: func(t *testing.T) {
			if err := syscall.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_ = os.RemoveAll(path)
			_ = os.Remove(path + ".alias")
			_ = os.Remove(path + ".target")
			test.setup(t)
			if _, err := LoadOpenAIKey(context.Background()); err == nil {
				t.Fatal("unsafe credential file was accepted")
			}
		})
	}
}

func TestCredentialStoreRejectsUnsafeLockFile(t *testing.T) {
	_, _ = prepareCredentialStore(t)
	directory, err := credentialDirectory()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, credentialLockName)
	tests := []struct {
		name  string
		setup func(t *testing.T)
	}{
		{name: "mode", setup: func(t *testing.T) { writeMode(t, path, nil, 0644) }},
		{name: "nonempty", setup: func(t *testing.T) { writeMode(t, path, []byte("x"), 0600) }},
		{name: "symlink", setup: func(t *testing.T) {
			target := path + ".target"
			writeMode(t, target, nil, 0600)
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hardlink", setup: func(t *testing.T) {
			writeMode(t, path, nil, 0600)
			if err := os.Link(path, path+".alias"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "directory", setup: func(t *testing.T) {
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_ = os.RemoveAll(path)
			_ = os.Remove(path + ".alias")
			_ = os.Remove(path + ".target")
			test.setup(t)
			if _, err := LoadOpenAIKey(context.Background()); err == nil {
				t.Fatal("unsafe credential lock was accepted")
			}
		})
	}
}

func TestCredentialLockHonorsContextAndSerializesProcesses(t *testing.T) {
	prepareCredentialStore(t)
	lock, _, err := acquireCredentialLock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := StoreOpenAIKey(ctx, testAPIKey); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked update error=%v", err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestCredentialStoreProcessHelper$")
	command.Env = append(os.Environ(), "SUNABA_CREDENTIAL_PROCESS_HELPER=1")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		t.Fatalf("helper bypassed process lock: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	if err := lock.close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		t.Fatal("helper did not acquire released process lock")
	}
}

func TestCredentialStoreProcessHelper(t *testing.T) {
	if os.Getenv("SUNABA_CREDENTIAL_PROCESS_HELPER") != "1" {
		return
	}
	if err := StoreOpenAIKey(context.Background(), testAPIKey); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentCredentialUpdatesLeaveValidCompleteDocument(t *testing.T) {
	_, path := prepareCredentialStore(t)
	var wait sync.WaitGroup
	for index := 0; index < 20; index++ {
		wait.Add(2)
		go func(index int) {
			defer wait.Done()
			key := "sk-concurrent-0123456789-" + string(rune('a'+index))
			if err := StoreOpenAIKey(context.Background(), key); err != nil {
				t.Errorf("API update: %v", err)
			}
		}(index)
		go func(index int) {
			defer wait.Done()
			credential := testOAuth("concurrent-" + string(rune('a'+index)))
			if err := StoreCodexOAuth(context.Background(), credential); err != nil {
				t.Errorf("OAuth update: %v", err)
			}
		}(index)
	}
	wait.Wait()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document credentialDocument
	if err := json.Unmarshal(data, &document); err != nil || validateCredentialDocument(document) != nil || document.APIKey == "" || document.OAuth == nil {
		t.Fatalf("final credential document is invalid: error=%v", err)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".sunaba-securefs-*.tmp"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary files=%v error=%v", matches, err)
	}
}

func TestCredentialErrorsDoNotContainSecrets(t *testing.T) {
	_, path := prepareCredentialStore(t)
	secret := "sk-secret-should-never-appear-0123456789"
	writeMode(t, path, []byte(`{"version":1,"api_key":"`+secret+`","unknown":true}`), 0600)
	_, err := LoadOpenAIKey(context.Background())
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe error=%q", err)
	}
	invalid := "short-secret"
	if err := StoreOpenAIKey(context.Background(), invalid); err == nil || strings.Contains(err.Error(), invalid) {
		t.Fatalf("unsafe validation error=%q", err)
	}
}

func TestCredentialImplementationContainsNoKeychainAccess(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	for _, directory := range []string{filepath.Dir(source), filepath.Join(filepath.Dir(source), "..", "openauth")} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"/usr/bin/security", "Security.framework", "SecKeychain", "os/exec"} {
				if strings.Contains(string(data), forbidden) {
					t.Fatalf("%s contains forbidden Keychain access marker %q", entry.Name(), forbidden)
				}
			}
		}
	}
}

func prepareCredentialStore(t *testing.T) (string, string) {
	t.Helper()
	root := canonicalTempDir(t)
	t.Setenv("XDG_DATA_HOME", root)
	directory, err := credentialDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return root, filepath.Join(directory, credentialFileName)
}

func canonicalTempDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}

func mustCredentialJSON(t *testing.T) []byte {
	t.Helper()
	data, err := json.Marshal(credentialDocument{Version: credentialVersion, APIKey: testAPIKey, OAuth: oauthPointer(testOAuth("valid"))})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func oauthPointer(value CodexOAuthCredential) *CodexOAuthCredential { return &value }

func testOAuth(suffix string) CodexOAuthCredential {
	return CodexOAuthCredential{
		AccessToken: "access-token-" + suffix, RefreshToken: "refresh-token-" + suffix,
		IDToken: "identity-token-" + suffix, AccountID: "account-id-" + suffix, ExpiresAt: 1_800_000_000,
	}
}

func writeMode(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
