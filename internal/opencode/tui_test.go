package opencode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildHostTUICommandIsolatesHostEnvironment(t *testing.T) {
	cfg := hostTUIFixture(t)
	command, err := BuildHostTUICommand(context.Background(), cfg, []string{
		"PATH=/usr/bin", "TERM=xterm-256color", "OPENAI_API_KEY=host-secret",
		"OPENCODE_CONFIG=/host/project/opencode.json", "HTTP_PROXY=http://proxy.invalid",
	})
	if err != nil {
		t.Fatal(err)
	}
	canonicalSession, err := filepath.EvalSymlinks(cfg.SessionRoot)
	if err != nil {
		t.Fatal(err)
	}
	if command.Dir == canonicalSession || !strings.HasPrefix(command.Dir, canonicalSession+string(filepath.Separator)) {
		t.Fatalf("command dir=%q", command.Dir)
	}
	arguments := strings.Join(command.Args, "\x00")
	for _, expected := range []string{"attach", cfg.ServerURL, "--dir", cfg.GuestWorkspace, "--pure"} {
		if !strings.Contains(arguments, expected) {
			t.Fatalf("args=%q missing %q", command.Args, expected)
		}
	}
	if strings.Contains(arguments, cfg.Password) {
		t.Fatal("server password was placed in command arguments")
	}
	for _, forbidden := range []string{"OPENAI_API_KEY", "HTTP_PROXY", "/host/project"} {
		if strings.Contains(strings.Join(command.Env, "\n"), forbidden) {
			t.Fatalf("Host TUI environment retained %q: %v", forbidden, command.Env)
		}
	}
	for key, expected := range map[string]string{
		"OPENCODE_DISABLE_PROJECT_CONFIG":  "1",
		"OPENCODE_DISABLE_DEFAULT_PLUGINS": "1",
		"OPENCODE_SERVER_PASSWORD":         cfg.Password,
		"NO_PROXY":                         "127.0.0.1,localhost",
		"EDITOR":                           "/usr/bin/false",
		"VISUAL":                           "/usr/bin/false",
	} {
		if got := environmentValue(command.Env, key); got != expected {
			t.Fatalf("%s=%q, want %q", key, got, expected)
		}
	}
}

func TestBuildHostTUICommandRejectsNonGuestWorkspace(t *testing.T) {
	cfg := hostTUIFixture(t)
	cfg.GuestWorkspace = cfg.SessionRoot
	if _, err := BuildHostTUICommand(context.Background(), cfg, nil); err == nil {
		t.Fatal("non-guest workspace was accepted")
	}
}

func TestBuildHostTUICommandRejectsExecutableDigestMismatch(t *testing.T) {
	cfg := hostTUIFixture(t)
	cfg.ExpectedExecutableSHA256 = strings.Repeat("0", 64)
	if _, err := BuildHostTUICommand(context.Background(), cfg, nil); err == nil {
		t.Fatal("tampered managed OpenCode binary was accepted")
	}
}

func hostTUIFixture(t *testing.T) HostTUIConfig {
	t.Helper()
	root := t.TempDir()
	tools := filepath.Join(root, "tools")
	if err := os.Mkdir(tools, 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(tools, "opencode")
	script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 1.18.16; exit 0; fi\nexit 0\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(script))
	session := filepath.Join(root, "sunaba-session-test")
	if err := os.Mkdir(session, 0700); err != nil {
		t.Fatal(err)
	}
	return HostTUIConfig{
		Binary: binary, ManagedToolDir: tools, SessionRoot: session,
		ServerURL: "http://127.0.0.1:54321", GuestWorkspace: "/workspace/sunaba-test",
		Password:                 strings.Repeat("p", 32),
		ExpectedExecutableSHA256: hex.EncodeToString(digest[:]),
	}
}
