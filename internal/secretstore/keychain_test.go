package secretstore

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOpenAIKeyUsesFixedIdentityAndBoundsOutput(t *testing.T) {
	root := t.TempDir()
	arguments := filepath.Join(root, "arguments")
	fake := filepath.Join(root, "security")
	script := "#!/bin/sh\nif test \"$1\" = login-keychain; then printf '\"%s\"\\n' \"$SUNABA_TEST_KEYCHAIN\"; exit; fi\nprintf '%s\\n' \"$*\" > \"$SUNABA_TEST_ARGUMENTS\"\nprintf 'host-key-0123456789abcdef0123456789\\n'\n"
	if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	previous := commandPath
	commandPath = fake
	t.Cleanup(func() { commandPath = previous })
	t.Setenv("SUNABA_TEST_ARGUMENTS", arguments)
	keychain := filepath.Join(root, "login.keychain-db")
	t.Setenv("SUNABA_TEST_KEYCHAIN", keychain)
	key, err := LoadOpenAIKey(context.Background())
	if err != nil || key != "host-key-0123456789abcdef0123456789" {
		t.Fatalf("key length=%d error=%v", len(key), err)
	}
	got, _ := os.ReadFile(arguments)
	want := "find-generic-password -a " + OpenAIAccount + " -s " + OpenAIService + " -w " + keychain + "\n"
	if string(got) != want {
		t.Fatalf("arguments=%q want=%q", got, want)
	}
}

func TestLoadOpenAIKeyRejectsInvalidOrOversizedSecret(t *testing.T) {
	for name, secret := range map[string]string{
		"short":     "short",
		"control":   "host-key-0123456789\nembedded",
		"oversized": strings.Repeat("x", maximumSecretBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			fake := filepath.Join(root, "security")
			script := "#!/bin/sh\nif test \"$1\" = login-keychain; then printf '\"%s\"\\n' \"$SUNABA_TEST_KEYCHAIN\"; exit; fi\n/bin/cat \"$SUNABA_TEST_SECRET\"\n"
			if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			secretPath := filepath.Join(root, "secret")
			if err := os.WriteFile(secretPath, []byte(secret), 0600); err != nil {
				t.Fatal(err)
			}
			previous := commandPath
			commandPath = fake
			t.Cleanup(func() { commandPath = previous })
			t.Setenv("SUNABA_TEST_SECRET", secretPath)
			t.Setenv("SUNABA_TEST_KEYCHAIN", filepath.Join(root, "login.keychain-db"))
			if _, err := LoadOpenAIKey(context.Background()); err == nil {
				t.Fatal("invalid Keychain secret was accepted")
			}
		})
	}
}

func TestInteractiveStoreKeepsSecretOutOfArguments(t *testing.T) {
	root := t.TempDir()
	arguments := filepath.Join(root, "arguments")
	fake := filepath.Join(root, "security")
	script := "#!/bin/sh\nif test \"$1\" = login-keychain; then printf '\"%s\"\\n' \"$SUNABA_TEST_KEYCHAIN\"; exit; fi\nprintf '%s\\n' \"$*\" > \"$SUNABA_TEST_ARGUMENTS\"\nIFS= read -r secret\ntest \"$secret\" = 'host-key-from-tty'\n"
	if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	previous := commandPath
	commandPath = fake
	t.Cleanup(func() { commandPath = previous })
	t.Setenv("SUNABA_TEST_ARGUMENTS", arguments)
	t.Setenv("SUNABA_TEST_KEYCHAIN", filepath.Join(root, "login.keychain-db"))
	var output bytes.Buffer
	if err := StoreOpenAIKeyInteractively(context.Background(), strings.NewReader("host-key-from-tty\n"), &output, &output); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(arguments)
	if strings.Contains(string(got), "host-key") || !strings.HasSuffix(strings.TrimSpace(string(got)), "-w") {
		t.Fatalf("unsafe add arguments=%q", got)
	}
}

func TestCodexOAuthStoreUsesFixedAccountAndStdin(t *testing.T) {
	root := t.TempDir()
	arguments := filepath.Join(root, "arguments")
	stdin := filepath.Join(root, "stdin")
	fake := filepath.Join(root, "security")
	script := "#!/bin/sh\nif test \"$1\" = login-keychain; then printf '\"%s\"\\n' \"$SUNABA_TEST_KEYCHAIN\"; exit; fi\nprintf '%s\\n' \"$*\" > \"$SUNABA_TEST_ARGUMENTS\"\n/bin/cat > \"$SUNABA_TEST_STDIN\"\n"
	if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	previous := commandPath
	commandPath = fake
	t.Cleanup(func() { commandPath = previous })
	t.Setenv("SUNABA_TEST_ARGUMENTS", arguments)
	t.Setenv("SUNABA_TEST_STDIN", stdin)
	t.Setenv("SUNABA_TEST_KEYCHAIN", filepath.Join(root, "login.keychain-db"))
	credential := CodexOAuthCredential{AccessToken: "access-token", RefreshToken: "refresh-token", IDToken: "identity-token", AccountID: "account-id", ExpiresAt: 1_800_000_000}
	if err := StoreCodexOAuth(context.Background(), credential); err != nil {
		t.Fatal(err)
	}
	args, _ := os.ReadFile(arguments)
	secret, _ := os.ReadFile(stdin)
	if strings.Contains(string(args), "access-token") || !strings.Contains(string(args), "-a "+CodexOAuthAccount) || !strings.HasSuffix(strings.TrimSpace(string(args)), "-w") {
		t.Fatalf("unsafe OAuth Keychain arguments=%q", args)
	}
	var stored CodexOAuthCredential
	if json.Unmarshal(secret, &stored) != nil || stored != credential {
		t.Fatalf("stored OAuth credential=%q", secret)
	}
}

func TestStatusAndDeleteUseOnlyFixedItemInLoginKeychain(t *testing.T) {
	root := t.TempDir()
	arguments := filepath.Join(root, "arguments")
	keychain := filepath.Join(root, "login.keychain-db")
	fake := filepath.Join(root, "security")
	script := "#!/bin/sh\nif test \"$1\" = login-keychain; then printf '\"%s\"\\n' \"$SUNABA_TEST_KEYCHAIN\"; exit; fi\nprintf '%s\\n' \"$*\" >> \"$SUNABA_TEST_ARGUMENTS\"\n"
	if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	previous := commandPath
	commandPath = fake
	t.Cleanup(func() { commandPath = previous })
	t.Setenv("SUNABA_TEST_ARGUMENTS", arguments)
	t.Setenv("SUNABA_TEST_KEYCHAIN", keychain)
	if err := OpenAIKeyExists(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := DeleteOpenAIKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(arguments)
	want := "find-generic-password -a " + OpenAIAccount + " -s " + OpenAIService + " " + keychain + "\n" +
		"delete-generic-password -a " + OpenAIAccount + " -s " + OpenAIService + " " + keychain + "\n"
	if string(got) != want {
		t.Fatalf("arguments=%q want=%q", got, want)
	}
}

func TestLoginKeychainPathRejectsAmbiguousOutput(t *testing.T) {
	root := t.TempDir()
	fake := filepath.Join(root, "security")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf '/tmp/unquoted.keychain-db\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	previous := commandPath
	commandPath = fake
	t.Cleanup(func() { commandPath = previous })
	if _, err := loginKeychainPath(context.Background()); err == nil {
		t.Fatal("ambiguous login Keychain output was accepted")
	}
}
