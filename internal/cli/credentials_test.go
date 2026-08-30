package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sunaba/internal/secretstore"
)

func TestAPICredentialCLIUsesBoundedSingleInputWithoutLeak(t *testing.T) {
	dataHome := credentialTestDataHome(t)
	key := "sk-cli-test-0123456789abcdef0123456789"
	var output, errors bytes.Buffer
	a := &app{input: strings.NewReader(key + "\n"), output: &output, errors: &errors}
	if err := a.credentials(context.Background(), "api-key", "set"); err != nil {
		t.Fatal(err)
	}
	loaded, err := secretstore.LoadOpenAIKey(context.Background())
	if err != nil || loaded != key {
		t.Fatalf("stored key length=%d error=%v", len(loaded), err)
	}
	combined := output.String() + errors.String()
	if strings.Contains(combined, key) || strings.Contains(combined, dataHome) {
		t.Fatalf("credential CLI output leaked sensitive input or storage path: %q", combined)
	}
	output.Reset()
	errors.Reset()
	if err := a.credentials(context.Background(), "api-key", "status"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), key) || strings.Contains(output.String(), "expires") || strings.Contains(output.String(), "account") {
		t.Fatalf("credential status exposed unnecessary detail: %q", output.String())
	}
}

func TestAPICredentialCLIRejectsInvalidPipedInput(t *testing.T) {
	credentialTestDataHome(t)
	tests := map[string]string{
		"empty":     "",
		"short":     "short\n",
		"multiple":  "sk-valid-01234567890123456789\nsecond-line\n",
		"control":   "sk-valid-012345678901234\t56789\n",
		"c1":        "sk-valid-012345678901234\u008556789\n",
		"unicode":   "sk-valid-012345678901234日本語56789\n",
		"space":     "sk-valid-012345678901234 56789\n",
		"oversized": strings.Repeat("x", maximumAPIKeyInputBytes+1) + "\n",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			var output, errors bytes.Buffer
			a := &app{input: strings.NewReader(input), output: &output, errors: &errors}
			if err := a.credentials(context.Background(), "api-key", "set"); err == nil {
				t.Fatal("invalid API key input was accepted")
			}
			if input != "" && strings.Contains(output.String()+errors.String(), input) {
				t.Fatal("invalid API key input was echoed")
			}
		})
	}
}

func TestCredentialCLIStatusAndDeleteDoNotExposeCredentialDetails(t *testing.T) {
	credentialTestDataHome(t)
	credential := secretstore.CodexOAuthCredential{
		AccessToken: "access-token-secret", RefreshToken: "refresh-token-secret",
		IDToken: "identity-token-secret", AccountID: "account-id-secret", ExpiresAt: 1_800_000_000,
	}
	if err := secretstore.StoreCodexOAuth(context.Background(), credential); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"status", "delete"} {
		var output, errors bytes.Buffer
		a := &app{output: &output, errors: &errors}
		if err := a.credentials(context.Background(), "oauth", action); err != nil {
			t.Fatal(err)
		}
		combined := output.String() + errors.String()
		for _, secret := range []string{credential.AccessToken, credential.RefreshToken, credential.IDToken, credential.AccountID, "1800000000"} {
			if strings.Contains(combined, secret) {
				t.Fatalf("%s output leaked credential detail", action)
			}
		}
	}
}

func credentialTestDataHome(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_DATA_HOME", root)
	return root
}
