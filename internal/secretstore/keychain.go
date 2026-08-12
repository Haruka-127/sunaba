package secretstore

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	OpenAIService      = "dev.sunaba.openai"
	OpenAIAccount      = "openai-api-key"
	CodexOAuthAccount  = "codex-oauth"
	maximumSecretBytes = 32 << 10
)

type CodexOAuthCredential struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	AccountID    string `json:"account_id"`
	ExpiresAt    int64  `json:"expires_at"`
}

// commandPath is a link-time test seam. Production builds always use the
// absolute macOS security(1) path and do not accept an environment override.
var commandPath = "/usr/bin/security"

func LoadOpenAIKey(ctx context.Context) (string, error) {
	keychain, err := loginKeychainPath(ctx)
	if err != nil {
		return "", err
	}
	var output boundedWriter
	command := exec.CommandContext(ctx, commandPath, "find-generic-password", "-a", OpenAIAccount, "-s", OpenAIService, "-w", keychain)
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("OpenAI credential is unavailable in the macOS Keychain; run 'sunaba credentials openai set'")
	}
	secret := strings.TrimSuffix(output.String(), "\n")
	secret = strings.TrimSuffix(secret, "\r")
	if len(secret) < 20 || len(secret) > maximumSecretBytes || strings.ContainsAny(secret, "\x00\r\n\t") {
		return "", fmt.Errorf("OpenAI credential in the macOS Keychain is invalid")
	}
	return secret, nil
}

func OpenAIKeyExists(ctx context.Context) error {
	keychain, err := loginKeychainPath(ctx)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, commandPath, "find-generic-password", "-a", OpenAIAccount, "-s", OpenAIService, keychain)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return fmt.Errorf("OpenAI credential is not configured in the macOS Keychain")
	}
	return nil
}

func StoreOpenAIKeyInteractively(ctx context.Context, input io.Reader, output, errors io.Writer) error {
	keychain, err := loginKeychainPath(ctx)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, commandPath, "add-generic-password", "-U", "-a", OpenAIAccount, "-s", OpenAIService, keychain, "-w")
	command.Stdin, command.Stdout, command.Stderr = input, output, errors
	if err := command.Run(); err != nil {
		return fmt.Errorf("store OpenAI credential in the macOS Keychain: operation failed")
	}
	return nil
}

func DeleteOpenAIKey(ctx context.Context) error {
	keychain, err := loginKeychainPath(ctx)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, commandPath, "delete-generic-password", "-a", OpenAIAccount, "-s", OpenAIService, keychain)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return fmt.Errorf("delete OpenAI credential from the macOS Keychain: operation failed")
	}
	return nil
}

func LoadCodexOAuth(ctx context.Context) (CodexOAuthCredential, error) {
	secret, err := loadSecret(ctx, CodexOAuthAccount)
	if err != nil {
		return CodexOAuthCredential{}, fmt.Errorf("Codex OAuth credential is unavailable in the macOS Keychain; run 'sunaba credentials openai oauth login'")
	}
	var credential CodexOAuthCredential
	if json.Unmarshal([]byte(secret), &credential) != nil || validateCodexOAuth(credential) != nil {
		return CodexOAuthCredential{}, fmt.Errorf("Codex OAuth credential in the macOS Keychain is invalid")
	}
	return credential, nil
}

func StoreCodexOAuth(ctx context.Context, credential CodexOAuthCredential) error {
	if err := validateCodexOAuth(credential); err != nil {
		return err
	}
	encoded, err := json.Marshal(credential)
	if err != nil || len(encoded) > maximumSecretBytes {
		return fmt.Errorf("Codex OAuth credential is too large")
	}
	keychain, err := loginKeychainPath(ctx)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, commandPath, "add-generic-password", "-U", "-a", CodexOAuthAccount, "-s", OpenAIService, keychain, "-w")
	command.Stdin = strings.NewReader(string(encoded) + "\n")
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Run(); err != nil {
		return fmt.Errorf("store Codex OAuth credential in the macOS Keychain: operation failed")
	}
	return nil
}

func CodexOAuthExists(ctx context.Context) error {
	if err := secretExists(ctx, CodexOAuthAccount); err != nil {
		return fmt.Errorf("Codex OAuth credential is not configured in the macOS Keychain")
	}
	return nil
}

func DeleteCodexOAuth(ctx context.Context) error {
	keychain, err := loginKeychainPath(ctx)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, commandPath, "delete-generic-password", "-a", CodexOAuthAccount, "-s", OpenAIService, keychain)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Run(); err != nil {
		return fmt.Errorf("delete Codex OAuth credential from the macOS Keychain: operation failed")
	}
	return nil
}

func validateCodexOAuth(credential CodexOAuthCredential) error {
	for _, value := range []string{credential.AccessToken, credential.RefreshToken, credential.IDToken, credential.AccountID} {
		if !validOAuthSecretValue(value) {
			return fmt.Errorf("Codex OAuth credential is invalid")
		}
	}
	if credential.ExpiresAt <= 0 {
		return fmt.Errorf("Codex OAuth credential expiry is invalid")
	}
	return nil
}

func validOAuthSecretValue(value string) bool {
	if len(value) < 8 || len(value) > maximumSecretBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] == 0x7f {
			return false
		}
	}
	return true
}

func loadSecret(ctx context.Context, account string) (string, error) {
	keychain, err := loginKeychainPath(ctx)
	if err != nil {
		return "", err
	}
	var output boundedWriter
	command := exec.CommandContext(ctx, commandPath, "find-generic-password", "-a", account, "-s", OpenAIService, "-w", keychain)
	command.Stdout, command.Stderr = &output, io.Discard
	if err := command.Run(); err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(output.String(), "\n"), "\r"), nil
}

func secretExists(ctx context.Context, account string) error {
	keychain, err := loginKeychainPath(ctx)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, commandPath, "find-generic-password", "-a", account, "-s", OpenAIService, keychain)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	return command.Run()
}

func loginKeychainPath(ctx context.Context) (string, error) {
	var output boundedWriter
	command := exec.CommandContext(ctx, commandPath, "login-keychain")
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("macOS login Keychain is unavailable")
	}
	quoted := strings.TrimSpace(output.String())
	keychain, err := strconv.Unquote(quoted)
	if err != nil || !filepath.IsAbs(keychain) || filepath.Clean(keychain) != keychain || len(keychain) > 4096 || strings.ContainsAny(keychain, "\x00\r\n") {
		return "", fmt.Errorf("macOS login Keychain path is invalid")
	}
	return keychain, nil
}

type boundedWriter struct {
	data []byte
}

func (w *boundedWriter) Write(data []byte) (int, error) {
	if len(w.data)+len(data) > maximumSecretBytes+2 {
		return 0, fmt.Errorf("Keychain secret exceeded the bounded output limit")
	}
	w.data = append(w.data, data...)
	return len(data), nil
}

func (w *boundedWriter) String() string { return string(w.data) }
