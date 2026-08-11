package secretstore

import (
	"context"
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
	maximumSecretBytes = 8 << 10
)

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
