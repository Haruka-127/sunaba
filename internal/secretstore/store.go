package secretstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"sunaba/internal/securefs"
)

const (
	credentialVersion       = 1
	maximumSecretBytes      = 32 << 10
	maximumAccountIDBytes   = 1024
	maximumCredentialBytes  = 128 << 10
	maximumCredentialPath   = 4096
	credentialDirectoryName = "credentials"
	credentialFileName      = "openai.json"
	credentialLockName      = "openai.lock"
)

type CodexOAuthCredential struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	AccountID    string `json:"account_id"`
	ExpiresAt    int64  `json:"expires_at"`
}

type credentialDocument struct {
	Version int                   `json:"version"`
	APIKey  string                `json:"api_key,omitempty"`
	OAuth   *CodexOAuthCredential `json:"oauth,omitempty"`
}

func LoadOpenAIKey(ctx context.Context) (string, error) {
	document, err := loadCredentials(ctx)
	if err != nil {
		return "", err
	}
	if document.APIKey == "" {
		return "", fmt.Errorf("OpenAI API key is not configured; run 'sunaba credentials openai api-key set'")
	}
	return document.APIKey, nil
}

func OpenAIKeyExists(ctx context.Context) error {
	_, err := LoadOpenAIKey(ctx)
	return err
}

func StoreOpenAIKey(ctx context.Context, key string) error {
	if !validAPIKey(key) {
		return fmt.Errorf("OpenAI API key is invalid")
	}
	return updateCredentials(ctx, func(document *credentialDocument) error {
		document.APIKey = key
		return nil
	})
}

func DeleteOpenAIKey(ctx context.Context) error {
	return updateCredentials(ctx, func(document *credentialDocument) error {
		if document.APIKey == "" {
			return fmt.Errorf("OpenAI API key is not configured")
		}
		document.APIKey = ""
		return nil
	})
}

func LoadCodexOAuth(ctx context.Context) (CodexOAuthCredential, error) {
	document, err := loadCredentials(ctx)
	if err != nil {
		return CodexOAuthCredential{}, err
	}
	if document.OAuth == nil {
		return CodexOAuthCredential{}, fmt.Errorf("Codex OAuth credential is not configured; run 'sunaba credentials openai oauth login'")
	}
	return *document.OAuth, nil
}

func CodexOAuthExists(ctx context.Context) error {
	_, err := LoadCodexOAuth(ctx)
	return err
}

func StoreCodexOAuth(ctx context.Context, credential CodexOAuthCredential) error {
	if err := validateCodexOAuth(credential); err != nil {
		return err
	}
	return updateCredentials(ctx, func(document *credentialDocument) error {
		copy := credential
		document.OAuth = &copy
		return nil
	})
}

// UpdateCodexOAuth serializes OAuth refresh across sunaba processes. The
// callback runs while the credential file lock is held, so it must honor ctx
// and must not retain the credential after returning.
func UpdateCodexOAuth(ctx context.Context, update func(CodexOAuthCredential) (CodexOAuthCredential, error)) (CodexOAuthCredential, error) {
	if update == nil {
		return CodexOAuthCredential{}, fmt.Errorf("Codex OAuth update is invalid")
	}
	var updated CodexOAuthCredential
	err := updateCredentials(ctx, func(document *credentialDocument) error {
		if document.OAuth == nil {
			return fmt.Errorf("Codex OAuth credential is not configured; run 'sunaba credentials openai oauth login'")
		}
		var err error
		updated, err = update(*document.OAuth)
		if err != nil {
			return err
		}
		if err := validateCodexOAuth(updated); err != nil {
			return err
		}
		copy := updated
		document.OAuth = &copy
		return nil
	})
	if err != nil {
		return CodexOAuthCredential{}, err
	}
	return updated, nil
}

func DeleteCodexOAuth(ctx context.Context) error {
	return updateCredentials(ctx, func(document *credentialDocument) error {
		if document.OAuth == nil {
			return fmt.Errorf("Codex OAuth credential is not configured")
		}
		document.OAuth = nil
		return nil
	})
}

func loadCredentials(ctx context.Context) (credentialDocument, error) {
	lock, path, err := acquireCredentialLock(ctx)
	if err != nil {
		return credentialDocument{}, err
	}
	defer lock.close()
	document, exists, err := readCredentialDocument(path)
	if err != nil {
		return credentialDocument{}, err
	}
	if !exists {
		return credentialDocument{Version: credentialVersion}, nil
	}
	return document, nil
}

func updateCredentials(ctx context.Context, update func(*credentialDocument) error) error {
	lock, path, err := acquireCredentialLock(ctx)
	if err != nil {
		return err
	}
	defer lock.close()
	document, exists, err := readCredentialDocument(path)
	if err != nil {
		return err
	}
	if !exists {
		document.Version = credentialVersion
	}
	if err := update(&document); err != nil {
		return err
	}
	if err := validateCredentialDocument(document); err != nil {
		return err
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded)+1 > maximumCredentialBytes {
		return fmt.Errorf("OpenAI credential file is too large")
	}
	encoded = append(encoded, '\n')
	if err := securefs.AtomicWriteOwned(path, encoded); err != nil {
		return fmt.Errorf("store OpenAI credentials: %w", err)
	}
	return nil
}

func readCredentialDocument(path string) (credentialDocument, bool, error) {
	data, err := securefs.ReadOwnedRegular(path, maximumCredentialBytes)
	if errors.Is(err, os.ErrNotExist) {
		return credentialDocument{}, false, nil
	}
	if err != nil {
		return credentialDocument{}, false, fmt.Errorf("read OpenAI credential file: %w", err)
	}
	var document credentialDocument
	if err := securefs.DecodeStrictJSON(data, &document); err != nil || validateCredentialDocument(document) != nil {
		return credentialDocument{}, false, fmt.Errorf("OpenAI credential file is invalid")
	}
	return document, true, nil
}

func validateCredentialDocument(document credentialDocument) error {
	if document.Version != credentialVersion {
		return fmt.Errorf("OpenAI credential file version is invalid")
	}
	if document.APIKey != "" && !validAPIKey(document.APIKey) {
		return fmt.Errorf("OpenAI API key is invalid")
	}
	if document.OAuth != nil {
		if err := validateCodexOAuth(*document.OAuth); err != nil {
			return err
		}
	}
	return nil
}

func validateCodexOAuth(credential CodexOAuthCredential) error {
	for _, value := range []string{credential.AccessToken, credential.RefreshToken, credential.IDToken} {
		if !validBoundedSecret(value, 8, maximumSecretBytes) {
			return fmt.Errorf("Codex OAuth credential is invalid")
		}
	}
	if !validBoundedSecret(credential.AccountID, 8, maximumAccountIDBytes) {
		return fmt.Errorf("Codex OAuth credential is invalid")
	}
	if credential.ExpiresAt <= 0 {
		return fmt.Errorf("Codex OAuth credential expiry is invalid")
	}
	return nil
}

func validAPIKey(value string) bool {
	return validBoundedSecret(value, 20, maximumSecretBytes)
}

func validBoundedSecret(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

type credentialLock struct {
	file *os.File
}

func acquireCredentialLock(ctx context.Context) (*credentialLock, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", fmt.Errorf("lock OpenAI credential file: %w", err)
	}
	directory, err := credentialDirectory()
	if err != nil {
		return nil, "", err
	}
	if err := securefs.EnsureCanonicalOwnedDir(directory); err != nil {
		return nil, "", fmt.Errorf("prepare OpenAI credential directory: %w", err)
	}
	lockPath := filepath.Join(directory, credentialLockName)
	fd, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, "", fmt.Errorf("open OpenAI credential lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), lockPath)
	if file == nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("open OpenAI credential lock")
	}
	fail := func(err error) (*credentialLock, string, error) {
		_ = file.Close()
		return nil, "", err
	}
	if err := validateLockFile(fd); err != nil {
		return fail(err)
	}
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return fail(fmt.Errorf("lock OpenAI credential file: %w", err))
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fail(fmt.Errorf("lock OpenAI credential file: %w", ctx.Err()))
		case <-timer.C:
		}
	}
	if err := validateLockFile(fd); err != nil {
		_ = unix.Flock(fd, unix.LOCK_UN)
		return fail(err)
	}
	return &credentialLock{file: file}, filepath.Join(directory, credentialFileName), nil
}

func validateLockFile(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Size != 0 {
		return fmt.Errorf("OpenAI credential lock must be an empty mode 0600 regular file owned by the current user without hard links")
	}
	return nil
}

func (lock *credentialLock) close() error {
	return errors.Join(unix.Flock(int(lock.file.Fd()), unix.LOCK_UN), lock.file.Close())
}

func credentialDirectory() (string, error) {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", fmt.Errorf("resolve user data directory")
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	if len(dataHome) > maximumCredentialPath || !filepath.IsAbs(dataHome) || strings.IndexFunc(dataHome, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return "", fmt.Errorf("XDG data directory must be an absolute path without control characters")
	}
	dataHome = filepath.Clean(dataHome)
	path := filepath.Join(dataHome, "sunaba", credentialDirectoryName)
	if len(path) > maximumCredentialPath {
		return "", fmt.Errorf("OpenAI credential directory path is too long")
	}
	return path, nil
}
