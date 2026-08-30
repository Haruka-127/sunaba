package cli

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"sunaba/internal/dependency"
	"sunaba/internal/opencode"
	"sunaba/internal/securefs"
	hosttui "sunaba/internal/tui"
)

const (
	maximumHostArchiveBytes    = 512 << 20
	maximumHostExecutableBytes = 256 << 20
)

type dependencyArtifactInstaller struct {
	client  *http.Client
	sibling func(string) (string, error)
}

func (installer dependencyArtifactInstaller) ensure(ctx context.Context, stateRoot string, manifest dependency.Manifest, hostArchive string) error {
	if err := dependency.ValidateRuntimeManifest(manifest); err != nil {
		return err
	}
	if err := installer.ensureOpenCode(ctx, stateRoot, manifest, hostArchive); err != nil {
		return err
	}
	sibling := installer.sibling
	if sibling == nil {
		sibling = siblingExecutable
	}
	helper, err := sibling("sunaba-ui")
	if err != nil {
		return fmt.Errorf("locate bundled sunaba-ui: %w", err)
	}
	return installer.ensureSunabaUI(stateRoot, manifest, helper)
}

func (installer dependencyArtifactInstaller) ensureOpenCode(ctx context.Context, stateRoot string, manifest dependency.Manifest, hostArchive string) error {
	directory, destination, err := managedArtifactPath(stateRoot, "opencode", "v"+manifest.OpenCode.Version, "opencode")
	if err != nil {
		return err
	}
	if err := verifyManagedExecutableMetadata(destination, maximumHostExecutableBytes); err == nil {
		if _, err := opencode.VerifyHostTUIExecutableVersion(ctx, directory, destination, manifest.OpenCode.Host.ExecutableSHA256, manifest.OpenCode.Version); err == nil {
			return nil
		}
	}
	archive := hostArchive
	removeArchive := false
	if archive == "" {
		archive, err = installer.download(ctx, directory, manifest.OpenCode.Host)
		if err != nil {
			return err
		}
		removeArchive = true
	}
	if removeArchive {
		defer os.Remove(archive)
	}
	if err := installManagedOpenCodeArchive(ctx, archive, directory, destination, manifest); err != nil {
		return err
	}
	if err := verifyManagedExecutableMetadata(destination, maximumHostExecutableBytes); err != nil {
		return err
	}
	_, err = opencode.VerifyHostTUIExecutableVersion(ctx, directory, destination, manifest.OpenCode.Host.ExecutableSHA256, manifest.OpenCode.Version)
	return err
}

func verifyManagedExecutableMetadata(path string, maximum int64) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum < 0 {
		return fmt.Errorf("managed executable path or size bound is invalid")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open managed executable: %w", err)
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0700 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Size < 0 || stat.Size > maximum {
		return fmt.Errorf("managed executable must be a bounded mode 0700 current-user-owned regular file with one link")
	}
	return nil
}

func (installer dependencyArtifactInstaller) ensureSunabaUI(stateRoot string, manifest dependency.Manifest, source string) error {
	directory, destination, err := managedArtifactPath(stateRoot, "sunaba-ui", "v"+manifest.SunabaUI.Version, "sunaba-ui")
	if err != nil {
		return err
	}
	pin := hosttui.ArtifactPin{OS: manifest.SunabaUI.OS, Arch: manifest.SunabaUI.Arch, SHA256: manifest.SunabaUI.SHA256}
	if err := hosttui.VerifyHelperExecutable(destination, pin); err == nil {
		return nil
	}
	if err := hosttui.VerifyHelperExecutable(source, pin); err != nil {
		return fmt.Errorf("verify bundled sunaba-ui: %w", err)
	}
	if err := copyManagedExecutable(source, directory, destination, ".sunaba-ui-", maximumHostExecutableBytes, func(path string) error {
		return hosttui.VerifyHelperExecutable(path, pin)
	}); err != nil {
		return err
	}
	if err := hosttui.VerifyHelperExecutable(destination, pin); err != nil {
		return fmt.Errorf("verify installed sunaba-ui: %w", err)
	}
	return nil
}

func (installer dependencyArtifactInstaller) download(ctx context.Context, directory string, artifact dependency.Artifact) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", "sunaba-setup")
	response, err := installer.httpClient().Do(request)
	if err != nil {
		return "", fmt.Errorf("download managed OpenCode archive: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download managed OpenCode archive returned %s", response.Status)
	}
	if response.ContentLength > maximumHostArchiveBytes {
		return "", fmt.Errorf("managed OpenCode archive exceeds its size bound")
	}
	temporary, err := os.CreateTemp(directory, ".opencode-archive-")
	if err != nil {
		return "", err
	}
	path := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hash), io.LimitReader(response.Body, maximumHostArchiveBytes+1))
	if copyErr != nil || written > maximumHostArchiveBytes {
		return "", errors.Join(copyErr, fmt.Errorf("managed OpenCode archive exceeds or failed its size bound"))
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != artifact.SHA256 {
		return "", fmt.Errorf("managed OpenCode archive digest does not match dependency contract")
	}
	if err := temporary.Sync(); err != nil {
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	keep = true
	return path, nil
}

func (installer dependencyArtifactInstaller) httpClient() *http.Client {
	if installer.client != nil {
		return installer.client
	}
	return &http.Client{Timeout: 10 * time.Minute, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 || request.URL.Scheme != "https" || (request.URL.Host != "github.com" && !strings.HasSuffix(request.URL.Host, ".githubusercontent.com")) {
			return fmt.Errorf("refusing unexpected artifact redirect to %s", request.URL.Redacted())
		}
		return nil
	}}
}

func managedArtifactPath(stateRoot, tool, version, binary string) (string, string, error) {
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot || strings.ContainsAny(tool+version+binary, `/\\`) {
		return "", "", fmt.Errorf("managed artifact path is invalid")
	}
	directory := stateRoot
	for _, element := range []string{"tools", tool, version} {
		directory = filepath.Join(directory, element)
		if err := securefs.EnsureCanonicalOwnedDir(directory); err != nil {
			return "", "", fmt.Errorf("prepare managed artifact directory: %w", err)
		}
	}
	return directory, filepath.Join(directory, binary), nil
}

func installManagedOpenCodeArchive(ctx context.Context, archivePath, directory, destination string, manifest dependency.Manifest) error {
	archive, err := securefs.OpenOwnedRegularNoFollow(archivePath, maximumHostArchiveBytes)
	if err != nil {
		return fmt.Errorf("open managed OpenCode archive: %w", err)
	}
	defer archive.Close()
	info, err := archive.Stat()
	if err != nil {
		return err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(archive, maximumHostArchiveBytes+1)); err != nil {
		return err
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != manifest.OpenCode.Host.SHA256 {
		return fmt.Errorf("managed OpenCode archive digest does not match dependency contract")
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return err
	}
	reader, err := zip.NewReader(archive, info.Size())
	if err != nil {
		return fmt.Errorf("open managed OpenCode zip archive: %w", err)
	}
	var executable *zip.File
	for _, entry := range reader.File {
		if filepath.Base(entry.Name) != "opencode" || entry.FileInfo().IsDir() {
			continue
		}
		if executable != nil || entry.Mode()&os.ModeSymlink != 0 || entry.UncompressedSize64 > maximumHostExecutableBytes {
			return fmt.Errorf("managed OpenCode archive contains an unsafe executable")
		}
		executable = entry
	}
	if executable == nil {
		return fmt.Errorf("managed OpenCode archive does not contain opencode")
	}
	input, err := executable.Open()
	if err != nil {
		return err
	}
	defer input.Close()
	temporary, err := os.CreateTemp(directory, ".sunaba-opencode-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	executableHash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, executableHash), io.LimitReader(input, maximumHostExecutableBytes+1))
	closeErr := input.Close()
	if copyErr != nil || closeErr != nil || written > maximumHostExecutableBytes {
		_ = temporary.Close()
		return errors.Join(copyErr, closeErr, fmt.Errorf("managed OpenCode executable exceeds or failed its size bound"))
	}
	if got := hex.EncodeToString(executableHash.Sum(nil)); got != manifest.OpenCode.Host.ExecutableSHA256 {
		_ = temporary.Close()
		return fmt.Errorf("managed OpenCode executable digest does not match dependency contract")
	}
	if err := temporary.Chmod(0700); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := verifyManagedExecutableMetadata(temporaryPath, maximumHostExecutableBytes); err != nil {
		return err
	}
	if _, err := opencode.VerifyHostTUIExecutableVersion(ctx, directory, temporaryPath, manifest.OpenCode.Host.ExecutableSHA256, manifest.OpenCode.Version); err != nil {
		return fmt.Errorf("verify managed OpenCode archive executable: %w", err)
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return err
	}
	return securefs.SyncDir(directory)
}

func copyManagedExecutable(source, directory, destination, prefix string, maximum int64, validate func(string) error) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	temporary, err := os.CreateTemp(directory, prefix)
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	written, copyErr := io.Copy(temporary, io.LimitReader(input, maximum+1))
	if copyErr != nil || written > maximum {
		_ = temporary.Close()
		return errors.Join(copyErr, fmt.Errorf("managed executable exceeds or failed its size bound"))
	}
	if err := temporary.Chmod(0700); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if validate != nil {
		if err := validate(temporaryPath); err != nil {
			return err
		}
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return err
	}
	return securefs.SyncDir(directory)
}
