package tui

import (
	"crypto/sha256"
	"debug/macho"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type ArtifactPin struct {
	OS     string
	Arch   string
	SHA256 string
}

// VerifyHelperExecutable performs the launch-time checks. It intentionally
// opens with O_NOFOLLOW and hashes the already-validated descriptor.
func VerifyHelperExecutable(path string, pin ArtifactPin) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || pin.OS != "darwin" || pin.Arch != "arm64" || !noncePattern.MatchString(pin.SHA256) {
		return errors.New("invalid sunaba-ui artifact contract")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open sunaba-ui: %w", err)
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("open sunaba-ui file descriptor")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0777 != 0700 || stat.Nlink != 1 {
		return errors.New("sunaba-ui must be an owner-controlled regular executable")
	}
	if stat.Mode&0111 == 0 {
		return errors.New("sunaba-ui is not executable")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, 256<<20)); err != nil {
		return fmt.Errorf("hash sunaba-ui: %w", err)
	}
	if stat.Size > 256<<20 || hex.EncodeToString(hash.Sum(nil)) != pin.SHA256 {
		return errors.New("sunaba-ui digest does not match the active lock")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	binary, err := macho.NewFile(file)
	if err != nil {
		return fmt.Errorf("sunaba-ui is not a Mach-O executable: %w", err)
	}
	defer binary.Close()
	if binary.Cpu != macho.CpuArm64 || binary.Type != macho.TypeExec {
		return errors.New("sunaba-ui platform or architecture does not match the active lock")
	}
	return nil
}
