package securefs

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func EnsureOwnedDir(path string) error {
	if !isCleanAbsolute(path) {
		return fmt.Errorf("private directory path must be absolute and clean")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return CheckOwnedDir(path)
}

func EnsureCanonicalOwnedDir(path string) error {
	if err := EnsureOwnedDir(path); err != nil {
		return err
	}
	return CheckCanonicalOwnedDir(path)
}

func CheckOwnedDir(path string) error {
	if !isCleanAbsolute(path) {
		return fmt.Errorf("private directory path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	var stat unix.Stat_t
	statErr := unix.Lstat(path, &stat)
	if err != nil || statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("private directory must be mode 0700, current-user owned, and not be a symlink")
	}
	return nil
}

func CheckCanonicalOwnedDir(path string) error {
	if err := CheckOwnedDir(path); err != nil {
		return err
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return fmt.Errorf("private directory path must not contain symlinks")
	}
	return nil
}

func OpenOwnedRegularNoFollow(path string, maximum int64) (*os.File, error) {
	if !isCleanAbsolute(path) || maximum < 0 {
		return nil, fmt.Errorf("private file path or size bound is invalid")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open private file")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Size < 0 || stat.Size > maximum {
		_ = file.Close()
		return nil, fmt.Errorf("private file must be a bounded mode 0600 regular file owned by the current user")
	}
	return file, nil
}

func ReadOwnedRegular(path string, maximum int64) ([]byte, error) {
	file, err := OpenOwnedRegularNoFollow(path, maximum)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read bounded private file: %w", err)
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("private file exceeds its size bound")
	}
	return data, nil
}

func DecodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("JSON contains trailing data")
	}
	return nil
}

func AtomicWriteOwned(path string, data []byte) error {
	if !isCleanAbsolute(path) {
		return fmt.Errorf("private file path must be absolute and clean")
	}
	parent := filepath.Dir(path)
	if err := CheckOwnedDir(parent); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		var stat unix.Stat_t
		if statErr := unix.Lstat(path, &stat); statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
			return fmt.Errorf("existing private file is unsafe")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	temporary := filepath.Join(parent, ".sunaba-securefs-"+hex.EncodeToString(random)+".tmp")
	fd, err := unix.Open(temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	if file == nil {
		_ = unix.Close(fd)
		_ = os.Remove(temporary)
		return fmt.Errorf("create private temporary file")
	}
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = os.Remove(temporary)
		}
	}()
	if err := writeFull(file, data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	cleanup = false
	return SyncDir(parent)
}

func SyncDir(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func isCleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}
