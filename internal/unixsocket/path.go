// Package unixsocket validates filesystem Unix socket paths before an OS bind
// or dial. Darwin and Linux expose different sockaddr_un sizes, so derive the
// pathname limit from the target platform instead of duplicating constants.
package unixsocket

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ValidatePath requires a canonical absolute pathname that leaves room for
// sockaddr_un's terminating NUL byte.
func ValidatePath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') {
		return fmt.Errorf("Unix socket path must be canonical and absolute")
	}
	maximum := len(unix.RawSockaddrUnix{}.Path) - 1
	if len(path) > maximum {
		return fmt.Errorf("Unix socket path is %d bytes; platform limit is %d", len(path), maximum)
	}
	return nil
}
