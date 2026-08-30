package unixsocket

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestValidatePathUsesPlatformSockaddrLimit(t *testing.T) {
	maximum := len(unix.RawSockaddrUnix{}.Path) - 1
	valid := "/" + strings.Repeat("a", maximum-1)
	if err := ValidatePath(valid); err != nil {
		t.Fatalf("maximum socket path rejected: %v", err)
	}
	if err := ValidatePath(valid + "b"); err == nil {
		t.Fatal("overlong socket path accepted")
	}
	for _, invalid := range []string{"relative.sock", filepath.Clean("/tmp/socket.sock") + "\x00suffix", "/tmp/../tmp/socket.sock"} {
		if err := ValidatePath(invalid); err == nil {
			t.Fatalf("unsafe socket path accepted: %q", invalid)
		}
	}
}
