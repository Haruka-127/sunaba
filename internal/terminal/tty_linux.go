//go:build linux

package terminal

import (
	"os"

	"golang.org/x/sys/unix"
)

func IsTTY(file *os.File) bool {
	if file == nil {
		return false
	}
	_, err := unix.IoctlGetTermios(int(file.Fd()), unix.TCGETS)
	return err == nil
}
