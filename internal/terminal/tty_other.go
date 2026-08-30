//go:build !darwin && !linux

package terminal

import "os"

func IsTTY(*os.File) bool { return false }
