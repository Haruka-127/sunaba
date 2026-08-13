package boundedexec

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
)

func TestCaptureBoundsStdoutAndStderr(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "printf 123456789; printf abcdefghi >&2")
	result, err := Capture(command, Limits{StdoutBytes: 4, StderrBytes: 5})
	if !errors.Is(err, ErrStdoutLimit) || !errors.Is(err, ErrStderrLimit) {
		t.Fatalf("overflow error=%v", err)
	}
	if string(result.Stdout) != "1234" || string(result.Stderr) != "abcde" {
		t.Fatalf("bounded result stdout=%q stderr=%q", result.Stdout, result.Stderr)
	}
}

func TestCaptureHonorsCommandContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	command := exec.CommandContext(ctx, "/bin/sh", "-c", "while :; do printf x; done")
	result, err := Capture(command, Limits{StdoutBytes: 1024, StderrBytes: 1024, WaitDelay: 100 * time.Millisecond})
	if err == nil || len(result.Stdout) > 1024 {
		t.Fatalf("context or output bound was not enforced: bytes=%d error=%v", len(result.Stdout), err)
	}
}
