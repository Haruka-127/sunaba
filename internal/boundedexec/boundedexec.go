package boundedexec

import (
	"errors"
	"fmt"
	"os/exec"
	"time"
)

var (
	ErrStdoutLimit = errors.New("subprocess stdout exceeded limit")
	ErrStderrLimit = errors.New("subprocess stderr exceeded limit")
)

type Limits struct {
	StdoutBytes int64
	StderrBytes int64
	WaitDelay   time.Duration
}

type Result struct {
	Stdout []byte
	Stderr []byte
}

type boundedBuffer struct {
	data     []byte
	maximum  int64
	overflow bool
	cancel   func()
}

func (w *boundedBuffer) Write(value []byte) (int, error) {
	remaining := w.maximum - int64(len(w.data))
	if remaining > 0 {
		keep := int64(len(value))
		if keep > remaining {
			keep = remaining
		}
		w.data = append(w.data, value[:keep]...)
	}
	if int64(len(value)) > remaining {
		if !w.overflow {
			w.overflow = true
			w.cancel()
		}
	}
	return len(value), nil
}

func Capture(command *exec.Cmd, limits Limits) (Result, error) {
	if command == nil || limits.StdoutBytes <= 0 || limits.StderrBytes <= 0 {
		return Result{}, fmt.Errorf("bounded subprocess requires positive output limits")
	}
	waitDelay := limits.WaitDelay
	if waitDelay <= 0 {
		waitDelay = 2 * time.Second
	}
	command.WaitDelay = waitDelay
	kill := func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
	}
	stdout := boundedBuffer{maximum: limits.StdoutBytes, data: make([]byte, 0, min(limits.StdoutBytes, 32<<10)), cancel: kill}
	stderr := boundedBuffer{maximum: limits.StderrBytes, data: make([]byte, 0, min(limits.StderrBytes, 16<<10)), cancel: kill}
	command.Stdout = &stdout
	command.Stderr = &stderr
	runErr := command.Run()
	var limitErr error
	if stdout.overflow {
		limitErr = errors.Join(limitErr, ErrStdoutLimit)
	}
	if stderr.overflow {
		limitErr = errors.Join(limitErr, ErrStderrLimit)
	}
	return Result{Stdout: stdout.data, Stderr: stderr.data}, errors.Join(runErr, limitErr)
}

func min(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}
