//go:build linux

package tui

import (
	"errors"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func verifyPeer(connection *net.UnixConn, expectedPID int) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		credential, credentialErr := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if credentialErr != nil || credential.Uid != uint32(os.Geteuid()) || int(credential.Pid) != expectedPID {
			peerErr = errors.New("sunaba-ui peer identity does not match its binding")
		}
	}); err != nil {
		return err
	}
	return peerErr
}
