//go:build darwin

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
		credential, credentialErr := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		pid, pidErr := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		if credentialErr != nil || pidErr != nil || credential.Uid != uint32(os.Geteuid()) || pid != expectedPID {
			peerErr = errors.New("sunaba-ui peer identity does not match its binding")
		}
	}); err != nil {
		return err
	}
	return peerErr
}
