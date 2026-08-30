//go:build !darwin && !linux

package tui

import (
	"errors"
	"net"
)

func verifyPeer(_ *net.UnixConn, _ int) error {
	return errors.New("sunaba-ui peer identity verification is unsupported on this host")
}
