package git

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID is the connection's SO_PEERCRED uid.
func peerUID(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a Unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var serr error
	if err := raw.Control(func(fd uintptr) {
		var cr *unix.Ucred
		if cr, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); serr == nil {
			uid = cr.Uid
		}
	}); err != nil {
		return 0, err
	}
	return uid, serr
}
