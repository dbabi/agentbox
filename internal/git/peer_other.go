//go:build !linux

package git

import (
	"errors"
	"net"
)

// peerUID needs SO_PEERCRED: off Linux every peer is refused, and tests set Server.Peer.
func peerUID(net.Conn) (uint32, error) { return 0, errors.New("SO_PEERCRED is Linux only") }
