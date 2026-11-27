//go:build !linux

package broker

import (
	"errors"
	"net"
)

// peerUID needs SO_PEERCRED: the brokers run on Linux only; tests elsewhere set Server.Peer.
func peerUID(net.Conn) (uint32, error) { return 0, errors.New("SO_PEERCRED: Linux only") }
