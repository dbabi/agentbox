//go:build !linux

package rootd

import (
	"errors"
	"net"
)

func listeners() (map[string]*net.UnixListener, error) {
	return nil, errors.New("rootd runs on Linux only")
}

func (s *server) accept(string, *net.UnixListener) {}
