//go:build !linux

package gate

import (
	"errors"
	"net"
)

func (s *Server) accept(t *task) {}

// ServeControl needs SO_PEERCRED: agentboxd runs on Linux only.
func (s *Server) ServeControl(net.Listener) error { return errors.New("agentboxd runs on Linux only") }
