//go:build !linux

package nl

import (
	"errors"
	"net/netip"
)

// CheckRoute refuses everything off Linux: rootd runs only on the box.
func CheckRoute(netip.Addr) string { return "route_lookup: not linux" }

// Do is Linux only.
func Do(int, []byte, bool) ([]Msg, error) { return nil, errors.New("netlink: not linux") }

// DeleteFlows is Linux only.
func DeleteFlows(netip.Addr, uint16) (int, error) { return 0, errors.New("conntrack: not linux") }
