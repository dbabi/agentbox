//go:build !linux

package resolve

import (
	"errors"
	"net/netip"
)

var errLinux = errors.New("route checks need Linux netlink")

func defaultRoute(bool) (route, error)   { return route{}, errLinux }
func getRoute(netip.Addr) (route, error) { return route{}, errLinux }
