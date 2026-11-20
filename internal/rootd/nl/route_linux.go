package nl

import (
	"net/netip"

	"golang.org/x/sys/unix"
)

// CheckRoute runs RouteCheck against the kernel's routing for a. A lookup error refuses the address. With no default
// route for a's family it returns NoDefaultRoute: the box can't reach that family at all (an IPv4-only LAN).
func CheckRoute(a netip.Addr) string {
	msgs, err := Do(unix.NETLINK_ROUTE, DumpRoutesReq(2, a), true)
	if err != nil {
		return "route_dump: " + err.Error()
	}
	all, err := ParseRoutes(msgs)
	if err != nil {
		return "route_dump: " + err.Error()
	}
	def, ok := Default(all)
	if !ok {
		return NoDefaultRoute
	}
	msgs, err = Do(unix.NETLINK_ROUTE, GetRouteReq(1, a), false)
	if err != nil {
		return "route_lookup: " + err.Error()
	}
	got, err := ParseRoutes(msgs)
	if err != nil || len(got) != 1 {
		return "route_lookup: no single route"
	}
	for _, r := range []*Route{&got[0], &def} {
		if r.NhID != 0 && !r.Gateway {
			msgs, err := Do(unix.NETLINK_ROUTE, GetNexthopReq(3, r.NhID), false)
			if err != nil {
				return "nexthop_lookup: " + err.Error()
			}
			if r.Gateway, err = NhGateway(msgs); err != nil {
				return "nexthop_lookup: " + err.Error()
			}
		}
	}
	return RouteCheck(got[0], def, ok)
}
