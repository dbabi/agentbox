package nl

import (
	"encoding/binary"
	"net/netip"
)

// Route message constants (linux/rtnetlink.h).
const (
	rtmNewRoute = 24
	rtmGetRoute = 26
	rtaDst      = 1
	rtaOIF      = 4
	rtaGateway  = 5
	rtaPriority = 6
	rtaTable    = 15
	rtaVia      = 18
	rtaNhID     = 30
	rtmNewNh    = 104
	rtmGetNh    = 106
	nhaID       = 1
	nhaGroup    = 2
	nhaGateway  = 6
	rtnUnicast  = 1
	tableMain   = 254
	afInet      = 2
	afInet6     = 10
)

// Route is the part of an RTM_NEWROUTE that Appendix B check 3 reads.
type Route struct {
	Type    uint8
	DstLen  uint8
	Table   uint32
	OIF     uint32
	Gateway bool
	Prio    uint32
	NhID    uint32 // a nexthop-object route (RA defaults on 26.04): Gateway comes from the nexthop, see NhGateway
}

func family(a netip.Addr) byte {
	if a.Is4() {
		return afInet
	}
	return afInet6
}

// GetRouteReq asks the kernel which route it would use for a (ip route get).
func GetRouteReq(seq uint32, a netip.Addr) []byte {
	rt := make([]byte, 12)
	rt[0], rt[1] = family(a), byte(a.BitLen())
	return Encode(rtmGetRoute, FRequest, seq, Attr(rt, rtaDst, a.AsSlice()))
}

// DumpRoutesReq dumps the routes of a's family.
func DumpRoutesReq(seq uint32, a netip.Addr) []byte {
	rt := make([]byte, 12)
	rt[0] = family(a)
	return Encode(rtmGetRoute, FRequest|FDump, seq, rt)
}

// ParseRoutes reads the RTM_NEWROUTE messages among msgs.
func ParseRoutes(msgs []Msg) ([]Route, error) {
	var out []Route
	for _, m := range msgs {
		if m.Type != rtmNewRoute {
			continue
		}
		if len(m.Data) < 12 {
			return nil, errShort("rtmsg")
		}
		at, err := Attrs(m.Data[12:])
		if err != nil {
			return nil, err
		}
		r := Route{Type: m.Data[7], DstLen: m.Data[1], Table: uint32(m.Data[4])}
		if v := at[rtaTable]; len(v) == 4 {
			r.Table = binary.NativeEndian.Uint32(v)
		}
		if v := at[rtaOIF]; len(v) == 4 {
			r.OIF = binary.NativeEndian.Uint32(v)
		}
		if v := at[rtaPriority]; len(v) == 4 {
			r.Prio = binary.NativeEndian.Uint32(v)
		}
		if v := at[rtaNhID]; len(v) == 4 {
			r.NhID = binary.NativeEndian.Uint32(v)
		}
		_, gw := at[rtaGateway]
		_, via := at[rtaVia]
		r.Gateway = gw || via
		out = append(out, r)
	}
	return out, nil
}

// GetNexthopReq asks for nexthop object id.
func GetNexthopReq(seq, id uint32) []byte {
	return Encode(rtmGetNh, FRequest, seq, Attr(make([]byte, 8), nhaID, binary.NativeEndian.AppendUint32(nil, id)))
}

// NhGateway reports whether the RTM_NEWNEXTHOP among msgs has a gateway (a group counts: its members are gateways).
func NhGateway(msgs []Msg) (bool, error) {
	for _, m := range msgs {
		if m.Type != rtmNewNh {
			continue
		}
		if len(m.Data) < 8 {
			return false, errShort("nhmsg")
		}
		at, err := Attrs(m.Data[8:])
		if err != nil {
			return false, err
		}
		_, gw := at[nhaGateway]
		_, grp := at[nhaGroup]
		return gw || grp, nil
	}
	return false, errShort("nexthop reply")
}

// Default picks the main table's default route with the lowest metric, if any.
func Default(rs []Route) (Route, bool) {
	var best Route
	ok := false
	for _, r := range rs {
		if r.DstLen == 0 && r.Table == tableMain && r.Type == rtnUnicast && (!ok || r.Prio < best.Prio) {
			best, ok = r, true
		}
	}
	return best, ok
}

// NoDefaultRoute is RouteCheck's answer when the address's family has no default route.
const NoDefaultRoute = "no_default_route"

// RouteCheck is Appendix B check 3: the address must route as unicast out of the default route's interface, and
// through a gateway whenever the default route has one. That refuses the box's own addresses (local), on-link LAN
// addresses (no gateway) and tailnet or other interface routes. It returns the failed check's name, or "".
func RouteCheck(got Route, def Route, haveDef bool) string {
	switch {
	case !haveDef:
		return NoDefaultRoute
	case got.Type != rtnUnicast:
		return "route_not_unicast"
	case got.OIF != def.OIF:
		return "route_not_default_interface"
	case def.Gateway && !got.Gateway:
		return "route_on_link"
	}
	return ""
}
