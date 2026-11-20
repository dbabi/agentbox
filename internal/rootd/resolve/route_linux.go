package resolve

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"
)

func family(v4 bool) uint8 {
	if v4 {
		return syscall.AF_INET
	}
	return syscall.AF_INET6
}

func parseRoute(m syscall.NetlinkMessage) (route, *syscall.RtMsg, error) {
	if m.Header.Type == syscall.NLMSG_ERROR {
		if len(m.Data) >= 4 {
			if e := int32(binary.NativeEndian.Uint32(m.Data)); e != 0 {
				return route{}, nil, syscall.Errno(-e)
			}
		}
		return route{}, nil, errors.New("netlink error")
	}
	if len(m.Data) < syscall.SizeofRtMsg {
		return route{}, nil, errors.New("short route message")
	}
	rt := (*syscall.RtMsg)(unsafe.Pointer(&m.Data[0]))
	attrs, err := syscall.ParseNetlinkRouteAttr(&m)
	if err != nil {
		return route{}, nil, err
	}
	r := route{typ: rt.Type}
	for _, at := range attrs {
		switch at.Attr.Type {
		case syscall.RTA_OIF:
			if len(at.Value) >= 4 {
				r.oif = binary.NativeEndian.Uint32(at.Value)
			}
		case syscall.RTA_GATEWAY:
			r.gw = true
		}
	}
	return r, rt, nil
}

// defaultRoute is the main table's default route (dst length 0) for the family.
func defaultRoute(v4 bool) (route, error) {
	b, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, int(family(v4)))
	if err != nil {
		return route{}, err
	}
	msgs, err := syscall.ParseNetlinkMessage(b)
	if err != nil {
		return route{}, err
	}
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWROUTE {
			continue
		}
		r, rt, err := parseRoute(m)
		if err == nil && rt.Dst_len == 0 && rt.Table == syscall.RT_TABLE_MAIN && r.typ == syscall.RTN_UNICAST {
			return r, nil
		}
	}
	return route{}, fmt.Errorf("%w for IPv%d", ErrNoDefaultRoute, map[bool]int{true: 4, false: 6}[v4])
}

// getRoute is `ip route get a`: one RTM_GETROUTE request with RTA_DST.
func getRoute(a netip.Addr) (route, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return route{}, err
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return route{}, err
	}
	ab := a.AsSlice()
	attrLen := syscall.SizeofRtAttr + len(ab)
	n := syscall.SizeofNlMsghdr + syscall.SizeofRtMsg + attrLen
	b := make([]byte, n)
	binary.NativeEndian.PutUint32(b[0:], uint32(n))
	binary.NativeEndian.PutUint16(b[4:], syscall.RTM_GETROUTE)
	binary.NativeEndian.PutUint16(b[6:], syscall.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(b[8:], 1)
	o := syscall.SizeofNlMsghdr
	b[o] = family(a.Is4())
	b[o+1] = uint8(len(ab) * 8) // rtm_dst_len
	o += syscall.SizeofRtMsg
	binary.NativeEndian.PutUint16(b[o:], uint16(attrLen))
	binary.NativeEndian.PutUint16(b[o+2:], syscall.RTA_DST)
	copy(b[o+syscall.SizeofRtAttr:], ab)
	if err := syscall.Sendto(fd, b, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return route{}, err
	}
	buf := make([]byte, 1<<16)
	nr, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return route{}, err
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:nr])
	if err != nil || len(msgs) == 0 {
		return route{}, fmt.Errorf("route %s: bad netlink reply: %v", a, err)
	}
	r, _, err := parseRoute(msgs[0])
	if err != nil {
		return route{}, fmt.Errorf("route %s: %w", a, err)
	}
	return r, nil
}
