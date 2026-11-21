package nl

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// FuzzParse feeds a netlink receive buffer through everything rootd reads from the kernel: the message split, route
// and nexthop replies, and the conntrack dump that revocation turns into deletes (issue #10).
func FuzzParse(f *testing.F) {
	rt := make([]byte, 12)
	rt[1], rt[4], rt[7] = 0, tableMain, rtnUnicast
	rt = Attr(Attr(rt, rtaOIF, binary.NativeEndian.AppendUint32(nil, 2)), rtaGateway, []byte{10, 0, 0, 1})
	nh := Attr(make([]byte, 8), nhaGateway, []byte{10, 0, 0, 1})
	dst := netip.MustParseAddr("192.0.2.1")
	ip := Attr(nil, ctaIPv4Dst, dst.AsSlice())
	pr := Attr(Attr(nil, ctaProtoNum, []byte{ipprotoTCP}), ctaDstPort, []byte{1, 187})
	ct := Attr(Nest(nfgen(dst), ctaTupleOrig, Nest(Nest(nil, ctaTupleIP, ip), ctaTupleProt, pr)), ctaZone, []byte{0, 1})
	f.Add(append(append(append(Encode(rtmNewRoute, 0, 1, rt), Encode(rtmNewNh, 0, 1, nh)...), Encode(ctNew, 0, 1, ct)...), Encode(typeDone, 0, 1, nil)...))
	f.Add(Encode(typeErr, 0, 1, []byte{0xfe, 0xff, 0xff, 0xff}))
	f.Add([]byte{16, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		msgs, _, err := Parse(b)
		if err != nil {
			return
		}
		if rs, err := ParseRoutes(msgs); err == nil {
			d, ok := Default(rs)
			for _, r := range rs {
				RouteCheck(r, d, ok)
			}
		}
		NhGateway(msgs)
		reqs, err := CTDeleteReqs(7, msgs, dst, 443)
		if err != nil {
			return
		}
		for _, q := range reqs {
			// each delete is one well-formed message that carries the dump's original tuple back
			got, _, err := Parse(q)
			if err != nil || len(got) != 1 || got[0].Type != ctDelete || !bytes.Equal(got[0].Data[:4], nfgen(dst)) {
				t.Fatalf("delete request %x: %v %v", q, got, err)
			}
			if _, err := Attrs(got[0].Data[4:]); err != nil {
				t.Fatalf("delete request %x: %v", q, err)
			}
		}
	})
}
