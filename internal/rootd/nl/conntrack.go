package nl

import (
	"encoding/binary"
	"net/netip"
)

// ctnetlink (linux/netfilter/nfnetlink_conntrack.h).
const (
	ctNew        = 1 << 8 // | IPCTNL_MSG_CT_NEW, which is 0
	ctGet        = 1<<8 | 1
	ctDelete     = 1<<8 | 2
	ctaTupleOrig = 1
	ctaZone      = 18
	ctaTupleIP   = 1
	ctaTupleProt = 2
	ctaIPv4Dst   = 2
	ctaIPv6Dst   = 4
	ctaProtoNum  = 1
	ctaDstPort   = 3
	ipprotoTCP   = 6
)

func nfgen(a netip.Addr) []byte { return []byte{family(a), 0, 0, 0} }

// CTDumpReq dumps the conntrack table of a's family.
func CTDumpReq(seq uint32, a netip.Addr) []byte { return Encode(ctGet, FRequest|FDump, seq, nfgen(a)) }

// CTDeleteReqs returns one delete request per TCP entry whose original direction goes to dst:port: the revocation
// that cuts an established broker flow (Appendix B).
func CTDeleteReqs(seq uint32, msgs []Msg, dst netip.Addr, port uint16) ([][]byte, error) {
	var out [][]byte
	for _, m := range msgs {
		if m.Type != ctNew {
			continue
		}
		if len(m.Data) < 4 {
			return nil, errShort("nfgenmsg")
		}
		top, err := Attrs(m.Data[4:])
		if err != nil {
			return nil, err
		}
		orig := top[ctaTupleOrig]
		t, err := Attrs(orig)
		if err != nil {
			return nil, err
		}
		ip, err := Attrs(t[ctaTupleIP])
		if err != nil {
			return nil, err
		}
		pr, err := Attrs(t[ctaTupleProt])
		if err != nil {
			return nil, err
		}
		d := ip[ctaIPv4Dst]
		if dst.Is6() {
			d = ip[ctaIPv6Dst]
		}
		got, ok := netip.AddrFromSlice(d)
		if !ok || got != dst || len(pr[ctaProtoNum]) != 1 || pr[ctaProtoNum][0] != ipprotoTCP ||
			len(pr[ctaDstPort]) != 2 || binary.BigEndian.Uint16(pr[ctaDstPort]) != port {
			continue
		}
		b := Nest(nfgen(dst), ctaTupleOrig, orig)
		if z, ok := top[ctaZone]; ok {
			b = Attr(b, ctaZone, z)
		}
		seq++
		out = append(out, Encode(ctDelete, FRequest|FAck, seq, b))
	}
	return out, nil
}
