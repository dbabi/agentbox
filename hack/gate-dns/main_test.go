package main

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

func query(name string, qtype uint16, edns bool) []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		q = append(append(q, byte(len(l))), l...)
	}
	q = append(q, 0)
	q = binary.BigEndian.AppendUint16(q, qtype)
	q = binary.BigEndian.AppendUint16(q, 1)
	if edns {
		q[11] = 1
		q = append(q, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0)
	}
	return q
}

func TestAnswer(t *testing.T) {
	recs := records{"pub.test": {netip.MustParseAddr("192.88.96.1"), netip.MustParseAddr("2600::1")}}
	r, ok := answer(query("pub.test", 1, true), "test", recs)
	if !ok || binary.BigEndian.Uint16(r[0:]) != 0x1234 || r[3]&0xf != 0 || binary.BigEndian.Uint16(r[6:]) != 1 || binary.BigEndian.Uint16(r[10:]) != 1 {
		t.Fatalf("A reply: %x", r)
	}
	if a := r[len(r)-11-4 : len(r)-11]; netip.AddrFrom4([4]byte(a)).String() != "192.88.96.1" {
		t.Errorf("A rdata %x", a)
	}
	if r, _ := answer(query("pub.test", 28, false), "test", recs); binary.BigEndian.Uint16(r[6:]) != 1 || binary.BigEndian.Uint16(r[10:]) != 0 {
		t.Errorf("AAAA reply: %x", r)
	}
	if r, _ := answer(query("bad.test", 1, false), "test", recs); r[3]&0xf != 3 {
		t.Errorf("unknown name: rcode %d, want NXDOMAIN", r[3]&0xf)
	}
	if _, ok := answer(query("pub.else", 1, false), "test", recs); ok {
		t.Error("a name outside the zone was answered")
	}
	recs["ipv4only.arpa"] = []netip.Addr{netip.MustParseAddr("2600:ffff:64::c000:aa")}
	if r, ok := answer(query("ipv4only.arpa", 28, false), "test", recs); !ok || binary.BigEndian.Uint16(r[6:]) != 1 {
		t.Errorf("a name given with -a outside the zone: %v %x", ok, r)
	}
}
