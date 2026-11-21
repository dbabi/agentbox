package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// FuzzAnswer: gate-dns answers queries from the gate VM, so any packet gets a well-formed reply or none (issue #10).
func FuzzAnswer(f *testing.F) {
	f.Add(query("pub.test", 1, true))
	f.Add(query("pub.test", 28, false))
	f.Add([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12})
	recs := records{"pub.test": {netip.MustParseAddr("192.88.96.1"), netip.MustParseAddr("2600::1")}}
	f.Fuzz(func(t *testing.T, q []byte) {
		r, ok := answer(q, "test", recs)
		if !ok {
			return
		}
		_, _, end, err := question(r)
		if err != nil || binary.BigEndian.Uint16(r[0:]) != binary.BigEndian.Uint16(q[0:]) || int(binary.BigEndian.Uint16(r[6:]))*16 > len(r)-end {
			t.Fatalf("reply %x to %x: %v", r, q, err)
		}
	})
}
