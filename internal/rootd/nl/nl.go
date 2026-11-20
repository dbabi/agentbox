// Package nl is the little netlink rootd needs: route lookups (Appendix B check 3) and conntrack deletes (§6.1
// revocation). Encoding and parsing are plain functions, tested on any OS; Do talks to the kernel on Linux only.
package nl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
)

// Netlink header flags and message types (linux/netlink.h).
const (
	FRequest = 0x1
	FAck     = 0x4
	FDump    = 0x300
	typeErr  = 0x2
	typeDone = 0x3
	nested   = 0x8000
	typeMask = 0x3fff
)

// Msg is one netlink message: its type and the payload after the 16-byte header.
type Msg struct {
	Type uint16
	Data []byte
}

func align(n int) int { return (n + 3) &^ 3 }

// Encode builds a request with the given type, flags and sequence number.
func Encode(typ, flags uint16, seq uint32, payload []byte) []byte {
	b := make([]byte, 16, 16+len(payload))
	binary.NativeEndian.PutUint32(b[0:], uint32(16+len(payload)))
	binary.NativeEndian.PutUint16(b[4:], typ)
	binary.NativeEndian.PutUint16(b[6:], flags)
	binary.NativeEndian.PutUint32(b[8:], seq)
	return append(b, payload...)
}

// Attr appends one attribute (padded) to b.
func Attr(b []byte, typ uint16, v []byte) []byte {
	h := make([]byte, 4)
	binary.NativeEndian.PutUint16(h[0:], uint16(4+len(v)))
	binary.NativeEndian.PutUint16(h[2:], typ)
	b = append(append(b, h...), v...)
	return append(b, make([]byte, align(len(v))-len(v))...)
}

// Nest appends a nested attribute holding inner.
func Nest(b []byte, typ uint16, inner []byte) []byte { return Attr(b, typ|nested, inner) }

// Attrs parses a run of attributes into type → value; a repeated type keeps the first.
func Attrs(b []byte) (map[uint16][]byte, error) {
	m := map[uint16][]byte{}
	for len(b) >= 4 {
		l := int(binary.NativeEndian.Uint16(b[0:]))
		t := binary.NativeEndian.Uint16(b[2:]) & typeMask
		if l < 4 || l > len(b) {
			return nil, errors.New("netlink: bad attribute length")
		}
		if _, ok := m[t]; !ok {
			m[t] = b[4:l]
		}
		if align(l) >= len(b) {
			break
		}
		b = b[align(l):]
	}
	return m, nil
}

// Parse splits a receive buffer into messages. done reports NLMSG_DONE; a NLMSG_ERROR with a nonzero code is
// returned as that errno (code 0 is an ACK and is skipped).
func Parse(b []byte) (msgs []Msg, done bool, err error) {
	for len(b) >= 16 {
		l := int(binary.NativeEndian.Uint32(b[0:]))
		t := binary.NativeEndian.Uint16(b[4:])
		if l < 16 || l > len(b) {
			return nil, false, errors.New("netlink: bad message length")
		}
		switch t {
		case typeDone:
			return msgs, true, nil
		case typeErr:
			if l < 20 {
				return nil, false, errors.New("netlink: short error message")
			}
			if code := int32(binary.NativeEndian.Uint32(b[16:])); code != 0 {
				return msgs, false, syscall.Errno(-code)
			}
		default:
			msgs = append(msgs, Msg{t, b[16:l]})
		}
		if align(l) >= len(b) {
			break
		}
		b = b[align(l):]
	}
	return msgs, false, nil
}

// errShort is returned for a payload shorter than its fixed header.
func errShort(what string) error { return fmt.Errorf("netlink: short %s", what) }
