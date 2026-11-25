// Package ids mints and checks the `<kind>_<ULID>` ids of ARCHITECTURE.md §5.1 (bus task, message, fact, pending,
// snapshot and denial ids) and rootd's own op, request, trace and session ids. The 80 random bits come from
// crypto/rand, so a shared id (a bus task) can't be guessed.
package ids

import (
	"crypto/rand"
	"regexp"
	"time"
)

// The kinds §5.1 names, then rootd's own.
const (
	Task    = "task"
	Message = "msg"
	Fact    = "fact"
	Pending = "pnd"
	Snap    = "snap"
	Denial  = "dn"
	Op      = "op"    // an op's INTENT and RESULT (§5.2, §9)
	Request = "req"   // a human's task request (§4.2)
	Trace   = "trace" // a task chain's trace (§4.2)
	Session = "ses"   // an attach session (§4.2)
)

// Kinds is every kind New accepts.
var Kinds = []string{Task, Message, Fact, Pending, Snap, Denial, Op, Request, Trace, Session}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// A ULID is 26 Crockford base32 characters; the first can only be 0-7, since 26*5 = 130 bits hold 128.
var re = regexp.MustCompile(`^(task|msg|fact|pnd|snap|dn|op|req|trace|ses)_[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

// New returns a fresh id of kind: a 48-bit millisecond time and 80 random bits.
func New(kind string) string {
	if !Valid(kind + "_00000000000000000000000000") {
		panic("ids: unknown kind " + kind)
	}
	var b [16]byte
	ms := uint64(time.Now().UnixMilli())
	for i := 0; i < 6; i++ {
		b[i] = byte(ms >> (40 - 8*i))
	}
	rand.Read(b[6:]) // never fails (crypto/rand, Go 1.24+)
	out := make([]byte, 0, len(kind)+27)
	out = append(out, kind...)
	out = append(out, '_')
	// 128 bits as 26 base32 digits, most significant first: the top digit holds 3 bits.
	hi, lo := uint64(0), uint64(0)
	for i := 0; i < 8; i++ {
		hi, lo = hi<<8|uint64(b[i]), lo<<8|uint64(b[8+i])
	}
	var d [26]byte
	for i := 25; i >= 0; i-- {
		d[i] = crockford[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(append(out, d[:]...))
}

// Valid reports whether s is a well-formed id of any kind.
func Valid(s string) bool { return re.MatchString(s) }

// Is reports whether s is a well-formed id of kind.
func Is(kind, s string) bool { return len(s) > len(kind) && s[:len(kind)+1] == kind+"_" && Valid(s) }
