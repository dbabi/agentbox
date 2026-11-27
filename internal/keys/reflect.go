package keys

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

// matcher finds the injected key in an upstream reply as it streams (#18): the key itself, its standard and URL-safe
// base64 at each of the three byte alignments it can sit at inside a longer encoded string, and its percent-encoding
// with upper- or lowercase hex. It holds back only a tail that could still start a match, so a key split across two
// chunks is caught, and bytes that can't be part of one pass at once.
type matcher struct {
	pats [][]byte
	tail []byte
}

func newMatcher(key string) *matcher {
	if key == "" {
		return &matcher{}
	}
	k := []byte(key)
	m := &matcher{pats: [][]byte{k}}
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		for a := range 3 {
			e := enc.EncodeToString(append(make([]byte, a), k...))
			// the chars that the key's bytes alone decide: past the a prefix bytes' bits, and before the last partial
			// char, which the next byte in the stream would change
			from, to := (8*a+5)/6, 8*(a+len(k))/6
			if to-from >= 16 {
				m.pats = append(m.pats, []byte(e[from:to]))
			}
		}
	}
	var up, low strings.Builder
	for _, c := range k {
		fmt.Fprintf(&up, "%%%02X", c)
		fmt.Fprintf(&low, "%%%02x", c)
	}
	m.pats = append(m.pats, []byte(up.String()), []byte(low.String()))
	return m
}

// feed scans b after the held-back tail. It returns the bytes that are safe to pass on now, or found.
func (m *matcher) feed(b []byte) (out []byte, found bool) {
	if len(m.pats) == 0 {
		return b, false
	}
	buf := append(m.tail, b...)
	for _, p := range m.pats {
		if bytes.Contains(buf, p) {
			m.tail = nil
			return nil, true
		}
	}
	hold := len(buf)
	for i := max(0, len(buf)-m.longest()+1); i < len(buf); i++ {
		if m.startsMatch(buf[i:]) {
			hold = i
			break
		}
	}
	m.tail = bytes.Clone(buf[hold:])
	return buf[:hold], false
}

// rest is the held-back tail at the end of the stream: feed already scanned it, and nothing can complete it now.
func (m *matcher) rest() []byte { t := m.tail; m.tail = nil; return t }

// contains reports whether s holds the key in any form: for a reply's header values, which never stream.
func (m *matcher) contains(s string) bool {
	for _, p := range m.pats {
		if strings.Contains(s, string(p)) {
			return true
		}
	}
	return false
}

func (m *matcher) longest() int {
	n := 0
	for _, p := range m.pats {
		n = max(n, len(p))
	}
	return n
}

// startsMatch reports whether s is a proper prefix of some pattern: the stream could still complete it.
func (m *matcher) startsMatch(s []byte) bool {
	for _, p := range m.pats {
		if len(s) < len(p) && bytes.HasPrefix(p, s) {
			return true
		}
	}
	return false
}
