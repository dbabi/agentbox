// Package canary is the per-task canary secret (#105). rootd mints one at task.start and plants it where a task looks
// for credentials: the LLM key slot, GITHUB_TOKEN, ~/.netrc and gh's hosts.yml. It is no credential for anything. The
// points where a task's output leaves the box scan for it: git pre-receive, the gh.* binders and the keys broker's
// model requests (bus.send and memory.write when they land, #292), and a hit means the task tried to send a credential
// out.
// It is a detection aid, not a guarantee: an encoding Scan doesn't cover (a cipher, compression) is missed.
package canary

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
)

// Prefix shapes the canary like an Anthropic API key (sk-ant-api03-, 93 characters, AA), so a task takes it for a
// real one and stock secret scanners (internal/secrets' gitleaks rules among them) flag it too. The literal is split so
// a scanner reading this file sees no key prefix.
const Prefix = "sk-ant-" + "api03-"

const (
	bodyLen  = 93
	alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	// Len is a canary's length: the prefix, the body and "AA".
	Len = len(Prefix) + bodyLen + 2
)

// Mint returns a fresh canary from crypto/rand. 256 is a multiple of the 64-letter alphabet, so every letter is
// equally likely.
func Mint() string {
	b := make([]byte, bodyLen)
	rand.Read(b) // never fails (crypto/rand, Go 1.24+)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return Prefix + string(b) + "AA"
}

// Valid reports whether c has the minted shape. Every slot holds only a value Mint made, so a scan never runs on a
// short or empty string that would match by accident.
func Valid(c string) bool {
	if len(c) != Len || c[:len(Prefix)] != Prefix || c[Len-2:] != "AA" {
		return false
	}
	for i := len(Prefix); i < Len; i++ {
		if !inAlphabet(c[i]) {
			return false
		}
	}
	return true
}

func inAlphabet(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-'
}

func isB64(b byte) bool { return inAlphabet(b) || b == '+' || b == '/' }

func isHex(b byte) bool { return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F' }

// view is one way of reading the data: keep picks the bytes it keeps, and needles are what it looks for in them.
type view struct {
	keep    func(b byte) bool
	needles [][]byte
}

// views are the forms Scan covers.
//   - The raw value, with every byte outside its alphabet dropped: it is found split across lines, or cut into
//     quoted pieces joined with +, or with any other separator.
//   - Its base64 (standard and URL alphabets) at each of the 3 byte offsets it can start at, whitespace and padding
//     dropped: so base64 of a whole file that holds it, wrapped at any column, still matches.
//   - Its hex, case folded, with separators and 0x or \x prefixes dropped.
func views(c string) []view {
	raw := []byte(c)
	var b64 [][]byte
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		for k := range 3 {
			// k bytes before the canary: drop the leading group they share and a trailing partial group, so the
			// needle holds only characters the canary's bytes alone decide
			s := enc.EncodeToString(append(make([]byte, k), raw...))
			from := 0
			if k > 0 {
				from = 4
			}
			to := (k + len(raw)) / 3 * 4
			b64 = append(b64, []byte(s[from:to]))
		}
	}
	return []view{
		{inAlphabet, [][]byte{raw}},
		{isB64, b64},
		{isHex, [][]byte{[]byte(hex.EncodeToString(raw))}},
	}
}

// Scanner looks for one canary in a stream of writes, so a large git object is scanned with bounded memory. Each view
// keeps the tail of what it kept so far, one byte short of its longest needle, so a match across writes is found.
type Scanner struct {
	views []view
	tails [][]byte
	prev  byte // the last byte written, for a 0x prefix that spans writes
	max   int
	hit   bool
}

// New returns a Scanner for c, or nil if c is not a minted canary: an empty or invalid slot scans nothing.
func New(c string) *Scanner {
	if !Valid(c) {
		return nil
	}
	s := &Scanner{views: views(c)}
	s.tails = make([][]byte, len(s.views))
	for _, v := range s.views {
		for _, n := range v.needles {
			s.max = max(s.max, len(n))
		}
	}
	return s
}

// piece bounds what one view keeps at once: Write scans a large p in pieces, so a whole request body costs about the
// same memory as a small one.
const piece = 64 << 10

// Write scans p. It never fails.
func (s *Scanner) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 && !s.hit {
		k := min(len(p), piece)
		s.write(p[:k])
		p = p[k:]
	}
	return n, nil
}

func (s *Scanner) write(p []byte) {
	for i, v := range s.views {
		h := s.tails[i]
		prev := s.prev
		for _, b := range p {
			switch {
			case i == 2 && (b == 'x' || b == 'X') && prev == '0' && len(h) > 0 && h[len(h)-1] == '0':
				h = h[:len(h)-1] // a 0x prefix: its 0 is no digit of the value
			case i == 2 && isHex(b):
				h = append(h, b|0x20) // lower case
			case i != 2 && v.keep(b):
				h = append(h, b)
			}
			prev = b
		}
		for _, n := range v.needles {
			if bytes.Contains(h, n) {
				s.hit = true
			}
		}
		if len(h) >= s.max {
			h = append(h[:0:0], h[len(h)-s.max+1:]...)
		}
		s.tails[i] = h
	}
	if len(p) > 0 {
		s.prev = p[len(p)-1]
	}
}

// Hit reports whether anything written so far holds the canary.
func (s *Scanner) Hit() bool { return s != nil && s.hit }

// Scan reports whether data holds canary c in any form the views cover. An invalid c matches nothing.
func Scan(data []byte, c string) bool {
	s := New(c)
	if s == nil {
		return false
	}
	s.Write(data)
	return s.Hit()
}
