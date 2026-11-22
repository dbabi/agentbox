package attach

import (
	"io"
	"unicode/utf8"
)

// Filter is the attach output filter (ARCHITECTURE.md §4.2): rootd relays the session PTY's output through it, so a
// session can't make the admin's terminal write the clipboard (OSC 52), run a DCS, APC, PM or SOS string, or answer a
// report request whose reply would arrive as input. It drops those strings, every C1 control (8-bit, or UTF-8
// encoded) and CSI sequences with final byte c, n or t, and ESC Z (DECID, the 7-bit DA request). Other CSI and ESC
// sequences and all text pass, so TUIs still work. A sequence split across writes is handled: the state carries over.
type Filter struct {
	w     io.Writer
	st    state
	seq   []byte // the CSI or ESC sequence held until its final byte
	u8    []byte // an incomplete UTF-8 sequence
	out   []byte
	strEs bool // in a dropped string, the last byte was ESC
}

type state uint8

const (
	ground   state = iota
	esc            // after ESC
	escInter       // ESC and intermediates (0x20-0x2F), until the final byte
	csi            // after ESC [, until the final byte
	str            // inside a dropped OSC, DCS, APC, PM or SOS string
)

// maxSeq bounds a held CSI or ESC sequence; a longer one is dropped whole. Real sequences are far shorter.
const maxSeq = 256

func NewFilter(w io.Writer) *Filter { return &Filter{w: w} }

// Write filters p and writes what passes. It reports len(p) unless the underlying writer fails.
func (f *Filter) Write(p []byte) (int, error) {
	f.out = f.out[:0]
	for _, b := range p {
		f.byte(b)
	}
	if len(f.out) > 0 {
		if _, err := f.w.Write(f.out); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (f *Filter) byte(b byte) {
	switch f.st {
	case ground:
		f.text(b)
	case esc:
		f.seq = append(f.seq, b)
		switch {
		case b == ']' || b == 'P' || b == '_' || b == '^' || b == 'X': // OSC, DCS, APC, PM, SOS
			f.st, f.seq, f.strEs = str, f.seq[:0], false
		case b == '[':
			f.st = csi
		case b == 'Z': // DECID: the terminal answers with its DA reply
			f.st, f.seq = ground, f.seq[:0]
		case b == 0x1b:
			f.seq = f.seq[:1] // ESC ESC: the first is abandoned
		case b >= 0x20 && b <= 0x2f:
			f.st = escInter
		case b >= 0x30 && b <= 0x7e:
			f.emitSeq()
		case b == 0x18 || b == 0x1a: // CAN, SUB cancel the sequence
			f.st, f.seq = ground, f.seq[:0]
		case b < 0x20: // C0 inside a sequence is executed, the sequence goes on
			f.seq = f.seq[:len(f.seq)-1]
			f.out = append(f.out, b)
		default: // DEL or a byte >= 0x80: abandon the sequence
			f.st, f.seq = ground, f.seq[:0]
			f.text(b)
		}
	case escInter, csi:
		f.seq = append(f.seq, b)
		lo := byte(0x30)
		if f.st == csi {
			lo = 0x40
		}
		switch {
		case b >= lo && b <= 0x7e:
			if f.st == csi && (b == 'c' || b == 'n' || b == 't') {
				f.st, f.seq = ground, f.seq[:0] // DA, DSR/CPR, window reports
				return
			}
			f.emitSeq()
		case b >= 0x20 && b < lo:
			if len(f.seq) > maxSeq {
				f.st, f.seq = ground, f.seq[:0]
			}
		case b == 0x1b:
			f.st, f.seq = esc, append(f.seq[:0], b)
		case b == 0x18 || b == 0x1a:
			f.st, f.seq = ground, f.seq[:0]
		case b < 0x20:
			f.seq = f.seq[:len(f.seq)-1]
			f.out = append(f.out, b)
		default:
			f.st, f.seq = ground, f.seq[:0]
			f.text(b)
		}
	case str:
		// ST (ESC \), BEL, CAN or SUB ends the string. ESC and any other byte starts a new sequence: the terminal
		// never saw the string's introducer, so ending early only lets later bytes through the filter again.
		switch {
		case f.strEs && b == '\\':
			f.st = ground
		case f.strEs:
			f.st, f.seq = esc, append(f.seq[:0], 0x1b)
			f.byte(b)
		case b == 0x1b:
			f.strEs = true
		case b == 0x07 || b == 0x18 || b == 0x1a:
			f.st = ground
		}
	}
}

func (f *Filter) emitSeq() {
	f.out = append(f.out, f.seq...)
	f.st, f.seq = ground, f.seq[:0]
}

// text handles one byte in the ground state: ESC starts a sequence, ASCII passes, and UTF-8 is collected so a C1
// code point (U+0080-U+009F, which some terminals obey), a stray continuation byte or an invalid byte is dropped.
func (f *Filter) text(b byte) {
	if len(f.u8) > 0 && (b < 0x80 || utf8.RuneStart(b)) {
		f.u8 = f.u8[:0] // an incomplete sequence: drop it
	}
	if b < 0x80 {
		if b == 0x1b {
			f.st, f.seq = esc, append(f.seq[:0], b)
			return
		}
		f.out = append(f.out, b)
		return
	}
	f.u8 = append(f.u8, b)
	if !utf8.FullRune(f.u8) {
		return
	}
	r, n := utf8.DecodeRune(f.u8)
	if n == len(f.u8) && !(r == utf8.RuneError && n == 1) && r > 0x9f { // valid, and not C1
		f.out = append(f.out, f.u8...)
	}
	f.u8 = f.u8[:0]
}
