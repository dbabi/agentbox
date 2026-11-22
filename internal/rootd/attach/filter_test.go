package attach

import (
	"bytes"
	"testing"
	"unicode/utf8"
)

func filter(chunks ...string) string {
	var b bytes.Buffer
	f := NewFilter(&b)
	for _, c := range chunks {
		f.Write([]byte(c))
	}
	return b.String()
}

func TestFilter(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"plain text\r\n", "plain text\r\n"},
		{"héllo ’ ✓ \U0001F600 �", "héllo ’ ✓ \U0001F600 �"},
		{"a\x1b]52;c;ZXZpbA==\x07b", "ab"},                        // OSC 52 clipboard write, BEL-terminated
		{"a\x1b]0;title\x1b\\b", "ab"},                            // OSC title, ST-terminated
		{"a\x1bPq#0;2;0;0;0\x1b\\b", "ab"},                        // DCS (sixel)
		{"a\x1b_apc\x1b\\b\x1b^pm\x1b\\c\x1bXsos\x1b\\d", "abcd"}, // APC, PM, SOS
		{"a\x1b]52;c;x\x1b[31mred", "a\x1b[31mred"},               // ESC inside a string starts a new sequence
		{"\x1b[c\x1b[0c\x1b[>c\x1b[=c", ""},                       // DA1, DA2, DA3
		{"\x1b[5n\x1b[6n\x1b[?6n", ""},                            // DSR, CPR, DECXCPR
		{"\x1b[14t\x1b[18t\x1b[21t\x1b[8;24;80t", ""},             // window reports and ops
		{"\x1bZ", ""}, // DECID
		{"\x1b[1;31mred\x1b[0m \x1b[2J\x1b[H\x1b[?1049h\x1b[?25l", "\x1b[1;31mred\x1b[0m \x1b[2J\x1b[H\x1b[?1049h\x1b[?25l"},
		{"\x1b7\x1b8\x1b(B\x1b=\x1b>\x1bM", "\x1b7\x1b8\x1b(B\x1b=\x1b>\x1bM"},
		{"a\x9d52;c;x\x07b", "a52;c;x\x07b"},     // raw 8-bit OSC introducer
		{"a\xc2\x9d52;c;x\x07b", "a52;c;x\x07b"}, // UTF-8 encoded C1 OSC
		{"a\xc2\x9b6nb", "a6nb"},                 // UTF-8 encoded C1 CSI
		{"a\x90\x98\x9e\x9f\x9bb", "ab"},         // raw DCS, SOS, PM, APC, CSI
		{"a\xe0\x82\x9bb", "ab"},                 // overlong U+009B
		{"a\xc2Ab", "aAb"},                       // a truncated sequence is dropped, the next byte stays
		{"\x1b[31\nm", "\n\x1b[31m"},             // C0 inside CSI is executed
		{"\x1b[31\x18m", "m"},                    // CAN cancels
		{"\x1b\x1b[6n", ""},
	} {
		if got := filter(c.in); got != c.want {
			t.Errorf("%q: got %q, want %q", c.in, got, c.want)
		}
	}
}

// A sequence split at every byte filters the same as in one write.
func TestFilterSplit(t *testing.T) {
	in := "x\x1b]52;c;ZXZpbA==\x1b\\y\x1b[6n\x1b[1mz’\xc2\x9b\x1bPdcs\x07w\x1b[?1049h"
	want := filter(in)
	var chunks []string
	for i := range len(in) {
		chunks = append(chunks, in[i:i+1])
	}
	if got := filter(chunks...); got != want {
		t.Fatalf("byte by byte %q, whole %q", got, want)
	}
	if want != "xy\x1b[1mz’w\x1b[?1049h" {
		t.Fatalf("whole: %q", want)
	}
}

// filtered checks what Filter promises about its output: valid UTF-8 without C1 code points, no string introducer,
// no ESC Z, and no CSI ending in c, n or t.
func filtered(out []byte) bool {
	if !utf8.Valid(out) {
		return false
	}
	for _, r := range string(out) {
		if r >= 0x80 && r <= 0x9f {
			return false
		}
	}
	for i := 0; i < len(out); i++ {
		if out[i] != 0x1b {
			continue
		}
		if i+1 == len(out) || bytes.IndexByte([]byte("]P_^XZ"), out[i+1]) >= 0 {
			return false // a held sequence is never written half
		}
		if out[i+1] != '[' {
			continue
		}
		j := i + 2
		for j < len(out) && out[j] >= 0x20 && out[j] < 0x40 {
			j++
		}
		if j == len(out) || out[j] == 'c' || out[j] == 'n' || out[j] == 't' {
			return false
		}
	}
	return true
}

func FuzzFilter(f *testing.F) {
	f.Add([]byte("\x1b]52;c;x\x07\x1b[6n\xc2\x9b\x1bPq\x1b\\ok\x1b[1m"), uint8(3))
	f.Fuzz(func(t *testing.T, in []byte, split uint8) {
		var whole, parts bytes.Buffer
		NewFilter(&whole).Write(in)
		pf := NewFilter(&parts)
		n := int(split%16) + 1
		for i := 0; i < len(in); i += n {
			pf.Write(in[i:min(i+n, len(in))])
		}
		if !bytes.Equal(whole.Bytes(), parts.Bytes()) {
			t.Fatalf("split %d: %q vs %q", n, parts.Bytes(), whole.Bytes())
		}
		if !filtered(whole.Bytes()) {
			t.Fatalf("%q let through %q", in, whole.Bytes())
		}
	})
}
