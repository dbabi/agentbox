package secrets

import (
	"bytes"
	"slices"
	"testing"
)

// FuzzFind: Find matches the bytes of any workspace file. It never panics, each hit names a vendored rule and a line
// of the file, and a token on a line of its own after the file's bytes is always found.
func FuzzFind(f *testing.F) {
	gh := tok("gh"+"p_", 36, alnum)
	f.Add([]byte("x = 1\nGH_TOKEN=" + gh + "\n"))
	f.Add([]byte("-----BEGIN " + "RSA PRIVATE KEY-----\n" + string(bytes.Repeat([]byte("A"), 80)) + "\n-----END RSA " + "PRIVATE KEY-----"))
	f.Add([]byte("sk-ant-" + "api03-" + "\x00\xff\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		lines := 1 + bytes.Count(b, []byte{'\n'})
		for _, h := range Find("f", b) {
			if _, ok := Lookup(h.Rule); !ok || h.Path != "f" || h.Line < 1 || h.Line > lines {
				t.Fatalf("hit %+v in %d lines", h, lines)
			}
		}
		if hits := Find("f", append(append(slices.Clip(b), '\n'), gh+"\n"...)); !slices.Contains(hits, Hit{"f", "github-pat", lines + 1}) {
			t.Fatalf("a token after %q: hits %v", b, hits)
		}
	})
}
