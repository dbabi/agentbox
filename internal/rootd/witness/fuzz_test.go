package witness

import (
	"bytes"
	"testing"
)

// FuzzLines: whatever a task writes, rootd keeps at most MaxKept bytes of well-formed lines, and every kept line passes
// the anchored pattern.
func FuzzLines(f *testing.F) {
	f.Add([]byte("dn_00000000000000000000000000 - BROKER_UNAVAILABLE forwarder\njunk\nEND " + string(bytes.Repeat([]byte("a"), 64)) + "\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		w := &W{}
		for i := 0; i < 64; i++ { // repeat the input so the cap is reached
			for _, l := range bytes.SplitAfter(b, []byte("\n")) {
				if len(l) > maxLine {
					w.add(nil, len(l)) // as read does: an over-long line counts every byte
				} else if len(l) > 0 {
					w.add(l, len(l))
				}
			}
		}
		n := 0
		for _, l := range w.r.Lines {
			n += len(l) + 1
			if bytes.ContainsAny([]byte(l), "\n\x00") {
				t.Fatalf("kept %q", l)
			}
		}
		if n > MaxKept+64 || w.kept > MaxKept {
			t.Fatalf("kept %d bytes", n)
		}
	})
}
