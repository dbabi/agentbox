package dial

import (
	"errors"
	"testing"

	"agentbox/internal/rootd/resolve"
)

// FuzzParseReply: whatever rootd's reply line holds, a broker gets either addresses it can dial as IP literals or a
// refusal with one of the four reasons it maps to a denial.
func FuzzParseReply(f *testing.F) {
	f.Add([]byte(`{"ok":true,"addrs":["93.184.215.14","2606:2800:21f:cb07::1"],"expires_at":1800000600000}` + "\n"))
	f.Add([]byte(`{"ok":false,"reason":"non_public"}`))
	f.Add([]byte(`{"ok":true,"addrs":["fe80::1%eth0","::ffff:1.2.3.4","a.example"]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		as, err := parseReply(b)
		if err != nil {
			var r *resolve.Refused
			if !errors.As(err, &r) || (r.Reason != resolve.NotAllowlisted && r.Reason != resolve.NonPublic &&
				r.Reason != resolve.NoSuchName && r.Reason != resolve.Unavailable) {
				t.Fatalf("%q: %v", b, err)
			}
			return
		}
		if len(as) == 0 {
			t.Fatalf("%q: no address and no error", b)
		}
		for _, a := range as {
			if !a.IsValid() || a.Zone() != "" || a.Is4In6() {
				t.Fatalf("%q: address %v", b, a)
			}
		}
	})
}
