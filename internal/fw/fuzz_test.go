package fw

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// Fuzz targets for fwcheck's inputs: nft's JSON listing, rootd.db's element text, the reserved-ports sysctl (issue #10)
// and the ssh-from file, whose prefixes land in the nft script.

func FuzzParseTable(f *testing.F) {
	b, err := os.ReadFile("testdata/table.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte(`{"nftables":[{"set":null},{"rule":{"handle":1}},{"set":{"name":"s","elem":[{"prefix":{"addr":"10.0.0.1","len":8}},{"elem":{"val":1}},{"concat":[]}]}}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		tb, err := ParseTable(b)
		if err != nil {
			return
		}
		again, err := ParseTable(b)
		if err != nil || again.Hash != tb.Hash {
			t.Fatalf("hash not deterministic: %s %s %v", tb.Hash, again.Hash, err)
		}
		for s, es := range tb.Elems {
			if !slices.IsSorted(es) {
				t.Fatalf("set %s elements unsorted: %q", s, es)
			}
		}
	})
}

func FuzzCanon(f *testing.F) {
	for _, s := range []string{"0 . 43100", "1.2.3.4 . 443", "70001-70999", "10.0.0.0/8", "2001:db8::/32", "fe80::1%eth0", "+1", "1-", "4294967296"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, err := Canon(s)
		if err != nil {
			return
		}
		if again, err := Canon(c); err != nil || again != c {
			t.Fatalf("Canon(%q) = %q, then %q %v", s, c, again, err)
		}
	})
}

func FuzzReservedOK(f *testing.F) {
	f.Add("70000-79999")
	f.Add(" 1,2-3,,-,99999999999999999999 \n")
	f.Fuzz(func(t *testing.T, s string) { ReservedOK(s) })
}

func FuzzParseSSHFrom(f *testing.F) {
	f.Add([]byte("# lan\n192.168.1.0/24\nfd00::/8\n"))
	f.Add([]byte("10.0.0.0/8\n10.0.0.0/9\n::ffff:1.2.3.4/128\nfe80::/10%x } accept\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ps, err := ParseSSHFrom(b)
		if err != nil {
			return
		}
		v4, v6 := sshSets(ps)
		for _, e := range append(v4, v6...) {
			if c, err := Canon(e); err != nil || c != e || strings.ContainsAny(e, " ;{}\"\n") {
				t.Fatalf("element %q (Canon %q, %v) is not a plain prefix", e, c, err)
			}
		}
	})
}
