package fw

import (
	"os"
	"slices"
	"testing"
)

// Fuzz targets for fwcheck's inputs: nft's JSON listing, rootd.db's element text and the reserved-ports sysctl (issue #10).

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
