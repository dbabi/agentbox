package fw

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// testdata/table.json is `nft -j -s list table inet agentbox` from nftables 1.1.6 after `agentbox fw load` and three
// rootd-style adds: port_allow 0 . 43100, proxy_dst4 1.2.3.4 . 443 and git_dst6 2001:db8::1 . 443 (timeout 10m).
func fixture(t *testing.T) []byte {
	b, err := os.ReadFile("testdata/table.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRender(t *testing.T) {
	r := string(Render())
	if strings.Contains(r, "{{") {
		t.Fatal("unfilled placeholder in the ruleset")
	}
	for _, w := range []string{"tcp dport 43000-45999 ct state new meta skuid . tcp dport @port_allow accept",
		"ct direction original ct state established accept", "1879048192-2013265919", "::ffff:0:0/96, 64:ff9b:1::/48"} {
		if !strings.Contains(r, w) {
			t.Errorf("ruleset lacks %q", w)
		}
	}
	// add-only: no destroy or delete, and only the output chain and the three static sets are flushed, so every set
	// rootd fills keeps its elements
	for _, l := range strings.Split(r, "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "#") {
			continue
		}
		if strings.Contains(l, "destroy") || strings.Contains(l, "delete") {
			t.Errorf("not add-only: %q", l)
		}
		if strings.Contains(l, "flush") && !slices.Contains([]string{"flush chain inet agentbox output",
			"flush set inet agentbox confined", "flush set inet agentbox private4", "flush set inet agentbox private6"}, l) {
			t.Errorf("unexpected flush: %q", l)
		}
		// §6.1 (v5.3): no ruleset change for denials; a drop stays silent and nft logs nothing anyone could read
		for _, w := range strings.Fields(l) {
			if slices.Contains([]string{"log", "queue", "notrack", "dup", "fwd"}, w) {
				t.Errorf("ruleset statement %q in %q: drops must stay silent", w, l)
			}
		}
	}
}

// nft's own printing of the static sets must canonicalize to the Go constants, or every fwcheck fails.
func TestParseTableStatic(t *testing.T) {
	tb, err := ParseTable(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if bad := Static(tb.Elems); len(bad) > 0 {
		t.Fatalf("static sets differ from the constants: %v", bad)
	}
	for s, w := range map[string][]string{"port_allow": {"0 . 43100"}, "proxy_dst4": {"1.2.3.4 . 443"},
		"git_dst6": {"2001:db8::1 . 443"}, "keys_dst4": {}} {
		if !slices.Equal(tb.Elems[s], w) {
			t.Errorf("set %s: got %q, want %q", s, tb.Elems[s], w)
		}
	}
	if len(tb.Hash) != 64 {
		t.Fatalf("hash %q", tb.Hash)
	}
}

// edit decodes the fixture, applies f and re-encodes it.
func edit(t *testing.T, f func([]map[string]map[string]any) []map[string]map[string]any) []byte {
	var doc struct {
		Nftables []map[string]map[string]any `json:"nftables"`
	}
	if err := json.Unmarshal(fixture(t), &doc); err != nil {
		t.Fatal(err)
	}
	doc.Nftables = f(doc.Nftables)
	b, _ := json.Marshal(doc)
	return b
}

func TestHash(t *testing.T) {
	base, err := ParseTable(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	hash := func(b []byte) string {
		tb, err := ParseTable(b)
		if err != nil {
			t.Fatal(err)
		}
		return tb.Hash
	}
	same := map[string][]byte{
		// a reload renumbers every rule
		"new handles": edit(t, func(o []map[string]map[string]any) []map[string]map[string]any {
			for i, x := range o {
				for _, v := range x {
					if _, ok := v["handle"]; ok {
						v["handle"] = 1000 + i
					}
				}
			}
			return o
		}),
		// elements are excluded: rootd adds and expiry never move the hash
		"no elements": edit(t, func(o []map[string]map[string]any) []map[string]map[string]any {
			for _, x := range o {
				delete(x["set"], "elem")
			}
			return o
		}),
		// a set created by a later load lists after the chain
		"sets reordered": edit(t, func(o []map[string]map[string]any) []map[string]map[string]any {
			slices.Reverse(o[3:6])
			return o
		}),
	}
	for name, b := range same {
		if h := hash(b); h != base.Hash {
			t.Errorf("%s: hash changed", name)
		}
	}
	diff := map[string][]byte{
		"rule dropped": edit(t, func(o []map[string]map[string]any) []map[string]map[string]any {
			i := slices.IndexFunc(o, func(x map[string]map[string]any) bool { return x["rule"] != nil })
			return slices.Delete(o, i, i+1)
		}),
		"rules swapped": edit(t, func(o []map[string]map[string]any) []map[string]map[string]any {
			var r []int
			for i, x := range o {
				if x["rule"] != nil {
					r = append(r, i)
				}
			}
			o[r[0]], o[r[1]] = o[r[1]], o[r[0]]
			return o
		}),
		"policy drop": edit(t, func(o []map[string]map[string]any) []map[string]map[string]any {
			for _, x := range o {
				if c := x["chain"]; c != nil {
					c["policy"] = "drop"
				}
			}
			return o
		}),
		"extra chain": edit(t, func(o []map[string]map[string]any) []map[string]map[string]any {
			return append(o, map[string]map[string]any{"chain": {"family": "inet", "table": "agentbox", "name": "evil"}})
		}),
		"set flags": edit(t, func(o []map[string]map[string]any) []map[string]map[string]any {
			for _, x := range o {
				if s := x["set"]; s != nil && s["name"] == "keys_dst4" {
					delete(s, "flags")
				}
			}
			return o
		}),
	}
	for name, b := range diff {
		if h := hash(b); h == base.Hash {
			t.Errorf("%s: hash unchanged", name)
		}
	}
	if _, err := ParseTable([]byte(`{"nftables":[{"metainfo":{}}]}`)); err == nil {
		t.Error("an empty listing must not parse as a table")
	}
}

func TestCanon(t *testing.T) {
	for in, want := range map[string]string{"0 . 43100": "0 . 43100", "1.2.3.4 . 443": "1.2.3.4 . 443",
		"2001:DB8::0:1 . 443": "2001:db8::1 . 443", "990 . 10.0.0.5 . 22": "990 . 10.0.0.5 . 22",
		"::ffff:0:0/96": "::ffff:0.0.0.0/96", "70001-70999": "70001-70999"} {
		if got, err := Canon(in); err != nil || got != want {
			t.Errorf("Canon(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	// rootd.db text goes into an nft script: anything but numbers, ranges, addresses and prefixes is refused
	for _, in := range []string{"1.2.3.4 . 443 }\nflush ruleset", "1.2.3.4 . 443 timeout 1d", "fe80::1%eth0 . 443",
		"10.0.0.1/8", "", "1.2.3.4 .443", "+1 . 2", "99999999999 . 1", "a-b"} {
		if got, err := Canon(in); err == nil {
			t.Errorf("Canon(%q) = %q, want an error", in, got)
		}
	}
}

func i64(v int64) *int64 { return &v }

func TestCompare(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	rows := []Row{{"port_allow", "0 . 43100", nil}, {"proxy_dst4", "1.2.3.4 . 443", i64(now.UnixMilli() + 300_000)},
		{"keys_dst4", "5.6.7.8 . 443", i64(now.UnixMilli() - 60_000)}}
	live := map[string][]string{"port_allow": {"0 . 43100"}, "proxy_dst4": {"1.2.3.4 . 443"}}
	if bad := Compare(live, rows, now); len(bad) > 0 {
		t.Fatalf("matching sets: %v", bad)
	}
	for name, c := range map[string]struct {
		live map[string][]string
		rows []Row
		want string
	}{
		"port_allow missing":  {map[string][]string{}, rows[:1], "set port_allow: missing element 0 . 43100"},
		"port_allow extra":    {map[string][]string{"port_allow": {"0 . 43100", "1000 . 43100"}}, rows[:1], "set port_allow: unexpected element 1000 . 43100"},
		"dst not recorded":    {map[string][]string{"git_dst4": {"9.9.9.9 . 443"}}, nil, "set git_dst4: element 9.9.9.9 . 443 is not an unexpired rootd answer"},
		"dst expired row":     {map[string][]string{"keys_dst4": {"5.6.7.8 . 443"}}, rows, "set keys_dst4: element 5.6.7.8 . 443 is not an unexpired rootd answer"},
		"dst in another set":  {map[string][]string{"keys_dst4": {"1.2.3.4 . 443"}}, rows, "set keys_dst4: element 1.2.3.4 . 443 is not an unexpired rootd answer"},
		"row for static set":  {map[string][]string{}, []Row{{"confined", "1000", nil}}, `rootd.db names set "confined", which rootd may not fill`},
		"bad row":             {map[string][]string{}, []Row{{"port_allow", "0 . 43100 }", nil}}, `rootd.db set port_allow: bad set element "0 . 43100 }"`},
		"allow_private extra": {map[string][]string{"allow_private4": {"994 . 10.0.0.1 . 22"}}, nil, "set allow_private4: unexpected element 994 . 10.0.0.1 . 22"},
	} {
		if bad := Compare(c.live, c.rows, now); !slices.Contains(bad, c.want) {
			t.Errorf("%s: got %q, want %q", name, bad, c.want)
		}
	}
	// a dynamic set that is empty always passes
	if bad := Compare(map[string][]string{}, rows[1:], now); len(bad) > 0 {
		t.Errorf("empty dst sets: %v", bad)
	}
	if bad := Static(map[string][]string{"confined": append(slices.Clone(Confined), "1000"), "private4": Private4[1:]}); len(bad) != 2+len(Private6) {
		t.Errorf("static: %q", bad)
	}
}

func TestRefillScript(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	rows := []Row{{"port_allow", "0 . 43100", nil}, {"port_allow", "0 . 43200", nil},
		{"proxy_dst4", "1.2.3.4 . 443", i64(now.UnixMilli() + 312_000)}, {"keys_dst4", "5.6.7.8 . 443", i64(now.UnixMilli() - 1000)}}
	live := map[string][]string{"port_allow": {"0 . 43100", "1000 . 43100"}, "keys_dst4": {"5.6.7.8 . 443"}, "proxy_dst4": {}}
	got, err := RefillScript(live, rows)
	if err != nil {
		t.Fatal(err)
	}
	// the dst sets are rootd's resolver's: untouched here
	want := `delete element inet agentbox port_allow { 1000 . 43100 }
add element inet agentbox port_allow { 0 . 43200 }
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if s, err := RefillScript(map[string][]string{"port_allow": {"0 . 43100"}}, rows[:1]); err != nil || s != "" {
		t.Errorf("matching sets: %q, %v", s, err)
	}
	for _, r := range []Row{{"private4", "10.0.0.0/8", nil}, {"port_allow", "0 . 1 } ; flush ruleset ; add element inet agentbox port_allow { 0 . 2", nil}} {
		if _, err := RefillScript(nil, []Row{r}); err == nil {
			t.Errorf("row %v: want an error", r)
		}
	}
}

func TestReadDB(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rootd.db")
	if rows, err := readDB(p); rows != nil || err != nil {
		t.Fatalf("no rootd.db: %v %v", rows, err)
	}
	db, err := sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE x(a)`); err != nil {
		t.Fatal(err)
	}
	if rows, err := readDB(p); rows != nil || err != nil {
		t.Fatalf("no set_elements table: %v %v", rows, err)
	}
	if _, err := db.Exec(`CREATE TABLE set_elements(set_name TEXT NOT NULL, element TEXT NOT NULL, expires_at INTEGER,
		PRIMARY KEY(set_name, element)) STRICT; INSERT INTO set_elements VALUES ('port_allow', '0 . 43100', NULL),
		('keys_dst4', '1.2.3.4 . 443', 1800000000000)`); err != nil {
		t.Fatal(err)
	}
	rows, err := readDB(p)
	if err != nil || len(rows) != 2 || rows[0].Expires != nil || rows[1].Expires == nil || *rows[1].Expires != 1_800_000_000_000 {
		t.Fatalf("rows %+v %v", rows, err)
	}
}

func TestReservedOK(t *testing.T) {
	for v, want := range map[string]bool{"43000-45999\n": true, "8080,43000-45999": true, "42000-46000": true,
		"": false, "43000-45998": false, "43001-45999": false, "43000": false, "x": false} {
		if ReservedOK(v) != want {
			t.Errorf("ReservedOK(%q) != %v", v, want)
		}
	}
}

// rootd records the fixed port_allow tuples itself; twice is the same as once, and they are what fwcheck then expects.
func TestRecordFixed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rootd.db")
	db, err := sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE set_elements(set_name TEXT NOT NULL, element TEXT NOT NULL, expires_at INTEGER,
		PRIMARY KEY(set_name, element)) STRICT`); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(RecordFixed(db), RecordFixed(db)); err != nil {
		t.Fatal(err)
	}
	rows, err := readDB(p)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows %+v %v", rows, err)
	}
	if bad := Compare(map[string][]string{"port_allow": {"0 . 43100", "0 . 43200"}}, rows, time.Now()); len(bad) != 0 {
		t.Fatal(bad)
	}
}
