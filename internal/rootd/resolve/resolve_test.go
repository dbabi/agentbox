package resolve

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"agentbox/internal/fw"
	"agentbox/internal/rootd/nl"

	_ "modernc.org/sqlite"
)

func TestCheckPrefix(t *testing.T) {
	for a, want := range map[string]string{
		"93.184.215.14": "", "2606:2800:21f:cb07::1": "", "64:ff9b::808:808": "",
		"10.1.2.3": "private4", "100.64.0.1": "private4", "127.0.0.1": "private4", "169.254.1.1": "private4",
		"198.51.100.7": "private4", "224.0.0.251": "private4", "255.255.255.255": "private4", "0.1.2.3": "private4",
		"::1": "private6", "::ffff:8.8.8.8": "private6", "fd00::1": "private6", "fe80::1": "private6", "ff02::1": "private6",
		"2001:db8::1": "private6", "64:ff9b:1::1": "private6", "100::1": "private6", "3fff::10": "private6",
		"2001:2::5": "private6", "2001:1ff::1": "private6", "5f00::1": "private6", "2001:200::1": "",
		"64:ff9b::a00:1": "nat64_private", "64:ff9b::7f00:1": "nat64_private", "fe80::1%eth0": "zoned",
	} {
		if got := CheckPrefix(netip.MustParseAddr(a)); got != want {
			t.Errorf("CheckPrefix(%s) = %q, want %q", a, got, want)
		}
	}
}

// A network-specific NAT64 prefix (RFC 6052) wraps an IPv4 address just as 64:ff9b::/96 does, at any of its lengths.
func TestCheckPrefixNSP(t *testing.T) {
	nsp := []netip.Prefix{netip.MustParsePrefix("2a01:5c0:64::/96"), netip.MustParsePrefix("2a01:5c0:1:64::/64"),
		netip.MustParsePrefix("2a01:5c00::/40")}
	for a, want := range map[string]string{
		"2a01:5c0:64::c0a8:101": "nat64_private", "2a01:5c0:64::808:808": "", "2a01:5c0:1:64:a:0:100:0": "nat64_private",
		"2a01:5c00:7f:0:1::": "nat64_private", "2a01:5c00:c0:0:a0::": "nat64_private", "2a01:5c1::c0a8:101": "",
		"64:ff9b::a00:1": "nat64_private",
	} {
		if got := CheckPrefix(netip.MustParseAddr(a), nsp...); got != want {
			t.Errorf("CheckPrefix(%s) = %q, want %q", a, got, want)
		}
	}
	if CheckPrefix(netip.MustParseAddr("2a01:5c0:64::c0a8:101")) != "" {
		t.Error("without the NSP the address is just public IPv6")
	}
}

func TestNAT64Prefixes(t *testing.T) {
	dns := fakeDNS{"ipv4only.arpa": {netip.MustParseAddr("192.0.0.170"), netip.MustParseAddr("2a01:5c0:64::c000:aa"),
		netip.MustParseAddr("2a01:5c00:c0:0:ab::")}}
	ra := func(context.Context) ([]netip.Prefix, error) {
		return []netip.Prefix{netip.MustParsePrefix("2a01:5c0:1:64::/64")}, nil
	}
	got, err := NAT64Prefixes(context.Background(), dns.ResolveHostname, ra)
	want := []netip.Prefix{netip.MustParsePrefix("2a01:5c0:1:64::/64"), netip.MustParsePrefix("2a01:5c0:64::/96"),
		netip.MustParsePrefix("2a01:5c00::/40")}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("got %v %v, want %v", got, err, want)
	}
	v4only := fakeDNS{"ipv4only.arpa": wka}
	if got, err := NAT64Prefixes(context.Background(), v4only.ResolveHostname, nil); err != nil || len(got) != 0 {
		t.Fatalf("no DNS64, no RA: %v %v", got, err)
	}
	if _, err := NAT64Prefixes(context.Background(), fakeDNS{}.ResolveHostname, nil); err == nil {
		t.Fatal("NXDOMAIN for ipv4only.arpa must not read as no DNS64")
	}
	down := func(context.Context, string) ([]netip.Addr, error) { return nil, &Refused{Unavailable, "down"} }
	if _, err := NAT64Prefixes(context.Background(), down, nil); err == nil {
		t.Fatal("a failed ipv4only.arpa lookup must not read as no DNS64")
	}
}

func TestParsePref64(t *testing.T) {
	msg := `{"parameters":{"Interfaces":[{"Name":"lo"},{"Name":"eth0","NDisc":{"PREF64":[{"Prefix":[42,1,5,192,0,100,0,0,0,0,0,0,0,0,0,0],"PrefixLength":96,"LifetimeUSec":1800000000}]}}]}}`
	got, err := parsePref64([]byte(msg))
	if err != nil || !slices.Equal(got, []netip.Prefix{netip.MustParsePrefix("2a01:5c0:64::/96")}) {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{`{"error":"io.systemd.System"}`, `{"parameters":{"Interfaces":[{"NDisc":{"PREF64":[{"Prefix":[1,2,3,4],"PrefixLength":96}]}}]}}`,
		// 298 is not a byte: it must not wrap to 42
		`{"parameters":{"Interfaces":[{"NDisc":{"PREF64":[{"Prefix":[298,1,5,192,0,100,0,0,0,0,0,0,0,0,0,0],"PrefixLength":96}]}}]}}`} {
		if _, err := parsePref64([]byte(bad)); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

func TestParseEntry(t *testing.T) {
	if e, err := ParseEntry("API.Anthropic.com:443"); err != nil || e != (Entry{"api.anthropic.com", 443}) {
		t.Fatalf("got %v %v", e, err)
	}
	for _, s := range []string{"example.com", "example.com:0", "example.com:65536", "example.com:080", "localhost:443",
		"1.2.3.4:443", "[::1]:443", "*.example.com:443", "example.com.:443", "-x.example.com:443", "bücher.de:443",
		"xn--bcher-kva.de:443x", "example.123:443"} {
		if _, err := ParseEntry(s); err == nil {
			t.Errorf("ParseEntry(%q) accepted", s)
		}
	}
	if _, err := ParseEntry("xn--bcher-kva.de:443"); err != nil {
		t.Errorf("A-label refused: %v", err)
	}
}

// An edit matches rows as LoadLists parses them: a removal takes every row that names the entry, in any spelling, and
// an add finds an entry that is already listed in another spelling.
func TestEditListParsedRows(t *testing.T) {
	dir := t.TempDir()
	svcList, common := filepath.Join(dir, "service.list"), filepath.Join(dir, "common.list")
	os.WriteFile(svcList, []byte("keys API.Example.com:443 # by hand\ngit a.example.com:443\ngit a.example.com:443\nkeys a.example.com:443\n"), 0o644)
	os.WriteFile(common, []byte("GitHub.com:443\ngithub.com:443\n"), 0o644)
	allowed := func(svc string, e Entry) bool {
		l, err := LoadLists(dir)
		if err != nil {
			t.Fatal(err)
		}
		return l.Allowed(svc, "", e)
	}
	for _, c := range []struct {
		svc string
		e   Entry
	}{{"keys", Entry{"api.example.com", 443}}, {"git", Entry{"a.example.com", 443}}, {"proxy", Entry{"github.com", 443}}} {
		if ch, err := EditList(dir, c.svc, c.e, true); err != nil || ch {
			t.Errorf("allow %s %s: listed already, got changed=%v %v", c.svc, c.e, ch, err)
		}
		if ch, err := EditList(dir, c.svc, c.e, false); err != nil || !ch || allowed(c.svc, c.e) {
			t.Errorf("remove %s %s: changed=%v %v, still allowed: %v", c.svc, c.e, ch, err, allowed(c.svc, c.e))
		}
	}
	if !allowed("keys", Entry{"a.example.com", 443}) {
		t.Error("removing git's a.example.com:443 took keys' row too")
	}
	if ch, err := EditList(dir, "keys", Entry{"B.Example.com", 443}, true); err != nil || !ch {
		t.Fatalf("allow B.Example.com: %v %v", ch, err)
	}
	if b, _ := os.ReadFile(svcList); string(b) != "# managed by agentbox egress allow/remove (rootd)\nkeys a.example.com:443\nkeys b.example.com:443\n" {
		t.Errorf("service.list is not canonical:\n%s", b)
	}
	// a row whose entry does not parse fails the edit, and the file stays as it was
	os.WriteFile(common, []byte("example.com:080\n"), 0o644)
	if _, err := EditList(dir, "proxy", Entry{"b.example.com", 443}, true); err == nil {
		t.Error("an edit of a list with a bad row went through")
	}
	if b, _ := os.ReadFile(common); string(b) != "example.com:080\n" {
		t.Errorf("the failed edit wrote common.list:\n%s", b)
	}
}

// Concurrent edits each keep the others' changes: no removed entry comes back and no added one is lost.
func TestEditListConcurrent(t *testing.T) {
	dir := t.TempDir()
	const n = 16
	host := func(s string, i int) Entry { return Entry{fmt.Sprintf("%s%d.example.com", s, i), 443} }
	for i := range n {
		if _, err := EditList(dir, "keys", host("old", i), true); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for i := range n {
		for _, c := range []struct {
			s   string
			add bool
		}{{"old", false}, {"new", true}} {
			wg.Go(func() {
				if ch, err := EditList(dir, "keys", host(c.s, i), c.add); err != nil || !ch {
					t.Errorf("%s%d: %v %v", c.s, i, ch, err)
				}
			})
		}
	}
	wg.Wait()
	l, err := LoadLists(dir)
	if err != nil {
		t.Fatal(err)
	}
	var want []Entry
	for i := range n {
		want = append(want, host("new", i))
	}
	got := l.Service["keys"]
	slices.SortFunc(got, func(a, b Entry) int { return strings.Compare(a.Host, b.Host) })
	slices.SortFunc(want, func(a, b Entry) int { return strings.Compare(a.Host, b.Host) })
	if !slices.Equal(got, want) {
		t.Fatalf("after concurrent edits keys has %v, want %v", got, want)
	}
}

func TestAddScript(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.1")
	got := AddScript([]Timed{{Elem{"keys_dst4", a, 443}, 10 * time.Minute}, {Elem{"keys_dst4", a, 80}, 5 * time.Minute}}, 30*time.Second)
	// an element recorded under a longer timeout keeps its remaining time as its timeout: nft refuses expires > timeout
	want := "add element inet agentbox keys_dst4 { 192.0.2.1 . 443 timeout 600000ms expires 600000ms }\n" +
		"add element inet agentbox keys_dst4 { 192.0.2.1 . 80 timeout 300000ms expires 300000ms }\n"
	if got != want {
		t.Fatalf("got\n%swant\n%s", got, want)
	}
	if got := AddScript([]Timed{{Elem{"git_dst6", netip.MustParseAddr("2001:db8::1"), 22}, time.Minute}}, 10*time.Minute); got != "add element inet agentbox git_dst6 { 2001:db8::1 . 22 timeout 600000ms expires 60000ms }\n" {
		t.Fatalf("got %s", got)
	}
}

func TestParseSetJSON(t *testing.T) {
	j := `{"nftables":[{"metainfo":{}},{"set":{"family":"inet","name":"keys_dst4","table":"agentbox","type":["ipv4_addr","inet_service"],
	"flags":["timeout"],"elem":[{"elem":{"val":{"concat":["192.0.2.1",443]},"timeout":600,"expires":512}},{"concat":["192.0.2.2",80]}]}}]}`
	got, err := ParseSetJSON([]byte(j))
	if err != nil || !slices.Equal(got, []string{"192.0.2.1 . 443", "192.0.2.2 . 80"}) {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := ParseSetJSON([]byte(`{"nftables":[{"set":{"elem":[{"concat":["192.0.2.1"]}]}}]}`)); err == nil {
		t.Fatal("a one-part element parsed")
	}
	if got, err := ParseSetJSON([]byte(`{"nftables":[{"set":{"elem":[{"concat":["192.0.2.1",65979]}]}}]}`)); err == nil {
		t.Fatalf("port 65979 parsed as %v", got) // it must not wrap to 443
	}
}

func TestParseVarlink(t *testing.T) {
	ok := `{"parameters":{"addresses":[{"ifindex":2,"family":2,"address":[93,184,215,14]},{"family":10,"address":[32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1]}],"name":"example.com","flags":0}}`
	got, err := parseVarlink([]byte(ok))
	if err != nil || len(got) != 2 || got[0].String() != "93.184.215.14" || got[1].String() != "2001:db8::1" {
		t.Fatalf("%v %v", got, err)
	}
	for msg, want := range map[string]string{
		`{"error":"io.systemd.Resolve.DNSError","parameters":{"rcode":3}}`:    NoSuchName,
		`{"error":"io.systemd.Resolve.NoSuchResourceRecord","parameters":{}}`: NoSuchName,
		`{"error":"io.systemd.Resolve.DNSError","parameters":{"rcode":2}}`:    Unavailable,
		`{"error":"io.systemd.Resolve.NoNameServers","parameters":{}}`:        Unavailable,
		`{"parameters":{"addresses":[{"family":2,"address":[1,2,3,4,5,6]}]}}`: Unavailable,
		`{"parameters":{"addresses":[{"family":10,"address":[1,2,3,4]}]}}`:    Unavailable,
		`{"parameters":{"addresses":[{"family":2,"address":[1,2,3,256]}]}}`:   Unavailable,
		`{"parameters":{"addresses":[]}}`:                                     NoSuchName,
	} {
		_, err := parseVarlink([]byte(msg))
		if r, ok := err.(*Refused); !ok || r.Reason != want {
			t.Errorf("%s: %v, want %s", msg, err, want)
		}
	}
}

// fakes for the resolver's dependencies
func fixedClock() (string, int64) { return "boot-1", 0 }

type fakeDNS map[string][]netip.Addr

func (f fakeDNS) ResolveHostname(_ context.Context, n string) ([]netip.Addr, error) {
	if a, ok := f[n]; ok {
		return a, nil
	}
	return nil, &Refused{NoSuchName, "nx"}
}

type fakeNft struct{ sets map[string]map[string]bool }

func (n *fakeNft) Run(script string) error {
	for _, l := range strings.Split(strings.TrimSpace(script), "\n") {
		f := strings.Fields(l)
		if len(f) < 8 {
			continue
		}
		set, key := f[4], f[6]+" . "+f[8]
		if n.sets[set] == nil {
			n.sets[set] = map[string]bool{}
		}
		if f[0] == "add" {
			n.sets[set][key] = true
		} else {
			delete(n.sets[set], key)
		}
	}
	return nil
}

func (n *fakeNft) List(set string) ([]string, error) {
	var out []string
	for k := range n.sets[set] {
		out = append(out, k)
	}
	return out, nil
}

func TestResolveAndRefill(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "rootd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(Schema); err != nil {
		t.Fatal(err)
	}
	// fw's exact-set rows share set_elements with no expiry; the refill must leave them alone
	if _, err := db.Exec(`INSERT INTO set_elements VALUES ('port_allow', '0 . 43100', NULL)`); err != nil {
		t.Fatal(err)
	}
	pub4, pub6 := netip.MustParseAddr("93.184.215.14"), netip.MustParseAddr("2606:2800:21f:cb07::1")
	own := netip.MustParseAddr("93.184.215.99")
	now := time.UnixMilli(1_800_000_000_000)
	nft := &fakeNft{map[string]map[string]bool{}}
	noV6 := false // the box has no IPv6 default route (an IPv4-only LAN)
	var cut []string
	var denied []string
	s := &Service{
		DB: db, Dir: dir, Now: func() time.Time { return now }, Clock: fixedClock, Timeout: 10 * time.Minute, Nft: nft,
		Resolver: fakeDNS{"api.example.com": {pub4, pub6}, "own.example.com": {pub4, own}, "v4only.example.com": {pub4, pub6},
			"priv.example.com": {pub4, netip.MustParseAddr("10.0.0.1")},
			// DNS64 with a network-specific prefix, and a name that publishes only an AAAA wrapping a LAN address
			"ipv4only.arpa":   {netip.MustParseAddr("192.0.0.170"), netip.MustParseAddr("2a01:5c0:64::c000:aa")},
			"nsp.example.com": {netip.MustParseAddr("2a01:5c0:64::c0a8:101")}, "ra.example.com": {netip.MustParseAddr("2a01:5c0:1:64:a:0:100:0")}},
		Pref64: func(context.Context) ([]netip.Prefix, error) {
			return []netip.Prefix{netip.MustParsePrefix("2a01:5c0:1:64::/64")}, nil
		},
		Route: func(a netip.Addr) string {
			switch {
			case a == own:
				return "route_not_unicast"
			case a.Is6() && noV6:
				return nl.NoDefaultRoute
			}
			return ""
		},
		Flows: func(a netip.Addr, p uint16) (int, error) { cut = append(cut, a.String()); return 1, nil },
		Deny:  func(svc, entry, reason, detail string) { denied = append(denied, svc+" "+entry+" "+reason) },
	}
	resolve := func(svc, host string) (string, []netip.Addr) {
		addrs, _, err := s.Resolve(context.Background(), svc, "", Entry{host, 443})
		if r, ok := err.(*Refused); ok {
			return r.Reason, nil
		} else if err != nil {
			t.Fatal(err)
		}
		return "ok", addrs
	}

	if r, _ := resolve("keys", "api.example.com"); r != NotAllowlisted {
		t.Fatalf("unlisted: %s", r)
	}
	for _, h := range []string{"api.example.com", "own.example.com", "priv.example.com", "nx.example.com", "nsp.example.com", "ra.example.com"} {
		if _, err := EditList(dir, "keys", Entry{h, 443}, true); err != nil {
			t.Fatal(err)
		}
	}
	if r, a := resolve("keys", "api.example.com"); r != "ok" || len(a) != 2 {
		t.Fatalf("listed: %s %v", r, a)
	}
	if !nft.sets["keys_dst4"]["93.184.215.14 . 443"] || !nft.sets["keys_dst6"]["2606:2800:21f:cb07::1 . 443"] {
		t.Fatalf("sets: %v", nft.sets)
	}
	for h, want := range map[string]string{"own.example.com": NonPublic, "priv.example.com": NonPublic, "nx.example.com": NoSuchName,
		"nsp.example.com": NonPublic, "ra.example.com": NonPublic} {
		if r, _ := resolve("keys", h); r != want {
			t.Errorf("%s: %s, want %s", h, r, want)
		}
	}
	// on an IPv4-only LAN the AAAA answers are unusable, not a reason to refuse the name; they reach no set
	EditList(dir, "keys", Entry{"v4only.example.com", 443}, true)
	noV6 = true
	if r, a := resolve("keys", "v4only.example.com"); r != "ok" || !slices.Equal(a, []netip.Addr{pub4}) {
		t.Fatalf("v4-only box: %s %v", r, a)
	}
	noV6 = false
	EditList(dir, "keys", Entry{"v4only.example.com", 443}, false)
	if r, _ := resolve("git", "api.example.com"); r != NotAllowlisted {
		t.Fatal("git used keys' list")
	}
	if r, _ := resolve("proxy", "api.example.com"); r != NotAllowlisted {
		t.Fatal("proxy resolved with no task registry")
	}
	if len(nft.sets["git_dst4"])+len(nft.sets["proxy_dst4"]) != 0 || len(nft.sets["keys_dst4"]) != 1 {
		t.Fatalf("a refused name reached a set: %v", nft.sets)
	}

	// refill after the kernel lost everything (reboot): the live answers come back, an unknown element goes
	nft.sets = map[string]map[string]bool{"keys_dst4": {"1.1.1.1 . 80": true}}
	now = now.Add(time.Minute)
	if res, err := s.Refill(); err != nil || res.Added != 2 || res.Extra != 1 {
		t.Fatalf("refill: %+v %v", res, err)
	}
	if !nft.sets["keys_dst4"]["93.184.215.14 . 443"] || nft.sets["keys_dst4"]["1.1.1.1 . 80"] {
		t.Fatalf("after refill: %v", nft.sets)
	}

	// expiry: the element leaves set_elements, but its answer is kept so a removal still cuts the flow
	now = now.Add(10 * time.Minute)
	if res, err := s.Refill(); err != nil || res.Added != 0 || res.Expired != 2 {
		t.Fatalf("refill after expiry: %+v %v", res, err)
	}
	var n int
	db.QueryRow(`SELECT count(*) FROM set_elements WHERE set_name != 'port_allow'`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d expired rows in set_elements", n)
	}
	if db.QueryRow(`SELECT count(*) FROM set_elements WHERE set_name = 'port_allow'`).Scan(&n); n != 1 {
		t.Fatal("the refill dropped fw's port_allow row")
	}
	if _, err := EditList(dir, "keys", Entry{"api.example.com", 443}, false); err != nil {
		t.Fatal(err)
	}
	if res, err := s.Refill(); err != nil || res.Revoked != 2 || res.Flows != 2 || !slices.Contains(cut, "93.184.215.14") {
		t.Fatalf("removal: %+v %v cut=%v", res, err, cut)
	}
	if r, _ := resolve("keys", "api.example.com"); r != NotAllowlisted {
		t.Fatal("a removed entry still resolves")
	}

	// a deputy host never lands in common.list, and a hand-edited one makes the whole load fail
	if _, err := EditList(dir, "proxy", Entry{"proxy.golang.org", 443}, true); err == nil {
		t.Fatal("deputy host in common.list")
	}
	os.WriteFile(filepath.Join(dir, "common.list"), []byte("sum.golang.org:443\n"), 0o644)
	if _, err := LoadLists(dir); err == nil {
		t.Fatal("loaded a common.list naming a deputy host")
	}
	if len(denied) == 0 || !strings.Contains(strings.Join(denied, "\n"), "keys own.example.com:443 non_public") {
		t.Fatalf("denials: %v", denied)
	}
}

type failNft struct {
	*fakeNft
	fail bool
}

func (n *failNft) Run(script string) error {
	if n.fail {
		return errors.New("nft: injected failure")
	}
	return n.fakeNft.Run(script)
}

// A revocation whose nft run or conntrack cut fails (or is interrupted) keeps its rows, so the next refill cuts again;
// and a row stays in set_elements for fw.ElementSlack past its expiry, as long as fwcheck accepts its kernel element.
func TestRevocationRetriedAndSlack(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "rootd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(Schema); err != nil {
		t.Fatal(err)
	}
	a1, a2 := netip.MustParseAddr("93.184.215.14"), netip.MustParseAddr("93.184.215.15")
	now := time.UnixMilli(1_800_000_000_000)
	nft := &failNft{fakeNft: &fakeNft{map[string]map[string]bool{}}}
	flowsFail := 0
	var cut []string
	s := &Service{DB: db, Dir: dir, Now: func() time.Time { return now }, Clock: fixedClock, Timeout: 10 * time.Minute, Nft: nft,
		Resolver: fakeDNS{"a.example.com": {a1}, "b.example.com": {a2}, "ipv4only.arpa": wka}, Route: func(netip.Addr) string { return "" },
		Flows: func(a netip.Addr, p uint16) (int, error) {
			if flowsFail > 0 {
				flowsFail--
				return 0, errors.New("conntrack: injected failure")
			}
			cut = append(cut, a.String())
			return 1, nil
		}}
	rows := func(q string) (n int) { db.QueryRow(q).Scan(&n); return }
	for _, h := range []string{"a.example.com", "b.example.com"} {
		EditList(dir, "keys", Entry{h, 443}, true)
		if _, _, err := s.Resolve(context.Background(), "keys", "", Entry{h, 443}); err != nil {
			t.Fatal(err)
		}
	}
	EditList(dir, "keys", Entry{"a.example.com", 443}, false)
	EditList(dir, "keys", Entry{"b.example.com", 443}, false)
	nft.fail = true
	if _, err := s.Refill(); err == nil {
		t.Fatal("nft failure not reported")
	}
	nft.fail, flowsFail = false, 1
	if _, err := s.Refill(); err == nil {
		t.Fatal("conntrack failure not reported")
	}
	if n := rows(`SELECT count(*) FROM set_answers`); n != 2 {
		t.Fatalf("a failed revocation dropped its rows: %d left", n)
	}
	if res, err := s.Refill(); err != nil || res.Revoked != 2 || len(cut) != 3 || rows(`SELECT count(*) FROM set_answers`) != 0 {
		t.Fatalf("retry: %+v %v cut=%v", res, err, cut) // both cut on the retry, a2 also on the failed run (it went on)
	}

	EditList(dir, "keys", Entry{"a.example.com", 443}, true)
	EditList(dir, "keys", Entry{"b.example.com", 443}, true)
	s.Resolve(context.Background(), "keys", "", Entry{"a.example.com", 443})
	now = now.Add(10*time.Minute + 2*time.Second)
	s.Resolve(context.Background(), "keys", "", Entry{"b.example.com", 443})
	if rows(`SELECT count(*) FROM set_elements WHERE element = '93.184.215.14 . 443'`) != 1 {
		t.Fatal("a row 2 s past its expiry left set_elements while fwcheck may still see its element")
	}
	now = now.Add(4 * time.Second)
	s.Resolve(context.Background(), "keys", "", Entry{"b.example.com", 443})
	if rows(`SELECT count(*) FROM set_elements WHERE element = '93.184.215.14 . 443'`) != 0 {
		t.Fatal("a row past the slack stayed")
	}
}

// A wall step moves Now but not the kernel's element timeouts: rootd rebases the rows by the step (same boot only), so
// a forward step neither expires live elements early nor makes fwcheck see them as alterations, and a backward step
// never asks nft for an expiry past the timeout.
func TestRebaseOnClockStep(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "rootd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(Schema); err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(1_800_000_000_000)
	boot, off := "boot-1", int64(0)
	nft := &fakeNft{map[string]map[string]bool{}}
	s := &Service{DB: db, Dir: dir, Now: func() time.Time { return now }, Clock: func() (string, int64) { return boot, off },
		Timeout: 10 * time.Minute, Nft: nft, Resolver: fakeDNS{"a.example.com": {netip.MustParseAddr("93.184.215.14")},
			"ipv4only.arpa": wka}, Route: func(netip.Addr) string { return "" },
		Flows: func(netip.Addr, uint16) (int, error) { return 0, nil }}
	EditList(dir, "keys", Entry{"a.example.com", 443}, true)
	if _, _, err := s.Resolve(context.Background(), "keys", "", Entry{"a.example.com", 443}); err != nil {
		t.Fatal(err)
	}
	expires := func() (e int64) {
		db.QueryRow(`SELECT expires_at FROM set_elements WHERE set_name = 'keys_dst4'`).Scan(&e)
		return
	}
	want := now.Add(10 * time.Minute).UnixMilli()
	for _, step := range []time.Duration{time.Hour, -2 * time.Hour} {
		now, off = now.Add(time.Minute+step), off+step.Milliseconds()
		want += step.Milliseconds()
		res, err := s.Refill()
		if err != nil || res.Expired != 0 || res.Added != 1 || expires() != want {
			t.Fatalf("step %v: %+v %v, expires %d want %d", step, res, err, expires(), want)
		}
		rows, _ := fw.ReadRows(db)
		if bad := fw.Compare(map[string][]string{"keys_dst4": {"93.184.215.14 . 443"}}, rows, now); len(bad) != 0 {
			t.Fatalf("step %v: %v", step, bad)
		}
	}
	// a new boot: no rebase (the refill at boot re-adds with the wall-clock time left)
	boot, off = "boot-2", off+time.Hour.Milliseconds()
	if _, err := s.Refill(); err != nil || expires() != want {
		t.Fatalf("new boot: %v, expires %d want %d", err, expires(), want)
	}
}
