package resolve

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fuzz targets for what rootd's resolver reads: broker requests and allowlists, resolved and networkd Varlink replies,
// nft's set JSON and rootd.db rows (issue #10).

func FuzzParseEntry(f *testing.F) {
	for _, s := range []string{"api.anthropic.com:443", "API.Example.COM:8443", "1.2.3.4:443", "a.b:0", "a.b:080", "x.y:65536", "-a.b:1", "a..b:1", ":"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		e, err := ParseEntry(s)
		if err != nil {
			return
		}
		if again, err := ParseEntry(e.String()); err != nil || again != e || e.Port == 0 || e.Host != strings.ToLower(e.Host) {
			t.Fatalf("%q parsed as %+v, which reads back as %+v %v", s, e, again, err)
		}
		if _, k, err := parseEntryKey(entryKey("keys", e)); err != nil || k != e {
			t.Fatalf("entry key of %+v: %v", e, err)
		}
	})
}

func FuzzParseElem(f *testing.F) {
	f.Add("keys_dst4", "192.0.2.1 . 443")
	f.Add("keys_dst6", "2001:db8::1 . 22")
	f.Add("keys_dst6", "fe80::1%eth0 . 22")
	f.Fuzz(func(t *testing.T, set, key string) {
		e, err := ParseElem(set, key)
		if err != nil {
			splitKey(set + "\x00" + key)
			return
		}
		if again, err := ParseElem(set, e.Key()); err != nil || again != e {
			t.Fatalf("%q parsed as %+v, which reads back as %+v %v", key, e, again, err)
		}
	})
}

func FuzzParseSetJSON(f *testing.F) {
	f.Add([]byte(`{"nftables":[{"metainfo":{}},{"set":{"family":"inet","name":"keys_dst4","table":"agentbox","type":["ipv4_addr","inet_service"],` +
		`"flags":["timeout"],"elem":[{"elem":{"val":{"concat":["192.0.2.1",443]},"timeout":600,"expires":512}},{"concat":["192.0.2.2",80]}]}}]}`))
	f.Add([]byte(`{"nftables":[{"set":{"elem":[{"concat":["2001:db8::1",65535]},{"concat":["192.0.2.1",-1]}]}}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		keys, err := ParseSetJSON(b)
		if err != nil {
			return
		}
		for _, k := range keys {
			_, err4 := ParseElem("x4", k)
			_, err6 := ParseElem("x6", k)
			if (err4 == nil) == (err6 == nil) {
				t.Fatalf("key %q from %s does not read back", k, b)
			}
		}
	})
}

func FuzzParseVarlink(f *testing.F) {
	f.Add([]byte(`{"parameters":{"addresses":[{"ifindex":2,"family":2,"address":[93,184,215,14]},{"family":10,"address":[32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1]}],"name":"example.com","flags":0}}`))
	f.Add([]byte(`{"error":"io.systemd.Resolve.DNSError","parameters":{"rcode":3}}`))
	f.Add([]byte(`{"parameters":{"addresses":[{"family":2,"address":[1,2,3,256]}]}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		as, err := parseVarlink(b)
		if err != nil {
			if _, ok := err.(*Refused); !ok {
				t.Fatalf("error %T %v is not a Refused", err, err)
			}
			return
		}
		if len(as) == 0 {
			t.Fatal("no addresses and no error")
		}
		for _, a := range as {
			if !a.IsValid() || a.Zone() != "" {
				t.Fatalf("address %v", a)
			}
			CheckPrefix(a)
		}
	})
}

func FuzzParsePref64(f *testing.F) {
	f.Add([]byte(`{"parameters":{"Interfaces":[{"Name":"lo"},{"Name":"eth0","NDisc":{"PREF64":[{"Prefix":[42,1,5,192,0,100,0,0,0,0,0,0,0,0,0,0],"PrefixLength":96,"LifetimeUSec":1800000000}]}}]}}`))
	f.Add([]byte(`{"parameters":{"Interfaces":[{"NDisc":{"PREF64":[{"Prefix":[1,2,3,4],"PrefixLength":-1}]}}]}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		ps, err := parsePref64(b)
		if err != nil {
			return
		}
		for _, p := range ps {
			if !p.Addr().Is6() || p.Bits() < 0 {
				t.Fatalf("prefix %v", p)
			}
			// every address under an accepted prefix goes through the NAT64 check
			CheckPrefix(p.Addr(), p)
		}
	})
}

func FuzzCheckPrefix(f *testing.F) {
	f.Add([]byte(netip.MustParseAddr("64:ff9b::a00:1").AsSlice()), []byte(netip.MustParseAddr("2a01:5c0:64::").AsSlice()), 96)
	f.Add([]byte{10, 0, 0, 1}, []byte{}, 0)
	f.Fuzz(func(t *testing.T, a, p []byte, bits int) {
		addr, ok := netip.AddrFromSlice(a)
		if !ok {
			return
		}
		var nsp []netip.Prefix
		if pa, ok := netip.AddrFromSlice(p); ok {
			if pp, err := pa.Prefix(bits); err == nil {
				nsp = append(nsp, pp)
			}
		}
		CheckPrefix(addr, nsp...)
	})
}

// FuzzLoadLists reads an allowlist directory: service.list, common.list and one agent list.
func FuzzLoadLists(f *testing.F) {
	f.Add([]byte("keys api.anthropic.com:443 # comment\ngit github.com:443\n"), []byte("pypi.org:443\n"), []byte("proxy.golang.org:443\n"))
	f.Add([]byte("nope x.y:1\n"), []byte("a b\n"), []byte(strings.Repeat("x", 70000)))
	f.Fuzz(func(t *testing.T, svc, common, agent []byte) {
		dir := t.TempDir()
		for name, b := range map[string][]byte{"service.list": svc, "common.list": common, "agent-a.list": agent} {
			if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		l, err := LoadLists(dir)
		if err != nil {
			return
		}
		for _, e := range l.Common {
			if !l.Allowed("proxy", "", e) {
				t.Fatalf("common entry %v not allowed", e)
			}
		}
	})
}
