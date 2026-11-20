package ntfy

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestServerYML(t *testing.T) {
	y := ServerYML(BaseURL("box"))
	for _, l := range []string{`base-url: "https://box:8443"`, `listen-http: "-"`, "listen-unix: /run/ntfy/ntfy.sock",
		"listen-unix-mode: 0660", "auth-file: /var/lib/ntfy/user.db", "auth-default-access: deny-all", `upstream-base-url: "https://ntfy.sh"`} {
		if !strings.Contains("\n"+y, "\n"+l+"\n") {
			t.Errorf("server.yml has no line %q", l)
		}
	}
	if !strings.Contains(dropIn, "Requires=agentbox-firewall.service\n") || !strings.Contains(dropIn, "ExecStartPre=+"+agentboxBin+" fwcheck\n") {
		t.Error("drop-in lost the firewall gate")
	}
	if !strings.Contains(tmpfiles, "d /run/ntfy 2750 _ntfy agentbox-notify -\n") {
		t.Error("tmpfiles lost the setgid socket dir")
	}
}

func TestCheckStatusUID(t *testing.T) {
	st := "Name:\tntfy\nUid:\t983\t983\t983\t983\nGid:\t983\t983\t983\t983\n"
	if err := checkStatusUID(st, "983"); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{strings.Replace(st, "983\t983\t983\t983\nGid", "983\t0\t983\t983\nGid", 1), "Name:\tntfy\n"} {
		if checkStatusUID(bad, "983") == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if checkStatusUID(st, "65534") == nil {
		t.Error("accepted another uid")
	}
}

// nft 1.1.6 `nft -j list set inet agentbox ntfy_dst4`
const setJSON = `{"nftables": [{"metainfo": {"version": "1.1.6", "release_name": "Commodore Bullmoose #7", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "ntfy_dst4", "table": "agentbox", "type": {"typeof": {"concat": [{"payload": {"protocol": "ip", "field": "daddr"}}, {"payload": {"protocol": "tcp", "field": "dport"}}]}}, "handle": 2, "flags": ["timeout"], "elem": [{"elem": {"val": {"concat": ["159.203.148.75", 443]}, "timeout": 600, "expires": 599}}, {"concat": ["144.126.249.138", 443]}]}}]}`

func TestDstSubset(t *testing.T) {
	es, err := parseSetElems([]byte(setJSON))
	if err != nil || len(es) != 2 || es[0].addr.String() != "159.203.148.75" || es[1].port != 443 {
		t.Fatalf("%v %v", es, err)
	}
	now := time.Unix(1_800_000_000, 0)
	a1, a2 := netip.MustParseAddr("159.203.148.75"), netip.MustParseAddr("144.126.249.138")
	as := merge(nil, []netip.Addr{a1, a2}, now.Add(-9*time.Minute))
	if err := checkElems("ntfy_dst4", es, as, now); err != nil {
		t.Errorf("fresh answers: %v", err)
	}
	if err := checkElems("ntfy_dst4", es, as, now.Add(2*time.Minute)); err == nil {
		t.Error("answers older than the element timeout accepted")
	}
	if err := checkElems("ntfy_dst4", es, as[:1], now); err == nil || !strings.Contains(err.Error(), "144.126.249.138") {
		t.Errorf("an element rootd never added: %v", err)
	}
	if err := checkElems("ntfy_dst4", nil, nil, now); err != nil {
		t.Errorf("an empty set must pass: %v", err)
	}
	// a refresh restamps current answers and drops stale ones
	m := merge(as, []netip.Addr{a1}, now.Add(2*time.Minute))
	if len(m) != 1 || m[0].Addr != a1 || m[0].At != now.Add(2*time.Minute).Unix() {
		t.Errorf("merge: %+v", m)
	}
	if _, err := parseSetElems([]byte(`{"nftables": [{"set": {"elem": [{"concat": ["not-an-ip", 443]}]}}]}`)); err == nil {
		t.Error("bad element accepted")
	}
}
