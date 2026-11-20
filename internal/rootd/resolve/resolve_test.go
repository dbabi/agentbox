package resolve

import (
	"bufio"
	"encoding/json"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckPrefix(t *testing.T) {
	for a, ok := range map[string]bool{
		"1.1.1.1": true, "159.203.148.75": true, "2606:4700::1": true,
		"10.1.2.3": false, "127.0.0.53": false, "100.100.100.100": false, "169.254.1.1": false, "192.168.1.1": false,
		"240.0.0.1": false, "0.0.0.0": false, "::1": false, "::ffff:1.1.1.1": false, "fd00::1": false, "fe80::1": false,
		"64:ff9b::a00:1":   false, // NAT64 of 10.0.0.1
		"64:ff9b::101:101": true,  // NAT64 of 1.1.1.1: NAT64-only LANs still work
		"64:ff9b:1::1":     false,
	} {
		if err := CheckPrefix(netip.MustParseAddr(a)); (err == nil) != ok {
			t.Errorf("CheckPrefix(%s) = %v, want ok=%v", a, err, ok)
		}
	}
}

func TestCheckRoute(t *testing.T) {
	a := netip.MustParseAddr("1.1.1.1")
	def := route{typ: rtnUnicast, oif: 2, gw: true}
	for _, c := range []struct {
		r  route
		ok bool
	}{
		{route{rtnUnicast, 2, true}, true},
		{route{rtnUnicast, 2, false}, false}, // on-link LAN address that looks public
		{route{rtnUnicast, 7, true}, false},  // tailnet subnet route
		{route{2, 1, false}, false},          // RTN_LOCAL: the box's own address
	} {
		if err := checkRoute(a, c.r, def); (err == nil) != c.ok {
			t.Errorf("checkRoute(%+v) = %v, want ok=%v", c.r, err, c.ok)
		}
	}
	if err := checkRoute(a, route{rtnUnicast, 2, false}, route{rtnUnicast, 2, false}); err != nil {
		t.Errorf("no gateway on either route: %v", err)
	}
}

// fakeResolved answers one Varlink call with rep and returns the request it got.
func fakeResolved(t *testing.T, rep string) (string, chan map[string]any) {
	sock := filepath.Join(t.TempDir(), "r.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	got := make(chan map[string]any, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, _ := bufio.NewReader(c).ReadBytes(0)
		var m map[string]any
		json.Unmarshal(b[:len(b)-1], &m)
		got <- m
		c.Write(append([]byte(rep), 0))
	}()
	return sock, got
}

func TestHostname(t *testing.T) {
	sock, got := fakeResolved(t, `{"parameters":{"addresses":[{"ifindex":2,"family":2,"address":[159,203,148,75]},{"family":10,"address":[38,4,161,128,0,0,0,0,0,0,0,0,0,0,0,1]}],"name":"ntfy.sh","flags":1}}`)
	as, err := hostname(sock, "ntfy.sh")
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 2 || as[0].String() != "159.203.148.75" || as[1].String() != "2604:a180::1" {
		t.Fatalf("addresses %v", as)
	}
	req := <-got
	p := req["parameters"].(map[string]any)
	if req["method"] != "io.systemd.Resolve.ResolveHostname" || p["name"] != "ntfy.sh" || p["flags"].(float64) != Flags {
		t.Fatalf("request %v", req)
	}
	if Flags != 1|1<<8|1<<11|1<<13 {
		t.Fatalf("flags %#x", Flags)
	}
}

func TestHostnameErrors(t *testing.T) {
	for rep, want := range map[string]string{
		`{"error":"io.systemd.Resolve.NoSuchResourceRecord","parameters":{}}`:                            "NoSuchResourceRecord",
		`{"parameters":{"addresses":[]}}`:                                                                "no addresses",
		`{"parameters":{"addresses":[{"family":2,"address":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]}]}}`: "bad address",
		`{"parameters":{"addresses":[{"family":2,"address":[1,2,3,400]}]}}`:                              "bad address byte",
	} {
		sock, _ := fakeResolved(t, rep)
		if _, err := hostname(sock, "x.example"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("reply %s: err %v, want %q", rep, err, want)
		}
	}
}
