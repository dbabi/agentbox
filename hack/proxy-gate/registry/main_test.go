package main

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// The packages npm and pip check: gate-app names its 24 dependencies, every tarball matches its sha512 integrity
// line, the wheel matches the sha256 in its index link, and the log, read on the ctl name with the token only, names the
// package requests and the server name but none of its own connections or requests.
func TestRegistry(t *testing.T) {
	const tok = "0123456789abcdef0123"
	r, caPEM, err := New("reg.gate.test", tok, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go r.Serve(l)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("no CA")
	}
	client := func(name string) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: name},
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return new(net.Dialer).DialContext(ctx, "tcp", l.Addr().String())
			}}}
	}
	c := client("reg.gate.test")
	get := func(c *http.Client, path string) ([]byte, int) {
		t.Helper()
		resp, err := c.Get("https://reg.gate.test" + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return b, resp.StatusCode
	}
	var doc struct {
		Versions map[string]struct {
			Dependencies map[string]string
			Dist         struct{ Tarball, Integrity, Shasum string }
		}
	}
	b, _ := get(c, "/npm/gate-app")
	if json.Unmarshal(b, &doc) != nil || len(doc.Versions["1.0.0"].Dependencies) != Deps {
		t.Fatalf("gate-app packument: %s", b)
	}
	for _, n := range []string{"gate-app", "gate-dep-01", "gate-dep-24"} {
		b, _ := get(c, "/npm/"+n)
		json.Unmarshal(b, &doc)
		d := doc.Versions["1.0.0"].Dist
		tb, st := get(c, strings.TrimPrefix(d.Tarball, "https://reg.gate.test"))
		s := sha512.Sum512(tb)
		if st != 200 || d.Integrity != "sha512-"+base64.StdEncoding.EncodeToString(s[:]) {
			t.Fatalf("%s: tarball %d, integrity %s", n, st, d.Integrity)
		}
	}
	idx, _ := get(c, "/simple/gatepkg/")
	m := regexp.MustCompile(`href="([^"#]+)#sha256=([0-9a-f]{64})"`).FindSubmatch(idx)
	if m == nil {
		t.Fatalf("index: %s", idx)
	}
	whl, _ := get(c, string(m[1]))
	if h := sha256.Sum256(whl); hex.EncodeToString(h[:]) != string(m[2]) {
		t.Fatal("the wheel does not match its index link")
	}
	if b, st := get(c, "/_log/"+tok); st != 404 || strings.Contains(string(b), "req") {
		t.Fatalf("the log on the registry's own name: %d", st)
	}
	ctl := client("ctl.reg.gate.test")
	if _, st := get(ctl, "/_log/wrong"); st != 404 {
		t.Fatalf("a wrong token: %d", st)
	}
	lg, _ := get(ctl, "/_log/"+tok)
	if !strings.Contains(string(lg), "sni=reg.gate.test") || !strings.Contains(string(lg), "host=reg.gate.test GET /simple/gatepkg/") ||
		strings.Contains(string(lg), "ctl.") || strings.Contains(string(lg), "/_log/wrong") {
		t.Fatalf("log:\n%s", lg)
	}
}
