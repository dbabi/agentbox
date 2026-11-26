package gomodfilter

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testCert is a self-signed certificate for names and the pool that trusts it.
func testCert(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, pool
}

// fakeProxy is a task's proxy socket: CONNECT proxy.golang.org:443 tunnels to upstream, GET /_cache/go/... answers
// from files; it logs every request target.
type fakeProxy struct {
	sock     string
	upstream string
	files    map[string]string // request target -> body; anything else 404
	mu       sync.Mutex
	log      []string
	connects atomic.Int32
}

func (p *fakeProxy) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.log...)
}

func (p *fakeProxy) serve(t *testing.T) {
	l, err := net.Listen("unix", p.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				p.mu.Lock()
				p.log = append(p.log, req.Method+" "+req.RequestURI)
				p.mu.Unlock()
				if req.Method == http.MethodConnect {
					p.connects.Add(1)
					up, err := net.Dial("tcp", p.upstream)
					if err != nil {
						return
					}
					defer up.Close()
					io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
					go io.Copy(up, br)
					io.Copy(c, up)
					return
				}
				body, ok := p.files[req.RequestURI]
				if !ok {
					io.WriteString(c, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
					return
				}
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}()
		}
	}()
}

type fixture struct {
	f      *Filter
	p      *fakeProxy
	srv    *httptest.Server // the filter
	taints atomic.Int32
	asked  sync.Map // upstream request paths
}

// newFixture: an upstream proxy.golang.org that knows example.com/m at v1.0.0 (and its +incompatible and pseudo
// forms) and answers 410 for v1.9.0; the filter in front of a fake proxy socket.
func newFixture(t *testing.T, h2 bool) *fixture {
	t.Helper()
	x := &fixture{}
	cert, pool := testCert(t, Upstream)
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		x.asked.Store(r.URL.Path, r.Proto)
		v, ok := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/example.com/m/@v/"), ".info")
		switch {
		case !ok || v == "v1.9.0":
			http.Error(w, "gone", http.StatusGone)
		case v == "v1.8.0":
			fmt.Fprint(w, `{"Version":"v1.8.1","Time":"2026-01-01T00:00:00Z"}`) // not the version asked for
		default:
			fmt.Fprintf(w, `{"Version":%q,"Time":"2026-01-01T00:00:00Z"}`, v)
		}
	}))
	up.EnableHTTP2 = h2
	up.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	up.StartTLS()
	t.Cleanup(up.Close)
	dir, err := os.MkdirTemp("/tmp", "gmf") // sun_path is 104 bytes on macOS
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	x.p = &fakeProxy{sock: filepath.Join(dir, "proxy.sock"), upstream: up.Listener.Addr().String(), files: map[string]string{
		"/_cache/go/example.com/m/@v/v1.0.0.mod": "module example.com/m\n",
		"/_cache/go/example.com/m/@v/v1.0.0.zip": "zipbytes",
	}}
	x.p.serve(t)
	x.f = &Filter{Private: "corp.example/*", Roots: pool,
		Taint: func() error { x.taints.Add(1); return nil },
		Dial:  func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "unix", x.p.sock) }}
	x.srv = httptest.NewServer(x.f)
	t.Cleanup(x.srv.Close)
	return x
}

// raw sends one request head as written and returns the status code and body.
func (x *fixture) raw(t *testing.T, head string) (int, string) {
	t.Helper()
	c, err := net.Dial("tcp", x.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, head)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("%q: %v", head, err)
	}
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (x *fixture) get(t *testing.T, target string) (int, string) {
	return x.raw(t, "GET "+target+" HTTP/1.1\r\nHost: 127.0.0.1:8083\r\nConnection: close\r\n\r\n")
}

// A-G5's filter half: everything but an exact canonical .info, .mod or .zip gets the filter's own 404, with nothing
// on the proxy socket and no taint.
func TestFilterGrammar(t *testing.T) {
	x := newFixture(t, true)
	for _, head := range []string{
		"GET /example.com/m/@v/list HTTP/1.1\r\n\r\n",
		"GET /example.com/m/@latest HTTP/1.1\r\n\r\n",
		"GET /sumdb/sum.golang.org/supported HTTP/1.1\r\n\r\n",
		"GET /sumdb/sum.golang.org/lookup/example.com/m@v1.0.0 HTTP/1.1\r\n\r\n",
		"GET /example.com/m/@v/master.info HTTP/1.1\r\n\r\n",       // a branch
		"GET /example.com/m/@v/v1.2.info HTTP/1.1\r\n\r\n",         // a partial version
		"GET /example.com/m/@v/0123456789ab.info HTTP/1.1\r\n\r\n", // a commit hash
		"GET /example.com/m/@v/v1.0.0.info?x=1 HTTP/1.1\r\n\r\n",   // a query string
		"GET /example.com/m/@v/v1.0.0.info? HTTP/1.1\r\n\r\n",      // an empty one
		"GET /Example.com/m/@v/v1.0.0.info HTTP/1.1\r\n\r\n",       // a bad escape
		"GET /example.com/m/@v/v1.0.0-RC1.info HTTP/1.1\r\n\r\n",   // another
		"GET /ex%61mple.com/m/@v/v1.0.0.info HTTP/1.1\r\n\r\n",     // a % escape
		"GET /example.com/%2e%2e/m/@v/v1.0.0.mod HTTP/1.1\r\n\r\n", // and an escaped dot
		"GET /example.com/../m/@v/v1.0.0.mod HTTP/1.1\r\n\r\n",     // a dot-dot element
		"GET /corp.example/x/@v/v1.0.0.info HTTP/1.1\r\n\r\n",      // a GOPRIVATE path
		"GET /example.com/m/@v/v1.0.0.ziphash HTTP/1.1\r\n\r\n",    // another file
		"GET /example.com/m/@v/v1.0.0 HTTP/1.1\r\n\r\n",            // none
		"GET /example.com/m/@v/v1.0.0.info/x HTTP/1.1\r\n\r\n",     // a deeper path
		"GET http://example.com/m/@v/v1.0.0.info HTTP/1.1\r\n\r\n", // absolute form
		"HEAD /example.com/m/@v/v1.0.0.info HTTP/1.1\r\n\r\n",      // another method
		"POST /example.com/m/@v/v1.0.0.mod HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
		"GET /example.com/m/@v/v1.0.0.mod HTTP/1.1\r\nContent-Length: 2\r\n\r\nab", // a body
		"GET /example.com/m/@v/v1.0.0.mod HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
	} {
		h := strings.Replace(head, "\r\n\r\n", "\r\nHost: 127.0.0.1:8083\r\nConnection: close\r\n\r\n", 1)
		if st, _ := x.raw(t, h); st != http.StatusNotFound {
			t.Errorf("%q: %d, want the filter's 404", head, st)
		}
	}
	if s := x.p.seen(); len(s) != 0 || x.taints.Load() != 0 {
		t.Fatalf("refused requests reached the proxy %q or tainted the task %d times", s, x.taints.Load())
	}
}

// Steps 2 to 4: one taint for any number of concurrent first requests, .info from the live check, .mod and .zip from
// the cache path only for an available version, and every live check on one HTTP/2 tunnel.
func TestFilterServes(t *testing.T) {
	x := newFixture(t, true)
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v := fmt.Sprintf("v1.0.%d", i+1)
			if st, b := x.get(t, "/example.com/m/@v/"+v+".info"); st != 200 || !strings.Contains(b, `"`+v+`"`) {
				t.Errorf("%s.info: %d %q", v, st, b)
			}
		}()
	}
	wg.Wait()
	if n := x.taints.Load(); n != 1 {
		t.Errorf("%d taint calls for 20 parallel first requests, want 1", n)
	}
	for _, c := range []struct{ target, want string }{
		{"/example.com/m/@v/v1.0.0.mod", "module example.com/m\n"},
		{"/example.com/m/@v/v1.0.0.zip", "zipbytes"},
	} {
		if st, b := x.get(t, c.target); st != 200 || b != c.want {
			t.Errorf("%s: %d %q", c.target, st, b)
		}
	}
	for _, target := range []string{
		"/example.com/m/@v/v2.0.0+incompatible.info", // kept by CanonicalVersion
		"/example.com/m/@v/v0.0.0-20191109021931-daa7c04131f5.info",
	} {
		if st, _ := x.get(t, target); st != 200 {
			t.Errorf("%s: %d, want it served", target, st)
		}
	}
	if st, _ := x.get(t, "/example.com/m/@v/v2.0.0+incompatible.mod"); st != 404 { // the fake cache doesn't hold it
		t.Errorf("a cache miss: %d, want 404", st)
	}
	if n := x.p.connects.Load(); n != 1 {
		t.Errorf("%d CONNECTs for every live check, want 1 HTTP/2 tunnel", n)
	}
	x.asked.Range(func(k, v any) bool {
		if v != "HTTP/2.0" {
			t.Errorf("live check %s over %s", k, v)
		}
		return true
	})
	for _, l := range x.p.seen() {
		if l != "CONNECT proxy.golang.org:443" && !strings.HasPrefix(l, "GET /_cache/go/example.com/m/@v/") {
			t.Errorf("the proxy saw %q", l)
		}
	}
}

// Step 3: a version upstream withdraws (410), or whose .info names another version, gets 404 for every file, and the
// cache path is never asked for it; the outcome is asked again only after RetryAfter.
func TestFilterLiveCheck(t *testing.T) {
	x := newFixture(t, false) // HTTP/1.1 keep-alive
	now := time.Now()
	x.f.Now = func() time.Time { return now }
	x.p.files["/_cache/go/example.com/m/@v/v1.9.0.zip"] = "withdrawn but still cached"
	for _, target := range []string{"/example.com/m/@v/v1.9.0.info", "/example.com/m/@v/v1.9.0.mod", "/example.com/m/@v/v1.9.0.zip",
		"/example.com/m/@v/v1.8.0.info", "/example.com/m/@v/v1.8.0.zip"} {
		if st, _ := x.get(t, target); st != 404 {
			t.Errorf("%s: %d, want 404", target, st)
		}
	}
	for _, l := range x.p.seen() {
		if strings.HasPrefix(l, "GET /_cache/") {
			t.Errorf("an unavailable version reached the cache path: %q", l)
		}
	}
	n := 0
	x.asked.Range(func(any, any) bool { n++; return true })
	if n != 2 {
		t.Errorf("%d live checks for 2 versions, want one each", n)
	}
	x.asked.Delete("/example.com/m/@v/v1.9.0.info")
	now = now.Add(RetryAfter)
	x.get(t, "/example.com/m/@v/v1.9.0.mod")
	if _, ok := x.asked.Load("/example.com/m/@v/v1.9.0.info"); !ok {
		t.Error("a failed check was not asked again after RetryAfter")
	}
	if st, _ := x.get(t, "/example.com/m/@v/v1.0.0.mod"); st != 200 {
		t.Errorf("over HTTP/1.1: %d", st)
	}
}

// Step 2: if the taint call fails, the filter answers 404 to everything for the rest of the task and asks the proxy
// for nothing.
func TestFilterTaintFails(t *testing.T) {
	x := newFixture(t, true)
	x.f.Taint = func() error { x.taints.Add(1); return errors.New("gate unreachable") }
	for range 3 {
		if st, _ := x.get(t, "/example.com/m/@v/v1.0.0.info"); st != 404 {
			t.Errorf("after a failed taint: %d", st)
		}
	}
	if n := x.taints.Load(); n != 1 || len(x.p.seen()) != 0 {
		t.Errorf("taint calls %d (want 1), proxy requests %q (want none)", n, x.p.seen())
	}
}

// File.Escaped builds the proxy path from the checked values: upper case and +incompatible survive the round trip.
func TestEscaped(t *testing.T) {
	r := httptest.NewRequest("GET", "/github.com/!burnt!sushi/toml/@v/v1.2.0+incompatible.zip", nil)
	r.RequestURI = "/github.com/!burnt!sushi/toml/@v/v1.2.0+incompatible.zip"
	f, st := Request(r, "", []string{"zip"}, "")
	if st != 0 || f.Path != "github.com/BurntSushi/toml" || f.Escaped() != r.RequestURI || f.Key() != "go:github.com/BurntSushi/toml@v1.2.0+incompatible.zip" {
		t.Fatalf("%+v %d %s", f, st, f.Escaped())
	}
}
