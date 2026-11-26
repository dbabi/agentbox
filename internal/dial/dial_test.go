package dial

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"agentbox/internal/rootd/resolve"
)

// fakeRootd answers each line on its resolve socket with replies[host], and keeps the requests.
type fakeRootd struct {
	sock string
	mu   sync.Mutex
	reqs []map[string]any
}

func newRootd(t *testing.T, replies map[string]string) *fakeRootd {
	dir, err := os.MkdirTemp("", "dial") // short: a socket path holds 104 bytes on macOS
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &fakeRootd{sock: filepath.Join(dir, "resolve.sock")}
	l, err := net.Listen("unix", f.sock)
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
				line, err := bufio.NewReader(c).ReadBytes('\n')
				var req map[string]any
				if err != nil || json.Unmarshal(line, &req) != nil {
					return
				}
				f.mu.Lock()
				f.reqs = append(f.reqs, req)
				f.mu.Unlock()
				host, _ := req["host"].(string)
				if r, ok := replies[host]; ok && r != "" {
					io.WriteString(c, r+"\n")
				}
			}()
		}
	}()
	return f
}

func (f *fakeRootd) requests() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.reqs)
}

func reason(err error) string {
	var r *resolve.Refused
	if errors.As(err, &r) {
		return r.Reason
	}
	return "not a refusal"
}

func TestResolve(t *testing.T) {
	f := newRootd(t, map[string]string{
		"a.example":  `{"ok":true,"addrs":["93.184.215.14","2606:2800:21f:cb07::1"],"expires_at":1800000600000}`,
		"nl.example": `{"ok":false,"reason":"not_allowlisted"}`, "np.example": `{"ok":false,"reason":"non_public"}`,
		"nx.example": `{"ok":false,"reason":"no_such_name"}`, "un.example": `{"ok":false,"reason":"unavailable"}`,
		"br.example": `{"ok":false,"reason":"bad_request"}`, "empty.example": `{"ok":true,"addrs":[]}`,
		"zone.example": `{"ok":true,"addrs":["fe80::1%eth0"]}`, "mapped.example": `{"ok":true,"addrs":["::ffff:93.184.215.14"]}`,
		"name.example": `{"ok":true,"addrs":["a.example"]}`, "junk.example": `ok`, "closed.example": ``,
	})
	got, err := Resolve(context.Background(), f.sock, "task_01", "a.example", 443)
	if err != nil || !slices.Equal(got, []netip.Addr{netip.MustParseAddr("93.184.215.14"), netip.MustParseAddr("2606:2800:21f:cb07::1")}) {
		t.Fatalf("%v %v", got, err)
	}
	r := f.requests()[0]
	if r["op"] != "resolve" || r["host"] != "a.example" || r["port"] != 443.0 || r["task"] != "task_01" || len(r) != 4 {
		t.Fatalf("request %v", r)
	}
	for host, want := range map[string]string{"nl.example": resolve.NotAllowlisted, "np.example": resolve.NonPublic,
		"nx.example": resolve.NoSuchName, "un.example": resolve.Unavailable, "br.example": resolve.Unavailable,
		"empty.example": resolve.Unavailable, "zone.example": resolve.Unavailable, "mapped.example": resolve.Unavailable,
		"name.example": resolve.Unavailable, "junk.example": resolve.Unavailable, "closed.example": resolve.Unavailable} {
		if a, err := Resolve(context.Background(), f.sock, "", host, 443); reason(err) != want || a != nil {
			t.Errorf("%s: %v %v, want %s", host, a, err, want)
		}
	}
	if _, err := Resolve(context.Background(), filepath.Join(filepath.Dir(f.sock), "none.sock"), "", "a.example", 443); reason(err) != resolve.Unavailable {
		t.Errorf("no rootd socket: %v", err)
	}
}

// One HTTPS request through Client: rootd is asked once for the request's host and port, its addresses are dialed in
// order, and TLS and HTTP still name the host. A redirect is not followed.
func TestClient(t *testing.T) {
	var sni, hostHdr string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		sni, hostHdr = r.TLS.ServerName, r.Host
		io.WriteString(w, "pinned")
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	f := newRootd(t, map[string]string{"example.com": `{"ok":true,"addrs":["2001:db8::1","127.0.0.1"],"expires_at":1}`})
	var tried []string
	d := Dialer{Sock: f.sock, Task: "task_01", dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		tried = append(tried, addr)
		if addr != srv.Listener.Addr().String() {
			return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
		}
		return new(net.Dialer).DialContext(ctx, network, addr)
	}}
	c := d.Client()
	if d.Transport().Proxy != nil || c.Jar != nil {
		t.Fatal("the transport takes a proxy from the environment, or the client keeps cookies")
	}
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs // httptest's certificate names example.com
	c.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: pool}
	u := "https://example.com:" + strconv.Itoa(port)
	resp, err := c.Get(u + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "pinned" || sni != "example.com" || hostHdr != "example.com:"+strconv.Itoa(port) {
		t.Fatalf("body %q, SNI %q, Host %q", b, sni, hostHdr)
	}
	if want := []string{"[2001:db8::1]:" + strconv.Itoa(port), "127.0.0.1:" + strconv.Itoa(port)}; !slices.Equal(tried, want) {
		t.Fatalf("dialed %v, want %v", tried, want)
	}
	if r := f.requests(); len(r) != 1 || r[0]["host"] != "example.com" || r[0]["port"] != float64(port) || r[0]["task"] != "task_01" {
		t.Fatalf("rootd requests %v", r)
	}
	_, err = c.Get(u + "/moved")
	var ue *url.Error
	if !errors.As(err, &ue) || !errors.Is(err, ErrRedirect) {
		t.Fatalf("a redirect: %v", err)
	}
}

// The addresses share Budget: each attempt gets an even share of what is left, and a failure reports the first
// address's kind. A name rootd refuses, a non-TCP network and a bad port dial nothing.
func TestDialContext(t *testing.T) {
	f := newRootd(t, map[string]string{"two.example": `{"ok":true,"addrs":["93.184.215.14","93.184.215.15"]}`,
		"np.example": `{"ok":false,"reason":"non_public"}`, "1.2.3.4": `{"ok":false,"reason":"not_allowlisted"}`})
	var deadlines []time.Duration
	var fail error
	start := time.Now()
	d := Dialer{Sock: f.sock, dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		dl, _ := ctx.Deadline()
		deadlines = append(deadlines, dl.Sub(start))
		return nil, fail
	}}
	for _, c := range []struct {
		err  error
		kind string
	}{{&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, Refused},
		{&net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.EPERM)}, Blocked},
		{&net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}, Timeout}} {
		deadlines, fail, start = nil, c.err, time.Now()
		_, err := d.DialContext(context.Background(), "tcp", "two.example:443")
		var de *Error
		if !errors.As(err, &de) || de.Kind != c.kind || !errors.Is(err, c.err) {
			t.Fatalf("%v: got %v, want kind %s", c.err, err, c.kind)
		}
		if len(deadlines) != 2 || (deadlines[0]-Budget/2).Abs() > time.Second || (deadlines[1]-Budget).Abs() > time.Second {
			t.Fatalf("deadlines %v, want about %v and %v", deadlines, Budget/2, Budget)
		}
	}
	deadlines = nil
	for addr, want := range map[string]string{"np.example:443": resolve.NonPublic, "1.2.3.4:443": resolve.NotAllowlisted} {
		if _, err := d.DialContext(context.Background(), "tcp", addr); reason(err) != want {
			t.Errorf("%s: %v, want %s", addr, err, want)
		}
	}
	n := len(f.requests())
	for _, c := range [][2]string{{"udp", "two.example:443"}, {"tcp", "two.example"}, {"tcp", "two.example:0"}, {"tcp", "two.example:65536"}} {
		if _, err := d.DialContext(context.Background(), c[0], c[1]); err == nil {
			t.Errorf("%s %s dialed", c[0], c[1])
		}
	}
	if len(deadlines) != 0 || len(f.requests()) != n {
		t.Fatalf("refused names or bad requests reached the dialer (%v) or rootd", deadlines)
	}
}

// kind reads the errors the kernel and Go's dialer give: an expired budget is a timeout.
func TestKind(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := new(net.Dialer).DialContext(ctx, "tcp", "127.0.0.1:9")
	if k := kind(err); k != Timeout {
		t.Errorf("%v: %s, want timeout", err, k)
	}
	if k := kind(&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)}); k != Refused {
		t.Errorf("EHOSTUNREACH: %s, want refused", k)
	}
}
