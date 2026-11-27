package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"agentbox/internal/dial"
	"agentbox/internal/ops"
	"agentbox/internal/rootd/resolve"
)

const tid = "task_01JD000000000000000000000Z"

// pair is a connected loopback pair: c is the task's end, s the proxy's.
func pair(t *testing.T) (c, s net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if s, err = ln.Accept(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); s.Close() })
	return c, s
}

// fakeDial and rig take their lock on every field a Serve goroutine reads: socket I/O orders nothing for the race
// detector.
type fakeDial struct {
	mu    sync.Mutex
	calls []string
	fn    func(e resolve.Entry) (net.Conn, error)
}

func (f *fakeDial) Dial(_ context.Context, task string, e resolve.Entry) (net.Conn, error) {
	f.mu.Lock()
	f.calls = append(f.calls, task+" "+e.String())
	fn := f.fn
	f.mu.Unlock()
	return fn(e)
}

func (f *fakeDial) set(fn func(resolve.Entry) (net.Conn, error)) {
	f.mu.Lock()
	f.fn = fn
	f.mu.Unlock()
}
func (f *fakeDial) log() []string { f.mu.Lock(); defer f.mu.Unlock(); return slices.Clone(f.calls) }
func (f *fakeDial) n() int        { return len(f.log()) }

type rig struct {
	s     *Server
	dial  *fakeDial
	mu    sync.Mutex
	taint []map[string]any
	down  bool // auditd NACKs
}

func newRig(t *testing.T, lists map[string]string) *rig {
	dir := t.TempDir()
	for n, b := range lists {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r := &rig{dial: &fakeDial{fn: func(resolve.Entry) (net.Conn, error) { return nil, errors.New("no upstream in this test") }}}
	r.s = &Server{Egress: dir, Dial: r.dial, Taint: func(rec map[string]any) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.down {
			return errors.New("auditd down")
		}
		r.taint = append(r.taint, rec)
		return nil
	}}
	return r
}

func (r *rig) taints() []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.taint)
}
func (r *rig) auditDown(v bool) { r.mu.Lock(); r.down = v; r.mu.Unlock() }

// do sends one request head on a task connection for agent and reads the reply head; c stays open for a tunnel.
func (r *rig) do(t *testing.T, agent, head string) (*http.Response, *bufio.Reader, net.Conn) {
	t.Helper()
	c, s := pair(t)
	go r.s.Serve(tid, agent, s)
	if _, err := io.WriteString(c, head); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: strings.Fields(head)[0]})
	if err != nil {
		t.Fatalf("%q: no reply: %v", head, err)
	}
	return resp, br, c
}

func connect(target string) string {
	return "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
}

// denied checks a §5.6 CONNECT refusal end to end and returns its denial: status, reason phrase, header, body that
// passes the strict parser, Connection: close, then EOF.
func denied(t *testing.T, resp *http.Response, status int, code string) ops.Denial {
	t.Helper()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != status || resp.Status != fmt.Sprintf("%d agentbox %s (run: agentbox why)", status, code) {
		t.Fatalf("status %q, want %d %s; body %s", resp.Status, status, code, body)
	}
	c, next, id, ok := ops.ParseDenialHeader(resp.Header.Get(ops.DenialHeaderName))
	var b struct {
		Error    string          `json:"error"`
		Agentbox json.RawMessage `json:"agentbox"`
	}
	if !ok || c.String() != code || json.Unmarshal(body, &b) != nil {
		t.Fatalf("header %q, body %s", resp.Header.Get(ops.DenialHeaderName), body)
	}
	d, err := ops.ParseDenial(b.Agentbox)
	if err != nil || d.ID != id || d.Next != next || d.By != "proxy" || b.Error != d.Msg || !resp.Close {
		t.Fatalf("denial %s: %v (close %v)", b.Agentbox, err, resp.Close)
	}
	return d
}

// §6.2 step 1 and C-G3: every refusal before rootd is one typed denial in the CONNECT format, made before any rootd call
// and any taint; it names only the requested host:port, and an IP literal not at all.
func TestRefusedBeforeRootd(t *testing.T) {
	var many strings.Builder
	for i := range 50 {
		fmt.Fprintf(&many, "listed%d.example.com:443\n", i)
	}
	r := newRig(t, map[string]string{"common.list": many.String(), "ga.list": "registry.example.com:443\nproxy.golang.org:443\n",
		"gb.list": "api.anthropic.com:443\n"}) // a vendor host written into a list by hand is still refused
	for _, c := range []struct {
		agent, target string
		status        int
		code, what    string
		next          ops.Next
		host          string
		remedy        string
	}{
		{"ga", "unlisted.example.com:443", 403, "EGRESS_NOT_ALLOWLISTED", "", ops.Ask, "unlisted.example.com", "net.allow_domain"},
		{"ga", "Listed1.Example.com:80", 403, "EGRESS_NOT_ALLOWLISTED", "", ops.Ask, "listed1.example.com", "net.allow_domain"},
		{"gb", "registry.example.com:443", 403, "EGRESS_NOT_ALLOWLISTED", "", ops.Ask, "registry.example.com", "net.allow_domain"},
		{"gb", "proxy.golang.org:443", 403, "EGRESS_NOT_ALLOWLISTED", "deputy_host", ops.Human, "proxy.golang.org", ""},
		{"gb", "sum.golang.org:443", 403, "EGRESS_NOT_ALLOWLISTED", "deputy_host", ops.Human, "sum.golang.org", ""},
		{"gb", "api.anthropic.com:443", 400, "EGRESS_WRONG_ROUTE", "llm_vendor", ops.Fix, "api.anthropic.com", ""},
		{"ga", "API.OpenAI.com:443", 400, "EGRESS_WRONG_ROUTE", "llm_vendor", ops.Fix, "api.openai.com", ""},
		{"ga", "api.anthropic.com.:443", 400, "EGRESS_WRONG_ROUTE", "llm_vendor", ops.Fix, "", ""}, // no A-label: not echoed
		// raw IPs, v4 and v6, the metadata address among them: no list holds an address, and none is echoed
		{"ga", "169.254.169.254:80", 403, "EGRESS_NOT_ALLOWLISTED", "", ops.Ask, "", ""},
		{"ga", "93.184.215.14:443", 403, "EGRESS_NOT_ALLOWLISTED", "", ops.Ask, "", ""},
		{"ga", "[::1]:443", 403, "EGRESS_NOT_ALLOWLISTED", "", ops.Ask, "", ""},
		{"ga", "[fd00:ec2::254]:80", 403, "EGRESS_NOT_ALLOWLISTED", "", ops.Ask, "", ""},
		{"ga", "registry.example.com:0443", 403, "EGRESS_NOT_ALLOWLISTED", "", ops.Ask, "registry.example.com", ""},
		{"ga", "registry.example.com", 403, "EGRESS_NOT_ALLOWLISTED", "", ops.Ask, "", ""},
		{"ga", "*.example.com:443", 403, "EGRESS_NOT_ALLOWLISTED", "", ops.Ask, "", ""},
	} {
		resp, _, _ := r.do(t, c.agent, connect(c.target))
		d := denied(t, resp, c.status, c.code)
		host := ""
		if d.Subject != nil {
			host = d.Subject.Host
		}
		if d.What != c.what || d.Next != c.next || host != c.host {
			t.Errorf("%s %s: what %q next %q host %q", c.agent, c.target, d.What, d.Next, host)
		}
		if c.remedy != "" && (d.Remedy[0].Op != c.remedy || d.Remedy[0].Args == nil || d.Remedy[0].Args.Host != c.host) {
			t.Errorf("%s %s: remedy %+v", c.agent, c.target, d.Remedy)
		}
		if b, _ := json.Marshal(d); bytes.Contains(b, []byte("listed2.example.com")) || bytes.Contains(b, []byte("169.254")) ||
			bytes.Contains(b, []byte("fd00")) {
			t.Errorf("%s: the denial names another entry or an address: %s", c.target, b)
		}
	}
	if r.dial.n() != 0 || len(r.taints()) != 0 {
		t.Fatalf("a refusal before rootd reached rootd (%d) or tainted (%v)", r.dial.n(), r.taints())
	}
}

// §6.2 step 2-3: rootd's refusals and failed dials map to their codes and statuses, and none taints.
func TestRootdAndDialRefusals(t *testing.T) {
	r := newRig(t, map[string]string{"common.list": "registry.example.com:443\n"})
	for _, c := range []struct {
		err        error
		status     int
		code, what string
	}{
		{&resolve.Refused{Reason: resolve.NonPublic, Detail: "10.0.0.1: private4"}, 403, "EGRESS_NAME_REJECTED", "non_public"},
		{&resolve.Refused{Reason: resolve.NoSuchName}, 502, "EGRESS_RESOLVE_FAILED", "no_such_name"},
		{&resolve.Refused{Reason: resolve.Unavailable}, 502, "EGRESS_RESOLVE_FAILED", "unavailable"},
		{&resolve.Refused{Reason: "something new"}, 502, "EGRESS_RESOLVE_FAILED", "unavailable"},
		{&resolve.Refused{Reason: resolve.NotAllowlisted}, 403, "EGRESS_NOT_ALLOWLISTED", ""}, // removed while we checked
		{&dial.Error{What: dial.Timeout, Err: opErr(os.ErrDeadlineExceeded)}, 504, "EGRESS_DIAL_FAILED", "timeout"},
		{&dial.Error{What: dial.Refused, Err: opErr(syscall.ECONNREFUSED)}, 502, "EGRESS_DIAL_FAILED", "refused"},
		{&dial.Error{What: dial.Blocked, Err: opErr(syscall.EHOSTUNREACH)}, 502, "EGRESS_DIAL_FAILED", "blocked"},
		{errors.New("not a dial error"), 502, "EGRESS_DIAL_FAILED", "blocked"},
	} {
		r.dial.set(func(resolve.Entry) (net.Conn, error) { return nil, c.err })
		resp, _, _ := r.do(t, "ga", connect("registry.example.com:443"))
		d := denied(t, resp, c.status, c.code)
		if d.What != c.what {
			t.Errorf("%v: what %q, want %q", c.err, d.What, c.what)
		}
		if b, _ := json.Marshal(d); bytes.Contains(b, []byte("10.0.0.1")) || bytes.Contains(b, []byte("private4")) {
			t.Errorf("rootd's detail reached the task: %s", b)
		}
	}
	if len(r.taints()) != 0 {
		t.Fatalf("a refused CONNECT tainted: %v", r.taints())
	}
	if l := r.dial.log(); len(l) == 0 || l[0] != tid+" registry.example.com:443" {
		t.Fatalf("dial calls %v: each names the task and the canonical entry", l)
	}
}

// upstream is a TCP server that records every byte it gets and answers "hello" at once, then echoes.
func upstream(t *testing.T) (dial func(resolve.Entry) (net.Conn, error), got func() string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var b bytes.Buffer
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.Write([]byte("hello\n"))
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					mu.Lock()
					b.Write(buf[:n])
					mu.Unlock()
					c.Write(buf[:n])
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return func(resolve.Entry) (net.Conn, error) { return net.Dial("tcp", ln.Addr().String()) },
		func() string { mu.Lock(); defer mu.Unlock(); return b.String() }
}

// §6.2 step 4: the taint is ACKed before any byte flows; with auditd down the CONNECT gets 503 AUDIT_UNAVAILABLE and the
// upstream gets nothing. Then the tunnel carries bytes both ways, starting with any the client sent early.
func TestTaintBeforeTunnel(t *testing.T) {
	r := newRig(t, map[string]string{"ga.list": "registry.example.com:443\n"})
	dial, got := upstream(t)
	r.dial.set(dial)
	r.auditDown(true)
	resp, _, _ := r.do(t, "ga", connect("Registry.Example.COM:443")+"early bytes")
	denied(t, resp, 503, "AUDIT_UNAVAILABLE")
	time.Sleep(100 * time.Millisecond)
	if g := got(); g != "" {
		t.Fatalf("with auditd down the upstream got %q", g)
	}

	r.auditDown(false)
	resp, br, c := r.do(t, "ga", connect("registry.example.com:443")+"early ")
	if resp.StatusCode != 200 || resp.Header.Get(ops.DenialHeaderName) != "" {
		t.Fatalf("CONNECT: %s", resp.Status)
	}
	if tt := r.taints(); len(tt) != 1 || tt[0]["type"] != "TAINT" || tt[0]["subject"] != "task:"+tid ||
		tt[0]["source"] != "proxy:registry.example.com:443" || len(tt[0]) != 3 {
		t.Fatalf("taint records %v", tt)
	}
	if l, err := br.ReadString('\n'); err != nil || l != "hello\n" {
		t.Fatalf("upstream's first bytes: %q %v", l, err)
	}
	io.WriteString(c, "bytes\n")
	if l, err := br.ReadString('\n'); err != nil || l != "early bytes\n" {
		t.Fatalf("echo: %q %v", l, err)
	}
	// a half-close reaches the upstream, and its answer still comes back
	c.(*net.TCPConn).CloseWrite()
	if rest, err := io.ReadAll(br); err != nil || string(rest) != "" {
		t.Fatalf("after the half-close: %q %v", rest, err)
	}
	if g := got(); g != "early bytes\n" {
		t.Fatalf("upstream got %q", g)
	}
}

// revoke closes the task's end of a tunnel (gate.Server does it); the upstream connection closes with it.
func TestTunnelEndsWithTask(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	closed := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		io.Copy(io.Discard, c) // returns once the proxy closes its end
		close(closed)
	}()
	r := newRig(t, map[string]string{"common.list": "registry.example.com:443\n"})
	r.dial.set(func(resolve.Entry) (net.Conn, error) { return net.Dial("tcp", ln.Addr().String()) })
	c, s := pair(t)
	done := make(chan struct{})
	go func() { r.s.Serve(tid, "ga", s); close(done) }()
	io.WriteString(c, connect("registry.example.com:443"))
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	s.Close() // what revoke does to the task's connection
	for _, ch := range []chan struct{}{closed, done} {
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatal("the tunnel outlived the task's connection")
		}
	}
}

// Requests that are not CONNECT: plain HTTP is refused; an origin-form /_cache/ request is the cache's, or with no cache a
// bare miss, which go needs to fall back; an absolute-form one is plain HTTP.
func TestNotConnect(t *testing.T) {
	r := newRig(t, nil)
	for _, c := range []struct {
		head   string
		status int
		code   string
	}{
		{"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", 400, "EGRESS_WRONG_ROUTE"},
		{"POST /v1/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello", 400, "EGRESS_WRONG_ROUTE"},
		{"GET http://example.com/_cache/go/x/@v/v1.0.0.mod HTTP/1.1\r\nHost: example.com\r\n\r\n", 400, "EGRESS_WRONG_ROUTE"},
		{"GET /_cache/go/golang.org/x/mod/@v/v0.20.0.mod HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n", 404, ""},
		{"HEAD /_cache/go/golang.org/x/mod/@v/v0.20.0.zip HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n", 405, ""},
	} {
		resp, _, _ := r.do(t, "ga", c.head)
		if c.code == "" {
			b, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != c.status || resp.Header.Get(ops.DenialHeaderName) != "" || len(b) != 0 {
				t.Errorf("%q: %s %v %q, want a bare %d", c.head, resp.Status, resp.Header, b, c.status)
			}
			continue
		}
		if d := denied(t, resp, c.status, c.code); d.What != "plain_http" || d.Remedy[0].Expect != "use CONNECT" {
			t.Errorf("%q: %+v", c.head, d)
		}
	}
	if r.dial.n() != 0 || len(r.taints()) != 0 {
		t.Fatal("a request that is not a CONNECT reached rootd or tainted")
	}
	// with the cache: every origin-form /_cache/ request goes to it, with the task and agent; nothing else does
	fc := &fakeCache{}
	r.s.Cache = fc
	for _, head := range []string{"GET /_cache/go/golang.org/x/mod/@v/v0.20.0.mod HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
		"POST /_cache/go/x HTTP/1.1\r\nHost: proxy\r\nContent-Length: 2\r\n\r\nab"} {
		if resp, _, _ := r.do(t, "ga", head); resp.StatusCode != 299 {
			t.Errorf("%q: %s, want the cache's 299", head, resp.Status)
		}
	}
	resp, _, _ := r.do(t, "ga", "GET http://example.com/_cache/go/x/@v/v1.0.0.mod HTTP/1.1\r\nHost: example.com\r\n\r\n")
	denied(t, resp, 400, "EGRESS_WRONG_ROUTE")
	if got := fc.log(); strings.Join(got, ",") != tid+" ga GET /_cache/go/golang.org/x/mod/@v/v0.20.0.mod,"+tid+" ga POST /_cache/go/x" {
		t.Errorf("the cache got %q", got)
	}
}

// fakeCache answers 299 to every request it gets and logs "task agent method uri".
type fakeCache struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeCache) Serve(w io.Writer, task, agent string, req *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, task+" "+agent+" "+req.Method+" "+req.RequestURI)
	f.mu.Unlock()
	io.WriteString(w, "HTTP/1.1 299 Cached\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

func (f *fakeCache) log() []string { f.mu.Lock(); defer f.mu.Unlock(); return slices.Clone(f.calls) }

// Allowlists that don't load (a bad line) fail closed, before rootd; a head over 16 KiB, or one cut short, gets no
// answer.
func TestFailClosed(t *testing.T) {
	r := newRig(t, map[string]string{"common.list": "registry.example.com:443 extra\n"})
	resp, _, _ := r.do(t, "ga", connect("registry.example.com:443"))
	if d := denied(t, resp, 502, "EGRESS_RESOLVE_FAILED"); d.What != "unavailable" || r.dial.n() != 0 {
		t.Fatalf("%+v, %d dials", d, r.dial.n())
	}
	for _, head := range []string{"CONNECT registry.example.com:443 HTTP/1.1\r\nX: " + strings.Repeat("a", maxHead) + "\r\n\r\n",
		"CONNECT registry.example.com:443 HTTP/1.1\r\n"} {
		c, s := pair(t)
		done := make(chan struct{})
		go func() { r.s.Serve(tid, "ga", s); close(done) }()
		io.WriteString(c, head)
		c.(*net.TCPConn).CloseWrite()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Serve waited past the head limit")
		}
		c.SetReadDeadline(time.Now().Add(time.Second))
		if b, _ := io.ReadAll(c); len(b) != 0 {
			t.Fatalf("an answer to a bad head: %q", b)
		}
	}
}

// fakeRootd serves resolve-proxy.sock: each request line gets reply. reqs returns the requests so far.
func fakeRootd(t *testing.T, reply string) (sock string, reqs func() []map[string]any) {
	dir, err := os.MkdirTemp("/tmp", "px") // sun_path is short: t.TempDir is too long on macOS
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p := filepath.Join(dir, "r.sock")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var got []map[string]any
	var mu sync.Mutex
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			l, _ := bufio.NewReader(c).ReadBytes('\n')
			var m map[string]any
			json.Unmarshal(l, &m)
			mu.Lock()
			got = append(got, m)
			mu.Unlock()
			io.WriteString(c, reply+"\n")
			c.Close()
		}
	}()
	return p, func() []map[string]any { mu.Lock(); defer mu.Unlock(); return slices.Clone(got) }
}

// Pinned is internal/dial's pinned dialing for the task: one resolve request that names the task and the entry, then a
// connection to rootd's answer; a refusal keeps rootd's reason, and a dial that reaches no answer keeps its what.
func TestPinned(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := netip.MustParseAddrPort(ln.Addr().String()).Port()
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	cport := netip.MustParseAddrPort(closed.Addr().String()).Port()
	closed.Close()
	e := resolve.Entry{Host: "registry.example.com", Port: port}

	sock, reqs := fakeRootd(t, `{"ok":true,"addrs":["127.0.0.1"],"expires_at":1}`)
	c, err := Pinned(sock).Dial(context.Background(), tid, e)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if c.RemoteAddr().String() != ln.Addr().String() {
		t.Fatalf("dialed %s, not rootd's answer %s", c.RemoteAddr(), ln.Addr())
	}
	c.Close()
	want := map[string]any{"op": "resolve", "host": "registry.example.com", "port": float64(port), "task": tid}
	if r := reqs(); len(r) != 1 || fmt.Sprint(r[0]) != fmt.Sprint(want) {
		t.Fatalf("resolve requests %v", r)
	}
	sock, _ = fakeRootd(t, `{"ok":false,"reason":"non_public"}`)
	var rf *resolve.Refused
	if _, err := Pinned(sock).Dial(context.Background(), tid, e); !errors.As(err, &rf) || rf.Reason != resolve.NonPublic {
		t.Errorf("rootd refused: %v", err)
	}
	sock, _ = fakeRootd(t, `{"ok":true,"addrs":["127.0.0.1"]}`)
	_, err = Pinned(sock).Dial(context.Background(), tid, resolve.Entry{Host: "registry.example.com", Port: cport})
	if err == nil || errors.As(err, &rf) || dialWhat(err) != dial.Refused {
		t.Errorf("a closed port: %v (what %s)", err, dialWhat(err))
	}
}

// opErr is a failed connect as net.Dialer returns it.
func opErr(e error) error {
	if e == os.ErrDeadlineExceeded {
		return &net.OpError{Op: "dial", Net: "tcp", Err: e}
	}
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", e)}
}
