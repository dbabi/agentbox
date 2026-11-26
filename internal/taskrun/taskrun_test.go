package taskrun

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"agentbox/internal/ops"
)

// short dirs: a Unix socket path must fit in 104 bytes on macOS
func shortDir(t *testing.T) string {
	d, err := os.MkdirTemp("/tmp", "tr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// broker serves h on sock until the returned stop is called; stop unlinks the socket, like a broker going away.
func broker(t *testing.T, sock string, h http.Handler) (stop func()) {
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	s := &http.Server{Handler: h}
	go s.Serve(ln)
	return func() { s.Close(); os.Remove(sock) }
}

func setup(t *testing.T, name string, retry time.Duration) (*Forwarder, string, *Recorder) {
	dir := shortDir(t)
	rec := &Recorder{Log: filepath.Join(dir, "home", ".agentbox", "denials.jsonl"), Witness: filepath.Join(dir, "w")}
	syscall.Mkfifo(rec.Witness, 0o600)
	for _, ch := range Channels {
		if ch.Name == name {
			ch.Socket = filepath.Join(dir, name+".sock")
			return &Forwarder{Ch: ch, Rec: rec, Retry: retry}, ch.Socket, rec
		}
	}
	t.Fatal("no channel", name)
	return nil, "", nil
}

func TestReverseProxyRetryAndUnavailable(t *testing.T) {
	f, sock, rec := setup(t, "llm", 2*time.Second)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "pong "+r.URL.Path) })
	stop := broker(t, sock, ok)
	srv := httptest.NewServer(f.Handler())
	defer srv.Close()
	get := func() (*http.Response, string) {
		resp, err := http.Post(srv.URL+"/v1/messages", "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(b)
	}
	if r, b := get(); r.StatusCode != 200 || b != "pong /v1/messages" {
		t.Fatalf("%d %q", r.StatusCode, b)
	}
	// the broker restarts: down for 500 ms, inside the retry window, so the request still succeeds
	stop()
	restarted := make(chan func(), 1)
	go func() { time.Sleep(500 * time.Millisecond); restarted <- broker(t, sock, ok) }()
	if r, b := get(); r.StatusCode != 200 || b != "pong /v1/messages" {
		t.Fatalf("after restart: %d %q", r.StatusCode, b)
	}
	(<-restarted)()
	t0 := time.Now()
	r, b := get()
	if el := time.Since(t0); r.StatusCode != 503 || el < 2*time.Second || el > 4*time.Second {
		t.Fatalf("broker gone: %d after %v", r.StatusCode, el)
	}
	var env struct {
		Error    struct{ Type, Message string }
		Agentbox ops.Denial
	}
	if json.Unmarshal([]byte(b), &env) != nil || !strings.HasPrefix(env.Error.Message, "agentbox BROKER_UNAVAILABLE:") ||
		env.Agentbox.What != "llm" || r.Header.Get("x-should-retry") != "true" || !strings.HasPrefix(r.Header.Get(ops.DenialHeaderName), "v1 code=BROKER_UNAVAILABLE next=retry id=dn_") {
		t.Fatalf("503: %v %s", r.Header, b)
	}
	if ds := Recent(rec.Log, 10); len(ds) != 1 || ds[0].Code != "BROKER_UNAVAILABLE" || ds[0].ID != env.Agentbox.ID {
		t.Fatalf("log: %+v", ds)
	}
}

// #168: a broker can answer before it reads the body, as keys does for an endpoint it refuses. The client gets that
// answer, not 503 BROKER_UNAVAILABLE: the forwarder doesn't send Connection: close, which made a Go broker hang up at
// once and fail the forwarder's body write. Each request still gets its own connection. The body is bigger than a
// socket buffer, and no bigger than the 256 KiB a Go server reads past an unread body.
func TestReverseProxyEarlyAnswer(t *testing.T) {
	f, sock, rec := setup(t, "llm", 2*time.Second)
	deny := ops.Deny(ops.KeysRequestRejected, "endpoint", ops.Slots{By: "keys"})
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var conns atomic.Int32
	s := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Close {
				t.Error("the forwarder sent Connection: close")
			}
			w.Header().Set(ops.DenialHeaderName, ops.DenialHeader(deny))
			w.WriteHeader(http.StatusForbidden)
			w.Write(ops.KeysBody(deny))
		}),
		ConnState: func(_ net.Conn, st http.ConnState) {
			if st == http.StateNew {
				conns.Add(1)
			}
		},
	}
	go s.Serve(ln)
	defer s.Close()
	srv := httptest.NewServer(f.Handler())
	defer srv.Close()
	body := bytes.Repeat([]byte("x"), 240<<10)
	for range 2 {
		resp, err := http.Post(srv.URL+"/v1/files", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || !bytes.Equal(b, ops.KeysBody(deny)) {
			t.Fatalf("%d %q", resp.StatusCode, b)
		}
	}
	if ds := Recent(rec.Log, 10); len(ds) != 2 || ds[0].Code != "KEYS_REQUEST_REJECTED" || ds[0].ID != deny.ID {
		t.Fatalf("log: %+v", ds)
	}
	if n := conns.Load(); n != 2 {
		t.Fatalf("%d broker connections for 2 requests", n)
	}
}

func TestConnect(t *testing.T) {
	f, sock, rec := setup(t, "egress", 300*time.Millisecond)
	// a fake proxy: example.com is refused with a denial; ok.example is tunneled to an echo
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	deny := ops.Deny(ops.EgressNotAllowlisted, "", ops.Slots{By: "proxy", Subject: ops.Subject{Host: "example.com", Port: 443}})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				if req.Host != "ok.example:80" {
					body := ops.ConnectBody(deny)
					fmt.Fprintf(c, "HTTP/1.1 403 %s\r\n%s: %s\r\nContent-Length: %d\r\n\r\n%s", ops.ConnectReason(deny), ops.DenialHeaderName, ops.DenialHeader(deny), len(body), body)
					return
				}
				io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				io.Copy(c, br) // echo
			}(c)
		}
	}()
	srv := httptest.NewServer(f.Handler())
	defer srv.Close()
	connect := func(target string) (net.Conn, *bufio.Reader, string) {
		c, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		br := bufio.NewReader(c)
		line, _ := br.ReadString('\n')
		return c, br, line
	}
	c, _, line := connect("example.com:443")
	c.Close()
	if line != "HTTP/1.1 403 agentbox EGRESS_NOT_ALLOWLISTED (run: agentbox why)\r\n" {
		t.Fatalf("status line %q", line)
	}
	ds := Recent(rec.Log, 10)
	if len(ds) != 1 || ds[0].ID != deny.ID || ds[0].Subject == nil || ds[0].Subject.Host != "example.com" || ds[0].Remedy[0].Op != "net.allow_domain" {
		t.Fatalf("log: %+v", ds)
	}
	var out bytes.Buffer
	t.Setenv("HOME", filepath.Dir(filepath.Dir(rec.Log)))
	Why(&out, nil)
	if !strings.Contains(out.String(), "EGRESS_NOT_ALLOWLISTED next=ask by=proxy id="+deny.ID+" host=example.com:443") ||
		!strings.Contains(out.String(), "net.allow_domain{host: example.com, port: 443} (cli)") {
		t.Fatalf("why:\n%s", out.String())
	}
	// a tunnel: bytes after the head pass both ways
	c, br, line := connect("ok.example:80")
	if !strings.HasPrefix(line, "HTTP/1.1 200") {
		t.Fatalf("tunnel: %q", line)
	}
	br.ReadString('\n') // the blank line
	io.WriteString(c, "ping\n")
	if got, _ := br.ReadString('\n'); got != "ping\n" {
		t.Fatalf("echo %q", got)
	}
	c.Close()
	// no broker: the forwarder's own 503 in the CONNECT format, after the retry window
	ln.Close()
	os.Remove(sock)
	c, _, line = connect("example.com:443")
	c.Close()
	if line != "HTTP/1.1 503 agentbox BROKER_UNAVAILABLE (run: agentbox why)\r\n" {
		t.Fatalf("no broker: %q", line)
	}
}

func TestLogRingAndWitness(t *testing.T) {
	_, _, rec := setup(t, "git", 0)
	fd, err := syscall.Open(rec.Witness, syscall.O_RDWR|syscall.O_NONBLOCK, 0) // rootd's read end
	if err != nil {
		t.Fatal(err)
	}
	rd := os.NewFile(uintptr(fd), "w")
	defer rd.Close()
	var last ops.Denial
	for i := 0; i < LogMax+6; i++ {
		last = ops.Deny(ops.BrokerUnavailable, "git", ops.Slots{By: "forwarder"})
		rec.Record(last)
	}
	rec.End(strings.Repeat("0", 64))
	b, _ := os.ReadFile(rec.Log)
	if n := bytes.Count(b, []byte("\n")); n != LogMax {
		t.Fatalf("log has %d lines", n)
	}
	if ds := Recent(rec.Log, 10); len(ds) != 10 || ds[0].ID != last.ID {
		t.Fatalf("Recent: %d", len(ds))
	}
	rd.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64<<10)
	n, _ := rd.Read(buf)
	lines := strings.Split(strings.TrimSuffix(string(buf[:n]), "\n"), "\n")
	if len(lines) != LogMax+7 || lines[len(lines)-1] != "END "+strings.Repeat("0", 64) {
		t.Fatalf("witness: %d lines, last %q", len(lines), lines[len(lines)-1])
	}
	for _, l := range lines {
		if _, err := ops.ParseWitness(l); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
	}
}

func TestWhy(t *testing.T) {
	t.Setenv("HOME", shortDir(t))
	for args, want := range map[string]string{"--errno EOPNOTSUPP": "seccomp profile refuses btrfs ioctls", "": "No denials logged",
		"EGRESS_NOT_ALLOWLISTED": "what deputy_host: next human", "--errno eai_again": "no DNS"} {
		var out bytes.Buffer
		if err := Why(&out, strings.Fields(args)); err != nil || !strings.Contains(out.String(), want) {
			t.Errorf("why %s: %v %q", args, err, out.String())
		}
	}
	for _, bad := range []string{"NOPE", "--errno EFOO", "a b c"} {
		if Why(io.Discard, strings.Fields(bad)) == nil {
			t.Errorf("why %s passes", bad)
		}
	}
}
