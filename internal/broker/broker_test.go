package broker

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"agentbox/internal/canary"
	"agentbox/internal/ops"
)

// newServer is a broker on a temp dir whose task dirs are made as rootd makes them: this uid, this gid, 2750.
func newServer(t *testing.T, lim Limits, h func(t *Task) http.Handler) (*Server, string) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "b") // short: a socket path holds 104 bytes on macOS, and $TMPDIR is long there
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	gid := uint32(os.Getgid())
	s := &Server{Name: "keys", Dir: dir, By: "keys", Limits: lim, Handler: h,
		AgentIDs: func(string) (uint32, uint32, error) { return uint32(os.Getuid()), gid, nil },
		Format: func(h http.Header, d ops.Denial, status int) []byte {
			h.Set("Content-Type", "application/json")
			return []byte(fmt.Sprintf(`{"code":%q,"what":%q}`, d.Code, d.What))
		},
		Peer: func(net.Conn) (uint32, error) { return uint32(os.Getuid()), nil }}
	return s, dir
}

func addTask(t *testing.T, s *Server, dir, id string) string {
	t.Helper()
	d := filepath.Join(dir, "t", id)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(d, -1, os.Getgid()); err != nil { // macOS gives a new dir its parent's group
		t.Fatal(err)
	}
	if err := os.Chmod(d, os.ModeSetgid|0o750); err != nil {
		t.Fatal(err)
	}
	rep := s.Control([]byte(`{"call":"register","task":"` + id + `","agent":"ga","trace":"trace_01JAAAAAAAAAAAAAAAAAAAAAAA","chain":["human:root","agent:ga"]}`))
	if rep["ok"] != true {
		t.Fatalf("register: %v", rep)
	}
	t.Cleanup(func() { s.Control([]byte(`{"call":"revoke","task":"` + id + `"}`)) })
	return rep["socket"].(string)
}

func dial(t *testing.T, sock string) net.Conn {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// reply reads one response off c and returns its status and the CAP_REACHED what, if any.
// settle polls until the task's listener has at most n open connections, so a following dial sees the cap it tests
// rather than the race against the prior connection's release. The go scheduler on a slow CI runner delays it.
func settle(t *testing.T, s *Server, task string, n int) {
	t.Helper()
	for i := 0; i < 100; i++ {
		s.mu.Lock()
		tk, ok := s.tasks[task]
		s.mu.Unlock()
		if ok {
			tk.ln.mu.Lock()
			k := len(tk.ln.conns)
			tk.ln.mu.Unlock()
			if k <= n {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("task %s: still %d connections after 1 s", task, n)
}

func reply(t *testing.T, c net.Conn) (int, string) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("no reply: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	c.Close() // a refused connection counts against the cap until the client hangs up, as here
	if h := resp.Header.Get("Agentbox-Denial"); h != "" && !strings.Contains(h, "code=CAP_REACHED") {
		t.Fatalf("denial %s", h)
	}
	var what string
	if i := bytes.Index(b, []byte(`"what":"`)); i >= 0 {
		what = string(b[i+8 : i+8+bytes.IndexByte(b[i+8:], '"')])
	}
	return resp.StatusCode, what
}

// The admission caps (#115): a head over the byte cap, a head that doesn't finish in time, a body over the cap as sent
// or as decoded (a zip bomb, with memory bounded), a body that doesn't finish in time and one connection too many each
// get CAP_REACHED with its what before the handler sees anything; a request within them reaches the handler with
// its task, and revoke closes the socket and every connection.
func TestAdmission(t *testing.T) {
	const max = 1 << 20
	var gotMu sync.Mutex
	var got []string
	s, dir := newServer(t, Limits{HeadBytes: 4 << 10, HeadTimeout: 300 * time.Millisecond, ReadTimeout: time.Second, Conns: 2},
		func(tk *Task) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/hold" {
					time.Sleep(time.Second)
				}
				b, err := ReadBody(w, r, max)
				var c *Capped
				if errors.As(err, &c) {
					d, st := Cap("keys", c.What, c.Limit)
					h := w.Header()
					h.Set(ops.DenialHeaderName, ops.DenialHeader(d))
					w.WriteHeader(st)
					fmt.Fprintf(w, `{"code":%q,"what":%q}`, d.Code, d.What)
					return
				}
				gotMu.Lock()
				got = append(got, tk.ID+" "+tk.Trace+" "+fmt.Sprint(len(b), err))
				gotMu.Unlock()
				w.Write([]byte("ok"))
			})
		})
	sock := addTask(t, s, dir, "task_01JAAAAAAAAAAAAAAAAAAAAAAA")
	post := func(c net.Conn, path string, hdr string, body []byte) {
		fmt.Fprintf(c, "POST %s HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n%s\r\n", path, len(body), hdr)
		c.Write(body)
	}
	c := dial(t, sock)
	post(c, "/ok", "", []byte("hello"))
	if st, _ := reply(t, c); st != 200 || len(got) != 1 || got[0] != "task_01JAAAAAAAAAAAAAAAAAAAAAAA trace_01JAAAAAAAAAAAAAAAAAAAAAAA 5 <nil>" {
		t.Fatalf("a good request: %d %v", st, got)
	}
	c = dial(t, sock)
	post(c, "/x", "X-Pad: "+strings.Repeat("a", 8<<10)+"\r\n", nil)
	if st, w := reply(t, c); st != 431 || w != "header_bytes" {
		t.Errorf("head bytes: %d %s", st, w)
	}
	c = dial(t, sock)
	io.WriteString(c, "POST /x HTTP/1.1\r\nHost: x\r\n")
	if st, w := reply(t, c); st != 408 || w != "header_timeout" {
		t.Errorf("slow head: %d %s", st, w)
	}
	c = dial(t, sock)
	post(c, "/x", "", bytes.Repeat([]byte("a"), max+1))
	if st, w := reply(t, c); st != 413 || w != "body_bytes" {
		t.Errorf("body bytes: %d %s", st, w)
	}
	var bomb bytes.Buffer
	z := gzip.NewWriter(&bomb)
	for range 64 {
		z.Write(make([]byte, 1<<20)) // 64 MiB of zeros in about 64 KiB
	}
	z.Close()
	var ms0, ms1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms0)
	c = dial(t, sock)
	post(c, "/x", "Content-Encoding: gzip\r\n", bomb.Bytes())
	st, w := reply(t, c)
	runtime.ReadMemStats(&ms1)
	if st != 413 || w != "decoded_bytes" {
		t.Errorf("zip bomb: %d %s", st, w)
	}
	if grew := ms1.TotalAlloc - ms0.TotalAlloc; grew > 32<<20 {
		t.Errorf("the zip bomb cost %d MiB of allocation", grew>>20)
	}
	settle(t, s, "task_01JAAAAAAAAAAAAAAAAAAAAAAA", 0)
	c = dial(t, sock)
	io.WriteString(c, "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nshort")
	if st, w := reply(t, c); st != 408 || w != "read_timeout" {
		t.Errorf("slow body: %d %s", st, w)
	}
	settle(t, s, "task_01JAAAAAAAAAAAAAAAAAAAAAAA", 0)
	// two connections held by a slow handler, then a third
	h1, h2 := dial(t, sock), dial(t, sock)
	post(h1, "/hold", "", nil)
	post(h2, "/hold", "", nil)
	time.Sleep(200 * time.Millisecond)
	c = dial(t, sock)
	post(c, "/x", "", nil)
	if st, w := reply(t, c); st != 429 || w != "connections" {
		t.Errorf("connections: %d %s", st, w)
	}
	reply(t, h1)
	reply(t, h2)
	time.Sleep(100 * time.Millisecond)
	c = dial(t, sock)
	post(c, "/ok", "", nil)
	if st, _ := reply(t, c); st != 200 {
		t.Errorf("once the held connections ended: %d", st)
	}
	// revoke: the socket goes and a connection held open is closed
	h1 = dial(t, sock)
	if rep := s.Control([]byte(`{"call":"revoke","task":"task_01JAAAAAAAAAAAAAAAAAAAAAAA"}`)); rep["ok"] != true {
		t.Fatal(rep)
	}
	if _, err := os.Lstat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the socket outlived revoke: %v", err)
	}
	h1.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := h1.Read(make([]byte, 1)); err == nil {
		t.Error("a connection outlived revoke")
	}
}

// A body that stops arriving is cut after BodyGrace with CAP_REACHED{read_timeout}, long before the server's 60 s
// ReadTimeout (#315); one that keeps coming at the pace passes.
func TestBodyPace(t *testing.T) {
	s, dir := newServer(t, Limits{}, func(*Task) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, err := ReadBody(w, r, 4<<20)
			if c := (*Capped)(nil); errors.As(err, &c) {
				d, st := Cap("keys", c.What, c.Limit)
				w.Header().Set(ops.DenialHeaderName, ops.DenialHeader(d))
				w.WriteHeader(st)
				fmt.Fprintf(w, `{"code":%q,"what":%q}`, d.Code, d.What)
				return
			}
			fmt.Fprintf(w, "read %d", len(b))
		})
	})
	sock := addTask(t, s, dir, "task_01JAAAAAAAAAAAAAAAAAAAAAAA")
	c := dial(t, sock)
	t0 := time.Now()
	io.WriteString(c, "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nshort")
	if st, w := reply(t, c); st != 408 || w != "read_timeout" || time.Since(t0) < BodyGrace || time.Since(t0) > BodyGrace+3*time.Second {
		t.Errorf("a stalled body: %d %s after %v", st, w, time.Since(t0))
	}
	// 3 s of 64 KiB every 100 ms (640 KiB/s): above the pace throughout, past the grace
	c = dial(t, sock)
	const n = 30 * 64 << 10
	fmt.Fprintf(c, "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n", n)
	go func() {
		for range 30 {
			c.Write(make([]byte, 64<<10))
			time.Sleep(100 * time.Millisecond)
		}
	}()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(b) != fmt.Sprintf("read %d", n) {
		t.Errorf("a body at the pace: %d %s", resp.StatusCode, b)
	}
}

// A peer that is not the task's agent uid is closed before any byte; register refuses a dir rootd didn't make and a
// task with no trace to bill.
func TestPeerAndRegister(t *testing.T) {
	s, dir := newServer(t, Limits{}, func(*Task) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	})
	s.Peer = func(net.Conn) (uint32, error) { return 12345, nil }
	sock := addTask(t, s, dir, "task_01JBBBBBBBBBBBBBBBBBBBBBBB")
	c := dial(t, sock)
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.Read(make([]byte, 64)); err == nil {
		t.Errorf("another uid got %d bytes", n)
	}
	os.MkdirAll(filepath.Join(dir, "t", "task_01JCCCCCCCCCCCCCCCCCCCCCCC"), 0o755)
	for _, line := range []string{
		`{"call":"register","task":"task_01JCCCCCCCCCCCCCCCCCCCCCCC","agent":"ga","trace":"trace_01JAAAAAAAAAAAAAAAAAAAAAAA"}`, // mode 0755, no setgid
		`{"call":"register","task":"task_01JBBBBBBBBBBBBBBBBBBBBBBB","agent":"ga","trace":""}`,
		`{"call":"register","task":"../x","agent":"ga","trace":"trace_01JAAAAAAAAAAAAAAAAAAAAAAA"}`,
		`{"call":"register","task":"t","agent":"ga","trace":"trace_01JAAAAAAAAAAAAAAAAAAAAAAA","extra":1}`,
		`{"call":"register","task":"task_01JDDDDDDDDDDDDDDDDDDDDDDD","agent":"ga","trace":"trace_01JAAAAAAAAAAAAAAAAAAAAAAA","canary":"sk-ant-api03-short"}`,
	} {
		if rep := s.Control([]byte(line)); rep["ok"] != false {
			t.Errorf("%s: %v", line, rep)
		}
	}
	if rep := s.Control([]byte(`{"call":"list"}`)); fmt.Sprint(rep["tasks"]) != "[task_01JBBBBBBBBBBBBBBBBBBBBBBB]" {
		t.Errorf("list: %v", rep)
	}
}

// The task's canary (#105) comes with rootd's register and with task.list_live after a restart, and the handler's task
// carries it.
func TestRegisterCanary(t *testing.T) {
	s, dir := newServer(t, Limits{}, func(*Task) http.Handler { return http.NotFoundHandler() })
	c := canary.Mint()
	for _, id := range []string{"task_01JEEEEEEEEEEEEEEEEEEEEEEE", "task_01JFFFFFFFFFFFFFFFFFFFFFFF"} {
		d := filepath.Join(dir, "t", id)
		os.MkdirAll(d, 0o755)
		os.Chown(d, -1, os.Getgid())
		os.Chmod(d, os.ModeSetgid|0o750)
	}
	if rep := s.Control([]byte(`{"call":"register","task":"task_01JEEEEEEEEEEEEEEEEEEEEEEE","agent":"ga","trace":"trace_01JAAAAAAAAAAAAAAAAAAAAAAA","canary":"` + c + `"}`)); rep["ok"] != true {
		t.Fatalf("register: %v", rep)
	}
	l, _ := json.Marshal(map[string]any{"ok": true, "tasks": []map[string]any{{"task": "task_01JFFFFFFFFFFFFFFFFFFFFFFF", "agent": "ga",
		"trace": "trace_01JAAAAAAAAAAAAAAAAAAAAAAA", "canary": c}}})
	if err := s.Rebind(l); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"task_01JEEEEEEEEEEEEEEEEEEEEEEE", "task_01JFFFFFFFFFFFFFFFFFFFFFFF"} {
		if tk, ok := s.Lookup(id); !ok || tk.Canary != c {
			t.Errorf("%s: %+v %v", id, tk, ok)
		}
		s.Control([]byte(`{"call":"revoke","task":"` + id + `"}`))
	}
}

// FuzzReadBody: whatever the body and its encoding claim, ReadBody returns at most max bytes, or a cap or an error.
func FuzzReadBody(f *testing.F) {
	var z bytes.Buffer
	w := gzip.NewWriter(&z)
	w.Write(bytes.Repeat([]byte("x"), 5000))
	w.Close()
	f.Add(z.Bytes(), "gzip")
	f.Add([]byte("plain"), "")
	f.Add([]byte("x"), "br")
	f.Fuzz(func(t *testing.T, body []byte, enc string) {
		r, _ := http.NewRequest("POST", "/", bytes.NewReader(body))
		if enc != "" {
			r.Header.Set("Content-Encoding", enc)
		}
		b, err := ReadBody(nopWriter{}, r, 4096)
		if err == nil && len(b) > 4096 {
			t.Fatalf("%d bytes past the cap", len(b))
		}
	})
}

type nopWriter struct{}

func (nopWriter) Header() http.Header         { return http.Header{} }
func (nopWriter) Write(b []byte) (int, error) { return len(b), nil }
func (nopWriter) WriteHeader(int)             {}
