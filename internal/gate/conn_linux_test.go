package gate

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"agentbox/internal/ops"
	"golang.org/x/sys/unix"
)

// addTask registers task id on s in a dir made the §2.1 way, as newServer does for T1.
func addTask(t *testing.T, s *Server, id string) *task {
	t.Helper()
	td := filepath.Join(s.Dir, "t", id)
	if err := os.MkdirAll(td, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(td, os.ModeSetgid|0o750); err != nil {
		t.Fatal(err)
	}
	if rep := s.Control([]byte(`{"call":"register","task":"` + id + `","agent":"claude"}`)); rep["ok"] != true {
		t.Fatalf("register %s: %v", id, rep)
	}
	t.Cleanup(func() { s.revoke(id) })
	return s.tasks[id]
}

// served sends one line on c and reports whether a reply line came back within d.
func served(t *testing.T, c net.Conn, d time.Duration) bool {
	t.Helper()
	if _, err := c.Write([]byte("not json\n")); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(d))
	_, err := bufio.NewReader(c).ReadBytes('\n')
	return err == nil
}

func dial(t *testing.T, path string) net.Conn {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// #221: a task that holds MaxConns connections open gets no more served until one closes, and another task's socket
// still answers, so one task can't fill agentboxd's fd table.
func TestConnCap(t *testing.T) {
	s, t1 := newServer(t, nil)
	t2 := addTask(t, s, "T2")
	var held []net.Conn
	for range MaxConns {
		c := dial(t, t1.path)
		if !served(t, c, 5*time.Second) {
			t.Fatalf("connection %d of %d not served", len(held)+1, MaxConns)
		}
		held = append(held, c)
	}
	extra := dial(t, t1.path) // queued in the listen backlog
	if served(t, extra, 300*time.Millisecond) {
		t.Fatalf("a connection over the cap of %d was served", MaxConns)
	}
	if !served(t, dial(t, t2.path), 5*time.Second) {
		t.Fatal("another task's socket stopped answering")
	}
	held[0].Close()
	extra.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := bufio.NewReader(extra).ReadBytes('\n'); err != nil {
		t.Fatalf("the queued connection was not served once a slot freed: %v", err)
	}
}

// failing fails its first n Accepts with err.
type failing struct {
	net.Listener
	n   int
	err unix.Errno
}

func (f *failing) Accept() (net.Conn, error) {
	if f.n > 0 {
		f.n--
		return nil, &net.OpError{Op: "accept", Net: "unix", Err: os.NewSyscallError("accept4", f.err)}
	}
	return f.Listener.Accept()
}

func listen(t *testing.T) (net.Listener, string) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "gate") // sun_path is short: t.TempDir is too long
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, p
}

// #221: EMFILE, ENFILE, ENOBUFS and ENOMEM don't end a task socket's accept loop or ServeControl; any other error
// ends them, as before.
func TestAcceptRetry(t *testing.T) {
	for _, e := range []unix.Errno{unix.EMFILE, unix.ENFILE, unix.ENOBUFS, unix.ENOMEM} {
		l, p := listen(t)
		s := &Server{}
		tk := &task{id: "T9", uid: uint32(os.Getuid()), ln: &failing{l, 3, e}, conns: map[net.Conn]bool{}}
		go s.accept(tk)
		if !served(t, dial(t, p), 5*time.Second) {
			t.Fatalf("%v: the task's accept loop ended", e)
		}
	}
	l, _ := listen(t)
	if _, err := acceptRetry(&failing{l, 1, unix.EINVAL}, "test"); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("EINVAL: %v", err)
	}

	l, p := listen(t)
	s := &Server{}
	errc := make(chan error, 1)
	go func() { errc <- s.ServeControl(&failing{l, 3, unix.EMFILE}) }()
	c := dial(t, p)
	c.Write([]byte(`{"call":"list"}` + "\n"))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	// uid 0 gets the list, anyone else the close after SO_PEERCRED; either way the connection was accepted
	if _, err := bufio.NewReader(c).ReadBytes('\n'); errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("ServeControl stopped accepting after EMFILE")
	}
	l.Close()
	if err := <-errc; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ServeControl returned %v, want the listener closed", err)
	}
}

// #221: a read that fails, at the idle deadline or because revoke closed the connection, ends that connection only.
// ReadMsgUnix returns n = -1 with such an error, which lines once sliced with, so agentboxd panicked.
func TestReadErrorEndsConnection(t *testing.T) {
	l, p := listen(t)
	dial(t, p) // open and silent until the test ends, past the server's deadline
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan bool)
	go func() { lines(c.(*net.UnixConn), 50*time.Millisecond, func([]byte) []byte { return nil }); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("lines did not end at its idle deadline")
	}

	s, tk := newServer(t, nil)
	held := dial(t, tk.path)
	if !served(t, held, 5*time.Second) {
		t.Fatal("not served")
	}
	time.Sleep(100 * time.Millisecond) // the server is back in its read
	s.revoke("T1")
	held.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := held.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection outlived revoke")
	}
}

// A Conn handler (the proxy) gets each task connection past the peer check, with its task and agent: bytes flow both
// ways, Conns caps how many it serves at once, ancillary data closes the connection, and so does revoke.
func TestConnHandler(t *testing.T) {
	who := make(chan string, 8)
	s, _ := newServer(t, nil, func(s *Server) {
		s.Conn = func(task, agent string, c net.Conn) {
			who <- task + " " + agent
			io.Copy(c, c) // echo until the connection ends
		}
		s.Conns = 2
	})
	tk := addTask(t, s, "T2")
	echo := func(c net.Conn, d time.Duration) bool {
		c.Write([]byte("ping"))
		c.SetReadDeadline(time.Now().Add(d))
		b := make([]byte, 4)
		_, err := io.ReadFull(c, b)
		return err == nil && string(b) == "ping"
	}
	c1, c2 := dial(t, tk.path), dial(t, tk.path)
	if !echo(c1, 5*time.Second) || !echo(c2, 5*time.Second) || <-who != "T2 claude" {
		t.Fatal("the handler did not serve the task's connections")
	}
	c3 := dial(t, tk.path) // over Conns: waits in the backlog
	if echo(c3, 300*time.Millisecond) {
		t.Fatal("a connection over Conns was served")
	}
	c1.Close()
	c3.SetReadDeadline(time.Now().Add(5 * time.Second))
	if b := make([]byte, 4); func() bool { _, err := io.ReadFull(c3, b); return err != nil || string(b) != "ping" }() {
		t.Fatal("the queued connection was not served once a slot freed")
	}
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, _, err := c2.(*net.UnixConn).WriteMsgUnix([]byte("x"), unix.UnixRights(int(f.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c2.Read(make([]byte, 8)); err == nil {
		t.Fatalf("a connection that passed a descriptor stayed open (read %d bytes)", n)
	}
	s.revoke("T2")
	c3.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c3.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection outlived revoke")
	}
}

// #115: a line over MaxRequest, and a line that stops partway past the idle deadline, each get a typed CAP_REACHED
// before the connection closes; an idle connection with nothing sent just closes.
func TestLineCaps(t *testing.T) {
	for _, c := range []struct {
		name, what string
		send       []byte
	}{{"a line over MaxRequest", "body_bytes", bytes.Repeat([]byte("x"), MaxRequest+2)}, {"a stalled line", "read_timeout", []byte(`{"jsonrpc":"2.0"`)}} {
		l, p := listen(t)
		cl := dial(t, p)
		sc, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		go lines(sc.(*net.UnixConn), 200*time.Millisecond, func([]byte) []byte { return []byte("{}") })
		go cl.Write(c.send)
		cl.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := bufio.NewReader(cl).ReadBytes('\n')
		var rep struct {
			Error struct {
				Code    int
				Message string
				Data    ops.Denial
			}
		}
		if err != nil || json.Unmarshal(line, &rep) != nil || rep.Error.Code != ops.RPCDenial || rep.Error.Data.Code != "CAP_REACHED" || rep.Error.Data.What != c.what {
			t.Errorf("%s: %q %v", c.name, line, err)
		}
	}
}
