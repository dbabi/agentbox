package gate

import (
	"bufio"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

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
