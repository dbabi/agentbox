package gate

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"log"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var serr error
	err = raw.Control(func(fd uintptr) {
		var uc *unix.Ucred
		if uc, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); serr == nil {
			uid = uc.Uid
		}
	})
	if err == nil {
		err = serr
	}
	return uid, err
}

// lines calls f for each "\n"-terminated line on c and writes its reply. Ancillary data (SCM_RIGHTS included) or a
// line over MaxRequest closes the connection: the gate takes no descriptors (§2.1).
func lines(c *net.UnixConn, idle time.Duration, f func([]byte) []byte) {
	var buf []byte
	b := make([]byte, 4096)
	oob := make([]byte, unix.CmsgSpace(64*4))
	for {
		c.SetReadDeadline(time.Now().Add(idle))
		n, oobn, flags, _, err := c.ReadMsgUnix(b, oob)
		n = max(n, 0) // with an error (a deadline, a revoke's close), ReadMsgUnix can return n = -1
		if oobn > 0 || flags&unix.MSG_CTRUNC != 0 {
			if msgs, perr := unix.ParseSocketControlMessage(oob[:oobn]); perr == nil {
				for _, m := range msgs {
					if fds, err := unix.ParseUnixRights(&m); err == nil {
						for _, fd := range fds {
							unix.Close(fd)
						}
					}
				}
			}
			log.Printf("gate: peer sent ancillary data: connection closed")
			return
		}
		buf = append(buf, b[:n]...)
		for {
			i := bytes.IndexByte(buf, '\n')
			if i < 0 {
				break
			}
			if i > MaxRequest {
				return
			}
			if _, err := c.Write(append(f(buf[:i]), '\n')); err != nil {
				return
			}
			buf = buf[i+1:]
		}
		if len(buf) > MaxRequest || err != nil {
			return
		}
	}
}

// fdFree is a task connection for a Conn handler: a read that brings ancillary data (SCM_RIGHTS included) closes the
// descriptors and the connection, as lines does (§2.1).
type fdFree struct {
	*net.UnixConn
	oob []byte
}

var errAncillary = errors.New("peer sent ancillary data: connection closed")

func (f *fdFree) Read(p []byte) (int, error) {
	if f.oob == nil {
		f.oob = make([]byte, unix.CmsgSpace(64*4))
	}
	n, oobn, flags, _, err := f.ReadMsgUnix(p, f.oob)
	if oobn > 0 || flags&unix.MSG_CTRUNC != 0 {
		if msgs, perr := unix.ParseSocketControlMessage(f.oob[:oobn]); perr == nil {
			for _, m := range msgs {
				if fds, err := unix.ParseUnixRights(&m); err == nil {
					for _, fd := range fds {
						unix.Close(fd)
					}
				}
			}
		}
		f.Close()
		return 0, errAncillary
	}
	return max(n, 0), err
}

// MaxConns is how many connections one task's socket serves at once; more wait in the listen backlog. So a task can't
// fill agentboxd's fd table, which would fail every other task's accept and its dials to rootd.sock.
const MaxConns = 8

// acceptRetry is l.Accept, but it waits out a failure for want of a descriptor or kernel memory (EMFILE, ENFILE,
// ENOBUFS, ENOMEM), backing off from 5 ms to 1 s as net/http does, so a full fd table never ends a listener for good.
func acceptRetry(l net.Listener, name string) (net.Conn, error) {
	for wait := 5 * time.Millisecond; ; wait = min(2*wait, time.Second) {
		c, err := l.Accept()
		if err == nil || !(errors.Is(err, unix.EMFILE) || errors.Is(err, unix.ENFILE) || errors.Is(err, unix.ENOBUFS) || errors.Is(err, unix.ENOMEM)) {
			return c, err
		}
		log.Printf("%s: accept: %v; retrying in %v", name, err, wait)
		time.Sleep(wait)
	}
}

func (s *Server) accept(t *task) {
	slots := make(chan struct{}, cmp.Or(s.Conns, MaxConns))
	for {
		slots <- struct{}{} // revoke closes every connection, so a full set always drains
		c, err := acceptRetry(t.ln, "task "+t.id)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("task %s: accept: %v", t.id, err)
			}
			return
		}
		go func() {
			defer func() { <-slots }()
			s.serve(t, c.(*net.UnixConn))
		}()
	}
}

// serve is one task connection: only that task's agent uid (§2.1), tagged with the task so revoke closes it.
func (s *Server) serve(t *task, c *net.UnixConn) {
	defer c.Close()
	uid, err := peerUID(c)
	if err != nil || uid != t.uid {
		log.Printf("task %s: refused peer uid %d (want %d): %v", t.id, uid, t.uid, err)
		return
	}
	t.mu.Lock()
	if t.ended {
		t.mu.Unlock()
		return
	}
	t.conns[c] = true
	t.mu.Unlock()
	defer func() { t.mu.Lock(); delete(t.conns, c); t.mu.Unlock() }()
	if s.Conn != nil {
		s.Conn(t.id, t.agent, &fdFree{UnixConn: c})
		return
	}
	if s.Handle != nil {
		lines(c, 10*time.Minute, func(l []byte) []byte { return s.Handle(t.id, l) })
		return
	}
	lines(c, 10*time.Minute, func(l []byte) []byte { return s.call(t, l) })
}

// ServeControl serves svc-gate.sock: rootd's register and revoke, uid 0 only (§2.1).
func (s *Server) ServeControl(l net.Listener) error {
	for {
		c, err := acceptRetry(l, "svc-gate.sock")
		if err != nil {
			return err
		}
		go func(c *net.UnixConn) {
			defer c.Close()
			if uid, err := peerUID(c); err != nil || uid != 0 {
				log.Printf("svc-gate.sock: refused peer uid %d: %v", uid, err)
				return
			}
			lines(c, time.Minute, func(l []byte) []byte { b, _ := json.Marshal(s.Control(l)); return b })
		}(c.(*net.UnixConn))
	}
}
