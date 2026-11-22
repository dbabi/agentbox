package gate

import (
	"bytes"
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

func (s *Server) accept(t *task) {
	for {
		c, err := t.ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("task %s: accept: %v", t.id, err)
			}
			return
		}
		go s.serve(t, c.(*net.UnixConn))
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
	if s.Handle != nil {
		lines(c, 10*time.Minute, func(l []byte) []byte { return s.Handle(t.id, l) })
		return
	}
	lines(c, 10*time.Minute, func(l []byte) []byte { return s.call(t, l) })
}

// ServeControl serves svc-gate.sock: rootd's register and revoke, uid 0 only (§2.1).
func (s *Server) ServeControl(l net.Listener) error {
	for {
		c, err := l.Accept()
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
