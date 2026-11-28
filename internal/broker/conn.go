package broker

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// listener is one task's socket: it accepts only the task's agent uid, and over the connection cap it answers
// CAP_REACHED{connections} itself instead of handing the connection to net/http.
type listener struct {
	net.Listener
	s     *Server
	t     *task
	lim   Limits
	mu    sync.Mutex
	conns map[*conn]bool
}

func (s *Server) newListener(l net.Listener, t *task) *listener {
	return &listener{Listener: l, s: s, t: t, lim: s.Limits.withDefaults(), conns: map[*conn]bool{}}
}

func (s *Server) peer(c net.Conn) (uint32, error) {
	if s.Peer != nil {
		return s.Peer(c)
	}
	return peerUID(c)
}

// refusing bounds the goroutines that answer refused connections; past it a refused connection is just closed.
var refusing = make(chan struct{}, 64)

func (l *listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept() // net/http backs off on EMFILE and the like
		if err != nil {
			return nil, err
		}
		uc, ok := c.(*net.UnixConn)
		uid, perr := l.s.peer(c)
		if !ok || perr != nil || uid != l.t.UID {
			log.Printf("task %s: refused peer uid %d (want %d): %v", l.t.ID, uid, l.t.UID, perr)
			c.Close()
			continue
		}
		l.mu.Lock()
		if len(l.conns) >= l.lim.Conns {
			l.mu.Unlock()
			d, st := Cap(l.s.By, "connections", int64(l.lim.Conns))
			log.Printf("DENY by=%s task=%s code=%s what=connections id=%s", l.s.By, l.t.ID, d.Code, d.ID)
			select {
			case refusing <- struct{}{}:
				go func() { defer func() { <-refusing }(); answer(uc, l.s.raw(d, st)); uc.Close() }()
			default:
				uc.Close()
			}
			continue
		}
		cc := &conn{UnixConn: uc, l: l, head: true}
		l.conns[cc] = true
		l.mu.Unlock()
		return cc, nil
	}
}

func (l *listener) release(c *conn) {
	l.mu.Lock()
	delete(l.conns, c)
	l.mu.Unlock()
}

func (l *listener) closeAll() {
	l.mu.Lock()
	cs := make([]*conn, 0, len(l.conns))
	for c := range l.conns {
		cs = append(cs, c)
	}
	l.mu.Unlock()
	for _, c := range cs {
		c.Close()
	}
}

// answer writes a whole response to a connection whose request is still unread, then lets the client finish sending
// for a moment before the close, so its write doesn't fail before it reads the answer. Bounded: 5 s to write, then at
// most 1 s or 1 MiB of discarded input.
func answer(c *net.UnixConn, resp []byte) {
	c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(resp); err != nil {
		return
	}
	c.CloseWrite()
	c.SetReadDeadline(time.Now().Add(time.Second))
	io.Copy(io.Discard, io.LimitReader(c, 1<<20))
}

// conn is one accepted connection: no descriptor passing (§2.1), and the head of its one request read here first, so
// a head over the byte cap or the time cap gets a typed denial (net/http would send its own text, or nothing).
type conn struct {
	*net.UnixConn
	l    *listener
	head bool   // the request head is not read yet
	buf  []byte // read here, not yet handed to net/http
	once sync.Once
}

func (c *conn) Close() error {
	var err error
	c.once.Do(func() {
		c.l.release(c)
		err = c.UnixConn.Close()
	})
	return err
}

func (c *conn) Read(p []byte) (int, error) {
	if c.head {
		c.head = false
		if err := c.readHead(); err != nil {
			return 0, err
		}
	}
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.read(p)
}

// read is one read that refuses ancillary data: any descriptor that came with it is closed, and so is the connection.
func (c *conn) read(p []byte) (int, error) {
	oob := make([]byte, unix.CmsgSpace(16*4))
	n, oobn, flags, _, err := c.UnixConn.ReadMsgUnix(p, oob)
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
		log.Printf("task %s: peer sent ancillary data: connection closed", c.l.t.ID)
		c.Close()
		return 0, errors.New("ancillary data refused")
	}
	return max(n, 0), err
}

// readHead reads until the blank line that ends the head. net/http has set the head deadline (ReadHeaderTimeout)
// before its first read. Over either cap the connection gets CAP_REACHED and net/http sees EOF, so it sends nothing.
func (c *conn) readHead() error {
	lim := c.l.lim
	b := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)
	for {
		n, err := c.read(chunk)
		b = append(b, chunk[:n]...)
		if end := headEnd(b); end >= 0 && end <= lim.HeadBytes {
			c.buf = b
			return nil
		}
		if len(b) > lim.HeadBytes {
			c.refuse("header_bytes", int64(lim.HeadBytes))
			return io.EOF
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				c.refuse("header_timeout", lim.HeadTimeout.Milliseconds())
				return io.EOF
			}
			if len(b) > 0 && errors.Is(err, io.EOF) {
				c.buf = b // a cut-off head: net/http refuses it as malformed
				return nil
			}
			return err
		}
	}
}

func (c *conn) refuse(what string, limit int64) {
	d, st := Cap(c.l.s.By, what, limit)
	log.Printf("DENY by=%s task=%s code=%s what=%s id=%s", c.l.s.By, c.l.t.ID, d.Code, what, d.ID)
	c.UnixConn.SetReadDeadline(time.Time{})
	answer(c.UnixConn, c.l.s.raw(d, st))
}

// headEnd is the length of the head in b, through its blank line (CRLF or bare LF, as net/http reads it), or -1.
func headEnd(b []byte) int {
	i, j := bytes.Index(b, []byte("\r\n\r\n")), bytes.Index(b, []byte("\n\n"))
	switch {
	case i < 0 && j < 0:
		return -1
	case i < 0 || (j >= 0 && j+2 < i+4):
		return j + 2
	}
	return i + 4
}

// Capped is an admission limit a request body hit; Cap gives its denial.
type Capped struct {
	What  string
	Limit int64
}

func (c *Capped) Error() string { return "CAP_REACHED " + c.What }

// ErrEncoding is a request body in a Content-Encoding other than identity or gzip.
var ErrEncoding = errors.New("unsupported Content-Encoding")

// BodyGrace and MinBodyRate pace a request body (#315): after BodyGrace it must keep arriving at MinBodyRate on
// average, or it is cut with CAP_REACHED{read_timeout}. A local forwarder sends megabytes a second; a body that
// trickles in only holds a slot or a spool file.
const (
	BodyGrace   = 2 * time.Second
	MinBodyRate = 256 << 10 // bytes a second
)

// Paced is r's body under the pace: before each read it moves the connection's read deadline to the time the bytes so
// far allow, never past the server's ReadTimeout from now (DefaultReadTimeout with none). A read past it fails with
// os.ErrDeadlineExceeded. At the body's end it lifts the deadline, so a long reply is not cut off.
func Paced(w http.ResponseWriter, r *http.Request) io.Reader {
	lim := DefaultReadTimeout
	if srv, ok := r.Context().Value(http.ServerContextKey).(*http.Server); ok && srv.ReadTimeout > 0 {
		lim = srv.ReadTimeout
	}
	now := time.Now()
	return &paced{r: r.Body, rc: http.NewResponseController(w), start: now, end: now.Add(lim)}
}

type paced struct {
	r          io.Reader
	rc         *http.ResponseController
	start, end time.Time
	n          int64
}

func (p *paced) Read(b []byte) (int, error) {
	d := p.start.Add(BodyGrace + time.Duration(p.n)*time.Second/MinBodyRate)
	if d.After(p.end) {
		d = p.end
	}
	p.rc.SetReadDeadline(d)
	n, err := p.r.Read(b)
	p.n += int64(n)
	if err == io.EOF {
		p.rc.SetReadDeadline(time.Time{}) // the whole body came: the reply may take as long as it takes
	}
	return n, err
}

// ReadBody reads r's body within the caps (#115): at most max bytes as sent (body_bytes) and, for a gzip body, at most
// max bytes decoded (decoded_bytes), so a zip bomb stops at the cap; all within the server's ReadTimeout and at the
// pace of Paced (read_timeout). Memory stays within about twice max. It then lifts the connection's read deadline, so
// a long streamed answer is not cut off once ReadTimeout passes.
func ReadBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, error) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, io.NopCloser(Paced(w, r)), max))
	var mb *http.MaxBytesError
	switch {
	case errors.As(err, &mb):
		return nil, &Capped{"body_bytes", max}
	case errors.Is(err, os.ErrDeadlineExceeded):
		return nil, &Capped{"read_timeout", 0}
	case err != nil:
		return nil, err
	}
	http.NewResponseController(w).SetReadDeadline(time.Time{})
	switch enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))); {
	case len(r.Header.Values("Content-Encoding")) > 1:
		return nil, ErrEncoding
	case enc == "" || enc == "identity":
		return raw, nil
	case enc != "gzip":
		return nil, ErrEncoding
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, ErrEncoding
	}
	zr.Multistream(false)
	out, err := io.ReadAll(io.LimitReader(zr, max+1))
	if err != nil {
		return nil, ErrEncoding
	}
	if int64(len(out)) > max {
		return nil, &Capped{"decoded_bytes", max}
	}
	return out, nil
}
