// Package broker serves an HTTP broker's per-task sockets (ARCHITECTURE.md §2.1, §6.3): rootd's register and revoke on
// svc-<svc>.sock, one socket per task bound in the dir rootd made, only that task's agent uid as peer, no descriptor
// passing, and the admission limits of #115: request head bytes and time, body and decoded body size, read time and
// connections per task, each refused with a typed CAP_REACHED before the handler sees the request.
package broker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"

	"agentbox/internal/canary"
	"agentbox/internal/ids"
	"agentbox/internal/ops"
)

// Limits are the admission caps (#115). Zero fields take the defaults.
type Limits struct {
	HeadBytes   int           // request line plus headers: CAP_REACHED{header_bytes}
	HeadTimeout time.Duration // from accept to the end of the head: CAP_REACHED{header_timeout}
	ReadTimeout time.Duration // the whole request, body included: CAP_REACHED{read_timeout}
	Conns       int           // open connections per task: CAP_REACHED{connections}
}

// Defaults: a Claude Code or Codex request head is a few KiB; the forwarder is local, so a body arrives in well under
// a second; a task runs the main conversation and its subagents in parallel.
const (
	DefaultHeadBytes   = 64 << 10
	DefaultHeadTimeout = 10 * time.Second
	DefaultReadTimeout = 60 * time.Second
	DefaultConns       = 16
)

func (l Limits) withDefaults() Limits {
	if l.HeadBytes <= 0 {
		l.HeadBytes = DefaultHeadBytes
	}
	if l.HeadTimeout <= 0 {
		l.HeadTimeout = DefaultHeadTimeout
	}
	if l.ReadTimeout <= 0 {
		l.ReadTimeout = DefaultReadTimeout
	}
	if l.Conns <= 0 {
		l.Conns = DefaultConns
	}
	return l
}

// Task is one task rootd registered: the socket is its, and so is every request on it. Canary is the task's canary
// (#105), which the broker watches its requests for.
type Task struct {
	ID, Agent, Trace, Canary string
	Chain                    []string
	UID                      uint32
}

// Format writes a denial in the broker's own surface (§5.6 Surfaces): it sets h and returns the body.
type Format func(h http.Header, d ops.Denial, status int) []byte

// Server holds the registered tasks of one broker.
type Server struct {
	Name     string // the socket's base name: <Dir>/t/<task>/<Name>.sock
	Dir      string // /run/agentbox-<svc>; rootd makes t/<task>/ (§2.1)
	By       string // the denial's by: keys, proxy or git
	AgentIDs func(agent string) (uid, gid uint32, err error)
	Handler  func(t *Task) http.Handler
	Format   Format
	Limits   Limits
	// Peer is the connection's SO_PEERCRED uid; nil: peerUID (Linux). Tests replace it.
	Peer func(c net.Conn) (uint32, error)

	mu    sync.Mutex
	tasks map[string]*task
}

type task struct {
	Task
	srv  *http.Server
	ln   *listener
	path string
}

var (
	taskRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	agentRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	chainRe = regexp.MustCompile(`^([A-Za-z0-9_-]{1,64}|(human|agent):[a-z_][a-z0-9_.-]{0,31})$`)
)

// Control is one request from rootd on svc-<svc>.sock (the caller checked uid 0): register{task, agent, chain, trace,
// canary} binds the task's socket; revoke{task} unlinks it and closes it and every connection it accepted (§2.1).
func (s *Server) Control(line []byte) map[string]any {
	var r struct {
		Call, Task, Agent, Trace, Canary string
		Chain                            []string
	}
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil {
		return map[string]any{"ok": false, "error": "bad request"}
	}
	switch r.Call {
	case "register":
		if err := s.register(Task{ID: r.Task, Agent: r.Agent, Trace: r.Trace, Canary: r.Canary, Chain: r.Chain}); err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "socket": s.sockPath(r.Task)}
	case "revoke":
		return map[string]any{"ok": s.revoke(r.Task)}
	case "list":
		s.mu.Lock()
		defer s.mu.Unlock()
		l := []string{}
		for id := range s.tasks {
			l = append(l, id)
		}
		return map[string]any{"ok": true, "tasks": l}
	}
	return map[string]any{"ok": false, "error": "unknown call"}
}

func (s *Server) sockPath(id string) string { return filepath.Join(s.Dir, "t", id, s.Name+".sock") }

// Lookup returns the live registration of id.
func (s *Server) Lookup(id string) (*Task, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok {
		return nil, false
	}
	c := t.Task
	return &c, true
}

// register checks the dir rootd made (§2.1: a real dir, this service's uid, group ag-<agent>, mode 2750), replaces
// only this service's own stale socket in it, and binds <Name>.sock 0660. A task without a trace has no budget to
// bill (§6.3), so it is refused. A canary, when rootd sends one, must have the minted shape.
func (s *Server) register(t Task) error {
	if !taskRe.MatchString(t.ID) || !agentRe.MatchString(t.Agent) || !ids.Is(ids.Trace, t.Trace) || t.Canary != "" && !canary.Valid(t.Canary) {
		return errors.New("bad task, agent, trace or canary")
	}
	for _, c := range t.Chain {
		if !chainRe.MatchString(c) {
			return errors.New("bad chain member")
		}
	}
	uid, gid, err := s.AgentIDs(t.Agent)
	if err != nil {
		return fmt.Errorf("agent %s: %v", t.Agent, err)
	}
	t.UID = uid
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tasks == nil {
		s.tasks = map[string]*task{}
	}
	if _, ok := s.tasks[t.ID]; ok {
		return errors.New("task already registered")
	}
	p := s.sockPath(t.ID)
	fi, err := os.Lstat(filepath.Dir(p))
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.IsDir() || st.Uid != uint32(os.Getuid()) || st.Gid != gid || fi.Mode()&(os.ModePerm|os.ModeSetgid|os.ModeSticky|os.ModeSetuid) != os.ModeSetgid|0o750 {
		return fmt.Errorf("%s: want a dir owned by this service, group ag-%s, mode 2750", filepath.Dir(p), t.Agent)
	}
	if fi, err := os.Lstat(p); err == nil {
		if fi.Mode().Type() != os.ModeSocket {
			return fmt.Errorf("%s exists and is not a socket", p)
		}
		os.Remove(p) // our own stale socket from before a restart (§2.1)
	}
	ul, err := net.Listen("unix", p)
	if err != nil {
		return err
	}
	ul.(*net.UnixListener).SetUnlinkOnClose(false) // revoke unlinks first, so a new task socket never races the close
	if err := os.Chmod(p, 0o660); err != nil {
		ul.Close()
		os.Remove(p)
		return err
	}
	lt := &task{Task: t, path: p}
	lt.ln = s.newListener(ul, lt)
	lt.srv = s.httpServer(lt)
	s.tasks[t.ID] = lt
	go lt.srv.Serve(lt.ln)
	log.Printf("task %s (agent %s) registered: %s", t.ID, t.Agent, p)
	return nil
}

func (s *Server) revoke(id string) bool {
	s.mu.Lock()
	t := s.tasks[id]
	delete(s.tasks, id)
	s.mu.Unlock()
	if t == nil {
		return false
	}
	os.Remove(t.path)
	t.srv.Close() // the listener and every connection it accepted
	t.ln.closeAll()
	log.Printf("task %s revoked", id)
	return true
}

// Live reports whether t is still the registered task of its id: a request on a connection that outlived its revoke
// is refused (§2.1).
func (s *Server) Live(t *Task) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	lt, ok := s.tasks[t.ID]
	return ok && lt.Agent == t.Agent && lt.Trace == t.Trace
}

func (s *Server) httpServer(t *task) *http.Server {
	l := s.Limits.withDefaults()
	h := s.Handler(&t.Task)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !s.Live(&t.Task) {
				s.Refuse(w, ops.Deny(ops.TaskEnded, "", ops.Slots{By: s.By}), http.StatusConflict)
				return
			}
			h.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: l.HeadTimeout,
		ReadTimeout:       l.ReadTimeout,
		// the head gate refuses a bigger head with a typed denial first; this bounds what net/http buffers anyway
		MaxHeaderBytes: l.HeadBytes,
		ErrorLog:       log.New(logWriter{}, "", 0),
		BaseContext:    func(net.Listener) context.Context { return context.Background() },
	}
	// one request per connection: the head gate checks each connection's first head, and the in-task forwarder dials
	// afresh for every request anyway
	srv.SetKeepAlivesEnabled(false)
	return srv
}

type logWriter struct{}

func (logWriter) Write(b []byte) (int, error) {
	log.Printf("http: %s", bytes.TrimSpace(b))
	return len(b), nil
}

// Refuse writes d in the broker's surface with status and the denial header (§5.6).
func (s *Server) Refuse(w http.ResponseWriter, d ops.Denial, status int) {
	h := w.Header()
	h.Set(ops.DenialHeaderName, ops.DenialHeader(d))
	body := s.Format(h, d, status)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	w.Write(body)
}

// Cap is the CAP_REACHED denial a broker (by) gives for an admission limit (#115), and its HTTP status.
func Cap(by, what string, limit int64) (ops.Denial, int) {
	st := map[string]int{"body_bytes": http.StatusRequestEntityTooLarge, "decoded_bytes": http.StatusRequestEntityTooLarge,
		"header_bytes": http.StatusRequestHeaderFieldsTooLarge, "header_timeout": http.StatusRequestTimeout,
		"read_timeout": http.StatusRequestTimeout, "connections": http.StatusTooManyRequests}[what]
	var lp *int64
	if limit > 0 {
		lp = &limit
	}
	return ops.Deny(ops.CapReached, what, ops.Slots{By: by, Limit: lp}), st
}

// raw is a whole HTTP/1.1 response for d, for a connection refused before net/http reads it.
func (s *Server) raw(d ops.Denial, status int) []byte {
	h := http.Header{}
	h.Set(ops.DenialHeaderName, ops.DenialHeader(d))
	body := s.Format(h, d, status)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("Connection", "close")
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	h.Write(&b)
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes()
}

// Rebind registers every live task rootd lists (task.list_live), after a restart.
func (s *Server) Rebind(list []byte) error {
	var r struct {
		OK    bool `json:"ok"`
		Tasks []struct {
			Task, Agent, Trace, Canary string
			Chain                      []string
		} `json:"tasks"`
	}
	if err := json.Unmarshal(list, &r); err != nil || !r.OK {
		return fmt.Errorf("task.list_live: %s", bytes.TrimSpace(list))
	}
	for _, t := range r.Tasks {
		if err := s.register(Task{ID: t.Task, Agent: t.Agent, Trace: t.Trace, Canary: t.Canary, Chain: t.Chain}); err != nil {
			log.Printf("task %s: rebind: %v", t.Task, err)
		}
	}
	return nil
}

// ServeControl serves svc-<svc>.sock: rootd's register and revoke, uid 0 only (§2.1), one JSON line each way.
func (s *Server) ServeControl(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			log.Printf("svc-%s.sock: accept: %v", s.Name, err)
			time.Sleep(100 * time.Millisecond) // EMFILE and the like: back off, never end the listener
			continue
		}
		go func() {
			defer c.Close()
			if uid, err := s.peer(c); err != nil || uid != 0 {
				log.Printf("svc-%s.sock: refused peer uid %d: %v", s.Name, uid, err)
				return
			}
			br := bufio.NewReaderSize(c, 4096)
			for {
				c.SetReadDeadline(time.Now().Add(time.Minute))
				line, err := br.ReadSlice('\n')
				if err != nil {
					return // a line over the buffer (bufio.ErrBufferFull) ends the connection too
				}
				b, _ := json.Marshal(s.Control(line))
				if _, err := c.Write(append(b, '\n')); err != nil {
					return
				}
			}
		}()
	}
}
