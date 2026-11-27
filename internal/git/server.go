package git

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cgi"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"agentbox/internal/canary"
	"agentbox/internal/ids"
	"agentbox/internal/ops"
)

// Server is agentbox-git.
type Server struct {
	Root     string // git/
	TaskDir  string // /run/agentbox-git
	Hooks    string // core.hooksPath for local pushes
	Backend  string // git-http-backend
	DayCap   int64  // each agent's pushed bytes per UTC day
	MaxPush  int64  // receive.maxInputSize
	AgentIDs func(agent string) (uid, gid uint32, err error)
	Audit    Auditor
	Rootd    Rootd
	GitHub   *GitHub
	Pusher   Pusher
	// Peer is a connection's SO_PEERCRED uid; nil: peerUID (Linux).
	Peer func(net.Conn) (uint32, error)
	Now  func() time.Time

	store  *sql.DB
	mu     sync.Mutex
	tasks  map[string]*task
	denyMu sync.Mutex
	denied map[string]int64 // task and code: when its DENY record went out, so a loop sends one a minute
}

type task struct {
	id, agent, canary string
	uid               uint32
	path              string
	srv               *http.Server
}

// notFoundDelay is NOT_FOUND_OR_NOT_OWNED's floor (§5.6 leak rule 3): a missing repo and one the caller can't see leave
// at the same time.
var notFoundDelay = 200 * time.Millisecond

// maxWantBody bounds the upload-pack request the service reads to find what a fetch wants. A longer one is passed on
// unread, and every tainted ref of the repo counts as wanted.
const maxWantBody = 16 << 20

// Open opens the service's store. Call it before serving.
func (s *Server) Open() error {
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Peer == nil {
		s.Peer = peerUID
	}
	if s.DayCap <= 0 {
		s.DayCap = DayPushBytes
	}
	if s.MaxPush <= 0 {
		s.MaxPush = MaxPushBytes
	}
	db, err := OpenStore(s.Root)
	if err != nil {
		return err
	}
	os.RemoveAll(filepath.Join(s.Root, ".spool")) // request bodies a crash left
	s.store = db
	s.tasks = map[string]*task{}
	s.denied = map[string]int64{}
	return nil
}

// Close closes the store and every task socket.
func (s *Server) Close() error {
	s.mu.Lock()
	for id := range s.tasks {
		s.mu.Unlock()
		s.revoke(id)
		s.mu.Lock()
	}
	s.mu.Unlock()
	return s.store.Close()
}

// ctlReq is one line on svc-git.sock. Only rootd (uid 0) sends them.
type ctlReq struct {
	Call    string          `json:"call"`
	Task    string          `json:"task"`
	Agent   string          `json:"agent"`
	Chain   []string        `json:"chain"`
	Trace   string          `json:"trace"`
	Canary  string          `json:"canary"`
	Project string          `json:"project"`
	OID     string          `json:"oid"`
	Ref     string          `json:"ref"`
	URL     string          `json:"url"`
	ID      string          `json:"id"`
	Name    string          `json:"name"`
	Args    json.RawMessage `json:"args"`
	Bound   json.RawMessage `json:"bound"`
	Since   int64           `json:"since"`
}

func ok(kv ...any) map[string]any {
	m := map[string]any{"ok": true}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	return m
}

func bad(err error) map[string]any { return map[string]any{"ok": false, "error": err.Error()} }

// refused is an effect GitHub or git refused: what for the task's REMOTE_REJECTED, detail for humans only.
func refused(err error) map[string]any {
	var ae *APIError
	if errors.As(err, &ae) {
		return map[string]any{"ok": false, "what": ae.What, "detail": ae.Detail}
	}
	return map[string]any{"ok": false, "what": "other", "detail": err.Error()}
}

// Control answers one line from rootd.
func (s *Server) Control(line []byte) map[string]any {
	var r ctlReq
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil {
		return bad(errors.New("bad request"))
	}
	switch r.Call {
	case "register":
		if err := s.register(r.Task, r.Agent, r.Canary); err != nil {
			return bad(err)
		}
		return ok("socket", s.sockPath(r.Task))
	case "revoke":
		return ok("revoked", s.revoke(r.Task))
	case "list":
		s.mu.Lock()
		defer s.mu.Unlock()
		l := []string{}
		for id := range s.tasks {
			l = append(l, id)
		}
		slices.Sort(l)
		return ok("tasks", l)
	case "repo.create":
		if err := CreateRepo(s.Root, r.Agent, r.Project); err != nil {
			return bad(err)
		}
		return ok()
	case "repo.check":
		return s.check(r)
	case "remote.lookup":
		owner, repo, err := ParseRemoteURL(r.URL)
		if err != nil {
			return bad(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		info, err := s.GitHub.Repo(ctx, owner, repo)
		if err != nil {
			return refused(err)
		}
		return ok("nodeId", info.NodeID, "visibility", info.Visibility)
	case "remote.ref":
		return s.remoteRef(r)
	case "exec":
		return s.exec(r)
	case "reconcile":
		return s.reconcile(r)
	}
	return bad(errors.New("unknown call"))
}

// check answers repo.check: whether agent's repo exists, whether a branch contains oid, and ref's tip.
func (s *Server) check(r ctlReq) map[string]any {
	if !Exists(s.Root, r.Agent, r.Project) {
		return ok("exists", false)
	}
	repo := Repo(s.Root, r.Agent, r.Project)
	out := ok("exists", true)
	if r.OID != "" {
		c, err := Contains(repo, r.OID)
		if err != nil {
			return bad(err)
		}
		out["contains"] = c
	}
	if r.Ref != "" {
		tip, err := Tip(repo, r.Ref)
		if err != nil {
			return bad(err)
		}
		out["tip"] = tip
	}
	return out
}

func (s *Server) sockPath(id string) string { return filepath.Join(s.TaskDir, "t", id, "git.sock") }

// register binds the task's git.sock in the dir rootd made: a real dir, this service's uid, group ag-<agent>, mode
// 2750 (§2.1). Only the agent's uid may connect.
func (s *Server) register(id, agent, c string) error {
	if !ids.Is(ids.Task, id) || !reAgent.MatchString(agent) || c != "" && !canary.Valid(c) {
		return errors.New("bad task, agent or canary")
	}
	uid, gid, err := s.AgentIDs(agent)
	if err != nil {
		return fmt.Errorf("agent %s: %v", agent, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, dup := s.tasks[id]; dup {
		// rootd's register can come after this service's own rebind took the task (its first call starts the
		// service): the same registration again is a no-op
		if t.agent == agent && t.canary == c {
			return nil
		}
		return errors.New("task already registered")
	}
	p := s.sockPath(id)
	if err := checkDir(filepath.Dir(p), gid); err != nil {
		return err
	}
	if fi, err := os.Lstat(p); err == nil {
		if fi.Mode().Type() != os.ModeSocket {
			return fmt.Errorf("%s exists and is not a socket", p)
		}
		os.Remove(p) // this service's own socket from before a restart (§2.1)
	}
	ul, err := net.Listen("unix", p)
	if err != nil {
		return err
	}
	ul.(*net.UnixListener).SetUnlinkOnClose(false) // revoke unlinks first
	if err := os.Chmod(p, 0o660); err != nil {
		ul.Close()
		os.Remove(p)
		return err
	}
	t := &task{id: id, agent: agent, canary: c, uid: uid, path: p}
	t.srv = &http.Server{Handler: s.handler(t), ReadHeaderTimeout: 30 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	s.tasks[id] = t
	go t.srv.Serve(peerListener{ul, s, uid})
	log.Printf("task %s (agent %s) registered: %s", id, agent, p)
	return nil
}

// checkDir is §2.1's check of a per-task dir rootd made.
func checkDir(dir string, gid uint32) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.IsDir() || st.Uid != uint32(os.Getuid()) || st.Gid != gid ||
		fi.Mode()&(os.ModePerm|os.ModeSetgid|os.ModeSetuid|os.ModeSticky) != os.ModeSetgid|0o750 {
		return fmt.Errorf("%s: want a dir owned by this service, group of the agent, mode 2750", dir)
	}
	return nil
}

// revoke unlinks the task's socket, then closes it and every connection it accepted (§2.1).
func (s *Server) revoke(id string) bool {
	s.mu.Lock()
	t := s.tasks[id]
	delete(s.tasks, id)
	s.mu.Unlock()
	if t == nil {
		return false
	}
	os.Remove(t.path)
	t.srv.Close()
	s.denyMu.Lock()
	for k := range s.denied {
		if strings.HasPrefix(k, id+" ") {
			delete(s.denied, k)
		}
	}
	s.denyMu.Unlock()
	log.Printf("task %s revoked", id)
	return true
}

func (s *Server) live(t *task) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tasks[t.id] == t
}

// peerListener accepts only connections from uid (§2.1 peer check); any other peer is closed, and Accept waits on.
type peerListener struct {
	net.Listener
	s   *Server
	uid uint32
}

func (l peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if u, err := l.s.Peer(c); err == nil && u == l.uid {
			return c, nil
		}
		c.Close()
	}
}

// ServeControl serves svc-git.sock: one JSON line per call, uid 0 only (§2.1).
func (s *Server) ServeControl(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			if u, err := s.Peer(c); err != nil || u != 0 {
				log.Printf("svc-git.sock: refused a peer that is not root")
				return
			}
			br := bufio.NewReaderSize(c, 64<<10)
			for {
				c.SetReadDeadline(time.Now().Add(10 * time.Minute))
				line, err := br.ReadBytes('\n')
				if len(line) > 1<<20 {
					return
				}
				if len(bytes.TrimSpace(line)) > 0 {
					b, _ := json.Marshal(s.Control(line))
					c.SetWriteDeadline(time.Now().Add(30 * time.Second))
					if _, werr := c.Write(append(b, '\n')); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()
	}
}

// Rebind registers every live task rootd lists (task.list_live, §2.1) after a restart, with its canary.
func (s *Server) Rebind() error {
	rep, err := s.Rootd.Call(map[string]any{"op": "task.list_live"}, 10*time.Second)
	if err != nil {
		return err
	}
	l, _ := rep["tasks"].([]any)
	for _, x := range l {
		m, _ := x.(map[string]any)
		id, _ := m["task"].(string)
		agent, _ := m["agent"].(string)
		c, _ := m["canary"].(string)
		if err := s.register(id, agent, c); err != nil {
			log.Printf("task %s: rebind: %v", id, err)
		}
	}
	return nil
}

// denyOnce sends a DENY record for d unless one for the same task and code went out in the last minute (§9).
// shortcut: repeats in the window are not counted.
func (s *Server) denyOnce(d ops.Denial, t *task, detail string) {
	k, now := t.id+" "+d.Code+" "+d.What, s.Now().UnixMilli()
	s.denyMu.Lock()
	last, seen := s.denied[k]
	if !seen || now-last >= time.Minute.Milliseconds() {
		s.denied[k] = now
	}
	s.denyMu.Unlock()
	if !seen || now-last >= time.Minute.Milliseconds() {
		go s.Audit.Deny(d, t.id, t.agent, detail)
	}
}

// writeDenial writes a smart-HTTP refusal (§5.6 Surfaces): text/plain, msg then the denial JSON, 404 for
// NOT_FOUND_OR_NOT_OWNED, else the code's status.
func writeDenial(w http.ResponseWriter, d ops.Denial) {
	body := ops.GitBody(d)
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set(ops.DenialHeaderName, ops.DenialHeader(d))
	h.Set("Content-Length", strconv.Itoa(len(body)))
	c, _ := ops.LookupCode(d.Code)
	w.WriteHeader(ops.HTTPStatus(c))
	w.Write(body)
}

// rePath is the smart-HTTP surface: info/refs for one of the two services, and their POSTs. Nothing of the dumb
// protocol is served.
var rePath = regexp.MustCompile(`^/([a-z0-9][a-z0-9_-]{0,63})(?:\.git)?/(info/refs|git-upload-pack|git-receive-pack)$`)

// handler is one task's smart HTTP (§6.3): git http-backend over the agent's own repos only, REMOTE_USER the agent.
// A path that names no repo of the agent's (missing, another agent's, or not a smart-HTTP path) is one miss: 404
// NOT_FOUND_OR_NOT_OWNED at receipt + 200 ms.
func (s *Server) handler(t *task) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receipt := time.Now()
		if !s.live(t) {
			writeDenial(w, ops.Deny(ops.TaskEnded, "", ops.Slots{By: "git"}))
			return
		}
		m := rePath.FindStringSubmatch(r.URL.Path)
		svc := r.URL.Query().Get("service")
		okReq := m != nil && Exists(s.Root, t.agent, m[1]) && (m[2] == "info/refs" && r.Method == http.MethodGet &&
			(svc == "git-upload-pack" || svc == "git-receive-pack") || m[2] != "info/refs" && r.Method == http.MethodPost)
		if !okReq {
			d := ops.Deny(ops.NotFoundOrNotOwned, "", ops.Slots{Op: "repo.push", By: "git"})
			s.denyOnce(d, t, "")
			time.Sleep(time.Until(receipt.Add(notFoundDelay)))
			writeDenial(w, d)
			return
		}
		project := m[1]
		env := Env("GIT_PROJECT_ROOT="+filepath.Join(s.Root, t.agent), "GIT_HTTP_EXPORT_ALL=1", "REMOTE_USER="+t.agent)
		kv := [][2]string{
			{"core.hooksPath", s.Hooks},
			{"receive.maxInputSize", strconv.FormatInt(s.MaxPush, 10)},
			{"receive.fsckObjects", "true"},
			{"uploadpack.allowAnySHA1InWant", "false"},
			{"uploadpack.allowReachableSHA1InWant", "false"},
			{"uploadpack.allowTipSHA1InWant", "false"},
			{"uploadpack.allowRefInWant", "false"},
		}
		env = append(env, "GIT_CONFIG_COUNT="+strconv.Itoa(len(kv)))
		for i, x := range kv {
			env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, x[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, x[1]))
		}
		if r.Method == http.MethodPost && (r.ContentLength < 0 || len(r.TransferEncoding) > 0) {
			done, err := s.spool(r, s.MaxPush+spoolSlack)
			if errors.Is(err, errSpoolFull) {
				http.Error(w, "agentbox-git: the push is over receive.maxInputSize", http.StatusRequestEntityTooLarge)
				return
			}
			if err != nil {
				http.Error(w, "agentbox-git: the request body could not be read", http.StatusInternalServerError)
				return
			}
			defer done()
		}
		switch {
		case m[2] == "git-receive-pack":
			dir, err := os.MkdirTemp("", "agentbox-push-")
			if err != nil {
				http.Error(w, "agentbox-git: no temp dir", http.StatusInternalServerError)
				return
			}
			defer os.RemoveAll(dir)
			req, _ := json.Marshal(HookRequest{Task: t.id, Agent: t.agent, Project: project, Canary: t.canary, DayCap: s.DayCap,
				Store: s.Root, Resolve: s.Rootd.Sock, Audit: s.Audit.Sock})
			p := filepath.Join(dir, "push.json")
			if err := os.WriteFile(p, req, 0o600); err != nil {
				http.Error(w, "agentbox-git: no push request", http.StatusInternalServerError)
				return
			}
			env = append(env, HookEnv+"="+p)
		case m[2] == "git-upload-pack":
			body, err := s.readTaint(t, project, r)
			if err != nil {
				d := ops.Deny(ops.AuditUnavailable, "", ops.Slots{By: "git"})
				s.denyOnce(d, t, "fetch read taint: "+err.Error())
				writeDenial(w, d)
				return
			}
			r.Body = body
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/" + project + ".git/" + m[2] // the name http-backend finds under GIT_PROJECT_ROOT
		(&cgi.Handler{Path: s.Backend, Root: "/", Dir: s.Root, Env: env, Logger: log.New(io.Discard, "", 0)}).ServeHTTP(w, r2)
	})
}

// spoolSlack is what a push request holds beyond its pack: the ref update lines and pkt-line framing.
const spoolSlack = 1 << 20

var errSpoolFull = errors.New("request body over the limit")

// spool makes a chunked request body plain: net/http/cgi refuses a chunked body, and git sends one for every POST over
// http.postBuffer. The body goes to a file in git/.spool, so it counts against git/'s quota, of at most limit bytes,
// and r gets it with its length. done removes the file.
// shortcut: a push over the limit gets 413, not receive.maxInputSize's own message.
func (s *Server) spool(r *http.Request, limit int64) (func(), error) {
	dir := filepath.Join(s.Root, ".spool")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, "body-")
	if err != nil {
		return nil, err
	}
	done := func() { f.Close(); os.Remove(f.Name()) }
	n, err := io.Copy(f, io.LimitReader(r.Body, limit+1))
	if err == nil && n > limit {
		err = errSpoolFull
	}
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		done()
		return nil, err
	}
	r.Body, r.ContentLength, r.TransferEncoding = f, n, nil
	r.Header.Del("Transfer-Encoding")
	return done, nil
}

// readTaint applies read taint before the first pack byte (§6.3, §9): when the fetch may deliver objects of a tainted
// ref, auditd gets a READ_INTENT for each of the repo's tainted refs and ACKs it first. A fetch whose wants are all
// tips of clean refs needs none. It returns the body to pass on.
func (s *Server) readTaint(t *task, project string, r *http.Request) (io.ReadCloser, error) {
	tainted, err := taintedRefs(s.store, RepoName(t.agent, project))
	if err != nil {
		return nil, err
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, maxWantBody+1))
	if err != nil {
		return nil, err
	}
	body := io.NopCloser(io.MultiReader(bytes.NewReader(buf), r.Body))
	if len(tainted) == 0 {
		return body, nil
	}
	wants, ok := Wants(buf, r.Header.Get("Content-Encoding"))
	if ok && len(buf) <= maxWantBody {
		tips, err := Tips(Repo(s.Root, t.agent, project))
		if err != nil {
			return nil, err
		}
		clean := map[string]bool{}
		for ref, oid := range tips {
			if !slices.Contains(tainted, ref) {
				clean[oid] = true
			}
		}
		all := true
		for _, w := range wants {
			all = all && clean[w]
		}
		if all {
			return body, nil
		}
	}
	for _, ref := range tainted {
		if err := s.Audit.Send(map[string]any{"type": "READ_INTENT", "reader": "task:" + t.id, "source": RefSubject(t.agent, project, ref)}); err != nil {
			return nil, err
		}
	}
	return body, nil
}

// Wants parses an upload-pack request body (protocol v0 or v2 pkt-lines, gzip if enc says so) and returns the
// object ids it wants. ok is false when the body doesn't parse, or asks for a ref by name (want-ref): then a caller
// must assume it wants anything.
func Wants(b []byte, enc string) ([]string, bool) {
	if enc == "gzip" || enc == "x-gzip" {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, false
		}
		b, err = io.ReadAll(io.LimitReader(zr, maxWantBody))
		if err != nil {
			return nil, false
		}
	} else if enc != "" {
		return nil, false
	}
	var out []string
	for len(b) >= 4 {
		n, err := strconv.ParseUint(string(b[:4]), 16, 16)
		if err != nil {
			return nil, false
		}
		if n < 4 { // flush, delim or response-end
			b = b[4:]
			continue
		}
		if int(n) > len(b) {
			return nil, false
		}
		line := strings.TrimRight(string(b[4:n]), "\n")
		b = b[n:]
		if strings.HasPrefix(line, "want-ref ") {
			return nil, false
		}
		if w, found := strings.CutPrefix(line, "want "); found {
			oid, _, _ := strings.Cut(w, " ")
			if !ValidOID(oid) {
				return nil, false
			}
			out = append(out, oid)
		}
	}
	return out, len(b) == 0
}
