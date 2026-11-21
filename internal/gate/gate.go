// Package gate is agentboxd's task gate (ARCHITECTURE.md §2.1, §5.2, §5.6): one JSON-RPC socket per task that rootd
// registered, request validation against the op registry, provenance added server-side, agentbox-denial/v1 for every
// refusal, and forwarding to rootd, which runs nothing before auditd ACKs its INTENT.
//
// shortcut: no Cedar pass (weeks 9-10), no agentboxd-executed ops (bus, memory, ask.status: weeks 7-8) and no
// task.list_live at start (rootd's task registry is weeks 5-6), so registrations are lost when agentboxd restarts.
package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"

	"agentbox/internal/denial"
	"agentbox/internal/ops"
)

// MaxRequest is the longest request line a task may send; rootd.sock takes the same.
const MaxRequest = 64 << 10

var (
	taskRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	agentRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	rpcID   = regexp.MustCompile(`^("[A-Za-z0-9_.-]{1,64}"|-?[0-9]{1,15})$`)
)

// Server holds the registered tasks.
type Server struct {
	Dir string // /run/agentbox-gate: rootd makes t/<task>/ (§2.1); the socket is t/<task>/gate.sock
	// Forward sends one request to rootd.sock and returns its reply line.
	Forward func(req map[string]any) ([]byte, error)
	// AgentIDs is the uid and gid of ag-<agent>.
	AgentIDs func(agent string) (uid, gid uint32, err error)

	mu    sync.Mutex
	tasks map[string]*task
}

type task struct {
	id, agent string
	chain     []string
	uid       uint32
	ln        net.Listener
	path      string
	mu        sync.Mutex
	conns     map[net.Conn]bool
	ended     bool
}

// Control is one request from rootd on svc-gate.sock (the caller checked SO_PEERCRED uid 0): register{task, agent,
// chain} binds the task's gate socket; revoke{task} unlinks it, closes it and every connection it accepted (§2.1).
func (s *Server) Control(line []byte) map[string]any {
	var r struct {
		Call, Task, Agent string
		Chain             []string
	}
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil {
		return map[string]any{"ok": false, "error": "bad request"}
	}
	switch r.Call {
	case "register":
		if err := s.register(r.Task, r.Agent, r.Chain); err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "socket": s.sockPath(r.Task)}
	case "revoke":
		return map[string]any{"ok": s.revoke(r.Task)}
	case "list":
		s.mu.Lock()
		defer s.mu.Unlock()
		ids := []string{}
		for id := range s.tasks {
			ids = append(ids, id)
		}
		return map[string]any{"ok": true, "tasks": ids}
	}
	return map[string]any{"ok": false, "error": "unknown call"}
}

func (s *Server) sockPath(id string) string { return filepath.Join(s.Dir, "t", id, "gate.sock") }

// register checks the dir rootd made (§2.1: a real dir, agentboxd's uid, group ag-<agent>, mode 2750), replaces only
// this service's own stale socket in it, and binds gate.sock 0660.
func (s *Server) register(id, agent string, chain []string) error {
	if !taskRe.MatchString(id) || !agentRe.MatchString(agent) {
		return errors.New("bad task or agent name")
	}
	for _, c := range chain {
		if !taskRe.MatchString(c) {
			return errors.New("bad chain member")
		}
	}
	uid, gid, err := s.AgentIDs(agent)
	if err != nil {
		return fmt.Errorf("agent %s: %v", agent, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tasks == nil {
		s.tasks = map[string]*task{}
	}
	if _, ok := s.tasks[id]; ok {
		return errors.New("task already registered")
	}
	dir := filepath.Dir(s.sockPath(id))
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.IsDir() || st.Uid != uint32(os.Getuid()) || st.Gid != gid || fi.Mode()&(os.ModePerm|os.ModeSetgid|os.ModeSticky|os.ModeSetuid) != os.ModeSetgid|0o750 {
		return fmt.Errorf("%s: want a dir owned by this service, group ag-%s, mode 2750", dir, agent)
	}
	p := s.sockPath(id)
	if fi, err := os.Lstat(p); err == nil {
		if fi.Mode().Type() != os.ModeSocket {
			return fmt.Errorf("%s exists and is not a socket", p)
		}
		os.Remove(p) // our own stale socket from before a restart (§2.1)
	}
	ln, err := net.Listen("unix", p)
	if err != nil {
		return err
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false) // revoke unlinks first, so a new task socket never races the close
	if err := os.Chmod(p, 0o660); err != nil {
		ln.Close()
		os.Remove(p)
		return err
	}
	t := &task{id: id, agent: agent, chain: chain, uid: uid, ln: ln, path: p, conns: map[net.Conn]bool{}}
	s.tasks[id] = t
	go s.accept(t)
	log.Printf("task %s (agent %s) registered: %s", id, agent, p)
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
	t.ln.Close()
	t.mu.Lock()
	t.ended = true
	for c := range t.conns {
		c.Close()
	}
	t.mu.Unlock()
	log.Printf("task %s revoked", id)
	return true
}

func (s *Server) live(t *task) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tasks[t.id] == t
}

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func rpcError(id json.RawMessage, code int, msg string, data any) []byte {
	e := map[string]any{"code": code, "message": msg}
	if data != nil {
		e["data"] = data
	}
	if id == nil {
		id = json.RawMessage("null")
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": e})
	return b
}

func denied(id json.RawMessage, d any, code denial.Code) []byte {
	return rpcError(id, denial.RPCCode, string(code), d)
}

// call is one JSON-RPC request on task t's socket. The task, agent and chain come from the socket, never the request:
// params are only the op's args, and the registry schema refuses any field it doesn't declare.
func (s *Server) call(t *task, line []byte) []byte {
	var r rpcReq
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return rpcError(nil, -32700, "parse error", nil)
	}
	if r.JSONRPC != "2.0" || !rpcID.Match(r.ID) {
		return rpcError(nil, -32600, "invalid request", nil)
	}
	gd := func(code denial.Code, rule, field, expect string) []byte {
		dn := denial.New(code, "gate", rule, r.Method, field, expect)
		log.Printf("DENY by=gate task=%s op=%s code=%s rule=%s id=%s", t.id, dn.Op, dn.Code, dn.Rule, dn.ID)
		return denied(r.ID, dn, code)
	}
	if !s.live(t) {
		return gd(denial.TaskEnded, "gate.task_ended", "", "")
	}
	o, ok := ops.Lookup(r.Method)
	if !ok || !o.AgentCallable() {
		return gd(denial.UnknownOp, "gate.unknown_op", "", "")
	}
	if r.Params == nil {
		r.Params = json.RawMessage("{}")
	}
	if _, aerr := o.ValidateArgs(r.Params); aerr != nil {
		return gd(denial.InvalidArgs, "gate.schema", aerr.Field, aerr.Expect)
	}
	if !o.Rootd {
		return gd(denial.UnknownOp, "gate.not_built", "", "")
	}
	chain := t.chain
	if chain == nil {
		chain = []string{}
	}
	rep, err := s.Forward(map[string]any{"op": "task.op", "name": o.Name, "args": r.Params, "task": t.id, "agent": t.agent, "chain": chain})
	if err != nil {
		log.Printf("task %s %s: rootd: %v", t.id, o.Name, err)
		return gd(denial.BrokerUnavailable, "gate.rootd_unreachable", "", "")
	}
	var rr struct {
		OK     bool            `json:"ok"`
		OpID   string          `json:"opId"`
		Result json.RawMessage `json:"result"`
		Denial json.RawMessage `json:"denial"`
	}
	if json.Unmarshal(rep, &rr) != nil {
		return gd(denial.BrokerUnavailable, "gate.rootd_reply", "", "")
	}
	if !rr.OK {
		var dn denial.Denial
		if !denial.Valid(rr.Denial) || json.Unmarshal(rr.Denial, &dn) != nil {
			log.Printf("task %s %s: rootd refused without a valid denial: %s", t.id, o.Name, bytes.TrimSpace(rep))
			return gd(denial.BrokerUnavailable, "gate.rootd_reply", "", "")
		}
		return denied(r.ID, rr.Denial, dn.Code) // rootd's denial, relayed unchanged (§5.2)
	}
	res := map[string]any{"opId": rr.OpID}
	if rr.Result != nil {
		res["result"] = rr.Result
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": r.ID, "result": res})
	return b
}
