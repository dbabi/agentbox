// Package rootd is agentbox-rootd (ARCHITECTURE.md §2, §5.2), the root executor. The week-3 skeleton holds the state
// store, the systemd-activated sockets with their peer checks, the resolver that fills the broker destination sets
// (§6.1, §6.3, Appendix B) and audit segment creation and sealing (§9). Pending ops, the floor and the task registry
// come in later weeks on the same sockets and store.
package rootd

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"agentbox/internal/audit"
	"agentbox/internal/fw"
	"agentbox/internal/ops"
	"agentbox/internal/rootd/accounts"
	"agentbox/internal/rootd/attach"
	"agentbox/internal/rootd/nl"
	"agentbox/internal/rootd/quota"
	"agentbox/internal/rootd/resolve"

	_ "modernc.org/sqlite"
)

// Config is rootd's command line (agentbox rootd).
type Config struct {
	DB             string            // rootd.db
	EgressDir      string            // control/egress
	AuditDir       string            // audit/
	ElementTimeout time.Duration     // dst set element timeout (Appendix B: 10 min)
	RefillInterval time.Duration     // timer refill and ntfy_dst refresh (§6.1: 5 min)
	AuditSocket    string            // auditd's rootd producer socket, for DENY records
	GenDir         string            // the release's gen/: the files generated from the op registry (ops.Check)
	SealCrash      func(string)      // audit.Files' crash-mid-seal test hook (AGENTBOX_TEST_CRASH); nil in production
	Effects        map[string]Effect // the agent ops rootd can execute, by name
	RawAudit       bool              // AGENTBOX_TEST_AUDIT_RAW: INTENT args without their audit classes (test VMs only)
	Tasks          TaskConfig        // task.start and task.stop (§4.2)
	Attach         attach.Runner     // runs agent.attach sessions; nil: attach.Podman with the task image
	AttachRoot     string            // /var/lib/agentbox (attach.Root) unless a test sets it
	Alert          func(title, msg string) error
	QuotaHold      string // AGENTBOX_TEST_QUOTA_HOLD: while this file exists, a qgroup repair waits before its rescan (test VMs only)
}

// Socket names: each .socket unit sets FileDescriptorName= to one of these.
const (
	sockAdmin = "admin"
	sockSeal  = "audit-seal" // auditd's audit-seal.sock: audit.create and audit.seal (audit.SealClient)
)

// OpenDB opens rootd.db with WAL and synchronous=FULL (§2, App. E) and creates the week-3 tables.
func OpenDB(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	// agentbox-reconcile opens rootd.db before rootd, under the default umask: create it 0600, and fix one made 0644.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	err = f.Chmod(0o600)
	f.Close()
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout(10000)&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer; every transaction is BEGIN IMMEDIATE
	var mode string
	var syncv int
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		db.Close()
		return nil, err
	}
	if err := db.QueryRow(`PRAGMA synchronous`).Scan(&syncv); err != nil {
		db.Close()
		return nil, err
	}
	if mode != "wal" || syncv != 2 {
		db.Close()
		return nil, fmt.Errorf("rootd.db: journal_mode=%s synchronous=%d, need wal and FULL (2)", mode, syncv)
	}
	for _, schema := range []string{resolve.Schema, accounts.Schema, taskSchema, snapSchema, attach.Schema, attach.BaselineSchema} {
		if _, err := db.Exec(schema); err != nil {
			db.Close()
			return nil, err
		}
	}
	return db, nil
}

func lookupUID(name string) (uint32, bool) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseUint(u.Uid, 10, 32)
	return uint32(n), err == nil
}

func lookupGID(name string) (uint32, bool) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseUint(g.Gid, 10, 32)
	return uint32(n), err == nil
}

// approveNotAdmin is §2.1's start check: agentbox-approve is never a member of agentbox-admin.
func approveNotAdmin() error {
	u, err := user.Lookup("agentbox-approve")
	if err != nil {
		return nil // no approvald yet: nothing to check
	}
	g, ok := lookupGID("agentbox-admin")
	if !ok {
		return nil
	}
	ids, err := u.GroupIds()
	if err != nil {
		return fmt.Errorf("agentbox-approve's groups: %v", err)
	}
	if slices.Contains(ids, strconv.Itoa(int(g))) {
		return errors.New("agentbox-approve is a member of agentbox-admin: refusing to start (§2.1)")
	}
	return nil
}

// Run is agentbox-rootd.service (Type=notify): check, open the store, make the dst sets match it, serve the
// activated sockets, and only then send READY=1.
func Run(cfg Config) error {
	if err := ops.Check(cfg.GenDir); err != nil {
		return fmt.Errorf("op registry mismatch, refusing to start (§5.1): %v", err)
	}
	log.Printf("op registry matches %s: %d ops", cfg.GenDir, len(ops.Registry))
	if err := approveNotAdmin(); err != nil {
		return err
	}
	lns, err := listeners()
	if err != nil {
		return err
	}
	db, err := OpenDB(cfg.DB)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	da := newDenyAudit(func(r map[string]any) { sendDeny(cfg.AuditSocket, r) })
	go da.run(ctx)
	svc := &resolve.Service{
		DB: db, Dir: cfg.EgressDir, Resolver: resolve.Varlink{Path: resolve.ResolvedSocket},
		Route: nl.CheckRoute, Nft: resolve.Nft{Path: "nft"}, Flows: nl.DeleteFlows,
		Now: time.Now, Clock: fw.Clock, Timeout: cfg.ElementTimeout, Pref64: resolve.Networkd{Path: resolve.NetworkdSocket}.Pref64,
		Deny: func(svc, entry, reason, detail string) {
			log.Printf("DENY by=rootd svc=%s entry=%s code=%s detail=%q", svc, entry, reason, detail)
			if !da.deny(svc, entry, reason, detail) {
				log.Printf("DENY not audited: queue full")
			}
		},
	}
	if err := fw.RecordFixed(db); err != nil { // the fixed port_allow rows, before the refill puts them in the set
		return fmt.Errorf("port_allow rows: %v", err)
	}
	res, err := refill(db, svc)
	if err != nil {
		return fmt.Errorf("sets do not match rootd.db: %v", err)
	}
	log.Printf("sets match rootd.db: %d live elements re-added, %d revoked, %d expired, %d unknown removed",
		res.Added, res.Revoked, res.Expired, res.Extra)

	auid, aok := lookupUID("agentbox-audit")
	agid, gok := lookupGID("agentbox-audit")
	if !aok || !gok {
		return errors.New("no agentbox-audit user or group (sysusers.d/agentbox.conf)")
	}
	s := &server{cfg: cfg, db: db, svc: svc, seal: &audit.Files{Dir: cfg.AuditDir, UID: int(auid), GID: int(agid), Crash: cfg.SealCrash},
		audit: func(r map[string]any) error { return auditSend(cfg.AuditSocket, r) },
		store: accounts.EnsureStore, nested: nestedIn,
		applyOS:      func() error { _, err := quota.Run("systemctl", "start", accounts.Unit); return err },
		inconsistent: quota.Inconsistent, qrescan: quota.Rescan}
	if cfg.Tasks.Accounts == nil {
		cfg.Tasks.Accounts = idsAccounts{db}
	}
	if cfg.Tasks.EgressDir == "" {
		cfg.Tasks.EgressDir = cfg.EgressDir
	}
	if cfg.Tasks.Btrfs != nil {
		cfg.Tasks.Btrfs = checkedDelete{cfg.Tasks.Btrfs, s.checkQuota}
	}
	s.tasks = &tasks{cfg: cfg.Tasks, db: db, audit: s.audit, alert: cfg.Alert, nested: s.nested, query: func(r map[string]any) (*auditReply, error) { return auditQuery(cfg.AuditSocket, r) }}
	s.tasks.reopenWitnesses()
	s.tasks.resume()
	if s.cfg.Attach == nil {
		t := s.tasks.cfg
		s.cfg.Attach = attach.Podman{Seccomp: t.Seccomp, Image: t.Image, HostUsr: t.HostUsr, Ensure: func(agent string) error {
			a, err := t.Accounts.Lookup(agent)
			if err != nil {
				return err
			}
			return s.tasks.ensurePodman(a)
		}}
	}
	// the first qgroup check, before READY=1 so no writing op slips past it; a consistent one also thaws a freeze a dead
	// rootd left. A repair (a rescan can take minutes) runs after READY=1, with writing ops refused until it ends.
	s.fenced.Store(true)
	if bad, err := s.inconsistent(); err != nil || bad {
		go s.checkQuota()
	} else {
		s.checkQuota()
	}
	for name, ln := range lns {
		go s.accept(name, ln)
	}
	if err := notify("READY=1\nSTATUS=sets match rootd.db"); err != nil {
		return err
	}
	s.refresh(ctx) // ntfy_dst at start, then on the timer
	t := time.NewTicker(cfg.RefillInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			for _, ln := range lns {
				ln.Close()
			}
			return nil
		case <-t.C:
			if res, err := refill(db, svc); err != nil {
				log.Printf("timer refill: %v", err)
			} else if res != (resolve.RefillResult{Added: res.Added}) {
				log.Printf("timer refill: %+v", res)
			}
			s.refresh(ctx)
			go s.checkQuota()
		}
	}
}

// refill makes every set rootd fills match rootd.db: the exact sets (fw.Refill), then the dst sets.
func refill(db *sql.DB, svc *resolve.Service) (resolve.RefillResult, error) {
	if err := fw.Refill(db); err != nil {
		return resolve.RefillResult{}, fmt.Errorf("port_allow, allow_private4/6: %v", err)
	}
	return svc.Refill()
}

type server struct {
	cfg   Config
	tasks *tasks // nil: no task ops (tests)
	db    *sql.DB
	svc   *resolve.Service
	seal  audit.Sealer
	// audit sends one record to auditd's rootd producer socket and returns nil only on its ACK (auditSend)
	audit func(map[string]any) error

	agentMu sync.Mutex // one agent.add or agent.remove at a time
	store   func(accounts.Agent, uint64) error
	nested  func(subvol string) ([]string, error)
	// applyOS runs accounts.Reconcile in agentbox-accounts.service: rootd's ProtectSystem=strict keeps /etc read-only here
	applyOS func() error

	live sync.Map // agent -> session id of each running attach
	seen sync.Map // agent -> *attach.Seen: every session-home token version since rootd started, in memory only
	// watched is agent -> the session id whose every token version this rootd process saw: after a restart a rescan
	// can't match the versions the session rotated away, so it doesn't lift that block alone
	watched sync.Map

	// the qgroup fence (checkQuota); fenceMu also guards alerted
	fenced       atomic.Bool
	fenceMu      sync.Mutex
	alerted      bool
	inconsistent func() (bool, error)
	qrescan      func() error
}

// refresh re-resolves ntfy.sh:443 into ntfy_dst (§6.1). A failure only logs: ntfy is down until the next try.
func (s *server) refresh(ctx context.Context) {
	if _, _, err := s.svc.Resolve(ctx, "ntfy", "", resolve.NtfyEntry); err != nil {
		log.Printf("ntfy_dst refresh: %v", err)
	}
}

// auditQuery sends a taint.get and returns auditd's reply.
func auditQuery(sock string, rec map[string]any) (*auditReply, error) {
	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	b, _ := json.Marshal(rec)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var rep auditReply
	return &rep, json.Unmarshal(line, &rep)
}

// auditSend writes one record on auditd's rootd producer socket and waits for the reply: nil only on an ACK.
func auditSend(sock string, rec map[string]any) error {
	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	b, _ := json.Marshal(rec)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return err
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	var rep audit.Reply
	if err != nil || json.Unmarshal(line, &rep) != nil {
		return fmt.Errorf("no ACK: %v %s", err, bytes.TrimSpace(line))
	}
	if !rep.OK {
		return &auditNACK{rep.Code, rep.Detail}
	}
	return nil
}

// sendDeny is a best-effort DENY record (§9): a refusal is not an effect, so nothing waits on its ACK, and the journal
// line stays the fallback when auditd is down.
func sendDeny(sock string, rec map[string]any) {
	if err := auditSend(sock, rec); err != nil {
		log.Printf("DENY not audited: %v", err)
	}
}

// notify sends sd_notify state to $NOTIFY_SOCKET.
func notify(state string) error {
	p := os.Getenv("NOTIFY_SOCKET")
	if p == "" {
		return nil
	}
	if p[0] == '@' {
		p = "\x00" + p[1:]
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: p, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write([]byte(state))
	return err
}

type request struct {
	Op       string `json:"op"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Task     string `json:"task,omitempty"`
	Svc      string `json:"svc,omitempty"`
	Entry    string `json:"entry,omitempty"`
	Call     string `json:"call,omitempty"` // audit-seal.sock: auditd's audit.create or audit.seal
	Seg      uint64 `json:"seg,omitempty"`
	LastHash string `json:"last_hash,omitempty"`
	// rootd.sock task.op (§5.2): agentboxd names the task, agent and chain; args are the agent's, checked again here
	Name  string          `json:"name,omitempty"`
	Args  json.RawMessage `json:"args,omitempty"`
	Agent string          `json:"agent,omitempty"`
	Chain []string        `json:"chain,omitempty"`
	// task.start, task.stop and task.new (§4.2); agent.attach takes cli too
	Origin   string `json:"origin,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Probe    string `json:"probe,omitempty"` // gate task.stop: the isolation check a task failed (taskrun.ProbeChecks)
	Prompt   string `json:"prompt,omitempty"`
	CLI      string `json:"cli,omitempty"`
	Asks     *int   `json:"asks,omitempty"`
	Deadline string `json:"deadline,omitempty"` // a Go duration, at most 2h
	// rootd-admin.sock agent.attach (§4.2): name is the agent; the CLI's extra arguments, the terminal
	Workspace string   `json:"workspace,omitempty"`
	Argv      []string `json:"argv,omitempty"`
	Rows      int      `json:"rows,omitempty"`
	Cols      int      `json:"cols,omitempty"`
	Term      string   `json:"term,omitempty"`
	// agent.attach --ack-control-changes (§4.2); attach.rescan --ack-restart
	AckControlChanges bool `json:"ackControlChanges,omitempty"`
	AckRestart        bool `json:"ackRestart,omitempty"`
	// go.private.set (§5.3)
	Patterns *string `json:"patterns,omitempty"`
}

// peer is a connection's SO_PEERCRED uid and SO_PEERGROUPS groups.
type peer struct {
	uid    uint32
	groups []uint32
}

type reply map[string]any

func fail(reason string) reply { return reply{"ok": false, "reason": reason} }

func (s *server) handle(sock string, p peer, r request) reply {
	switch {
	case sock == sockSeal:
		err := fmt.Errorf("unknown call %q", r.Call)
		switch r.Call {
		case "audit.create":
			err = s.seal.Create(r.Seg)
		case "audit.seal":
			err = s.seal.Seal(r.Seg, r.LastHash)
		}
		if err != nil {
			log.Printf("audit seal: %s %d: %v", r.Call, r.Seg, err)
			return reply{"ok": false, "error": err.Error()}
		}
		return reply{"ok": true}
	case sock == sockAdmin:
		return s.admin(r, p)
	case sock == sockGate && r.Op == "task.op":
		return s.taskOp(r)
	case s.tasks == nil:
	case sock == sockGate && r.Op == "task.start":
		if rep := s.fenceDeny(r.Op); rep != nil {
			return rep
		}
		return s.tasks.start(r.Task, r.Agent, r.Origin)
	case sock == sockGate && r.Op == "task.stop":
		if r.Probe != "" {
			s.tasks.probeFailed(r.Task, r.Probe)
		}
		return s.tasks.stop(r.Task, r.Reason)
	case (sock == sockGate || strings.HasPrefix(sock, "resolve-")) && r.Op == "task.list_live":
		return s.tasks.listLive()
	case len(sock) > 8 && sock[:8] == "resolve-" && r.Op == "resolve":
		svc := sock[8:]
		e, err := resolve.ParseEntry(r.Host + ":" + strconv.Itoa(r.Port))
		if err != nil {
			return fail(resolve.NotAllowlisted) // a name no list can hold
		}
		addrs, exp, err := s.svc.Resolve(context.Background(), svc, r.Task, e)
		if err != nil {
			var rf *resolve.Refused
			if errors.As(err, &rf) {
				return fail(rf.Reason)
			}
			return fail(resolve.Unavailable)
		}
		out := make([]string, len(addrs))
		for i, a := range addrs {
			out[i] = a.String()
		}
		return reply{"ok": true, "addrs": out, "expires_at": exp.UnixMilli()}
	}
	return fail("bad_request")
}

func (s *server) admin(r request, p peer) reply {
	switch r.Op {
	case "task.new", "task.stop", "task.list", "task.undo":
		if s.tasks == nil {
			return fail("bad_request")
		}
		if rep := s.fenceDeny(r.Op); (r.Op == "task.new" || r.Op == "task.undo") && rep != nil {
			return rep
		}
		return s.taskAdmin(r, p)
	case "egress.allow", "egress.remove":
		e, err := resolve.ParseEntry(r.Entry)
		if err != nil {
			return reply{"ok": false, "error": err.Error()}
		}
		// §9: INTENT, its ACK, the effect, RESULT. auditd down means the list stays as it is.
		// shortcut: rootd logs the edit as an admin op itself; weeks 9-10's net.allow_domain flow replaces this.
		id := newDenyID()
		if err := s.audit(map[string]any{"type": "INTENT", "opId": id, "name": r.Op, "origin": "admin",
			"args": map[string]string{"svc": r.Svc, "entry": e.String()}}); err != nil {
			return reply{"ok": false, "error": "audit: the INTENT was not ACKed, nothing changed: " + err.Error()}
		}
		changed, err := resolve.EditList(s.cfg.EgressDir, r.Svc, e, r.Op == "egress.allow")
		status, detail := "executed", ""
		if err != nil {
			status, detail = "failed", err.Error()
		}
		aerr := s.audit(map[string]any{"type": "RESULT", "opId": id, "status": status, "detail": detail, "changed": changed})
		if err != nil {
			return reply{"ok": false, "error": err.Error()}
		}
		rep := s.refill(r) // even with no RESULT ACK: a removal must still revoke
		rep["changed"] = changed
		if aerr != nil {
			log.Printf("%s %s %s: RESULT not audited: %v", r.Op, r.Svc, r.Entry, aerr)
			rep["ok"], rep["error"] = false, "the list changed, but its audit RESULT was not ACKed: "+aerr.Error()
		}
		return rep
	case "agent.add", "agent.remove":
		return s.agentOp(r)
	case "agent.list":
		all, err := accounts.List(s.db)
		if err != nil {
			return reply{"ok": false, "error": err.Error()}
		}
		return reply{"ok": true, "agents": all}
	case "go.private.set":
		return s.goPrivateSet(r)
	case "sets.refill":
		return s.refill(r)
	case "quota.check":
		fenced, err := s.checkQuota()
		if err != nil {
			return reply{"ok": false, "fenced": fenced, "error": err.Error()}
		}
		return reply{"ok": true, "fenced": fenced}
	case "attach.status":
		l, err := attach.List(s.db)
		if err != nil {
			return reply{"ok": false, "error": err.Error()}
		}
		return reply{"ok": true, "blocks": l}
	case "attach.rescan":
		return s.rescan(r.Name, r.AckRestart)
	case "egress.list":
		l, err := resolve.LoadLists(s.cfg.EgressDir)
		if err != nil {
			return reply{"ok": false, "error": err.Error()}
		}
		ans, err := s.svc.Entries()
		if err != nil {
			return reply{"ok": false, "error": err.Error()}
		}
		return reply{"ok": true, "lists": l, "answers": ans}
	}
	return fail("bad_request")
}

// refill is the notify path: an allowlist change or an admin refill runs it at once, not at the next timer tick.
func (s *server) refill(r request) reply {
	res, err := refill(s.db, s.svc)
	if err != nil {
		return reply{"ok": false, "error": err.Error()}
	}
	log.Printf("%s %s %s: %+v", r.Op, r.Svc, r.Entry, res)
	return reply{"ok": true, "refill": res}
}

// line answers one request line from socket name with one reply line.
func (s *server) line(name string, b []byte) []byte { return s.lineFrom(name, peer{}, b) }

func (s *server) lineFrom(name string, p peer, b []byte) []byte {
	var r request
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	rep := fail("bad_request")
	if dec.Decode(&r) == nil {
		rep = s.handle(name, p, r)
	}
	return encode(rep)
}

// taskAdmin is the human side (§4.2): `agentbox task new` records a request and passes it to agentboxd, which starts
// it through task.start; `agentbox task stop` is task.stop with reason canceled.
func (s *server) taskAdmin(r request, p peer) reply {
	switch r.Op {
	case "task.list":
		return s.tasks.list()
	case "task.stop":
		if r.Reason == "" {
			r.Reason = "canceled"
		}
		return s.tasks.stop(r.Task, r.Reason)
	}
	human := "root"
	if u, err := user.LookupId(strconv.Itoa(int(p.uid))); err == nil {
		human = u.Username
	}
	if r.Op == "task.undo" {
		return s.tasks.undo(r.Task, "rootd-admin:"+human)
	}
	asks, dl := DefaultAsks, DefaultDeadline
	if r.Asks != nil {
		asks = *r.Asks
	}
	if r.Deadline != "" {
		d, err := time.ParseDuration(r.Deadline)
		if err != nil {
			return reply{"ok": false, "error": "--deadline: " + err.Error()}
		}
		dl = d
	}
	req, err := s.tasks.newRequest(human, r.Agent, asks, dl)
	if err != nil {
		return reply{"ok": false, "error": err.Error()}
	}
	rep, err := s.tasks.cfg.Svc("gate", map[string]any{"call": "dispatch", "request": req, "agent": r.Agent, "cli": r.CLI, "prompt": r.Prompt})
	if err != nil {
		return reply{"ok": false, "request": req, "error": "agentboxd: " + err.Error()}
	}
	rep["request"] = req
	return reply(rep)
}

func encode(r reply) []byte { b, _ := json.Marshal(r); return append(b, '\n') }
