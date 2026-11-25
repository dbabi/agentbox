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
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"agentbox/internal/denial"
	"agentbox/internal/ids"
	"agentbox/internal/rootd/accounts"
	"agentbox/internal/rootd/attach"
	"agentbox/internal/rootd/witness"
	"agentbox/internal/seccomp"
	"agentbox/internal/secrets"
	"agentbox/internal/task"
	"agentbox/internal/taskenv"
	"agentbox/internal/taskrun"
)

// The task registry (Appendix E) and the human requests behind admin-origin tasks. task_requests is not in Appendix E:
// §4.2 has rootd record each `agentbox task new` request, its human and its agent, and start it once.
const taskSchema = `
CREATE TABLE IF NOT EXISTS task_registry(task TEXT PRIMARY KEY, parent TEXT, agent TEXT NOT NULL, uid INTEGER NOT NULL, chain TEXT NOT NULL CHECK(json_valid(chain)),
                           origin TEXT NOT NULL, trace TEXT NOT NULL, deadline INTEGER NOT NULL, started_at INTEGER, ended_at INTEGER,
                           end_reason TEXT CHECK(end_reason IN ('completed','failed','canceled','timeout','deadline','parent_stopped')),
                           asks_budget INTEGER NOT NULL CHECK(asks_budget BETWEEN 0 AND 10),
                           asks_used INTEGER NOT NULL DEFAULT 0, asks_granted INTEGER NOT NULL DEFAULT 0,
                           asks_created INTEGER NOT NULL DEFAULT 0,
                           quote_items INTEGER NOT NULL DEFAULT 0 CHECK(quote_items >= 0), quote_deny INTEGER NOT NULL DEFAULT 0,
                           CHECK(asks_used + asks_granted <= asks_budget)) STRICT;
CREATE INDEX IF NOT EXISTS task_registry_parent ON task_registry(parent, ended_at);
CREATE TABLE IF NOT EXISTS delegations(task TEXT PRIMARY KEY, parent TEXT NOT NULL, executor TEXT NOT NULL, allowed_transitions TEXT NOT NULL CHECK(json_valid(allowed_transitions)),
                         expires_at INTEGER NOT NULL, version INTEGER NOT NULL, asks INTEGER NOT NULL DEFAULT 0) STRICT;
CREATE TABLE IF NOT EXISTS task_requests(id TEXT PRIMARY KEY, human TEXT NOT NULL, agent TEXT NOT NULL,
                           asks INTEGER NOT NULL CHECK(asks BETWEEN 0 AND 10), deadline INTEGER NOT NULL, created_at INTEGER NOT NULL, task TEXT UNIQUE) STRICT;
`

// Account is an agent's Unix account (ARCHITECTURE.md §4.1).
type Account struct {
	Name      string // the agent; the user is ag-<name>
	UID, GID  uint32
	SubID     uint32 // the first of its 65536 sub-ids
	Workspace string // data/workspaces/<name>, mounted rw at /workspace
	Snaps     string // data/agents/<name>/snapshots: its workspace snapshots, root-only
	Home, XDG string // the root-owned home and XDG base dirs its podman runs with
}

// Accounts resolves an agent to its account.
type Accounts interface {
	Lookup(agent string) (Account, error)
}

// idsAccounts is the active agents in rootd's ids table (§4.1).
type idsAccounts struct{ db *sql.DB }

func (i idsAccounts) Lookup(agent string) (Account, error) {
	if !accounts.ValidName(agent) {
		return Account{}, errors.New("bad agent name")
	}
	a, err := accounts.Lookup(i.db, agent)
	if err != nil {
		return Account{}, err
	}
	return Account{Name: a.Name, UID: uint32(a.UID()), GID: uint32(a.UID()), SubID: uint32(a.SubID()), Workspace: a.Workspace(), Snaps: a.Dir() + "/snapshots", Home: a.Home(), XDG: a.XDG()}, nil
}

func (a Account) podmanEnv() []string {
	return []string{"HOME=" + a.Home, "XDG_RUNTIME_DIR=/run/user/" + strconv.Itoa(int(a.UID)), "XDG_CONFIG_HOME=" + a.XDG + "/config", "XDG_DATA_HOME=" + a.XDG + "/data",
		"CONTAINERS_STORAGE_CONF=" + a.XDG + "/config/containers/storage.conf"}
}

// TaskConfig is what task.start and task.stop act through; tests replace every function.
type TaskConfig struct {
	Accounts Accounts // nil: rootd's ids table
	// Pause is checkPause before every launch and attach; nil skips it.
	Pause func(Account) (string, error)
	// EnsureImage makes sure the agent's podman has the task image; setup says its pause process is not live in its
	// user manager, so a podman call must run there first. nil skips it.
	EnsureImage func(a Account, setup bool) error
	// Launch runs the task's one systemd-run (task.Argv) and returns when the unit has started.
	Launch func(argv []string) error
	// RunAs runs a command as uid outside the bridge (the task.stop podman rm backup).
	RunAs func(uid uint32, env []string, argv ...string) error
	// Svc sends one call to /run/agentbox-rootd/svc-<svc>.sock and returns the reply; ErrNoSvc if that service has no
	// socket (proxy, keys and git until weeks 7-8).
	Svc func(svc string, req map[string]any) (map[string]any, error)
	// MakeDir makes one per-task dir: mkdirat, fchownat (no symlink follow) to owner:gid, mode 2750 (§2.1).
	MakeDir     func(path, owner string, gid uint32) error
	Cgroup      string // the cgroup2 root, /sys/fs/cgroup
	Exports     string // control/exports
	EgressDir   string // control/egress: the allowlists and go.private patterns the task env comes from; rootd's own if ""
	WitnessRoot string // /run/agentbox-witness/t (§5.6 Witness)
	Btrfs       Btrfs  // the task-start snapshot and undo; nil: none (tests)
	// SecretScan runs the offline credential scan of a workspace (#104); nil: none (tests)
	SecretScan func(Account) ([]secrets.Hit, error)
	Seccomp    string
	Image      string
	HostUsr    []string
	Now        func() time.Time
}

type tasks struct {
	cfg     TaskConfig
	db      *sql.DB
	audit   func(map[string]any) error // waits for the ACK
	query   func(map[string]any) (*auditReply, error)
	alert   func(title, msg string) error // queues an ntfy alert (Config.Alert); nil: none
	mu      sync.Mutex
	stops   map[string]*sync.Mutex // one task.stop at a time per task
	watch   map[string]bool
	noWatch bool // tests: no cgroup to watch
	nested  func(string) ([]string, error)
	fenced  func() bool // the qgroup fence (fence.go); nil: none
	witMu   sync.Mutex
	wit     map[string]*witness.W // the live tasks' witnesses, by task id
	scans   sync.Map              // workspace subject -> *sync.Mutex: one credential scan at a time per workspace
}

type auditReply struct {
	OK   bool `json:"ok"`
	View *struct {
		Subjects []taintSubject `json:"subjects"`
	} `json:"view"`
}

type taintSubject struct {
	Subject string `json:"subject"`
	Tainted bool   `json:"tainted"`
	Epoch   int64  `json:"epoch"`
}

var errSnapshot = errors.New("task-start snapshot")

// errFenced is a task-start snapshot that raised the qgroup fence: the task never runs (#205).
var errFenced = errors.New("the task-start snapshot made qgroups inconsistent")

// ErrNoSvc is a service with no svc-<svc>.sock on this box.
var ErrNoSvc = errors.New("service not installed")

var endReasons = map[string]bool{"completed": true, "failed": true, "canceled": true, "timeout": true, "deadline": true, "parent_stopped": true}

// Defaults (§4.2): a top-level task has 2 h, an admin task 3 asks, a daemon task 1.
const (
	DefaultDeadline = 2 * time.Hour
	DefaultAsks     = 3
	minDeadline     = 10 * time.Second
)

func (t *tasks) now() int64 { return t.cfg.Now().UnixMilli() }

// newRequest records a human's `agentbox task new` (rootd-admin.sock) and returns its id.
func (t *tasks) newRequest(human, agent string, asks int, deadline time.Duration) (string, error) {
	if _, err := t.cfg.Accounts.Lookup(agent); err != nil {
		return "", fmt.Errorf("agent %s: %v", agent, err)
	}
	if asks < 0 || asks > 10 {
		return "", errors.New("--asks must be 0 to 10")
	}
	if deadline < minDeadline || deadline > DefaultDeadline {
		return "", errors.New("--deadline must be 10s to 2h")
	}
	id := denial.NewID("req")
	_, err := t.db.Exec(`INSERT INTO task_requests(id, human, agent, asks, deadline, created_at) VALUES(?,?,?,?,?,?)`,
		id, human, agent, asks, t.now()+deadline.Milliseconds(), t.now())
	return id, err
}

type startInfo struct {
	parent         sql.NullString
	chain          []string
	trace          string
	deadline       int64
	asks           int
	taint          bool
	source, origin string
	request        string // admin:<request>: used up in the transaction that registers the task
}

// start is task.start{task, agent, origin} from agentboxd (§4.2): rootd derives the provenance, registers the task, makes
// its socket dirs and launches its container. agentboxd supplies no chain, trace or taint.
func (t *tasks) start(id, agent, origin string) reply {
	if !ids.Is(ids.Task, id) {
		return fail("bad_task_id")
	}
	acct, err := t.cfg.Accounts.Lookup(agent)
	if err != nil {
		log.Printf("task.start %s: agent %s: %v", id, agent, err)
		return fail("no_agent")
	}
	si, why := t.provenance(id, agent, origin)
	if why == "" {
		if rep := t.secretGate(acct, 0); rep != nil {
			log.Printf("task.start %s: %s: %v", id, rep["reason"], rep["error"])
			return rep
		}
	}
	// held from the registry row through the launch: a task.stop that finds the row waits, then kills what started
	m := t.stopLock(id)
	m.Lock()
	if why == "" {
		why = t.register(id, acct, si)
	}
	if why != "" {
		m.Unlock()
		log.Printf("task.start %s: %s", id, why)
		return fail(why)
	}
	tainted, err := t.launch(id, acct, si)
	m.Unlock()
	if err != nil {
		log.Printf("task.start %s: %v; stopping it", id, err)
		t.stop(id, "failed")
		if errors.Is(err, errFenced) {
			return fenceReply("task.start")
		}
		reason := "launch_failed"
		if errors.Is(err, errSnapshot) {
			reason = "snapshot_failed"
		} else if strings.Contains(err.Error(), "cannot set user namespace") {
			reason = "podman_userns" // podman joined a process that is not its pause process (#125)
		}
		return reply{"ok": false, "reason": reason, "error": err.Error()}
	}
	return reply{"ok": true, "task": id, "unit": task.Unit(id), "chain": si.chain, "trace": si.trace, "tainted": tainted}
}

// register is one transaction: the agent's task block (an attach holds the workspace until its token scan is clean, and
// a task that left processes holds it until they are gone, §4.2; an unreadable block refuses too), the human request
// used up, and the registry row. attach.Begin refuses while that row is live, so an attach and a task never overlap.
func (t *tasks) register(id string, acct Account, si startInfo) string {
	tx, err := t.db.Begin()
	if err != nil {
		return "registry"
	}
	defer tx.Rollback()
	if b, on, err := attach.Blocked(tx, acct.Name); on || err != nil {
		log.Printf("task.start %s: agent %s: block %s %v", id, acct.Name, b.Reason, err)
		if b.Reason == attach.TaskNotEmpty {
			return "agent_blocked"
		}
		return "attach_blocked"
	}
	if si.request != "" {
		res, err := tx.Exec(`UPDATE task_requests SET task=? WHERE id=? AND task IS NULL`, id, si.request)
		if err != nil {
			return "no_unused_request" // the task id already used up another request (task UNIQUE)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return "no_unused_request"
		}
	}
	chain, _ := json.Marshal(si.chain)
	if _, err := tx.Exec(`INSERT INTO task_registry(task, parent, agent, uid, chain, origin, trace, deadline, started_at, asks_budget)
		VALUES(?,?,?,?,?,?,?,?,?,?)`, id, si.parent, acct.Name, acct.UID, string(chain), si.origin, si.trace, si.deadline, t.now(), si.asks); err != nil {
		log.Printf("task.start %s: registry: %v", id, err)
		return "registry"
	}
	if err := tx.Commit(); err != nil {
		return "registry"
	}
	return ""
}

// provenance checks origin and derives chain, trace, deadline, ask budget and taint (§4.2). A non-empty string refuses.
func (t *tasks) provenance(id, agent, origin string) (startInfo, string) {
	now := t.now()
	si := startInfo{origin: origin}
	switch {
	case origin == "daemon":
		// no parent and no human request: registered tainted, so every non-read, non-Safe op needs a signature
		si.chain, si.trace, si.deadline, si.asks = []string{"agent:" + agent}, denial.NewID("trace"), now+DefaultDeadline.Milliseconds(), 1
		si.taint, si.source = true, "origin:daemon"
	case strings.HasPrefix(origin, "admin:"):
		req := origin[6:]
		var human, ragent string
		var asks int
		var dl int64
		err := t.db.QueryRow(`SELECT human, agent, asks, deadline FROM task_requests WHERE id=? AND task IS NULL`, req).Scan(&human, &ragent, &asks, &dl)
		if err != nil || ragent != agent {
			return si, "no_unused_request"
		}
		si.request = req
		si.chain, si.trace, si.deadline, si.asks = []string{"human:" + human, "agent:" + agent}, denial.NewID("trace"), dl, asks
	case strings.HasPrefix(origin, "parent:"):
		p := origin[7:]
		var pchain, ptrace string
		var pdl int64
		var ended sql.NullInt64
		if err := t.db.QueryRow(`SELECT chain, trace, deadline, ended_at FROM task_registry WHERE task=?`, p).Scan(&pchain, &ptrace, &pdl, &ended); err != nil {
			return si, "no_parent"
		}
		if ended.Valid {
			return si, "parent_ended"
		}
		var asks int
		if err := t.db.QueryRow(`SELECT asks FROM delegations WHERE task=? AND parent=? AND executor=? AND expires_at > ?`, id, p, agent, now).Scan(&asks); err != nil {
			return si, "no_delegation"
		}
		json.Unmarshal([]byte(pchain), &si.chain)
		si.chain = append(si.chain, "agent:"+agent)
		si.parent = sql.NullString{String: p, Valid: true}
		si.trace, si.deadline, si.asks = ptrace, pdl, asks
		// taint(child) := the parent's effective taint, registered with auditd before the child runs
		rep, err := t.query(map[string]any{"type": "taint.get", "holder": "task:" + p})
		if err != nil || !rep.OK || rep.View == nil {
			return si, "audit_unavailable"
		}
		for _, s := range rep.View.Subjects {
			si.taint = si.taint || s.Tainted
		}
		si.source = "parent:" + p
	default:
		return si, "bad_origin"
	}
	if si.deadline <= now+minDeadline.Milliseconds()/2 {
		return si, "deadline_passed"
	}
	return si, ""
}

// launch is §4.2 Dispatch steps 1-3: auditd learns the writer and any start taint (ACKed), rootd makes the socket dirs
// and has each service bind there, then the one launch over the agent's user bus. It reports whether the task starts
// tainted: by its origin, or by live workspace taint (a tainted workspace taints every task that mounts it, §5.2).
func (t *tasks) launch(id string, acct Account, si startInfo) (bool, error) {
	if err := t.audit(map[string]any{"type": "WRITER_ADD", "holder": "task:" + id, "workspace": accounts.WorkspaceSubject(acct.Name, int(acct.UID))}); err != nil {
		return false, fmt.Errorf("auditd WRITER_ADD: %v", err)
	}
	if si.taint {
		if err := t.audit(map[string]any{"type": "TAINT", "subject": "task:" + id, "source": si.source}); err != nil {
			return false, fmt.Errorf("auditd TAINT: %v", err)
		}
	}
	tainted := si.taint
	if rep, err := t.query(map[string]any{"type": "taint.get", "holder": "task:" + id}); err == nil && rep.OK && rep.View != nil {
		for _, s := range rep.View.Subjects {
			tainted = tainted || s.Tainted
		}
	}
	if t.cfg.Btrfs != nil {
		// before anything of the task runs: `agentbox task undo` restores this tree (#103)
		if _, err := t.snapshot(acct, "task:"+id, id, "task-start"); err != nil {
			return false, fmt.Errorf("%w: %v", errSnapshot, err)
		}
		defer t.prune(acct)
		if t.fenced != nil && t.fenced() {
			return false, errFenced
		}
	}
	for _, v := range task.Svcs {
		if err := t.cfg.MakeDir(task.SockDir(v.Name, id), task.SvcUser[v.Name], acct.GID); err != nil {
			return false, fmt.Errorf("%s: %v", task.SockDir(v.Name, id), err)
		}
		rep, err := t.cfg.Svc(v.Name, map[string]any{"call": "register", "task": id, "agent": acct.Name, "chain": si.chain})
		if errors.Is(err, ErrNoSvc) && v.Name != "gate" {
			continue // the dir is still made and mounted, so the service can bind there once it is installed
		}
		if err == nil && rep["ok"] != true {
			err = fmt.Errorf("refused: %v", rep["error"])
		}
		if err != nil {
			return false, fmt.Errorf("%s register: %v", v.Name, err)
		}
	}
	env, err := taskenv.ForAgent(t.cfg.EgressDir, acct.Name)
	if err != nil {
		return false, fmt.Errorf("task env: %v", err)
	}
	if err := t.openWitness(id, acct.GID); err != nil {
		return false, fmt.Errorf("witness: %v", err)
	}
	if err := task.WriteExports(filepath.Join(t.cfg.Exports, acct.Name)); err != nil {
		return false, fmt.Errorf("exports: %v", err)
	}
	if err := t.ensurePodman(acct); err != nil {
		return false, err
	}
	dl := time.UnixMilli(si.deadline)
	argv := task.Argv(task.Spec{Task: id, Agent: acct.Name, Runtime: dl.Sub(t.cfg.Now()), Deadline: dl, Workspace: acct.Workspace,
		Seccomp: t.cfg.Seccomp, Image: t.cfg.Image, HostUsr: t.cfg.HostUsr, Env: env, Witness: filepath.Join(t.cfg.WitnessRoot, id)})
	t0 := time.Now()
	err = t.cfg.Launch(argv)
	log.Printf("task %s (agent %s): launch %d ms over the user bus: %v", id, acct.Name, time.Since(t0).Milliseconds(), err)
	if err != nil {
		return false, fmt.Errorf("systemd-run: %v", err)
	}
	t.watchTask(id, acct.UID, si.deadline)
	return tainted, nil
}

// probeFailed records a task whose isolation probe found a way out (taskrun.Probe): an ALERT to auditd and ntfy. The
// check name comes from the task, so only a known one is passed on.
func (t *tasks) probeFailed(id, check string) {
	if !slices.Contains(taskrun.ProbeChecks, check) {
		check = "unknown"
	}
	var agent string
	t.db.QueryRow(`SELECT agent FROM task_registry WHERE task=?`, id).Scan(&agent)
	msg := fmt.Sprintf("task %s (agent %s): %s: the %s check failed inside the task; it stopped before the CLI started", id, agent, taskrun.ProbeFailed, check)
	log.Printf("ALERT %s", msg)
	go t.audit(map[string]any{"type": "ALERT", "reason": taskrun.ProbeFailed, "task": id, "check": check})
	if t.alert != nil {
		if err := t.alert("agentbox: task "+agent, msg); err != nil {
			log.Printf("alert not queued: %v", err)
		}
	}
}

// stopLock is id's task.stop mutex: one stop at a time, and none while task.start is between register and launch's end.
func (t *tasks) stopLock(id string) *sync.Mutex {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stops == nil {
		t.stops = map[string]*sync.Mutex{}
	}
	m := t.stops[id]
	if m == nil {
		m = &sync.Mutex{}
		t.stops[id] = m
	}
	return m
}

// stop is task.stop{task, reason} (§4.2), each step idempotent and none waiting for auditd.
func (t *tasks) stop(id, reason string) reply {
	if !endReasons[reason] || !ids.Is(ids.Task, id) {
		return fail("bad_request")
	}
	var agent string
	var uid uint32
	if err := t.db.QueryRow(`SELECT agent, uid FROM task_registry WHERE task=?`, id).Scan(&agent, &uid); err != nil {
		return fail("no_task")
	}
	m := t.stopLock(id)
	m.Lock()
	defer m.Unlock()
	t0 := time.Now()
	cg := filepath.Join(t.cfg.Cgroup, task.CgroupDir(uid, id))
	// 1-2: cgroup.kill is recursive, so it reaches the payload sub-cgroup; then wait for it to be empty
	if err := os.WriteFile(filepath.Join(cg, "cgroup.kill"), []byte("1"), 0); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("task %s: cgroup.kill: %v", id, err)
	}
	empty := false
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if !populated(cg) {
			empty = true
			break
		}
	}
	if !empty {
		// in rootd.db at once, so a restart keeps it; step 5 writes it again with ended_at. attach.rescan lifts it once
		// this cgroup is empty.
		if err := attach.BlockTask(t.db, agent, id, t.cfg.Now()); err != nil {
			log.Printf("task %s: block agent %s: %v", id, agent, err)
		}
		msg := fmt.Sprintf("task %s: its cgroup is not empty 10 s after cgroup.kill: agent %s gets no more tasks (agentbox attach status)", id, agent)
		log.Printf("ALERT %s", msg)
		go t.audit(map[string]any{"type": "ALERT", "reason": "task_not_empty", "task": id})
		if t.alert != nil {
			if err := t.alert("agentbox: task "+agent, msg); err != nil {
				log.Printf("alert not queued: %v", err)
			}
		}
	}
	// 2a: with no writer left, the witness holds every line the task wrote; WITNESS goes to auditd unwaited
	t.closeWitness(id)
	// 3: the unit's ExecStopPost already removes the container; this is its backup, outside the user bus
	acct, err := t.cfg.Accounts.Lookup(agent)
	if err == nil {
		if err := t.cfg.RunAs(acct.UID, acct.podmanEnv(), task.Podman, "rm", "-f", "-i", "-t", "0", task.Container(id)); err != nil {
			log.Printf("task %s: podman rm: %v", id, err)
		}
	}
	// 4: revoke the sockets, then remove the dirs
	for _, v := range task.Svcs {
		if _, err := t.cfg.Svc(v.Name, map[string]any{"call": "revoke", "task": id}); err != nil && !errors.Is(err, ErrNoSvc) {
			log.Printf("task %s: %s revoke: %v", id, v.Name, err)
		}
		if err := os.RemoveAll(task.SockDir(v.Name, id)); err != nil {
			log.Printf("task %s: %v", id, err)
		}
	}
	// 5: the registry and the task's own delegations; 6 (pending rows) comes with the pending table in weeks 9-10
	n, err := t.end(id, agent, reason, !empty)
	if err != nil {
		// the row stays live: no attach starts, and a task.stop again (or resume after a restart) finishes the stop
		log.Printf("task %s: registry: %v", id, err)
		return reply{"ok": false, "reason": "registry", "task": id, "empty": empty}
	}
	go t.audit(map[string]any{"type": "WRITER_DEL", "holder": "task:" + id}) // never waited for (§4.2)
	if n == 1 {
		log.Printf("task %s stopped (%s) in %d ms", id, reason, time.Since(t0).Milliseconds())
	}
	// 7: children
	rows, err := t.db.Query(`SELECT task FROM task_registry WHERE parent=? AND ended_at IS NULL`, id)
	if err == nil {
		var kids []string
		for rows.Next() {
			var k string
			if rows.Scan(&k) == nil {
				kids = append(kids, k)
			}
		}
		rows.Close()
		for _, k := range kids {
			t.stop(k, "parent_stopped")
		}
	}
	return reply{"ok": true, "task": id, "stopped": n == 1, "empty": empty}
}

// end is stop step 5 in one transaction: a leftover task's block, ended_at, and the task's delegations expired. It
// reports whether this call ended the row.
func (t *tasks) end(id, agent, reason string, leftover bool) (int64, error) {
	tx, err := t.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now := t.now()
	if leftover {
		if err := attach.BlockTask(tx, agent, id, t.cfg.Now()); err != nil {
			return 0, err
		}
	}
	res, err := tx.Exec(`UPDATE task_registry SET ended_at=?, end_reason=? WHERE task=? AND ended_at IS NULL`, now, reason, id)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`UPDATE delegations SET expires_at=? WHERE parent=? AND expires_at > ?`, now, id, now); err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// liveRow is one task_registry row with ended_at IS NULL.
type liveRow struct {
	Task  string   `json:"task"`
	Agent string   `json:"agent"`
	Chain []string `json:"chain"`
	uid   uint32
	dl    int64
}

func (t *tasks) live() ([]liveRow, error) {
	rows, err := t.db.Query(`SELECT task, agent, chain, uid, deadline FROM task_registry WHERE ended_at IS NULL ORDER BY task`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []liveRow{}
	for rows.Next() {
		var r liveRow
		var c string
		if err := rows.Scan(&r.Task, &r.Agent, &c, &r.uid, &r.dl); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(c), &r.Chain)
		out = append(out, r)
	}
	return out, rows.Err()
}

// listLive answers task.list_live (§2.1): a restarted service rebinds these tasks' sockets.
func (t *tasks) listLive() reply {
	l, err := t.live()
	if err != nil {
		return fail("registry")
	}
	return reply{"ok": true, "tasks": l}
}

// list answers `agentbox task list` (admin).
func (t *tasks) list() reply {
	rows, err := t.db.Query(`SELECT task, agent, origin, chain, deadline, started_at, ended_at, end_reason FROM task_registry ORDER BY started_at`)
	if err != nil {
		return fail("registry")
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, agent, origin, chain string
		var dl int64
		var st, en sql.NullInt64
		var why sql.NullString
		if rows.Scan(&id, &agent, &origin, &chain, &dl, &st, &en, &why) != nil {
			continue
		}
		r := map[string]any{"task": id, "agent": agent, "origin": origin, "chain": json.RawMessage(chain), "deadline": dl, "started_at": st.Int64}
		if en.Valid {
			r["ended_at"], r["end_reason"] = en.Int64, why.String
		}
		out = append(out, r)
	}
	return reply{"ok": true, "tasks": out}
}

// resume watches every live task again after a rootd restart; a task whose cgroup is gone is stopped as failed.
func (t *tasks) resume() {
	l, err := t.live()
	if err != nil {
		log.Printf("task registry: %v", err)
		return
	}
	for _, r := range l {
		t.watchTask(r.Task, r.uid, r.dl)
	}
}

// watchTask stops the task when its unit's cgroup empties (the task exited, or RuntimeMaxSec stopped it) and, as a
// backstop, at the deadline plus TimeoutStopSec.
func (t *tasks) watchTask(id string, uid uint32, deadline int64) {
	if t.noWatch {
		return
	}
	t.mu.Lock()
	if t.watch == nil {
		t.watch = map[string]bool{}
	}
	if t.watch[id] {
		t.mu.Unlock()
		return
	}
	t.watch[id] = true
	t.mu.Unlock()
	go func() {
		defer func() { t.mu.Lock(); delete(t.watch, id); t.mu.Unlock() }()
		cg := filepath.Join(t.cfg.Cgroup, task.CgroupDir(uid, id))
		backstop := time.UnixMilli(deadline).Add(task.StopTimeout + 5*time.Second)
		reason := waitEmpty(cg, backstop)
		if reason == "" {
			reason = "failed"
			if t.cfg.Now().UnixMilli() >= deadline-1000 {
				reason = "timeout"
			}
		}
		t.stop(id, reason)
	}()
}

// DefaultTaskConfig is the box's: systemd-run, the svc-<svc>.sock sockets, cgroup2 at /sys/fs/cgroup.
func DefaultTaskConfig() TaskConfig {
	return TaskConfig{
		Pause:       func(a Account) (string, error) { return checkPause("/run/user", "/proc", a) },
		EnsureImage: ensureImage,
		Launch:      func(argv []string) error { return runFor(30*time.Second, argv...) },
		RunAs: func(uid uint32, env []string, argv ...string) error {
			// a system unit as the agent uid: no login session, and podman's pause process ends with the unit
			a := []string{"systemd-run", "--uid=" + strconv.Itoa(int(uid)), "--wait", "--collect", "--quiet", "-p", "TimeoutStartSec=4"}
			for _, e := range env {
				a = append(a, "-E", e)
			}
			return runFor(5*time.Second, append(a, argv...)...)
		},
		Svc:         svcCall,
		MakeDir:     makeTaskDir,
		Btrfs:       btrfsCmd{},
		SecretScan:  runSecretScan(filepath.Dir(task.ExportsDir)),
		Cgroup:      "/sys/fs/cgroup",
		Exports:     task.ExportsDir,
		WitnessRoot: witness.Root,
		Seccomp:     seccomp.Path,
		Image:       task.Image(),
		HostUsr:     task.HostUsr(),
		Now:         time.Now,
	}
}

func runFor(d time.Duration, argv ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// svcLine is req as one line with no HTML escaping: json.Marshal would turn each <, > and & of a dispatch prompt into
// 6 bytes, so a prompt within gate.MaxPrompt could pass svc-gate.sock's line limit.
func svcLine(req map[string]any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.Encode(req) // Encode ends the line with '\n'
	return b.Bytes()
}

// svcCall sends one line to svc-<svc>.sock (uid 0 only, §2.1) and decodes the reply.
func svcCall(svc string, req map[string]any) (map[string]any, error) {
	p := "/run/agentbox-rootd/svc-" + svc + ".sock"
	if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoSvc
	}
	c, err := net.DialTimeout("unix", p, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second)) // dispatch waits for task.start
	if _, err := c.Write(svcLine(req)); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("no reply: %v", err)
	}
	var rep map[string]any
	return rep, json.Unmarshal(line, &rep)
}

// ensurePodman runs before every launch and attach: a stale pause.pid is removed and audited, and unless the pause
// process is live in the agent's user manager, a podman call there makes one (§4.2).
func (t *tasks) ensurePodman(a Account) error {
	setup := false
	if t.cfg.Pause != nil {
		why, err := t.cfg.Pause(a)
		if err != nil {
			return err
		}
		if why != "" && why != PauseAbsent {
			log.Printf("agent %s: stale pause.pid (%s) removed", a.Name, why)
			if err := t.audit(map[string]any{"type": "PAUSE_PID_STALE", "agent": a.Name, "reason": why}); err != nil {
				log.Printf("agent %s: PAUSE_PID_STALE not audited: %v", a.Name, err)
			}
		}
		setup = why != ""
	}
	if t.cfg.EnsureImage == nil {
		return nil
	}
	if err := t.cfg.EnsureImage(a, setup); err != nil {
		return fmt.Errorf("task image: %v", err)
	}
	return nil
}

var imported sync.Map // uid: the agent's podman has task.Image()

// ensureImage imports the stub task image into the agent's podman once per uid, through its user manager so podman's
// pause process lands there (§4.2); with setup, it calls podman there again even if the image is in.
func ensureImage(a Account, setup bool) error {
	if _, ok := imported.Load(a.UID); ok && !setup {
		return nil
	}
	sk := task.Skeleton()
	if b, err := os.ReadFile(task.ImageTar); err != nil || !bytes.Equal(b, sk) {
		if err := os.WriteFile(task.ImageTar, sk, 0o644); err != nil {
			return err
		}
	}
	if err := os.Chmod(task.ImageTar, 0o644); err != nil { // rootd's UMask=0077; the agent's podman reads it
		return err
	}
	user := []string{"systemd-run", "--user", "-M", "ag-" + a.Name + "@", "--wait", "--quiet", "--collect", task.Podman}
	if runFor(30*time.Second, append(user, "image", "exists", task.Image())...) != nil {
		if err := runFor(60*time.Second, append(user, "import", task.ImageTar, task.Image())...); err != nil {
			return err
		}
	}
	imported.Store(a.UID, true)
	return nil
}
