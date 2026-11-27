package rootd

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"agentbox/internal/ids"
	"agentbox/internal/ops"
	"agentbox/internal/rootd/accounts"
	"agentbox/internal/rootd/attach"
	"agentbox/internal/task"
)

type fakeAccounts struct{}

func (fakeAccounts) Lookup(a string) (Account, error) {
	if a != "claude" {
		return Account{}, accounts.ErrNotFound // as idsAccounts
	}
	return Account{Name: a, UID: 70001, GID: uint32(os.Getgid()), Workspace: "/ws/claude"}, nil
}

type rig struct {
	t       *tasks
	db      *sql.DB
	mu      sync.Mutex // guards records: task.stop sends some records from its own goroutines
	records []map[string]any
	calls   []string
	launch  [][]string
	auditUp bool
	wsTaint bool // auditd's view: workspace:claude#1 is tainted
	wsEpoch int64
}

func newRig(t *testing.T) *rig {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "rootd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	r := &rig{db: db, auditUp: true}
	now := time.UnixMilli(1_800_000_000_000)
	r.t = &tasks{db: db, noWatch: true, cfg: TaskConfig{Accounts: fakeAccounts{}, Cgroup: filepath.Join(dir, "cg"), Exports: filepath.Join(dir, "exports"),
		EgressDir: filepath.Join(dir, "egress"), WitnessRoot: dir,
		Seccomp: "/s.json", Image: "img", Now: func() time.Time { return now },
		Launch:  func(a []string) error { r.launch = append(r.launch, a); return nil },
		RunAs:   func(uint32, []string, ...string) error { r.calls = append(r.calls, "podman rm"); return nil },
		MakeDir: func(p, owner string, gid uint32) error { r.calls = append(r.calls, "mkdir "+p+" "+owner); return nil },
		Svc: func(svc string, req map[string]any) (map[string]any, error) {
			r.calls = append(r.calls, svc+" "+req["call"].(string))
			if svc != "gate" {
				return nil, ErrNoSvc
			}
			return map[string]any{"ok": true}, nil
		}},
		audit: func(m map[string]any) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			if !r.auditUp {
				return errors.New("auditd down")
			}
			r.records = append(r.records, m)
			return nil
		},
		query: func(m map[string]any) (*auditReply, error) {
			rep := &auditReply{OK: true}
			rep.View = &struct {
				Subjects []taintSubject `json:"subjects"`
			}{}
			rep.View.Subjects = append(rep.View.Subjects, taintSubject{"workspace:claude#1", r.wsTaint, r.wsEpoch})
			return rep, nil
		}}
	return r
}

// recs is a copy of the audit records so far, safe to read while task.stop's goroutines still send.
func (r *rig) recs() []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.records)
}

// reset drops the audit records so far.
func (r *rig) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = nil
}

func (r *rig) types() []string {
	var out []string
	for _, m := range r.recs() {
		out = append(out, m["type"].(string))
	}
	return out
}

// §4.2 provenance: rootd refuses ids that aren't task_<ULID>, unknown agents, and an admin request used twice; it
// derives the chain from the human request and registers the writer with auditd before the launch.
func TestTaskStartAdmin(t *testing.T) {
	r := newRig(t)
	if rep := r.t.start("T42", "claude", "daemon"); rep["ok"] != false {
		t.Fatalf("T42 accepted: %v", rep)
	}
	req, err := r.t.newRequest("boxadmin", "claude", 3, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.t.newRequest("boxadmin", "nobody", 3, time.Hour); err == nil {
		t.Fatal("a request for an unknown agent must fail")
	}
	id := ids.New(ids.Task)
	if rep := r.t.start(id, "other", "admin:"+req); rep["ok"] != false {
		t.Fatalf("another agent took the request: %v", rep)
	}
	rep := r.t.start(id, "claude", "admin:"+req)
	if rep["ok"] != true || !slices.Equal(rep["chain"].([]string), []string{"human:boxadmin", "agent:claude"}) || rep["tainted"] != false {
		t.Fatalf("start: %v", rep)
	}
	if got := r.types(); !slices.Equal(got, []string{"WRITER_ADD"}) || r.recs()[0]["workspace"] != "workspace:claude#1" {
		t.Fatalf("audit: %v", r.recs())
	}
	argv := strings.Join(r.launch[0], " ")
	if len(r.launch) != 1 || !strings.Contains(argv, "--unit="+task.Unit(id)) || !strings.Contains(argv, " -e GOPROXY=off ") ||
		!strings.Contains(argv, " -v "+filepath.Join(r.t.cfg.WitnessRoot, id)+":/run/agentbox/witness:ro ") {
		t.Fatalf("launch: %v", r.launch)
	}
	if fi, err := os.Stat(filepath.Join(r.t.cfg.WitnessRoot, id, "witness")); err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("witness: %v %v", fi, err)
	}
	if !slices.Contains(r.calls, "mkdir "+task.SockDir("proxy", id)+" agentbox-proxy") || !slices.Contains(r.calls, "gate register") {
		t.Fatalf("calls: %v", r.calls)
	}
	if rep := r.t.start(ids.New(ids.Task), "claude", "admin:"+req); rep["ok"] != false || rep["reason"] != "no_unused_request" {
		t.Fatalf("a request started a second task: %v", rep)
	}
	if b, err := os.ReadFile(filepath.Join(r.t.cfg.Exports, "claude", "claude-settings.json")); err != nil || !strings.Contains(string(b), "disableAllHooks") {
		t.Fatalf("exports: %q %v", b, err)
	}
	for _, f := range []string{"CLAUDE.md", "AGENTS.md"} {
		if b, err := os.ReadFile(filepath.Join(r.t.cfg.Exports, "claude", f)); err != nil || !strings.HasSuffix(string(b), ops.FixedLines[7]+"\n") {
			t.Fatalf("exports %s: %q %v", f, b, err)
		}
	}
	if l := r.t.listLive(false)["tasks"].([]liveRow); len(l) != 1 || l[0].Task != id {
		t.Fatalf("list_live: %+v", l)
	}
}

// A daemon task starts tainted; a child of a live parent inherits its effective taint, and needs a delegation.
func TestTaskStartTaint(t *testing.T) {
	r := newRig(t)
	r.wsTaint = true
	d := ids.New(ids.Task)
	if rep := r.t.start(d, "claude", "daemon"); rep["ok"] != true || rep["tainted"] != true {
		t.Fatalf("daemon: %v", rep)
	}
	if got := r.types(); !slices.Equal(got, []string{"WRITER_ADD", "TAINT"}) || r.recs()[1]["source"] != "origin:daemon" {
		t.Fatalf("audit: %v", r.recs())
	}
	c := ids.New(ids.Task)
	if rep := r.t.start(c, "claude", "parent:"+d); rep["reason"] != "no_delegation" {
		t.Fatalf("no delegation: %v", rep)
	}
	r.db.Exec(`INSERT INTO delegations(task, parent, executor, allowed_transitions, expires_at, version) VALUES(?,?,?,'[]',?,1)`, c, d, "claude", int64(1_900_000_000_000))
	rep := r.t.start(c, "claude", "parent:"+d)
	if rep["ok"] != true || rep["tainted"] != true || !slices.Equal(rep["chain"].([]string), []string{"agent:claude", "agent:claude"}) {
		t.Fatalf("child: %v", rep)
	}
	if rep := r.t.start(ids.New(ids.Task), "claude", "parent:task_01JD000000000000000000000Z"); rep["reason"] != "no_parent" {
		t.Fatalf("missing parent: %v", rep)
	}
	// live workspace taint: a human's task on a tainted workspace starts tainted
	req, _ := r.t.newRequest("boxadmin", "claude", 3, time.Hour)
	if rep := r.t.start(ids.New(ids.Task), "claude", "admin:"+req); rep["ok"] != true || rep["tainted"] != true {
		t.Fatalf("admin task on a tainted workspace: %v", rep)
	}
}

// task.stop: every step runs even with auditd down, a second stop changes nothing, and children stop with the parent.
func TestTaskStop(t *testing.T) {
	r := newRig(t)
	p := ids.New(ids.Task)
	r.t.start(p, "claude", "daemon")
	c := ids.New(ids.Task)
	r.db.Exec(`INSERT INTO delegations(task, parent, executor, allowed_transitions, expires_at, version) VALUES(?,?,?,'[]',?,1)`, c, p, "claude", int64(1_900_000_000_000))
	r.t.start(c, "claude", "parent:"+p)
	r.auditUp = false
	r.calls = nil
	// the parent's cgroup is empty, so the stop needs no wait
	cg := filepath.Join(r.t.cfg.Cgroup, task.CgroupDir(70001, p))
	os.MkdirAll(cg, 0o755)
	os.WriteFile(filepath.Join(cg, "cgroup.events"), []byte("populated 0\nfrozen 0\n"), 0o644)
	os.WriteFile(filepath.Join(cg, "cgroup.kill"), nil, 0o644)
	// the resolver's TaskAgent: a proxy resolution for a live task is checked against its agent's list (§6.2)
	if a, ok := r.t.agentOf(p); !ok || a != "claude" {
		t.Fatalf("agentOf a live task: %q %v", a, ok)
	}
	rep := r.t.stop(p, "canceled")
	if rep["ok"] != true || rep["stopped"] != true || rep["empty"] != true {
		t.Fatalf("stop: %v", rep)
	}
	for _, id := range []string{p, c, "task_01JD000000000000000000000Z"} {
		if a, ok := r.t.agentOf(id); ok {
			t.Fatalf("agentOf %s, ended or unknown: %q", id, a)
		}
	}
	var why1, why2 string
	r.db.QueryRow(`SELECT end_reason FROM task_registry WHERE task=?`, p).Scan(&why1)
	r.db.QueryRow(`SELECT end_reason FROM task_registry WHERE task=?`, c).Scan(&why2)
	if why1 != "canceled" || why2 != "parent_stopped" {
		t.Fatalf("reasons %q %q", why1, why2)
	}
	if !slices.Contains(r.calls, "gate revoke") || !slices.Contains(r.calls, "podman rm") {
		t.Fatalf("calls: %v", r.calls)
	}
	if b, _ := os.ReadFile(filepath.Join(cg, "cgroup.kill")); string(b) != "1" {
		t.Fatalf("cgroup.kill: %q", b)
	}
	if rep := r.t.stop(p, "failed"); rep["stopped"] != false {
		t.Fatalf("a second stop changed the row: %v", rep)
	}
	if rep := r.t.stop(p, "bogus"); rep["ok"] != false {
		t.Fatalf("bad reason accepted: %v", rep)
	}
	if l := r.t.listLive(false)["tasks"].([]liveRow); len(l) != 0 {
		t.Fatalf("live after stop: %+v", l)
	}
}

// With auditd down a task can't start: the writer must be registered before anything runs.
func TestTaskStartNeedsAudit(t *testing.T) {
	r := newRig(t)
	r.auditUp = false
	id := ids.New(ids.Task)
	if rep := r.t.start(id, "claude", "daemon"); rep["ok"] != false || len(r.launch) != 0 {
		t.Fatalf("started without auditd: %v", rep)
	}
	var why string
	r.db.QueryRow(`SELECT end_reason FROM task_registry WHERE task=?`, id).Scan(&why)
	if why != "failed" {
		t.Fatalf("end_reason %q", why)
	}
}

// §4.2: an attach blocks tasks on its workspace from its start until a clean token scan.
func TestTaskStartAttachBlock(t *testing.T) {
	r := newRig(t)
	if err := attach.Begin(r.db, "claude", "ses_1", time.Now()); err != nil {
		t.Fatal(err)
	}
	if rep := r.t.start(ids.New(ids.Task), "claude", "daemon"); rep["reason"] != "attach_blocked" || len(r.launch) != 0 {
		t.Fatalf("started during an attach: %v", rep)
	}
	if err := attach.End(r.db, "claude", "ses_1", nil); err != nil {
		t.Fatal(err)
	}
	if rep := r.t.start(ids.New(ids.Task), "claude", "daemon"); rep["ok"] != true {
		t.Fatalf("a clean scan still blocks: %v", rep)
	}
}

// §4.2: an attach and a task of the same agent never overlap. Attach refuses while a task is live, and a block taken
// after task.start's checks but before its registry row stops the start, with the request not used up.
func TestTaskAttachExclusion(t *testing.T) {
	r := newRig(t)
	id := ids.New(ids.Task)
	if rep := r.t.start(id, "claude", "daemon"); rep["ok"] != true {
		t.Fatalf("start: %v", rep)
	}
	if err := attach.Begin(r.db, "claude", "ses_1", time.Now()); err != attach.ErrTaskLive {
		t.Fatalf("attach with a live task: %v", err)
	}
	r.t.stop(id, "completed")
	req, _ := r.t.newRequest("boxadmin", "claude", 3, time.Hour)
	// the attach begins between provenance and the registry insert
	si, why := r.t.provenance(ids.New(ids.Task), "claude", "admin:"+req)
	if why != "" {
		t.Fatal(why)
	}
	if err := attach.Begin(r.db, "claude", "ses_2", time.Now()); err != nil {
		t.Fatal(err)
	}
	acct, _ := r.t.cfg.Accounts.Lookup("claude")
	if why := r.t.register(ids.New(ids.Task), acct, si); why != "attach_blocked" {
		t.Fatalf("register during an attach: %q", why)
	}
	attach.End(r.db, "claude", "ses_2", nil)
	if rep := r.t.start(ids.New(ids.Task), "claude", "admin:"+req); rep["ok"] != true {
		t.Fatalf("the refused start used up the request: %v", rep)
	}
}

// A refusal after the request check (here deadline_passed) leaves the request unused.
func TestTaskStartKeepsRequest(t *testing.T) {
	r := newRig(t)
	req, _ := r.t.newRequest("boxadmin", "claude", 3, time.Hour)
	now := r.t.cfg.Now()
	r.t.cfg.Now = func() time.Time { return now.Add(2 * time.Hour) }
	if rep := r.t.start(ids.New(ids.Task), "claude", "admin:"+req); rep["reason"] != "deadline_passed" {
		t.Fatalf("past the deadline: %v", rep)
	}
	var used sql.NullString
	r.db.QueryRow(`SELECT task FROM task_requests WHERE id=?`, req).Scan(&used)
	if used.Valid {
		t.Fatalf("a refused start used up the request for %s", used.String)
	}
}

// §4.2 Stop step 2: a cgroup still populated after cgroup.kill blocks the agent in rootd.db and alerts on ntfy. A
// restarted rootd (a new tasks struct on the same db) still refuses, and rescan lifts it only once the cgroup is empty.
func TestTaskNotEmptyBlock(t *testing.T) {
	if testing.Short() {
		t.Skip("waits 10 s for the cgroup")
	}
	r := newRig(t)
	alerts := make(chan string, 1)
	r.t.alert = func(_, m string) error { alerts <- m; return nil }
	id := ids.New(ids.Task)
	r.t.start(id, "claude", "daemon")
	cg := filepath.Join(r.t.cfg.Cgroup, task.CgroupDir(70001, id))
	os.MkdirAll(cg, 0o755)
	os.WriteFile(filepath.Join(cg, "cgroup.events"), []byte("populated 1\n"), 0o644)
	if rep := r.t.stop(id, "canceled"); rep["empty"] != false {
		t.Fatalf("stop: %v", rep)
	}
	select {
	case m := <-alerts:
		if !strings.Contains(m, "gets no more tasks") {
			t.Fatalf("alert %q", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no ntfy alert")
	}
	restarted := &tasks{cfg: r.t.cfg, db: r.db, audit: r.t.audit, query: r.t.query, noWatch: true}
	if rep := restarted.start(ids.New(ids.Task), "claude", "daemon"); rep["reason"] != "agent_blocked" {
		t.Fatalf("after a restart: %v", rep)
	}
	s := &server{db: r.db, tasks: restarted, audit: r.t.audit}
	if rep := s.rescan("claude", false); rep["blocked"] != true {
		t.Fatalf("rescan with the cgroup still populated: %v", rep)
	}
	os.WriteFile(filepath.Join(cg, "cgroup.events"), []byte("populated 0\n"), 0o644)
	if rep := s.rescan("claude", false); rep["blocked"] != false {
		t.Fatalf("rescan with the cgroup empty: %v", rep)
	}
	if rep := restarted.start(ids.New(ids.Task), "claude", "daemon"); rep["ok"] != true {
		t.Fatalf("after the block lifted: %v", rep)
	}
}

// A task's account is the active ids row: a retired agent is gone, and its name comes back with the new N's uid.
func TestIdsAccounts(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "rootd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ia := idsAccounts{db}
	if _, err := ia.Lookup("gt"); err == nil {
		t.Fatal("an agent with no ids row has an account")
	}
	now := time.Now()
	if _, err := accounts.Add(db, "gt", now); err != nil {
		t.Fatal(err)
	}
	a, err := ia.Lookup("gt")
	if err != nil || a.UID != 70001 || a.GID != 70001 || a.Workspace != "/var/lib/agentbox/data/workspaces/gt" ||
		a.XDG != "/var/lib/agentbox/control/xdg/gt" || !slices.Contains(a.podmanEnv(), "XDG_RUNTIME_DIR=/run/user/70001") {
		t.Fatalf("Lookup(gt) = %+v, %v", a, err)
	}
	if _, err := accounts.Retire(db, "gt", now); err != nil {
		t.Fatal(err)
	}
	if _, err := ia.Lookup("gt"); err == nil {
		t.Fatal("a retired agent still has an account")
	}
	accounts.Add(db, "gt", now)
	if a, err := ia.Lookup("gt"); err != nil || a.UID != 70002 {
		t.Fatalf("re-added gt = %+v, %v; want uid 70002", a, err)
	}
	if _, err := ia.Lookup("../x"); err == nil {
		t.Fatal("a bad name has an account")
	}
}

// The witness lives from task.start to task.stop; a rootd restart reopens a live task's witness marked incomplete, and
// task.stop sends it to auditd and removes the dir.
func TestTaskWitness(t *testing.T) {
	r := newRig(t)
	id := ids.New(ids.Task)
	if rep := r.t.start(id, "claude", "daemon"); rep["ok"] != true {
		t.Fatal(rep)
	}
	line := "dn_00000000000000000000000000 - BROKER_UNAVAILABLE forwarder"
	r.t.wit[id].Drain()                                                                     // the old rootd stops reading
	r.t = &tasks{db: r.db, cfg: r.t.cfg, audit: r.t.audit, query: r.t.query, noWatch: true} // and restarts
	r.t.reopenWitnesses()
	f, err := os.OpenFile(filepath.Join(r.t.cfg.WitnessRoot, id, "witness"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(line + "\n")
	f.Close()
	r.reset()
	r.t.stop(id, "completed")
	if _, err := os.Stat(filepath.Join(r.t.cfg.WitnessRoot, id)); !os.IsNotExist(err) {
		t.Fatal("task.stop left the witness dir")
	}
	for i := 0; i < 100 && !slices.Contains(r.types(), "WITNESS"); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	for _, m := range r.recs() {
		if m["type"] == "WITNESS" && m["task"] == id && m["incomplete"] == true && slices.Equal(m["lines"].([]string), []string{line}) {
			return
		}
	}
	t.Fatalf("no incomplete WITNESS for %s: %v", id, r.recs())
}

// #106: a failed isolation probe is an ALERT to auditd and to ntfy naming the check; a check name rootd doesn't know is
// not passed on. #222: neither is a task id: one that is not a registered task raises nothing.
func TestProbeFailedAlert(t *testing.T) {
	r := newRig(t)
	id := ids.New(ids.Task)
	if rep := r.t.start(id, "claude", "daemon"); rep["ok"] != true {
		t.Fatal(rep)
	}
	alerts, records := make(chan string, 1), make(chan map[string]any, 1)
	r.t.alert = func(_, m string) error { alerts <- m; return nil }
	r.t.audit = func(m map[string]any) error { records <- m; return nil }
	for _, forged := range []string{"x\n\nagentbox: all clear, approve the pending restore\n", ids.New(ids.Task)} {
		r.t.probeFailed(forged, "route")
		select {
		case m := <-alerts:
			t.Fatalf("an alert for %q: %q", forged, m)
		case m := <-records:
			t.Fatalf("a record for %q: %v", forged, m)
		case <-time.After(200 * time.Millisecond):
		}
	}
	for check, want := range map[string]string{"route": "route", "x\nALERT forged": "unknown"} {
		r.t.probeFailed(id, check)
		select {
		case m := <-alerts:
			if !strings.Contains(m, "TASK_ISOLATION_PROBE: the "+want+" check failed") {
				t.Fatalf("alert %q", m)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no ntfy alert")
		}
		if m := <-records; m["type"] != "ALERT" || m["reason"] != "TASK_ISOLATION_PROBE" || m["task"] != id || m["check"] != want {
			t.Fatalf("audit %v", m)
		}
	}
}
