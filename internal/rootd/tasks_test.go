package rootd

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"agentbox/internal/ids"
	"agentbox/internal/task"
)

type fakeAccounts struct{}

func (fakeAccounts) Lookup(a string) (Account, error) {
	if a != "claude" {
		return Account{}, errors.New("no such agent")
	}
	return Account{Name: a, UID: 70001, GID: 70001, Workspace: "/ws/claude"}, nil
}

type rig struct {
	t       *tasks
	db      *sql.DB
	records []map[string]any
	calls   []string
	launch  [][]string
	auditUp bool
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
			if !r.auditUp {
				return errors.New("auditd down")
			}
			r.records = append(r.records, m)
			return nil
		},
		query: func(m map[string]any) (*auditReply, error) {
			rep := &auditReply{OK: true}
			rep.View = &struct {
				Subjects []struct {
					Subject string `json:"subject"`
					Tainted bool   `json:"tainted"`
				} `json:"subjects"`
			}{}
			rep.View.Subjects = append(rep.View.Subjects, struct {
				Subject string `json:"subject"`
				Tainted bool   `json:"tainted"`
			}{"workspace:claude", true})
			return rep, nil
		}}
	return r
}

func (r *rig) types() []string {
	var out []string
	for _, m := range r.records {
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
	if got := r.types(); !slices.Equal(got, []string{"WRITER_ADD"}) || r.records[0]["workspace"] != "workspace:claude" {
		t.Fatalf("audit: %v", r.records)
	}
	if len(r.launch) != 1 || !strings.Contains(strings.Join(r.launch[0], " "), "--unit="+task.Unit(id)) {
		t.Fatalf("launch: %v", r.launch)
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
	if l := r.t.listLive()["tasks"].([]liveRow); len(l) != 1 || l[0].Task != id {
		t.Fatalf("list_live: %+v", l)
	}
}

// A daemon task starts tainted; a child of a live parent inherits its effective taint, and needs a delegation.
func TestTaskStartTaint(t *testing.T) {
	r := newRig(t)
	d := ids.New(ids.Task)
	if rep := r.t.start(d, "claude", "daemon"); rep["ok"] != true || rep["tainted"] != true {
		t.Fatalf("daemon: %v", rep)
	}
	if got := r.types(); !slices.Equal(got, []string{"WRITER_ADD", "TAINT"}) || r.records[1]["source"] != "origin:daemon" {
		t.Fatalf("audit: %v", r.records)
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
	rep := r.t.stop(p, "canceled")
	if rep["ok"] != true || rep["stopped"] != true || rep["empty"] != true {
		t.Fatalf("stop: %v", rep)
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
	if l := r.t.listLive()["tasks"].([]liveRow); len(l) != 0 {
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
