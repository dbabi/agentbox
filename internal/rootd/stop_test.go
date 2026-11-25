package rootd

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"agentbox/internal/gate"
	"agentbox/internal/ids"
	"agentbox/internal/rootd/attach"
	"agentbox/internal/task"
)

// #197: a task.stop that lands while task.start is launching waits for the launch, then kills and revokes what it
// started, so a stopped task never runs on after its stop.
func TestTaskStopDuringLaunch(t *testing.T) {
	r := newRig(t)
	entered, release := make(chan struct{}), make(chan struct{})
	r.t.cfg.Launch = func(a []string) error {
		close(entered)
		<-release
		r.calls = append(r.calls, "launched")
		return nil
	}
	id := ids.New(ids.Task)
	started := make(chan reply)
	go func() { started <- r.t.start(id, "claude", "daemon") }()
	<-entered
	stopped := make(chan reply)
	go func() { stopped <- r.t.stop(id, "canceled") }()
	select {
	case rep := <-stopped:
		t.Fatalf("task.stop returned during the launch: %v", rep)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	if rep := <-started; rep["ok"] != true {
		t.Fatalf("start: %v", rep)
	}
	if rep := <-stopped; rep["ok"] != true || rep["stopped"] != true {
		t.Fatalf("stop: %v", rep)
	}
	i, j := slices.Index(r.calls, "launched"), slices.Index(r.calls, "podman rm")
	if i < 0 || j < i || !slices.Contains(r.calls[i:], "gate revoke") {
		t.Fatalf("the stop did not come after the launch: %v", r.calls)
	}
	var reason string
	r.db.QueryRow(`SELECT end_reason FROM task_registry WHERE task=?`, id).Scan(&reason)
	if reason != "canceled" {
		t.Fatalf("end_reason %q", reason)
	}
}

// #222 R53: a task id that already used up one request is refused for a second one, and agentboxd's JSON null reply
// to dispatch is an error, not a rootd crash.
func TestTaskStartUntrustedInput(t *testing.T) {
	r := newRig(t)
	id := ids.New(ids.Task)
	req1, _ := r.t.newRequest("boxadmin", "claude", 3, time.Hour)
	req2, _ := r.t.newRequest("boxadmin", "claude", 3, time.Hour)
	if rep := r.t.start(id, "claude", "admin:"+req1); rep["ok"] != true {
		t.Fatalf("start: %v", rep)
	}
	if rep := r.t.start(id, "claude", "admin:"+req2); rep["ok"] != false || rep["reason"] != "no_unused_request" {
		t.Fatalf("the same task id on a second request: %v", rep)
	}
	r.t.cfg.Svc = func(string, map[string]any) (map[string]any, error) { return nil, nil }
	s := &server{db: r.db, tasks: r.t}
	if rep := s.taskAdmin(request{Op: "task.new", Agent: "claude"}, peer{}); rep["ok"] != false || rep["error"] != "agentboxd: no reply object" {
		t.Fatalf("null dispatch reply: %v", rep)
	}
}

// #213: for a task new prompt at gate.MaxPrompt, full of '<' and newlines, the dispatch line rootd sends agentboxd
// fits svc-gate.sock's line limit (gate.MaxRequest): svcLine leaves each '<' 1 byte, where json.Marshal makes it 6.
func TestDispatchLineFits(t *testing.T) {
	r := newRig(t)
	var line []byte
	r.t.cfg.Svc = func(_ string, req map[string]any) (map[string]any, error) {
		line = svcLine(req)
		return map[string]any{"ok": true}, nil
	}
	p := strings.Repeat("<<<<<<<<<\n", gate.MaxPrompt/11-1) // 11 bytes each as JSON
	p += strings.Repeat("<", gate.MaxPrompt-gate.PromptLen(p))
	s := &server{db: r.db, tasks: r.t}
	if rep := s.taskAdmin(request{Op: "task.new", Agent: "claude", CLI: "claude", Prompt: p}, peer{}); rep["ok"] != true {
		t.Fatalf("task.new: %v", rep)
	}
	if gate.PromptLen(p) != gate.MaxPrompt || len(line) == 0 || len(line)-1 > gate.MaxRequest || line[len(line)-1] != '\n' || bytes.Contains(line, []byte(`\u003c`)) {
		t.Fatalf("a %d-byte dispatch line for a prompt of %d bytes as JSON", len(line), gate.PromptLen(p))
	}
}

// #222 R54: task.stop writes a leftover task's block and ended_at in one transaction. When it fails, the row stays live
// and task.stop says so.
func TestTaskStopEndAtomic(t *testing.T) {
	r := newRig(t)
	id := ids.New(ids.Task)
	r.t.start(id, "claude", "daemon")
	if _, err := r.db.Exec(`CREATE TEMP TRIGGER no_leftover BEFORE INSERT ON task_leftover BEGIN SELECT RAISE(ABORT, 'disk I/O'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := r.t.end(id, "claude", "canceled", true); err == nil {
		t.Fatal("end without its block succeeded")
	}
	if l := r.t.listLive()["tasks"].([]liveRow); len(l) != 1 {
		t.Fatalf("the task ended without its block: %+v", l)
	}
	r.db.Exec(`DROP TRIGGER no_leftover`)
	r.db.Exec(`CREATE TEMP TRIGGER no_end BEFORE UPDATE ON task_registry BEGIN SELECT RAISE(ABORT, 'disk I/O'); END`)
	if rep := r.t.stop(id, "canceled"); rep["ok"] != false || rep["reason"] != "registry" {
		t.Fatalf("stop with a failed registry write: %v", rep)
	}
	if _, err := r.t.end(id, "claude", "canceled", true); err == nil {
		t.Fatal("end with a failed registry write succeeded")
	}
	if _, on, _ := attach.Blocked(r.db, "claude"); on {
		t.Fatal("the failed transaction left its block")
	}
	r.db.Exec(`DROP TRIGGER no_end`)
	if rep := r.t.stop(id, "canceled"); rep["ok"] != true || rep["stopped"] != true {
		t.Fatalf("stop again: %v", rep)
	}
}

// #222 R48: every task that left processes blocks its agent, and rescan lifts the block only once all their cgroups
// are empty. A task_not_empty task_block row from an older rootd moves to task_leftover.
func TestTaskLeftovers(t *testing.T) {
	r := newRig(t)
	t1, t2 := ids.New(ids.Task), ids.New(ids.Task)
	cg := map[string]string{}
	for _, id := range []string{t1, t2} { // two live tasks of one agent
		if rep := r.t.start(id, "claude", "daemon"); rep["ok"] != true {
			t.Fatal(rep)
		}
	}
	for _, id := range []string{t1, t2} {
		cg[id] = filepath.Join(r.t.cfg.Cgroup, task.CgroupDir(70001, id))
		os.MkdirAll(cg[id], 0o755)
		os.WriteFile(filepath.Join(cg[id], "cgroup.events"), []byte("populated 1\n"), 0o644)
		if n, err := r.t.end(id, "claude", "canceled", true); n != 1 || err != nil {
			t.Fatalf("end %s: %d %v", id, n, err)
		}
	}
	if l, _ := attach.List(r.db); len(l) != 2 || !slices.Contains([]string{t1, t2}, l[0].Session) || !slices.Contains([]string{t1, t2}, l[1].Session) ||
		l[0].Session == l[1].Session || l[1].Reason != attach.TaskNotEmpty {
		t.Fatalf("blocks: %+v", l)
	}
	if err := attach.Begin(r.db, "claude", "ses_1", time.Now()); err != attach.ErrLive {
		t.Fatalf("attach with leftover tasks: %v", err)
	}
	s := &server{db: r.db, tasks: r.t, audit: r.t.audit}
	r.reset()
	if rep := s.rescan("claude", false); rep["blocked"] != true || len(r.recs()) != 0 {
		t.Fatalf("rescan with both populated changes nothing, so it sends no INTENT: %v, records %v", rep, r.recs())
	}
	os.WriteFile(filepath.Join(cg[t1], "cgroup.events"), []byte("populated 0\n"), 0o644)
	// §9: lifting a leftover is an admin effect. auditd down: the INTENT gets no ACK, and the leftover stays.
	r.auditUp = false
	if rep := s.rescan("claude", false); rep["ok"] != false || rep["blocked"] != true {
		t.Fatalf("rescan with auditd down: %v", rep)
	}
	if left, _ := attach.Leftovers(r.db, "claude"); len(left) != 2 {
		t.Fatalf("auditd down lifted a leftover: %v", left)
	}
	r.auditUp = true
	r.reset()
	if rep := s.rescan("claude", false); rep["blocked"] != true {
		t.Fatalf("rescan with %s still populated: %v", t2, rep)
	}
	if recs := r.recs(); len(recs) != 2 || recs[0]["type"] != "INTENT" || recs[0]["name"] != "attach.rescan" || recs[0]["origin"] != "admin" ||
		recs[1]["type"] != "RESULT" || recs[1]["opId"] != recs[0]["opId"] || recs[1]["status"] != "executed" ||
		!slices.Equal(recs[1]["outputs"].(map[string]any)["tasks"].([]string), []string{t1}) {
		t.Fatalf("rescan records %v", recs)
	}
	if rep := r.t.start(ids.New(ids.Task), "claude", "daemon"); rep["reason"] != "agent_blocked" {
		t.Fatalf("start with %s still populated: %v", t2, rep)
	}
	os.RemoveAll(cg[t2])
	if rep := s.rescan("claude", false); rep["blocked"] != false {
		t.Fatalf("rescan with both empty: %v", rep)
	}
	if rep := r.t.start(ids.New(ids.Task), "claude", "daemon"); rep["ok"] != true {
		t.Fatalf("start after the block lifted: %v", rep)
	}

	// an older rootd's block row
	dbPath := filepath.Join(t.TempDir(), "old.db")
	old, err := OpenDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	old.Exec(`INSERT INTO task_block(agent, session, reason, started_ms) VALUES('claude', ?, 'task_not_empty', 1)`, t1)
	old.Close()
	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if b, on, _ := attach.Blocked(db, "claude"); !on || b.Reason != attach.TaskNotEmpty || b.Session != t1 {
		t.Fatalf("migrated block: %+v %v", b, on)
	}
	if left, _ := attach.Leftovers(db, "claude"); !slices.Equal(left, []string{t1}) {
		t.Fatalf("leftovers: %v", left)
	}
}

// #222: a cgroup.events rootd can't read counts as populated, never as empty. task.stop blocks the agent and alerts,
// attach rescan keeps that block and says why, and waitEmpty waits for its backstop. A cgroup that is gone is empty.
func TestPopulatedReadError(t *testing.T) {
	if p, err := populated(filepath.Join(t.TempDir(), "gone")); p || err != nil {
		t.Fatalf("a cgroup that is gone: %v %v", p, err)
	}
	r := newRig(t)
	alerts := make(chan string, 1)
	r.t.alert = func(_, m string) error { alerts <- m; return nil }
	id := ids.New(ids.Task)
	if rep := r.t.start(id, "claude", "daemon"); rep["ok"] != true {
		t.Fatal(rep)
	}
	cg := filepath.Join(r.t.cfg.Cgroup, task.CgroupDir(70001, id))
	os.MkdirAll(filepath.Join(cg, "cgroup.events"), 0o755) // a read fails (EISDIR), also as root
	if p, err := populated(cg); !p || err == nil {
		t.Fatalf("an unreadable cgroup.events: %v %v", p, err)
	}
	if got := waitEmpty(cg, time.Now()); got != "deadline" {
		t.Fatalf("waitEmpty on an unreadable cgroup.events: %q", got)
	}
	if rep := r.t.stop(id, "canceled"); rep["ok"] != true || rep["empty"] != false {
		t.Fatalf("stop: %v", rep)
	}
	select {
	case m := <-alerts:
		if !strings.Contains(m, "not empty") {
			t.Fatalf("alert %q", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no alert")
	}
	s := &server{db: r.db, tasks: r.t, audit: r.t.audit}
	if rep := s.rescan("claude", true); rep["ok"] != false || rep["blocked"] != true || !strings.Contains(fmt.Sprint(rep["error"]), "cgroup.events") {
		t.Fatalf("rescan: %v", rep)
	}
	if left, _ := attach.Leftovers(r.db, "claude"); !slices.Equal(left, []string{id}) {
		t.Fatalf("leftovers after the rescan: %v", left)
	}
}

// #222: watchTask times the task on the monotonic clock. A wall clock that steps past the deadline while the task runs
// doesn't make its exit a timeout.
func TestWatchTaskClockStep(t *testing.T) {
	r := newRig(t)
	var wall atomic.Int64
	wall.Store(1_800_000_000_000)
	r.t.cfg.Now = func() time.Time { return time.UnixMilli(wall.Load()) }
	id := ids.New(ids.Task)
	if rep := r.t.start(id, "claude", "daemon"); rep["ok"] != true {
		t.Fatal(rep)
	}
	cg := filepath.Join(r.t.cfg.Cgroup, task.CgroupDir(70001, id))
	os.MkdirAll(cg, 0o755)
	os.WriteFile(filepath.Join(cg, "cgroup.events"), []byte("populated 1\n"), 0o644)
	var dl int64
	r.db.QueryRow(`SELECT deadline FROM task_registry WHERE task=?`, id).Scan(&dl)
	r.t.noWatch = false
	r.t.watchTask(id, 70001, dl)
	wall.Add((3 * time.Hour).Milliseconds()) // the clock steps 3 h, past the 2 h deadline
	os.WriteFile(filepath.Join(cg, "cgroup.events"), []byte("populated 0\n"), 0o644)
	var why sql.NullString
	for i := 0; i < 100 && !why.Valid; i++ {
		time.Sleep(50 * time.Millisecond)
		r.db.QueryRow(`SELECT end_reason FROM task_registry WHERE task=?`, id).Scan(&why)
	}
	if why.String != "failed" {
		t.Fatalf("end_reason %q, want failed: the task exited 2 h before its deadline", why.String)
	}
}

// #222: an admin whose uid names no user is refused, never recorded as root.
func TestTaskAdminUnknownUID(t *testing.T) {
	r := newRig(t)
	s := &server{db: r.db, tasks: r.t}
	for _, op := range []string{"task.new", "task.undo"} {
		if rep := s.taskAdmin(request{Op: op, Agent: "claude", Task: ids.New(ids.Task)}, peer{uid: 3999999999}); rep["ok"] != false ||
			!strings.Contains(fmt.Sprint(rep["error"]), "uid 3999999999 names no user") {
			t.Fatalf("%s: %v", op, rep)
		}
	}
	var n int
	if r.db.QueryRow(`SELECT count(*) FROM task_requests`).Scan(&n); n != 0 {
		t.Fatalf("%d requests recorded", n)
	}
	if rep := s.taskAdmin(request{Op: "task.new", Agent: "claude"}, peer{}); rep["ok"] != true {
		t.Fatalf("uid 0: %v", rep)
	}
	var human string
	if r.db.QueryRow(`SELECT human FROM task_requests`).Scan(&human); human != "root" {
		t.Fatalf("uid 0 recorded as %q", human)
	}
}
