package rootd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"agentbox/internal/audit"
	"agentbox/internal/canary"
	"agentbox/internal/git"
	"agentbox/internal/ids"
	"agentbox/internal/ops"
	"agentbox/internal/rootd/accounts"
)

// gitRig is rootd with the real auditd, the task registry and a fake agentbox-git.
type gitRig struct {
	s       *server
	a       *audit.Server
	dir     string
	task    string
	c       string
	mu      sync.Mutex
	calls   []map[string]any
	alerts  []string
	gitFn   func(m map[string]any) (map[string]any, error)
	node    string // what GitHub says the repo's node id is
	headOID string // the remote head ref, for gh.pr.create
}

const oidA, oidB = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func newGitRig(t *testing.T) *gitRig {
	t.Helper()
	sigFloor, missFloor, reconcileGap = 0, 0, 0
	t.Cleanup(func() { sigFloor, missFloor, reconcileGap = 2*time.Second, 200*time.Millisecond, 30*time.Second })
	g := &gitRig{dir: t.TempDir(), node: "R_1", headOID: oidA}
	g.a = &audit.Server{Dir: g.dir, Seal: plainSeal{g.dir}, ReserveBytes: 1 << 20, Logf: t.Logf}
	if err := g.a.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.a.Close() })
	db, err := OpenDB(filepath.Join(g.dir, "rootd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	handle := func(r map[string]any) (map[string]any, error) {
		b, _ := json.Marshal(r)
		rep := g.a.Handle("rootd", 0, 1, b)
		var m map[string]any
		rb, _ := json.Marshal(rep)
		json.Unmarshal(rb, &m)
		return m, nil
	}
	g.s = &server{db: db, cfg: Config{Alert: func(title, msg string) error {
		g.mu.Lock()
		g.alerts = append(g.alerts, title+": "+msg)
		g.mu.Unlock()
		return nil
	}}, auditQ: handle}
	g.s.audit = func(r map[string]any) error {
		b, _ := json.Marshal(r)
		if rep := g.a.Handle("rootd", 0, 1, b); !rep.OK {
			return &auditNACK{rep.Code, rep.Detail}
		}
		return nil
	}
	g.s.tasks = &tasks{db: db, noWatch: true, cfg: TaskConfig{Now: time.Now}, query: func(r map[string]any) (*auditReply, error) {
		b, _ := json.Marshal(r)
		rep := g.a.Handle("rootd", 0, 1, b)
		var ar auditReply
		rb, _ := json.Marshal(rep)
		return &ar, json.Unmarshal(rb, &ar)
	}}
	g.gitFn = g.fakeGit
	g.s.git = func(m map[string]any, _ time.Duration) (map[string]any, error) {
		g.mu.Lock()
		g.calls = append(g.calls, m)
		g.mu.Unlock()
		return g.gitFn(m)
	}
	if _, err := accounts.Add(db, "claude", time.Now()); err != nil {
		t.Fatal(err)
	}
	g.task, g.c = g.startTask(t)
	if _, err := db.Exec(`INSERT INTO remotes VALUES('origin','app','claude','https://github.com/acme/app','R_1','private',1)`); err != nil {
		t.Fatal(err)
	}
	return g
}

// startTask registers a live task of claude's with 3 asks and a canary, as task.start does.
func (g *gitRig) startTask(t *testing.T) (string, string) {
	id, c := ids.New(ids.Task), canary.Mint()
	if _, err := g.s.db.Exec(`INSERT INTO task_registry(task, agent, uid, chain, origin, trace, deadline, started_at, asks_budget)
		VALUES(?,?,?,?,?,?,?,?,3)`, id, "claude", 70001, `["human:boxadmin","agent:claude"]`, "admin:x", ids.New(ids.Trace),
		time.Now().Add(time.Hour).UnixMilli(), time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	g.s.db.Exec(`INSERT INTO task_canaries VALUES(?,?)`, id, c)
	return id, c
}

func (g *gitRig) fakeGit(m map[string]any) (map[string]any, error) {
	switch m["call"] {
	case "repo.check":
		return map[string]any{"ok": true, "exists": true, "contains": m["oid"] == oidA || m["oid"] == oidB, "tip": oidA}, nil
	case "remote.lookup":
		return map[string]any{"ok": true, "nodeId": g.node, "visibility": "private"}, nil
	case "remote.ref":
		return map[string]any{"ok": true, "oid": g.headOID}, nil
	case "repo.create":
		return map[string]any{"ok": true}, nil
	case "exec":
		switch m["name"] {
		case "repo.push":
			return map[string]any{"ok": true, "outputs": map[string]any{"remote": "origin", "oid": oidA}}, nil
		case "gh.pr.create":
			return map[string]any{"ok": true, "outputs": map[string]any{"remote": "origin", "headOid": oidA, "number": 7, "url": "https://github.com/acme/app/pull/7"}}, nil
		}
		return map[string]any{"ok": true, "outputs": map[string]any{"remote": "origin", "id": 99, "url": "https://github.com/acme/app/issues/7#c99"}}, nil
	case "reconcile":
		return map[string]any{"ok": true, "found": true, "outputs": map[string]any{"remote": "origin", "id": 99, "url": "u"}}, nil
	}
	return map[string]any{"ok": false, "error": "unknown call"}, nil
}

func (g *gitRig) op(name string, args map[string]any) reply {
	b, _ := json.Marshal(args)
	return g.s.taskOp(request{Op: "task.op", Name: name, Task: g.task, Agent: "claude", Chain: []string{"human:boxadmin", "agent:claude"}, Args: b})
}

func (g *gitRig) chain() string {
	b, _ := os.ReadFile(filepath.Join(g.dir, audit.SegName(1)))
	return string(b)
}

func denialOf(t *testing.T, name string, args map[string]any, rep reply) ops.Denial {
	t.Helper()
	d, ok := rep["denial"].(ops.Denial)
	if !ok {
		t.Fatalf("%s: no denial: %v", name, rep)
	}
	b, _ := json.Marshal(args)
	if _, _, ok := ops.CheckDenial(name, b, d.JSON()); !ok {
		t.Fatalf("%s: the denial fails the in-task check: %s", name, d.JSON())
	}
	return d
}

func (g *gitRig) execs() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, c := range g.calls {
		if c["call"] == "exec" {
			n++
		}
	}
	return n
}

// §5.2, §5.3: a remote write is a stored P that waits for a human; nothing runs before the approval; the approval runs
// the effect once, between an ACKed INTENT and its RESULT; a resubmission returns the open ask, then the stored result.
func TestGitPushPendingFlow(t *testing.T) {
	g := newGitRig(t)
	args := map[string]any{"remote": "origin", "ref": "refs/heads/agent/claude/x", "oid": oidA}
	rep := g.op("repo.push", args)
	d := denialOf(t, "repo.push", args, rep)
	if d.Code != "NEEDS_SIGNATURE" || d.Reason != "signed" || d.Channel != "cli" || !ids.Is(ids.Pending, d.ID) || *d.AsksLeft != 2 {
		t.Fatalf("repo.push: %s", d.JSON())
	}
	if g.execs() != 0 || strings.Contains(g.chain(), `"INTENT"`) {
		t.Fatal("something ran before the approval")
	}
	if again := denialOf(t, "repo.push", args, g.op("repo.push", args)); again.ID != d.ID {
		t.Fatalf("a resubmission made a new ask: %s, first %s", again.ID, d.ID)
	}
	if len(g.alerts) != 1 || !strings.Contains(g.alerts[0], "agentbox approve "+d.ID) {
		t.Fatalf("alerts %v", g.alerts)
	}
	ap := g.s.pendingAdmin(request{Op: "pending.approve", ID: d.ID}, "boxadmin:admin")
	if ap["ok"] != true || ap["state"] != "executed" || g.execs() != 1 {
		t.Fatalf("approve: %v, %d execs", ap, g.execs())
	}
	ch := g.chain()
	if !strings.Contains(ch, `"opId":"`+d.ID+`"`) || !strings.Contains(ch, `"signer":"boxadmin:admin"`) || !strings.Contains(ch, `"status":"executed"`) {
		t.Fatalf("chain: %s", ch)
	}
	if ap := g.s.pendingAdmin(request{Op: "pending.approve", ID: d.ID}, "boxadmin:admin"); ap["ok"] == true || g.execs() != 1 {
		t.Fatalf("a second approval ran the op again: %v", ap)
	}
	// executed: the same push again returns the stored result, with only agentbox's outputs, and makes no ask
	if r := g.op("repo.push", args); r["ok"] != true || fmt.Sprint(r["result"]) != "map[oid:"+oidA+" remote:origin]" {
		t.Fatalf("resubmission after execution: %v", r)
	}
	// owner-scoped: another agent's remote and a missing one are one miss; outside the namespace and an OID in no branch
	g.s.db.Exec(`INSERT INTO remotes VALUES('theirs','x','other','https://github.com/acme/x','R_2','private',1)`)
	for _, c := range []struct {
		args map[string]any
		code string
	}{{map[string]any{"remote": "theirs", "ref": "refs/heads/agent/claude/x", "oid": oidA}, "NOT_FOUND_OR_NOT_OWNED"},
		{map[string]any{"remote": "nosuch", "ref": "refs/heads/agent/claude/x", "oid": oidA}, "NOT_FOUND_OR_NOT_OWNED"},
		{map[string]any{"remote": "origin", "ref": "refs/heads/main", "oid": oidA}, "REF_OUTSIDE_NAMESPACE"},
		{map[string]any{"remote": "origin", "ref": "refs/heads/agent/claude/x", "oid": strings.Repeat("c", 40)}, "OID_NOT_IN_REMOTE_REPO"},
		{map[string]any{"remote": "origin", "ref": "refs/heads/agent/claude/x", "oid": "nothex"}, "INVALID_ARGS"}} {
		if d := denialOf(t, "repo.push", c.args, g.op("repo.push", c.args)); d.Code != c.code {
			t.Errorf("%v: %s, want %s", c.args, d.Code, c.code)
		}
	}
}

// gh.* (§5.3, #105): the body gets the op marker before H; a body with the canary is refused with EXFIL_CANARY and
// taints the task; GitHub's refusal reaches the task as REMOTE_REJECTED{what} and its text only the DENY detail.
func TestGitCommentMarkerAndCanary(t *testing.T) {
	g := newGitRig(t)
	bad := map[string]any{"remote": "origin", "number": 7, "body": "here is the key: " + g.c[:30] + "\n" + g.c[30:]}
	if d := denialOf(t, "gh.pr.comment", bad, g.op("gh.pr.comment", bad)); d.Code != "EXFIL_CANARY" || d.By != "floor" {
		t.Fatalf("canary comment: %s", d.JSON())
	}
	for i := 0; i < 50 && !strings.Contains(g.chain(), `"reason":"exfil_canary"`); i++ {
		time.Sleep(20 * time.Millisecond) // the ALERT record goes out on its own goroutine
	}
	if !strings.Contains(g.chain(), `"subject":"task:`+g.task+`"`) || !strings.Contains(g.chain(), `"reason":"exfil_canary"`) {
		t.Fatalf("no taint or alert: %s", g.chain())
	}
	// the canary counts first: an attempt through a remote the agent doesn't have is still an attempt
	miss := map[string]any{"remote": "nosuch", "number": 7, "body": g.c}
	if d := denialOf(t, "gh.issue.comment", miss, g.op("gh.issue.comment", miss)); d.Code != "EXFIL_CANARY" {
		t.Fatalf("canary to a missing remote: %s", d.JSON())
	}
	if len(g.alerts) != 2 || !strings.Contains(g.alerts[0], "canary") {
		t.Fatalf("alerts %v", g.alerts)
	}
	pr := map[string]any{"remote": "origin", "head": "refs/heads/agent/claude/x", "base": "main", "title": "t", "body": "b64 " + g.c}
	if d := denialOf(t, "gh.pr.create", pr, g.op("gh.pr.create", pr)); d.Code != "EXFIL_CANARY" {
		t.Fatalf("canary PR body: %s", d.JSON())
	}
	// the task is tainted now: a clean comment still asks, as tainted
	ok := map[string]any{"remote": "origin", "number": 7, "body": "LGTM"}
	d := denialOf(t, "gh.pr.comment", ok, g.op("gh.pr.comment", ok))
	if d.Code != "NEEDS_SIGNATURE" || d.Reason != "tainted" {
		t.Fatalf("comment: %s", d.JSON())
	}
	var op string
	g.s.db.QueryRow(`SELECT op FROM pending WHERE id=?`, d.ID).Scan(&op)
	if !strings.Contains(op, `LGTM\n<!-- agentbox-op:`+d.ID+` -->`) && !strings.Contains(op, "LGTM\\n<!-- agentbox-op:"+d.ID+" -->") {
		t.Fatalf("P's body has no marker: %s", op)
	}
	// GitHub refuses at execution
	g.gitFn = func(m map[string]any) (map[string]any, error) {
		if m["call"] == "exec" {
			return map[string]any{"ok": false, "what": "not_found", "detail": "POST: 404 secret-github-text"}, nil
		}
		return g.fakeGit(m)
	}
	ap := g.s.pendingAdmin(request{Op: "pending.approve", ID: d.ID}, "boxadmin:admin")
	if ap["state"] != "failed" || ap["reason"] != "REMOTE_REJECTED:not_found" {
		t.Fatalf("refused at GitHub: %v", ap)
	}
	time.Sleep(100 * time.Millisecond) // the DENY record goes out on its own goroutine
	if ch := g.chain(); !strings.Contains(ch, `"errorCode":"REMOTE_REJECTED"`) || !strings.Contains(ch, "secret-github-text") ||
		strings.Contains(ch, "LGTM") {
		t.Fatalf("chain: %s", ch)
	}
	// the final row keeps the body only as a hash
	g.s.db.QueryRow(`SELECT op FROM pending WHERE id=?`, d.ID).Scan(&op)
	if strings.Contains(op, "LGTM") || !strings.Contains(op, `"sha256"`) {
		t.Fatalf("final P still holds the body: %s", op)
	}
}

// §5.2 recovery: an effect whose INTENT has no RESULT is found again through agentbox-git and gets its RESULT, with
// no second run; one that can't be found is indeterminate, and a gh.* write is offered again with the same marker.
func TestGitReconcile(t *testing.T) {
	g := newGitRig(t)
	g.s.db.Exec(`UPDATE task_registry SET asks_budget=10 WHERE task=?`, g.task)
	args := map[string]any{"remote": "origin", "number": 7, "body": "hello"}
	d := denialOf(t, "gh.pr.comment", args, g.op("gh.pr.comment", args))
	// the exec call breaks after the POST: rootd can't know whether it ran, so it reconciles
	g.gitFn = func(m map[string]any) (map[string]any, error) {
		if m["call"] == "exec" {
			return nil, errors.New("connection reset by peer")
		}
		return g.fakeGit(m)
	}
	ap := g.s.pendingAdmin(request{Op: "pending.approve", ID: d.ID}, "boxadmin:admin")
	if ap["ok"] != true || ap["state"] != "executed" || g.execs() != 1 {
		t.Fatalf("reconciled after a broken exec: %v, %d execs", ap, g.execs())
	}
	// a restart between INTENT and RESULT: reconcileStart leaves the row to reconcileBrokers, which finds it
	d2 := denialOf(t, "gh.issue.comment", args, g.op("gh.issue.comment", args))
	g.s.pendingAdmin(request{Op: "pending.approve", ID: d2.ID}, "boxadmin:admin") // exec breaks again: reconcile finds it
	d3 := denialOf(t, "gh.pr.comment", map[string]any{"remote": "origin", "number": 8, "body": "x"},
		g.op("gh.pr.comment", map[string]any{"remote": "origin", "number": 8, "body": "x"}))
	g.s.db.Exec(`UPDATE pending SET state='executing' WHERE id=?`, d3.ID)
	if err := g.s.audit(map[string]any{"type": "INTENT", "opId": d3.ID, "name": "gh.pr.comment", "origin": "gate",
		"args": map[string]any{"remote": "origin", "number": 8, "body": ops.Hashed("x")}, "ts": time.Now().UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	g.gitFn = func(m map[string]any) (map[string]any, error) {
		if m["call"] == "reconcile" {
			return map[string]any{"ok": true, "found": false}, nil
		}
		return g.fakeGit(m)
	}
	g.s.reconcileStart()
	var st string
	g.s.db.QueryRow(`SELECT state FROM pending WHERE id=?`, d3.ID).Scan(&st)
	if st != "executing" {
		t.Fatalf("reconcileStart moved an INTENT-only row to %s", st)
	}
	g.s.reconcileBrokers()
	g.s.db.QueryRow(`SELECT state FROM pending WHERE id=?`, d3.ID).Scan(&st)
	var n int
	g.s.db.QueryRow(`SELECT count(*) FROM pending WHERE task=? AND state='pending' AND bound LIKE ?`, g.task, `%"marker":"`+d3.ID+`"%`).Scan(&n)
	if st != "indeterminate" || n != 1 || g.execs() != 2 {
		t.Fatalf("not found: state %s, %d re-offers, %d execs", st, n, g.execs())
	}
	// an executing row whose outcome nothing recorded, with agentbox-git back: a human's approve settles it by
	// inspection, never a second run
	d5 := denialOf(t, "gh.pr.comment", map[string]any{"remote": "origin", "number": 10, "body": "w"},
		g.op("gh.pr.comment", map[string]any{"remote": "origin", "number": 10, "body": "w"}))
	g.s.db.Exec(`UPDATE pending SET state='executing' WHERE id=?`, d5.ID)
	g.s.audit(map[string]any{"type": "INTENT", "opId": d5.ID, "name": "gh.pr.comment", "origin": "gate",
		"args": map[string]any{"remote": "origin", "number": 10, "body": ops.Hashed("w")}, "ts": time.Now().UnixMilli()})
	g.gitFn = g.fakeGit
	runs := g.execs()
	if ap := g.s.pendingAdmin(request{Op: "pending.approve", ID: d5.ID}, "boxadmin:admin"); ap["state"] != "executed" || g.execs() != runs {
		t.Fatalf("approve of an executing row: %v, %d execs (was %d)", ap, g.execs(), runs)
	}
	// an executing row with no INTENT ran nothing: refused
	d4 := denialOf(t, "gh.pr.comment", map[string]any{"remote": "origin", "number": 9, "body": "y"},
		g.op("gh.pr.comment", map[string]any{"remote": "origin", "number": 9, "body": "y"}))
	if d4.Code != "NEEDS_SIGNATURE" {
		t.Fatalf("d4: %s", d4.JSON())
	}
	g.s.db.Exec(`UPDATE pending SET state='executing' WHERE id=?`, d4.ID)
	g.s.reconcileStart()
	g.s.db.QueryRow(`SELECT state FROM pending WHERE id=?`, d4.ID).Scan(&st)
	if st != "refused" {
		t.Fatalf("no INTENT: %s", st)
	}
}

// The re-checks at execution (§5.2, §5.3): a repo whose node id moved on GitHub, a remotes row replaced, a head ref
// that moved on the remote are refused before any INTENT. A denied key stays denied; caps hold.
func TestGitRecheckAndCaps(t *testing.T) {
	g := newGitRig(t)
	push := map[string]any{"remote": "origin", "ref": "refs/heads/agent/claude/x", "oid": oidA}
	d := denialOf(t, "repo.push", push, g.op("repo.push", push))
	g.node = "R_other"
	if ap := g.s.pendingAdmin(request{Op: "pending.approve", ID: d.ID}, "boxadmin:admin"); ap["reason"] != "STALE:remote_changed" {
		t.Fatalf("moved node: %v", ap)
	}
	g.node = "R_1"
	pr := map[string]any{"remote": "origin", "head": "refs/heads/agent/claude/x", "base": "main", "title": "t", "body": "b"}
	dp := denialOf(t, "gh.pr.create", pr, g.op("gh.pr.create", pr))
	g.headOID = oidB
	if ap := g.s.pendingAdmin(request{Op: "pending.approve", ID: dp.ID}, "boxadmin:admin"); ap["reason"] != "STALE:ref_moved" {
		t.Fatalf("moved head: %v", ap)
	}
	if strings.Contains(g.chain(), `"INTENT"`) || g.execs() != 0 {
		t.Fatal("a refused re-check wrote an INTENT or ran")
	}
	// the task budget of 3: a third ask, then ASK_CAP{task_budget}
	c := map[string]any{"remote": "origin", "number": 1, "body": "z"}
	dc := denialOf(t, "gh.pr.comment", c, g.op("gh.pr.comment", c))
	c2 := map[string]any{"remote": "origin", "number": 2, "body": "z"}
	if d := denialOf(t, "gh.pr.comment", c2, g.op("gh.pr.comment", c2)); d.Code != "ASK_CAP" || d.What != "task_budget" {
		t.Fatalf("4th ask: %s", d.JSON())
	}
	// a human denies: the same key is final in this task
	if r := g.s.pendingAdmin(request{Op: "pending.deny", ID: dc.ID}, "boxadmin:admin"); r["state"] != "denied" {
		t.Fatalf("deny: %v", r)
	}
	if d := denialOf(t, "gh.pr.comment", c, g.op("gh.pr.comment", c)); d.Code != "ASK_DENIED" {
		t.Fatalf("after deny: %s", d.JSON())
	}
}

// push.report (§6.3): a tainted task's push taints the refs it updates before git moves them; a clean one taints
// nothing; an ended task gets task_ended.
func TestPushReport(t *testing.T) {
	g := newGitRig(t)
	r := g.s.pushReport(request{Task: g.task, Repo: "claude/app", Refs: []string{"refs/heads/agent/claude/x"}})
	if r["ok"] != true || r["tainted"] != false || strings.Contains(g.chain(), `"TAINT"`) {
		t.Fatalf("clean push: %v", r)
	}
	g.s.canaryHit(g.task, "repo.push")
	r = g.s.pushReport(request{Task: g.task, Repo: "claude/app", Refs: []string{"refs/heads/agent/claude/x"}, Secrets: []string{"github-pat"}})
	if r["tainted"] != true || !strings.Contains(g.chain(), `"subject":"ref:claude/app:refs/heads/agent/claude/x"`) {
		t.Fatalf("tainted push: %v %s", r, g.chain())
	}
	if !slices.ContainsFunc(g.alerts, func(a string) bool { return strings.Contains(a, "github-pat") }) {
		t.Fatalf("no secret alert: %v", g.alerts)
	}
	if r := g.s.pushReport(request{Task: g.task, Repo: "other/app", Refs: []string{"refs/heads/agent/other/x"}}); r["ok"] != false {
		t.Fatalf("another agent's repo: %v", r)
	}
	if r := g.s.pushReport(request{Task: g.task, Repo: "claude/app", Refs: []string{"refs/heads/main"}}); r["ok"] != false {
		t.Fatalf("a ref outside the namespace: %v", r)
	}
	g.s.db.Exec(`UPDATE task_registry SET ended_at=1, end_reason='failed' WHERE task=?`, g.task)
	if r := g.s.pushReport(request{Task: g.task, Repo: "claude/app"}); r["reason"] != "task_ended" {
		t.Fatalf("ended task: %v", r)
	}
}

// remote.set (App. E): GitHub gives the node id and visibility; the local repo is made; the row is audited.
func TestRemoteSet(t *testing.T) {
	g := newGitRig(t)
	set := func(args map[string]any) reply {
		b, _ := json.Marshal(args)
		return g.s.remoteSet(request{Args: b})
	}
	r := set(map[string]any{"id": "up", "agent": "claude", "project": "web", "url": "https://github.com/acme/web.git"})
	rr, _ := r["remote"].(remoteRow)
	if r["ok"] != true || rr.URL != "https://github.com/acme/web" || rr.NodeID != "R_1" || rr.Visibility != "private" {
		t.Fatalf("remote.set: %v", r)
	}
	if !strings.Contains(g.chain(), `"name":"remote.set"`) {
		t.Fatal("remote.set not audited")
	}
	for _, bad := range []map[string]any{{"id": "up", "agent": "nobody", "project": "web", "url": "https://github.com/acme/web"},
		{"id": "up", "agent": "claude", "project": "../x", "url": "https://github.com/acme/web"},
		{"id": "up", "agent": "claude", "project": "web", "url": "https://evil.example/acme/web"},
		{"id": "origin2", "agent": "claude", "project": "web", "url": "https://github.com/acme/web", "extra": 1}} {
		if r := set(bad); r["ok"] == true {
			t.Errorf("%v: accepted", bad)
		}
	}
	if _, ok := g.s.remote("up", "claude"); !ok {
		t.Fatal("no row")
	}
	if _, ok := g.s.remote("up", "other"); ok {
		t.Fatal("another agent reads the row")
	}
}

var _ = git.Bound{}
