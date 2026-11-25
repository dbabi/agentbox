package rootd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"agentbox/internal/ids"
	"agentbox/internal/rootd/attach"
)

// fakeBtrfs copies nothing: a snapshot is a dir holding a "from" file, so a test can see which tree is where.
type fakeBtrfs struct{ calls []string }

func (f *fakeBtrfs) Snapshot(src, dst, q string, ro bool) error {
	f.calls = append(f.calls, "snapshot "+filepath.Base(src)+" "+filepath.Base(dst)+" "+q+" ro="+map[bool]string{true: "1", false: "0"}[ro])
	if err := os.Mkdir(dst, 0o700); err != nil {
		return err
	}
	b, _ := os.ReadFile(filepath.Join(src, "from"))
	if len(b) == 0 {
		b = []byte(filepath.Base(src))
	}
	return os.WriteFile(filepath.Join(dst, "from"), b, 0o600)
}

func (f *fakeBtrfs) Delete(p string) error {
	f.calls = append(f.calls, "delete "+filepath.Base(p))
	return os.RemoveAll(p)
}

func (f *fakeBtrfs) Exchange(a, b string) error {
	f.calls = append(f.calls, "exchange "+filepath.Base(a)+" "+filepath.Base(b))
	tmp := a + ".x"
	if err := os.Rename(a, tmp); err != nil {
		return err
	}
	if err := os.Rename(b, a); err != nil {
		return err
	}
	return os.Rename(tmp, b)
}

type dirAccounts struct{ ws, snaps string }

func (d dirAccounts) Lookup(a string) (Account, error) {
	acct, err := fakeAccounts{}.Lookup(a)
	acct.Workspace, acct.Snaps = d.ws, d.snaps
	return acct, err
}

func snapRig(t *testing.T) (*rig, *fakeBtrfs, dirAccounts) {
	r := newRig(t)
	dir := t.TempDir()
	d := dirAccounts{filepath.Join(dir, "workspaces", "claude"), filepath.Join(dir, "snapshots")}
	os.MkdirAll(d.ws, 0o700)
	fb := &fakeBtrfs{}
	r.t.cfg.Accounts, r.t.cfg.Btrfs = d, fb
	r.t.nested = func(string) ([]string, error) { return nil, nil }
	return r, fb, d
}

func (r *rig) adminTask(t *testing.T) string {
	t.Helper()
	req, err := r.t.newRequest("boxadmin", "claude", 3, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id := ids.New(ids.Task)
	if rep := r.t.start(id, "claude", "admin:"+req); rep["ok"] != true {
		t.Fatalf("start: %v", rep)
	}
	r.db.Exec(`UPDATE task_registry SET ended_at=1 WHERE task=?`, id)
	return id
}

func (r *rig) snaps(kind string) []string {
	var out []string
	rows, _ := r.db.Query(`SELECT id FROM workspace_snapshots WHERE kind=? ORDER BY id`, kind)
	defer rows.Close()
	for rows.Next() {
		var s string
		rows.Scan(&s)
		out = append(out, s)
	}
	return out
}

// #103: a read-only snapshot in the agent's qgroup before the launch, its INTENT bound to the workspace epoch and its
// taint copied; after 7 tasks the newest 5 task-start snapshots are kept and a clean-baseline one is never pruned.
func TestTaskStartSnapshot(t *testing.T) {
	r, fb, d := snapRig(t)
	r.db.Exec(`INSERT INTO workspace_snapshots(id, workspace, agent, kind, created_at) VALUES('snap_00000000000000000000000000','workspace:claude#1','claude','clean-baseline',1)`)
	r.wsTaint, r.wsEpoch = true, 4
	first := r.adminTask(t)
	var intent map[string]any
	for _, m := range r.recs() {
		if m["name"] == "workspace.snapshot" {
			intent = m
		}
	}
	snap := r.snaps("task-start")
	if len(snap) != 1 || intent == nil || intent["opId"] != snap[0] || intent["task"] != first ||
		intent["taintEpochs"].(map[string]int64)["workspace:claude#1"] != 4 {
		t.Fatalf("snapshot INTENT %v, rows %v", intent, snap)
	}
	if !slices.ContainsFunc(r.recs(), func(m map[string]any) bool { return m["type"] == "TAINT" && m["subject"] == "snap:"+snap[0] }) {
		t.Fatalf("the workspace taint was not copied to snap:%s: %v", snap[0], r.recs())
	}
	if want := "snapshot claude " + snap[0] + " 1/1 ro=1"; len(fb.calls) != 1 || fb.calls[0] != want || len(r.launch) != 1 {
		t.Fatalf("calls %v, want %q before the one launch", fb.calls, want)
	}
	if _, err := os.Stat(filepath.Join(d.snaps, snap[0])); err != nil {
		t.Fatal(err)
	}
	r.wsTaint = false
	for range 6 {
		r.adminTask(t)
	}
	if got := r.snaps("task-start"); len(got) != 5 || slices.Contains(got, snap[0]) || len(r.snaps("clean-baseline")) != 1 {
		t.Fatalf("after 7 tasks: task-start %v, clean-baseline %v", got, r.snaps("clean-baseline"))
	}
	if n := len(slices.DeleteFunc(slices.Clone(fb.calls), func(c string) bool { return !strings.HasPrefix(c, "delete ") })); n != 2 {
		t.Fatalf("%d deletes: %v", n, fb.calls)
	}
	if rep := r.t.undo(first, "rootd-admin:root"); rep["ok"] != false || !strings.Contains(rep["error"].(string), "pruned") {
		t.Fatalf("undo of a pruned snapshot: %v", rep)
	}
}

// A snapshot that fails stops the task before its container starts.
func TestTaskStartSnapshotFails(t *testing.T) {
	r, _, d := snapRig(t)
	os.WriteFile(d.snaps, nil, 0o600) // the snapshots dir can't be made
	req, _ := r.t.newRequest("boxadmin", "claude", 3, time.Hour)
	if rep := r.t.start(ids.New(ids.Task), "claude", "admin:"+req); rep["ok"] != false || rep["reason"] != "snapshot_failed" || len(r.launch) != 0 {
		t.Fatalf("start: %v, launches %d", rep, len(r.launch))
	}
}

// undo: pre-restore snapshot first, then a signed workspace.restore INTENT naming the agent's workspace and the
// snapshot, then the swap; it refuses while a task of the agent is live, and leaves no block.
func TestUndo(t *testing.T) {
	r, fb, d := snapRig(t)
	id := r.adminTask(t)
	snap := r.snaps("task-start")[0]
	os.WriteFile(filepath.Join(d.ws, "from"), []byte("after the task"), 0o600)

	live := ids.New(ids.Task)
	req, _ := r.t.newRequest("boxadmin", "claude", 3, time.Hour)
	r.t.start(live, "claude", "admin:"+req)
	if rep := r.t.undo(id, "rootd-admin:root"); rep["ok"] != false || !strings.Contains(rep["error"].(string), "task of this agent is running") {
		t.Fatalf("undo with a live task: %v", rep)
	}
	r.db.Exec(`UPDATE task_registry SET ended_at=1 WHERE task=?`, live)

	r.reset()
	fb.calls = nil
	rep := r.t.undo(id, "rootd-admin:root")
	if rep["ok"] != true || rep["snapshot"] != snap {
		t.Fatalf("undo: %v", rep)
	}
	if b, _ := os.ReadFile(filepath.Join(d.ws, "from")); string(b) != "claude" {
		t.Fatalf("workspace holds %q, want the start snapshot's tree", b)
	}
	pre := r.snaps("pre-restore")
	if len(pre) != 1 || rep["preRestore"] != pre[0] {
		t.Fatalf("pre-restore rows %v, reply %v", pre, rep)
	}
	if b, _ := os.ReadFile(filepath.Join(d.snaps, pre[0], "from")); string(b) != "after the task" {
		t.Fatalf("pre-restore holds %q", b)
	}
	var names []string
	var restore map[string]any
	for _, m := range r.recs() {
		n, _ := m["name"].(string)
		names = append(names, m["type"].(string)+" "+n)
		if m["name"] == "workspace.restore" {
			restore = m
		}
	}
	want := []string{"SUBJECT_ADD ", "INTENT workspace.snapshot", "RESULT ", "INTENT workspace.restore", "RESULT "}
	if !slices.Equal(names, want) || restore["signer"] != "rootd-admin:root" || restore["origin"] != "admin" || restore["agent"] != "claude" ||
		restore["workspace"] != "workspace:claude#1" || restore["args"].(map[string]string)["id"] != snap {
		t.Fatalf("records %q, restore %v", names, restore)
	}
	next := "claude.undo-" + snap
	if !slices.Equal(fb.calls[1:], []string{"snapshot " + snap + " " + next + " 1/1 ro=0", "exchange " + next + " claude", "delete " + next}) {
		t.Fatalf("calls %v", fb.calls)
	}
	if _, on, _ := attach.Blocked(r.db, "claude"); on {
		t.Fatal("undo left a block")
	}
	if rep := r.t.undo(ids.New(ids.Task), "x"); rep["ok"] != false {
		t.Fatalf("undo of an unknown task: %v", rep)
	}
}

// hookBtrfs runs during each snapshot, after the tree is taken.
type hookBtrfs struct {
	*fakeBtrfs
	during func()
}

func (h hookBtrfs) Snapshot(src, dst, q string, ro bool) error {
	err := h.fakeBtrfs.Snapshot(src, dst, q, ro)
	h.during()
	return err
}

// #184: a task that taints the workspace while the snapshot runs (the bytes it wrote are in the tree) taints
// snap:<id>, though the INTENT saw a clean workspace.
func TestTaskStartSnapshotTaintedDuring(t *testing.T) {
	r, fb, _ := snapRig(t)
	r.t.cfg.Btrfs = hookBtrfs{fb, func() { r.wsTaint = true }}
	r.adminTask(t)
	snap := r.snaps("task-start")
	if len(snap) != 1 || !slices.ContainsFunc(r.recs(), func(m map[string]any) bool { return m["type"] == "TAINT" && m["subject"] == "snap:"+snap[0] }) {
		t.Fatalf("rows %v: snap: not tainted: %v", snap, r.recs())
	}
}

// #184: when the TAINT of a tainted snapshot is not ACKed, the task fails and neither the row nor the subvolume is
// left for undo to restore with a clean label.
func TestTaskStartSnapshotTaintNotACKed(t *testing.T) {
	r, _, d := snapRig(t)
	r.wsTaint = true
	audit := r.t.audit
	r.t.audit = func(m map[string]any) error {
		if m["type"] == "TAINT" {
			return errors.New("auditd disk full")
		}
		return audit(m)
	}
	req, _ := r.t.newRequest("boxadmin", "claude", 3, time.Hour)
	if rep := r.t.start(ids.New(ids.Task), "claude", "admin:"+req); rep["ok"] != false || rep["reason"] != "snapshot_failed" || len(r.launch) != 0 {
		t.Fatalf("start: %v, launches %d", rep, len(r.launch))
	}
	if rows := r.snaps("task-start"); len(rows) != 0 {
		t.Fatalf("rows %v left", rows)
	}
	if es, _ := os.ReadDir(d.snaps); len(es) != 0 {
		t.Fatalf("subvolumes %v left", es)
	}
	var op string
	for _, m := range r.recs() {
		if m["name"] == "workspace.snapshot" {
			op, _ = m["opId"].(string)
		}
	}
	if !slices.ContainsFunc(r.recs(), func(m map[string]any) bool {
		return m["type"] == "RESULT" && m["opId"] == op && m["status"] == "failed"
	}) {
		t.Fatalf("no failed RESULT for %s: %v", op, r.recs())
	}
}

// #184: a nested subvolume refuses the task-start snapshot with NESTED_SUBVOLUME before its INTENT; the task fails.
func TestTaskStartSnapshotNested(t *testing.T) {
	r, fb, _ := snapRig(t)
	r.t.nested = func(string) ([]string, error) { return []string{"workspaces/claude/sub"}, nil }
	req, _ := r.t.newRequest("boxadmin", "claude", 3, time.Hour)
	rep := r.t.start(ids.New(ids.Task), "claude", "admin:"+req)
	if rep["ok"] != false || rep["reason"] != "snapshot_failed" || !strings.Contains(rep["error"].(string), "NESTED_SUBVOLUME") || len(r.launch) != 0 || len(fb.calls) != 0 {
		t.Fatalf("start: %v, launches %d, btrfs %v", rep, len(r.launch), fb.calls)
	}
	if slices.ContainsFunc(r.recs(), func(m map[string]any) bool { return m["name"] == "workspace.snapshot" }) {
		t.Fatalf("an INTENT was sent: %v", r.recs())
	}
}

// #184: a rootd that died between the swap and the delete left <ws>.undo-<snap>; the retried undo deletes it first.
func TestUndoLeftover(t *testing.T) {
	r, fb, d := snapRig(t)
	id := r.adminTask(t)
	snap := r.snaps("task-start")[0]
	if err := os.Mkdir(d.ws+".undo-"+snap, 0o700); err != nil {
		t.Fatal(err)
	}
	fb.calls = nil
	if rep := r.t.undo(id, "rootd-admin:root"); rep["ok"] != true {
		t.Fatalf("undo: %v", rep)
	}
	if fb.calls[0] != "delete claude.undo-"+snap {
		t.Fatalf("calls %v", fb.calls)
	}
}

type stopOnly struct{ attach.Runner }

func (stopOnly) Stop(string, string) error { return nil }

// #222: attach rescan, even with --ack-restart, keeps the hold of an undo that runs, so no task starts and no second
// undo runs mid-restore; once the undo ends, nothing is held.
func TestUndoHoldKept(t *testing.T) {
	r, fb, _ := snapRig(t)
	id := r.adminTask(t)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "data", "workspaces", "claude"), 0o755) // a clean scan, if rescan got that far
	s := &server{db: r.db, tasks: r.t, audit: r.t.audit, cfg: Config{AttachRoot: root, Attach: stopOnly{}}}
	var during []reply
	hooked := false
	r.t.cfg.Btrfs = hookBtrfs{fb, func() {
		if !hooked { // once: in the first snapshot, the pre-restore one
			hooked = true
			req, _ := r.t.newRequest("boxadmin", "claude", 3, time.Hour)
			during = append(during, s.rescan("claude", true), r.t.start(ids.New(ids.Task), "claude", "admin:"+req), r.t.undo(id, "rootd-admin:root"))
		}
	}}
	if rep := r.t.undo(id, "rootd-admin:root"); rep["ok"] != true {
		t.Fatalf("undo: %v", rep)
	}
	if len(during) != 3 || during[0]["blocked"] != true || !strings.Contains(fmt.Sprint(during[0]["error"]), "undo of this agent is running") ||
		during[1]["reason"] != "attach_blocked" || !strings.Contains(fmt.Sprint(during[2]["error"]), "another undo") {
		t.Fatalf("rescan, task start and undo during the undo: %v", during)
	}
	if rep := s.rescan("claude", false); rep["blocked"] != false || s.undoing("claude") != "" {
		t.Fatalf("after the undo: %v, undoing %q", rep, s.undoing("claude"))
	}
}
