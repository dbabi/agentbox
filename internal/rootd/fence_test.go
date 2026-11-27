package rootd

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"agentbox/internal/ids"
	"agentbox/internal/ops"
	"agentbox/internal/rootd/accounts"
)

// #79: inconsistent qgroups freeze every agent slice and refuse writing ops BUSY with one alert; a failed rescan keeps
// the fence; only a rescan that leaves the flag at 0 thaws, and reads still pass while it is up.
func TestQuotaFence(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "rootd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cg := t.TempDir()
	a, err := accounts.Add(db, "claude", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	slice := filepath.Join(cg, "user.slice", "user-"+strconv.Itoa(a.UID())+".slice")
	if err := os.MkdirAll(slice, 0o755); err != nil || os.WriteFile(filepath.Join(slice, "cgroup.freeze"), []byte("0"), 0o644) != nil {
		t.Fatal(err)
	}
	proxy := filepath.Join(cg, "system.slice", ProxyUnit) // the proxy fills data/cache (§6.2), so it freezes too
	if err := os.MkdirAll(proxy, 0o755); err != nil || os.WriteFile(filepath.Join(proxy, "cgroup.freeze"), []byte("0"), 0o644) != nil {
		t.Fatal(err)
	}
	frozen := func() string {
		b, _ := os.ReadFile(filepath.Join(slice, "cgroup.freeze"))
		if p, _ := os.ReadFile(filepath.Join(proxy, "cgroup.freeze")); string(p) != string(b) {
			return "slice " + string(b) + ", proxy " + string(p)
		}
		return string(b)
	}
	flag, rescanErr, rescans, limits := true, errors.New("no space"), 0, 0
	var alerts atomic.Int32
	s := &server{db: db, tasks: &tasks{}, cfg: Config{Tasks: TaskConfig{Cgroup: cg}, Alert: func(_, _ string) error { alerts.Add(1); return nil },
		Effects: map[string]Effect{"file.write": func(string, map[string]any) (map[string]any, error) { return nil, nil }}},
		audit:        func(map[string]any) error { return nil },
		inconsistent: func() (bool, error) { return flag, nil },
		qrescan:      func() error { rescans++; return rescanErr },
		qlimit:       func() error { limits++; return nil }}
	// a BUSY that passes the denial schema and names no reason (§5.6 leak rule 6)
	busy := func(rep reply) bool {
		d, ok := rep["denial"].(ops.Denial)
		_, err := ops.ParseDenial(d.JSON())
		return ok && d.Code == "BUSY" && err == nil && d.Rule == "" && d.What == ""
	}
	write := request{Op: "task.op", Name: "file.write", Task: "T1", Agent: "claude", Args: json.RawMessage(`{"path":"/srv/a/x","content":"x"}`)}

	if f, err := s.checkQuota(); !f || err == nil || frozen() != "1" || !s.fenced.Load() {
		t.Fatalf("inconsistent, rescan fails: fenced %v %v, freeze %q", f, err, frozen())
	}
	if !busy(s.taskOp(write)) || !busy(s.handle(sockGate, peer{}, request{Op: "task.start", Task: "T1", Agent: "claude"})) ||
		!busy(s.admin(request{Op: "task.new", Agent: "claude"}, peer{})) || !busy(s.admin(request{Op: "task.undo", Task: "T1"}, peer{})) {
		t.Fatal("writing ops not refused BUSY while fenced")
	}
	if d, _ := s.taskOp(request{Op: "task.op", Name: "disk.usage", Task: "T1", Agent: "claude", Args: json.RawMessage(`{}`)})["denial"].(ops.Denial); d.Code != "FLOOR_NEVER" {
		t.Fatalf("a read must pass the fence (and stop at not_built): %+v", d)
	}
	s.checkQuota()
	if rescans != 2 || alerts.Load() != 1 {
		t.Fatalf("a retry: %d rescans, %d alerts (want 2 and 1)", rescans, alerts.Load())
	}

	rescanErr = nil // the rescan succeeds but the flag stays set: still fenced
	if f, _ := s.checkQuota(); !f || frozen() != "1" {
		t.Fatalf("flag still 1 after the rescan: fenced %v, freeze %q", f, frozen())
	}
	if limits != 0 { // #209: 2/0's referenced count is wrong while the flag is set
		t.Fatalf("2/0's limit moved %d times while qgroups were inconsistent", limits)
	}
	s.qrescan = func() error { flag = false; return nil }
	if f, err := s.checkQuota(); f || err != nil || frozen() != "0" || s.fenced.Load() || limits != 1 {
		t.Fatalf("repaired: fenced %v %v, freeze %q, %d limit moves", f, err, frozen(), limits)
	}
	if rep := s.taskOp(write); rep["ok"] != true {
		t.Fatalf("after the thaw: %v", rep)
	}
	os.WriteFile(filepath.Join(slice, "cgroup.freeze"), []byte("1"), 0o644) // someone else's freeze: a consistent check keeps it
	os.WriteFile(filepath.Join(proxy, "cgroup.freeze"), []byte("1"), 0o644)
	s.checkQuota()
	if frozen() != "1" || alerts.Load() != 1 || limits != 2 {
		t.Fatalf("consistent check: freeze %q, %d alerts, %d limit moves", frozen(), alerts.Load(), limits)
	}
	s.fenced.Store(true) // rootd's start: the first consistent check thaws a freeze a dead rootd left
	if f, _ := s.checkQuota(); f || frozen() != "0" {
		t.Fatalf("start: fenced %v, freeze %q", f, frozen())
	}
}

type fakeDelete struct{ Btrfs }

func (fakeDelete) Delete(string) error { return nil }

// #79: a subvolume delete (a snapshot prune, an undo) is followed by a qgroup check.
func TestCheckedDeleteChecks(t *testing.T) {
	done := make(chan struct{})
	d := checkedBtrfs{fakeDelete{}, func() { close(done) }}
	if err := d.Delete(filepath.Join(t.TempDir(), "snap")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("no check after the delete")
	}
}

// #205: a task-start snapshot that leaves qgroups inconsistent (an agent reflinked a file from outside 1/N) raises the
// fence before the snapshot call returns: the task is refused BUSY with no launch, and the background repair runs.
// A flag that can't be read fences too, and so does a set flag whose fence a check that read the flag before the
// snapshot lowered again before the repair queued behind it ran. The hold file keeps the repair from ending before the
// launch looks.
func TestSnapshotFences(t *testing.T) {
	for _, c := range []struct {
		name    string
		readErr error
		lowered bool
	}{{"flag set", nil, false}, {"flag unreadable", errors.New("no uuid"), false}, {"fence lowered by a stale check", nil, true}} {
		r, fb, _ := snapRig(t)
		var flag atomic.Bool
		rescanned := make(chan struct{}, 1)
		hold := filepath.Join(t.TempDir(), "hold")
		os.WriteFile(hold, nil, 0o600)
		s := &server{db: r.db, tasks: r.t, cfg: Config{Tasks: TaskConfig{Cgroup: t.TempDir()}, QuotaHold: hold},
			audit:        func(map[string]any) error { return nil },
			inconsistent: func() (bool, error) { return flag.Load(), c.readErr },
			qrescan:      func() error { flag.Store(false); rescanned <- struct{}{}; return nil }}
		fence := s.fenceAfter
		if c.lowered { // the stale check holds fenceMu, so the repair waits, and lowers the fence on its way out
			s.fenceMu.Lock()
			fence = func() { s.fenceAfter(); s.fenced.Store(false) }
		}
		r.t.fenced = s.fencedNow
		r.t.cfg.Btrfs = checkedBtrfs{hookBtrfs{fb, func() { flag.Store(true) }}, fence}
		req, _ := r.t.newRequest("boxadmin", "claude", 3, time.Hour)
		rep := r.t.start(ids.New(ids.Task), "claude", "admin:"+req)
		if c.lowered {
			s.fenceMu.Unlock()
		}
		d, ok := rep["denial"].(ops.Denial)
		if rep["ok"] != false || !ok || d.Code != "BUSY" || rep["reason"] != "quota_fence" || len(r.launch) != 0 {
			t.Fatalf("%s: start %v, launches %d", c.name, rep, len(r.launch))
		}
		os.Remove(hold)
		if c.readErr == nil {
			select {
			case <-rescanned:
			case <-time.After(10 * time.Second):
				t.Fatalf("%s: no repair after the snapshot", c.name)
			}
		}
	}
	// a consistent flag after the snapshot: the task launches
	r, fb, _ := snapRig(t)
	s := &server{inconsistent: func() (bool, error) { return false, nil }}
	r.t.fenced = s.fencedNow
	r.t.cfg.Btrfs = checkedBtrfs{fb, s.fenceAfter}
	r.adminTask(t)
	if len(r.launch) != 1 || s.fenced.Load() {
		t.Fatalf("consistent: launches %d, fenced %v", len(r.launch), s.fenced.Load())
	}
}
