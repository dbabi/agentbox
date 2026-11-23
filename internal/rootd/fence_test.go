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

	"agentbox/internal/denial"
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
	frozen := func() string { b, _ := os.ReadFile(filepath.Join(slice, "cgroup.freeze")); return string(b) }
	flag, rescanErr, rescans := true, errors.New("no space"), 0
	var alerts atomic.Int32
	s := &server{db: db, tasks: &tasks{}, cfg: Config{Tasks: TaskConfig{Cgroup: cg}, Alert: func(_, _ string) error { alerts.Add(1); return nil },
		Effects: map[string]Effect{"file.write": func(string, map[string]any) (map[string]any, error) { return nil, nil }}},
		audit:        func(map[string]any) error { return nil },
		inconsistent: func() (bool, error) { return flag, nil },
		qrescan:      func() error { rescans++; return rescanErr }}
	busy := func(rep reply) bool {
		d, ok := rep["denial"].(denial.Denial)
		b, _ := json.Marshal(d)
		return ok && d.Code == denial.Busy && denial.Valid(b)
	}
	write := request{Op: "task.op", Name: "file.write", Task: "T1", Agent: "claude", Args: json.RawMessage(`{"path":"/srv/a/x","content":"x"}`)}

	if f, err := s.checkQuota(); !f || err == nil || frozen() != "1" || !s.fenced.Load() {
		t.Fatalf("inconsistent, rescan fails: fenced %v %v, freeze %q", f, err, frozen())
	}
	if !busy(s.taskOp(write)) || !busy(s.handle(sockGate, peer{}, request{Op: "task.start", Task: "T1", Agent: "claude"})) ||
		!busy(s.admin(request{Op: "task.new", Agent: "claude"}, peer{})) {
		t.Fatal("writing ops not refused BUSY while fenced")
	}
	if d, _ := s.taskOp(request{Op: "task.op", Name: "disk.usage", Task: "T1", Agent: "claude", Args: json.RawMessage(`{}`)})["denial"].(denial.Denial); d.Rule != "floor.not_built" {
		t.Fatalf("a read must pass the fence (and stop at not_built): %+v", d)
	}
	s.checkQuota()
	time.Sleep(100 * time.Millisecond) // the alert goes from its own goroutine
	if rescans != 2 || alerts.Load() != 1 {
		t.Fatalf("a retry: %d rescans, %d alerts (want 2 and 1)", rescans, alerts.Load())
	}

	rescanErr = nil // the rescan succeeds but the flag stays set: still fenced
	if f, _ := s.checkQuota(); !f || frozen() != "1" {
		t.Fatalf("flag still 1 after the rescan: fenced %v, freeze %q", f, frozen())
	}
	s.qrescan = func() error { flag = false; return nil }
	if f, err := s.checkQuota(); f || err != nil || frozen() != "0" || s.fenced.Load() {
		t.Fatalf("repaired: fenced %v %v, freeze %q", f, err, frozen())
	}
	if rep := s.taskOp(write); rep["ok"] != true {
		t.Fatalf("after the thaw: %v", rep)
	}
	os.WriteFile(filepath.Join(slice, "cgroup.freeze"), []byte("1"), 0o644) // someone else's freeze: a consistent check keeps it
	s.checkQuota()
	if frozen() != "1" || alerts.Load() != 1 {
		t.Fatalf("consistent check: freeze %q, %d alerts", frozen(), alerts.Load())
	}
	s.fenced.Store(true) // rootd's start: the first consistent check thaws a freeze a dead rootd left
	if f, _ := s.checkQuota(); f || frozen() != "0" {
		t.Fatalf("start: fenced %v, freeze %q", f, frozen())
	}
}
