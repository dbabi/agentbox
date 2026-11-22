package rootd

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"agentbox/internal/rootd/accounts"
	"agentbox/internal/rootd/attach"
	"agentbox/internal/rootd/resolve"
)

// §9: an allowlist edit is INTENT, ACK, effect, RESULT. With auditd down the INTENT gets no ACK and the list stays.
func TestEgressEditIsAudited(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "rootd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := resolve.Entry{Host: "evil.example", Port: 443}
	listed := func() bool {
		l, err := resolve.LoadLists(dir)
		return err == nil && l.AllowedAny("keys", e)
	}
	var recs []map[string]any
	down := true
	s := &server{cfg: Config{EgressDir: dir}, db: db, svc: &resolve.Service{DB: db, Dir: dir},
		audit: func(r map[string]any) error {
			if down {
				return errors.New("connect: no such file or directory")
			}
			r["listed"] = listed()
			recs = append(recs, r)
			return nil
		}}
	req := request{Op: "egress.allow", Svc: "keys", Entry: "evil.example:443"}
	if rep := s.admin(req, peer{}); rep["ok"] != false || listed() {
		t.Fatalf("auditd down: %v, listed %v", rep, listed())
	}
	down = false
	s.admin(req, peer{}) // the refill after it needs nft; the edit and its records are what count here
	if !listed() || len(recs) != 2 || recs[0]["type"] != "INTENT" || recs[0]["origin"] != "admin" || recs[0]["listed"] != false ||
		recs[1]["type"] != "RESULT" || recs[1]["opId"] != recs[0]["opId"] || recs[1]["status"] != "executed" || recs[1]["listed"] != true {
		t.Fatalf("records %v, listed %v", recs, listed())
	}
}

// agent.add and agent.remove are registry admin ops: INTENT, its ACK, the effect, RESULT. A nested subvolume refuses
// the removal before any INTENT and taints the workspace; a removed agent's uid is never handed out again.
func TestAgentOps(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "rootd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var recs []map[string]any
	var limits []uint64
	applied, nested := 0, map[string][]string{}
	s := &server{db: db, audit: func(r map[string]any) error { recs = append(recs, r); return nil },
		store:   func(a accounts.Agent, l uint64) error { limits = append(limits, l); return nil },
		nested:  func(p string) ([]string, error) { return nested[p], nil },
		applyOS: func() error { applied++; return nil }}
	call := func(op, args string) reply { return s.admin(request{Op: op, Args: json.RawMessage(args)}, peer{}) }
	if rep := call("agent.add", `{"name":"a","diskBytes":67108864}`); rep["ok"] != true || limits[0] != 64<<20 {
		t.Fatalf("add a: %v %v", rep, limits)
	}
	if len(recs) != 2 || recs[0]["type"] != "INTENT" || recs[0]["name"] != "agent.add" || recs[0]["origin"] != "admin" ||
		recs[1]["type"] != "RESULT" || recs[1]["status"] != "executed" || recs[1]["opId"] != recs[0]["opId"] || applied != 1 {
		t.Fatalf("records %v, applied %d", recs, applied)
	}
	for _, bad := range []string{`{"name":"A"}`, `{"name":"a","diskBytes":1}`, `{"name":"a","extra":1}`, `{}`} {
		if rep := call("agent.add", bad); rep["ok"] != false {
			t.Errorf("add %s: %v", bad, rep)
		}
	}
	call("agent.add", `{"name":"b"}`)
	b := accounts.Agent{N: 2, Name: "b"}
	nested[b.Storage()] = []string{"@var_lib_agentbox_data/agents/b/storage/x"}
	recs = nil
	rep := call("agent.remove", `{"name":"b"}`)
	if rep["ok"] != false || rep["code"] != "NESTED_SUBVOLUME" || rep["tainted"] != true || len(recs) != 1 ||
		recs[0]["type"] != "TAINT" || recs[0]["subject"] != "workspace:b" {
		t.Fatalf("nested: %v, records %v", rep, recs)
	}
	if a, err := accounts.Lookup(db, "b"); err != nil || a.N != 2 {
		t.Fatalf("a refused removal must leave b active: %v %v", a, err)
	}
	delete(nested, b.Storage())
	recs = nil
	if rep := call("agent.remove", `{"name":"nope"}`); rep["ok"] != false || len(recs) != 0 {
		t.Fatalf("removing an unknown agent: %v %v", rep, recs)
	}
	attach.BlockTask(db, "b", "task_x", time.Now()) // a block of the old b must not reach a new agent named b
	s.agentSeen("b").Add([]string{"old-b-token-AAAAAAAAAAAAAAAAAAAA"})
	if rep := call("agent.remove", `{"name":"b"}`); rep["ok"] != true || rep["agent"].(map[string]any)["active"] != false || applied != 3 {
		t.Fatalf("remove b: %v, applied %d", rep, applied)
	}
	if _, on, _ := attach.Blocked(db, "b"); on || len(s.agentSeen("b").All()) != 0 {
		t.Fatal("removing b left its task block or token versions")
	}
	c := call("agent.add", `{"name":"c"}`)["agent"].(map[string]any)
	if c["n"] != 3 || c["uid"] != 70003 {
		t.Fatalf("after removing b (n 2), c got %v", c)
	}
	if rep := call("agent.list", ""); rep["ok"] != true || len(rep["agents"].([]accounts.Agent)) != 3 {
		t.Fatalf("list: %v", rep)
	}
	recs = nil
	s.audit = func(map[string]any) error { return errors.New("down") }
	if rep := call("agent.add", `{"name":"d"}`); rep["ok"] != false {
		t.Fatalf("auditd down: %v", rep)
	}
	if _, err := accounts.Lookup(db, "d"); err != accounts.ErrNotFound {
		t.Fatalf("auditd down: d was allocated: %v", err)
	}
}
