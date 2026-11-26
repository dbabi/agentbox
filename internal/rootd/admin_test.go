package rootd

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentbox/internal/rootd/accounts"
	"agentbox/internal/rootd/attach"
	"agentbox/internal/rootd/resolve"
	"agentbox/internal/taskenv"
)

// App. E: rootd.db is 0600 even when opened under umask 0022 (agentbox reconcile opens it first), and every table is
// STRICT.
func TestOpenDBModeAndStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rootd.db")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("rootd.db mode %v, %v: want 0600", fi.Mode().Perm(), err)
	}
	rows, err := db.Query(`SELECT name, sql FROM sqlite_master WHERE type='table'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var name, sql string
		if err := rows.Scan(&name, &sql); err != nil {
			t.Fatal(err)
		}
		n++
		if !strings.HasSuffix(strings.TrimSpace(sql), "STRICT") {
			t.Errorf("table %s is not STRICT", name)
		}
	}
	if err := rows.Err(); err != nil || n == 0 {
		t.Fatalf("%d tables, %v", n, err)
	}
}

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
		recs[0]["type"] != "TAINT" || recs[0]["subject"] != "workspace:b#2" {
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
	if _, on, _ := attach.Blocked(db, "b"); on || func() bool { all, _ := s.agentSeen("b").All(); return len(all) != 0 }() {
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

// go.private.set is audited like an egress edit; a bad pattern is refused before any INTENT.
func TestGoPrivateSet(t *testing.T) {
	dir := t.TempDir()
	var recs []map[string]any
	s := &server{cfg: Config{EgressDir: dir}, audit: func(r map[string]any) error { recs = append(recs, r); return nil }}
	p := "corp.example/*"
	if rep := s.admin(request{Op: "go.private.set", Agent: "ga", Patterns: &p}, peer{}); rep["ok"] != true || len(recs) != 2 || recs[0]["name"] != "go.private.set" {
		t.Fatalf("%v %v", rep, recs)
	}
	if gp, _ := taskenv.ReadGoPrivate(dir, "ga"); gp != p {
		t.Fatalf("patterns %q", gp)
	}
	bad := "a b"
	if rep := s.admin(request{Op: "go.private.set", Agent: "ga", Patterns: &bad}, peer{}); rep["ok"] != false || len(recs) != 2 {
		t.Fatalf("bad patterns: %v", rep)
	}
}

// #198: an error that names an agent-made path reaches the admin with each terminal control escaped, and the quotes the
// error already has kept.
func TestEscaped(t *testing.T) {
	in := "open \"a\x1b]52;c;eA==\a\u202eb\": é\u009b\xff"
	if got, want := escaped(in), `open "a\x1b]52;c;eA==\a\u202eb": é\u009b`+"\ufffd"; got != want {
		t.Fatalf("escaped(%q) = %q, want %q", in, got, want)
	}
}

// #222 R50: at stop rootd waits for the request lines in flight, holds new ones back, and gives up after its bound.
func TestDrain(t *testing.T) {
	var s server
	s.reqs.RLock() // a request in flight
	go func() { time.Sleep(100 * time.Millisecond); s.reqs.RUnlock() }()
	if !s.drain(5 * time.Second) {
		t.Fatal("drain gave up on a request that ended")
	}
	var s2 server
	s2.reqs.RLock() // one that outlives the bound
	t0 := time.Now()
	if s2.drain(200*time.Millisecond) || time.Since(t0) < 200*time.Millisecond {
		t.Fatal("drain did not wait out its bound")
	}
	held := make(chan struct{})
	go func() { s2.reqs.RLock(); close(held) }() // a new request line while rootd stops
	select {
	case <-held:
		t.Fatal("a new request ran during the drain")
	case <-time.After(200 * time.Millisecond):
	}
}

// countSeal is rootd's seal half that only counts its calls.
type countSeal struct{ n *int }

func (c countSeal) Create(uint64) error       { *c.n++; return nil }
func (c countSeal) Seal(uint64, string) error { *c.n++; return nil }

// #273: while rootd drains, it still answers. A new request line gets the typed stopping refusal at once and runs
// nothing: a task op gets the BUSY denial agentboxd relays, a resolve the broker's unavailable. The seal socket is
// served as before, since a RESULT in flight may need a seal. A request in flight writes its reply before the drain
// ends, and a client that never reads holds the drain up only until the write deadline.
func TestDrainAnswers(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "rootd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	seals := 0
	s := &server{db: db, seal: countSeal{&seals}, inconsistent: func() (bool, error) { close(entered); <-release; return false, nil }}
	// send writes line to name on a fresh connection and returns the client end; answer's error goes to done
	send := func(name, line string, done chan<- error) net.Conn {
		c, r := net.Pipe()
		go func() { err := s.answer(r, name, peer{}, []byte(line)); r.Close(); done <- err }()
		return c
	}
	read := func(c net.Conn) reply {
		t.Helper()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := bufio.NewReader(c).ReadBytes('\n')
		var rep reply
		if err != nil || json.Unmarshal(line, &rep) != nil {
			t.Fatalf("no reply: %v %q", err, line)
		}
		return rep
	}
	done1 := make(chan error, 1)
	c1 := send(sockAdmin, `{"op":"quota.check"}`, done1) // in flight: its handler waits for release
	<-entered
	drained := make(chan bool, 1)
	go func() { drained <- s.drain(10 * time.Second) }()
	for s.reqs.TryRLock() { // until the drain waits
		s.reqs.RUnlock()
		time.Sleep(time.Millisecond)
	}
	done := make(chan error, 4)
	if rep := read(send(sockAdmin, `{"op":"agent.list"}`, done)); rep["ok"] != false || rep["reason"] != "stopping" {
		t.Fatalf("admin request during the drain: %v", rep)
	}
	rep := read(send(sockGate, `{"op":"task.op","name":"file.write","task":"T1","agent":"claude"}`, done))
	if d, _ := rep["denial"].(map[string]any); rep["ok"] != false || d["code"] != "BUSY" || d["op"] != "file.write" {
		t.Fatalf("task op during the drain: %v", rep)
	}
	if rep := read(send("resolve-proxy", `{"op":"resolve","host":"example.com","port":443}`, done)); rep["reason"] != resolve.Unavailable {
		t.Fatalf("resolve during the drain: %v", rep)
	}
	if rep := read(send(sockSeal, `{"call":"audit.seal","seg":1,"last_hash":"h"}`, done)); rep["ok"] != true || seals != 1 {
		t.Fatalf("seal during the drain: %v, %d seals", rep, seals)
	}
	close(release)
	select {
	case <-drained:
		t.Fatal("the drain ended before the reply in flight was read")
	case <-time.After(300 * time.Millisecond):
	}
	if rep := read(c1); rep["ok"] != true || rep["fenced"] != false {
		t.Fatalf("the reply in flight: %v", rep)
	}
	if !<-drained || <-done1 != nil {
		t.Fatal("the drain did not end once the reply in flight was written")
	}

	// a client that never reads its reply
	defer func(d time.Duration) { replyTimeout = d }(replyTimeout)
	replyTimeout = 200 * time.Millisecond
	s2 := &server{db: db}
	c, r := net.Pipe()
	defer c.Close()
	go s2.answer(r, sockAdmin, peer{}, []byte(`{"op":"agent.list"}`))
	for s2.reqs.TryLock() { // until the request is in flight
		s2.reqs.Unlock()
		time.Sleep(time.Millisecond)
	}
	t0 := time.Now()
	if !s2.drain(5*time.Second) || time.Since(t0) > 2*time.Second {
		t.Fatalf("a client that never reads held the drain up for %v", time.Since(t0))
	}
}

// #273: a box set up wrong is a refusal, which systemd never restarts: rootd.db in another mode than WAL with
// synchronous=FULL, and no agentbox-audit user or group.
func TestStartRefusals(t *testing.T) {
	mem, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer mem.Close()
	if err := walFull(mem); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "journal_mode=memory") {
		t.Fatalf("an in-memory store: %v", err)
	}
	db, err := OpenDB(filepath.Join(t.TempDir(), "rootd.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, ok := lookupUID("agentbox-audit"); ok {
		t.Skip("skipped: this host has an agentbox-audit user")
	}
	if _, _, err := auditIDs(); !errors.Is(err, ErrRefused) {
		t.Fatalf("no agentbox-audit user: %v", err)
	}
}
