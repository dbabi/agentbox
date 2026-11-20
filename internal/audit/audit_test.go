package audit

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type box struct {
	t      *testing.T
	dir    string
	s      *Server
	wall   int64
	boot   int64
	bootID string
	avail  uint64
	crash  string // point at which the next server panics, once
}

type crashed struct{ point string }

func newBox(t *testing.T) *box {
	b := &box{t: t, dir: t.TempDir(), wall: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC).UnixMilli(), boot: 5000, bootID: "boot-1", avail: 100 << 30}
	b.start()
	return b
}

func (b *box) hook(p string) {
	if p == b.crash {
		b.crash = ""
		panic(crashed{p})
	}
}

// start runs a fresh auditd process on the box's directory, as systemd would after a crash or reboot.
func (b *box) start() {
	b.t.Helper()
	if b.s != nil {
		b.s.Close()
	}
	files := &Files{Dir: b.dir, UID: os.Getuid(), GID: os.Getgid(), Crash: b.hook}
	b.s = &Server{Dir: b.dir, Seal: files, SegmentBytes: 2048, ReserveBytes: 1 << 20, Crash: b.hook, BootID: b.bootID,
		Wall: func() int64 { b.wall += 10; return b.wall }, Boot: func() int64 { b.boot += 10; return b.boot },
		Avail: func() (uint64, error) { return b.avail, nil }, Logf: b.t.Logf}
	if err := b.s.Start(); err != nil {
		b.t.Fatalf("Start: %v", err)
	}
}

// send handles one request; it reports a crash hook firing as a crashed reply instead of panicking the test.
func (b *box) send(p string, rec string) (rep Reply, crash string) {
	defer func() {
		if r := recover(); r != nil {
			c, ok := r.(crashed)
			if !ok {
				panic(r)
			}
			crash = c.point
		}
	}()
	uid := uint32(1000)
	if p == rootdProducer {
		uid = 0
	}
	return b.s.Handle(p, uid, 42, []byte(rec)), ""
}

func (b *box) ok(p, rec string) Reply {
	b.t.Helper()
	r, c := b.send(p, rec)
	if c != "" || !r.OK {
		b.t.Fatalf("%s %s: want ACK, got %+v (crash %q)", p, rec, r, c)
	}
	return r
}

func (b *box) nack(p, rec, code string) Reply {
	b.t.Helper()
	r, _ := b.send(p, rec)
	if r.OK || r.Code != code {
		b.t.Fatalf("%s %s: want NACK %s, got %+v", p, rec, code, r)
	}
	return r
}

func (b *box) taint(subject string) taintRow {
	b.t.Helper()
	tx, err := b.s.db.Begin()
	if err != nil {
		b.t.Fatal(err)
	}
	defer tx.Rollback()
	row, err := get(tx, subject)
	if err != nil {
		b.t.Fatal(err)
	}
	return row
}

func (b *box) verify() []SegReport {
	b.t.Helper()
	rep, err := VerifyDir(b.dir)
	if err != nil {
		b.t.Fatalf("verify: %v (%+v)", err, rep)
	}
	return rep
}

func TestChainVerifyAndTamper(t *testing.T) {
	b := newBox(t)
	for i := 0; i < 40; i++ { // several rotations at 2 KiB
		b.ok("proxy", `{"type":"TAINT","subject":"task:T1","source":"connect:example.com"}`)
	}
	b.start() // a restart in the same boot keeps the segment
	b.ok("agentboxd", `{"type":"DENY","id":"d1","code":"X"}`)
	rep := b.verify()
	if len(rep) < 3 {
		t.Fatalf("want rotations at 2 KiB, got %d segments", len(rep))
	}
	for _, r := range rep[:len(rep)-1] {
		if !r.Closed {
			t.Fatalf("%s not closed", SegName(r.Seg))
		}
	}
	// a changed byte in a sealed segment breaks the chain
	p := filepath.Join(b.dir, SegName(1))
	data, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(data), "connect:example.com", "connect:exbmple.com", 1)), 0o640)
	if _, err := VerifyDir(b.dir); err == nil {
		t.Fatal("verify passed a tampered segment")
	}
	os.WriteFile(p, data, 0o640)
	os.Remove(filepath.Join(b.dir, SegName(2)))
	if _, err := VerifyDir(b.dir); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("verify passed a missing segment: %v", err)
	}
}

func TestTornTail(t *testing.T) {
	b := newBox(t)
	b.ok("proxy", `{"type":"TAINT","subject":"task:T1","source":"s"}`)
	ns, _ := Segments(b.dir)
	p := filepath.Join(b.dir, SegName(ns[len(ns)-1]))
	f, _ := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString(`{"seq":99,"prev":"ab`) // a crash mid-append
	f.Close()
	if _, err := VerifyDir(b.dir); err != nil {
		t.Fatalf("an undeclared tail in the newest segment is not an error: %v", err)
	}
	b.start()
	b.ok("proxy", `{"type":"TAINT","subject":"task:T2","source":"s"}`)
	// crash again: once right after auditd's "\n", once mid-way through the torn record itself
	b.s.Close()
	f, _ = os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString("garbage\n{\"seq\":")
	f.Close()
	b.start()
	b.ok("proxy", `{"type":"TAINT","subject":"task:T3","source":"s"}`)
	torn := 0
	for _, r := range b.verify() {
		torn += len(r.Torn)
	}
	if torn != 2 {
		t.Fatalf("want 2 torn ranges, got %d", torn)
	}
}

func TestCrashMidSeal(t *testing.T) {
	for _, point := range []string{"close-written", "immutable-set", "next-created", "sealed"} {
		t.Run(point, func(t *testing.T) {
			b := newBox(t)
			b.crash = point
			for i := 0; ; i++ {
				_, c := b.send("proxy", `{"type":"TAINT","subject":"task:T1","source":"s"}`)
				if c != "" {
					break
				}
				if i > 100 {
					t.Fatal("no rotation")
				}
			}
			b.start()
			for i := 0; i < 30; i++ { // and through the next rotation
				b.ok("proxy", `{"type":"TAINT","subject":"task:T1","source":"s"}`)
			}
			b.verify()
		})
	}
}

func TestClockStepBackAcrossMidnight(t *testing.T) {
	b := newBox(t)
	b.wall = time.Date(2026, 11, 21, 0, 0, 30, 0, time.UTC).UnixMilli()
	b.ok("proxy", `{"type":"TAINT","subject":"task:T1","source":"s"}`) // the step forward is logged too
	b.wall = time.Date(2026, 11, 20, 23, 59, 30, 0, time.UTC).UnixMilli()
	b.ok("proxy", `{"type":"TAINT","subject":"task:T1","source":"s"}`)
	b.start()
	b.ok("proxy", `{"type":"TAINT","subject":"task:T1","source":"s"}`)
	rep := b.verify()
	if len(rep) != 1 || rep[0].ClockSteps != 2 {
		t.Fatalf("want one segment with 2 clock_step records, got %+v", rep)
	}
}

func TestNewBootRotates(t *testing.T) {
	b := newBox(t)
	b.ok("proxy", `{"type":"TAINT","subject":"task:T1","source":"s"}`)
	b.bootID, b.boot = "boot-2", 100 // CLOCK_BOOTTIME restarts
	b.start()
	b.ok("proxy", `{"type":"TAINT","subject":"task:T1","source":"s"}`)
	rep := b.verify()
	if len(rep) != 2 || !rep[0].Closed || rep[1].ClockSteps != 0 {
		t.Fatalf("want a rotation at the first start in a new boot and no clock_step across boots, got %+v", rep)
	}
}

func TestTaintWriteRules(t *testing.T) {
	b := newBox(t)
	b.ok("proxy", `{"type":"TAINT","subject":"workspace:alice","source":"connect:x"}`)
	if r := b.taint("workspace:alice"); !r.Tainted || r.Epoch != 1 {
		t.Fatalf("want tainted at epoch 1, got %+v", r)
	}
	b.ok("keys", `{"type":"TAINT","subject":"workspace:alice","source":"other","tainted":1}`) // re-taint: no epoch move
	if r := b.taint("workspace:alice"); r.Epoch != 1 {
		t.Fatalf("re-taint moved the epoch: %+v", r)
	}
	for _, p := range []string{"agentboxd", "proxy", "keys", "git"} {
		for _, rec := range []string{
			`{"type":"TAINT","subject":"workspace:alice","source":"x","tainted":0}`,
			`{"type":"TAINT","subject":"workspace:alice","source":"x","tainted":false}`,
			`{"type":"TAINT","subject":"workspace:alice","source":"x","epoch":7}`,
			`{"type":"INTENT","opId":"op-` + p + `","name":"taint.clear","origin":"admin","args":{"subject":"workspace:alice","contentId":"S1"},"taintEpochs":{"workspace:alice":1}}`,
			`{"type":"RESULT","opId":"op-` + p + `","name":"taint.clear","status":"executed"}`,
			`{"type":"WRITER_DEL","holder":"task:T1"}`,
		} {
			b.nack(p, rec, CodeViolation)
		}
	}
	if r := b.taint("workspace:alice"); !r.Tainted || r.Epoch != 1 {
		t.Fatalf("a clear from a non-rootd socket changed the subject: %+v", r)
	}
	b.nack(rootdProducer, `{"type":"TAINT","subject":"workspace:alice","source":"x","tainted":0}`, CodeBadRecord)
	clr := `{"type":"INTENT","opId":"op-1","name":"taint.clear","origin":"admin","signer":"boxadmin:ssh","args":{"subject":"workspace:alice","contentId":"S1"},"taintEpochs":{"workspace:alice":%d}}`
	r := b.nack(rootdProducer, strings.Replace(clr, "%d", "0", 1), CodeStale)
	if r.Moved["workspace:alice"] != 1 {
		t.Fatalf("STALE must name the current epoch: %+v", r)
	}
	b.nack(rootdProducer, `{"type":"RESULT","opId":"op-1","status":"executed"}`, CodeUnknownOp) // no INTENT yet
	b.ok(rootdProducer, strings.Replace(clr, "%d", "1", 1))
	b.nack(rootdProducer, strings.Replace(clr, "%d", "1", 1), CodeDuplicate)
	b.nack("agentboxd", `{"type":"RESULT","opId":"op-1","status":"executed"}`, CodeUnknownOp) // op-1 is rootd's
	if r := b.taint("workspace:alice"); !r.Tainted {
		t.Fatal("INTENT alone cleared")
	}
	if rep := b.ok(rootdProducer, `{"type":"RESULT","opId":"op-1","status":"executed"}`); rep.Applied == nil || !*rep.Applied {
		t.Fatalf("clear not applied: %+v", rep)
	}
	if r := b.taint("workspace:alice"); r.Tainted || r.Epoch != 2 {
		t.Fatalf("want the row kept, clean at epoch 2, got %+v", r)
	}
	b.ok("proxy", `{"type":"TAINT","subject":"workspace:alice","source":"again"}`)
	if r := b.taint("workspace:alice"); !r.Tainted || r.Epoch != 3 {
		t.Fatalf("re-taint after a clear: want epoch 3, got %+v", r)
	}
	// a clear whose epoch moved between INTENT and RESULT doesn't apply
	b.ok(rootdProducer, strings.Replace(strings.Replace(clr, "op-1", "op-2", 1), "%d", "3", 1))
	b.ok(rootdProducer, `{"type":"INTENT","opId":"op-3","name":"workspace.restore","origin":"admin","signer":"boxadmin:ssh","args":{"workspace":"workspace:alice","snapshot":"S9"}}`)
	if rep := b.ok(rootdProducer, `{"type":"RESULT","opId":"op-2","status":"executed"}`); rep.Applied == nil || *rep.Applied {
		t.Fatalf("a clear applied after its epoch moved: %+v", rep)
	}
	if r := b.taint("workspace:alice"); !r.Tainted || r.Epoch != 4 {
		t.Fatalf("restore: want max(tainted, clean)=tainted at epoch 4, got %+v", r)
	}
	b.nack(rootdProducer, `{"type":"INTENT","opId":"op-4","name":"taint.clear","origin":"admin","args":{"subject":"task:T1","contentId":"x"},"taintEpochs":{"task:T1":0}}`, CodeBadRecord)
	if _, err := b.s.db.Exec("DELETE FROM taint"); err == nil {
		t.Fatal("taint rows must never be deleted")
	}
	b.verify()
}

func TestWritersAndTaintGet(t *testing.T) {
	b := newBox(t)
	b.ok(rootdProducer, `{"type":"WRITER_ADD","holder":"task:T1","workspace":"workspace:alice"}`)
	b.ok(rootdProducer, `{"type":"WRITER_ADD","holder":"session:S1","workspace":"workspace:bob"}`)
	b.ok(rootdProducer, `{"type":"SUBJECT_ADD","task":"task:T1","subject":"task:P0"}`)
	b.nack("agentboxd", `{"type":"WRITER_ADD","holder":"task:T9","workspace":"workspace:alice"}`, CodeViolation)
	b.ok("keys", `{"type":"TAINT","subject":"task:T1","source":"llm"}`)
	if r := b.taint("workspace:alice"); !r.Tainted || r.Epoch != 1 {
		t.Fatalf("tainting a writer must taint its workspace in the same commit: %+v", r)
	}
	b.ok(rootdProducer, `{"type":"TAINT","subject":"session:S1","source":"attach"}`)
	b.ok(rootdProducer, `{"type":"WRITER_ADD","holder":"session:S2","workspace":"workspace:carol"}`)
	b.ok(rootdProducer, `{"type":"TAINT","subject":"session:S2","source":"attach"}`)
	for holder, kind := range map[string]string{"task:T1": "task", "session:S1": "session"} {
		rep := b.ok("agentboxd", `{"type":"taint.get","holder":"`+holder+`"}`)
		if len(rep.View.Writers) != 1 || rep.View.Writers[0].Kind != kind {
			t.Fatalf("taint.get %s: want one writer of kind %s, got %+v", holder, kind, rep.View)
		}
	}
	rep := b.ok("agentboxd", `{"type":"taint.get","holder":"task:T1"}`)
	got := map[string]taintRow{}
	for _, s := range rep.View.Subjects {
		got[s.Subject] = s
	}
	if !got["task:T1"].Tainted || !got["workspace:alice"].Tainted || got["task:P0"].Tainted || len(got) != 3 {
		t.Fatalf("taint.get subjects: %+v", rep.View.Subjects)
	}
	b.nack("proxy", `{"type":"taint.get","holder":"task:T1"}`, CodeNotAllowed)
	// a tainted ref fetched by a clean task taints it and joins its subjects
	b.ok("git", `{"type":"TAINT","subject":"ref:site:main","source":"push"}`)
	b.ok("git", `{"type":"READ_INTENT","reader":"task:T5","source":"ref:site:main"}`)
	b.ok("git", `{"type":"READ_INTENT","reader":"task:T6","source":"ref:site:clean"}`)
	if !b.taint("task:T5").Tainted || b.taint("task:T6").Tainted {
		t.Fatal("READ_INTENT: taint(reader) |= taint(source)")
	}
	rep = b.ok("agentboxd", `{"type":"taint.get","holder":"task:T5"}`)
	if len(rep.View.Subjects) != 2 {
		t.Fatalf("want the fetched ref in T5's subjects: %+v", rep.View.Subjects)
	}
	b.ok(rootdProducer, `{"type":"WRITER_DEL","holder":"task:T1"}`)
	if rep := b.ok("agentboxd", `{"type":"taint.get","holder":"task:T1"}`); len(rep.View.Writers) != 0 {
		t.Fatal("WRITER_DEL left the row")
	}
	b.ok(rootdProducer, `{"type":"op.get","opId":"none"}`)
}

func TestDiskFull(t *testing.T) {
	b := newBox(t)
	res := filepath.Join(b.dir, ".reserve")
	if fi, err := os.Stat(res); err != nil || fi.Size() != 1<<20 {
		t.Fatalf("reserve missing at start: %v", err)
	}
	b.ok("proxy", `{"type":"TAINT","subject":"workspace:alice","source":"x"}`)
	b.avail = 1000 // below the reserve
	b.nack("proxy", `{"type":"TAINT","subject":"task:T1","source":"x"}`, CodeDiskFull)
	b.nack(rootdProducer, `{"type":"INTENT","opId":"op-a","name":"app.deploy","taintEpochs":{}}`, CodeDiskFull)
	b.nack("agentboxd", `{"type":"DENY","id":"d1"}`, CodeDiskFull)
	if _, err := os.Stat(res); !os.IsNotExist(err) {
		t.Fatal("disk-full mode keeps the reserve")
	}
	b.ok(rootdProducer, `{"type":"INTENT","opId":"op-c","name":"taint.clear","origin":"admin","signer":"boxadmin:ssh","args":{"subject":"workspace:alice","contentId":"S1"},"taintEpochs":{"workspace:alice":1}}`)
	b.ok(rootdProducer, `{"type":"RESULT","opId":"op-c","status":"executed"}`)
	b.ok(rootdProducer, `{"type":"INTENT","opId":"op-r","name":"agent.remove","origin":"admin","signer":"boxadmin:ssh","args":{"agent":"bob"}}`)
	b.ok(rootdProducer, `{"type":"RESULT","opId":"op-r","status":"executed"}`)
	if r := b.taint("workspace:alice"); r.Tainted {
		t.Fatal("taint.clear did not run in disk-full mode")
	}
	b.avail = 1<<20 + 1<<30 - 1 // not yet above reserve + 1 GiB
	b.nack("proxy", `{"type":"TAINT","subject":"task:T1","source":"x"}`, CodeDiskFull)
	b.avail = 10 << 30
	b.ok("proxy", `{"type":"TAINT","subject":"task:T1","source":"x"}`)
	if _, err := os.Stat(res); err != nil {
		t.Fatal("reserve not recreated")
	}
	b.verify()
}

func TestPeerCred(t *testing.T) {
	b := newBox(t)
	sock := filepath.Join(t.TempDir(), "p.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go b.s.Serve(l, Producer{"proxy", uint32(os.Getuid()) + 1})
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte(`{"type":"TAINT","subject":"task:T1","source":"x"}` + "\n"))
	var rep Reply
	if err := json.NewDecoder(c).Decode(&rep); err != nil || rep.OK || rep.Code != CodeNotAllowed {
		t.Fatalf("a peer with another uid must be refused: %+v %v", rep, err)
	}
	c.Close()
	l2, _ := net.Listen("unix", sock+"2")
	defer l2.Close()
	go b.s.Serve(l2, Producer{"proxy", uint32(os.Getuid())})
	c, _ = net.Dial("unix", sock+"2")
	defer c.Close()
	c.Write([]byte(`{"type":"TAINT","subject":"task:T1","source":"x"}` + "\n"))
	if err := json.NewDecoder(c).Decode(&rep); err != nil || !rep.OK {
		t.Fatalf("own uid: %+v %v", rep, err)
	}
}
