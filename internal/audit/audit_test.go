package audit

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	b := &box{t: t, dir: tempDir(t), wall: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC).UnixMilli(), boot: 5000, bootID: "boot-1", avail: 100 << 30}
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
		if errors.Is(err, syscall.EPERM) && strings.Contains(err.Error(), "chattr") {
			// the unprivileged CI go test lands here; CI's sudo step reruns this package and fails on any skip
			b.t.Skipf("skipped: chattr needs CAP_LINUX_IMMUTABLE, as rootd has (§9); run as root to cover it: %v", err)
		}
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
	b.ok("agentboxd", `{"type":"DENY","id":"dn_01JF0000000000000000000000","code":"EGRESS_NOT_ALLOWLISTED","by":"proxy","subject":{"host":"x.example","port":443},"count":1,"first":1,"last":1}`)
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
	unlock(t, p) // as root the sealed segment is immutable; an attacker with CAP_LINUX_IMMUTABLE clears that first
	if err := os.WriteFile(p, []byte(strings.Replace(string(data), "connect:example.com", "connect:exbmple.com", 1)), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDir(b.dir); err == nil {
		t.Fatal("verify passed a tampered segment")
	}
	if err := os.WriteFile(p, data, 0o640); err != nil {
		t.Fatal(err)
	}
	unlock(t, filepath.Join(b.dir, SegName(2)))
	if err := os.Remove(filepath.Join(b.dir, SegName(2))); err != nil {
		t.Fatal(err)
	}
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
	b.ok(rootdProducer, `{"type":"INTENT","opId":"op-3","name":"workspace.restore","origin":"admin","signer":"boxadmin:ssh","agent":"alice","args":{"id":"S9"}}`)
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
	b.nack("agentboxd", `{"type":"DENY","id":"dn_01JF0000000000000000000000","code":"EGRESS_NOT_ALLOWLISTED","by":"proxy","subject":{"host":"x.example","port":443},"count":1,"first":1,"last":1}`, CodeDiskFull)
	if _, err := os.Stat(res); !os.IsNotExist(err) {
		t.Fatal("disk-full mode keeps the reserve")
	}
	b.ok(rootdProducer, `{"type":"INTENT","opId":"op-c","name":"taint.clear","origin":"admin","signer":"boxadmin:ssh","args":{"subject":"workspace:alice","contentId":"S1"},"taintEpochs":{"workspace:alice":1}}`)
	b.ok(rootdProducer, `{"type":"RESULT","opId":"op-c","status":"executed"}`)
	b.ok(rootdProducer, `{"type":"INTENT","opId":"op-r","name":"agent.remove","origin":"admin","signer":"boxadmin:ssh","args":{"name":"bob"}}`)
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

// A clock step logged as the first thing of a rotation must come before close, so close still names its predecessor.
func TestClockStepThenRotate(t *testing.T) {
	b := newBox(t)
	for i := 0; i < 30; i++ {
		b.wall -= 3_600_000 // every record follows a backward step
		b.ok("proxy", `{"type":"TAINT","subject":"task:T1","source":"`+strings.Repeat("p", 200)+`"}`)
	}
	if rep := b.verify(); len(rep) < 2 {
		t.Fatalf("want a rotation, got %+v", rep)
	}
}

// rootd dies at next-created while auditd stays up, then NTP steps the clock: the retried seal's new segment must
// still start with open, the clock_step after it.
func TestClockStepAcrossInterruptedSeal(t *testing.T) {
	b := newBox(t)
	b.crash = "next-created"
	for i := 0; ; i++ {
		if _, c := b.send("proxy", `{"type":"TAINT","subject":"task:T1","source":"s"}`); c != "" {
			break
		}
		if i > 100 {
			t.Fatal("no rotation")
		}
	}
	b.wall -= 2000
	b.ok("proxy", `{"type":"TAINT","subject":"task:T1","source":"s"}`)
	rep := b.verify()
	if last := rep[len(rep)-1]; last.ClockSteps != 1 {
		t.Fatalf("want the step logged in the new segment, got %+v", rep)
	}
	b.start()
	b.ok("proxy", `{"type":"TAINT","subject":"task:T1","source":"s"}`)
}

// rotate sends records until the crash hook fires at point.
func (b *box) rotate(point string) {
	b.t.Helper()
	b.crash = point
	for i := 0; i < 200; i++ {
		if _, c := b.send("proxy", `{"type":"TAINT","subject":"task:T1","source":"s"}`); c != "" {
			return
		}
	}
	b.t.Fatalf("no crash at %s", point)
}

func (b *box) newest() uint64 {
	ns, _ := Segments(b.dir)
	return ns[len(ns)-1]
}

// fault replaces the segment writes for one test: w and y return ok=false to fall through to the real call.
func fault(t *testing.T, w func(f *os.File, b []byte) (int, error, bool), y func(f *os.File) (error, bool)) {
	ow, oy := writeFile, syncFile
	t.Cleanup(func() { writeFile, syncFile = ow, oy })
	if w != nil {
		writeFile = func(f *os.File, b []byte) (int, error) {
			if n, err, ok := w(f, b); ok {
				return n, err
			}
			return ow(f, b)
		}
	}
	if y != nil {
		syncFile = func(f *os.File) error {
			if err, ok := y(f); ok {
				return err
			}
			return oy(f)
		}
	}
}

// after a fault: ACKs resume, the chain verifies, and so does a fresh start on it
func (b *box) recovers() {
	b.t.Helper()
	for i := 0; i < 30; i++ {
		b.ok("proxy", `{"type":"TAINT","subject":"task:T2","source":"s"}`)
	}
	b.verify()
	b.start()
	b.ok("proxy", `{"type":"TAINT","subject":"task:T3","source":"s"}`)
	b.verify()
}

// The audit dir is agentbox-audit's: a symlink or hard link planted at a segment name must not make rootd chown,
// chmod or chattr the file it points at.
func TestSegmentLinkRefused(t *testing.T) {
	victim := filepath.Join(tempDir(t), "victim")
	os.WriteFile(victim, []byte("x\n"), 0o604)
	untouched := func(what string) {
		t.Helper()
		if fi, err := os.Stat(victim); err != nil || fi.Mode().Perm() != 0o604 {
			t.Fatalf("%s: the link's target changed: %v %v", what, fi.Mode(), err)
		}
	}
	dir := tempDir(t)
	fs := &Files{Dir: dir, UID: os.Getuid(), GID: os.Getgid()}
	os.Symlink(victim, filepath.Join(dir, SegName(1)))
	if err := fs.Create(1); err == nil {
		t.Fatal("Create(1) followed a symlinked seg-000001")
	}
	untouched("Create")

	b := newBox(t)
	b.rotate("close-written") // seg N ends in close; seg N+1 does not exist yet
	n := b.newest()
	data, _ := os.ReadFile(filepath.Join(b.dir, SegName(n)))
	sc, err := ScanSegment(data, "", 0, false)
	if err != nil || !sc.Closed {
		t.Fatalf("%v %+v", err, sc)
	}
	next := filepath.Join(b.dir, SegName(n+1))
	fs = &Files{Dir: b.dir, UID: os.Getuid(), GID: os.Getgid()}
	os.Symlink(victim, next)
	if err := fs.Seal(n, sc.LastHash); err == nil {
		t.Fatal("Seal followed a symlinked next segment")
	}
	untouched("Seal, symlink")
	os.Remove(next)
	if err := os.Link(victim, next); err != nil {
		t.Skipf("skipped: this filesystem refuses hard links: %v", err)
	}
	if err := fs.Seal(n, sc.LastHash); err == nil {
		t.Fatal("Seal took a hard-linked next segment")
	}
	untouched("Seal, hard link")
}

// rootd stopped after +i, before the next segment: a restarted auditd must not open the immutable segment for write.
func TestRestartOnImmutableSegment(t *testing.T) {
	b := newBox(t)
	b.rotate("immutable-set")
	sealed := filepath.Join(b.dir, SegName(b.newest()))
	of := openFile
	t.Cleanup(func() { openFile = of })
	openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		if name == sealed && flag&(os.O_WRONLY|os.O_RDWR) != 0 {
			return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EPERM} // what +i does
		}
		return of(name, flag, perm)
	}
	b.start()
	b.recovers()
}

// rootd killed between creating the next segment and handing it to agentbox-audit: no seg N+1 exists yet, so a
// restarted auditd finds a closed seg N and asks for the seal again.
func TestCrashInCreateSeg(t *testing.T) {
	b := newBox(t)
	b.rotate("tmp-created")
	n := b.newest()
	if _, err := os.Stat(filepath.Join(b.dir, "."+SegName(n+1)+".new")); err != nil {
		t.Fatalf("no temporary segment: %v", err)
	}
	b.start()
	if b.newest() != n+1 {
		t.Fatalf("the restart did not finish the seal: newest %d", b.newest())
	}
	if m, _ := filepath.Glob(filepath.Join(b.dir, ".seg-*")); len(m) != 0 {
		t.Fatalf("leftover %v", m)
	}
	b.recovers()
}

// The new segment's open record fails to write (disk full right after the seal): no record may come before it.
func TestOpenWriteFails(t *testing.T) {
	for _, partial := range []int{0, 20} {
		b := newBox(t)
		armed := true
		fault(t, func(f *os.File, p []byte) (int, error, bool) {
			if !armed || !strings.Contains(string(p), `"type":"open"`) {
				return 0, nil, false
			}
			armed = false
			n, _ := f.Write(p[:partial])
			return n, syscall.EIO, true
		}, nil)
		for i := 0; armed; i++ {
			if i > 200 {
				t.Fatal("the fault never fired")
			}
			b.send("proxy", `{"type":"TAINT","subject":"task:T1","source":"s"}`)
		}
		b.recovers()
	}
}

// A record is cut short, then the torn record that declares it fails: the next record must still declare the bytes.
func TestTornWriteFails(t *testing.T) {
	for _, partial := range []int{0, 30} {
		b := newBox(t)
		b.ok("proxy", `{"type":"TAINT","subject":"task:T1","source":"s"}`)
		step := 0
		fault(t, func(f *os.File, p []byte) (int, error, bool) {
			switch {
			case step == 0 && strings.Contains(string(p), "task:F"):
				step++
				n, _ := f.Write(p[:40])
				return n, syscall.EIO, true
			case step == 1 && strings.Contains(string(p), `"type":"torn"`):
				step++
				n, _ := f.Write(p[:partial])
				return n, syscall.ENOSPC, true
			}
			return 0, nil, false
		}, nil)
		b.nack("proxy", `{"type":"TAINT","subject":"task:F","source":"s"}`, CodeUnavailable)
		b.nack("proxy", `{"type":"TAINT","subject":"task:G","source":"s"}`, CodeUnavailable)
		if step != 2 {
			t.Fatalf("faults fired: %d", step)
		}
		b.avail = 100 << 30
		b.recovers()
	}
}

// close is written but its fdatasync fails: nothing may be appended after close, and the seal still happens.
func TestCloseSyncFails(t *testing.T) {
	for _, e := range []error{syscall.EIO, syscall.ENOSPC} {
		b := newBox(t)
		closed, armed := false, true
		fault(t, func(f *os.File, p []byte) (int, error, bool) {
			closed = strings.Contains(string(p), `"type":"close"`)
			return 0, nil, false
		}, func(f *os.File) (error, bool) {
			if armed && closed {
				armed = false
				return e, true
			}
			return nil, false
		})
		for i := 0; armed; i++ {
			if i > 200 {
				t.Fatal("the fault never fired")
			}
			b.send("proxy", `{"type":"TAINT","subject":"task:T1","source":"s"}`)
		}
		b.recovers()
		if rep := b.verify(); len(rep) < 2 || !rep[0].Closed {
			t.Fatalf("%v: no seal after the failed sync: %+v", e, rep)
		}
	}
}

// auditd killed right after the seal, then NTP steps the clock before it restarts: the new segment logs the step.
func TestClockStepAcrossRestartOntoEmptySegment(t *testing.T) {
	b := newBox(t)
	b.rotate("sealed")
	b.wall -= 2000
	b.start()
	b.ok("proxy", `{"type":"TAINT","subject":"task:T1","source":"s"}`)
	rep := b.verify()
	if last := rep[len(rep)-1]; last.ClockSteps != 1 {
		t.Fatalf("want the step logged in the new segment, got %+v", rep)
	}
}

// A record loses only its final "\n" (a power cut, or a short write on ENOSPC): the torn mark must not turn it into a
// live record, or the records ACKed after it are declared torn at the next start and their seqs handed out again.
func TestTornJustBeforeNewline(t *testing.T) {
	tornRanges := func(b *box) int {
		n := 0
		for _, r := range b.verify() {
			n += len(r.Torn)
		}
		return n
	}
	t.Run("short write", func(t *testing.T) {
		b := newBox(t)
		b.ok("proxy", `{"type":"TAINT","subject":"task:T1","source":"s"}`)
		armed := true
		fault(t, func(f *os.File, p []byte) (int, error, bool) {
			if !armed || !strings.Contains(string(p), "task:F") {
				return 0, nil, false
			}
			armed = false
			n, _ := f.Write(p[:len(p)-1])
			return n, syscall.ENOSPC, true
		}, nil)
		b.nack("proxy", `{"type":"TAINT","subject":"task:F","source":"s"}`, CodeUnavailable)
		seqs := map[uint64]bool{}
		for i := 0; i < 3; i++ {
			seqs[b.ok("proxy", `{"type":"TAINT","subject":"task:T2","source":"s"}`).Seq] = true
		}
		b.start()
		if r := b.ok("proxy", `{"type":"TAINT","subject":"task:T3","source":"s"}`); seqs[r.Seq] {
			t.Fatalf("seq %d handed out again after the restart", r.Seq)
		}
		if n := tornRanges(b); n != 1 {
			t.Fatalf("want 1 torn range, got %d", n)
		}
		b.recovers() // and the next rotation still seals
	})
	t.Run("power cut", func(t *testing.T) {
		b := newBox(t)
		b.ok("proxy", `{"type":"TAINT","subject":"task:T1","source":"s"}`)
		b.s.Close()
		p := filepath.Join(b.dir, SegName(b.newest()))
		data, _ := os.ReadFile(p)
		sc, _ := ScanSegment(data, "", 0, false)
		line, _ := json.Marshal(Record{Seq: sc.Last.Seq + 1, Prev: sc.LastHash, TsWall: b.wall, TsBoot: b.boot, BootID: b.bootID,
			Type: "TAINT", Producer: "proxy", UID: 1000, Body: json.RawMessage(`{}`)})
		f, _ := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
		f.Write(line) // every byte but the "\n"
		f.Close()
		b.start()
		seq := b.ok("proxy", `{"type":"TAINT","subject":"task:T2","source":"s"}`).Seq
		b.start()
		if r := b.ok("proxy", `{"type":"TAINT","subject":"task:T3","source":"s"}`); r.Seq != seq+1 {
			t.Fatalf("want seq %d after the restart, got %d", seq+1, r.Seq)
		}
		if n := tornRanges(b); n != 1 {
			t.Fatalf("want 1 torn range, got %d", n)
		}
		b.recovers()
	})
}

// auditd dies mid-way through the new segment's open, then the wall clock steps before it restarts in the same boot:
// the torn record may come before open, the clock_step only after it.
func TestClockStepAfterPartialOpen(t *testing.T) {
	b := newBox(t)
	b.rotate("sealed")
	f, _ := os.OpenFile(filepath.Join(b.dir, SegName(b.newest())), os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString(`{"seq":`)
	f.Close()
	b.wall -= 5000
	b.start()
	b.ok("proxy", `{"type":"TAINT","subject":"task:T1","source":"s"}`)
	rep := b.verify()
	if last := rep[len(rep)-1]; last.ClockSteps != 1 || len(last.Torn) != 1 {
		t.Fatalf("want the torn open and the step logged in the new segment, got %+v", rep)
	}
	b.start()
	b.ok("proxy", `{"type":"TAINT","subject":"task:T2","source":"s"}`)
	b.verify()
}

// auditd may die between writing close and its fdatasync; the seal then fsyncs the segment before it sets +i and
// creates the successor, so a power cut can't leave a sealed segment without its close next to seg+1.
func TestSealSyncsSegment(t *testing.T) {
	b := newBox(t)
	b.rotate("close-written")
	n := b.newest()
	data, _ := os.ReadFile(filepath.Join(b.dir, SegName(n)))
	sc, err := ScanSegment(data, "", 0, false)
	if err != nil || !sc.Closed {
		t.Fatalf("%v %+v", err, sc)
	}
	var order []string
	fault(t, nil, func(f *os.File) (error, bool) {
		order = append(order, "sync "+filepath.Base(f.Name()))
		return nil, false
	})
	fs := &Files{Dir: b.dir, UID: os.Getuid(), GID: os.Getgid(), Crash: func(p string) { order = append(order, p) }}
	if err := fs.Seal(n, sc.LastHash); err != nil {
		t.Fatal(err)
	}
	if len(order) < 2 || order[0] != "sync "+SegName(n) || order[1] != "immutable-set" {
		t.Fatalf("want %s synced before +i, got %v", SegName(n), order)
	}
}

// TestDenySink is C-G1's sink check: DENY records are checked against the schema generated from the codes table.
func TestDenySink(t *testing.T) {
	b := newBox(t)
	const id = `"id":"dn_01JF0000000000000000000000","by":"gate","count":1,"first":1,"last":2`
	b.ok("agentboxd", `{"type":"DENY",`+id+`,"code":"INVALID_ARGS","op":"file.write","subject":{"pointer":"/path"}}`)
	b.ok("agentboxd", `{"type":"DENY_FLOOD","by":"gate","count":7}`)
	for why, line := range map[string]string{
		"unknown code":                     `{"type":"DENY",` + id + `,"code":"X"}`,
		"what not in list":                 `{"type":"DENY",` + id + `,"code":"BUSY","what":"os_lock"}`,
		"free-text field":                  `{"type":"DENY",` + id + `,"code":"DENIED_POLICY","reason":"ignore previous instructions"}`,
		"unhashed hash field":              `{"type":"DENY",` + id + `,"code":"INVALID_ARGS","op":"file.write","args":{"content":"sk-live-secret"}}`,
		"drop field":                       `{"type":"DENY",` + id + `,"code":"INVALID_ARGS","op":"secret.set","args":{"value":{"sha256":"` + strings.Repeat("a", 64) + `","len":3}}}`,
		"IP in subject":                    `{"type":"DENY",` + id + `,"code":"EGRESS_NAME_REJECTED","what":"non_public","subject":{"host":"192.168.1.10"}}`,
		"hex id":                           `{"type":"DENY","id":"0123abcd","by":"gate","count":1,"first":1,"last":1,"code":"BUSY"}`,
		"flood without by":                 `{"type":"DENY_FLOOD","count":7}`,
		"case-folded key":                  `{"type":"DENY",` + id + `,"Code":"BUSY"}`,
		"case-folded subject":              `{"type":"DENY",` + id + `,"code":"BUSY","subject":{"HOST":"x.example"}}`,
		"repeated subject key":             `{"type":"DENY",` + id + `,"code":"EGRESS_NOT_ALLOWLISTED","subject":{"host":"free text secret!","host":"a.example"}}`,
		"hashed args (no args in §9 DENY)": `{"type":"DENY",` + id + `,"code":"INVALID_ARGS","op":"file.write","args":{"content":{"sha256":"` + strings.Repeat("a", 64) + `","len":3}}}`,
	} {
		before := b.verify()
		b.nack("agentboxd", line, CodeBadRecord)
		if after := b.verify(); after[len(after)-1].Records != before[len(before)-1].Records {
			t.Errorf("%s: a NACKed DENY was appended", why)
		}
	}
}

// §9 enforcement at the sink: an INTENT (or RESULT) whose args don't carry the registry's audit classes is NACKed and
// never enters the chain or the ops table, so no RESULT for it is ever accepted and the effect never runs.
func TestSinkCheck(t *testing.T) {
	b := newBox(t)
	h := `{"sha256":"` + strings.Repeat("a", 64) + `","len":5}`
	big := strings.Repeat("x", 1025)
	for _, c := range []struct{ rec, why string }{
		{`{"type":"INTENT","opId":"s1","name":"secret.set","origin":"admin","args":{"name":"k","value":"sk-live-123"}}`, "/args/value: drop-class"},
		{`{"type":"INTENT","opId":"s2","name":"gh.pr.comment","args":{"remote":"r","number":1,"body":"hello"}}`, "/args/body: hash-class"},
		{`{"type":"INTENT","opId":"s3","name":"file.write","args":{"path":"/srv/a/x","content":{"sha256":"zz","len":5}}}`, "/args/content: hash-class"},
		{`{"type":"INTENT","opId":"s4","name":"file.write","args":{"path":"/srv/a/x","content":` + h + `,"token":"t"}}`, "/args/token: undeclared"},
		{`{"type":"INTENT","opId":"s5","name":"file.write","args":{"path":"` + big + `","content":` + h + `}}`, "/args/path: keep-class string over"},
		{`{"type":"INTENT","opId":"s6","name":"egress.allow","origin":"admin","args":{"svc":"keys","entry":"` + big + `"}}`, "/args/entry: keep-class"},
		{`{"type":"INTENT","opId":"s7","name":"ask.batch","args":{"shape":"push+pr","ops":[{"name":"gh.pr.create","args":{"remote":"r","head":"h","base":"main","title":"t","body":` + h + `}}]}}`, "/args/ops/0/args/title: hash-class"},
	} {
		if r := b.nack(rootdProducer, c.rec, CodeBadRecord); !strings.Contains(r.Detail, c.why) || strings.Contains(r.Detail, "sk-live") {
			t.Errorf("%s: detail %q, want %q and no value", c.rec, r.Detail, c.why)
		}
	}
	b.nack(rootdProducer, `{"type":"RESULT","opId":"s1","status":"executed"}`, CodeUnknownOp)
	b.ok(rootdProducer, `{"type":"INTENT","opId":"g1","name":"file.write","args":{"path":"/srv/a/x","content":`+h+`}}`)
	b.ok(rootdProducer, `{"type":"INTENT","opId":"g2","name":"app.logs","args":{"app":"a"}}`)
	b.nack(rootdProducer, `{"type":"RESULT","opId":"g2","status":"executed","outputs":{"log":["line"]}}`, CodeBadRecord)
	b.ok(rootdProducer, `{"type":"RESULT","opId":"g2","status":"executed","outputs":{"log":`+h+`}}`)
	for _, r := range b.verify() {
		data, _ := os.ReadFile(filepath.Join(b.dir, SegName(r.Seg)))
		if strings.Contains(string(data), "sk-live") || strings.Contains(string(data), `"hello"`) {
			t.Fatalf("%s holds a NACKed value", SegName(r.Seg))
		}
	}
}
