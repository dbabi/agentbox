package audit

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fuzz targets for auditd's inputs: producer request lines, segment files read back at start and by verify, and the
// line reader both sockets use (issue #10).

// FuzzScanSegment reads segment files as auditd's start and verify do. Its seeds come from a server on fakeSeal, so it
// fuzzes without root, as the nightly jobs run it (#270).
func FuzzScanSegment(f *testing.F) {
	dir := f.TempDir()
	s := fakeServer(f, dir, 2048) // small segments: the seeds hold sealed ones and the open one
	for i := 0; i < 30; i++ {
		if rep := s.Handle("proxy", 1000, 42, []byte(`{"type":"TAINT","subject":"task:T1","source":"connect:example.com"}`)); !rep.OK {
			f.Fatalf("seed record: %+v", rep)
		}
	}
	ns, _ := Segments(dir)
	for _, n := range ns {
		data, err := os.ReadFile(filepath.Join(dir, SegName(n)))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data, "", uint64(0), false)
		f.Add(append(data, "garbage\n{\"seq\":"...), ZeroHash, uint64(0), true)
	}
	f.Fuzz(func(t *testing.T, data []byte, prev string, seq uint64, anchor bool) {
		s, err := ScanSegment(data, prev, seq, anchor)
		if s == nil || s.End < 0 || s.End > s.Size || s.Undeclared() < 0 {
			t.Fatalf("scan %+v", s)
		}
		if err == nil && s.Records > 0 && (s.Last == nil || s.OpenRec == nil || data[s.End-1] != '\n') {
			t.Fatalf("scan %+v", s)
		}
	})
}

// fakeSeal is Files without chattr, so the fuzz server runs unprivileged on Linux too.
type fakeSeal struct{ dir string }

func (s fakeSeal) Create(seg uint64) error { return s.touch(seg) }
func (s fakeSeal) Seal(seg uint64, _ string) error {
	return s.touch(seg + 1)
}
func (s fakeSeal) touch(seg uint64) error {
	f, err := os.OpenFile(filepath.Join(s.dir, SegName(seg)), os.O_CREATE|os.O_RDONLY, 0o640)
	if err != nil {
		return err
	}
	return f.Close()
}

// fakeServer is a started auditd on dir with fakeSeal and test clocks; it closes when tb ends.
func fakeServer(tb testing.TB, dir string, segmentBytes int64) *Server {
	var wall, boot int64 = 1_800_000_000_000, 5000
	s := &Server{Dir: dir, Seal: fakeSeal{dir}, SegmentBytes: segmentBytes, ReserveBytes: 1 << 20, BootID: "boot-1",
		Wall: func() int64 { wall += 10; return wall }, Boot: func() int64 { boot += 10; return boot },
		Avail: func() (uint64, error) { return 100 << 30, nil }}
	if err := s.Start(); err != nil {
		tb.Fatal(err)
	}
	if err := s.Settle(); err != nil { // as the daemon, after READY=1
		tb.Fatal(err)
	}
	tb.Cleanup(func() { s.Close() })
	return s
}

// FuzzHandle sends a short history of request lines (one per input line; sel[i] picks line i's producer) to a fresh
// auditd, so a crasher holds every line that built the state it needs (writers, subjects, ops, rotation) and replays
// the same way under go test. After every line the chain must still verify.
func FuzzHandle(f *testing.F) {
	producers := []string{rootdProducer, "agentboxd", "proxy", "taskrun"}
	seeds := []string{
		`{"type":"TAINT","subject":"task:T1","source":"connect:example.com"}`,
		`{"type":"WRITER_ADD","subject":"workspace:a","holder":"task:T1"}`,
		`{"type":"SUBJECT_ADD","subject":"session:s1"}`,
		`{"type":"INTENT","opId":"op1","name":"taint.clear","origin":"admin","args":{"subject":"workspace:a","contentId":"c"},"taintEpochs":{"workspace:a":0}}`,
		`{"type":"RESULT","opId":"op1","status":"executed"}`,
		`{"type":"taint.get","holder":"task:T1"}`,
		`{"type":"op.get","opId":"op1"}`,
		`{"type":"DENY","id":"dn_01JF0000000000000000000000","code":"EGRESS_NOT_ALLOWLISTED","by":"proxy","subject":{"host":"x.example","port":443},"count":1,"first":1,"last":1}`,
		`{"type":"TAINT","subject":"task:T1","tainted":0,"epoch":3}`,
		`{"type":"open"}`,
	}
	for _, l := range seeds {
		for i := range producers {
			f.Add([]byte{uint8(i)}, []byte(l))
		}
	}
	f.Add([]byte{2, 0, 0, 1, 0}, []byte(strings.Join(seeds[:5], "\n"))) // taint, writer, subject, then an op on them
	f.Fuzz(func(t *testing.T, sel, lines []byte) {
		dir := t.TempDir()
		s := fakeServer(t, dir, 4096)
		for i, line := range bytes.SplitN(lines, []byte("\n"), 64) { // 64 lines keep one input's chain short
			p := producers[0]
			if len(sel) > 0 {
				p = producers[int(sel[i%len(sel)])%len(producers)]
			}
			uid := uint32(1000)
			if p == rootdProducer {
				uid = 0
			}
			rep := s.Handle(p, uid, 42, line)
			if rep.OK == (rep.Code != "") {
				t.Fatalf("line %d: reply %+v", i, rep)
			}
			if rep, err := VerifyDir(dir); err != nil {
				t.Fatalf("after line %d %q from %s: %v (%+v)", i, line, p, err, rep)
			}
		}
	})
}

func FuzzReadLine(f *testing.F) {
	f.Add([]byte("{\"type\":\"TAINT\"}\nnext\n"), 64)
	f.Add([]byte(strings.Repeat("x", 100)+"\n"), 99)
	f.Add([]byte("no newline"), 4)
	f.Fuzz(func(t *testing.T, b []byte, max int) {
		max = max & 0xfff
		line, err := readLine(bufio.NewReaderSize(bytes.NewReader(b), 16), max)
		if err != nil {
			return
		}
		if len(line) > max || bytes.IndexByte(line, '\n') >= 0 || !bytes.HasPrefix(b, append(line, '\n')) {
			t.Fatalf("readLine(%q, %d) = %q", b, max, line)
		}
	})
}
