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

func FuzzScanSegment(f *testing.F) {
	b := newBox(f)
	for i := 0; i < 30; i++ {
		b.send("proxy", `{"type":"TAINT","subject":"task:T1","source":"connect:example.com"}`)
	}
	ns, _ := Segments(b.dir)
	for _, n := range ns {
		data, err := os.ReadFile(filepath.Join(b.dir, SegName(n)))
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

// FuzzHandle sends request lines to one long-lived auditd, so state carries from input to input (writers, subjects,
// ops, rotation). After every line the chain must still verify.
func FuzzHandle(f *testing.F) {
	producers := []string{rootdProducer, "agentboxd", "proxy", "taskrun"}
	for _, l := range []string{
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
	} {
		for i := range producers {
			f.Add(uint8(i), []byte(l))
		}
	}
	var s *Server
	var dir string
	n := 0
	var wall, boot int64 = 1_800_000_000_000, 5000
	f.Cleanup(func() {
		if s != nil {
			s.Close()
			os.RemoveAll(dir)
		}
	})
	f.Fuzz(func(t *testing.T, pi uint8, line []byte) {
		if s == nil || n%2000 == 0 { // a fresh box now and then keeps the chain short and the disk small
			if s != nil {
				s.Close()
				os.RemoveAll(dir)
			}
			var err error
			if dir, err = os.MkdirTemp("", "agentbox-fuzz-audit"); err != nil {
				t.Fatal(err)
			}
			s = &Server{Dir: dir, Seal: fakeSeal{dir}, SegmentBytes: 4096, ReserveBytes: 1 << 20, BootID: "boot-1",
				Wall: func() int64 { wall += 10; return wall }, Boot: func() int64 { boot += 10; return boot },
				Avail: func() (uint64, error) { return 100 << 30, nil }}
			if err := s.Start(); err != nil {
				t.Fatal(err)
			}
		}
		n++
		p := producers[int(pi)%len(producers)]
		uid := uint32(1000)
		if p == rootdProducer {
			uid = 0
		}
		rep := s.Handle(p, uid, 42, line)
		if rep.OK == (rep.Code != "") {
			t.Fatalf("reply %+v", rep)
		}
		if rep, err := VerifyDir(dir); err != nil {
			t.Fatalf("after %q from %s: %v (%+v)", line, p, err, rep)
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
