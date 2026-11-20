package seal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeFS keeps inode flags in memory and enforces them like the kernel does for the writes the tests make.
type fakeFS struct{ ap, imm map[string]bool }

func newFS() *fakeFS { return &fakeFS{map[string]bool{}, map[string]bool{}} }

func (f *fakeFS) Flags(p string) (bool, bool, error) { return f.ap[p], f.imm[p], nil }
func (f *fakeFS) SetAppend(p string) error           { f.ap[p] = true; return nil }
func (f *fakeFS) SetImmutable(p string) error        { f.imm[p] = true; return nil }
func (f *fakeFS) Chown(string) error                 { return nil }

// chain builds records the way auditd writes them: open, n records, then close{seq, last_hash}.
type chain struct {
	b    strings.Builder
	prev string
	seq  uint64
}

func (c *chain) put(typ string, body any) {
	c.seq++
	bb, _ := json.Marshal(body)
	line, _ := json.Marshal(map[string]any{"seq": c.seq, "prev": c.prev, "type": typ, "producer": "auditd", "body": json.RawMessage(bb)})
	c.b.Write(line)
	c.b.WriteByte('\n')
	c.prev = Hash(line)
}

func (c *chain) close() { c.put("close", map[string]any{"seq": c.seq, "last_hash": c.prev}) }

func segment(n int) (*chain, string) {
	c := &chain{prev: strings.Repeat("0", 64)}
	c.put("open", map[string]any{})
	for i := 0; i < n; i++ {
		c.put("intent", map[string]any{"i": i})
	}
	c.close()
	return c, c.b.String()
}

func TestVerify(t *testing.T) {
	c, good := segment(3)
	if h, err := Verify([]byte(good)); err != nil || h != c.prev {
		t.Fatalf("good segment: %q %v", h, err)
	}

	// a torn write: bytes that never became a record, the newline auditd appends, then torn{offset, len, sha256}
	tc := &chain{prev: strings.Repeat("0", 64)}
	tc.put("open", map[string]any{})
	tc.put("intent", map[string]any{})
	off := tc.b.Len()
	tc.b.WriteString(`{"seq":3,"partial` + "\n")
	junk := tc.b.String()[off:]
	tc.put("torn", map[string]any{"offset": off, "len": len(junk), "sha256": Hash([]byte(junk))})
	tc.close()
	if h, err := Verify([]byte(tc.b.String())); err != nil || h != tc.prev {
		t.Fatalf("torn segment: %q %v", h, err)
	}

	lines := strings.SplitAfter(good, "\n")
	bad := map[string]string{
		"no close":            strings.Join(lines[:len(lines)-2], ""),
		"unterminated tail":   good + `{"seq":9`,
		"bytes after close":   good + "junk\n",
		"edited record":       strings.Replace(good, `"i":1`, `"i":7`, 1),
		"dropped record":      lines[0] + lines[2] + lines[3] + lines[4],
		"undeclared garbage":  lines[0] + "junk\n" + strings.Join(lines[1:], ""),
		"no open":             strings.Join(lines[1:], ""),
		"torn with wrong sha": strings.Replace(tc.b.String(), Hash([]byte(junk)), strings.Repeat("a", 64), 1),
	}
	for name, s := range bad {
		if _, err := Verify([]byte(s)); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// a close that names the wrong record
	wc := &chain{prev: strings.Repeat("0", 64)}
	wc.put("open", map[string]any{})
	wc.put("close", map[string]any{"seq": 7, "last_hash": wc.prev})
	if _, err := Verify([]byte(wc.b.String())); err == nil {
		t.Error("close naming another seq: verified")
	}
}

func TestCreateAndSeal(t *testing.T) {
	dir := t.TempDir()
	fs := newFS()
	f := &Files{Dir: dir, FS: fs}
	p1, p2 := filepath.Join(dir, Name(1)), filepath.Join(dir, Name(2))

	if err := f.Create(2); err == nil {
		t.Fatal("Create(2) on an empty box")
	}
	if err := f.Create(1); err != nil || !fs.ap[p1] {
		t.Fatalf("Create(1): %v, +a=%v", err, fs.ap[p1])
	}
	if err := f.Create(1); err != nil {
		t.Fatalf("Create(1) again (auditd restarted before its open): %v", err)
	}
	if st, _ := os.Stat(p1); st.Mode().Perm() != 0o640 {
		t.Fatalf("seg 1 mode %v", st.Mode().Perm())
	}

	c, data := segment(2)
	os.WriteFile(p1, []byte(data), 0o640)
	if err := f.Seal(1, strings.Repeat("f", 64)); err == nil || fs.imm[p1] {
		t.Fatal("Seal with the wrong last_hash sealed")
	}
	if err := f.Seal(1, c.prev); err != nil || !fs.imm[p1] || !fs.ap[p2] {
		t.Fatalf("Seal: %v, +i=%v, next +a=%v", err, fs.imm[p1], fs.ap[p2])
	}
	if err := f.Seal(1, c.prev); err != nil {
		t.Fatalf("Seal again (idempotent): %v", err)
	}
	if err := f.Create(1); err == nil {
		t.Fatal("Create(1) with seg 2 present")
	}

	// a crash after +i, before seg 3 exists: the repeated call finishes it
	_, data2 := segment(1)
	os.WriteFile(p2, []byte(data2), 0o640)
	h2, _ := Verify([]byte(data2))
	fs.imm[p2] = true
	if err := f.Seal(2, h2); err != nil || !fs.ap[filepath.Join(dir, Name(3))] {
		t.Fatalf("Seal after a crash mid-seal: %v", err)
	}
	if err := f.Seal(1, c.prev); err == nil {
		t.Fatal("sealed a segment two behind the newest")
	}

	// a file rootd did not make (data, no +a) is never adopted as the next segment
	dir2 := t.TempDir()
	f2 := &Files{Dir: dir2, FS: newFS()}
	os.WriteFile(filepath.Join(dir2, Name(1)), []byte(data), 0o640)
	os.WriteFile(filepath.Join(dir2, Name(2)), []byte("planted\n"), 0o640)
	if err := f2.Seal(1, c.prev); err == nil || !strings.Contains(fmt.Sprint(err), "did not make") {
		t.Fatalf("adopted a planted next segment: %v", err)
	}
}
