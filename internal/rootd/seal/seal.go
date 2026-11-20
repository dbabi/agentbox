// Package seal is rootd's half of the audit files (ARCHITECTURE.md §9): rootd creates each segment owned by
// agentbox-audit, 0640, append-only (chattr +a), and on auditd's audit.seal call checks the chain through the
// segment's close record, makes it immutable (+i) and creates the next one. auditd is the only writer; setting +a and +i
// needs CAP_LINUX_IMMUTABLE, which only rootd holds.
//
// shortcut: this is a stand-in for the auditd area's audit.Sealer, audit.Files and audit.ServeSeal (wk/w3-auditd,
// internal/audit/seal.go) with the same interface, wire format and record format. When that area merges, rootd serves
// audit.Files with audit.ServeSeal's protocol and this package goes away.
package seal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
)

// Dir is the audit directory: agentbox-audit:agentbox-audit 0750 (§9 Access), made by tmpfiles.d.
const Dir = "/var/lib/agentbox/audit"

// Sealer is auditd's audit.Sealer: the two calls auditd makes on audit-seal.sock.
type Sealer interface {
	// Create makes the box's first segment, seg-000001. It refuses any other number: later segments come from Seal.
	Create(seg uint64) error
	// Seal checks seg's chain through its close record, whose line hash must be lastHash, sets +i and creates seg+1.
	// It is idempotent: after a crash at any point it finishes whichever step is missing.
	Seal(seg uint64, lastHash string) error
}

var segRE = regexp.MustCompile(`^seg-([0-9]{6})\.jsonl$`)

// Name is the file name of segment n: named by sequence, never by date (§9).
func Name(n uint64) string { return fmt.Sprintf("seg-%06d.jsonl", n) }

// Hash is a record's chain hash: hex SHA-256 of its line without the newline.
func Hash(line []byte) string { s := sha256.Sum256(line); return hex.EncodeToString(s[:]) }

// FS is what sealing needs from the box: inode flags and the owner. The Linux one is Box; tests use a fake.
type FS interface {
	Flags(path string) (appendOnly, immutable bool, err error)
	SetAppend(path string) error    // chattr +a
	SetImmutable(path string) error // chattr +i
	Chown(path string) error        // agentbox-audit:agentbox-audit
}

// Files is the Sealer on the audit directory; rootd runs it as root.
type Files struct {
	Dir string
	FS  FS
}

// Segments lists the segment numbers in dir, ascending.
func Segments(dir string) ([]uint64, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var ns []uint64
	for _, e := range ents {
		if m := segRE.FindStringSubmatch(e.Name()); m != nil && e.Type().IsRegular() {
			n, _ := strconv.ParseUint(m[1], 10, 64)
			ns = append(ns, n)
		}
	}
	sort.Slice(ns, func(i, j int) bool { return ns[i] < ns[j] })
	return ns, nil
}

func (f *Files) Create(seg uint64) error {
	ns, err := Segments(f.Dir)
	if err != nil {
		return err
	}
	if seg != 1 || len(ns) > 1 || (len(ns) == 1 && ns[0] != 1) {
		return fmt.Errorf("audit.create: only seg 1 on a box with no other segment (have %v)", ns)
	}
	return f.create(1)
}

func (f *Files) Seal(seg uint64, lastHash string) error {
	ns, err := Segments(f.Dir)
	if err != nil {
		return err
	}
	if len(ns) == 0 || (ns[len(ns)-1] != seg && ns[len(ns)-1] != seg+1) {
		return fmt.Errorf("audit.seal: %s is neither the newest segment nor the one before it (have %v)", Name(seg), ns)
	}
	p := filepath.Join(f.Dir, Name(seg))
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	h, err := Verify(b)
	if err != nil {
		return fmt.Errorf("audit.seal %s: %w", Name(seg), err)
	}
	if h != lastHash {
		return fmt.Errorf("audit.seal %s: the chain does not end in a close record with hash %s", Name(seg), lastHash)
	}
	if _, imm, err := f.FS.Flags(p); err != nil {
		return err
	} else if !imm {
		if err := f.FS.SetImmutable(p); err != nil {
			return fmt.Errorf("chattr +i %s: %w", p, err)
		}
	}
	return f.create(seg + 1)
}

// create makes seg n, or finishes a half-made one: owner and mode first, since +a then forbids changing them. A
// non-empty file that is not yet append-only was not made by rootd, so it is refused.
func (f *Files) create(n uint64) error {
	p := filepath.Join(f.Dir, Name(n))
	fd, err := os.OpenFile(p, os.O_RDONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if errors.Is(err, os.ErrExist) {
		fd, err = os.Open(p)
	}
	if err != nil {
		return err
	}
	defer fd.Close()
	ap, _, err := f.FS.Flags(p)
	if err != nil {
		return err
	}
	if !ap {
		st, err := fd.Stat()
		if err != nil {
			return err
		}
		if st.Size() != 0 {
			return fmt.Errorf("%s holds data but is not append-only: rootd did not make it", p)
		}
		if err := errors.Join(f.FS.Chown(p), fd.Chmod(0o640)); err != nil {
			return err
		}
		if err := f.FS.SetAppend(p); err != nil {
			return fmt.Errorf("chattr +a %s: %w", p, err)
		}
	}
	d, err := os.Open(f.Dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// record is auditd's audit.Record, as far as the chain check reads it.
type record struct {
	Seq  uint64          `json:"seq"`
	Prev string          `json:"prev"`
	Type string          `json:"type"`
	Body json.RawMessage `json:"body"`
}

// Verify checks one segment's chain the way auditd's ScanSegment does with no anchor (§9 Format): the first record is
// open (or a torn record right after unchained bytes), each next record has seq+1 and prev = the hash of the line
// before it, unchained bytes are allowed only when the torn record right after them declares their exact range and
// SHA-256, and the segment ends in close{seq, last_hash} naming the record before it, with nothing after. It returns
// the hash of the close line.
func Verify(data []byte) (string, error) {
	var last, n int
	var seq uint64
	prev, garbage, closed, opened := "", -1, false, false
	for pos := 0; pos < len(data); {
		i := bytes.IndexByte(data[pos:], '\n')
		if i < 0 {
			return "", fmt.Errorf("bytes %d-%d are an unterminated tail", pos, len(data))
		}
		line, next := data[pos:pos+i], pos+i+1
		var r record
		ok := json.Unmarshal(line, &r) == nil && r.Type != ""
		if ok && n == 0 {
			ok = r.Type == "open" || (r.Type == "torn" && garbage >= 0)
		} else if ok {
			ok = r.Seq == seq+1 && r.Prev == prev
		}
		if !ok {
			if garbage < 0 {
				garbage = pos
			}
			pos = next
			continue
		}
		if closed {
			return "", fmt.Errorf("record seq %d at offset %d follows close", r.Seq, pos)
		}
		if !opened && r.Type != "open" && !(r.Type == "torn" && garbage >= 0) {
			return "", fmt.Errorf("record at offset %d is %q before the segment's open", pos, r.Type)
		}
		opened = opened || r.Type == "open"
		if garbage >= 0 {
			var t struct {
				Offset, Len int64
				SHA256      string
			}
			if r.Type != "torn" || json.Unmarshal(r.Body, &t) != nil || t.Offset != int64(garbage) ||
				t.Offset+t.Len != int64(pos) || t.SHA256 != Hash(data[garbage:pos]) {
				return "", fmt.Errorf("bytes %d-%d are not a chained record, and the record after them does not declare them torn", garbage, pos)
			}
			garbage = -1
		}
		if r.Type == "close" {
			var c struct {
				Seq      uint64 `json:"seq"`
				LastHash string `json:"last_hash"`
			}
			if json.Unmarshal(r.Body, &c) != nil || c.Seq != seq || c.LastHash != prev {
				return "", fmt.Errorf("close at offset %d does not name the record before it", pos)
			}
			closed = true
		}
		prev, seq, last, pos = Hash(line), r.Seq, next, next
		n++
	}
	if !closed || last != len(data) {
		return "", errors.New("the segment does not end in a close record")
	}
	return prev, nil
}
