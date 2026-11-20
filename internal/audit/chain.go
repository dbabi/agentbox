// Package audit is agentbox-auditd (ARCHITECTURE.md §9): the hash-chained audit segments, taint.db with per-subject
// taint epochs, the producer sockets, and `agentbox audit verify`. Segment creation and sealing belong to rootd; this
// package holds both halves of that call (seal.go) so rootd and auditd share one implementation of the chain check.
package audit

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

// Record is one line of a segment. Order comes from Seq and Prev, never from the timestamps (§9).
type Record struct {
	Seq      uint64          `json:"seq"`
	Prev     string          `json:"prev"`    // SHA-256 (hex) of the previous record's line, without its "\n"
	TsWall   int64           `json:"ts_wall"` // CLOCK_REALTIME, Unix ms
	TsBoot   int64           `json:"ts_boot"` // CLOCK_BOOTTIME, ms
	BootID   string          `json:"boot_id"`
	Type     string          `json:"type"`
	Producer string          `json:"producer"` // the socket's producer name, or "auditd" for auditd's own records
	UID      uint32          `json:"uid"`      // SO_PEERCRED of the connection that sent it
	PID      int32           `json:"pid,omitempty"`
	Body     json.RawMessage `json:"body,omitempty"`
}

// Record types auditd writes itself; no producer may send them.
const (
	TypeOpen      = "open"
	TypeClose     = "close"
	TypeTorn      = "torn"
	TypeClockStep = "clock_step"
	TypeViolation = "violation"
	TypeAlert     = "alert"
)

// ZeroHash is the prev of the very first record of a box's chain.
var ZeroHash = hex.EncodeToString(make([]byte, sha256.Size))

func lineHash(line []byte) string { s := sha256.Sum256(line); return hex.EncodeToString(s[:]) }

type closeBody struct {
	Seq      uint64 `json:"seq"`       // seq of the last record before close
	LastHash string `json:"last_hash"` // its line hash
}

type tornBody struct {
	Offset int64  `json:"offset"`
	Len    int64  `json:"len"`
	SHA256 string `json:"sha256"`
}

type clockStepBody struct {
	DeltaMs int64 `json:"delta_ms"` // wall-clock delta minus CLOCK_BOOTTIME delta since the previous record
}

var segRe = regexp.MustCompile(`^seg-([0-9]{6})\.jsonl$`)

// SegName is the file name of segment n: named by sequence, never by date (§9).
func SegName(n uint64) string { return fmt.Sprintf("seg-%06d.jsonl", n) }

// Segments lists the segment numbers in dir, ascending.
func Segments(dir string) ([]uint64, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var ns []uint64
	for _, e := range ents {
		if m := segRe.FindStringSubmatch(e.Name()); m != nil && e.Type().IsRegular() {
			n, _ := strconv.ParseUint(m[1], 10, 64)
			ns = append(ns, n)
		}
	}
	sort.Slice(ns, func(i, j int) bool { return ns[i] < ns[j] })
	return ns, nil
}

// Torn is a byte range that a torn record declared: bytes of a write that never completed, so never ACKed.
type Torn struct{ Offset, Len int64 }

// Scan is what one segment holds, read the way verify and auditd's start read it.
type Scan struct {
	Records    int
	OpenRec    *Record // the segment's open record, nil before it
	Last       *Record // last complete record in the chain
	LastHash   string  // line hash of Last ("" if empty)
	End        int64   // offset just past Last's "\n"
	Size       int64
	Torn       []Torn
	ClockSteps int
	Closed     bool // Last is a close record
}

// Undeclared is the number of bytes after the last complete record that no torn record covers yet: a crash mid-append
// that auditd marks torn at its next start.
func (s *Scan) Undeclared() int64 { return s.Size - s.End }

// ScanSegment checks one segment's chain. prev and seq are the line hash and seq of the record before this segment
// (the previous segment's close); with anchor false they are unknown (the oldest segment kept) and the first record is
// taken as given. Bytes that don't form a chained record are allowed only when a torn record right after them declares
// exactly their range and hash, or at the very end (Undeclared).
func ScanSegment(data []byte, prev string, seq uint64, anchor bool) (*Scan, error) {
	s := &Scan{Size: int64(len(data)), LastHash: prev}
	garbage := int64(-1) // start of bytes that are not part of the chain, awaiting their torn record
	for pos := int64(0); pos < int64(len(data)); {
		i := bytes.IndexByte(data[pos:], '\n')
		if i < 0 {
			break // an unterminated tail; End stays before it
		}
		line := data[pos : pos+int64(i)]
		next := pos + int64(i) + 1
		var r Record
		ok := json.Unmarshal(line, &r) == nil && r.Type != ""
		if ok && s.Records == 0 && !anchor {
			ok = r.Type == TypeOpen || (r.Type == TypeTorn && garbage >= 0)
		} else if ok {
			ok = r.Seq == seq+1 && r.Prev == s.LastHash
		}
		if !ok {
			if garbage < 0 {
				garbage = pos
			}
			pos = next
			continue
		}
		if s.Closed {
			return s, fmt.Errorf("record seq %d at offset %d follows close", r.Seq, pos)
		}
		// a torn record may come first (a crash mid-way through the segment's open), then open
		if s.OpenRec == nil && r.Type != TypeOpen && !(r.Type == TypeTorn && garbage >= 0) {
			return s, fmt.Errorf("first record at offset %d is %q, want open", pos, r.Type)
		}
		if garbage >= 0 {
			var t tornBody
			if r.Type != TypeTorn || json.Unmarshal(r.Body, &t) != nil || t.Offset != garbage || t.Offset+t.Len != pos ||
				t.SHA256 != lineHash(data[garbage:pos]) {
				return s, fmt.Errorf("bytes %d-%d are not a chained record, and the record after them (seq %d) does not declare them torn", garbage, pos, r.Seq)
			}
			s.Torn = append(s.Torn, Torn{t.Offset, t.Len})
			garbage = -1
		}
		switch r.Type {
		case TypeClose:
			var c closeBody
			if json.Unmarshal(r.Body, &c) != nil || c.Seq != seq || c.LastHash != s.LastHash {
				return s, fmt.Errorf("close at offset %d does not name the record before it", pos)
			}
			s.Closed = true
		case TypeClockStep:
			s.ClockSteps++
		case TypeOpen:
			if s.OpenRec != nil {
				return s, fmt.Errorf("second open at offset %d", pos)
			}
		}
		rr := r
		if r.Type == TypeOpen {
			s.OpenRec = &rr
		}
		s.Last, s.LastHash, seq, s.End = &rr, lineHash(line), r.Seq, next
		s.Records++
		pos = next
	}
	return s, nil
}

// SegReport is one segment's result in a verify report.
type SegReport struct {
	Seg        uint64
	Records    int
	Torn       []Torn
	ClockSteps int
	Closed     bool
	Undeclared int64
}

// VerifyDir checks every segment in dir, in order: each chain, each torn range, every sealed segment ending in close,
// and each open record chaining to the close before it. The newest segment may still be open, and may end in bytes a
// crash left (auditd declares them torn at its next start); no other segment may.
func VerifyDir(dir string) ([]SegReport, error) {
	ns, err := Segments(dir)
	if err != nil {
		return nil, err
	}
	if len(ns) == 0 {
		return nil, errors.New("no segments")
	}
	var out []SegReport
	prev, seq, anchor := "", uint64(0), false
	for i, n := range ns {
		if i > 0 && n != ns[i-1]+1 {
			return out, fmt.Errorf("segment %s is missing", SegName(ns[i-1]+1))
		}
		data, err := os.ReadFile(filepath.Join(dir, SegName(n)))
		if err != nil {
			return out, err
		}
		s, err := ScanSegment(data, prev, seq, anchor)
		if err != nil {
			return out, fmt.Errorf("%s: %w", SegName(n), err)
		}
		last := i == len(ns)-1
		out = append(out, SegReport{n, s.Records, s.Torn, s.ClockSteps, s.Closed, s.Undeclared()})
		if !last && (!s.Closed || s.Undeclared() != 0) {
			return out, fmt.Errorf("%s: a segment with a successor must end in close", SegName(n))
		}
		if last && s.Records == 0 && i > 0 {
			break // created by the seal; auditd writes its open next (bytes here are a crash during that write)
		}
		if s.Records == 0 {
			return out, fmt.Errorf("%s: no records", SegName(n))
		}
		prev, seq, anchor = s.LastHash, s.Last.Seq, true
	}
	return out, nil
}
