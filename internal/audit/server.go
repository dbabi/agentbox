package audit

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Producer is one producer socket: /run/agentbox-audit/<Name>.sock, accepted only from peers with UID (§2.1).
type Producer struct {
	Name string
	UID  uint32
}

const rootdProducer = "rootd"

// Defaults from §9.
const (
	DefaultSegmentBytes = 64 << 20
	DefaultSegmentAgeMs = 24 * 3600 * 1000
	DefaultReserveBytes = 512 << 20
	reserveSlack        = 1 << 30 // disk-full mode ends once free space is above the reserve plus 1 GiB
	maxRecord           = 1 << 20
)

// Server is agentbox-auditd: the only writer of the audit segments and taint.db.
type Server struct {
	Dir          string
	Seal         Sealer
	SegmentBytes int64
	SegmentAgeMs int64
	ReserveBytes int64
	Logf         func(format string, args ...any)
	Crash        func(point string) // test hook for the crash-mid-seal gate

	// clocks and the free-space probe; tests replace them
	Wall   func() int64
	Boot   func() int64
	BootID string
	Avail  func() (uint64, error)

	mu       sync.Mutex
	db       *sql.DB
	f        *os.File // the open segment, O_APPEND
	seg      uint64
	seq      uint64
	last     string // line hash of record seq
	end      int64  // bytes of the open segment that hold complete records
	openBoot int64  // ts_boot of the open segment's open record
	lastWall int64
	lastBoot int64
	sealing  bool // close is written; the segment still needs rootd's seal and its successor's open
	needOpen bool // the open segment has no open record yet: nothing else may be appended first
	torn     bool // a failed append may have left bytes past end
	diskFull bool
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

func (s *Server) crash(p string) {
	if s.Crash != nil {
		s.Crash(p)
	}
}

// Start opens taint.db and the chain: it marks a torn tail, finishes a seal a crash interrupted, and rotates at its
// first start in a new boot. Only then may it ACK.
func (s *Server) Start() error {
	if s.SegmentBytes == 0 {
		s.SegmentBytes = DefaultSegmentBytes
	}
	if s.SegmentAgeMs == 0 {
		s.SegmentAgeMs = DefaultSegmentAgeMs
	}
	if s.ReserveBytes == 0 {
		s.ReserveBytes = DefaultReserveBytes
	}
	if s.Wall == nil {
		s.Wall = func() int64 { return time.Now().UnixMilli() }
	}
	if s.Boot == nil {
		s.Boot = bootTimeMs
	}
	if s.BootID == "" {
		s.BootID = bootID()
	}
	if s.Avail == nil {
		s.Avail = func() (uint64, error) { return availBytes(s.Dir) }
	}
	db, err := openTaintDB(filepath.Join(s.Dir, "taint.db"))
	if err != nil {
		return err
	}
	s.db = db
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkSpace()
	return s.openChain()
}

func (s *Server) openChain() error {
	ns, err := Segments(s.Dir)
	if err != nil {
		return err
	}
	if len(ns) == 0 {
		if err := s.Seal.Create(1); err != nil {
			return err
		}
		ns = []uint64{1}
	}
	n := ns[len(ns)-1]
	data, err := os.ReadFile(filepath.Join(s.Dir, SegName(n)))
	if err != nil {
		return err
	}
	sc, err := ScanSegment(data, "", 0, false)
	if err != nil {
		return fmt.Errorf("%s: %w", SegName(n), err)
	}
	s.seg, s.seq, s.last, s.end = n, 0, ZeroHash, sc.End
	if sc.Records > 0 {
		s.seq, s.last = sc.Last.Seq, sc.LastHash
	} else if n > 1 {
		// the seal created this segment, and a crash came before (or during) its open: chain to the close before it
		pdata, err := os.ReadFile(filepath.Join(s.Dir, SegName(n-1)))
		if err != nil {
			return err
		}
		p, err := ScanSegment(pdata, "", 0, false)
		if err != nil || !p.Closed {
			return fmt.Errorf("%s: newest segment is empty and the one before it does not end in close: %v", SegName(n), err)
		}
		if err := s.Seal.Seal(n-1, p.LastHash); err != nil { // idempotent: it may have stopped before +i
			return err
		}
		s.seq, s.last = p.Last.Seq, p.LastHash
		if p.Last.BootID == s.BootID { // so writeOpen logs a clock step since that close
			s.lastWall, s.lastBoot = p.Last.TsWall, p.Last.TsBoot
		}
	}
	// a closed segment may already be +i, which refuses any open for write; finishSeal opens its successor
	if !sc.Closed {
		if s.f, err = openFile(filepath.Join(s.Dir, SegName(n)), os.O_WRONLY|os.O_APPEND, 0); err != nil {
			return err
		}
	}
	if sc.OpenRec == nil && !sc.Closed {
		s.needOpen = true // set before markTorn: no clock_step may come ahead of the segment's open
	}
	if sc.Undeclared() > 0 && !sc.Closed {
		if err := s.markTorn(data[sc.End:]); err != nil {
			return err
		}
	}
	if sc.OpenRec != nil {
		s.openBoot = sc.OpenRec.TsBoot
		if sc.Last.BootID == s.BootID {
			s.lastWall, s.lastBoot = sc.Last.TsWall, sc.Last.TsBoot
		}
	}
	switch {
	case sc.Closed:
		s.sealing = true
		err = s.finishSeal()
	case sc.OpenRec == nil:
		s.needOpen = true
		return s.writeOpen()
	case sc.OpenRec.BootID != s.BootID:
		err = s.rotate() // first start in a new boot
	}
	if err != nil && s.sealing {
		s.logf("audit: %v; nothing is ACKed until the seal succeeds", err) // retried at every request
		err = nil
	}
	return err
}

// markTorn declares the bytes past the last complete record: "\x00\n" first if they lack a "\n", then torn{offset, len,
// sha256}, chained to the last complete record. Nothing is truncated, so +a never has to come off (§9). The NUL keeps
// a record cut just before its "\n" from becoming valid JSON, and so a live record.
func (s *Server) markTorn(tail []byte) error {
	off := s.end
	if len(tail) > 0 && tail[len(tail)-1] != '\n' {
		end := []byte{0, '\n'}
		if _, err := writeFile(s.f, end); err != nil {
			return err
		}
		tail = append(tail[:len(tail):len(tail)], end...)
	}
	s.end = off + int64(len(tail)) // append counts the torn record from here
	s.logf("audit: %s: torn tail of %d bytes at offset %d", SegName(s.seg), len(tail), off)
	b, _ := json.Marshal(tornBody{off, int64(len(tail)), lineHash(tail)})
	if _, err := s.append(TypeTorn, "auditd", uint32(os.Getuid()), 0, b); err != nil {
		// undeclared again: the retry's tail runs from off, the "\n" and any partial torn bytes included
		s.end, s.torn = off, true
		return err
	}
	return nil
}

// repairTail runs after a failed append: whatever reached the file past end is declared torn before the next record.
func (s *Server) repairTail() error {
	p := filepath.Join(s.Dir, SegName(s.seg))
	data, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	s.torn = false
	if int64(len(data)) > s.end {
		if err := s.markTorn(data[s.end:]); err != nil {
			s.torn = true
			return err
		}
	}
	return nil
}

// writeOpen logs a clock step since the previous segment's last record after open: a segment must start with open.
func (s *Server) writeOpen() error {
	d := s.clockStep()
	if _, err := s.append(TypeOpen, "auditd", uint32(os.Getuid()), 0, nil); err != nil {
		return err
	}
	s.needOpen = false
	s.openBoot = s.lastBoot
	return s.logClockStep(d)
}

// rotate: stop ACKing (the caller holds mu), append close, fdatasync, close the fd, ask rootd to seal, open the next
// segment with open{prev = hash(close)} (§9).
func (s *Server) rotate() error {
	if err := s.noteClockStep(); err != nil { // before close's body: close must name the record right before it
		return err
	}
	b, _ := json.Marshal(closeBody{s.seq, s.last})
	seq := s.seq
	_, err := s.append(TypeClose, "auditd", uint32(os.Getuid()), 0, b)
	if s.seq != seq {
		s.sealing = true // close is in the file even if fdatasync failed: nothing may follow it; finishSeal syncs again
	}
	if err != nil {
		return err
	}
	s.crash("close-written")
	return s.finishSeal()
}

func (s *Server) finishSeal() error {
	if s.f != nil {
		if err := syncFile(s.f); err != nil {
			return err
		}
		s.f.Close()
		s.f = nil
	}
	if err := s.Seal.Seal(s.seg, s.last); err != nil {
		return fmt.Errorf("audit.seal %s: %w", SegName(s.seg), err)
	}
	s.crash("sealed")
	f, err := openFile(filepath.Join(s.Dir, SegName(s.seg+1)), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	s.f, s.seg, s.end, s.sealing, s.needOpen = f, s.seg+1, 0, false, true
	return s.writeOpen()
}

// ready brings the chain to a state that can take a record: a pending seal done, a torn tail declared, a full segment
// rotated.
func (s *Server) ready() error {
	if s.sealing {
		if err := s.finishSeal(); err != nil {
			return err
		}
	}
	if s.torn {
		if err := s.repairTail(); err != nil {
			return err
		}
	}
	if s.needOpen {
		if err := s.writeOpen(); err != nil {
			return err
		}
	}
	if s.end >= s.SegmentBytes || s.Boot()-s.openBoot >= s.SegmentAgeMs {
		return s.rotate()
	}
	return nil
}

// append writes one record with a single write on the O_APPEND fd, then fdatasync. A wall-clock step against
// CLOCK_BOOTTIME since the previous record is logged first; it never rotates anything.
func (s *Server) append(typ, producer string, uid uint32, pid int32, body json.RawMessage) (uint64, error) {
	// rotate logs it before close, writeOpen after open; a torn record before open waits for open too
	if typ != TypeClockStep && typ != TypeClose && typ != TypeOpen && !s.needOpen {
		if err := s.noteClockStep(); err != nil {
			return 0, err
		}
	}
	wall, boot := s.Wall(), s.Boot()
	r := Record{Seq: s.seq + 1, Prev: s.last, TsWall: wall, TsBoot: boot, BootID: s.BootID, Type: typ, Producer: producer, UID: uid, PID: pid, Body: body}
	line, err := json.Marshal(r)
	if err != nil {
		return 0, err
	}
	n, err := writeFile(s.f, append(line, '\n'))
	if err != nil {
		if n > 0 {
			s.torn = true
		}
		return 0, err
	}
	s.seq, s.last, s.end = r.Seq, lineHash(line), s.end+int64(n)
	if typ != TypeTorn || !s.needOpen { // a torn record before open leaves the step since the last close for writeOpen to log
		s.lastWall, s.lastBoot = wall, boot
	}
	// the line is in the file even if fdatasync fails, so the chain goes on from it; the record is just not ACKed
	return r.Seq, syncFile(s.f)
}

// The segment fd's open, write and sync; tests replace them to inject faults.
var (
	openFile  = os.OpenFile
	writeFile = (*os.File).Write
	syncFile  = fdatasync
)

// noteClockStep appends clock_step{delta} when the wall clock moved more than 1 s apart from CLOCK_BOOTTIME since the
// previous record.
func (s *Server) noteClockStep() error { return s.logClockStep(s.clockStep()) }

func (s *Server) clockStep() int64 {
	if s.lastBoot == 0 {
		return 0
	}
	return (s.Wall() - s.lastWall) - (s.Boot() - s.lastBoot)
}

func (s *Server) logClockStep(d int64) error {
	if d > 1000 || d < -1000 {
		b, _ := json.Marshal(clockStepBody{d})
		_, err := s.append(TypeClockStep, "auditd", uint32(os.Getuid()), 0, b)
		return err
	}
	return nil
}

func (s *Server) reservePath() string { return filepath.Join(s.Dir, ".reserve") }

// checkSpace enters disk-full mode below the reserve (deleting it frees the room admin ops need) and leaves it once
// there is room for the reserve plus 1 GiB.
func (s *Server) checkSpace() {
	avail, err := s.Avail()
	if err != nil {
		return
	}
	switch {
	case !s.diskFull && avail < uint64(s.ReserveBytes):
		s.enterDiskFull("free space below the reserve")
	case s.diskFull && avail > uint64(s.ReserveBytes+reserveSlack):
		if err := s.makeReserve(); err != nil {
			return
		}
		s.diskFull = false
		s.logf("audit: CRITICAL: disk-full mode ended; reserve recreated")
		s.alert("disk_ok")
	case !s.diskFull:
		if fi, err := os.Stat(s.reservePath()); err != nil || fi.Size() < s.ReserveBytes {
			if err := s.makeReserve(); err != nil {
				s.enterDiskFull("cannot keep the reserve: " + err.Error())
			}
		}
	}
}

func (s *Server) makeReserve() error {
	f, err := os.OpenFile(s.reservePath(), os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	err = fallocate(f, s.ReserveBytes)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(s.reservePath())
	}
	return err
}

func (s *Server) enterDiskFull(why string) {
	if s.diskFull {
		return
	}
	os.Remove(s.reservePath())
	s.diskFull = true
	s.logf("audit: CRITICAL: disk-full mode (%s): only admin ops from rootd are ACKed", why)
	s.alert("disk_full")
}

// alert writes a critical alert record when the chain can take it; the journal line above is the fallback.
func (s *Server) alert(reason string) {
	if s.f == nil || s.sealing || (s.torn && s.repairTail() != nil) || (s.needOpen && s.writeOpen() != nil) {
		return
	}
	b, _ := json.Marshal(map[string]string{"reason": reason})
	if _, err := s.append(TypeAlert, "auditd", uint32(os.Getuid()), 0, b); err != nil {
		s.logf("audit: alert %s not recorded: %v", reason, err)
	}
}

// Reply is auditd's answer to one request line. An INTENT is ACKed only with OK.
type Reply struct {
	OK      bool             `json:"ok"`
	Seq     uint64           `json:"seq,omitempty"`
	Code    string           `json:"code,omitempty"`
	Detail  string           `json:"detail,omitempty"`
	Moved   map[string]int64 `json:"moved,omitempty"` // STALE: the current epoch of each subject that moved
	Applied *bool            `json:"applied,omitempty"`
	View    *taintView       `json:"view,omitempty"`
	Op      *opView          `json:"op,omitempty"`
}

// NACK codes.
const (
	CodeStale       = "STALE"       // an epoch in taintEpochs moved (STALE{taint_moved}, §5.2)
	CodeDiskFull    = "DISK_FULL"   // disk-full mode: only admin ops from rootd
	CodeViolation   = "VIOLATION"   // a taint write rule was broken; logged
	CodeNotAllowed  = "NOT_ALLOWED" // this producer may not send this
	CodeBadRecord   = "BAD_RECORD"
	CodeUnknownOp   = "UNKNOWN_OP"
	CodeDuplicate   = "DUPLICATE_OP"
	CodeUnavailable = "AUDIT_UNAVAILABLE"
)

type request struct {
	Type        string           `json:"type"`
	OpID        string           `json:"opId"`
	Name        string           `json:"name"`
	Origin      string           `json:"origin"` // "admin": rootd received the op on rootd-admin.sock
	Signer      string           `json:"signer"`
	Status      string           `json:"status"`
	TaintEpochs map[string]int64 `json:"taintEpochs"`
	Args        struct {
		Subject   string `json:"subject"`
		ContentID string `json:"contentId"`
		Workspace string `json:"workspace"`
		Snapshot  string `json:"snapshot"`
	} `json:"args"`
	Subject   string `json:"subject"`
	Source    string `json:"source"`
	Reader    string `json:"reader"`
	Holder    string `json:"holder"`
	Workspace string `json:"workspace"`
	Task      string `json:"task"`
}

type opView struct {
	OpID      string `json:"opId"`
	Name      string `json:"name"`
	IntentSeq int64  `json:"intentSeq"`
	ResultSeq *int64 `json:"resultSeq,omitempty"`
	Status    string `json:"status,omitempty"`
}

// Who may send what. Every producer may raise taint and log its own effects; only rootd registers writers and
// subjects, clears, restores, and reads op state.
var (
	bestEffort = map[string]bool{"DENY": true, "DENY_FLOOD": true, "WITNESS": true, "GATE_MISMATCH": true,
		"PAD_OVERRUN": true, "QUOTE": true, "ALERT": true, "CACHE": true}
	rootdOnly   = map[string]bool{"WRITER_ADD": true, "WRITER_DEL": true, "SUBJECT_ADD": true, "op.get": true}
	rootdOnlyOp = map[string]bool{"taint.clear": true, "workspace.restore": true}
	queryFrom   = map[string]bool{rootdProducer: true, "agentboxd": true} // taint.get
)

// Handle processes one request line from producer p (uid and pid from SO_PEERCRED) and returns the reply.
func (s *Server) Handle(p string, uid uint32, pid int32, line []byte) Reply {
	s.mu.Lock()
	defer s.mu.Unlock()
	var raw map[string]json.RawMessage
	var r request
	if err := json.Unmarshal(line, &raw); err != nil || json.Unmarshal(line, &r) != nil {
		return Reply{Code: CodeBadRecord, Detail: "not a JSON object"}
	}
	delete(raw, "type")
	isRootd := p == rootdProducer
	// Taint write rules (§9): a producer names a subject and a source, never tainted=0 or an epoch.
	if _, ok := raw["epoch"]; ok || (raw["tainted"] != nil && isFalsy(raw["tainted"])) {
		if isRootd {
			return Reply{Code: CodeBadRecord, Detail: "tainted and epoch are set by auditd; a clear is a taint.clear RESULT"}
		}
		return s.violation(p, uid, pid, line, "taint record with tainted=0 or an epoch field")
	}
	if !isRootd && (rootdOnly[r.Type] || ((r.Type == "INTENT" || r.Type == "RESULT") && rootdOnlyOp[r.Name])) {
		return s.violation(p, uid, pid, line, r.Type+" "+r.Name+" is rootd's only")
	}
	switch r.Type {
	case "taint.get":
		if !queryFrom[p] {
			return Reply{Code: CodeNotAllowed}
		}
		if !strings.HasPrefix(r.Holder, "task:") && !strings.HasPrefix(r.Holder, "session:") || !validSubject(r.Holder) {
			return Reply{Code: CodeBadRecord, Detail: "holder must be task:<id> or session:<id>"}
		}
		tx, err := s.db.Begin()
		if err != nil {
			return Reply{Code: CodeUnavailable, Detail: err.Error()}
		}
		defer tx.Rollback()
		v, err := view(tx, r.Holder)
		if err != nil {
			return Reply{Code: CodeUnavailable, Detail: err.Error()}
		}
		return Reply{OK: true, View: v}
	case "op.get":
		var o opView
		var rs sql.NullInt64
		var st sql.NullString
		err := s.db.QueryRow("SELECT op_id, name, intent_seq, result_seq, status FROM ops WHERE op_id=?", r.OpID).Scan(&o.OpID, &o.Name, &o.IntentSeq, &rs, &st)
		if errors.Is(err, sql.ErrNoRows) {
			return Reply{OK: true}
		}
		if err != nil {
			return Reply{Code: CodeUnavailable, Detail: err.Error()}
		}
		if rs.Valid {
			o.ResultSeq, o.Status = &rs.Int64, st.String
		}
		return Reply{OK: true, Op: &o}
	case "INTENT", "RESULT", "TAINT", "READ_INTENT", "WRITER_ADD", "WRITER_DEL", "SUBJECT_ADD":
	default:
		if !bestEffort[r.Type] {
			return Reply{Code: CodeBadRecord, Detail: fmt.Sprintf("unknown record type %q", r.Type)}
		}
	}
	s.checkSpace()
	if s.diskFull && !s.admitDiskFull(isRootd, &r) {
		return Reply{Code: CodeDiskFull}
	}
	if err := s.ready(); err != nil {
		s.failed(err)
		return Reply{Code: CodeUnavailable, Detail: err.Error()}
	}
	body, _ := json.Marshal(raw)
	tx, err := s.db.Begin()
	if err != nil {
		return Reply{Code: CodeUnavailable, Detail: err.Error()}
	}
	defer tx.Rollback()
	now := s.Wall()
	rep, after, err := s.apply(tx, p, &r, now)
	if err != nil {
		return Reply{Code: CodeUnavailable, Detail: err.Error()}
	}
	if rep.Code != "" {
		return rep
	}
	seq, err := s.append(r.Type, p, uid, pid, body)
	if err != nil {
		s.failed(err)
		return Reply{Code: CodeUnavailable, Detail: err.Error()}
	}
	if after != nil {
		if err := after(int64(seq)); err != nil {
			return Reply{Code: CodeUnavailable, Detail: err.Error()}
		}
	}
	if err := tx.Commit(); err != nil { // synchronous=FULL: durable when Commit returns
		s.failed(err)
		return Reply{Code: CodeUnavailable, Detail: err.Error()}
	}
	rep.OK, rep.Seq = true, seq
	return rep
}

// admitDiskFull: in disk-full mode only INTENTs (and their RESULTs) of admin ops that rootd took on rootd-admin.sock
// are ACKed, plus writer removal, which only drops capability.
func (s *Server) admitDiskFull(isRootd bool, r *request) bool {
	if !isRootd {
		return false
	}
	switch r.Type {
	case "INTENT":
		return r.Origin == "admin"
	case "RESULT":
		var origin sql.NullString
		s.db.QueryRow("SELECT origin FROM ops WHERE op_id=?", r.OpID).Scan(&origin)
		return origin.String == "admin"
	case "WRITER_DEL":
		return true
	}
	return false
}

func (s *Server) failed(err error) {
	if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) || strings.Contains(err.Error(), "disk is full") {
		s.enterDiskFull(err.Error())
	}
	s.logf("audit: %v", err)
}

// apply validates r and makes its taint.db changes in tx. A non-empty Code refuses it; after, if set, runs once the
// record has its seq.
func (s *Server) apply(tx *sql.Tx, p string, r *request, now int64) (Reply, func(int64) error, error) {
	bad := func(d string) (Reply, func(int64) error, error) {
		return Reply{Code: CodeBadRecord, Detail: d}, nil, nil
	}
	switch r.Type {
	case "INTENT":
		if r.OpID == "" || len(r.OpID) > 128 || r.Name == "" {
			return bad("INTENT needs opId and name")
		}
		for subj := range r.TaintEpochs {
			if !validSubject(subj) {
				return bad("bad subject in taintEpochs")
			}
		}
		var n int
		if err := tx.QueryRow("SELECT count(*) FROM ops WHERE op_id=?", r.OpID).Scan(&n); err != nil {
			return Reply{}, nil, err
		}
		if n > 0 {
			return Reply{Code: CodeDuplicate}, nil, nil
		}
		moved, err := epochsMatch(tx, r.TaintEpochs)
		if err != nil {
			return Reply{}, nil, err
		}
		if len(moved) > 0 {
			return Reply{Code: CodeStale, Detail: "taint_moved", Moved: moved}, nil, nil
		}
		var target, content string
		switch r.Name {
		case "taint.clear":
			target, content = r.Args.Subject, r.Args.ContentID
			if !validSubject(target) || strings.HasPrefix(target, "task:") || content == "" || r.Origin != "admin" {
				return bad("taint.clear: an admin op on a non-task subject, with a contentId")
			}
			if _, ok := r.TaintEpochs[target]; !ok {
				return bad("taint.clear: taintEpochs must bind the subject's epoch")
			}
		case "workspace.restore":
			target, content = r.Args.Workspace, r.Args.Snapshot
			if !strings.HasPrefix(target, "workspace:") || !validSubject(target) || !validSubject("snap:"+content) || r.Signer == "" {
				return bad("workspace.restore: a signed restore of workspace:<agent> from a snapshot id")
			}
			if err := restore(tx, target, "snap:"+content, "restore:"+content, now); err != nil {
				return Reply{}, nil, err
			}
		}
		return Reply{}, func(seq int64) error {
			_, err := tx.Exec("INSERT INTO ops(op_id, producer, name, origin, signer, target, content_id, epochs, intent_seq) VALUES(?,?,?,?,?,?,?,?,?)",
				r.OpID, p, r.Name, r.Origin, r.Signer, target, content, epochsJSON(r.TaintEpochs), seq)
			return err
		}, nil
	case "RESULT":
		var producer, name, target, content, epochs string
		var signer sql.NullString
		var rs sql.NullInt64
		err := tx.QueryRow("SELECT producer, name, signer, target, content_id, epochs, result_seq FROM ops WHERE op_id=?", r.OpID).
			Scan(&producer, &name, &signer, &target, &content, &epochs, &rs)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && producer != p) {
			return Reply{Code: CodeUnknownOp, Detail: "no ACKed INTENT from this producer has this opId"}, nil, nil
		}
		if err != nil {
			return Reply{}, nil, err
		}
		if rs.Valid {
			return Reply{Code: CodeDuplicate}, nil, nil
		}
		if r.Status == "" {
			return bad("RESULT needs status")
		}
		var rep Reply
		if name == "taint.clear" && r.Status == "executed" {
			var ep map[string]int64
			json.Unmarshal([]byte(epochs), &ep)
			ok, err := clear(tx, target, ep[target], signer.String, content, now)
			if err != nil {
				return Reply{}, nil, err
			}
			if ok && strings.HasPrefix(target, "workspace:") {
				// the reviewed snapshot is the cleared content (§7 step 4)
				if sn, err := get(tx, "snap:"+content); err != nil {
					return Reply{}, nil, err
				} else if sn.Tainted {
					if _, err := clear(tx, sn.Subject, sn.Epoch, signer.String, content, now); err != nil {
						return Reply{}, nil, err
					}
				}
			}
			rep.Applied = &ok
			if !ok {
				rep.Detail = "taint_moved: the subject's epoch moved after the INTENT; it stays tainted"
			}
		}
		return rep, func(seq int64) error {
			_, err := tx.Exec("UPDATE ops SET result_seq=?, status=? WHERE op_id=?", seq, r.Status, r.OpID)
			return err
		}, nil
	case "TAINT":
		if !validSubject(r.Subject) || r.Source == "" || len(r.Source) > 1024 {
			return bad("TAINT needs a subject and a source")
		}
		return Reply{}, nil, raise(tx, r.Subject, r.Source, now)
	case "READ_INTENT":
		if !validSubject(r.Reader) || !validSubject(r.Source) {
			return bad("READ_INTENT needs reader and source subjects")
		}
		src, err := get(tx, r.Source)
		if err != nil || !src.Tainted {
			return Reply{}, nil, err
		}
		if strings.HasPrefix(r.Reader, "task:") && strings.HasPrefix(r.Source, "ref:") {
			if _, err := tx.Exec("INSERT OR IGNORE INTO task_subjects(task, subject) VALUES(?,?)", r.Reader, r.Source); err != nil {
				return Reply{}, nil, err
			}
		}
		return Reply{}, nil, raise(tx, r.Reader, "read:"+r.Source, now)
	case "WRITER_ADD":
		if !(strings.HasPrefix(r.Holder, "task:") || strings.HasPrefix(r.Holder, "session:")) || !validSubject(r.Holder) ||
			!strings.HasPrefix(r.Workspace, "workspace:") || !validSubject(r.Workspace) {
			return bad("WRITER_ADD needs a task: or session: holder and a workspace: subject")
		}
		if _, err := tx.Exec("INSERT INTO writers(holder, workspace) VALUES(?,?) ON CONFLICT(holder) DO UPDATE SET workspace=excluded.workspace", r.Holder, r.Workspace); err != nil {
			return Reply{}, nil, err
		}
		h, err := get(tx, r.Holder)
		if err != nil || !h.Tainted {
			return Reply{}, nil, err
		}
		return Reply{}, nil, raise(tx, r.Workspace, "writer:"+r.Holder, now) // a tainted holder taints what it mounts
	case "WRITER_DEL":
		_, err := tx.Exec("DELETE FROM writers WHERE holder=?", r.Holder)
		return Reply{}, nil, err
	case "SUBJECT_ADD":
		if !validSubject(r.Task) || !validSubject(r.Subject) {
			return bad("SUBJECT_ADD needs task and subject")
		}
		_, err := tx.Exec("INSERT OR IGNORE INTO task_subjects(task, subject) VALUES(?,?)", r.Task, r.Subject)
		return Reply{}, nil, err
	}
	return Reply{}, nil, nil // best-effort records: logged only
}

func isFalsy(v json.RawMessage) bool {
	s := strings.TrimSpace(string(v))
	return s == "0" || s == "false" || s == "0.0" || s == `"0"` || s == "null"
}

// violation logs a broken taint write rule, without the record's content (it may hold anything), and refuses it.
func (s *Server) violation(p string, uid uint32, pid int32, line []byte, why string) Reply {
	s.logf("audit: violation from %s (uid %d, pid %d): %s", p, uid, pid, why)
	if !s.diskFull && s.ready() == nil {
		b, _ := json.Marshal(map[string]any{"producer": p, "reason": why, "sha256": lineHash(line), "len": len(line)})
		if _, err := s.append(TypeViolation, "auditd", uint32(os.Getuid()), 0, b); err != nil {
			s.failed(err)
		}
	}
	return Reply{Code: CodeViolation, Detail: why}
}

// Serve accepts producer p's connections on l. Each connection is checked with SO_PEERCRED once, then sends request
// lines and gets one reply line each.
func (s *Server) Serve(l net.Listener, p Producer) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go s.conn(c.(*net.UnixConn), p)
	}
}

func (s *Server) conn(c *net.UnixConn, p Producer) {
	defer c.Close()
	uid, pid, err := peerCred(c)
	if err != nil || uid != p.UID {
		s.logf("audit: %s.sock: refused peer uid %d pid %d (want uid %d): %v", p.Name, uid, pid, p.UID, err)
		b, _ := json.Marshal(Reply{Code: CodeNotAllowed, Detail: "peer uid is not this socket's producer"})
		c.Write(append(b, '\n'))
		return
	}
	br := bufio.NewReaderSize(fdFree{c}, 64<<10)
	for {
		line, err := readLine(br, maxRecord)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.logf("audit: %s.sock pid %d: %v", p.Name, pid, err)
			}
			return
		}
		b, _ := json.Marshal(s.Handle(p.Name, uid, pid, line))
		if _, err := c.Write(append(b, '\n')); err != nil {
			return
		}
	}
}

// Close closes taint.db and the open segment.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if s.f != nil {
		err = s.f.Close()
	}
	if s.db != nil {
		err = errors.Join(err, s.db.Close())
	}
	return err
}
