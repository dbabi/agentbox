package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Sealer is rootd's half of the segment files (§9). auditd is the only writer, but only rootd has CAP_LINUX_IMMUTABLE,
// so rootd creates every segment (owner agentbox-audit, 0640, +a) and seals it (+i). auditd calls it over the seal
// socket with SealClient; rootd serves Files with ServeSeal.
type Sealer interface {
	// Create makes the box's first segment, seg-000001. It refuses any other number: later segments come from Seal.
	Create(seg uint64) error
	// Seal checks seg's chain through its close record, whose line hash must be lastHash, sets +i and creates seg+1.
	// It is idempotent: after a crash at any point it finishes whichever step is missing.
	Seal(seg uint64, lastHash string) error
}

// Files is the Sealer on the audit directory itself; rootd runs it as root.
type Files struct {
	Dir      string
	UID, GID int // agentbox-audit
	// Crash, if set, is called at each step (test hook for the crash-mid-seal gate).
	Crash func(point string)
}

func (fs *Files) crash(p string) {
	if fs.Crash != nil {
		fs.Crash(p)
	}
}

func (fs *Files) Create(seg uint64) error {
	ns, err := Segments(fs.Dir)
	if err != nil {
		return err
	}
	if seg != 1 || len(ns) > 1 || (len(ns) == 1 && ns[0] != 1) {
		return fmt.Errorf("audit.create: only seg 1 on a box with no other segment (have %v)", ns)
	}
	return fs.createSeg(1)
}

func (fs *Files) Seal(seg uint64, lastHash string) error {
	ns, err := Segments(fs.Dir)
	if err != nil {
		return err
	}
	if len(ns) == 0 || (ns[len(ns)-1] != seg && ns[len(ns)-1] != seg+1) {
		return fmt.Errorf("audit.seal: %s is neither the newest segment nor the one before it (have %v)", SegName(seg), ns)
	}
	p := filepath.Join(fs.Dir, SegName(seg))
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	data := make([]byte, fi.Size())
	if _, err := f.ReadAt(data, 0); err != nil && fi.Size() > 0 {
		return err
	}
	s, err := ScanSegment(data, "", 0, false)
	if err != nil {
		return fmt.Errorf("audit.seal %s: %w", SegName(seg), err)
	}
	if !s.Closed || s.Undeclared() != 0 || s.LastHash != lastHash {
		return fmt.Errorf("audit.seal %s: the chain does not end in a close record with hash %s", SegName(seg), lastHash)
	}
	if err := addFlags(f, flagImmutable); err != nil {
		return fmt.Errorf("chattr +i %s: %w", p, err)
	}
	fs.crash("immutable-set")
	if err := fs.createSeg(seg + 1); err != nil {
		return err
	}
	fs.crash("next-created")
	return nil
}

// createSeg makes seg n, or finishes a half-made one: owner and mode first, since +a then forbids changing them.
func (fs *Files) createSeg(n uint64) error {
	p := filepath.Join(fs.Dir, SegName(n))
	f, err := os.OpenFile(p, os.O_RDONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if errors.Is(err, os.ErrExist) {
		f, err = os.Open(p)
	}
	if err != nil {
		return err
	}
	defer f.Close()
	fl, err := getFlags(f)
	if err != nil {
		return err
	}
	if fl&flagAppend == 0 {
		if err := errors.Join(f.Chown(fs.UID, fs.GID), f.Chmod(0o640)); err != nil {
			return err
		}
		if err := addFlags(f, flagAppend); err != nil {
			return fmt.Errorf("chattr +a %s: %w", p, err)
		}
	}
	return syncDir(fs.Dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

type sealReq struct {
	Call     string `json:"call"` // audit.create or audit.seal
	Seg      uint64 `json:"seg"`
	LastHash string `json:"last_hash,omitempty"`
}

type sealReply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// ServeSeal answers audit.create and audit.seal on l, one call per connection, for peers with uid allowUID
// (agentbox-audit) only. rootd runs it on /run/agentbox-rootd/audit-seal.sock.
func ServeSeal(l net.Listener, s Sealer, allowUID uint32, logf func(string, ...any)) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			uc := c.(*net.UnixConn)
			if uid, _, err := peerCred(uc); err != nil || uid != allowUID {
				logf("audit seal: refused peer uid %d (%v)", uid, err)
				return
			}
			c.SetDeadline(time.Now().Add(5 * time.Minute)) // a seal reads and hashes up to one 64 MiB segment
			line, err := readLine(bufio.NewReader(fdFree{uc}), 4096)
			if err != nil {
				return
			}
			var r sealReq
			var rep sealReply
			if err = json.Unmarshal(line, &r); err == nil {
				switch r.Call {
				case "audit.create":
					err = s.Create(r.Seg)
				case "audit.seal":
					err = s.Seal(r.Seg, r.LastHash)
				default:
					err = fmt.Errorf("unknown call %q", r.Call)
				}
			}
			if rep.OK = err == nil; err != nil {
				rep.Error = err.Error()
				logf("audit seal: %s %d: %v", r.Call, r.Seg, err)
			}
			b, _ := json.Marshal(rep)
			c.Write(append(b, '\n'))
		}()
	}
}

// SealClient is auditd's side: it calls rootd on the seal socket.
type SealClient struct{ Path string }

func (sc SealClient) Create(seg uint64) error {
	return sc.call(sealReq{Call: "audit.create", Seg: seg})
}
func (sc SealClient) Seal(seg uint64, h string) error {
	return sc.call(sealReq{Call: "audit.seal", Seg: seg, LastHash: h})
}

func (sc SealClient) call(r sealReq) error {
	c, err := net.DialTimeout("unix", sc.Path, 5*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(6 * time.Minute))
	b, _ := json.Marshal(r)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return err
	}
	line, err := readLine(bufio.NewReader(c), 64<<10)
	if err != nil {
		return fmt.Errorf("%s: %w", r.Call, err)
	}
	var rep sealReply
	if err := json.Unmarshal(line, &rep); err != nil {
		return err
	}
	if !rep.OK {
		return fmt.Errorf("%s: rootd: %s", r.Call, rep.Error)
	}
	return nil
}
