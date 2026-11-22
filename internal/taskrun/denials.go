// Package taskrun holds the in-task side of agentbox (ARCHITECTURE.md §4.2 Inside the container, §5.6): the HTTP-aware
// forwarders on 127.0.0.1:8080-8082, the in-task denial log and its witness lines, and `agentbox why`.
package taskrun

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"agentbox/internal/ops"
)

// WitnessPath is the task's witness FIFO, rootd's dir mounted read-only (Appendix C).
const WitnessPath = "/run/agentbox/witness/witness"

// LogMax is the in-task log's ring size (§5.6 In-task fallback).
const LogMax = 64

// LogPath is $HOME/.agentbox/denials.jsonl: help text in the tmpfs HOME, never evidence (task code can write it).
func LogPath() string { return filepath.Join(os.Getenv("HOME"), ".agentbox", "denials.jsonl") }

// Recorder logs each denial the task sees to the in-task log and writes its line to the witness.
type Recorder struct {
	Log     string // LogPath()
	Witness string // WitnessPath
	mu      sync.Mutex
	w       *os.File
}

// Record is best effort: a denial reaches the caller whether or not the log or the witness took it.
func (r *Recorder) Record(d ops.Denial) {
	r.mu.Lock()
	defer r.mu.Unlock()
	appendLog(r.Log, d.JSON())
	r.witness(ops.WitnessLine(d))
}

// End writes taskrun's last witness line, END <sha256 of the posted result>.
func (r *Recorder) End(sha256hex string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.witness("END " + sha256hex)
}

// witness writes one line in one write, which a FIFO keeps whole (under PIPE_BUF). With no reader (rootd restarting)
// the open fails and the line is lost; rootd marks such a witness incomplete.
func (r *Recorder) witness(line string) {
	if r.w == nil {
		fd, err := syscall.Open(r.Witness, syscall.O_WRONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			return
		}
		r.w = os.NewFile(uintptr(fd), "witness")
	}
	r.w.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := r.w.WriteString(line + "\n"); err != nil {
		r.w.Close()
		r.w = nil
	}
}

// appendLog keeps the newest LogMax lines. The flock covers every writer in the task: the forwarders and agentbox mcp.
func appendLog(path string, line []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	lines := readLines(f)
	lines = append(lines, line)
	if len(lines) > LogMax {
		lines = lines[len(lines)-LogMax:]
	}
	out := append(bytes.Join(lines, []byte("\n")), '\n')
	if _, err := f.WriteAt(out, 0); err != nil {
		return err
	}
	return f.Truncate(int64(len(out)))
}

func readLines(f *os.File) [][]byte {
	f.Seek(0, 0)
	var out [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 64<<10)
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			out = append(out, bytes.Clone(sc.Bytes()))
		}
	}
	return out
}

// Recent returns up to n of the newest logged denials, newest first. Lines that don't decode are skipped.
func Recent(path string, n int) []ops.Denial {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	syscall.Flock(int(f.Fd()), syscall.LOCK_SH)
	lines := readLines(f)
	var out []ops.Denial
	for i := len(lines) - 1; i >= 0 && len(out) < n; i-- {
		var d ops.Denial
		if json.Unmarshal(lines[i], &d) == nil && d.Code != "" {
			out = append(out, d)
		}
	}
	return out
}
