// Package witness is rootd's side of the per-task witness FIFO (ARCHITECTURE.md §2.1, §4.2, §5.6 Witness): create it at
// task.start, hold the read end and keep at most 64 KiB of lines, drain it at task.stop, and remove the dir. The
// task's forwarders and agentbox mcp write `<id> <op> <code> <by>` lines; taskrun ends with `END <sha256>`.
// The check of the kept lines against task_denials is weeks 9-10.
package witness

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"agentbox/internal/ops"
)

// Root is /run/agentbox-witness/t (tmpfiles, §2.1); a task's FIFO is <Root>/<task>/witness.
const Root = "/run/agentbox-witness/t"

// MaxKept is how many bytes of lines rootd keeps per task; every later line only counts in Dropped.
const MaxKept = 64 << 10

const maxLine = 256 // longer than any witness line: the rest of it counts as one bad line

var reTask = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Result is what rootd keeps of one task's witness.
type Result struct {
	Lines      []string `json:"lines"`      // well-formed lines within MaxKept, in order
	Bad        int      `json:"bad"`        // lines within MaxKept that fail the one anchored pattern
	Dropped    int      `json:"dropped"`    // lines past MaxKept
	End        string   `json:"end"`        // the last END line's sha256, kept even past MaxKept
	Incomplete bool     `json:"incomplete"` // rootd restarted mid-task: lines written while it was down are lost
}

// W is one open witness.
type W struct {
	dir  string
	f    *os.File
	done chan struct{}
	mu   sync.Mutex
	r    Result
	kept int
}

// Create makes <root>/<task>/ (root:gid 0750) holding the FIFO witness (root:gid 0620) and starts reading it. gid is
// the agent's group; gid < 0 leaves the group as is (tests). It fails if the dir already exists.
func Create(root, task string, gid int) (*W, error) {
	if !reTask.MatchString(task) {
		return nil, fmt.Errorf("bad task id %q", task)
	}
	dir := filepath.Join(root, task)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	fifo := filepath.Join(dir, "witness")
	err := syscall.Mkfifo(fifo, 0o600)
	if err == nil && gid >= 0 { // the owner stays rootd's: root
		err = errors.Join(os.Chown(fifo, -1, gid), os.Chown(dir, -1, gid))
	}
	if err == nil { // modes after the owner, so the agent's group never sees a wider file
		err = errors.Join(os.Chmod(fifo, 0o620), os.Chmod(dir, 0o750))
	}
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	w, err := open(dir, false)
	if err != nil {
		os.RemoveAll(dir)
	}
	return w, err
}

// Reopen opens an existing witness after a rootd restart. It is marked incomplete.
func Reopen(root, task string) (*W, error) {
	if !reTask.MatchString(task) {
		return nil, fmt.Errorf("bad task id %q", task)
	}
	return open(filepath.Join(root, task), true)
}

// open holds the FIFO read-write: a reader with no writer would see EOF, and an O_RDWR end keeps reads blocking until
// Drain. Lines a writer leaves in the pipe while no reader holds it are refused (ENXIO on its open), not queued.
func open(dir string, incomplete bool) (*W, error) {
	fi, err := os.Lstat(filepath.Join(dir, "witness"))
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeNamedPipe == 0 {
		return nil, fmt.Errorf("%s/witness is not a FIFO", dir)
	}
	fd, err := syscall.Open(filepath.Join(dir, "witness"), syscall.O_RDWR|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "witness") // non-blocking, so the runtime poller serves reads and Drain's deadline
	w := &W{dir: dir, f: f, done: make(chan struct{}), r: Result{Incomplete: incomplete}}
	go w.read()
	return w, nil
}

func (w *W) read() {
	defer close(w.done)
	br := bufio.NewReaderSize(w.f, maxLine)
	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			for errors.Is(err, bufio.ErrBufferFull) { // skip the rest of an over-long line
				_, err = br.ReadSlice('\n')
			}
			w.add(nil, maxLine)
		} else if len(line) > 0 { // also a last line with no newline when Drain stops the read
			w.add(line, len(line))
		}
		if err != nil {
			return
		}
	}
}

// add counts one line of n bytes; b is nil for an over-long line.
func (w *W) add(b []byte, n int) {
	long := b == nil
	line := strings.TrimSuffix(string(b), "\n")
	e, err := ops.ParseWitness(line)
	w.mu.Lock()
	defer w.mu.Unlock()
	if !long && err == nil && e.End != "" {
		w.r.End = e.End
		return
	}
	if w.kept+n > MaxKept {
		w.r.Dropped++
		return
	}
	w.kept += n
	if long || err != nil {
		w.r.Bad++
		return
	}
	w.r.Lines = append(w.r.Lines, line)
}

// Drain reads what writers left in the pipe and stops reading. Call it once the task's cgroup is empty: with no writer
// left, everything written is already in the pipe.
func (w *W) Drain() Result {
	w.f.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	r := w.r
	r.Lines = append([]string(nil), w.r.Lines...)
	return r
}

// Remove closes the FIFO and deletes the task's dir (task.stop step 4).
func (w *W) Remove() error {
	w.f.Close()
	<-w.done
	return os.RemoveAll(w.dir)
}
