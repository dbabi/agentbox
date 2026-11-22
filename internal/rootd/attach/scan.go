package attach

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

// CredFiles are the session-home files that hold subscription logins (§4.3): Claude's OAuth tokens and Codex's.
var CredFiles = []string{".claude/.credentials.json", ".codex/auth.json"}

// minToken keeps short values (ids, expiry times written as strings) out of the scan.
const minToken = 20

var tokenKey = regexp.MustCompile(`(?i)token|key`)

// Tokens collects every string under a key naming a token or key in the session-home credential files.
func Tokens(home string) []string {
	var out []string
	for _, f := range CredFiles {
		b, err := readNoFollow(home, f, 1<<20)
		if err != nil {
			continue
		}
		var v any
		if json.Unmarshal(b, &v) == nil {
			collect(v, false, &out)
		}
	}
	return out
}

func collect(v any, keyed bool, out *[]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			collect(x, keyed || tokenKey.MatchString(k), out)
		}
	case []any:
		for _, x := range t {
			collect(x, keyed, out)
		}
	case string:
		if keyed && len(t) >= minToken && !slices.Contains(*out, t) {
			*out = append(*out, t)
		}
	}
}

// readNoFollow reads rel under dir without following a symlink in any component below dir.
func readNoFollow(dir, rel string, max int64) ([]byte, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	fi, err := root.Lstat(rel)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fs.ErrInvalid
	}
	f, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}

// Seen is every token version a session-home held during one attach (the issue's rotation case: a CLI refreshes its
// token mid-session, and the scan must still find the older one). It lives in rootd's memory only.
type Seen struct {
	mu     sync.Mutex
	tokens []string
}

func (s *Seen) Add(ts []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range ts {
		if !slices.Contains(s.tokens, t) {
			s.tokens = append(s.tokens, t)
		}
	}
}

func (s *Seen) All() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.tokens)
}

// Watch re-reads the credential files every interval until stop closes, and once more then.
// shortcut: polling, not inotify; a token that lives for less than one interval can be missed. Use inotify if a CLI
// ever rotates that fast.
func (s *Seen) Watch(home string, every time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		s.Add(Tokens(home))
		select {
		case <-stop:
			s.Add(Tokens(home))
			return
		case <-t.C:
		}
	}
}

// Hit is one file that holds a token. It never carries the token.
type Hit struct{ Path string }

// Scan looks for any of tokens in the workspace entries that changed since start (ctime: a session can't set it back):
// whole file bodies, symlink targets, and the name of every entry (changed or not), including loose git objects,
// which hold a committed file zlib-compressed. Symlinks are not followed.
// shortcut: packfiles aren't unpacked; a session that commits the token and runs git gc hides it from this scan. The
// review diff (§7) covers that until a pack reader lands.
func Scan(ws string, start time.Time, tokens []string) ([]Hit, error) {
	if len(tokens) == 0 {
		return nil, nil
	}
	since := start.Add(-time.Second) // the kernel stamps ctime from a coarse clock, up to a tick behind time.Now
	m := newMatcher(tokens)
	var hits []Hit
	err := filepath.WalkDir(ws, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(ws, p)
		hit := func() error { hits = append(hits, Hit{rel}); return nil }
		if m.has([]byte(d.Name())) {
			// the hit names the entry's dir, never the name itself; nothing under a named dir is listed either
			hits = append(hits, Hit{filepath.Join(filepath.Dir(rel), "(an entry named with a token)")})
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		t := d.Type()
		if !t.IsRegular() && t&fs.ModeSymlink == 0 {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && ctime(st).Before(since) {
			return nil
		}
		if t&fs.ModeSymlink != 0 {
			if l, err := os.Readlink(p); err != nil {
				return err
			} else if m.has([]byte(l)) {
				return hit()
			}
			return nil
		}
		f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		if ok, err := m.in(f); err != nil || ok {
			if err != nil {
				return err
			}
			return hit()
		}
		if looseObject(p) {
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return err
			}
			if z, err := zlib.NewReader(f); err == nil {
				if ok, _ := m.in(z); ok { // a corrupt object is still scanned up to the damage
					return hit()
				}
			}
		}
		return nil
	})
	return hits, err
}

// matcher finds any token in a stream of any length: each chunk is searched with the last longest-1 bytes of the
// one before, so a token split across chunks is still found.
type matcher struct {
	pats    [][]byte
	longest int
}

func newMatcher(tokens []string) *matcher {
	m := &matcher{}
	for _, t := range tokens {
		m.pats = append(m.pats, []byte(t))
		m.longest = max(m.longest, len(t))
	}
	return m
}

func (m *matcher) has(b []byte) bool {
	for _, p := range m.pats {
		if bytes.Contains(b, p) {
			return true
		}
	}
	return false
}

func (m *matcher) in(r io.Reader) (bool, error) {
	buf := make([]byte, 0, m.longest-1+1<<20)
	for {
		n, err := io.ReadFull(r, buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if m.has(buf) {
			return true, nil
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		keep := min(len(buf), m.longest-1)
		buf = append(buf[:0], buf[len(buf)-keep:]...)
	}
}

var objRe = regexp.MustCompile(`/objects/[0-9a-f]{2}/[0-9a-f]{38,62}$`)

func looseObject(p string) bool {
	return strings.Contains(p, ".git/") && objRe.MatchString(filepath.ToSlash(p))
}
