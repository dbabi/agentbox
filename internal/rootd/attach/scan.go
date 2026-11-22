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

// maxScanFile bounds what the scan reads of one file: §4.2's output cap is 50 MB, and a token sits anywhere in it.
const maxScanFile = 64 << 20

// Hit is one file that holds a token. It never carries the token.
type Hit struct{ Path string }

// Scan looks for any of tokens in the workspace files that changed since start (ctime: a session can't set it back),
// including loose git objects, which hold a committed file zlib-compressed. Symlinks are not followed.
// shortcut: packfiles aren't unpacked; a session that commits the token and runs git gc hides it from this scan. The
// review diff (§7) covers that until a pack reader lands.
func Scan(ws string, start time.Time, tokens []string) ([]Hit, error) {
	if len(tokens) == 0 {
		return nil, nil
	}
	since := start.Add(-time.Second) // the kernel stamps ctime from a coarse clock, up to a tick behind time.Now
	pats := make([][]byte, len(tokens))
	for i, t := range tokens {
		pats[i] = []byte(t)
	}
	has := func(b []byte) bool {
		for _, p := range pats {
			if bytes.Contains(b, p) {
				return true
			}
		}
		return false
	}
	var hits []Hit
	err := filepath.WalkDir(ws, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if ok && ctime(st).Before(since) {
			return nil
		}
		f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, maxScanFile))
		if err != nil {
			return err
		}
		if !has(b) && looseObject(p) {
			if z, err := zlib.NewReader(bytes.NewReader(b)); err == nil {
				b, _ = io.ReadAll(io.LimitReader(z, maxScanFile))
			}
		}
		if has(b) {
			rel, _ := filepath.Rel(ws, p)
			hits = append(hits, Hit{rel})
		}
		return nil
	})
	return hits, err
}

var objRe = regexp.MustCompile(`/objects/[0-9a-f]{2}/[0-9a-f]{38,62}$`)

func looseObject(p string) bool {
	return strings.Contains(p, ".git/") && objRe.MatchString(filepath.ToSlash(p))
}
