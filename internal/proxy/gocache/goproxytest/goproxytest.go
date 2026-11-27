// Package goproxytest is a fake proxy.golang.org for the Go module cache's tests and the cache gate's upstream:
// synthetic modules with their .info, .mod and .zip files, and a checksum database at /sumdb/<name>/ signed with a test
// key. It is never part of a release.
package goproxytest

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/mod/sumdb"
	"golang.org/x/mod/sumdb/dirhash"
	"golang.org/x/mod/sumdb/note"
	modzip "golang.org/x/mod/zip"
)

// Module is one module version: its files (go.mod among them), keyed by path in the module.
type Module struct {
	Path, Version string
	Files         map[string]string
}

type built struct {
	mod, zip  []byte
	h1, modH1 string
}

// Server serves the modules and their checksum database. Its knobs may change while it serves.
type Server struct {
	Name, VKey string // the checksum database's name and verifier key (sum.golang.org+<hash>+<key>)
	Time       string // every version's .info Time

	skey string
	mods map[string]*built // path@version
	vers map[string][]string

	mu    sync.Mutex
	sum   http.Handler
	alter map[string]bool // path@version.ext: served with one byte changed
	gone  map[string]bool // path@version: 410 for every file
	delay time.Duration   // before each module file reply
	rate  int64           // bytes per second of a module file reply; 0: no limit
	log   []string
}

// New builds mods and signs their go.sum lines with a new test key named name.
func New(name string, mods []Module) (*Server, error) {
	skey, vkey, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		return nil, err
	}
	s := &Server{Name: name, VKey: vkey, Time: "2026-01-02T03:04:05Z", skey: skey, mods: map[string]*built{}, vers: map[string][]string{},
		alter: map[string]bool{}, gone: map[string]bool{}}
	for _, m := range mods {
		b, err := build(m)
		if err != nil {
			return nil, err
		}
		s.mods[m.Path+"@"+m.Version] = b
		s.vers[m.Path] = append(s.vers[m.Path], m.Version)
	}
	for _, v := range s.vers {
		sort.Slice(v, func(i, j int) bool { return semver.Compare(v[i], v[j]) < 0 })
	}
	s.Fork()
	return s, nil
}

// Fork starts a new checksum database with the same key: a client that saw the old tree finds the new one
// inconsistent with it (a security error), and one that saw none takes it.
func (s *Server) Fork() {
	ts := sumdb.NewTestServer(s.skey, func(path, vers string) ([]byte, error) {
		b := s.mods[path+"@"+vers]
		if b == nil {
			return nil, fs.ErrNotExist
		}
		return []byte(fmt.Sprintf("%s %s %s\n%s %s/go.mod %s\n", path, vers, b.h1, path, vers, b.modH1)), nil
	})
	h := http.StripPrefix("/sumdb/"+s.Name, sumdb.NewServer(ts))
	s.mu.Lock()
	s.sum = h
	s.mu.Unlock()
}

type memFile struct {
	name string
	data []byte
}

func (f memFile) Path() string                 { return f.name }
func (f memFile) Lstat() (os.FileInfo, error)  { return memInfo(f), nil }
func (f memFile) Open() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(f.data)), nil }

type memInfo memFile

func (i memInfo) Name() string       { return filepath.Base(i.name) }
func (i memInfo) Size() int64        { return int64(len(i.data)) }
func (i memInfo) Mode() fs.FileMode  { return 0o644 }
func (i memInfo) ModTime() time.Time { return time.Time{} }
func (i memInfo) IsDir() bool        { return false }
func (i memInfo) Sys() any           { return nil }

func build(m Module) (*built, error) {
	var files []modzip.File
	names := make([]string, 0, len(m.Files))
	for n := range m.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		files = append(files, memFile{n, []byte(m.Files[n])})
	}
	var z bytes.Buffer
	if err := modzip.Create(&z, module.Version{Path: m.Path, Version: m.Version}, files); err != nil {
		return nil, err
	}
	b := &built{mod: []byte(m.Files["go.mod"]), zip: z.Bytes()}
	if _, ok := m.Files["go.mod"]; !ok { // a +incompatible version: go synthesizes its go.mod, and so does the proxy
		b.mod = []byte("module " + m.Path + "\n")
	}
	tmp, err := os.CreateTemp("", "goproxytest-*.zip")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	tmp.Write(b.zip)
	tmp.Close()
	if b.h1, err = dirhash.HashZip(tmp.Name(), dirhash.Hash1); err != nil {
		return nil, err
	}
	b.modH1, err = dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b.mod)), nil })
	return b, err
}

// GoSum is the go.sum lines of every module, sorted, as go would write them.
func (s *Server) GoSum() string {
	var l []string
	for k, b := range s.mods {
		p, v, _ := strings.Cut(k, "@")
		l = append(l, fmt.Sprintf("%s %s %s", p, v, b.h1), fmt.Sprintf("%s %s/go.mod %s", p, v, b.modH1))
	}
	sort.Strings(l)
	return strings.Join(l, "\n") + "\n"
}

// Zip and Mod are a module version's files as served unaltered.
func (s *Server) Zip(path, version string) []byte { return s.mods[path+"@"+version].zip }
func (s *Server) Mod(path, version string) []byte { return s.mods[path+"@"+version].mod }

// Alter serves path@version.ext with its last byte changed (ext mod or zip), or as built again.
func (s *Server) Alter(path, version, ext string, on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alter[path+"@"+version+"."+ext] = on
}

// Gone answers 410 for every file of path@version (a takedown), or serves it again.
func (s *Server) Gone(path, version string, on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gone[path+"@"+version] = on
}

// Slow delays each module file reply by d and sends it at rate bytes per second (0: no limit).
func (s *Server) Slow(d time.Duration, rate int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delay, s.rate = d, rate
}

// Log returns every request path served since the last Log, and clears it.
func (s *Server) Log() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.log
	s.log = nil
	return l
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.log = append(s.log, r.Method+" "+r.URL.EscapedPath())
	delay, rate, sum := s.delay, s.rate, s.sum
	s.mu.Unlock()
	p := r.URL.EscapedPath()
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if strings.HasPrefix(p, "/sumdb/") {
		if p == "/sumdb/"+s.Name+"/supported" {
			return
		}
		sum.ServeHTTP(w, r)
		return
	}
	esc, rest, ok := strings.Cut(p[1:], "/@")
	mod, err := module.UnescapePath(esc)
	if !ok || err != nil || s.vers[mod] == nil {
		http.NotFound(w, r)
		return
	}
	if rest == "latest" {
		v := s.vers[mod][len(s.vers[mod])-1]
		s.writeInfo(w, mod, v)
		return
	}
	file, ok := strings.CutPrefix(rest, "v/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	if file == "list" {
		io.WriteString(w, strings.Join(s.vers[mod], "\n")+"\n")
		return
	}
	i := strings.LastIndex(file, ".")
	if i < 0 {
		http.NotFound(w, r)
		return
	}
	v, err := module.UnescapeVersion(file[:i])
	ext := file[i+1:]
	b := s.mods[mod+"@"+v]
	s.mu.Lock()
	gone, alter := s.gone[mod+"@"+v], s.alter[mod+"@"+v+"."+ext]
	s.mu.Unlock()
	switch {
	case err != nil || b == nil:
		http.NotFound(w, r)
	case gone:
		http.Error(w, "gone", http.StatusGone)
	case ext == "info":
		s.writeInfo(w, mod, v)
	case ext == "mod" || ext == "zip":
		data := b.zip
		if ext == "mod" {
			data = b.mod
		}
		if alter {
			data = slices.Clone(data)
			data[len(data)-1] ^= 1
		}
		time.Sleep(delay)
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		send(w, data, rate)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) writeInfo(w http.ResponseWriter, mod, v string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"Version": v, "Time": s.Time})
}

// send writes data at rate bytes per second, in 32 KiB pieces.
func send(w http.ResponseWriter, data []byte, rate int64) {
	if rate <= 0 {
		w.Write(data)
		return
	}
	f, _ := w.(http.Flusher)
	for len(data) > 0 {
		n := min(len(data), 32<<10)
		if _, err := w.Write(data[:n]); err != nil {
			return
		}
		if f != nil {
			f.Flush()
		}
		data = data[n:]
		time.Sleep(time.Duration(int64(n) * int64(time.Second) / rate))
	}
}
