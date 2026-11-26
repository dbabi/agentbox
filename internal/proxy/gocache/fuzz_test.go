package gocache

import (
	"bytes"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb"

	"agentbox/internal/proxy/gocache/goproxytest"
	"agentbox/internal/taskrun/gomodfilter"
)

// FuzzZip (A-G14): a hostile .zip never panics zip.CheckZip and HashZip, and only a zip that passes CheckZip gets an
// h1 the fill would compare.
func FuzzZip(f *testing.F) {
	up, err := goproxytest.New("sum.golang.org", mods())
	if err != nil {
		f.Fatal(err)
	}
	z := up.Zip("example.com/a", "v1.0.0")
	f.Add(z)
	f.Add(z[:len(z)/2])
	f.Add(bytes.Replace(z, []byte("example.com/a@v1.0.0/"), []byte("example.com/a@v1.0.0/../"), 1))
	f.Add([]byte("PK\x05\x06" + strings.Repeat("\x00", 18)))
	dir := f.TempDir()
	file := gomodfilter.File{Path: "example.com/a", Version: "v1.0.0", Ext: "zip"}
	f.Fuzz(func(t *testing.T, b []byte) {
		p := filepath.Join(dir, "z")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		h, err := hash(file, p)
		if err == nil && !strings.HasPrefix(h, "h1:") {
			t.Fatalf("hash %q", h)
		}
	})
}

// fuzzOps is a checksum database that answers every lookup with one reply and every tile with another.
type fuzzOps struct {
	key           string
	lookup, tiles []byte
}

func (o *fuzzOps) ReadRemote(path string) ([]byte, error) {
	if strings.HasPrefix(path, "/lookup/") {
		return o.lookup, nil
	}
	if strings.HasPrefix(path, "/tile/") {
		return o.tiles, nil
	}
	return nil, errors.New("no such path")
}
func (o *fuzzOps) ReadConfig(file string) ([]byte, error) {
	if file == "key" {
		return []byte(o.key), nil
	}
	return nil, nil
}
func (o *fuzzOps) WriteConfig(string, []byte, []byte) error { return nil }
func (o *fuzzOps) ReadCache(string) ([]byte, error)         { return nil, errors.New("none") }
func (o *fuzzOps) WriteCache(string, []byte)                {}
func (o *fuzzOps) Log(string)                               {}
func (o *fuzzOps) SecurityError(string)                     {}

// FuzzSumdb (A-G14): hostile checksum database replies (lookup records with their signed tree notes, tiles) never
// panic the client the fill uses, and never yield a line for another module or version.
func FuzzSumdb(f *testing.F) {
	up, err := goproxytest.New("sum.golang.org", mods())
	if err != nil {
		f.Fatal(err)
	}
	vkey := up.VKey
	get := func(p string) []byte {
		w := httptest.NewRecorder()
		up.ServeHTTP(w, httptest.NewRequest("GET", "/sumdb/sum.golang.org"+p, nil))
		return w.Body.Bytes()
	}
	rec := get("/lookup/example.com/a@v1.0.0") // a real record and its signed tree, then that tree's tile
	f.Add(rec, get("/tile/8/0/000.p/1"))
	f.Add(rec, []byte{})
	f.Add([]byte("1\nexample.com/a v1.0.0 h1:x=\nexample.com/a v1.0.0/go.mod h1:y=\n\ngo.sum database tree\n1\nAAAA\n\n— sum.golang.org AAAA\n"), []byte{})
	f.Add([]byte("x"), bytes.Repeat([]byte{0}, 32))
	f.Add([]byte(""), []byte(""))
	f.Fuzz(func(t *testing.T, lookup, tiles []byte) {
		lines, err := sumdb.NewClient(&fuzzOps{key: vkey, lookup: lookup, tiles: tiles}).Lookup("example.com/a", "v1.0.0")
		if err != nil {
			return
		}
		for _, l := range lines {
			if !strings.HasPrefix(l, "example.com/a v1.0.0 ") {
				t.Fatalf("line %q", l)
			}
		}
	})
}
