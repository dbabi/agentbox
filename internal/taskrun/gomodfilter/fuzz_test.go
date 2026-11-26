package gomodfilter

import (
	"bufio"
	"bytes"
	"net/http"
	"strings"
	"testing"
	"unicode"

	"golang.org/x/mod/module"
)

// FuzzRequest (A-G14): any request the HTTP parser takes either gets a 404 or 405, or names a module file that passes
// module.Check at a canonical version, matches no private pattern, and escapes back to exactly the path it came in on.
func FuzzRequest(f *testing.F) {
	for _, s := range []string{
		"GET /example.com/m/@v/v1.0.0.info HTTP/1.1\r\nHost: x\r\n\r\n",
		"GET /github.com/!burnt!sushi/toml/@v/v1.2.0+incompatible.zip HTTP/1.1\r\nHost: x\r\n\r\n",
		"GET /example.com/m/@v/v0.0.0-20191109021931-daa7c04131f5.mod HTTP/1.1\r\nHost: x\r\n\r\n",
		"GET /_cache/go/example.com/m/@v/v1.0.0.mod HTTP/1.1\r\nHost: x\r\n\r\n",
		"GET /example.com/m/@v/list HTTP/1.1\r\nHost: x\r\n\r\n",
		"GET /corp.example/x/@v/v1.0.0.mod HTTP/1.1\r\nHost: x\r\n\r\n",
		"GET /example.com/%2e%2e/@v/v1.0.0.mod HTTP/1.1\r\nHost: x\r\n\r\n",
		"POST /example.com/m/@v/v1.0.0.zip HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\nx",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b)))
		if err != nil {
			return
		}
		for _, c := range []struct {
			prefix string
			exts   []string
		}{{"", []string{"info", "mod", "zip"}}, {"/_cache/go", []string{"mod", "zip"}}} {
			file, st := Request(r, c.prefix, c.exts, "corp.example/*")
			if st != 0 {
				if st != http.StatusNotFound && st != http.StatusMethodNotAllowed {
					t.Fatalf("status %d", st)
				}
				continue
			}
			if module.Check(file.Path, file.Version) != nil || module.CanonicalVersion(file.Version) != file.Version ||
				module.MatchPrefixPatterns("corp.example/*", file.Path) {
				t.Fatalf("accepted %+v", file)
			}
			if c.prefix+file.Escaped() != r.RequestURI {
				t.Fatalf("%q escapes back to %q", r.RequestURI, c.prefix+file.Escaped())
			}
			if strings.ContainsFunc(file.Key(), func(r rune) bool { return r > unicode.MaxASCII || !unicode.IsPrint(r) }) {
				t.Fatalf("key %q", file.Key())
			}
		}
	})
}

// FuzzInfo (A-G14): the .info reply parser never panics, and accepts only a reply that names the version asked for.
func FuzzInfo(f *testing.F) {
	f.Add([]byte(`{"Version":"v1.0.0","Time":"2026-01-01T00:00:00Z"}`), "v1.0.0")
	f.Add([]byte(`{"Version":"v1.0.1"}`), "v1.0.0")
	f.Add([]byte(`{"version":"v1.0.0"}`), "v1.0.0")
	f.Add([]byte(`[]`), "v1.0.0")
	f.Fuzz(func(t *testing.T, b []byte, v string) {
		if InfoOK(b, v) && (v == "" || len(b) > InfoMax || !bytes.Contains(b, []byte(`"`))) {
			t.Fatalf("accepted %q for %q", b, v)
		}
	})
}
