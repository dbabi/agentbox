package keys

import (
	"bytes"
	"encoding/base64"
	"math/rand/v2"
	"net/url"
	"strings"
	"testing"
)

const fakeKey = "sk-ant-api03-GATEfakeKEY0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-0123456789AA"

// feedAll runs b through a fresh matcher in chunks of n bytes: what passed, and whether it found the key.
func feedAll(key string, b []byte, n int) ([]byte, bool) {
	m := newMatcher(key)
	var out []byte
	for i := 0; i < len(b); i += n {
		o, found := m.feed(b[i:min(i+n, len(b))])
		if found {
			return out, true
		}
		out = append(out, o...)
	}
	return append(out, m.rest()...), false
}

// The key is caught raw, base64 (standard and URL-safe, at every alignment) and percent-encoded, at every chunk size,
// so split across any boundary; nothing of a stream that holds it passes past the match, and a stream that doesn't
// passes byte for byte.
func TestMatcher(t *testing.T) {
	var forms []string
	for a := range 3 {
		pre := strings.Repeat("p", a)
		forms = append(forms, base64.StdEncoding.EncodeToString([]byte(pre+fakeKey+"tail")),
			base64.URLEncoding.EncodeToString([]byte(pre+fakeKey+"q")), base64.RawStdEncoding.EncodeToString([]byte(pre+fakeKey)))
	}
	var pct strings.Builder
	for i := 0; i < len(fakeKey); i++ {
		pct.WriteString("%" + strings.ToUpper(string("0123456789abcdef"[fakeKey[i]>>4])) + strings.ToUpper(string("0123456789abcdef"[fakeKey[i]&15])))
	}
	forms = append(forms, fakeKey, pct.String(), strings.ToLower(pct.String()))
	for _, f := range forms {
		stream := []byte(`event: content_block_delta` + "\ndata: {\"delta\":{\"text\":\"" + f + "\"}}\n\n")
		for _, n := range []int{1, 2, 3, 7, 64, 100, 4096} {
			out, found := feedAll(fakeKey, stream, n)
			if !found {
				t.Fatalf("form %.20s... missed at chunk size %d", f, n)
			}
			if bytes.Contains(out, []byte(f[:len(f)/2])) && len(f) > 40 {
				t.Fatalf("chunk size %d: half the encoded key passed before the match", n)
			}
		}
	}
	r := rand.New(rand.NewPCG(1, 2))
	clean := make([]byte, 1<<20)
	for i := range clean {
		clean[i] = byte(r.IntN(95) + 32)
	}
	clean = append(clean, []byte(fakeKey[:len(fakeKey)-1]+"!")...) // almost the key, at the very end
	for _, n := range []int{1, 13, 32 << 10} {
		out, found := feedAll(fakeKey, clean, n)
		if found || !bytes.Equal(out, clean) {
			t.Fatalf("chunk size %d: a clean stream came out changed (found %v)", n, found)
		}
	}
	m := newMatcher(fakeKey)
	if !m.contains("x-echo: " + url.QueryEscape(fakeKey)) { // the key's characters need no escape: this is the raw key
		t.Error("a header with the key passed")
	}
	if out, _ := newMatcher("").feed([]byte("x")); string(out) != "x" {
		t.Error("an empty key held bytes back")
	}
}

// FuzzMatcher: chunked feeding finds the key exactly when the whole stream holds it, and a clean stream comes out as
// it went in.
func FuzzMatcher(f *testing.F) {
	f.Add([]byte("abc"+fakeKey+"def"), uint8(5))
	f.Add([]byte("nothing to see"), uint8(1))
	f.Fuzz(func(t *testing.T, b []byte, n uint8) {
		size := int(n%64) + 1
		out, found := feedAll(fakeKey, b, size)
		whole, wfound := feedAll(fakeKey, b, max(len(b), 1))
		if found != wfound {
			t.Fatalf("chunk size %d found %v, whole stream %v", size, found, wfound)
		}
		if !found && (!bytes.Equal(out, b) || !bytes.Equal(whole, b)) {
			t.Fatal("a clean stream came out changed")
		}
		if found != newMatcher(fakeKey).contains(string(b)) {
			t.Fatalf("feed and contains disagree on %q", b)
		}
	})
}
