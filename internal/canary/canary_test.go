package canary

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"agentbox/internal/secrets"
)

func TestMint(t *testing.T) {
	c := Mint()
	if !Valid(c) || len(c) != Len {
		t.Fatalf("minted %q fails Valid", c)
	}
	// shaped like a real Anthropic key: the gitleaks rule that the workspace scan uses flags it too
	if h := secrets.Find("k.txt", []byte(`ANTHROPIC_API_KEY="`+c+`"`)); len(h) != 1 || h[0].Rule != "anthropic-api-key" {
		t.Fatalf("gitleaks rules: %v", h)
	}
	if a, b := Mint(), Mint(); a == b {
		t.Fatal("two mints gave the same canary")
	}
	for _, bad := range []string{"", Prefix + "short", c + "x", "x" + c[1:], c[:Len-2] + "AB", strings.Replace(c, c[20:21], "!", 1)} {
		if Valid(bad) {
			t.Errorf("Valid(%q) = true", bad)
		}
	}
}

func wrap(s string, n int) string {
	var b strings.Builder
	for i := 0; i < len(s); i += n {
		b.WriteString(s[i:min(i+n, len(s))] + "\n")
	}
	return b.String()
}

func TestScanForms(t *testing.T) {
	c := Mint()
	raw := []byte(c)
	netrc := "machine github.com\n  login x-access-token\n  password " + c + "\n"
	h := hex.EncodeToString(raw)
	var oxs []string
	for _, b := range raw {
		oxs = append(oxs, fmt.Sprintf("0x%02X", b))
	}
	hits := map[string]string{
		"raw":                   "token = " + c + "\n",
		"in json":               `{"GITHUB_TOKEN":"` + c + `"}`,
		"split across 2 lines":  c[:50] + "\n" + c[50:] + "\n",
		"split, indented":       "a = '" + c[:40] + "'\n    '" + c[40:] + "'\n",
		"quoted pieces with +":  `k = "` + c[:30] + `" + "` + c[30:70] + `" + "` + c[70:] + `"`,
		"base64 alone":          base64.StdEncoding.EncodeToString(raw),
		"base64 url, raw":       base64.RawURLEncoding.EncodeToString(raw),
		"base64 of netrc":       base64.StdEncoding.EncodeToString([]byte(netrc)),
		"base64 of netrc, +1":   base64.StdEncoding.EncodeToString([]byte("x" + netrc)),
		"base64 of netrc, +2":   base64.StdEncoding.EncodeToString([]byte("xy" + netrc)),
		"base64 url of netrc+1": base64.URLEncoding.EncodeToString([]byte("#" + netrc)),
		"base64 wrapped at 76":  wrap(base64.StdEncoding.EncodeToString([]byte("prefix "+netrc)), 76),
		"hex":                   "x=" + h + ";",
		"hex upper":             strings.ToUpper(h),
		"hex 0x, commas":        strings.Join(oxs, ", "),
		`hex \x escapes`:        `"\x` + hexEscapes(raw) + `"`,
		"hex with spaces":       spaced(h),
	}
	for name, data := range hits {
		if !Scan([]byte(data), c) {
			t.Errorf("%s: missed", name)
		}
	}
	misses := map[string]string{
		"empty":            "",
		"other text":       "a commit that names sk-ant- and api03 but holds no key",
		"other canary":     Mint(), // another task's canary is not this one
		"prefix only":      Prefix + "AAAA",
		"half":             c[:Len/2],
		"all but one":      c[:Len-1],
		"base64 of a half": base64.StdEncoding.EncodeToString(raw[:Len/2]),
	}
	for name, data := range misses {
		if Scan([]byte(data), c) {
			t.Errorf("%s: false hit", name)
		}
	}
	if Scan([]byte(c), "") || Scan([]byte(c), c[:Len-1]) || New("x") != nil || New("x").Hit() {
		t.Fatal("an invalid canary matched")
	}
}

func hexEscapes(b []byte) string {
	var s strings.Builder
	for i, x := range b {
		if i > 0 {
			s.WriteString(`\x`)
		}
		fmt.Fprintf(&s, "%02x", x)
	}
	return s.String()
}

func spaced(h string) string {
	var s strings.Builder
	for i := 0; i < len(h); i += 2 {
		s.WriteString(h[i:i+2] + " ")
	}
	return s.String()
}

// A large object is written in pieces: a canary cut at any point between two writes is still found.
func TestScanStream(t *testing.T) {
	c := Mint()
	for _, data := range []string{"pad " + c + " pad", base64.StdEncoding.EncodeToString([]byte("pad " + c)), "0x" + hex.EncodeToString([]byte(c))} {
		for cut := 0; cut <= len(data); cut++ {
			s := New(c)
			s.Write([]byte(data[:cut]))
			s.Write([]byte(data[cut:]))
			if !s.Hit() {
				t.Fatalf("cut at %d of %q: missed", cut, data[:20])
			}
		}
		s := New(c)
		for i := range len(data) {
			s.Write([]byte{data[i]})
		}
		if !s.Hit() {
			t.Fatalf("one byte per write: missed %q", data[:20])
		}
	}
}

// One large write is scanned in pieces (a model request body is up to 32 MiB): a canary across a piece boundary, in
// each form, is still found.
func TestScanLarge(t *testing.T) {
	c := Mint()
	for _, form := range []string{c, base64.StdEncoding.EncodeToString([]byte("p" + c)), "0x" + hex.EncodeToString([]byte(c))} {
		for _, at := range []int{piece - 1 - len(form)/2, 3*piece - 7} {
			data := append(bytes.Repeat([]byte{' '}, at), form...)
			data = append(data, bytes.Repeat([]byte{' '}, piece)...)
			if !Scan(data, c) {
				t.Fatalf("%q at %d of %d: missed", form[:8], at, len(data))
			}
		}
	}
	if Scan(bytes.Repeat([]byte("x"), 5*piece), c) {
		t.Fatal("a hit in a large clean write")
	}
}

func FuzzScan(f *testing.F) {
	c := "sk-ant-" + "api03-" + strings.Repeat("a1_-", 23) + "bAA"
	f.Add([]byte(c), 3)
	f.Add([]byte(base64.StdEncoding.EncodeToString([]byte(c))), 17)
	f.Fuzz(func(t *testing.T, data []byte, cut int) {
		// a split write finds exactly what one write finds
		want := Scan(data, c)
		if cut < 0 || cut > len(data) {
			cut = len(data) / 2
		}
		s := New(c)
		s.Write(data[:cut])
		s.Write(data[cut:])
		if s.Hit() != want {
			t.Fatalf("split at %d: %v, whole: %v", cut, s.Hit(), want)
		}
	})
}
