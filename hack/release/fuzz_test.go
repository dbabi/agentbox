package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// FuzzVersion: a version build accepts names releases/<ver> on the box and the tarball, so it is one path element that
// install.sh's charset check also accepts (issue #10).
func FuzzVersion(f *testing.F) {
	for _, v := range []string{"2026.11.1", "0", "..", "a/b", "1~rc.1", "-x", strings.Repeat("9", 65), "1\n"} {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, v string) {
		if !reVersion.MatchString(v) {
			return
		}
		// install.sh: case $VER in ''|[!0-9A-Za-z]*|*[!0-9A-Za-z._~-]*) die
		alnum := func(c rune) bool { return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }
		if !alnum(rune(v[0])) || strings.IndexFunc(v, func(c rune) bool { return !alnum(c) && !strings.ContainsRune("._~-", c) }) >= 0 {
			t.Fatalf("install.sh refuses %q", v)
		}
		if n := "agentbox-" + v + ".tgz"; filepath.Base(n) != n || filepath.Base(v) != v || v == "." || v == ".." {
			t.Fatalf("%q is not one path element", v)
		}
	})
}
