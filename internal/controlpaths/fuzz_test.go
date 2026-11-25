package controlpaths

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzFindRoots: a task writes the .git files, commondir files and links that FindRoots reads as root, so they hold
// any bytes. FindRoots never panics, and each git dir it returns is a clean path inside the workspace.
func FuzzFindRoots(f *testing.F) {
	f.Add([]byte("gitdir: ../g\n"), []byte("../shared\n"), "g")
	f.Add([]byte("gitdir: /workspace/g"), []byte("/home/agent/x"), "/proc/self/cwd")
	f.Add([]byte("gitdir:"+strings.Repeat("../", 40)+"g"), []byte(".."), "lnk/../../g")
	f.Add([]byte("gitdir: lnk/x"), []byte("lnk"), "lnk")
	f.Fuzz(func(t *testing.T, gitfile, commondir []byte, link string) {
		ws := t.TempDir()
		for name, b := range map[string][]byte{"sub/.git": gitfile, "g/commondir": commondir, "g/HEAD": []byte("ref: refs/heads/main\n")} {
			os.MkdirAll(filepath.Join(ws, filepath.Dir(name)), 0o755)
			if err := os.WriteFile(filepath.Join(ws, name), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		os.MkdirAll(filepath.Join(ws, "g", "objects"), 0o755)
		os.MkdirAll(filepath.Join(ws, "g", "refs"), 0o755)
		os.Symlink(link, filepath.Join(ws, "lnk")) // a link the gitdir: or commondir path can pass through; "" makes none
		r, err := FindRoots(ws)
		if err != nil {
			return
		}
		for _, g := range r.GitDirs {
			if g != path.Clean(g) || path.IsAbs(g) || g == ".." || strings.HasPrefix(g, "../") {
				t.Fatalf("git dir %q is not a clean workspace path (.git %q, commondir %q, link %q)", g, gitfile, commondir, link)
			}
		}
	})
}
