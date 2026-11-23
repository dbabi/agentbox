package wsfs

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestWalk(t *testing.T) {
	ws, out := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(out, "secret"), []byte("outside"), 0o600)
	os.MkdirAll(filepath.Join(ws, "d/e"), 0o755)
	os.WriteFile(filepath.Join(ws, "d/e/f"), []byte("x"), 0o640)
	os.Symlink(out, filepath.Join(ws, "linkdir"))
	os.Symlink(filepath.Join(out, "secret"), filepath.Join(ws, "linkfile"))
	if err := syscall.Mkfifo(filepath.Join(ws, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	var got []string
	err := Walk(ws, func(e Entry) error {
		got = append(got, e.Rel+" "+e.Mode.Type().String())
		if e.Rel == "linkdir" {
			if l, _ := e.Readlink(); l != out {
				t.Errorf("Readlink = %q", l)
			}
		}
		switch e.Rel {
		case "fifo", "linkfile", "linkdir", "d":
			if f, err := e.Open(); err == nil {
				t.Errorf("Open(%s) = %v; want refused", e.Rel, f.Name())
			}
		case "d/e/f":
			f, err := e.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if b, err := f.ReadAll(1); string(b) != "x" || err != nil || e.Mode.Perm() != 0o640 {
				t.Errorf("d/e/f: %q %v %v", b, err, e.Mode)
			}
		}
		return nil
	})
	want := []string{". d---------", "d d---------", "d/e d---------", "d/e/f ----------", "fifo p---------", "linkdir L---------", "linkfile L---------"}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("Walk = %q, %v; want %q", got, err, want)
	}
}

// The agent swaps an entry after the walk listed it: the reader still never leaves the tree or blocks.
func TestWalkSwap(t *testing.T) {
	ws, out := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(out, "secret"), []byte("outside"), 0o600)
	os.MkdirAll(filepath.Join(ws, "d"), 0o755)
	os.WriteFile(filepath.Join(ws, "f"), nil, 0o644)
	os.WriteFile(filepath.Join(ws, "p"), nil, 0o644)
	var seen []string
	err := Walk(ws, func(e Entry) error {
		seen = append(seen, e.Rel)
		switch e.Rel {
		case "d": // a dir becomes a link to outside before the walk descends
			os.Rename(filepath.Join(ws, "d"), filepath.Join(ws, "d.old"))
			os.Symlink(out, filepath.Join(ws, "d"))
		case "f": // a file becomes a link
			os.Remove(filepath.Join(ws, "f"))
			os.Symlink(filepath.Join(out, "secret"), filepath.Join(ws, "f"))
			if _, err := e.Open(); err == nil {
				t.Error("opened f through a link swapped in")
			}
		case "p": // a file becomes a FIFO with no writer: refused, not blocked
			os.Remove(filepath.Join(ws, "p"))
			syscall.Mkfifo(filepath.Join(ws, "p"), 0o644)
			if _, err := e.Open(); !errors.Is(err, ErrNotRegular) {
				t.Errorf("Open(fifo) = %v", err)
			}
		}
		return nil
	})
	if err == nil || slices.ContainsFunc(seen, func(s string) bool { return strings.Contains(s, "secret") }) {
		t.Errorf("Walk went through the swapped dir: %v %q", err, seen)
	}
}

func TestReadFile(t *testing.T) {
	ws, out := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(out, "secret"), []byte("outside"), 0o600)
	os.MkdirAll(filepath.Join(ws, "a"), 0o755)
	os.WriteFile(filepath.Join(ws, "a/f"), []byte("12345"), 0o644)
	os.Symlink(out, filepath.Join(ws, "l"))
	os.Symlink(filepath.Join(out, "secret"), filepath.Join(ws, "a/s"))
	os.Symlink("f", filepath.Join(ws, "a/rel"))
	syscall.Mkfifo(filepath.Join(ws, "a/fifo"), 0o644)
	if b, err := ReadFile(ws, "a/f", 5); string(b) != "12345" || err != nil {
		t.Errorf("ReadFile(a/f) = %q, %v", b, err)
	}
	if _, err := ReadFile(ws, "a/f", 4); !errors.Is(err, ErrTooLarge) {
		t.Errorf("over the cap: %v", err)
	}
	for _, rel := range []string{"l/secret", "a/s", "a/rel", "a/fifo", "a/../a/f", "/etc/passwd", "a", ""} {
		if b, err := ReadFile(ws, rel, 1<<20); err == nil {
			t.Errorf("ReadFile(%s) = %q, want refused", rel, b)
		}
	}
}

// readers are the files that read an agent-writable tree from root. Each must do it through this package only: a
// new one goes here.
var readers = []string{"../rootd/attach/scan.go", "../rootd/attach/control.go", "../controlpaths/controlpaths.go"}

// fsCalls are the calls that open, list or stat a path by name, which a planted symlink can redirect.
var fsCalls = map[string][]string{
	"os":       {"Open", "OpenFile", "ReadFile", "ReadDir", "Lstat", "Stat", "Readlink", "OpenRoot", "OpenInRoot", "DirFS", "CopyFS"},
	"filepath": {"Walk", "WalkDir", "Glob", "EvalSymlinks"},
	"fs":       {"WalkDir", "ReadFile", "ReadDir", "Glob", "Stat"},
	"syscall":  {"Open", "Openat", "Stat", "Lstat", "Readlink"},
	"unix":     {"Open", "Openat", "Openat2", "Stat", "Lstat", "Fstatat", "Readlink", "Readlinkat"},
	"ioutil":   {"ReadFile", "ReadDir"},
}

func TestReadersUseWalker(t *testing.T) {
	for _, p := range readers {
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		uses := false
		for _, im := range f.Imports {
			if s, _ := strconv.Unquote(im.Path.Value); s == "agentbox/internal/wsfs" {
				uses = true
			}
		}
		if !uses {
			t.Errorf("%s does not import internal/wsfs", p)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if s, ok := n.(*ast.SelectorExpr); ok {
				if x, ok := s.X.(*ast.Ident); ok && slices.Contains(fsCalls[x.Name], s.Sel.Name) {
					t.Errorf("%s calls %s.%s: read the tree through internal/wsfs", p, x.Name, s.Sel.Name)
				}
			}
			return true
		})
	}
}
