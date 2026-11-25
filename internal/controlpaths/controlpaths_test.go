package controlpaths

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A-G2: lockfile-only changes need no --ack-control-changes; a planted .mcp.json still does.
func TestChanged(t *testing.T) {
	if c := Changed([]string{"go.mod", "go.sum", "web/package-lock.json", "proj/go.sum", "src/agents.md.go", "env/bin/python"}); len(c) != 0 {
		t.Fatalf("lockfiles are control paths: %q", c)
	}
	got := Changed([]string{"go.sum", "proj/.mcp.json", ".claude/skills/x/SKILL.md", "p/.git/hooks/pre-commit", "CLAUDE.md", "a/AGENTS.md", ".envrc", "x/.devcontainer/devcontainer.json",
		"a/.agents/skills/s/SKILL.md", "sub/opencode.json", "opencode.jsonc", ".vscode/tasks.json", "p/.idea/workspace.xml", ".zed/settings.json", "sub/.git", "sub/.git/config",
		"AGENTS.override.md", "p/AGENTS.override.md", "CLAUDE.local.md", "AGENTS.override.md.bak"})
	want := []string{"proj/.mcp.json", ".claude/skills/x/SKILL.md", "p/.git/hooks/pre-commit", "CLAUDE.md", "a/AGENTS.md", ".envrc", "x/.devcontainer/devcontainer.json",
		"a/.agents/skills/s/SKILL.md", "sub/opencode.json", "opencode.jsonc", ".vscode/tasks.json", "p/.idea/workspace.xml", ".zed/settings.json", "sub/.git", "sub/.git/config",
		"AGENTS.override.md", "p/AGENTS.override.md", "CLAUDE.local.md"}
	if !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
}

// #123: a venv is found by its pyvenv.cfg whatever its name, and a gitdir: line names a git dir in the workspace.
func TestRoots(t *testing.T) {
	ws := t.TempDir()
	for f, b := range map[string]string{"env/pyvenv.cfg": "home = /usr/bin\n", "env/bin/activate": "", "env/lib/python3/site-packages/x.pth": "import os\n",
		"env/lib/python3/site-packages/m.py": "", "notvenv/bin/x": "", "wt/.git": "gitdir: ../meta\n", "meta/config": "", "meta/objects/ab": "",
		"abs/.git": "gitdir: /workspace/m2\n", "m2/hooks/post-checkout": "", "out/.git": "gitdir: ../../elsewhere\n", "big/.git": "gitdir: x\n"} {
		os.MkdirAll(filepath.Join(ws, filepath.Dir(f)), 0o755)
		os.WriteFile(filepath.Join(ws, f), []byte(b), 0o644)
	}
	r, err := FindRoots(ws)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(r.GitDirs)
	if !slices.Equal(r.Venvs, []string{"env"}) || !slices.Equal(r.GitDirs, []string{"big/x", "m2", "meta"}) {
		t.Fatalf("roots %+v", r)
	}
	for p, want := range map[string]bool{"env/pyvenv.cfg": true, "env/bin": true, "env/bin/activate": true, "env/lib/python3/site-packages/x.pth": true,
		"env/lib/python3/site-packages/m.py": false, "notvenv/bin/x": false, "meta/config": true, "meta": false, "m2/hooks/post-checkout": true,
		"wt/.git": true, "metadata/config": false} {
		if r.Is(p) != want {
			t.Errorf("Is(%q) = %v", p, !want)
		}
	}
}

// #182: a venv at the workspace root; the dir a git dir's commondir names; a bare repo anywhere, the root included;
// a gitdir: naming the workspace root.
func TestRootsByContent(t *testing.T) {
	write := func(ws string, files map[string]string) {
		for f, b := range files {
			os.MkdirAll(filepath.Join(ws, filepath.Dir(f)), 0o755)
			os.WriteFile(filepath.Join(ws, f), []byte(b), 0o644)
		}
	}
	ws := t.TempDir()
	write(ws, map[string]string{"pyvenv.cfg": "home = /usr/bin\n", "bin/python": "", "lib/python3.13/site-packages/evil.pth": "import os\n",
		"lib/python3.13/site-packages/m.py": "", "src/main.py": "", "sub/.venv2/pyvenv.cfg": "", "sub/.venv2/bin/python": "",
		"wt/.git": "gitdir: ../meta\n", "meta/commondir": "../hidden\n", "hidden/config": "", "hidden/objects/ab": "",
		"main/.git/worktrees/w/commondir": "../../../../shared", "shared/hooks/x": "",
		"bare/HEAD": "ref: refs/heads/main\n", "bare/config": "", "bare/objects/ab": "", "bare/refs/heads/main": "",
		"nothead/HEAD": "", "nothead/objects/x": "", "stray/commondir": "../other", "other/config": ""})
	r, err := FindRoots(ws)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(r.Venvs)
	slices.Sort(r.GitDirs)
	if !slices.Equal(r.Venvs, []string{".", "sub/.venv2"}) || !slices.Equal(r.GitDirs, []string{"bare", "hidden", "meta", "shared"}) {
		t.Fatalf("roots %+v", r)
	}
	for p, want := range map[string]bool{"pyvenv.cfg": true, "bin/python": true, "lib/python3.13/site-packages/evil.pth": true,
		"lib/python3.13/site-packages/m.py": false, "src/main.py": false, "sub/.venv2/bin/python": true,
		"hidden/config": true, "shared/hooks/x": true, "bare/config": true, "bare/HEAD": true, "nothead/HEAD": false, "other/config": false} {
		if r.Is(p) != want {
			t.Errorf("Is(%q) = %v", p, !want)
		}
	}
	// the root as a git dir: everything in the workspace is under it
	ws = t.TempDir()
	write(ws, map[string]string{"a/.git": "gitdir: /workspace\n", "config": "", "src/x.go": ""})
	if r, err = FindRoots(ws); err != nil || !slices.Equal(r.GitDirs, []string{"."}) || !r.Is("config") || !r.Is("src/x.go") {
		t.Fatalf("root git dir: %+v %v", r, err)
	}
	// a git dir in session-home can change after its .git file was acked: refused, also when a relative path climbs
	// out of /workspace into it (#201) or a link on the way leads there
	for _, files := range []map[string]string{{"p/.git": "gitdir: /home/agent/g\n"}, {"wt/.git": "gitdir: ../m\n", "m/commondir": "/home/agent/c"},
		{"p/.git": "gitdir: /home/agent\n"}, {".git": "gitdir: ../home/agent/gd\n"}, {"p/.git": "gitdir: ../../home/agent/g\n"},
		{"wt/.git": "gitdir: ../m\n", "m/commondir": "../../home/agent/c"}, {"p/.git": "gitdir: ../../../../home/./agent/g\n"}} {
		ws = t.TempDir()
		write(ws, files)
		if _, err := FindRoots(ws); err == nil || !strings.Contains(err.Error(), "session-home") {
			t.Errorf("%v: %v", files, err)
		}
	}
	// a relative path that climbs out and back in is in the workspace
	ws = t.TempDir()
	write(ws, map[string]string{"p/.git": "gitdir: ../../workspace/store\n", "store/config": ""})
	if r, err := FindRoots(ws); err != nil || !slices.Equal(r.GitDirs, []string{"store"}) {
		t.Fatalf("out and back in: %+v %v", r, err)
	}
}

// #199, #202: a .git that is a symlink is the git dir it resolves to; a link on a gitdir: path is followed as the
// kernel would; either one into session-home is refused. A symlinked HEAD, objects or refs still marks a bare repo,
// and a symlinked commondir or pyvenv.cfg counts.
func TestRootsThroughLinks(t *testing.T) {
	type link struct{ at, to string }
	mk := func(files map[string]string, links ...link) string {
		ws := t.TempDir()
		for f, b := range files {
			os.MkdirAll(filepath.Join(ws, filepath.Dir(f)), 0o755)
			os.WriteFile(filepath.Join(ws, f), []byte(b), 0o644)
		}
		for _, l := range links {
			os.MkdirAll(filepath.Join(ws, filepath.Dir(l.at)), 0o755)
			if err := os.Symlink(l.to, filepath.Join(ws, l.at)); err != nil {
				t.Fatal(err)
			}
		}
		return ws
	}
	for _, c := range []struct {
		name  string
		ws    string
		git   []string
		venvs []string
	}{
		{"a .git link to a dir", mk(map[string]string{"store/config": "", "store/HEAD": ""}, link{"proj/.git", "../store"}), []string{"store"}, nil},
		{"a .git link, absolute", mk(map[string]string{"store/config": ""}, link{"proj/.git", "/workspace/store"}), []string{"store"}, nil},
		{"a .git link to a gitfile", mk(map[string]string{"gf": "gitdir: meta\n", "proj/meta/config": ""}, link{"proj/.git", "../gf"}), []string{"proj/meta"}, nil},
		{"a gitdir: through a link", mk(map[string]string{"p/.git": "gitdir: h/g\n", "real/g/config": ""}, link{"p/h", "../real"}), []string{"real/g"}, nil},
		{"a .. after a link", mk(map[string]string{"p/.git": "gitdir: h/../g\n", "a/b/x": "", "a/g/config": ""}, link{"p/h", "../a/b"}), []string{"a/g"}, nil},
		{"a bare repo with linked objects and refs", mk(map[string]string{"b/HEAD": "", "b/config": "", "o/ab": "", "r/heads/main": ""},
			link{"b/objects", "../o"}, link{"b/refs", "../r"}), []string{"b"}, nil},
		{"a linked commondir", mk(map[string]string{"wt/.git": "gitdir: ../m\n", "cd": "../c\n", "c/config": ""}, link{"m/commondir", "../cd"}),
			[]string{"c", "m"}, nil},
		{"a linked pyvenv.cfg", mk(map[string]string{"cfg": "home = /usr/bin\n", "env/bin/python": ""}, link{"env/pyvenv.cfg", "../cfg"}), nil, []string{"env"}},
		{"links outside the workspace", mk(nil, link{"proj/.git", "/etc"}, link{"env/pyvenv.cfg", "/usr/pyvenv.cfg"}), nil, nil},
	} {
		r, err := FindRoots(c.ws)
		slices.Sort(r.GitDirs)
		if err != nil || !slices.Equal(r.GitDirs, c.git) || !slices.Equal(r.Venvs, c.venvs) {
			t.Errorf("%s: %+v %v", c.name, r, err)
		}
	}
	for _, c := range []struct {
		name string
		ws   string
	}{
		{"a .git link into session-home", mk(nil, link{"proj/.git", "/home/agent/g"})},
		{"a relative .git link into session-home", mk(nil, link{".git", "../home/agent/g"})},
		{"a gitdir: through a link to session-home", mk(map[string]string{"p/.git": "gitdir: h/g\n"}, link{"p/h", "/home/agent"})},
		{"a linked commondir into session-home", mk(map[string]string{"wt/.git": "gitdir: ../m\n"}, link{"m/commondir", "/home/agent/cd"})},
	} {
		if _, err := FindRoots(c.ws); err == nil || !strings.Contains(err.Error(), "session-home") {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if _, err := FindRoots(mk(nil, link{"a/.git", "../b/.git"}, link{"b/.git", "../a/.git"})); err == nil || !strings.Contains(err.Error(), "symlinks") {
		t.Errorf("a link loop: %v", err)
	}
}

func TestResolve(t *testing.T) {
	trees := []Tree{{Mount: Workspace, Links: map[string]string{"l": "real", "abs": "/home/agent/x", "up": "../..", "d/back": "../l", "cwd": "/proc/self/cwd"}},
		{Mount: Home, Links: map[string]string{".local": "/workspace/dot"}}, {Mount: "/opaque", Opaque: true}}
	for p, want := range map[string]struct {
		t   int
		rel string
		via string
	}{
		"/workspace/l/f": {0, "real/f", "/workspace/l"}, "/workspace/abs/y": {1, "x/y", "/workspace/abs"}, "/workspace/up/workspace/l": {0, "real", "/workspace/up /workspace/l"},
		"/workspace/d/back/z": {0, "real/z", "/workspace/d/back /workspace/l"}, "/home/agent/.local/bin": {0, "dot/bin", "/home/agent/.local"},
		"/workspace/../home/agent": {1, ".", ""}, "/workspace/l/../x": {0, "x", "/workspace/l"}, "/etc/passwd": {-1, "", ""},
		"/opaque/a/b": {2, ".", ""}, "/workspace": {0, ".", ""}, "/workspace/./a//b/": {0, "a/b", ""}, "/workspace/cwd/x": {-1, "", "/workspace/cwd"},
	} {
		tr, rel, via, err := Resolve(p, trees)
		if err != nil || tr != want.t || rel != want.rel || strings.Join(via, " ") != want.via {
			t.Errorf("Resolve(%s) = %d %q %q %v, want %d %q %q", p, tr, rel, via, err, want.t, want.rel, want.via)
		}
	}
	// in a session's trees, /proc and /dev are opaque: /proc/self/cwd is the workspace, /dev/fd leads into /proc
	trees = Trees(map[string]string{"cwd": "/proc/self/cwd", "fd": "/dev/fd/3"}, nil)
	for _, p := range []string{"/workspace/cwd/x", "/workspace/fd/x", "/proc/1/root/workspace/x"} {
		if tr, _, _, err := Resolve(p, trees); err != nil || tr < 0 || !trees[tr].Opaque || tr == TreeWorkspace {
			t.Errorf("Resolve(%s) = %d %v, want an opaque tree", p, tr, err)
		}
	}
}

// A git dir planted in another one's objects, or reached through /proc, can't hide: the innermost git dir decides what
// is inert, and /proc refuses like session-home.
func TestRootsNested(t *testing.T) {
	ws := t.TempDir()
	for f, b := range map[string]string{"p/.git": "gitdir: ../.git/objects/fake\n", ".git/objects/fake/config": "[alias]\n", ".git/objects/fake/HEAD": "",
		".git/objects/ab/cd": "o", "s/HEAD": "", "s/objects/x/HEAD": "", "s/objects/x/objects/1": "", "s/objects/x/refs/r": "", "s/objects/x/config": "", "s/refs/r": ""} {
		os.MkdirAll(filepath.Join(ws, filepath.Dir(f)), 0o755)
		os.WriteFile(filepath.Join(ws, f), []byte(b), 0o644)
	}
	r, err := FindRoots(ws)
	if err != nil {
		t.Fatal(err)
	}
	for p, inert := range map[string]bool{".git/objects/fake/config": false, ".git/objects/fake/HEAD": true, ".git/objects/ab/cd": true,
		"s/objects/x/config": false, "s/objects/x/objects/1": true, "s/HEAD": true, "s/objects/1": true} {
		if !r.Is(p) || r.Inert(p) != inert {
			t.Errorf("%s: Is %v, Inert %v, want inert %v (roots %q)", p, r.Is(p), r.Inert(p), inert, r.GitDirs)
		}
	}
	os.WriteFile(filepath.Join(ws, "p", ".git"), []byte("gitdir: /proc/self/cwd/../home/agent/g\n"), 0o644)
	if _, err := FindRoots(ws); err == nil || !strings.Contains(err.Error(), "/proc") {
		t.Errorf("a gitdir: through /proc: %v", err)
	}
}

// #206: a .git or commondir file is read as git reads it, up to git's 1 MiB limit for a .git file. One FindRoots can't
// read in full, or whose path git and other readers could take differently, fails it. A bare repo can keep its
// objects and refs in the dir its commondir names.
func TestRootsGitFiles(t *testing.T) {
	write := func(files map[string]string) string {
		ws := t.TempDir()
		for f, b := range files {
			os.MkdirAll(filepath.Join(ws, filepath.Dir(f)), 0o755)
			os.WriteFile(filepath.Join(ws, f), []byte(b), 0o644)
		}
		return ws
	}
	pad := strings.Repeat("\n", 5000)
	for _, c := range []struct {
		name  string
		files map[string]string
		git   []string
	}{
		{"a .git file padded past 4 KiB", map[string]string{"p/.git": "gitdir: ../gd" + pad, "gd/HEAD": "", "gd/commondir": "../gd2\r\n", "gd2/config": ""}, []string{"gd", "gd2"}},
		{"a commondir padded past 4 KiB", map[string]string{"r/.git/HEAD": "", "r/.git/commondir": "../../shared" + pad, "shared/config": ""}, []string{"shared"}},
		{"a bare repo with its objects and refs in its commondir's dir", map[string]string{"x/HEAD": "", "x/commondir": "../y\n", "y/objects/ab": "", "y/refs/heads/main": "",
			"y/config": ""}, []string{"x", "y"}},
		{"a path with a space in it", map[string]string{"p/.git": "gitdir: ../my repo\n", "my repo/config": ""}, []string{"my repo"}},
		{"a .git file that is not a gitfile", map[string]string{"p/.git": "not a gitfile\n"}, nil},
	} {
		r, err := FindRoots(write(c.files))
		slices.Sort(r.GitDirs)
		if err != nil || !slices.Equal(r.GitDirs, c.git) {
			t.Errorf("%s: %q %v, want %q", c.name, r.GitDirs, err, c.git)
		}
	}
	over := strings.Repeat("\n", gitFileCap)
	for name, files := range map[string]map[string]string{
		"a .git file over 1 MiB": {"p/.git": "gitdir: ../gd" + over}, "a commondir over 1 MiB": {"r/.git/HEAD": "", "r/.git/commondir": "../../shared" + over},
		// git reads "gd " and " ../gd", libgit2 "gd" and "../gd"; git refuses "gitdir:../gd", which libgit2 reads; C stops at a NUL
		"a trailing space": {"p/.git": "gitdir: ../gd \n"}, "two spaces": {"p/.git": "gitdir:  ../gd\n"}, "no space": {"p/.git": "gitdir:../gd\n"},
		"a NUL": {"p/.git": "gitdir: ../gd\x00x\n"}, "only a NUL": {"p/.git": "gitdir: \x00\n"}, "two lines": {"p/.git": "gitdir: ../a\n../b\n"},
		"a commondir with a trailing space": {"r/.git/HEAD": "", "r/.git/commondir": "../../shared \n"},
	} {
		if _, err := FindRoots(write(files)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
