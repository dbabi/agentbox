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
		"a/.agents/skills/s/SKILL.md", "sub/opencode.json", "opencode.jsonc", ".vscode/tasks.json", "p/.idea/workspace.xml", ".zed/settings.json", "sub/.git", "sub/.git/config"})
	want := []string{"proj/.mcp.json", ".claude/skills/x/SKILL.md", "p/.git/hooks/pre-commit", "CLAUDE.md", "a/AGENTS.md", ".envrc", "x/.devcontainer/devcontainer.json",
		"a/.agents/skills/s/SKILL.md", "sub/opencode.json", "opencode.jsonc", ".vscode/tasks.json", "p/.idea/workspace.xml", ".zed/settings.json", "sub/.git", "sub/.git/config"}
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
	// a git dir in session-home can change after its .git file was acked: refused
	for _, files := range []map[string]string{{"p/.git": "gitdir: /home/agent/g\n"}, {"wt/.git": "gitdir: ../m\n", "m/commondir": "/home/agent/c"},
		{"p/.git": "gitdir: /home/agent\n"}} {
		ws = t.TempDir()
		write(ws, files)
		if _, err := FindRoots(ws); err == nil || !strings.Contains(err.Error(), "session-home") {
			t.Errorf("%v: %v", files, err)
		}
	}
}
