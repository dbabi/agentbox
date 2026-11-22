// Package controlpaths is the workspace control-path list (ARCHITECTURE.md §4.2 "Workspace control files can't steer
// later tasks"): the files an agent CLI, an IDE or git reads as config or instructions, or runs. A change to one needs
// an explicit acknowledgement at `taint review` and `agent.attach` (--ack-control-changes). Lockfiles (go.mod,
// go.sum, package-lock.json, ...) are not control paths; the dependency report covers them (§7).
package controlpaths

import (
	"bytes"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

var (
	// Dirs are control paths with everything under them, at any depth of the workspace (one repo per project dir).
	// .git matches a nested repo's dir and a worktree's or submodule's gitdir file alike.
	Dirs = []string{".claude", ".codex", ".agents", ".opencode", ".git", ".devcontainer", ".vscode", ".idea", ".zed"}
	// Files are control paths by base name, at any depth.
	Files = []string{".mcp.json", "CLAUDE.md", "AGENTS.md", ".envrc", "opencode.json", "opencode.jsonc"}
)

// Workspace is the workspace's path inside a task or session, which an absolute gitdir: line names.
const Workspace = "/workspace"

// Is reports whether a workspace-relative, slash-separated path is a control path by its name alone.
func Is(p string) bool {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range segs {
		if slices.Contains(Dirs, s) || (i == len(segs)-1 && slices.Contains(Files, s)) {
			return true
		}
	}
	return false
}

// Changed returns the control paths among changed, in order.
func Changed(changed []string) []string {
	var out []string
	for _, p := range changed {
		if Is(p) {
			out = append(out, p)
		}
	}
	return out
}

// Roots are the workspace dirs that are control paths by content, not by name: each venv (a dir holding pyvenv.cfg,
// whatever its name) and each git dir a .git file points at.
type Roots struct{ Venvs, GitDirs []string }

// Is reports whether p is a control path by name or under a root: in a venv its pyvenv.cfg, bin/ (the interpreter
// and activate scripts an IDE runs) and every .pth file (python runs their import lines at startup).
func (r Roots) Is(p string) bool {
	if Is(p) {
		return true
	}
	for _, v := range r.Venvs {
		if rest, ok := under(p, v); ok && (rest == "pyvenv.cfg" || rest == "bin" || strings.HasPrefix(rest, "bin/") || strings.HasSuffix(rest, ".pth")) {
			return true
		}
	}
	return r.GitDir(p) != ""
}

// GitDir returns the git dir root that p is inside, or "".
func (r Roots) GitDir(p string) string {
	for _, g := range r.GitDirs {
		if _, ok := under(p, g); ok {
			return g
		}
	}
	return ""
}

func under(p, root string) (string, bool) {
	rest, ok := strings.CutPrefix(p, root+"/")
	return rest, ok && rest != ""
}

// FindRoots walks the workspace dir ws for Roots. Symlinks are not followed; a gitdir outside the workspace is
// not one (the task can't write there).
func FindRoots(ws string) (Roots, error) {
	var r Roots
	err := filepath.WalkDir(ws, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(ws, p)
		rel = filepath.ToSlash(rel)
		switch {
		case d.IsDir():
			if fi, err := os.Lstat(filepath.Join(p, "pyvenv.cfg")); err == nil && fi.Mode().IsRegular() {
				r.Venvs = append(r.Venvs, rel)
			}
		case d.Name() == ".git" && d.Type().IsRegular():
			if g := gitdir(p, path.Dir(rel)); g != "" {
				r.GitDirs = append(r.GitDirs, g)
			}
		}
		return nil
	})
	return r, err
}

// gitdir reads a .git file at p, in the workspace dir dir, and returns the workspace-relative dir it names.
func gitdir(p, dir string) string {
	b, err := os.ReadFile(p)
	if err != nil || len(b) > 4096 {
		return ""
	}
	t, ok := bytes.CutPrefix(bytes.TrimSpace(b), []byte("gitdir:"))
	if !ok {
		return ""
	}
	g := string(bytes.TrimSpace(t))
	if path.IsAbs(g) {
		rest, ok := strings.CutPrefix(path.Clean(g), Workspace+"/")
		if !ok {
			return ""
		}
		g = rest
	} else {
		g = path.Join(dir, g)
	}
	if g == "." || g == ".." || strings.HasPrefix(g, "../") {
		return ""
	}
	return g
}
