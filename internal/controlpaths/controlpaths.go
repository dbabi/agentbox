// Package controlpaths is the workspace control-path list (ARCHITECTURE.md §4.2 "Workspace control files can't steer
// later tasks"): the files an agent CLI, an IDE or git reads as config or instructions, or runs. A change to one needs
// an explicit acknowledgement at `taint review` and `agent.attach` (--ack-control-changes). Lockfiles (go.mod,
// go.sum, package-lock.json, ...) are not control paths; the dependency report covers them (§7).
package controlpaths

import (
	"bytes"
	"fmt"
	"path"
	"slices"
	"strings"

	"agentbox/internal/wsfs"
)

var (
	// Dirs are control paths with everything under them, at any depth of the workspace (one repo per project dir).
	// .git matches a nested repo's dir and a worktree's or submodule's gitdir file alike.
	Dirs = []string{".claude", ".codex", ".agents", ".opencode", ".git", ".devcontainer", ".vscode", ".idea", ".zed"}
	// Files are control paths by base name, at any depth.
	Files = []string{".mcp.json", "CLAUDE.md", "AGENTS.md", ".envrc", "opencode.json", "opencode.jsonc"}
)

// Workspace is the workspace's path inside a task or session, which an absolute gitdir: line names. Home is
// session-home's path in an attach: it persists and a session can write it, so a git dir there could change after its
// .git file was acked, and FindRoots refuses one.
const (
	Workspace = "/workspace"
	Home      = "/home/agent"
)

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

// Roots are the dirs that are control paths by content, not by name: each venv (a dir holding pyvenv.cfg, whatever its
// name, the workspace root included), each git dir a .git or commondir file names, and each bare repo (a dir holding
// HEAD, objects/ and refs/). They are workspace-relative; "." is the root.
type Roots struct{ Venvs, GitDirs []string }

// Is reports whether p is a control path by name or under a root: in a venv its pyvenv.cfg, bin/ (the interpreter
// and activate scripts an IDE runs) and every .pth file (python runs their import lines at startup).
func (r Roots) Is(p string) bool {
	if Is(p) {
		return true
	}
	for _, v := range r.Venvs {
		if rest, ok := Under(p, v); ok && (rest == "pyvenv.cfg" || rest == "bin" || strings.HasPrefix(rest, "bin/") || strings.HasSuffix(rest, ".pth")) {
			return true
		}
	}
	return r.GitDir(p) != ""
}

// GitDir returns the git dir root that p is inside, or "".
func (r Roots) GitDir(p string) string {
	for _, g := range r.GitDirs {
		if _, ok := Under(p, g); ok {
			return g
		}
	}
	return ""
}

// Under returns p's path below root, if p is below it. Root "." is the whole workspace.
func Under(p, root string) (string, bool) {
	if root == "." {
		return p, p != "" && p != "."
	}
	rest, ok := strings.CutPrefix(p, root+"/")
	return rest, ok && rest != ""
}

// FindRoots walks the workspace dir ws for Roots. Symlinks are not followed. A git dir outside the workspace is not
// one (the task can't write there, or it doesn't persist), except under Home: FindRoots fails on that.
func FindRoots(ws string) (Roots, error) {
	var r Roots
	common := map[string][]byte{} // dir: the commondir file in it
	head, objects, refs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	read := func(e wsfs.Entry) ([]byte, error) {
		f, err := e.Open()
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return f.ReadAll(4096)
	}
	err := wsfs.Walk(ws, func(e wsfs.Entry) error {
		dir := path.Dir(e.Rel)
		switch {
		case e.IsDir() && e.Name == "objects":
			objects[dir] = true
		case e.IsDir() && e.Name == "refs":
			refs[dir] = true
		case !e.Mode.IsRegular():
		case e.Name == "HEAD":
			head[dir] = true
		case e.Name == "pyvenv.cfg":
			r.Venvs = append(r.Venvs, dir)
		case e.Name == ".git":
			b, err := read(e)
			if t, ok := bytes.CutPrefix(bytes.TrimSpace(b), []byte("gitdir:")); err == nil && ok {
				return r.add(string(t), e.Rel, dir)
			}
		case e.Name == "commondir":
			if b, err := read(e); err == nil {
				common[dir] = b
			}
		}
		return nil
	})
	// a bare repo: git finds it from a cwd inside it (safe.bareRepository is explicit only in tasks and attach)
	for d := range head {
		if objects[d] && refs[d] && !Is(d) {
			r.GitDirs = append(r.GitDirs, d)
		}
	}
	// git reads config, hooks and info from the dir a git dir's commondir names
	for d, b := range common {
		if err == nil && (Is(d) || slices.Contains(r.GitDirs, d) || r.GitDir(d) != "") {
			err = r.add(string(b), path.Join(d, "commondir"), d)
		}
	}
	return r, err
}

// add records the git dir that g, a path the git file file in the workspace dir dir names, points at.
func (r *Roots) add(g, file, dir string) error {
	g = strings.TrimSpace(g)
	if g == "" {
		return nil
	}
	if path.IsAbs(g) {
		g = path.Clean(g) + "/"
		if strings.HasPrefix(g, Home+"/") {
			return fmt.Errorf("%s names %s, a git dir in session-home, which a session can change unseen: point it into the workspace", file, path.Clean(g))
		}
		rest, ok := strings.CutPrefix(g, Workspace+"/")
		if !ok {
			return nil
		}
		g = path.Clean("./" + rest)
	} else {
		g = path.Join(dir, g)
	}
	if g == ".." || strings.HasPrefix(g, "../") || Is(g) {
		return nil // outside the workspace, or a control path by name already
	}
	r.GitDirs = append(r.GitDirs, g)
	return nil
}
