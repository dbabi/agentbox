// Package controlpaths is the workspace control-path list (ARCHITECTURE.md §4.2 "Workspace control files can't steer
// later tasks"): the files an agent CLI, an IDE or git reads as config or instructions, or runs. A change to one needs
// an explicit acknowledgement at `taint review` and `agent.attach` (--ack-control-changes). Lockfiles (go.mod,
// go.sum, package-lock.json, ...) are not control paths; the dependency report covers them (§7).
package controlpaths

import (
	"bytes"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"agentbox/internal/wsfs"
)

var (
	// Dirs are control paths with everything under them, at any depth of the workspace (one repo per project dir).
	// .git matches a nested repo's dir and a worktree's or submodule's gitdir file alike.
	Dirs = []string{".claude", ".codex", ".agents", ".opencode", ".git", ".devcontainer", ".vscode", ".idea", ".zed"}
	// Files are control paths by base name, at any depth. Codex reads AGENTS.override.md in place of AGENTS.md, and
	// Claude loads CLAUDE.local.md as project memory.
	Files = []string{".mcp.json", "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENTS.override.md", ".envrc", "opencode.json", "opencode.jsonc"}
	// GitInert is what in a git dir can't steer git or a CLI: objects, history and refs. Everything else there (config,
	// hooks, info/attributes, anything unknown) is a control path.
	GitInert = []string{"objects", "logs", "refs", "index", "HEAD", "ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD", "COMMIT_EDITMSG", "packed-refs", "description", "lfs"}
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
// name, the workspace root included), each git dir a .git file or link or a commondir file leads to, and each bare repo
// (a dir holding HEAD, objects and refs, links counted). They are workspace-relative; "." is the root. Links is every
// symlink in the workspace (path: target) and Docs every regular .md file, for the callers that follow links and
// imports from control paths.
type Roots struct {
	Venvs, GitDirs []string
	Links          map[string]string
	Docs           []string
}

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

// GitDir returns the innermost git dir root that p is inside, or "": a git dir planted in another one's objects is its
// own git dir, with its own config.
func (r Roots) GitDir(p string) string {
	in := ""
	for _, g := range r.GitDirs {
		if _, ok := Under(p, g); ok && (in == "" || depth(g) > depth(in)) {
			in = g
		}
	}
	return in
}

// Inert reports whether p is in the objects, history or refs (GitInert) of the innermost git dir it is in, a .git dir
// or a root: those can't steer git or a CLI, so the manifest leaves them out.
func (r Roots) Inert(p string) bool {
	in, segs := r.GitDir(p), strings.Split(p, "/")
	for i := range len(segs) - 1 {
		if segs[i] == ".git" && (in == "" || i+1 > depth(in)) {
			in = strings.Join(segs[:i+1], "/")
		}
	}
	rest, ok := Under(p, in)
	return in != "" && ok && slices.Contains(GitInert, strings.SplitN(rest, "/", 2)[0])
}

func depth(p string) int {
	if p == "." {
		return 0
	}
	return strings.Count(p, "/") + 1
}

// Under returns p's path below root, if p is below it. Root "." is the whole workspace.
func Under(p, root string) (string, bool) {
	if root == "." {
		return p, p != "" && p != "."
	}
	rest, ok := strings.CutPrefix(p, root+"/")
	return rest, ok && rest != ""
}

// FindRoots walks the workspace dir ws for Roots. The walk follows no symlink. A .git, commondir or pyvenv.cfg that is
// one, and every gitdir: or commondir path, is resolved as a session's git or kernel would (Resolve), through the
// workspace's links. A git dir outside the workspace is not one (the task can't write there, or it doesn't persist),
// except in session-home, /proc or /dev: FindRoots fails on one there, and on any path to one that passes through them.
func FindRoots(ws string) (Roots, error) {
	r := Roots{Links: map[string]string{}}
	common := map[string][]byte{} // dir: the commondir file in it
	head, objects, refs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	type gitfile struct{ g, file, dir string } // a gitdir: line g in file, in the workspace dir dir
	var gitfiles []gitfile
	var linked []string // .git, commondir and pyvenv.cfg entries that are symlinks
	read := func(e wsfs.Entry) ([]byte, error) {
		f, err := e.Open()
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return f.ReadAll(4096)
	}
	err := wsfs.Walk(ws, func(e wsfs.Entry) error {
		dir, link := path.Dir(e.Rel), e.Mode&fs.ModeSymlink != 0
		if link {
			l, err := e.Readlink()
			if err != nil {
				return err
			}
			r.Links[e.Rel] = l
		}
		switch {
		case (e.IsDir() || link) && e.Name == "objects":
			objects[dir] = true
		case (e.IsDir() || link) && e.Name == "refs":
			refs[dir] = true
		case (e.Mode.IsRegular() || link) && e.Name == "HEAD":
			head[dir] = true
		case link && (e.Name == ".git" || e.Name == "commondir" || e.Name == "pyvenv.cfg"):
			linked = append(linked, e.Rel)
		case !e.Mode.IsRegular():
		case strings.HasSuffix(e.Name, ".md"):
			r.Docs = append(r.Docs, e.Rel)
		case e.Name == "pyvenv.cfg":
			r.Venvs = append(r.Venvs, dir)
		case e.Name == ".git":
			b, err := read(e)
			if t, ok := bytes.CutPrefix(bytes.TrimSpace(b), []byte("gitdir:")); err == nil && ok {
				gitfiles = append(gitfiles, gitfile{string(t), e.Rel, dir})
			}
		case e.Name == "commondir":
			if b, err := read(e); err == nil {
				common[dir] = b
			}
		}
		return nil
	})
	if err != nil {
		return r, err
	}
	trees := Trees(r.Links, nil)
	for _, g := range gitfiles {
		if err := r.add(trees, g.g, g.file, g.dir); err != nil {
			return r, err
		}
	}
	// a linked .git is the git dir it leads to, or the gitfile there, whose gitdir: git reads relative to the link's
	// dir; a linked commondir or pyvenv.cfg is read the same way
	for _, l := range linked {
		dir, name := path.Dir(l), path.Base(l)
		t, rel, _, err := Resolve(Workspace+"/"+l, trees)
		switch {
		case err != nil:
			return r, fmt.Errorf("%q: %v", l, err)
		case t > TreeWorkspace:
			return r, fmt.Errorf("%q leads into %s: point it into the workspace", l, trees[t].Why)
		case t < 0:
			continue // the session's image: read-only, and nothing in it persists
		case name == "pyvenv.cfg":
			r.Venvs = append(r.Venvs, dir)
			continue
		}
		b, _ := wsfs.ReadFile(ws, rel, 4096)
		g, ok := bytes.CutPrefix(bytes.TrimSpace(b), []byte("gitdir:"))
		switch {
		case name == "commondir":
			common[dir] = b
		case ok:
			if err := r.add(trees, string(g), l, dir); err != nil {
				return r, err
			}
		default:
			r.GitDirs = append(r.GitDirs, rel)
		}
	}
	// a bare repo: git finds it from a cwd inside it (safe.bareRepository is explicit only in tasks and attach); a
	// .git dir is a control path by name already
	for d := range head {
		if objects[d] && refs[d] && path.Base(d) != ".git" {
			r.GitDirs = append(r.GitDirs, d)
		}
	}
	// git reads config, hooks and info from the dir a git dir's commondir names
	for d, b := range common {
		if Is(d) || slices.Contains(r.GitDirs, d) || r.GitDir(d) != "" {
			if err := r.add(trees, string(b), path.Join(d, "commondir"), d); err != nil {
				return r, err
			}
		}
	}
	slices.Sort(r.GitDirs)
	r.GitDirs = slices.Compact(r.GitDirs)
	return r, nil
}

// add records the git dir that g, a path the git file file in the workspace dir dir names, leads to in a session.
func (r *Roots) add(trees []Tree, g, file, dir string) error {
	g = strings.TrimSpace(g)
	if g == "" {
		return nil
	}
	p := g
	if !path.IsAbs(g) {
		p = Workspace + "/" + dir + "/" + g // not path.Join: git resolves a ".." after a link from the link's target
	}
	t, rel, _, err := Resolve(p, trees)
	switch {
	case err != nil:
		return fmt.Errorf("%q names %q: %v", file, g, err)
	case t > TreeWorkspace:
		return fmt.Errorf("%q names %q, a git dir in %s: point it into the workspace", file, g, trees[t].Why)
	case t == TreeWorkspace:
		r.GitDirs = append(r.GitDirs, rel)
	}
	return nil // t < 0: the session's image, where nothing a session writes persists
}

// Tree is a tree as a session sees it: mounted at Mount, with its symlinks (path in the tree: target). Resolve stops
// at an Opaque tree, whose links are not known, and callers refuse a path into one. Why names the tree in errors.
type Tree struct {
	Mount  string
	Links  map[string]string
	Opaque bool
	Why    string
}

// Abs is rel's path in the session.
func (t Tree) Abs(rel string) string {
	if rel == "." {
		return t.Mount
	}
	return t.Mount + "/" + rel
}

// The trees Trees returns, by index.
const (
	TreeWorkspace = iota
	TreeHome
)

// Trees is what a path an agent wrote can lead to in a session: the workspace and session-home with their links
// (session-home opaque if home is nil), and /proc and /dev, where the kernel resolves names for each process
// (/proc/self/cwd is the workspace), so they are opaque.
func Trees(ws, home map[string]string) []Tree {
	return []Tree{
		{Mount: Workspace, Links: ws, Why: "the workspace"},
		{Mount: Home, Links: home, Opaque: home == nil, Why: "session-home, which a session can change unseen"},
		{Mount: "/proc", Opaque: true, Why: "/proc, where the kernel resolves names for each process"},
		{Mount: "/dev", Opaque: true, Why: "/dev, whose links lead into /proc"},
	}
}

// MaxLinks is how many symlinks Resolve follows for one path, as the kernel does (MAXSYMLINKS).
const MaxLinks = 40

// Resolve follows p, an absolute path in a session, one name at a time through the trees' symlinks, the way the
// session's kernel opens it: a ".." after a link climbs from the link's target. It returns the tree p ends in, or the
// opaque tree it enters first (-1 for neither: the session's image), the path in that tree ("." for its root), and
// the session path of each link it followed. More than MaxLinks links is an error, as it is for the kernel.
func Resolve(p string, trees []Tree) (int, string, []string, error) {
	todo, cur := strings.Split(p, "/"), "/"
	var via []string
	for len(todo) > 0 {
		c := todo[0]
		todo = todo[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			cur = path.Dir(cur)
			continue
		}
		next := path.Join(cur, c)
		t, rel := Where(next, trees)
		if t >= 0 && trees[t].Opaque {
			return t, rel, via, nil
		}
		if l, ok := linkAt(trees, t, rel); ok {
			if len(via) == MaxLinks {
				return -1, "", via, fmt.Errorf("%q: more than %d symlinks", p, MaxLinks)
			}
			via = append(via, next)
			if path.IsAbs(l) {
				cur = "/"
			}
			todo = append(strings.Split(l, "/"), todo...)
			continue
		}
		cur = next
	}
	t, rel := Where(cur, trees)
	return t, rel, via, nil
}

func linkAt(trees []Tree, t int, rel string) (string, bool) {
	if t < 0 {
		return "", false
	}
	l, ok := trees[t].Links[rel]
	return l, ok
}

// Where returns the tree that p, a clean absolute path, is in and p's path there ("." for its root); -1 for none.
func Where(p string, trees []Tree) (int, string) {
	for i, t := range trees {
		if p == t.Mount {
			return i, "."
		}
		if rest, ok := strings.CutPrefix(p, t.Mount+"/"); ok {
			return i, rest
		}
	}
	return -1, ""
}
