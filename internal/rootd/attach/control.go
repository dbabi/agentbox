package attach

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"agentbox/internal/controlpaths"
	"agentbox/internal/wsfs"
)

// BaselineSchema is the control-path state the admin last accepted for each agent's workspace (§4.2: rootd refuses
// agent.attach while control paths changed since the last reviewed state). No row is the empty workspace.
// shortcut: a manifest in rootd.db, not a reviewed snapshot; use the snapshot pair once workspace snapshots land.
const BaselineSchema = `
CREATE TABLE IF NOT EXISTS attach_baseline(agent TEXT PRIMARY KEY, manifest TEXT NOT NULL CHECK(json_valid(manifest))) STRICT;
`

// HomePaths are the session-home paths a CLI loads as instructions or runs from (#153): Claude's, Codex's user skills
// and plugins in ~/.agents (#186), npm's and ~/.local/bin. They are also the files the shells and tools in a session
// read at startup and can run code from (#200): bash's startup files (Claude's Bash tool sources ~/.bashrc, Codex runs
// a login shell) and what they pull in on Ubuntu, readline's, vim's, nano's, less's (lesskey can set LESSOPEN),
// tmux's and screen's, the python user site, node's home module dirs, ~/bin (on the login PATH), ssh's config, git's
// per-user attributes and go's env file (GOFLAGS). Not git's ignore file, which Claude Code writes and which runs
// nothing, nor go's telemetry counters, which every go command updates. Session-home persists and the session can
// write it, so a file planted there would steer every later attach: they are control paths too, in the same baseline
// as the workspace's, keyed by their path in the session (/home/agent/...), which no workspace-relative path can match.
var HomePaths = []string{".claude/CLAUDE.md", ".claude/rules", ".claude/skills", ".claude/agents", ".claude/commands", ".agents", ".npmrc", ".local/bin",
	".bashrc", ".bash_profile", ".bash_login", ".profile", ".bash_logout", ".bash_aliases", ".bash_completion", ".local/share/bash-completion",
	".inputrc", ".vimrc", ".exrc", ".vim", ".config/vim", ".nanorc", ".config/nano", ".lesskey", ".config/lesskey", ".less", ".config/less",
	".lessfilter", ".tmux.conf", ".config/tmux", ".screenrc", ".local/lib", ".node_modules", ".node_libraries", "bin", ".ssh", ".config/git/attributes", ".config/go/env"}

func homePath(rel string) bool {
	return slices.ContainsFunc(HomePaths, func(hp string) bool { return rel == hp || under(rel, hp) })
}

// Controls is an attach's control-path state: the workspace's control paths and session-home's HomePaths, each file's
// mode and sha256 and each symlink's target. What a control path leads to is one too (#202, #210): the target of a
// symlink at or under one, in the workspace or session-home, each link on the way there, and each file an instruction
// file imports with @path (Claude's memory imports), followed again from there. A link or import that leads into /proc
// or /dev refuses the attach.
func Controls(p Paths) (map[string]string, error) { return controls(p.Workspace, p.SessionHome) }

// Manifest is the workspace's control paths alone, the same way. A link or import that leads into session-home refuses
// here too: what is there is not known.
func Manifest(ws string) (map[string]string, error) { return controls(ws, "") }

// maxExtra and maxRounds bound what links and imports add: more paths, or links and imports nested deeper, refuse
// the attach instead of walking on.
const (
	maxExtra  = 1000
	maxRounds = 16
)

// importRe is Claude Code's memory import: @path at the start of a line or after a space, with "\ " for a space.
var importRe = regexp.MustCompile(`(?:^|\s)@((?:[^\s\\]|\\ )+)`)

func controls(ws, home string) (map[string]string, error) {
	roots, err := controlpaths.FindRoots(ws)
	if err != nil {
		return nil, err
	}
	docs := [2][]string{roots.Docs}
	var homeLinks map[string]string
	if home != "" {
		if homeLinks, docs[1], err = index(home); err != nil {
			return nil, err
		}
	}
	trees, dirs := controlpaths.Trees(roots.Links, homeLinks), [2]string{ws, home}
	extra := [2]paths{{}, {}} // what links and imports add, by tree: the workspace, then session-home
	recorded := func(t int, rel string) bool {
		if _, ok := extra[t].cover(rel); ok {
			return true
		}
		if t == controlpaths.TreeWorkspace {
			return (roots.Is(rel) || slices.Contains(roots.GitDirs, rel)) && !roots.Inert(rel)
		}
		return homePath(rel)
	}
	grew := false
	mark := func(t int, rel string) error {
		switch {
		case recorded(t, rel):
			return nil
		case len(extra[0])+len(extra[1]) >= maxExtra:
			return fmt.Errorf("control-path links and imports lead to more than %d paths", maxExtra)
		}
		extra[t][rel], grew = true, true
		return nil
	}
	add := func(from, p string) error {
		t, rel, via, err := controlpaths.Resolve(p, trees)
		switch {
		case err != nil:
			return fmt.Errorf("%q: %v", from, err)
		case t >= 0 && trees[t].Opaque:
			return fmt.Errorf("%q leads to %q, in %s", from, p, trees[t].Why)
		}
		for _, v := range via { // a link on the way is one too: retargeting it changes what the control path reads
			if err := mark(controlpaths.Where(v, trees)); err != nil {
				return err
			}
		}
		if t < 0 {
			return nil // the session's image: read-only, and nothing in it persists
		}
		return mark(t, rel)
	}
	// parents[d]: besides d's own parent, the dir of each link that leads to d. A name through that link is a name of
	// d too, and Node's path.resolve, which Claude may use for an import, takes ".." from the name, not from d.
	parents := map[string][]string{}
	for t := range 2 {
		for rel := range trees[t].Links {
			at := trees[t].Abs(rel)
			if lt, lrel, _, err := controlpaths.Resolve(at, trees); err == nil && lt >= 0 && !trees[lt].Opaque {
				d := trees[lt].Abs(lrel)
				parents[d] = append(parents[d], path.Dir(at))
			}
		}
	}
	// ups is every dir that k ".." from a name of dir d can reach
	ups := func(d string, k int) ([]string, error) {
		level := []string{d}
		for range k {
			var next []string
			for _, y := range level {
				next = append(append(next, path.Dir(y)), parents[y]...)
			}
			slices.Sort(next)
			if level = slices.Compact(next); len(level) > maxExtra {
				return nil, fmt.Errorf("more than %d paths lead to %q", maxExtra, d)
			}
		}
		return level, nil
	}
	// names is every path the import imp in the file at abs can name: as the kernel reads it, and cleaned as Node's
	// path.resolve does, from the file's dir, from the dir of each link that leads to the file, and from the session's
	// working dir (a command file's @path is relative to it)
	names := func(abs, imp string) ([]string, error) {
		switch {
		case strings.HasPrefix(imp, "~/"):
			imp = Home + imp[1:]
			fallthrough
		case path.IsAbs(imp):
			return []string{imp, path.Clean(imp)}, nil
		}
		c, k := path.Clean(imp), 0
		for c == ".." || strings.HasPrefix(c, "../") {
			c, k = strings.TrimPrefix(strings.TrimPrefix(c, ".."), "/"), k+1
		}
		var out []string
		for _, b := range append([]string{path.Dir(abs), Workspace}, parents[abs]...) {
			xs, err := ups(b, k)
			if err != nil {
				return nil, err
			}
			out = append(out, b+"/"+imp)
			for _, x := range xs {
				out = append(out, path.Join(x, c))
			}
		}
		return out, nil
	}
	if home != "" {
		for _, hp := range HomePaths { // as a CLI opens them: through any link on the way
			if err := add(Home+"/"+hp, Home+"/"+hp); err != nil {
				return nil, err
			}
		}
	}
	seen := map[string]bool{}
	for round := 0; round == 0 || grew; round++ {
		if round == maxRounds {
			return nil, fmt.Errorf("control-path links and imports nest more than %d deep", maxRounds)
		}
		grew = false
		for t := range 2 {
			// a symlink at or under a control path: what it leads to is one too
			for rel := range trees[t].Links {
				if at := trees[t].Abs(rel); !seen[at] && recorded(t, rel) {
					seen[at] = true
					if err := add(at, at); err != nil {
						return nil, err
					}
				}
			}
			// an instruction file's imports, and an import target's, whatever its name
			for _, d := range slices.Concat(docs[t], slices.Sorted(maps.Keys(extra[t]))) {
				at := trees[t].Abs(d)
				if seen["doc "+at] || !recorded(t, d) {
					continue
				}
				seen["doc "+at] = true
				// shortcut: an import past a file's first 64 MiB is missed; that much text is past any CLI's context
				b, _ := wsfs.ReadFile(dirs[t], d, hashCap) // a dir, FIFO or link imports nothing
				for _, m := range importRe.FindAllSubmatch(b[:min(len(b), hashCap)], -1) {
					imp := strings.ReplaceAll(string(m[1]), `\ `, " ")
					// "@notes.md," at the end of a clause: the path as written, and without the punctuation
					for _, imp := range []string{imp, strings.TrimRight(imp, `.,;:!?)]}'"`)} {
						if imp == "" {
							continue
						}
						ns, err := names(at, imp)
						if err != nil {
							return nil, fmt.Errorf("%q: %v", at, err)
						}
						for _, n := range ns {
							if err := add(at, n); err != nil {
								return nil, err
							}
						}
					}
				}
			}
		}
	}
	m, err := walk(ws, func(rel string, _ wsfs.Entry) sel {
		x, linked := extra[0].cover(rel)
		switch {
		case linked && (roots.Inert(x) || !roots.Inert(rel)):
			return record // what a link or import leads to, with everything under it; git's objects only if it names them
		case !linked && !roots.Is(rel):
			return descend
		case roots.Inert(rel) && extra[0].below(rel):
			return descend
		case roots.Inert(rel):
			return skip
		}
		return record
	})
	if err != nil || home == "" {
		return m, err
	}
	h, err := walk(home, func(rel string, d wsfs.Entry) sel {
		_, linked := extra[1].cover(rel)
		above := extra[1].below(rel) || slices.ContainsFunc(HomePaths, func(hp string) bool { return under(hp, rel) })
		switch {
		case slices.Contains(GitConfigs, rel):
			return skip // the empty git config Prepare binds over it: rootd makes the file, the session can't write it
		case linked || homePath(rel):
			return record
		case above && d.Mode&fs.ModeSymlink != 0:
			return record // ~/.local as a link: the CLI would follow it to a bin dir no walk sees
		case above:
			return descend
		}
		return skip
	})
	for k, v := range h {
		m[Home+"/"+k] = v
	}
	return m, err
}

// paths is a set of tree-relative paths, each a control path with everything under it.
type paths map[string]bool

// cover returns the path in the set that rel is, or is below (the nearest one), if any.
func (ps paths) cover(rel string) (string, bool) {
	for p := rel; ; p = path.Dir(p) {
		if ps[p] {
			return p, true
		}
		if p == "." || p == "/" {
			return "", false
		}
	}
}

// below reports whether a path in the set is below rel.
func (ps paths) below(rel string) bool {
	for p := range ps {
		if under(p, rel) {
			return true
		}
	}
	return false
}

// under reports whether p is below root; root "." is the whole tree.
func under(p, root string) bool {
	_, ok := controlpaths.Under(p, root)
	return ok
}

// index is a tree's symlinks (path: target) and regular .md files.
func index(dir string) (map[string]string, []string, error) {
	links, docs := map[string]string{}, []string(nil)
	err := wsfs.Walk(dir, func(e wsfs.Entry) error {
		switch {
		case e.Mode&fs.ModeSymlink != 0:
			l, err := e.Readlink()
			links[e.Rel] = l
			return err
		case e.Mode.IsRegular() && strings.HasSuffix(e.Name, ".md"):
			docs = append(docs, e.Rel)
		}
		return nil
	})
	return links, docs, err
}

type sel int

const (
	record  sel = iota // in the manifest, with everything under it
	descend            // not itself, but maybe something under it
	skip               // neither
)

// hashCap is the largest control-path file walk hashes. A larger one is recorded by size and ctime instead: any write
// to it moves its ctime, and a session can't set ctime back, so a change still shows (a chmod or touch shows too).
const hashCap = 64 << 20

func walk(root string, which func(rel string, d wsfs.Entry) sel) (map[string]string, error) {
	m := map[string]string{}
	err := wsfs.Walk(root, func(e wsfs.Entry) error {
		rel := e.Rel
		if rel == "." {
			return nil
		}
		switch which(rel, e) {
		case skip:
			if e.IsDir() {
				return fs.SkipDir
			}
			return nil
		case descend:
			return nil
		}
		switch t := e.Mode.Type(); {
		case t&fs.ModeSymlink != 0:
			l, err := e.Readlink()
			if err != nil {
				return err
			}
			m[rel] = "link " + l
		case t.IsRegular():
			f, err := e.Open()
			if err != nil {
				return err
			}
			defer f.Close()
			if f.Size > hashCap {
				m[rel] = fmt.Sprintf("%s large %d %d", e.Mode.Perm(), f.Size, e.Ctime.UnixNano())
				return nil
			}
			h := sha256.New()
			if _, err := io.Copy(h, io.LimitReader(f, hashCap)); err != nil {
				return err
			}
			m[rel] = e.Mode.Perm().String() + " " + hex.EncodeToString(h.Sum(nil))
		case !t.IsDir():
			m[rel] = "special " + t.String() // a fifo or device: unusual, so it needs an ack too
		}
		return nil
	})
	return m, err
}

// ControlChanges is the control paths added, changed or removed since agent's baseline, sorted.
func ControlChanges(db *sql.DB, agent string, cur map[string]string) ([]string, error) {
	base := map[string]string{}
	var s string
	err := db.QueryRow(`SELECT manifest FROM attach_baseline WHERE agent=?`, agent).Scan(&s)
	if err == nil {
		err = json.Unmarshal([]byte(s), &base)
	} else if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for p, v := range cur {
		if base[p] != v {
			out = append(out, p)
		}
	}
	for p := range base {
		if _, ok := cur[p]; !ok {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out, nil
}

// Digest names a list of control-path changes with the state each path is in now. agent.attach prints it with the
// refusal, and --ack-control-changes must quote it: the ack accepts what the admin was shown, and nothing a task
// changed since. Each path and state is quoted, so no two lists share an encoding.
func Digest(changed []string, cur map[string]string) string {
	h := sha256.New()
	for _, p := range changed {
		v, ok := cur[p]
		fmt.Fprintf(h, "%q %q %t\n", p, v, ok)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// SaveBaseline makes cur agent's accepted control-path state.
func SaveBaseline(db *sql.DB, agent string, cur map[string]string) error {
	b, _ := json.Marshal(cur)
	_, err := db.Exec(`INSERT INTO attach_baseline(agent, manifest) VALUES(?,?) ON CONFLICT(agent) DO UPDATE SET manifest=excluded.manifest`, agent, string(b))
	return err
}

// ForgetBaseline drops a removed agent's baseline: a new agent of the same name starts from the empty workspace.
func ForgetBaseline(db *sql.DB, agent string) error {
	_, err := db.Exec(`DELETE FROM attach_baseline WHERE agent=?`, agent)
	return err
}
