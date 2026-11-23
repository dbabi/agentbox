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

// gitInert is what under a .git dir can't steer git or a CLI: objects, history and refs. Everything else there
// (config, hooks, info/attributes, anything unknown) is a control path.
var gitInert = []string{"objects", "logs", "refs", "index", "HEAD", "ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD", "COMMIT_EDITMSG", "packed-refs", "description", "lfs"}

func inertGit(rel string, r controlpaths.Roots) bool {
	segs := strings.Split(rel, "/")
	i := slices.Index(segs, ".git")
	if g := r.GitDir(rel); i < 0 && g != "" {
		i = strings.Count(g, "/") // a git dir a .git file names has the same inert entries
	}
	return i >= 0 && i+1 < len(segs) && slices.Contains(gitInert, segs[i+1])
}

// HomePaths are the session-home paths a CLI loads as instructions or runs from (#153). Session-home persists and the
// session can write it, so a file planted there would steer every later attach: they are control paths too, in the
// same baseline as the workspace's, keyed by their path in the session (/home/agent/...), which no workspace-relative
// path can match.
var HomePaths = []string{".claude/CLAUDE.md", ".claude/rules", ".claude/skills", ".claude/agents", ".claude/commands", ".npmrc", ".local/bin"}

// Controls is an attach's control-path state: the workspace's control paths, and session-home's HomePaths.
func Controls(p Paths) (map[string]string, error) {
	m, err := Manifest(p.Workspace)
	if err != nil {
		return nil, err
	}
	h, err := walk(p.SessionHome, func(rel string, d wsfs.Entry) sel {
		for _, hp := range HomePaths {
			switch {
			case rel == hp || strings.HasPrefix(rel, hp+"/"):
				return record
			case strings.HasPrefix(hp, rel+"/") && d.Mode&fs.ModeSymlink != 0:
				return record // ~/.local as a link: the CLI would follow it to a bin dir no walk sees
			case strings.HasPrefix(hp, rel+"/"):
				return descend
			}
		}
		return skip
	})
	for k, v := range h {
		m[Home+"/"+k] = v
	}
	return m, err
}

// Manifest is the workspace's control paths: each file's mode and sha256, each symlink's target. Symlinks are not
// followed.
func Manifest(ws string) (map[string]string, error) {
	roots, err := controlpaths.FindRoots(ws)
	if err != nil {
		return nil, err
	}
	return walk(ws, func(rel string, _ wsfs.Entry) sel {
		switch {
		case !roots.Is(rel):
			return descend
		case inertGit(rel, roots):
			return skip
		}
		return record
	})
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
