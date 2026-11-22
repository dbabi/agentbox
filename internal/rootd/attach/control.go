package attach

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"agentbox/internal/controlpaths"
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

func inertGit(rel string) bool {
	segs := strings.Split(rel, "/")
	i := slices.Index(segs, ".git")
	return i >= 0 && i+1 < len(segs) && slices.Contains(gitInert, segs[i+1])
}

// Manifest is the workspace's control paths: each file's mode and sha256, each symlink's target. Symlinks are not
// followed.
func Manifest(ws string) (map[string]string, error) {
	m := map[string]string{}
	err := filepath.WalkDir(ws, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(ws, p)
		rel = filepath.ToSlash(rel)
		if rel == "." || !controlpaths.Is(rel) {
			return nil
		}
		if inertGit(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		switch t := d.Type(); {
		case t&fs.ModeSymlink != 0:
			l, err := os.Readlink(p)
			if err != nil {
				return err
			}
			m[rel] = "link " + l
		case t.IsRegular():
			fi, err := d.Info()
			if err != nil {
				return err
			}
			f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
			if err != nil {
				return err
			}
			h := sha256.New()
			_, err = io.Copy(h, f)
			f.Close()
			if err != nil {
				return err
			}
			m[rel] = fi.Mode().Perm().String() + " " + hex.EncodeToString(h.Sum(nil))
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
