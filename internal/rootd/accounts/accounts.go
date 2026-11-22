// Package accounts is one Unix account per agent (ARCHITECTURE.md §4.1, Appendix C): rootd's ids table, the only
// allocator, and everything derived from an agent's N: uid/gid 70000+N, the sub-id block 0x70000000+N·0x10000, the
// root-owned XDG dirs, the user@ and slice drop-ins, linger, and the workspace and storage subvolumes in qgroup 1/N
// under 2/0. ids rows are never deleted and N only grows, so a uid or sub-id range is never reused.
//
// rootd writes the rows and the persistent stores under /var/lib/agentbox; the OS-domain half (/etc, linger) is
// Reconcile, which agentbox-reconcile runs at every boot and agentbox-accounts.service runs when rootd asks (§3.2).
package accounts

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"agentbox/internal/rootd/quota"
)

const (
	UIDBase = 70000
	MaxN    = 999
	SubBase = 0x70000000 // agent N's sub-id block starts at SubBase + N·SubSize
	SubSize = 0x10000
	// SubEnd is the end of the agentbox sub-id span (agents and apps, §4.1): no other /etc/subuid entry may reach into it.
	SubEnd  = 0x78000000
	MinDisk = 16 << 20 // the smallest 1/N limit agent.add takes

	Control = "/var/lib/agentbox/control"
)

// Schema is the ids table of Appendix E, plus triggers that keep rows from being deleted, renumbered or reactivated.
const Schema = `
CREATE TABLE IF NOT EXISTS ids(kind TEXT NOT NULL CHECK(kind IN ('agent','app')), n INTEGER NOT NULL CHECK(n BETWEEN 1 AND 999), name TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('active','retired')), created_at INTEGER NOT NULL, retired_at INTEGER, PRIMARY KEY(kind,n)) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS ids_active_name ON ids(kind,name) WHERE state='active';
CREATE TRIGGER IF NOT EXISTS ids_never_deleted BEFORE DELETE ON ids BEGIN SELECT RAISE(ABORT, 'ids rows are never deleted'); END;
CREATE TRIGGER IF NOT EXISTS ids_never_reused BEFORE UPDATE ON ids
  WHEN NEW.kind IS NOT OLD.kind OR NEW.n IS NOT OLD.n OR NEW.name IS NOT OLD.name OR OLD.state = 'retired'
  BEGIN SELECT RAISE(ABORT, 'ids rows are never renumbered, renamed or reactivated'); END;
`

// The user name is ag-<name>, at most 32 characters.
var nameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,28}$`)

// ValidName reports whether name can be an agent name.
func ValidName(name string) bool { return nameRe.MatchString(name) }

var (
	ErrFull     = errors.New("accounts: all 999 agent ids are used; ids are never reused")
	ErrNotFound = errors.New("accounts: no active agent by that name")
)

// Agent is one ids row of kind agent.
type Agent struct {
	N      int    `json:"n"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

func (a Agent) UID() int { return UIDBase + a.N }

// WorkspaceSubject is the workspace's taint.db subject, keyed by N as well as the name: a name comes back after
// agent.remove, N never does, so a new agent of an old name starts with a clean workspace (#95).
func WorkspaceSubject(name string, uid int) string {
	return "workspace:" + name + "#" + strconv.Itoa(uid-UIDBase)
}
func (a Agent) User() string    { return "ag-" + a.Name }
func (a Agent) SubID() int      { return SubBase + a.N*SubSize }
func (a Agent) Dir() string     { return quota.Data + "/agents/" + a.Name }
func (a Agent) Home() string    { return a.Dir() + "/account" } // root-owned and empty
func (a Agent) XDG() string     { return Control + "/xdg/" + a.Name }
func (a Agent) Storage() string { return a.Dir() + "/storage" }

// SessionHome is the persistent HOME agent.attach mounts (§4.2), never mounted into tasks.
func (a Agent) SessionHome() string { return a.Dir() + "/session-home" }
func (a Agent) Workspace() string {
	return quota.Data + "/workspaces/" + a.Name
}

// Archive is where removal moves a retired agent's subvolumes: they still own files in its sub-id range.
func (a Agent) Archive() string { return quota.Data + "/archive/agent-" + strconv.Itoa(a.N) }

// Add allocates the next N for name in one transaction: N = COALESCE(MAX(n),0)+1, over retired rows too. An agent
// that is already active comes back unchanged, so a rerun of agent.add repairs a half-done one.
func Add(db *sql.DB, name string, now time.Time) (Agent, error) {
	if !ValidName(name) {
		return Agent{}, fmt.Errorf("accounts: bad agent name %q", name)
	}
	tx, err := db.Begin()
	if err != nil {
		return Agent{}, err
	}
	defer tx.Rollback()
	a := Agent{Name: name, Active: true}
	err = tx.QueryRow(`SELECT n FROM ids WHERE kind='agent' AND name=? AND state='active'`, name).Scan(&a.N)
	if err == nil {
		return a, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Agent{}, err
	}
	if err := tx.QueryRow(`SELECT COALESCE(MAX(n),0)+1 FROM ids WHERE kind='agent'`).Scan(&a.N); err != nil {
		return Agent{}, err
	}
	if a.N > MaxN {
		return Agent{}, ErrFull
	}
	if _, err := tx.Exec(`INSERT INTO ids(kind, n, name, state, created_at) VALUES('agent', ?, ?, 'active', ?)`, a.N, name, now.UnixMilli()); err != nil {
		return Agent{}, err
	}
	return a, tx.Commit()
}

// Lookup returns the active agent name.
func Lookup(db *sql.DB, name string) (Agent, error) {
	a := Agent{Name: name, Active: true}
	err := db.QueryRow(`SELECT n FROM ids WHERE kind='agent' AND name=? AND state='active'`, name).Scan(&a.N)
	if errors.Is(err, sql.ErrNoRows) {
		return Agent{}, ErrNotFound
	}
	return a, err
}

// Retire marks the active agent name retired. Its row, N and sub-id range stay reserved forever.
func Retire(db *sql.DB, name string, now time.Time) (Agent, error) {
	a, err := Lookup(db, name)
	if err != nil {
		return a, err
	}
	if _, err := db.Exec(`UPDATE ids SET state='retired', retired_at=? WHERE kind='agent' AND n=? AND state='active'`, now.UnixMilli(), a.N); err != nil {
		return Agent{}, err
	}
	a.Active = false
	return a, nil
}

// List returns every agent row, retired ones included, by N.
func List(db *sql.DB) ([]Agent, error) {
	rows, err := db.Query(`SELECT n, name, state FROM ids WHERE kind='agent' ORDER BY n`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		var a Agent
		var st string
		if err := rows.Scan(&a.N, &a.Name, &st); err != nil {
			return nil, err
		}
		a.Active = st == "active"
		out = append(out, a)
	}
	return out, rows.Err()
}

func mkdirRoot(p string, mode os.FileMode) error {
	if err := os.MkdirAll(p, mode); err != nil {
		return err
	}
	if err := os.Lchown(p, 0, 0); err != nil {
		return err
	}
	return os.Chmod(p, mode) // rootd runs with UMask=0077
}

// owner is p's uid, or -1 if p doesn't exist.
func owner(p string) (int, error) {
	fi, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return -1, nil
	} else if err != nil {
		return 0, err
	}
	return statUID(fi), nil
}

// StorageConf is the root-owned containers/storage.conf in the agent's XDG_CONFIG_HOME (Appendix C).
func (a Agent) StorageConf() string {
	return fmt.Sprintf("[storage]\ndriver = \"overlay\"\ngraphroot = %q\nrunroot = \"/run/user/%d/containers\"\n", a.Storage(), a.UID())
}

// EnsureStore makes a's persistent state, idempotently: the root-owned home and XDG dirs with storage.conf, and the
// workspace, storage and session-home subvolumes, each in qgroup 1/N (limit as in quota.EnsureAgent) before the agent
// owns them.
// A store still owned by another uid (a retired agent of the same name that is not archived yet) is an error.
func EnsureStore(a Agent, limit uint64) error {
	stores := []string{a.Workspace(), a.Storage(), a.SessionHome()}
	for _, p := range stores {
		if u, err := owner(p); err != nil {
			return err
		} else if u != -1 && u != 0 && u != a.UID() {
			return fmt.Errorf("accounts: %s belongs to uid %d, not %s (%d)", p, u, a.User(), a.UID())
		}
	}
	// the agent's user manager reads its XDG dirs, so control/ and control/xdg/ are traverse-only for it
	for _, d := range []string{Control, Control + "/xdg"} {
		if err := mkdirRoot(d, 0o711); err != nil {
			return err
		}
	}
	for _, d := range []string{quota.Data + "/workspaces", quota.Data + "/agents", a.Dir(), a.Home(), a.XDG(), a.XDG() + "/config",
		a.XDG() + "/config/containers", a.XDG() + "/data"} {
		if err := mkdirRoot(d, 0o755); err != nil {
			return err
		}
	}
	if err := writeIfChanged(a.XDG()+"/config/containers/storage.conf", a.StorageConf()); err != nil {
		return err
	}
	for _, p := range stores {
		if err := quota.EnsureSubvol(p); err != nil {
			return err
		}
	}
	if err := quota.EnsureAgent(a.N, limit, stores...); err != nil {
		return err
	}
	for _, p := range stores {
		if err := os.Lchown(p, a.UID(), a.UID()); err != nil {
			return err
		}
		if err := os.Chmod(p, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// archive moves a retired agent's subvolumes to a.Archive(), only while a's uid still owns them: the same name may
// belong to a newer agent by now.
func archive(a Agent) error {
	moves := [][2]string{{a.Workspace(), "workspace"}, {a.Dir(), "agent"}}
	for _, m := range moves {
		probe := m[0]
		if m[1] == "agent" {
			probe = a.Storage()
		}
		if u, err := owner(probe); err != nil {
			return err
		} else if u != a.UID() {
			continue
		}
		if err := mkdirRoot(a.Archive(), 0o700); err != nil {
			return err
		}
		if err := os.Rename(m[0], filepath.Join(a.Archive(), m[1])); err != nil {
			return err
		}
	}
	return nil
}
