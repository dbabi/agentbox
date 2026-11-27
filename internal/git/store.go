package git

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// storeSchema is the service's own state, git/.state.db (owned by agentbox-git). push_days is each agent's pushed bytes
// per UTC day (the daily cap). tainted_refs and tainted_commits are what tainted pushes and merges brought in (§6.3): a
// fetch that may deliver them gets read taint first, and repo.merge carries them to main. A row is never deleted, so a
// cleared or deleted ref only costs a READ_INTENT that auditd finds clean. ops is every effect op id the service
// started, so rootd's one-shot capability runs once.
const storeSchema = `
CREATE TABLE IF NOT EXISTS push_days(day_start INTEGER NOT NULL, agent TEXT NOT NULL, bytes INTEGER NOT NULL, PRIMARY KEY(day_start, agent)) STRICT;
CREATE TABLE IF NOT EXISTS tainted_refs(repo TEXT NOT NULL, ref TEXT NOT NULL, since INTEGER NOT NULL, PRIMARY KEY(repo, ref)) STRICT;
CREATE TABLE IF NOT EXISTS tainted_commits(repo TEXT NOT NULL, oid TEXT NOT NULL, task TEXT NOT NULL, since INTEGER NOT NULL, PRIMARY KEY(repo, oid)) STRICT;
CREATE TABLE IF NOT EXISTS ops(id TEXT PRIMARY KEY, name TEXT NOT NULL, started_at INTEGER NOT NULL) STRICT;
`

// OpenStore opens (and creates) dir/.state.db with WAL and synchronous=FULL. The hook opens the same file while the
// service has it open, so writers wait on the busy timeout instead of failing.
func OpenStore(dir string) (*sql.DB, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, ".state.db")+"?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout(10000)&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(storeSchema); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// DayStart is 00:00 UTC of t, in Unix ms.
func DayStart(t time.Time) int64 {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC).UnixMilli()
}

// errDayCap is a push that would take the agent over its day cap.
var errDayCap = errors.New("push_bytes_day")

// usedToday is agent's pushed bytes today.
func usedToday(db *sql.DB, agent string, now time.Time) (int64, error) {
	var n int64
	err := db.QueryRow(`SELECT bytes FROM push_days WHERE day_start=? AND agent=?`, DayStart(now), agent).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return n, err
}

// addToday counts n more bytes for agent today, in one transaction that also re-checks the cap: two pushes that each
// fit alone can't both pass it.
func addToday(db *sql.DB, agent string, n, limit int64, now time.Time) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var used int64
	err = tx.QueryRow(`SELECT bytes FROM push_days WHERE day_start=? AND agent=?`, DayStart(now), agent).Scan(&used)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if used+n > limit {
		return errDayCap
	}
	if _, err := tx.Exec(`INSERT INTO push_days(day_start, agent, bytes) VALUES(?,?,?) ON CONFLICT(day_start, agent)
		DO UPDATE SET bytes=bytes+excluded.bytes`, DayStart(now), agent, n); err != nil {
		return err
	}
	return tx.Commit()
}

// markTainted records refs and commits of repo as tainted, in one transaction.
func markTainted(db *sql.DB, repo, task string, refs, commits []string, now int64) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, r := range refs {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO tainted_refs(repo, ref, since) VALUES(?,?,?)`, repo, r, now); err != nil {
			return err
		}
	}
	for _, c := range commits {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO tainted_commits(repo, oid, task, since) VALUES(?,?,?,?)`, repo, c, task, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// taintedRefs lists repo's refs that a tainted push or merge updated.
func taintedRefs(db *sql.DB, repo string) ([]string, error) {
	rows, err := db.Query(`SELECT ref FROM tainted_refs WHERE repo=? ORDER BY ref`, repo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// anyTaintedCommit reports whether any of oids is a commit a tainted push brought into repo.
func anyTaintedCommit(db *sql.DB, repo string, oids []string) (bool, error) {
	for _, o := range oids {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM tainted_commits WHERE repo=? AND oid=?`, repo, o).Scan(&n); err != nil {
			return false, err
		}
		if n > 0 {
			return true, nil
		}
	}
	return false, nil
}

// errOpSeen is an op id the service already started: rootd's capability is one-shot.
var errOpSeen = errors.New("op already started")

// startOp records op id before its effect; a second start of the same id fails.
func startOp(db *sql.DB, id, name string, now int64) error {
	res, err := db.Exec(`INSERT OR IGNORE INTO ops(id, name, started_at) VALUES(?,?,?)`, id, name, now)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errOpSeen
	}
	return nil
}
