package audit

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	_ "modernc.org/sqlite"
)

// taint.db (Appendix E). Taint rows are never deleted, so a subject's epochs never repeat. ops is auditd's own index of
// the INTENTs it ACKed, so a RESULT can be matched to its INTENT (a clear applies only to a taint.clear whose INTENT is
// already in the chain, §9) and rootd's recovery can reconcile by op id.
const schema = `
CREATE TABLE IF NOT EXISTS taint(subject TEXT PRIMARY KEY, tainted INTEGER NOT NULL, epoch INTEGER NOT NULL DEFAULT 0, source TEXT, since INTEGER,
                   cleared_by TEXT, cleared_at INTEGER, content_id TEXT) STRICT;
CREATE TABLE IF NOT EXISTS writers(holder TEXT PRIMARY KEY, workspace TEXT NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS task_subjects(task TEXT NOT NULL, subject TEXT NOT NULL, PRIMARY KEY(task, subject)) STRICT;
CREATE TABLE IF NOT EXISTS ops(op_id TEXT PRIMARY KEY, producer TEXT NOT NULL, name TEXT NOT NULL, origin TEXT, signer TEXT,
                   target TEXT, content_id TEXT, epochs TEXT NOT NULL CHECK(json_valid(epochs)),
                   intent_seq INTEGER NOT NULL, result_seq INTEGER, status TEXT) STRICT;
CREATE TRIGGER IF NOT EXISTS taint_never_deleted BEFORE DELETE ON taint BEGIN SELECT RAISE(ABORT, 'taint rows are never deleted'); END;
`

func openTaintDB(path string) (*sql.DB, error) {
	q := url.Values{}
	for _, p := range []string{"journal_mode(WAL)", "synchronous(FULL)", "busy_timeout(5000)", "foreign_keys(ON)"} {
		q.Add("_pragma", p)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // auditd is the only writer, and every record runs under its one lock
	var mode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		db.Close()
		return nil, fmt.Errorf("taint.db: journal_mode %q, want wal: %v", mode, err)
	}
	var sync int
	if err := db.QueryRow("PRAGMA synchronous").Scan(&sync); err != nil || sync != 2 {
		db.Close()
		return nil, fmt.Errorf("taint.db: synchronous %d, want 2 (FULL): %v", sync, err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

var subjectKinds = []string{"task:", "session:", "workspace:", "ref:", "snap:", "fact:"}

func validSubject(s string) bool {
	if len(s) > 1024 || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return false
	}
	for _, k := range subjectKinds {
		if strings.HasPrefix(s, k) && len(s) > len(k) {
			return true
		}
	}
	return false
}

type taintRow struct {
	Subject string `json:"subject"`
	Tainted bool   `json:"tainted"`
	Epoch   int64  `json:"epoch"`
}

// get reads a subject; a missing row is clean at epoch 0 (§5.2).
func get(tx *sql.Tx, subject string) (taintRow, error) {
	r := taintRow{Subject: subject}
	err := tx.QueryRow("SELECT tainted, epoch FROM taint WHERE subject=?", subject).Scan(&r.Tainted, &r.Epoch)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return r, err
}

// raise taints subject: the epoch moves only on clean → tainted, so re-tainting never NACKs pending approvals (§5.2).
// Tainting a task or session also taints every workspace it writes, in the same transaction.
func raise(tx *sql.Tx, subject, source string, now int64) error {
	if _, err := tx.Exec(`INSERT INTO taint(subject, tainted, epoch, source, since) VALUES(?, 1, 1, ?, ?) ON CONFLICT(subject) DO UPDATE SET
		tainted=1, epoch=epoch+(tainted=0), source=CASE tainted WHEN 0 THEN excluded.source ELSE source END,
		since=CASE tainted WHEN 0 THEN excluded.since ELSE since END`, subject, source, now); err != nil {
		return err
	}
	if !strings.HasPrefix(subject, "task:") && !strings.HasPrefix(subject, "session:") {
		return nil
	}
	var ws string
	err := tx.QueryRow("SELECT workspace FROM writers WHERE holder=?", subject).Scan(&ws)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return raise(tx, ws, "writer:"+subject, now)
}

// clear is the only way down: the RESULT of a taint.clear on rootd's socket (§9). It applies only while the epoch is
// still the one the INTENT was ACKed at, and it moves the epoch, so the row stays and the old epoch never matches again.
func clear(tx *sql.Tx, subject string, epoch int64, by, contentID string, now int64) (bool, error) {
	r, err := get(tx, subject)
	if err != nil || r.Epoch != epoch {
		return false, err
	}
	_, err = tx.Exec(`INSERT INTO taint(subject, tainted, epoch, cleared_by, cleared_at, content_id) VALUES(?, 0, ?, ?, ?, ?)
		ON CONFLICT(subject) DO UPDATE SET tainted=0, epoch=epoch+1, cleared_by=excluded.cleared_by, cleared_at=excluded.cleared_at,
		content_id=excluded.content_id`, subject, epoch+1, by, now, contentID)
	return err == nil, err
}

// restore applies a signed workspace.restore: the workspace takes max(current, snapshot) and its epoch moves by 1 (§5.2).
func restore(tx *sql.Tx, ws, snap, source string, now int64) error {
	s, err := get(tx, snap)
	if err != nil {
		return err
	}
	w, err := get(tx, ws)
	if err != nil {
		return err
	}
	t := w.Tainted || s.Tainted
	_, err = tx.Exec(`INSERT INTO taint(subject, tainted, epoch, source, since) VALUES(?, ?, 1, ?, ?) ON CONFLICT(subject) DO UPDATE SET
		tainted=excluded.tainted, epoch=epoch+1, source=CASE WHEN excluded.tainted=1 AND tainted=0 THEN excluded.source ELSE source END,
		since=CASE WHEN excluded.tainted=1 AND tainted=0 THEN excluded.since ELSE since END`, ws, t, source, now)
	return err
}

// epochsMatch reports the subjects whose epoch moved since the caller evaluated them.
func epochsMatch(tx *sql.Tx, want map[string]int64) (map[string]int64, error) {
	moved := map[string]int64{}
	for s, e := range want {
		r, err := get(tx, s)
		if err != nil {
			return nil, err
		}
		if r.Epoch != e {
			moved[s] = r.Epoch
		}
	}
	return moved, nil
}

type writer struct {
	Holder    string `json:"holder"`
	Kind      string `json:"kind"` // task or session
	Workspace string `json:"workspace"`
}

type taintView struct {
	Holder   string     `json:"holder"`
	Subjects []taintRow `json:"subjects"`
	Writers  []writer   `json:"writers"`
}

// view answers taint.get: the holder's effective subjects with {tainted, epoch}, and W from writers with the holder kind.
func view(tx *sql.Tx, holder string) (*taintView, error) {
	v := &taintView{Holder: holder, Subjects: []taintRow{}, Writers: []writer{}}
	seen := map[string]bool{}
	add := func(s string) error {
		if seen[s] {
			return nil
		}
		seen[s] = true
		r, err := get(tx, s)
		v.Subjects = append(v.Subjects, r)
		return err
	}
	if err := add(holder); err != nil {
		return nil, err
	}
	rows, err := tx.Query("SELECT holder, workspace FROM writers WHERE holder=?", holder)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var w writer
		if err := rows.Scan(&w.Holder, &w.Workspace); err != nil {
			rows.Close()
			return nil, err
		}
		w.Kind, _, _ = strings.Cut(w.Holder, ":")
		v.Writers = append(v.Writers, w)
	}
	rows.Close()
	var subs []string
	rows, err = tx.Query("SELECT subject FROM task_subjects WHERE task=? ORDER BY subject", holder)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return nil, err
		}
		subs = append(subs, s)
	}
	rows.Close()
	for _, w := range v.Writers {
		subs = append(subs, w.Workspace)
	}
	for _, s := range subs {
		if err := add(s); err != nil {
			return nil, err
		}
	}
	return v, nil
}

func epochsJSON(m map[string]int64) string {
	if m == nil {
		m = map[string]int64{}
	}
	b, _ := json.Marshal(m)
	return string(b)
}
