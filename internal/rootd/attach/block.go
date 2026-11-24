package attach

import (
	"database/sql"
	"errors"
	"strconv"
	"time"
)

// Schema is rootd.db's task block (§4.2): a workspace whose attach is live, or whose last attach wrote a token, takes
// no task. The row goes in before the session starts and comes out only after a clean scan, so a rootd crash mid-attach
// leaves the workspace blocked, not unscanned. A task whose cgroup kept processes after task.stop blocks its agent the
// same way: one task_leftover row per such task, so each one's cgroup is checked before the agent gets tasks again.
// Older rootds kept that block as a task_block row (reason TaskNotEmpty); it moves to task_leftover here.
const Schema = `
CREATE TABLE IF NOT EXISTS task_block(agent TEXT PRIMARY KEY, session TEXT NOT NULL, reason TEXT NOT NULL,
  started_ms INTEGER NOT NULL, detail TEXT NOT NULL DEFAULT '') STRICT;
CREATE TABLE IF NOT EXISTS task_leftover(task TEXT PRIMARY KEY, agent TEXT NOT NULL, started_ms INTEGER NOT NULL) STRICT;
INSERT OR IGNORE INTO task_leftover(task, agent, started_ms) SELECT session, agent, started_ms FROM task_block WHERE reason='task_not_empty';
DELETE FROM task_block WHERE reason='task_not_empty';
`

// Block reasons.
const (
	Live  = "attach_live"        // the session is running, or rootd stopped before its scan
	Token = "token_in_workspace" // the scan found a session-home token
	// TaskNotEmpty is §4.2 Stop step 2 failing closed: a stopped task's unit cgroup still had processes
	TaskNotEmpty = "task_not_empty"
)

// ErrLive is a second attach of the same agent, or an attach while a block stands.
var ErrLive = errors.New("an attach is live, or the last one is not cleared (agentbox attach status)")

// ErrTaskLive is an attach while a task of the agent runs: that task has the workspace mounted read-write and would
// see what the session writes there before the token scan.
var ErrTaskLive = errors.New("a task of this agent is running (agentbox task list): attach after it ends")

// Begin blocks the agent's workspace for session id. It refuses while any block stands or a task of the agent is live
// in rootd's task_registry. One statement does both, so it can't interleave with task.start, which inserts its
// registry row and checks this block in one transaction.
func Begin(db *sql.DB, agent, id string, start time.Time) error {
	res, err := db.Exec(`INSERT INTO task_block(agent, session, reason, started_ms) SELECT ?,?,?,?
		WHERE NOT EXISTS(SELECT 1 FROM task_registry WHERE agent=? AND ended_at IS NULL) AND NOT EXISTS(SELECT 1 FROM task_leftover WHERE agent=?)
		ON CONFLICT(agent) DO NOTHING`,
		agent, id, Live, start.UnixMilli(), agent, agent)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	if _, on, _ := Blocked(db, agent); on {
		return ErrLive
	}
	return ErrTaskLive
}

// Execer is a *sql.DB or a *sql.Tx.
type Execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// BlockTask records task id of agent as leftover (TaskNotEmpty). Every leftover task blocks the agent until ClearTask.
func BlockTask(db Execer, agent, id string, now time.Time) error {
	_, err := db.Exec(`INSERT INTO task_leftover(task, agent, started_ms) VALUES(?,?,?) ON CONFLICT(task) DO NOTHING`, id, agent, now.UnixMilli())
	return err
}

// Leftovers is agent's leftover tasks, oldest first.
func Leftovers(db *sql.DB, agent string) ([]string, error) {
	rows, err := db.Query(`SELECT task FROM task_leftover WHERE agent=? ORDER BY started_ms, task`, agent)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ClearTask lifts leftover task id: its unit cgroup is empty or gone.
func ClearTask(db *sql.DB, id string) error {
	_, err := db.Exec(`DELETE FROM task_leftover WHERE task=?`, id)
	return err
}

// Clear deletes every block of agent: the agent was removed.
func Clear(db *sql.DB, agent string) error {
	_, err := db.Exec(`DELETE FROM task_block WHERE agent=?`, agent)
	if err == nil {
		_, err = db.Exec(`DELETE FROM task_leftover WHERE agent=?`, agent)
	}
	return err
}

// End records the scan of session id: no hits lifts the block, a hit turns it into Token.
func End(db *sql.DB, agent, id string, hits []Hit) error {
	if len(hits) == 0 {
		_, err := db.Exec(`DELETE FROM task_block WHERE agent=? AND session=?`, agent, id)
		return err
	}
	detail := ""
	for i, h := range hits {
		if i == 10 {
			detail += " ..."
			break
		}
		if i > 0 {
			detail += " "
		}
		detail += strconv.QuoteToASCII(h.Path) // the agent named it; attach status shows it
	}
	_, err := db.Exec(`UPDATE task_block SET reason=?, detail=? WHERE agent=? AND session=?`, Token, detail, agent, id)
	return err
}

// BlockRow is one standing block.
type BlockRow struct {
	Agent   string `json:"agent"`
	Session string `json:"session"`
	Reason  string `json:"reason"`
	Started int64  `json:"started_ms"`
	Detail  string `json:"detail,omitempty"`
}

// Querier is a *sql.DB or a *sql.Tx.
type Querier interface {
	QueryRow(query string, args ...any) *sql.Row
}

// blocks is task_block's rows and one TaskNotEmpty row per leftover task (session holds the task id), attach blocks first.
const blocks = `SELECT agent, session, reason, started_ms, detail, 0 AS k FROM task_block
  UNION ALL SELECT agent, task, 'task_not_empty', started_ms, '', 1 FROM task_leftover`

// Blocked is task.start's check: a standing block refuses the task (the task launcher calls it in the transaction
// that registers the task). An attach block comes before a leftover task's.
func Blocked(db Querier, agent string) (BlockRow, bool, error) {
	r := BlockRow{Agent: agent}
	err := db.QueryRow(`SELECT session, reason, started_ms, detail FROM (`+blocks+`) WHERE agent=? ORDER BY k, started_ms, session LIMIT 1`, agent).
		Scan(&r.Session, &r.Reason, &r.Started, &r.Detail)
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	return r, err == nil, err
}

// List is every standing block.
func List(db *sql.DB) ([]BlockRow, error) {
	rows, err := db.Query(`SELECT agent, session, reason, started_ms, detail FROM (` + blocks + `) ORDER BY agent, k, started_ms, session`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BlockRow{}
	for rows.Next() {
		var r BlockRow
		if err := rows.Scan(&r.Agent, &r.Session, &r.Reason, &r.Started, &r.Detail); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
