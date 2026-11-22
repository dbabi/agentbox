package attach

import (
	"database/sql"
	"errors"
	"time"
)

// Schema is rootd.db's task block (§4.2): a workspace whose attach is live, or whose last attach wrote a token, takes
// no task. The row goes in before the session starts and comes out only after a clean scan, so a rootd crash mid-attach
// leaves the workspace blocked, not unscanned.
const Schema = `
CREATE TABLE IF NOT EXISTS task_block(agent TEXT PRIMARY KEY, session TEXT NOT NULL, reason TEXT NOT NULL,
  started_ms INTEGER NOT NULL, detail TEXT NOT NULL DEFAULT '');
`

// Block reasons.
const (
	Live  = "attach_live"        // the session is running, or rootd stopped before its scan
	Token = "token_in_workspace" // the scan found a session-home token
)

// ErrLive is a second attach of the same agent, or an attach while a block stands.
var ErrLive = errors.New("an attach is live, or the last one is not cleared (agentbox attach status)")

// Begin blocks the agent's workspace for session id. It refuses while any block stands.
func Begin(db *sql.DB, agent, id string, start time.Time) error {
	res, err := db.Exec(`INSERT INTO task_block(agent, session, reason, started_ms) VALUES(?,?,?,?) ON CONFLICT(agent) DO NOTHING`,
		agent, id, Live, start.UnixMilli())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrLive
	}
	return nil
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
		detail += h.Path
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

// Blocked is task.start's check: a standing block refuses the task (the task launcher calls it).
func Blocked(db *sql.DB, agent string) (BlockRow, bool, error) {
	r := BlockRow{Agent: agent}
	err := db.QueryRow(`SELECT session, reason, started_ms, detail FROM task_block WHERE agent=?`, agent).Scan(&r.Session, &r.Reason, &r.Started, &r.Detail)
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	return r, err == nil, err
}

// List is every standing block.
func List(db *sql.DB) ([]BlockRow, error) {
	rows, err := db.Query(`SELECT agent, session, reason, started_ms, detail FROM task_block ORDER BY agent`)
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
