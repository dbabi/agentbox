package keys

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Ledger is keys' spend ledger (§6.3 Budget reservation): one row per billed request, reserved before it goes
// upstream and settled from the reply's usage. A row a crash left unsettled counts at its reservation, so a restart
// never frees budget that a request may have spent.
type Ledger struct{ db *sql.DB }

const ledgerSchema = `
CREATE TABLE IF NOT EXISTS spend(id TEXT PRIMARY KEY, day INTEGER NOT NULL, agent TEXT NOT NULL, trace TEXT NOT NULL,
  task TEXT NOT NULL, model TEXT NOT NULL, reserved INTEGER NOT NULL CHECK(reserved >= 0), spent INTEGER CHECK(spent >= 0),
  at INTEGER NOT NULL) STRICT;
CREATE INDEX IF NOT EXISTS spend_day_agent ON spend(day, agent);
CREATE INDEX IF NOT EXISTS spend_trace ON spend(trace);
`

// OpenLedger opens path (WAL, synchronous=FULL) and settles what a previous run left open at its reservation.
func OpenLedger(path string) (*Ledger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout(10000)&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(ledgerSchema); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`UPDATE spend SET spent = reserved WHERE spent IS NULL`); err != nil {
		db.Close()
		return nil, err
	}
	return &Ledger{db: db}, nil
}

func (l *Ledger) Close() error { return l.db.Close() }

// Limits are a request's caps in nanodollars; 0 is none. Box is the backstop: day shares sum to at most the box cap,
// so only a bug or a hand-edited shares file reaches it.
type Limits struct {
	Agent, Trace, Box int64
	Capped            bool // the box has a day cap, so the agent's share applies (0 is a share of nothing)
}

// Over is a reservation that a limit refuses: which one.
type Over struct{ What string } // agent, trace or box

func (o *Over) Error() string { return "budget: over the " + o.What + " limit" }

const nanosPerCent = 10_000_000

func dayOf(t time.Time) int64 { return t.UTC().UnixMilli() / 86_400_000 }

// NextDay is when the agent's day share resets: the next 00:00 UTC.
func NextDay(t time.Time) time.Time { return time.UnixMilli((dayOf(t) + 1) * 86_400_000).UTC() }

// Reserve books nanos for id against the agent's day, the trace and the box day, all in one transaction, or refuses
// with *Over and books nothing. Only the caller's own share and trace decide its refusal (§6.3), unless the box
// backstop trips.
func (l *Ledger) Reserve(id, agent, trace, task, model string, nanos int64, lim Limits, now time.Time) error {
	tx, err := l.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	day := dayOf(now)
	sum := func(q string, args ...any) (int64, error) {
		var n int64
		err := tx.QueryRow(`SELECT COALESCE(SUM(COALESCE(spent, reserved)), 0) FROM spend WHERE `+q, args...).Scan(&n)
		return n, err
	}
	a, err := sum(`day = ? AND agent = ?`, day, agent)
	if err != nil {
		return err
	}
	if lim.Capped && a+nanos > lim.Agent {
		return &Over{"agent"}
	}
	if lim.Trace > 0 {
		t, err := sum(`trace = ?`, trace)
		if err != nil {
			return err
		}
		if t+nanos > lim.Trace {
			return &Over{"trace"}
		}
	}
	if lim.Box > 0 {
		b, err := sum(`day = ?`, day)
		if err != nil {
			return err
		}
		if b+nanos > lim.Box {
			return &Over{"box"}
		}
	}
	if _, err := tx.Exec(`INSERT INTO spend(id, day, agent, trace, task, model, reserved, spent, at) VALUES(?,?,?,?,?,?,?,NULL,?)`,
		id, day, agent, trace, task, model, nanos, now.UnixMilli()); err != nil {
		return err
	}
	return tx.Commit()
}

// Settle records what id spent. A request whose reply carried no usage settles at its reservation.
func (l *Ledger) Settle(id string, nanos int64) error {
	r, err := l.db.Exec(`UPDATE spend SET spent = ? WHERE id = ? AND spent IS NULL`, max(nanos, 0), id)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n != 1 {
		return fmt.Errorf("settle %s: no open reservation", id)
	}
	return nil
}

// Spent is the agent's spend today and the trace's spend so far, settled or reserved, in nanodollars.
func (l *Ledger) Spent(agent, trace string, now time.Time) (day, tr int64, err error) {
	err = l.db.QueryRow(`SELECT COALESCE(SUM(COALESCE(spent, reserved)), 0) FROM spend WHERE day = ? AND agent = ?`, dayOf(now), agent).Scan(&day)
	if err == nil {
		err = l.db.QueryRow(`SELECT COALESCE(SUM(COALESCE(spent, reserved)), 0) FROM spend WHERE trace = ?`, trace).Scan(&tr)
	}
	return day, tr, err
}
