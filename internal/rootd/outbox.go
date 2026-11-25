package rootd

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"
)

// alertSchema is the alert outbox (ARCHITECTURE.md §11, #220): every rootd alert, and each one fwcheck or agentbox os
// could not send, waits here until ntfy takes it. Rows persist, so neither an ntfy restart nor a rootd one loses an alert.
const alertSchema = `CREATE TABLE IF NOT EXISTS alert_outbox(id INTEGER PRIMARY KEY, title TEXT NOT NULL, msg TEXT NOT NULL,
  queued_at INTEGER NOT NULL) STRICT;`

// alertMax bounds the outbox: rootd.db is control state outside 2/0, so alerts piling up while ntfy is down must not
// eat the disk reserve.
const alertMax = 256

// alertRetry is how often rootd sends the queued alerts again.
const alertRetry = 10 * time.Second

// QueueAlert puts one alert in rootd.db's outbox. rootd sends it and deletes it once ntfy took it.
func QueueAlert(db *sql.DB, title, msg string) error {
	r, err := db.Exec(`INSERT INTO alert_outbox(title, msg, queued_at) SELECT ?, ?, ? WHERE (SELECT count(*) FROM alert_outbox) < ?`,
		title, msg, time.Now().UnixMilli(), alertMax)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err == nil && n == 0 {
		err = fmt.Errorf("the alert outbox already holds %d alerts", alertMax)
	}
	return err
}

// outbox sends the queued alerts with send (ntfy.Publish).
type outbox struct {
	db   *sql.DB
	send func(title, msg string) error
	kick chan struct{} // cap 1: a queued alert asks run for a drain now
}

// queue is Config.Alert once Run started the outbox: the alert goes in rootd.db, and run sends it right away.
func (o *outbox) queue(title, msg string) error {
	if err := QueueAlert(o.db, title, msg); err != nil {
		return err
	}
	select {
	case o.kick <- struct{}{}:
	default: // a drain is already due
	}
	return nil
}

// drain sends each queued alert, oldest first, and deletes it once ntfy took it. One that fails stays for the next
// drain and doesn't hold back the others. It returns the first error.
func (o *outbox) drain() error {
	type alert struct {
		id         int64
		title, msg string
	}
	rows, err := o.db.Query(`SELECT id, title, msg FROM alert_outbox ORDER BY id`)
	if err != nil {
		return err
	}
	var q []alert
	for rows.Next() {
		var a alert
		if err := rows.Scan(&a.id, &a.title, &a.msg); err != nil {
			rows.Close()
			return err
		}
		q = append(q, a)
	}
	rows.Close() // before the sends: rootd.db has one connection (OpenDB), and each delete needs it
	first := rows.Err()
	for _, a := range q {
		err := o.send(a.title, a.msg)
		if err == nil {
			log.Printf("alert sent: %s", a.msg)
			_, err = o.db.Exec(`DELETE FROM alert_outbox WHERE id=?`, a.id)
		}
		if first == nil {
			first = err
		}
	}
	return first
}

// run drains at start, after each queue and every retry until ctx ends. A run of failures logs once.
func (o *outbox) run(ctx context.Context, retry time.Duration) {
	t := time.NewTicker(retry)
	defer t.Stop()
	failing := false
	for {
		err := o.drain()
		if err != nil && !failing {
			log.Printf("alert not sent: %v; it stays queued in rootd.db and is sent again every %s", err, retry)
		}
		failing = err != nil
		select {
		case <-ctx.Done():
			return
		case <-o.kick:
		case <-t.C:
		}
	}
}
