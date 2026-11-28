package rootd

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

func queued(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT title || ': ' || msg FROM alert_outbox ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var q []string
	for rows.Next() {
		var s string
		rows.Scan(&s)
		q = append(q, s)
	}
	return q
}

// #220: an alert ntfy doesn't take stays in rootd.db, across a rootd restart, until a later drain sends it. One that
// keeps failing doesn't hold back the others, and the outbox is bounded.
func TestAlertOutbox(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rootd.db")
	db, err := OpenDB(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"a", "b", "c"} {
		if err := QueueAlert(db, "agentbox: t", m); err != nil {
			t.Fatal(err)
		}
	}
	down := errors.New("dial unix /run/ntfy/ntfy.sock: connect: no such file or directory")
	o := &outbox{db: db, send: func(string, string) error { return down }}
	if err := o.drain(); !errors.Is(err, down) || len(queued(t, db)) != 3 {
		t.Fatalf("ntfy down: drain %v, queued %q", err, queued(t, db))
	}
	db.Close()
	if db, err = OpenDB(p); err != nil { // rootd restarted
		t.Fatal(err)
	}
	defer db.Close()
	var sent []string
	o = &outbox{db: db, send: func(title, msg string) error {
		if msg == "b" {
			return errors.New("ntfy publish: 400 Bad Request")
		}
		sent = append(sent, title+": "+msg)
		return nil
	}}
	if err := o.drain(); err == nil || !slices.Equal(sent, []string{"agentbox: t: a", "agentbox: t: c"}) || !slices.Equal(queued(t, db), []string{"agentbox: t: b"}) {
		t.Fatalf("ntfy back, b refused: drain %v, sent %q, queued %q", err, sent, queued(t, db))
	}
	for i := 1; i < alertMax; i++ {
		if err := QueueAlert(db, "agentbox: t", "x"); err != nil {
			t.Fatalf("alert %d of %d: %v", i+1, alertMax, err)
		}
	}
	if err := QueueAlert(db, "agentbox: t", "x"); err == nil || len(queued(t, db)) != alertMax {
		t.Fatalf("a full outbox took one more: %v, %d queued", err, len(queued(t, db)))
	}
}

// #220: run sends a queued alert at once, and one ntfy refused at the next retry.
func TestAlertOutboxRun(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "rootd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, c := range []struct {
		name  string
		fails int
		retry time.Duration
	}{{"sent at once (no retry before an hour)", 0, time.Hour}, {"ntfy refuses twice, sent at the second retry", 2, 50 * time.Millisecond}} {
		t.Run(c.name, func(t *testing.T) {
			var mu sync.Mutex
			tries, sent := 0, make(chan string, 1)
			o := &outbox{db: db, kick: make(chan struct{}, 1), send: func(_, msg string) error {
				mu.Lock()
				defer mu.Unlock()
				if tries++; tries <= c.fails {
					return errors.New("ntfy down")
				}
				sent <- msg
				return nil
			}}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); o.run(ctx, c.retry) }()
			// the cases share rootd.db: this run must end before the next case queues, or it can send that alert (#323)
			defer func() { cancel(); <-done }()
			if err := o.queue("agentbox: t", c.name); err != nil {
				t.Fatal(err)
			}
			select {
			case m := <-sent:
				if m != c.name {
					t.Fatalf("sent %q", m)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("not sent")
			}
			for i := 0; i < 100 && len(queued(t, db)) > 0; i++ {
				time.Sleep(10 * time.Millisecond) // the delete follows the send
			}
			if q := queued(t, db); len(q) > 0 {
				t.Fatalf("still queued after the send: %q", q)
			}
		})
	}
}
