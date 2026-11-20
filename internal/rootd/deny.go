package rootd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"
)

// §9's DENY producer rules, for rootd's resolver refusals.
const (
	denyWindow = time.Minute // one record per (broker, code, entry) per window; repeats reuse its id
	denyCap    = 500         // records per broker per denyPeriod; past it, only a DENY_FLOOD count
	// shortcut: rootd has no task registry yet (weeks 4-6), so the cap runs per broker per hour and DENY_FLOOD goes at
	// the hour's end; key it by task, and send DENY_FLOOD when the task ends, once tasks exist.
	denyPeriod = time.Hour
	denyQueue  = 256 // refusals waiting for the one sender; more are dropped (the journal line stays)
)

type denial struct {
	svc, entry, code, detail string
	at                       time.Time
}

type denyKey struct{ svc, code, entry string }

type denyWin struct {
	id          string
	n           int
	first, last time.Time
	detail      string
}

// denyAudit throttles rootd's DENY records and sends them from one goroutine, so a broker looping on an unlisted name
// costs neither a goroutine nor an auditd fsync per request.
type denyAudit struct {
	send    func(map[string]any) // one record to auditd's rootd socket
	q       chan denial
	wins    map[denyKey]*denyWin
	sent    map[string]int // per broker in this period
	skipped map[string]int
	period  time.Time
}

func newDenyAudit(send func(map[string]any)) *denyAudit {
	return &denyAudit{send: send, q: make(chan denial, denyQueue), wins: map[denyKey]*denyWin{}, sent: map[string]int{},
		skipped: map[string]int{}}
}

// deny queues one refusal; it never blocks the resolver.
func (d *denyAudit) deny(svc, entry, code, detail string) bool {
	select {
	case d.q <- denial{svc, entry, code, detail, time.Now()}:
		return true
	default:
		return false
	}
}

func (d *denyAudit) run(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case x := <-d.q:
			d.add(x)
		case now := <-t.C:
			d.flush(now)
		case <-ctx.Done():
			return
		}
	}
}

func (d *denyAudit) add(x denial) {
	if d.period.IsZero() {
		d.period = x.at
	}
	k := denyKey{x.svc, x.code, x.entry}
	if w := d.wins[k]; w != nil {
		w.n, w.last = w.n+1, x.at
		return
	}
	if d.sent[x.svc] >= denyCap {
		d.skipped[x.svc]++
		return
	}
	d.sent[x.svc]++
	w := &denyWin{id: newDenyID(), n: 1, first: x.at, last: x.at, detail: x.detail}
	d.wins[k] = w
	d.send(denyRecord(k, w))
}

// flush ends windows: one with repeats sends its count under the same id. At the end of a period each broker that hit
// the cap gets a DENY_FLOOD with the number it skipped.
func (d *denyAudit) flush(now time.Time) {
	for k, w := range d.wins {
		if now.Sub(w.first) >= denyWindow {
			if w.n > 1 {
				d.send(denyRecord(k, w))
			}
			delete(d.wins, k)
		}
	}
	if !d.period.IsZero() && now.Sub(d.period) >= denyPeriod {
		for svc, n := range d.skipped {
			d.send(map[string]any{"type": "DENY_FLOOD", "by": "rootd", "svc": svc, "count": n})
		}
		d.sent, d.skipped, d.period = map[string]int{}, map[string]int{}, now
	}
}

func denyRecord(k denyKey, w *denyWin) map[string]any {
	return map[string]any{"type": "DENY", "id": w.id, "by": "rootd", "svc": k.svc, "entry": k.entry, "code": k.code,
		"detail": w.detail, "count": w.n, "first": w.first.UnixMilli(), "last": w.last.UnixMilli()}
}

func newDenyID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
