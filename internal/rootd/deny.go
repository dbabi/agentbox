package rootd

import (
	"context"
	"strconv"
	"strings"
	"time"

	"agentbox/internal/ids"
	"agentbox/internal/ops"
	"agentbox/internal/rootd/resolve"
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

type refusal struct {
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
	q       chan refusal
	wins    map[denyKey]*denyWin
	sent    map[string]int // per broker in this period
	skipped map[string]int
	period  time.Time
}

func newDenyAudit(send func(map[string]any)) *denyAudit {
	return &denyAudit{send: send, q: make(chan refusal, denyQueue), wins: map[denyKey]*denyWin{}, sent: map[string]int{},
		skipped: map[string]int{}}
}

// deny queues one refusal; it never blocks the resolver.
func (d *denyAudit) deny(svc, entry, code, detail string) bool {
	select {
	case d.q <- refusal{svc, entry, code, detail, time.Now()}:
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

func (d *denyAudit) add(x refusal) {
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
			d.send(map[string]any{"type": "DENY_FLOOD", "by": svc, "count": n})
		}
		d.sent, d.skipped, d.period = map[string]int{}, map[string]int{}, now
	}
}

// resolveCodes maps a resolver refusal reason to its §5.6 code and what (§6.2: the proxy maps them the same way).
var resolveCodes = map[string][2]string{
	resolve.NotAllowlisted: {"EGRESS_NOT_ALLOWLISTED", ""},
	resolve.NonPublic:      {"EGRESS_NAME_REJECTED", "non_public"},
	resolve.NoSuchName:     {"EGRESS_RESOLVE_FAILED", "no_such_name"},
	resolve.Unavailable:    {"EGRESS_RESOLVE_FAILED", "unavailable"},
}

// denyRecord is the DENY record for one window (§9): the broker is the enforcer, the entry is the subject (fields that
// fail their grammar are dropped, so auditd's schema check passes), and the address and check stay in detail.
func denyRecord(k denyKey, w *denyWin) map[string]any {
	c, ok := resolveCodes[k.code]
	if !ok {
		c = resolveCodes[resolve.Unavailable]
	}
	host, port, _ := strings.Cut(k.entry, ":")
	p, _ := strconv.ParseInt(port, 10, 64)
	r := map[string]any{"type": "DENY", "id": w.id, "by": k.svc, "code": c[0], "detail": trunc(w.detail, 1024),
		"count": w.n, "first": w.first.UnixMilli(), "last": w.last.UnixMilli()}
	if c[1] != "" {
		r["what"] = c[1]
	}
	if sub := (ops.Subject{Host: host, Port: p}).Clean(); sub != (ops.Subject{}) {
		r["subject"] = sub
	}
	return r
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func newDenyID() string { return ids.New(ids.Denial) }
