package rootd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentbox/internal/budgets"
	"agentbox/internal/rootd/accounts"
)

type cacheFix struct {
	s      *server
	recs   []map[string]any
	alerts []string
	svc    []map[string]any
	svcRep map[string]any
	svcErr error
	remade []string
	limits map[string]uint64
	nested map[string][]string
}

func newCacheFix(t *testing.T) *cacheFix {
	t.Helper()
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "rootd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, n := range []string{"ga", "gb", "gc"} {
		if _, err := accounts.Add(db, n, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	accounts.Retire(db, "gc", time.Now())
	x := &cacheFix{limits: map[string]uint64{}, nested: map[string][]string{}}
	x.s = &server{db: db, cfg: Config{Budgets: filepath.Join(dir, "budgets.toml"), Shares: filepath.Join(dir, "day-shares.json"),
		Alert: func(title, msg string) error { x.alerts = append(x.alerts, title+": "+msg); return nil }},
		audit:       func(r map[string]any) error { x.recs = append(x.recs, r); return nil },
		proxyActive: func() bool { return x.svcRep != nil || x.svcErr != nil },
		recreateCache: func(a accounts.Agent) error {
			x.remade = append(x.remade, a.Name)
			return nil
		},
		limitCache: func(p string, max uint64) error { x.limits[p] = max; return nil },
		nested:     func(p string) ([]string, error) { return x.nested[p], nil }}
	x.s.tasks = &tasks{cfg: TaskConfig{Svc: func(svc string, req map[string]any) (map[string]any, error) {
		x.svc = append(x.svc, req)
		return x.svcRep, x.svcErr
	}}}
	return x
}

func (x *cacheFix) types() string {
	var t []string
	for _, r := range x.recs {
		t = append(t, r["type"].(string))
	}
	return strings.Join(t, " ")
}

// cache.purge (§5.3, A-G12): INTENT, then the running proxy's purge, or with the proxy stopped rootd re-makes the
// store; a proxy that doesn't confirm is CACHE_PURGE_FAILED, and nothing is re-made behind its back.
func TestCachePurge(t *testing.T) {
	x := newCacheFix(t)
	if rep := x.s.cachePurge(request{Agent: "gz"}); rep["ok"] != false || len(x.recs) != 0 {
		t.Fatalf("an unknown agent: %v %v", rep, x.recs)
	}
	if rep := x.s.cachePurge(request{Agent: "ga"}); rep["ok"] != true || strings.Join(x.remade, ",") != "ga" || len(x.svc) != 0 {
		t.Fatalf("proxy stopped: %v, re-made %v, svc %v", rep, x.remade, x.svc)
	}
	x.svcRep = map[string]any{"ok": true}
	if rep := x.s.cachePurge(request{Agent: "gb"}); rep["ok"] != true || len(x.remade) != 1 || x.svc[0]["call"] != "cache.purge" || x.svc[0]["agent"] != "gb" {
		t.Fatalf("proxy running: %v, svc %v", rep, x.svc)
	}
	x.svcRep, x.svcErr = nil, errors.New("i/o timeout")
	if rep := x.s.cachePurge(request{Agent: "gb"}); rep["ok"] != false || rep["code"] != "CACHE_PURGE_FAILED" || len(x.remade) != 1 {
		t.Fatalf("proxy hung: %v, re-made %v", rep, x.remade)
	}
	if got := x.types(); got != "INTENT RESULT INTENT RESULT INTENT RESULT" {
		t.Fatalf("records %s", got)
	}
	if last := x.recs[len(x.recs)-1]; last["status"] != "failed" {
		t.Fatalf("the failed purge's RESULT: %v", last)
	}
}

// cache.alert (§6.2 Alerts): only the three reasons no task can cause, an ALERT record each, and at most one ntfy
// alert per agent per 24 h with a count per reason since the last.
func TestCacheAlert(t *testing.T) {
	x := newCacheFix(t)
	for _, r := range []request{{Agent: "ga", Reason: "withdrawn"}, {Agent: "Bad", Reason: "sum_mismatch"}} {
		if rep := x.s.cacheAlert(r); rep["ok"] != false {
			t.Errorf("%+v: %v", r, rep)
		}
	}
	for _, reason := range []string{"sum_mismatch", "sum_mismatch", "blob_corrupt"} {
		if rep := x.s.cacheAlert(request{Agent: "ga", Reason: reason}); rep["ok"] != true {
			t.Fatal(rep)
		}
	}
	x.s.cacheAlert(request{Agent: "gb", Reason: "sumdb_security"})
	if len(x.alerts) != 2 || x.alerts[0] != "agentbox: Go module cache: agent ga: sum_mismatch 1 (details in audit)" {
		t.Fatalf("alerts %q", x.alerts)
	}
	if n := strings.Count(x.types(), "ALERT"); n != 4 {
		t.Fatalf("%d ALERT records, want 4", n)
	}
	x.s.db.Exec(`UPDATE cache_alerts SET sent_at = sent_at - ?`, (25 * time.Hour).Milliseconds())
	x.s.cacheAlert(request{Agent: "ga", Reason: "sumdb_security"})
	if len(x.alerts) != 3 || x.alerts[2] != "agentbox: Go module cache: agent ga: sum_mismatch 1, sumdb_security 1, blob_corrupt 1 (details in audit)" {
		t.Fatalf("after 24 h: %q", x.alerts)
	}
}

// budget.set (C-G4): refused, with nothing written, when explicit shares pass the box cap; otherwise the file, each
// active agent's cache limit and the recomputed day shares.
func TestBudgetSet(t *testing.T) {
	x := newCacheFix(t)
	over := "keys.day_cap_cents = 1000\nkeys.agent_day_share.ga = 700\nkeys.agent_day_share.gb = 400\n"
	if rep := x.s.budgetSet(request{Budgets: &over}); rep["ok"] != false || len(x.recs) != 0 {
		t.Fatalf("shares above the cap: %v", rep)
	}
	if _, err := os.Stat(x.s.cfg.Budgets); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused budget.set wrote the file")
	}
	ok := "keys.day_cap_cents = 1000\nkeys.agent_day_share.ga = 700\ncache.agent_max_bytes = 1073741824\n"
	if rep := x.s.budgetSet(request{Budgets: &ok}); rep["ok"] != true {
		t.Fatal(rep)
	}
	if got := x.types(); got != "INTENT RESULT" {
		t.Fatalf("records %s", got)
	}
	ga, _ := accounts.Lookup(x.s.db, "ga")
	if x.limits[ga.Cache()] != 1<<30 || len(x.limits) != 2 {
		t.Fatalf("cache limits %v", x.limits)
	}
	sh, err := budgets.ReadShares(x.s.cfg.Shares)
	if err != nil || sh.CapCents != 1000 || sh.Agents["ga"] != 700 || sh.Agents["gb"] != 300 || len(sh.Agents) != 2 {
		t.Fatalf("shares %+v %v", sh, err)
	}
	accounts.Add(x.s.db, "gd", time.Now())
	x.s.refreshShares()
	if sh, _ = budgets.ReadShares(x.s.cfg.Shares); sh.Agents["gb"] != 150 || sh.Agents["gd"] != 150 || sh.Agents["ga"] != 700 {
		t.Fatalf("after agent.add: %+v", sh)
	}
}

// The hourly sweep (§4.1, A-G13): a subvolume nested in an active agent's cache alerts; a clean store doesn't.
func TestSweepCaches(t *testing.T) {
	x := newCacheFix(t)
	x.s.sweepCaches()
	if len(x.alerts) != 0 {
		t.Fatalf("clean stores alerted: %q", x.alerts)
	}
	gb, _ := accounts.Lookup(x.s.db, "gb")
	x.nested[gb.Cache()] = []string{"data/cache/gb/sub"}
	x.s.sweepCaches()
	if len(x.alerts) != 1 || !strings.Contains(x.alerts[0], "agent gb: 1 nested subvolume") || x.types() != "ALERT" {
		t.Fatalf("alerts %q, records %s", x.alerts, x.types())
	}
}
