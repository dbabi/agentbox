package rootd

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"time"

	"agentbox/internal/budgets"
	"agentbox/internal/rootd/accounts"
	"agentbox/internal/rootd/gens"
	"agentbox/internal/rootd/quota"
)

// The Go module cache's rootd half (ARCHITECTURE.md §4.1, §5.3, §6.2): cache.purge, cache.alert from the proxy, the
// hourly nested-subvolume sweep of data/cache/<name>, and budget.set with the per-agent day shares (§6.3).

// cacheAlertSchema keeps the cache alerts' rate limit across restarts: one ntfy alert per agent per 24 h, with a count
// per reason since the last one.
const cacheAlertSchema = `CREATE TABLE IF NOT EXISTS cache_alerts(agent TEXT PRIMARY KEY, sent_at INTEGER NOT NULL,
  counts TEXT NOT NULL CHECK(json_valid(counts))) STRICT;`

// CacheAlertReasons are the events no task can cause (§6.2 Alerts).
var CacheAlertReasons = []string{"sum_mismatch", "sumdb_security", "blob_corrupt"}

const cacheAlertEvery = 24 * time.Hour

// ProxyUnit is the proxy's service: stopped, rootd itself empties a store for a purge.
const ProxyUnit = "agentbox-proxy.service"

// errPurgeFailed is CACHE_PURGE_FAILED, a human CLI reply (§5.6): a running proxy didn't confirm the purge.
var errPurgeFailed = errors.New("CACHE_PURGE_FAILED")

// cachePurge is the admin op cache.purge{agent}: INTENT, the purge, RESULT. It needs no approver signature: it only
// deletes cached public files.
func (s *server) cachePurge(r request) reply {
	a, err := accounts.Lookup(s.db, r.Agent)
	if err != nil {
		return reply{"ok": false, "error": "cache.purge: " + err.Error()}
	}
	id := newDenyID()
	if err := s.audit(map[string]any{"type": "INTENT", "opId": id, "name": "cache.purge", "origin": "admin",
		"args": map[string]string{"agent": a.Name}}); err != nil {
		return reply{"ok": false, "error": "audit: the INTENT was not ACKed, nothing changed: " + err.Error()}
	}
	err = s.purgeCache(a)
	status, detail := "executed", ""
	if err != nil {
		status, detail = "failed", err.Error()
	}
	aerr := s.audit(map[string]any{"type": "RESULT", "opId": id, "status": status, "detail": detail})
	if err != nil {
		rep := reply{"ok": false, "error": err.Error()}
		if errors.Is(err, errPurgeFailed) {
			rep["code"] = errPurgeFailed.Error()
		}
		return rep
	}
	if aerr != nil {
		return reply{"ok": false, "error": "the cache was purged, but the audit RESULT was not ACKed: " + aerr.Error()}
	}
	return reply{"ok": true}
}

// purgeCache empties a's store: a running proxy does it (cancelling the agent's fills first) and must confirm; with
// the proxy stopped, rootd deletes the subvolume and makes it again, empty.
func (s *server) purgeCache(a accounts.Agent) error {
	if done, err := s.proxyPurge(a.Name); done || err != nil {
		return err
	}
	if s.recreateCache == nil {
		return errors.New("no cache store on this box")
	}
	return s.recreateCache(a)
}

// proxyPurge sends cache.purge{agent} on svc-proxy.sock when the proxy runs. It reports whether the proxy confirmed;
// a running proxy that doesn't is errPurgeFailed.
func (s *server) proxyPurge(agent string) (bool, error) {
	if s.proxyActive == nil || !s.proxyActive() || s.tasks == nil {
		return false, nil
	}
	rep, err := s.tasks.cfg.Svc("proxy", map[string]any{"call": "cache.purge", "agent": agent})
	switch {
	case err == nil && rep["ok"] == true:
		return true, nil
	case errors.Is(err, ErrNoSvc):
		return false, nil
	}
	return false, fmt.Errorf("%w: the proxy did not confirm the purge of %s: %v %v", errPurgeFailed, agent, err, rep["error"])
}

// recreateCacheStore is purgeCache with the proxy stopped: the store's subvolume goes, by name in the root-owned
// data/cache, and EnsureStore makes it again in 1/N, owned by the proxy, with its limit.
func (s *server) recreateCacheStore(a accounts.Agent) error {
	if _, err := os.Lstat(a.Cache()); err == nil {
		if err := s.deleteSubvol(a.Cache()); err != nil {
			return err
		}
	}
	return s.store(a, 0)
}

// deleteSubvol deletes a subvolume rootd made and runs the qgroup check after it (#79).
func (s *server) deleteSubvol(p string) error {
	if s.tasks != nil && s.tasks.cfg.Btrfs != nil {
		return s.tasks.cfg.Btrfs.Delete(p)
	}
	_, err := quota.Run("btrfs", "subvolume", "delete", p)
	return err
}

// cacheAlert is the proxy's cache.alert{agent, reason} on resolve-proxy.sock (§6.2 Alerts): an ALERT record each time,
// and at most one ntfy alert per agent per 24 h from a fixed template, with a count per reason. Details stay in audit.
func (s *server) cacheAlert(r request) reply {
	if !accounts.ValidName(r.Agent) || !slices.Contains(CacheAlertReasons, r.Reason) {
		return fail("bad_request")
	}
	if err := s.audit(map[string]any{"type": "ALERT", "source": "cache", "agent": r.Agent, "reason": r.Reason}); err != nil {
		log.Printf("cache.alert %s %s: ALERT not audited: %v", r.Agent, r.Reason, err)
	}
	now := time.Now()
	var sent int64
	var raw string
	counts := map[string]int{}
	err := s.db.QueryRow(`SELECT sent_at, counts FROM cache_alerts WHERE agent=?`, r.Agent).Scan(&sent, &raw)
	if err == nil {
		json.Unmarshal([]byte(raw), &counts)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return reply{"ok": false, "error": err.Error()}
	}
	counts[r.Reason]++
	if now.Sub(time.UnixMilli(sent)) >= cacheAlertEvery && s.cfg.Alert != nil {
		var parts []string
		for _, k := range CacheAlertReasons {
			if counts[k] > 0 {
				parts = append(parts, fmt.Sprintf("%s %d", k, counts[k]))
			}
		}
		if err := s.cfg.Alert("agentbox: Go module cache", "agent "+r.Agent+": "+strings.Join(parts, ", ")+" (details in audit)"); err != nil {
			log.Printf("cache.alert %s: %v", r.Agent, err)
		} else {
			sent, counts = now.UnixMilli(), map[string]int{}
		}
	}
	b, _ := json.Marshal(counts)
	if _, err := s.db.Exec(`INSERT INTO cache_alerts VALUES(?,?,?) ON CONFLICT(agent) DO UPDATE SET sent_at=excluded.sent_at, counts=excluded.counts`,
		r.Agent, sent, string(b)); err != nil {
		return reply{"ok": false, "error": err.Error()}
	}
	return reply{"ok": true}
}

// sweepCaches is the hourly sweep (§4.1): a subvolume nested in an agent's cache store alerts. The service filter
// should make one impossible, so a hit means it failed or root made one.
func (s *server) sweepCaches() {
	all, err := accounts.List(s.db)
	if err != nil {
		log.Printf("cache sweep: %v", err)
		return
	}
	for _, a := range all {
		if !a.Active {
			continue
		}
		n, err := s.nested(a.Cache())
		if err != nil {
			log.Printf("cache sweep %s: %v", a.Name, err)
			continue
		}
		if len(n) == 0 {
			continue
		}
		log.Printf("cache sweep %s: NESTED_SUBVOLUME in %s: %q", a.Name, a.Cache(), n)
		if err := s.audit(map[string]any{"type": "ALERT", "source": "cache_sweep", "agent": a.Name, "reason": "nested_subvolume"}); err != nil {
			log.Printf("cache sweep %s: ALERT not audited: %v", a.Name, err)
		}
		if s.cfg.Alert != nil {
			if err := s.cfg.Alert("agentbox: nested subvolume", fmt.Sprintf("agent %s: %d nested subvolume(s) in its Go module cache", a.Name, len(n))); err != nil {
				log.Printf("cache sweep %s: %v", a.Name, err)
			}
		}
	}
}

// budgetSet is the admin op budget.set{budgets}: the whole budgets.toml, checked (known keys, integers, explicit day
// shares no more than the box cap), INTENT, then the file, the caches' limits and the day shares, RESULT.
func (s *server) budgetSet(r request) reply {
	if r.Budgets == nil {
		return reply{"ok": false, "error": "budget.set needs budgets"}
	}
	b, err := budgets.Parse(*r.Budgets)
	if err != nil {
		return reply{"ok": false, "error": err.Error()}
	}
	id := newDenyID()
	if err := s.audit(map[string]any{"type": "INTENT", "opId": id, "name": "budget.set", "origin": "admin",
		"args": map[string]string{"budgets": *r.Budgets}}); err != nil {
		return reply{"ok": false, "error": "audit: the INTENT was not ACKed, nothing changed: " + err.Error()}
	}
	err = gens.WriteAtomic(s.budgetsPath(), []byte(b.Render()), 0o644)
	if err == nil {
		err = s.applyBudgets()
	}
	status, detail := "executed", ""
	if err != nil {
		status, detail = "failed", err.Error()
	}
	aerr := s.audit(map[string]any{"type": "RESULT", "opId": id, "status": status, "detail": detail})
	if err != nil {
		return reply{"ok": false, "error": err.Error()}
	}
	if aerr != nil {
		return reply{"ok": false, "error": "the budgets changed, but the audit RESULT was not ACKed: " + aerr.Error()}
	}
	return reply{"ok": true}
}

func (s *server) budgetsPath() string {
	if s.cfg.Budgets != "" {
		return s.cfg.Budgets
	}
	return budgets.Path
}

func (s *server) sharesPath() string {
	if s.cfg.Shares != "" {
		return s.cfg.Shares
	}
	return budgets.SharesPath
}

// applyBudgets re-applies budgets.toml: each active agent's cache limit, and the day shares keys reads.
func (s *server) applyBudgets() error {
	b, err := budgets.Read(s.budgetsPath())
	if err != nil {
		return err
	}
	all, err := accounts.List(s.db)
	if err != nil {
		return err
	}
	var errs []error
	if s.limitCache != nil {
		for _, a := range all {
			if a.Active {
				if err := s.limitCache(a.Cache(), uint64(b.Get("cache.agent_max_bytes"))); err != nil {
					errs = append(errs, fmt.Errorf("%s: %v", a.Name, err))
				}
			}
		}
	}
	return errors.Join(append(errs, s.writeShares(b, all))...)
}

// writeShares recomputes the per-agent day shares from the box cap and the active agents (§6.3), at rootd start,
// agent.add, agent.remove and budget.set.
func (s *server) writeShares(b budgets.Budgets, all []accounts.Agent) error {
	var active []string
	for _, a := range all {
		if a.Active {
			active = append(active, a.Name)
		}
	}
	sh, err := b.Shares(active)
	if err != nil {
		return err
	}
	return gens.WriteAtomic(s.sharesPath(), sh.JSON(), 0o644)
}

// refreshShares is writeShares from the files, after an agent.add or agent.remove.
func (s *server) refreshShares() {
	b, err := budgets.Read(s.budgetsPath())
	if err == nil {
		var all []accounts.Agent
		if all, err = accounts.List(s.db); err == nil {
			err = s.writeShares(b, all)
		}
	}
	if err != nil {
		log.Printf("day shares: %v", err)
	}
}
