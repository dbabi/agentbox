package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"time"

	"agentbox/internal/audit"
	"agentbox/internal/budgets"
	"agentbox/internal/dial"
	"agentbox/internal/gate"
	"agentbox/internal/proxy"
	"agentbox/internal/proxy/gocache"
	"agentbox/internal/rootd/resolve"
	"agentbox/internal/taskenv"
)

const (
	proxyDir          = "/run/agentbox-proxy"
	proxyResolveSock  = "/run/agentbox-rootd/resolve-proxy.sock"
	proxyAuditSock    = "/run/agentbox-audit/proxy.sock"
	proxyCacheRoot    = "/var/lib/agentbox/data/cache"
	proxyListLiveWait = 10 * time.Second
)

// cmdProxy is agentbox-proxy.service (§2, §6.2): the CONNECT egress of every task, and the Go module cache behind each
// task's proxy.sock. It installs the service btrfs seccomp filter first (§2 Common hardening). svc-proxy.sock comes
// from its .socket unit; on rootd's register it binds the task's proxy.sock in the dir rootd made, on revoke it also
// cancels the task's cache fills, and cache.purge{agent} empties that agent's store. At start it sweeps the stores and
// rebinds rootd's live tasks, so a running task survives a proxy restart (§2.1).
func cmdProxy(args []string) error {
	if err := parse(flag.NewFlagSet("proxy", flag.ContinueOnError), args); err != nil {
		return err
	}
	if err := serviceFilter(); err != nil {
		return err
	}
	ls, err := listenFDs()
	if err != nil {
		return err
	}
	ctl, ok := ls["svc-proxy"]
	if !ok || len(ls) != 1 {
		return errors.New("proxy: want exactly the svc-proxy socket from systemd")
	}
	send := func(rec map[string]any) error { return audit.Send(proxyAuditSock, rec) }
	s := &gate.Server{Dir: proxyDir, Name: "proxy", Conns: proxy.MaxConns,
		AgentIDs: func(a string) (uint32, uint32, error) { return uidOf("ag-" + a) }}
	key := gocache.SumKey
	if k := os.Getenv("AGENTBOX_TEST_SUMDB"); k != "" { // a gate's fake checksum database; test VMs only
		key = k
		log.Printf("cache: checksum database key %s (AGENTBOX_TEST_SUMDB)", k)
	}
	cache := gocache.New(gocache.Config{Root: proxyCacheRoot, Key: key, Audit: send, Limits: cacheLimits, Live: s.Live,
		// a fill dials as a CONNECT does (§6.3): rootd's answers for the task, which must still be live
		Upstream: func(ctx context.Context, task string) (net.Conn, error) {
			if !s.Live(task) {
				return nil, errors.New("no live task")
			}
			return dial.Dialer{Sock: proxyResolveSock, Task: task}.DialContext(ctx, "tcp", taskenv.GoProxyEntry.String())
		},
		Alert: func(agent, reason string) {
			l, err := lineCall(proxyResolveSock, map[string]any{"op": "cache.alert", "agent": agent, "reason": reason}, proxyListLiveWait)
			var r struct{ OK bool }
			if err == nil && (json.Unmarshal(l, &r) != nil || !r.OK) {
				err = errors.New(string(l))
			}
			if err != nil {
				log.Printf("cache.alert %s %s: %v", agent, reason, err)
			}
		},
		Allowed: func(agent string) bool {
			l, err := resolve.LoadLists(resolve.EgressDir)
			return err == nil && l.Allowed("proxy", agent, taskenv.GoProxyEntry)
		},
		Private: func(agent string) string {
			p, err := taskenv.ReadGoPrivate(resolve.EgressDir, agent)
			if err != nil {
				log.Printf("cache: agent %s: go.private: %v: every path is private", agent, err)
				return "*" // fail closed: a pattern every module path matches
			}
			return p
		},
	})
	s.Conn = (&proxy.Server{Egress: resolve.EgressDir, Dial: proxy.Pinned(proxyResolveSock), Taint: send, Cache: cache}).Serve
	s.Purge, s.Revoked = cache.Purge, cache.Revoke
	if err := cache.Open(cacheAgents()...); err != nil { // the start sweep
		log.Printf("cache: %v", err)
	}
	go func() { // idle eviction: local work, no network
		for {
			if err := cache.Nightly(cacheAgents()...); err != nil {
				log.Printf("cache nightly: %v", err)
			}
			time.Sleep(24 * time.Hour)
		}
	}()
	if l, err := lineCall(proxyResolveSock, map[string]any{"op": "task.list_live"}, proxyListLiveWait); err != nil {
		log.Printf("task.list_live: %v: no task sockets rebound", err)
	} else if err := s.Rebind(l); err != nil {
		log.Print(err)
	}
	sdNotify("READY=1")
	return s.ServeControl(ctl)
}

// cacheLimits are the cache's budgets.toml keys (App. E), read at each fill as keys and git read theirs.
func cacheLimits() (gocache.Limits, error) {
	b, err := budgets.Read(budgets.Path)
	if err != nil {
		return gocache.Limits{}, err
	}
	lim := gocache.DefaultLimits()
	lim.AgentMaxBytes = b.Get("cache.agent_max_bytes")
	lim.TaskFillMaxBytes = b.Get("cache.task_fill_max_bytes")
	lim.TaskFillMaxFiles = int(b.Get("cache.task_fill_max_files"))
	lim.AgentFillDayBytes = b.Get("cache.agent_fill_day_bytes")
	lim.MaxIdleDays = int(b.Get("cache.max_idle_days"))
	lim.ReserveBytes = b.Get("disk.reserve_bytes")
	return lim, nil
}

// cacheAgents are the agents whose lists hold proxy.golang.org:443, the only ones whose stores can fill: data/cache is
// root-owned 0711, so the proxy can't list it. A deputy host is never in common.list (§6.2).
func cacheAgents() []string {
	l, err := resolve.LoadLists(resolve.EgressDir)
	if err != nil {
		log.Printf("cache: allowlists: %v", err)
		return nil
	}
	var out []string
	for a := range l.Agent {
		if l.Allowed("proxy", a, taskenv.GoProxyEntry) {
			out = append(out, a)
		}
	}
	return out
}
