package main

import (
	"errors"
	"flag"
	"log"
	"time"

	"agentbox/internal/gate"
	"agentbox/internal/proxy"
	"agentbox/internal/rootd/resolve"
)

const (
	proxyDir          = "/run/agentbox-proxy"
	proxyResolveSock  = "/run/agentbox-rootd/resolve-proxy.sock"
	proxyAuditSock    = "/run/agentbox-audit/proxy.sock"
	proxyListLiveWait = 10 * time.Second
)

// cmdProxy is agentbox-proxy.service (§2, §6.2): the CONNECT egress of every task. svc-proxy.sock comes from its
// .socket unit; on rootd's register it binds the task's proxy.sock in the dir rootd made, and at start it rebinds
// rootd's live tasks, so a running task survives a proxy restart (§2.1).
func cmdProxy(args []string) error {
	if err := parse(flag.NewFlagSet("proxy", flag.ContinueOnError), args); err != nil {
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
	p := &proxy.Server{Egress: resolve.EgressDir, Dial: proxy.Pinned(proxyResolveSock), Taint: proxy.Audit(proxyAuditSock)}
	s := &gate.Server{Dir: proxyDir, Name: "proxy", Conn: p.Serve, Conns: proxy.MaxConns,
		AgentIDs: func(a string) (uint32, uint32, error) { return uidOf("ag-" + a) }}
	if l, err := lineCall(proxyResolveSock, map[string]any{"op": "task.list_live"}, proxyListLiveWait); err != nil {
		log.Printf("task.list_live: %v: no task sockets rebound", err)
	} else if err := s.Rebind(l); err != nil {
		log.Print(err)
	}
	sdNotify("READY=1")
	return s.ServeControl(ctl)
}
