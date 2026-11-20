// Package rootd is agentbox-rootd (ARCHITECTURE.md §2, §5.2), the root executor. The week-3 skeleton holds the state
// store, the systemd-activated sockets with their peer checks, the resolver that fills the broker destination sets
// (§6.1, §6.3, Appendix B) and audit segment creation and sealing (§9). Pending ops, the floor and the task registry
// come in later weeks on the same sockets and store.
package rootd

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"agentbox/internal/audit"
	"agentbox/internal/fw"
	"agentbox/internal/rootd/nl"
	"agentbox/internal/rootd/resolve"

	_ "modernc.org/sqlite"
)

// Config is rootd's command line (agentbox rootd).
type Config struct {
	DB             string        // rootd.db
	EgressDir      string        // control/egress
	AuditDir       string        // audit/
	ElementTimeout time.Duration // dst set element timeout (Appendix B: 10 min)
	RefillInterval time.Duration // timer refill and ntfy_dst refresh (§6.1: 5 min)
	AuditSocket    string        // auditd's rootd producer socket, for DENY records
	SealCrash      func(string)  // audit.Files' crash-mid-seal test hook (AGENTBOX_TEST_CRASH); nil in production
}

// Socket names: each .socket unit sets FileDescriptorName= to one of these.
const (
	sockAdmin = "admin"
	sockSeal  = "audit-seal" // auditd's audit-seal.sock: audit.create and audit.seal (audit.SealClient)
)

// OpenDB opens rootd.db with WAL and synchronous=FULL (§2, App. E) and creates the week-3 tables.
func OpenDB(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout(10000)&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer; every transaction is BEGIN IMMEDIATE
	var mode string
	var syncv int
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		db.Close()
		return nil, err
	}
	if err := db.QueryRow(`PRAGMA synchronous`).Scan(&syncv); err != nil {
		db.Close()
		return nil, err
	}
	if mode != "wal" || syncv != 2 {
		db.Close()
		return nil, fmt.Errorf("rootd.db: journal_mode=%s synchronous=%d, need wal and FULL (2)", mode, syncv)
	}
	if _, err := db.Exec(resolve.Schema); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func lookupUID(name string) (uint32, bool) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseUint(u.Uid, 10, 32)
	return uint32(n), err == nil
}

func lookupGID(name string) (uint32, bool) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseUint(g.Gid, 10, 32)
	return uint32(n), err == nil
}

// approveNotAdmin is §2.1's start check: agentbox-approve is never a member of agentbox-admin.
func approveNotAdmin() error {
	u, err := user.Lookup("agentbox-approve")
	if err != nil {
		return nil // no approvald yet: nothing to check
	}
	g, ok := lookupGID("agentbox-admin")
	if !ok {
		return nil
	}
	ids, err := u.GroupIds()
	if err != nil {
		return fmt.Errorf("agentbox-approve's groups: %v", err)
	}
	if slices.Contains(ids, strconv.Itoa(int(g))) {
		return errors.New("agentbox-approve is a member of agentbox-admin: refusing to start (§2.1)")
	}
	return nil
}

// Run is agentbox-rootd.service (Type=notify): check, open the store, make the dst sets match it, serve the
// activated sockets, and only then send READY=1.
func Run(cfg Config) error {
	if err := approveNotAdmin(); err != nil {
		return err
	}
	lns, err := listeners()
	if err != nil {
		return err
	}
	db, err := OpenDB(cfg.DB)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	da := newDenyAudit(func(r map[string]any) { sendDeny(cfg.AuditSocket, r) })
	go da.run(ctx)
	svc := &resolve.Service{
		DB: db, Dir: cfg.EgressDir, Resolver: resolve.Varlink{Path: resolve.ResolvedSocket},
		Route: nl.CheckRoute, Nft: resolve.Nft{Path: "nft"}, Flows: nl.DeleteFlows,
		Now: time.Now, Timeout: cfg.ElementTimeout, Pref64: resolve.Networkd{Path: resolve.NetworkdSocket}.Pref64,
		Deny: func(svc, entry, reason, detail string) {
			log.Printf("DENY by=rootd svc=%s entry=%s code=%s detail=%q", svc, entry, reason, detail)
			if !da.deny(svc, entry, reason, detail) {
				log.Printf("DENY not audited: queue full")
			}
		},
	}
	if err := fw.RecordFixed(db); err != nil { // the fixed port_allow rows, before the refill puts them in the set
		return fmt.Errorf("port_allow rows: %v", err)
	}
	res, err := refill(db, svc)
	if err != nil {
		return fmt.Errorf("sets do not match rootd.db: %v", err)
	}
	log.Printf("sets match rootd.db: %d live elements re-added, %d revoked, %d expired, %d unknown removed",
		res.Added, res.Revoked, res.Expired, res.Extra)

	auid, aok := lookupUID("agentbox-audit")
	agid, gok := lookupGID("agentbox-audit")
	if !aok || !gok {
		return errors.New("no agentbox-audit user or group (sysusers.d/agentbox.conf)")
	}
	s := &server{cfg: cfg, db: db, svc: svc, seal: &audit.Files{Dir: cfg.AuditDir, UID: int(auid), GID: int(agid), Crash: cfg.SealCrash}}
	for name, ln := range lns {
		go s.accept(name, ln)
	}
	if err := notify("READY=1\nSTATUS=sets match rootd.db"); err != nil {
		return err
	}
	s.refresh(ctx) // ntfy_dst at start, then on the timer
	t := time.NewTicker(cfg.RefillInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			for _, ln := range lns {
				ln.Close()
			}
			return nil
		case <-t.C:
			if res, err := refill(db, svc); err != nil {
				log.Printf("timer refill: %v", err)
			} else if res != (resolve.RefillResult{Added: res.Added}) {
				log.Printf("timer refill: %+v", res)
			}
			s.refresh(ctx)
		}
	}
}

// refill makes every set rootd fills match rootd.db: the exact sets (fw.Refill), then the dst sets.
func refill(db *sql.DB, svc *resolve.Service) (resolve.RefillResult, error) {
	if err := fw.Refill(db); err != nil {
		return resolve.RefillResult{}, fmt.Errorf("port_allow, allow_private4/6: %v", err)
	}
	return svc.Refill()
}

type server struct {
	cfg  Config
	db   *sql.DB
	svc  *resolve.Service
	seal audit.Sealer
}

// refresh re-resolves ntfy.sh:443 into ntfy_dst (§6.1). A failure only logs: ntfy is down until the next try.
func (s *server) refresh(ctx context.Context) {
	if _, _, err := s.svc.Resolve(ctx, "ntfy", "", resolve.NtfyEntry); err != nil {
		log.Printf("ntfy_dst refresh: %v", err)
	}
}

// sendDeny is a best-effort DENY record on auditd's rootd producer socket (§9): a refusal is not an effect, so
// nothing waits on its ACK, and the journal line above stays the fallback when auditd is down.
func sendDeny(sock string, rec map[string]any) {
	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		log.Printf("DENY not audited: %v", err)
		return
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	b, _ := json.Marshal(rec)
	if _, err := c.Write(append(b, '\n')); err != nil {
		log.Printf("DENY not audited: %v", err)
		return
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	var rep audit.Reply
	if err != nil || json.Unmarshal(line, &rep) != nil || !rep.OK {
		log.Printf("DENY not audited: %v %s", err, bytes.TrimSpace(line))
	}
}

// notify sends sd_notify state to $NOTIFY_SOCKET.
func notify(state string) error {
	p := os.Getenv("NOTIFY_SOCKET")
	if p == "" {
		return nil
	}
	if p[0] == '@' {
		p = "\x00" + p[1:]
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: p, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write([]byte(state))
	return err
}

type request struct {
	Op       string `json:"op"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Task     string `json:"task,omitempty"`
	Svc      string `json:"svc,omitempty"`
	Entry    string `json:"entry,omitempty"`
	Call     string `json:"call,omitempty"` // audit-seal.sock: auditd's audit.create or audit.seal
	Seg      uint64 `json:"seg,omitempty"`
	LastHash string `json:"last_hash,omitempty"`
}

type reply map[string]any

func fail(reason string) reply { return reply{"ok": false, "reason": reason} }

func (s *server) handle(sock string, r request) reply {
	switch {
	case sock == sockSeal:
		err := fmt.Errorf("unknown call %q", r.Call)
		switch r.Call {
		case "audit.create":
			err = s.seal.Create(r.Seg)
		case "audit.seal":
			err = s.seal.Seal(r.Seg, r.LastHash)
		}
		if err != nil {
			log.Printf("audit seal: %s %d: %v", r.Call, r.Seg, err)
			return reply{"ok": false, "error": err.Error()}
		}
		return reply{"ok": true}
	case sock == sockAdmin:
		return s.admin(r)
	case len(sock) > 8 && sock[:8] == "resolve-" && r.Op == "resolve":
		svc := sock[8:]
		e, err := resolve.ParseEntry(r.Host + ":" + strconv.Itoa(r.Port))
		if err != nil {
			return fail(resolve.NotAllowlisted) // a name no list can hold
		}
		addrs, exp, err := s.svc.Resolve(context.Background(), svc, r.Task, e)
		if err != nil {
			var rf *resolve.Refused
			if errors.As(err, &rf) {
				return fail(rf.Reason)
			}
			return fail(resolve.Unavailable)
		}
		out := make([]string, len(addrs))
		for i, a := range addrs {
			out[i] = a.String()
		}
		return reply{"ok": true, "addrs": out, "expires_at": exp.UnixMilli()}
	}
	return fail("bad_request")
}

func (s *server) admin(r request) reply {
	switch r.Op {
	case "egress.allow", "egress.remove":
		e, err := resolve.ParseEntry(r.Entry)
		if err != nil {
			return reply{"ok": false, "error": err.Error()}
		}
		changed, err := resolve.EditList(s.cfg.EgressDir, r.Svc, e, r.Op == "egress.allow")
		if err != nil {
			return reply{"ok": false, "error": err.Error()}
		}
		rep := s.refill(r)
		rep["changed"] = changed
		return rep
	case "sets.refill":
		return s.refill(r)
	case "egress.list":
		l, err := resolve.LoadLists(s.cfg.EgressDir)
		if err != nil {
			return reply{"ok": false, "error": err.Error()}
		}
		ans, err := s.svc.Entries()
		if err != nil {
			return reply{"ok": false, "error": err.Error()}
		}
		return reply{"ok": true, "lists": l, "answers": ans}
	}
	return fail("bad_request")
}

// refill is the notify path: an allowlist change or an admin refill runs it at once, not at the next timer tick.
func (s *server) refill(r request) reply {
	res, err := refill(s.db, s.svc)
	if err != nil {
		return reply{"ok": false, "error": err.Error()}
	}
	log.Printf("%s %s %s: %+v", r.Op, r.Svc, r.Entry, res)
	return reply{"ok": true, "refill": res}
}

func encode(r reply) []byte { b, _ := json.Marshal(r); return append(b, '\n') }
