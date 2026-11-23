package rootd

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"strconv"
	"time"

	"agentbox/internal/ops"
	"agentbox/internal/rootd/accounts"
	"agentbox/internal/rootd/attach"
	"agentbox/internal/rootd/quota"
)

// agentOp is the admin ops agent.add{name, diskBytes?} and agent.remove{name} (§4.1), checked against their registry
// schema, then INTENT, its ACK, the effect, RESULT (§9). add commits the ids row first, then the stores in qgroup 1/N,
// then the OS half; remove refuses NESTED_SUBVOLUME before anything, then retires the row and the OS half tears the
// account down and archives its subvolumes. A failure after the row leaves it for the next run or reconcile to repair.
func (s *server) agentOp(r request) reply {
	o, _ := ops.Lookup(r.Op)
	args, aerr := o.ValidateArgs(r.Args)
	if aerr != nil {
		return reply{"ok": false, "error": "args " + aerr.Error()}
	}
	name, _ := args["name"].(string)
	if !accounts.ValidName(name) {
		return reply{"ok": false, "error": "args /name: expected [a-z][a-z0-9-]{0,28}"}
	}
	var limit uint64
	if n, ok := args["diskBytes"].(json.Number); ok {
		v, err := strconv.ParseUint(n.String(), 10, 64)
		if err != nil || v < accounts.MinDisk {
			return reply{"ok": false, "error": "args /diskBytes: expected at least " + strconv.Itoa(accounts.MinDisk)}
		}
		limit = v
	}
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	if r.Op == "agent.remove" {
		a, err := accounts.Lookup(s.db, name)
		if err != nil {
			return reply{"ok": false, "error": err.Error()}
		}
		if rep := s.refuseNested(a); rep != nil {
			return rep
		}
	}
	id := newDenyID()
	if err := s.audit(map[string]any{"type": "INTENT", "opId": id, "name": r.Op, "origin": "admin", "args": ops.Classify(o.Args, args)}); err != nil {
		return reply{"ok": false, "error": "audit: the INTENT was not ACKed, nothing changed: " + err.Error()}
	}
	var a accounts.Agent
	var err error
	if r.Op == "agent.add" {
		if a, err = accounts.Add(s.db, name, time.Now()); err == nil {
			if err = s.store(a, limit); err == nil {
				err = s.applyOS()
			}
		}
	} else if a, err = accounts.Retire(s.db, name, time.Now()); err == nil {
		s.forget(name)
		err = s.applyOS()
	}
	if err == nil && r.Op == "agent.add" && s.tasks != nil {
		if acct, lerr := s.tasks.cfg.Accounts.Lookup(name); lerr == nil {
			s.tasks.rescan(acct, 0, false) // #104: at creation; the first task scans again
		}
	}
	status, detail := "executed", ""
	if err != nil {
		status, detail = "failed", err.Error()
		log.Printf("%s %s: %v", r.Op, name, err)
	}
	aerr2 := s.audit(map[string]any{"type": "RESULT", "opId": id, "status": status, "detail": detail})
	if err != nil {
		return reply{"ok": false, "error": err.Error()}
	}
	rep := reply{"ok": true, "opId": id, "agent": map[string]any{"name": a.Name, "n": a.N, "uid": a.UID(), "subid": a.SubID(), "active": a.Active}}
	if aerr2 != nil {
		log.Printf("%s %s: RESULT not audited: %v", r.Op, name, aerr2)
		rep["ok"], rep["error"] = false, "the op ran, but its audit RESULT was not ACKed: "+aerr2.Error()
	}
	return rep
}

// forget drops rootd's name-keyed state of a retired agent, so a new agent of the same name (a new N, a fresh
// workspace) doesn't inherit its task block or token versions. A live attach keeps its block until its scan.
func (s *server) forget(name string) {
	if _, live := s.live.Load(name); live {
		return
	}
	if err := attach.Clear(s.db, name); err != nil {
		log.Printf("agent.remove %s: task block: %v", name, err)
	}
	if err := attach.ForgetBaseline(s.db, name); err != nil {
		log.Printf("agent.remove %s: control-path baseline: %v", name, err)
	}
	s.seen.Delete(name)
	s.watched.Delete(name)
}

// refuseNested is §4.1's check before removal: a subvolume nested in an agent subvolume would be missing from its
// archive and snapshots, so rootd refuses NESTED_SUBVOLUME, taints the workspace, and never deletes recursively.
func (s *server) refuseNested(a accounts.Agent) reply {
	for _, p := range []string{a.Workspace(), a.Storage(), a.SessionHome()} {
		nested, err := s.nested(p)
		if err != nil {
			return reply{"ok": false, "error": "nested subvolume check: " + err.Error()}
		}
		if len(nested) == 0 {
			continue
		}
		log.Printf("agent.remove %s: NESTED_SUBVOLUME in %s: %q", a.Name, p, nested)
		rep := reply{"ok": false, "code": ops.NestedSubvolume.String(), "error": p + " holds nested subvolumes; remove them by hand first",
			"nested": nested, "tainted": true}
		if err := s.audit(map[string]any{"type": "TAINT", "subject": accounts.WorkspaceSubject(a.Name, a.UID()), "source": "nested_subvolume"}); err != nil {
			log.Printf("agent.remove %s: workspace taint not ACKed: %v", a.Name, err)
			rep["tainted"] = false
		}
		return rep
	}
	return nil
}

// nestedIn is quota.Nested, except that a subvolume a half-made agent never got holds nothing.
func nestedIn(p string) ([]string, error) {
	if _, err := os.Lstat(p); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return quota.Nested(p)
}
