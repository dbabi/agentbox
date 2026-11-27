package rootd

import (
	"fmt"
	"log"
	"regexp"
	"slices"
	"strings"
	"time"

	"agentbox/internal/audit"
	"agentbox/internal/git"
	"agentbox/internal/ids"
	"agentbox/internal/ops"
	"agentbox/internal/rootd/resolve"
)

// sockGate is rootd.sock: agentboxd's forwarded task ops (§2.1, §5.2), uid agentbox only.
const sockGate = "rootd"

// Effect runs one op after its INTENT is ACKed. outputs takes the op's Out classes in RESULT.
type Effect func(opID string, args map[string]any) (outputs map[string]any, err error)

var (
	taskRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	agentRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	// a chain member is an ancestor task id or rootd's provenance: human:<name>, agent:<agent> (§4.2), as the gate checks
	chainRe = regexp.MustCompile(`^([A-Za-z0-9_-]{1,64}|(human|agent):[a-z_][a-z0-9_.-]{0,31})$`)
)

// maxChain is the longest chain rootd derives: the human, the first agent and one agent per hop, at most 4 (§7 Limits).
const maxChain = 6

// deny logs and returns a floor denial (§5.6). rule says why, for the journal only: an agent sees a rule only from
// Cedar (leak rule 5), and a BUSY never names its reason (leak rule 6).
func deny(d ops.Denial, rule string) reply {
	log.Printf("DENY by=floor op=%s code=%s rule=%s id=%s", d.Op, d.Code, rule, d.ID)
	return reply{"ok": false, "denial": d}
}

// floor is the floor's denial of code on op, with no other slot.
func floor(c ops.Code, what, op string) ops.Denial {
	return ops.Deny(c, what, ops.Slots{Op: op, By: "floor"})
}

// taskOp is §5.2's rootd half for a forwarded op: rootd checks the request against the registry itself (it never
// trusts agentboxd's check), then INTENT with the audit classes applied, auditd's ACK, the effect, RESULT. Nothing runs
// without the ACK.
//
// shortcut: no chain check, binding, floor or pending P yet, and the op is not checked against task_registry; rootd
// takes agentboxd's task, agent and chain as given (the §5.2 compromise bound) and runs only ops that have an Effect.
// Check the task's live row here once every gate registration comes from task.start (`agentbox gate register` skips it).
func (s *server) taskOp(r request) reply {
	receipt := time.Now()
	// UNKNOWN_OP is the gate's code (§5.6), so an op the floor never runs here, one the gate should have refused or one
	// with no effect yet, is FLOOR_NEVER{never_available}.
	o, ok := ops.Lookup(r.Name)
	if !ok || !o.AgentCallable() || !o.Rootd {
		return deny(floor(ops.FloorNever, "never_available", ""), "floor.unknown_op")
	}
	// the chain goes into the INTENT next to them (#222)
	badMember := func(m string) bool { return !chainRe.MatchString(m) }
	if !taskRe.MatchString(r.Task) || !agentRe.MatchString(r.Agent) || len(r.Chain) > maxChain || slices.ContainsFunc(r.Chain, badMember) {
		return deny(floor(ops.InvalidArgs, "", o.Name), "floor.provenance")
	}
	args, aerr := o.ValidateArgs(r.Args)
	if aerr != nil {
		return deny(aerr.Denial(o.Name, "floor"), "floor.schema")
	}
	if rep := s.fenceDeny(o.Name); o.Class != ops.Read && rep != nil {
		return rep
	}
	// an LLM vendor host is never on a proxy list: its route is keys (§6.2, C-G3)
	if h, _ := args["host"].(string); o.Name == "net.allow_domain" && slices.Contains(resolve.VendorHosts, strings.TrimSuffix(strings.ToLower(h), ".")) {
		return deny(floor(ops.FloorNever, "vendor_host", o.Name), "floor.vendor_host")
	}
	if pendingOps[o.Name] && s.tasks != nil {
		return s.submit(o, r, args, receipt) // a remote write or merge waits for a human (§5.3)
	}
	eff := s.cfg.Effects[o.Name]
	if eff == nil && o.Name == "repo.create" && s.tasks != nil {
		if name, _ := args["name"].(string); !git.ValidProject(name) {
			return deny(ops.Deny(ops.InvalidArgs, "", ops.Slots{Op: o.Name, By: "floor", Subject: ops.Subject{Pointer: "/name"}, Expect: "valid"}), "floor.repo_name")
		}
		eff = s.repoCreate(r.Task, r.Agent)
	}
	if eff == nil {
		return deny(floor(ops.FloorNever, "never_available", o.Name), "floor.not_built")
	}
	logged := ops.Classify(o.Args, args)
	if s.cfg.RawAudit {
		logged = args // AGENTBOX_TEST_AUDIT_RAW: a producer that forgot its classes; the sink must NACK it
	}
	id := ids.New(ids.Op)
	chain := r.Chain
	if chain == nil {
		chain = []string{}
	}
	if err := s.audit(map[string]any{"type": "INTENT", "opId": id, "name": o.Name, "origin": "gate", "args": logged,
		"agent": r.Agent, "task": r.Task, "chain": chain, "taintEpochs": map[string]int64{}, "ts": time.Now().UnixMilli()}); err != nil {
		log.Printf("%s %s task %s: INTENT not ACKed, nothing ran: %v", id, o.Name, r.Task, err)
		if nack, ok := err.(*auditNACK); ok && nack.code == audit.CodeBadRecord {
			return deny(floor(ops.EffectFailed, "", o.Name), "audit.bad_record") // a rootd bug: a human must look
		}
		return deny(floor(ops.AuditUnavailable, "", o.Name), "audit.no_ack")
	}
	out, err := eff(id, args)
	res := map[string]any{"type": "RESULT", "opId": id, "status": "executed"}
	if err != nil {
		log.Printf("%s %s task %s: effect failed: %v", id, o.Name, r.Task, err)
		res["status"], res["errorCode"] = "failed", ops.EffectFailed.String()
	} else if out != nil {
		res["outputs"] = ops.Classify(o.Out, out)
	}
	if aerr := s.audit(res); aerr != nil {
		// §5.2: an op is executed only once its RESULT is ACKed, so the agent is not told ok.
		// shortcut: no rootd.db executing row yet, so nothing retries the RESULT; a human reconciles the op id from this
		// line until weeks 9-10's executing rows do it at restart.
		log.Printf("%s %s task %s: effect ran (err %v) but RESULT not ACKed: %v", id, o.Name, r.Task, err, aerr)
		return deny(floor(ops.EffectFailed, "", o.Name), "audit.result_unacked")
	}
	if err != nil {
		return deny(floor(ops.EffectFailed, "", o.Name), "floor.effect")
	}
	rep := reply{"ok": true, "opId": id}
	if out != nil {
		rep["result"] = out
	}
	return rep
}

// auditNACK is a reply from auditd that is not an ACK.
type auditNACK struct{ code, detail string }

func (e *auditNACK) Error() string { return fmt.Sprintf("NACK %s %s", e.code, e.detail) }

// repoCreate is repo.create's effect (Safe, §5.3): agentbox-git makes the task's agent a local bare repo. The agent
// comes from rootd's own registry row, never from the request.
func (s *server) repoCreate(task, claimed string) Effect {
	return func(_ string, args map[string]any) (map[string]any, error) {
		agent, live, _, err := s.taskAgent(task)
		if err != nil || !live || agent != claimed {
			return nil, fmt.Errorf("task %s is not live for agent %s", task, claimed)
		}
		name, _ := args["name"].(string)
		if !git.ValidProject(name) {
			return nil, fmt.Errorf("bad repo name")
		}
		_, err = s.gitOK(map[string]any{"call": "repo.create", "agent": agent, "project": name}, time.Minute)
		return nil, err
	}
}
