package rootd

import (
	"fmt"
	"log"
	"regexp"
	"time"

	"agentbox/internal/audit"
	"agentbox/internal/denial"
	"agentbox/internal/ops"
)

// sockGate is rootd.sock: agentboxd's forwarded task ops (§2.1, §5.2), uid agentbox only.
const sockGate = "rootd"

// Effect runs one op after its INTENT is ACKed. outputs takes the op's Out classes in RESULT.
type Effect func(opID string, args map[string]any) (outputs map[string]any, err error)

var (
	taskRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	agentRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
)

func deny(code denial.Code, rule, op, field, expect string) reply {
	d := denial.New(code, "floor", rule, op, field, expect)
	log.Printf("DENY by=floor op=%s code=%s rule=%s id=%s", d.Op, d.Code, d.Rule, d.ID)
	return reply{"ok": false, "denial": d}
}

// taskOp is §5.2's rootd half for a forwarded op: rootd checks the request against the registry itself (it never
// trusts agentboxd's check), then INTENT with the audit classes applied, auditd's ACK, the effect, RESULT. Nothing runs
// without the ACK.
//
// shortcut: no chain check, binding, floor or pending P yet, and the op is not checked against task_registry; rootd
// takes agentboxd's task, agent and chain as given (the §5.2 compromise bound) and runs only ops that have an Effect.
// Check the task's live row here once every gate registration comes from task.start (`agentbox gate register` skips it).
func (s *server) taskOp(r request) reply {
	o, ok := ops.Lookup(r.Name)
	if !ok || !o.AgentCallable() || !o.Rootd {
		return deny(denial.UnknownOp, "floor.unknown_op", r.Name, "", "")
	}
	if !taskRe.MatchString(r.Task) || !agentRe.MatchString(r.Agent) {
		return deny(denial.InvalidArgs, "floor.provenance", r.Name, "", "")
	}
	args, aerr := o.ValidateArgs(r.Args)
	if aerr != nil {
		return deny(denial.InvalidArgs, "floor.schema", r.Name, aerr.Field, aerr.Expect)
	}
	eff := s.cfg.Effects[o.Name]
	if eff == nil {
		return deny(denial.UnknownOp, "floor.not_built", r.Name, "", "")
	}
	logged := ops.Classify(o.Args, args)
	if s.cfg.RawAudit {
		logged = args // AGENTBOX_TEST_AUDIT_RAW: a producer that forgot its classes; the sink must NACK it
	}
	id := denial.NewID("op")
	chain := r.Chain
	if chain == nil {
		chain = []string{}
	}
	if err := s.audit(map[string]any{"type": "INTENT", "opId": id, "name": o.Name, "origin": "gate", "args": logged,
		"agent": r.Agent, "task": r.Task, "chain": chain, "taintEpochs": map[string]int64{}, "ts": time.Now().UnixMilli()}); err != nil {
		log.Printf("%s %s task %s: INTENT not ACKed, nothing ran: %v", id, o.Name, r.Task, err)
		if nack, ok := err.(*auditNACK); ok && nack.code == audit.CodeBadRecord {
			return deny(denial.EffectFailed, "audit.bad_record", o.Name, "", "") // a rootd bug: a human must look
		}
		return deny(denial.AuditUnavailable, "audit.no_ack", o.Name, "", "")
	}
	out, err := eff(id, args)
	res := map[string]any{"type": "RESULT", "opId": id, "status": "executed"}
	if err != nil {
		log.Printf("%s %s task %s: effect failed: %v", id, o.Name, r.Task, err)
		res["status"], res["errorCode"] = "failed", string(denial.EffectFailed)
	} else if out != nil {
		res["outputs"] = ops.Classify(o.Out, out)
	}
	if aerr := s.audit(res); aerr != nil {
		// §5.2: an op is executed only once its RESULT is ACKed, so the agent is not told ok.
		// shortcut: no rootd.db executing row yet, so nothing retries the RESULT; a human reconciles the op id from this
		// line until weeks 9-10's executing rows do it at restart.
		log.Printf("%s %s task %s: effect ran (err %v) but RESULT not ACKed: %v", id, o.Name, r.Task, err, aerr)
		return deny(denial.EffectFailed, "audit.result_unacked", o.Name, "", "")
	}
	if err != nil {
		return deny(denial.EffectFailed, "floor.effect", o.Name, "", "")
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
