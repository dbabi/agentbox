package rootd

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"time"

	"agentbox/internal/audit"
	"agentbox/internal/canary"
	"agentbox/internal/git"
	"agentbox/internal/ids"
	"agentbox/internal/ops"
)

// The pending ops of the git service (§5.2, §5.3): repo.push, gh.pr.create, gh.pr.comment, gh.issue.comment and
// repo.merge each need a human. rootd binds the op's immutable inputs, stores P and answers NEEDS_SIGNATURE; a human
// approves on rootd-admin.sock; rootd re-checks, writes INTENT, has agentbox-git run the effect once, and writes
// RESULT. After a restart it finds an effect whose INTENT has no RESULT through agentbox-git (the op marker for gh.*,
// the remote ref for repo.push) and never runs it again.
//
// shortcut: an approval is an agentbox-admin peer on rootd-admin.sock, not an SSHSIG over H (#24); no Cedar pass,
// push policy, batch, quote or ask grant yet (#22, #23). The task's own ask budget and the 3 open asks are enforced.
// #303 tracks moving the git service to them.

// Ask windows (§5.4): an ask expires 15 min after creation, and an approval must start executing within 15 min.
const (
	askTTL      = 15 * time.Minute
	approvalTTL = 15 * time.Minute
	maxOpen     = 3
)

// sigFloor and missFloor are the reply floors (§5.6 leak rules 3 and 5); vars, so tests can shorten them.
var (
	sigFloor  = 2 * time.Second
	missFloor = 200 * time.Millisecond
)

// pendingOps are the ops this release stores as P, by name.
var pendingOps = map[string]bool{"repo.push": true, "gh.pr.create": true, "gh.pr.comment": true, "gh.issue.comment": true, "repo.merge": true}

// pendingP is P's op column: the stored canonical request rootd executes (§5.2 Exact execution).
type pendingP struct {
	Name        string           `json:"name"`
	Args        map[string]any   `json:"args"`
	Agent       string           `json:"agent"`
	Task        string           `json:"task"`
	Chain       []string         `json:"chain"`
	TaintEpochs map[string]int64 `json:"taintEpochs"`
}

// floorAt holds a denial until its reply floor (§5.6) after receipt.
func floorAt(rep reply, receipt time.Time) reply {
	if d, ok := rep["denial"].(ops.Denial); ok {
		switch d.Code {
		case "NOT_FOUND_OR_NOT_OWNED":
			time.Sleep(time.Until(receipt.Add(missFloor)))
		case "NEEDS_SIGNATURE":
			time.Sleep(time.Until(receipt.Add(sigFloor)))
		}
	}
	return rep
}

func floorDeny(c ops.Code, what, op string, sub ops.Subject, expect string) reply {
	return deny(ops.Deny(c, what, ops.Slots{Op: op, By: "floor", Subject: sub, Expect: expect}), "floor.git")
}

// binding is what a binder fixes for P: the bound inputs, the args as stored (a gh.* body with its op marker), and
// the structural fields the match key hashes.
type binding struct {
	bound git.Bound
	args  map[string]any
	key   map[string]any
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func num(m map[string]any, k string) int64 {
	switch v := m[k].(type) {
	case json.Number:
		n, _ := v.Int64()
		return n
	case float64:
		return int64(v)
	}
	return 0
}

// sha is the hex SHA-256 of s.
func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// bind runs op's binder (§5.2, §5.3): owner-scoped lookups, the namespace and OID checks, the canary check of a gh.*
// body (#105), and the op marker appended to it. A non-nil reply refuses the op.
func (s *server) bind(name, task, agent, id string, args map[string]any) (binding, reply) {
	b := binding{args: map[string]any{}, key: map[string]any{}}
	for k, v := range args {
		b.args[k] = v
		if k != "title" && k != "body" {
			b.key[k] = v // structural: not the agent's free text
		}
	}
	// the canary first (#105): an attempt to send it out counts whatever else is wrong with the request
	if strings.HasPrefix(name, "gh.") {
		if c := s.canaryOf(task); canary.Scan([]byte(str(args, "title")+"\n"+str(args, "body")), c) {
			s.canaryHit(task, name)
			return b, deny(ops.Deny(ops.ExfilCanary, "", ops.Slots{Op: name, By: "floor"}), "floor.canary")
		}
	}
	miss := func() reply { return floorDeny(ops.NotFoundOrNotOwned, "", name, ops.Subject{}, "") }
	var rem remoteRow
	if name != "repo.merge" {
		var ok bool
		if rem, ok = s.remote(str(args, "remote"), agent); !ok {
			return b, miss()
		}
		b.bound = git.Bound{Remote: rem.ID, URL: rem.URL, NodeID: rem.NodeID, Visibility: rem.Visibility, Project: rem.Project}
	}
	check := func(project, oid, ref string) (map[string]any, reply) {
		rep, err := s.gitOK(map[string]any{"call": "repo.check", "agent": agent, "project": project, "oid": oid, "ref": ref}, time.Minute)
		if err != nil {
			log.Printf("%s task %s: repo.check: %v", name, task, err)
			return nil, deny(ops.Deny(ops.BrokerUnavailable, "git", ops.Slots{Op: name, By: "forwarder"}), "floor.git_unavailable")
		}
		return rep, nil
	}
	switch name {
	case "repo.push":
		ref, oid := str(args, "ref"), str(args, "oid")
		if !git.InNamespace(agent, ref) {
			return b, floorDeny(ops.RefOutsideNamespace, "", name, ops.Subject{Ref: ref}, "refs/heads/agent/<name>/*")
		}
		if !git.ValidOID(oid) {
			return b, floorDeny(ops.InvalidArgs, "", name, ops.Subject{Pointer: "/oid"}, "valid")
		}
		rep, d := check(rem.Project, oid, "")
		if d != nil {
			return b, d
		}
		if rep["contains"] != true {
			return b, floorDeny(ops.OidNotInRemoteRepo, "", name, ops.Subject{OID: oid}, "an OID pushed through :8082")
		}
		b.bound.OID, b.bound.Ref = oid, ref
	case "gh.pr.create":
		head := str(args, "head")
		if !git.InNamespace(agent, head) {
			return b, floorDeny(ops.RefOutsideNamespace, "", name, ops.Subject{Ref: head}, "refs/heads/agent/<name>/*")
		}
		base, ok := git.Branch(str(args, "base"))
		if !ok {
			return b, floorDeny(ops.InvalidArgs, "", name, ops.Subject{Pointer: "/base"}, "valid")
		}
		rep, d := check(rem.Project, "", head)
		if d != nil {
			return b, d
		}
		tip := str(rep, "tip")
		if !git.ValidOID(tip) {
			return b, floorDeny(ops.OidNotInRemoteRepo, "", name, ops.Subject{Ref: head}, "an OID pushed through :8082")
		}
		b.bound.OID, b.bound.Ref, b.bound.Base = tip, head, base
		b.key["head"], b.key["base"] = head, base
	case "gh.pr.comment", "gh.issue.comment":
		n := num(args, "number")
		if n < 1 {
			return b, floorDeny(ops.InvalidArgs, "", name, ops.Subject{Pointer: "/number"}, "valid")
		}
		b.bound.Number = n
	case "repo.merge":
		p, src, dst := str(args, "p"), str(args, "srcOid"), str(args, "dstOid")
		if !git.ValidProject(p) {
			return b, miss()
		}
		if !git.ValidOID(src) || !git.ValidOID(dst) {
			return b, floorDeny(ops.InvalidArgs, "", name, ops.Subject{Pointer: "/srcOid"}, "valid")
		}
		rep, d := check(p, src, "refs/heads/main")
		if d != nil {
			return b, d
		}
		if rep["exists"] != true {
			return b, miss()
		}
		if rep["contains"] != true {
			return b, floorDeny(ops.OidNotInRemoteRepo, "", name, ops.Subject{OID: src}, "an OID pushed through :8082")
		}
		if strings.Trim(dst, "0") == "" {
			dst = "" // main doesn't exist yet
		}
		if str(rep, "tip") != dst {
			return b, deny(ops.Deny(ops.Stale, "ref_moved", ops.Slots{Op: name, By: "floor", Subject: ops.Subject{OID: src}}), "floor.git")
		}
		b.bound = git.Bound{Project: p, SrcOID: src, DstOID: dst}
	}
	if strings.HasPrefix(name, "gh.") {
		body := str(args, "body")
		// §5.3 step 1: ValidateArgs refused a body holding agentbox-op:; the marker is rootd's, appended before H
		b.bound.Marker, b.bound.BodyHash = id, sha(body)
		b.args["body"] = body + git.Marker(id)
	}
	k := b.bound
	k.Marker = "" // the match key holds the body hash taken before the marker (§5.4 step 5), not the marker
	b.key["bound"] = k
	return b, nil
}

// submit stores P for one of pendingOps (§5.2) and answers NEEDS_SIGNATURE at receipt + 2 s. An open ask with the
// same match key in this task comes back instead of a new one; a key a human denied stays denied in this task; an
// executed remote write returns its stored result (§5.4 step 5).
func (s *server) submit(o ops.Op, r request, args map[string]any, receipt time.Time) reply {
	agent, live, _, err := s.taskAgent(r.Task)
	if err != nil || !live || agent != r.Agent {
		return deny(floor(ops.TaskEnded, "", o.Name), "floor.task")
	}
	id := ids.New(ids.Pending)
	b, rep := s.bind(o.Name, r.Task, agent, id, args)
	if rep != nil {
		return floorAt(rep, receipt)
	}
	tainted, epochs, err := s.effectiveTaint(r.Task)
	if err != nil {
		log.Printf("%s task %s: taint.get: %v", o.Name, r.Task, err)
		return deny(floor(ops.AuditUnavailable, "", o.Name), "audit.no_taint")
	}
	chain := r.Chain
	if chain == nil {
		chain = []string{}
	}
	now := time.Now().UnixMilli()
	exp := now + askTTL.Milliseconds()
	p := pendingP{Name: o.Name, Args: b.args, Agent: agent, Task: r.Task, Chain: chain, TaintEpochs: epochs}
	nb := make([]byte, 16)
	rand.Read(nb)
	nonce := hex.EncodeToString(nb)
	h := sha(string(canonJSON(map[string]any{"op": p, "bound": b.bound, "nonce": nonce, "expiresAt": exp})))
	key := sha(string(canonJSON(map[string]any{"op": o.Name, "args": b.key})))
	opJSON, boundJSON := canonJSON(p), canonJSON(b.bound)

	tx, err := s.db.Begin()
	if err != nil {
		return deny(floor(ops.EffectFailed, "", o.Name), "floor.db")
	}
	defer tx.Rollback()
	// one match key (§5.4 step 5), against this task's rows
	var prev, pstate string
	var preason, presult sql.NullString
	var pexp int64
	err = tx.QueryRow(`SELECT id, state, reason, result, expires_at FROM pending WHERE task=? AND match_key=? ORDER BY created_at DESC LIMIT 1`,
		r.Task, key).Scan(&prev, &pstate, &preason, &presult, &pexp)
	if err == nil {
		switch pstate {
		case "pending", "approved", "executing":
			tx.Rollback()
			return floorAt(s.needsSig(o.Name, prev, tainted, pexp, true, r.Task), receipt)
		case "denied":
			if preason.String == "ASK_DENIED" {
				return deny(ops.Deny(ops.AskDenied, "", ops.Slots{Op: o.Name, By: "floor", Pending: prev}), "floor.ask_denied")
			}
		case "executed":
			var res map[string]any
			json.Unmarshal([]byte(presult.String), &res)
			return reply{"ok": true, "opId": prev, "result": agentboxOutputs(res)}
		}
	}
	var budget, used, granted, open int
	if err := tx.QueryRow(`SELECT asks_budget, asks_used, asks_granted FROM task_registry WHERE task=?`, r.Task).Scan(&budget, &used, &granted); err != nil {
		return deny(floor(ops.TaskEnded, "", o.Name), "floor.task")
	}
	var openIDs []string
	rows, err := tx.Query(`SELECT id FROM pending WHERE task=? AND state IN ('pending','approved','executing') ORDER BY created_at`, r.Task)
	if err != nil {
		return deny(floor(ops.EffectFailed, "", o.Name), "floor.db")
	}
	for rows.Next() {
		var x string
		rows.Scan(&x)
		openIDs = append(openIDs, x)
	}
	rows.Close()
	open = len(openIDs)
	switch {
	case used+granted >= budget:
		return deny(ops.Deny(ops.AskCap, "task_budget", ops.Slots{Op: o.Name, By: "floor"}), "floor.ask_budget")
	case open >= maxOpen:
		return deny(ops.Deny(ops.AskCap, "task_open", ops.Slots{Op: o.Name, By: "floor", Open: openIDs}), "floor.ask_open")
	}
	if _, err := tx.Exec(`UPDATE task_registry SET asks_used=asks_used+1, asks_created=asks_created+1 WHERE task=?`, r.Task); err != nil {
		return deny(floor(ops.EffectFailed, "", o.Name), "floor.db")
	}
	if _, err := tx.Exec(`INSERT INTO pending(id, task, agent, op, bound, h, nonce, state, match_key, expires_at, created_at)
		VALUES(?,?,?,?,?,?,?,'pending',?,?,?)`, id, r.Task, agent, string(opJSON), string(boundJSON), h, nonce, key, exp, now); err != nil {
		log.Printf("%s task %s: pending row: %v", o.Name, r.Task, err)
		return deny(floor(ops.EffectFailed, "", o.Name), "floor.db")
	}
	if err := tx.Commit(); err != nil {
		return deny(floor(ops.EffectFailed, "", o.Name), "floor.db")
	}
	log.Printf("pending %s: %s by task %s (agent %s), tainted %v, expires %s", id, o.Name, r.Task, agent, tainted, time.UnixMilli(exp).UTC().Format(time.RFC3339))
	notified := false
	if s.cfg.Alert != nil {
		// a fixed template from P only (§5.4 phone flow step 1): op name, agent, ids
		notified = s.cfg.Alert("agentbox: ask from "+agent, o.Name+" by task "+r.Task+" waits for a human: agentbox approve "+id) == nil
	}
	return floorAt(s.needsSig(o.Name, id, tainted, exp, notified, r.Task), receipt)
}

// needsSig is the NEEDS_SIGNATURE for pending row id (§5.6 Asks).
func (s *server) needsSig(op, id string, tainted bool, exp int64, notified bool, task string) reply {
	reason := "signed"
	if tainted {
		reason = "tainted"
	}
	var budget, used, granted, open int64
	s.db.QueryRow(`SELECT asks_budget, asks_used, asks_granted FROM task_registry WHERE task=?`, task).Scan(&budget, &used, &granted)
	s.db.QueryRow(`SELECT count(*) FROM pending WHERE task=? AND state IN ('pending','approved','executing')`, task).Scan(&open)
	left := max(0, min(budget-used-granted, maxOpen-open))
	return deny(ops.Deny(ops.NeedsSignature, "", ops.Slots{Op: op, By: "floor", Reason: reason, Taint: &ops.Taint{Tainted: tainted}, Pending: id,
		ExpiresAt: &exp, Notified: &notified, AsksLeft: &left}), "floor.ask")
}

// agentboxOutputs is the part of an op's outputs agentbox generated (§5.3 Op outputs): ask.status and a resubmission
// return only these; GitHub's numbers and URLs stay in pending.result for humans.
func agentboxOutputs(res map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range []string{"remote", "oid", "headOid", "tainted"} {
		if v, ok := res[k]; ok {
			out[k] = v
		}
	}
	return out
}

// pendingRow is one row as the admin CLI sees it.
type pendingRow struct {
	ID        string          `json:"id"`
	Task      string          `json:"task"`
	Agent     string          `json:"agent"`
	Op        json.RawMessage `json:"op"`
	Bound     json.RawMessage `json:"bound"`
	H         string          `json:"h"`
	State     string          `json:"state"`
	Signer    string          `json:"signer,omitempty"`
	Reason    string          `json:"reason,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	ExpiresAt int64           `json:"expiresAt"`
	CreatedAt int64           `json:"createdAt"`
}

const pendingCols = `id, task, agent, op, bound, h, state, signer, reason, result, expires_at, created_at`

func scanPending(sc interface{ Scan(...any) error }) (pendingRow, error) {
	var p pendingRow
	var op, bound string
	var signer, reason, result sql.NullString
	err := sc.Scan(&p.ID, &p.Task, &p.Agent, &op, &bound, &p.H, &p.State, &signer, &reason, &result, &p.ExpiresAt, &p.CreatedAt)
	p.Op, p.Bound, p.Signer, p.Reason = json.RawMessage(op), json.RawMessage(bound), signer.String, reason.String
	if result.Valid {
		p.Result = json.RawMessage(result.String)
	}
	return p, err
}

// pendingAdmin answers pending.list, pending.get, pending.approve and pending.deny on rootd-admin.sock.
func (s *server) pendingAdmin(r request, signer string) reply {
	switch r.Op {
	case "pending.list":
		rows, err := s.db.Query(`SELECT ` + pendingCols + ` FROM pending WHERE state IN ('pending','approved','executing','indeterminate') ORDER BY created_at`)
		if err != nil {
			return reply{"ok": false, "error": err.Error()}
		}
		defer rows.Close()
		out := []pendingRow{}
		for rows.Next() {
			p, err := scanPending(rows)
			if err != nil {
				return reply{"ok": false, "error": err.Error()}
			}
			out = append(out, p)
		}
		return reply{"ok": true, "pending": out}
	case "pending.get":
		p, err := scanPending(s.db.QueryRow(`SELECT `+pendingCols+` FROM pending WHERE id=?`, r.ID))
		if err != nil {
			return reply{"ok": false, "error": "no pending op " + r.ID}
		}
		return reply{"ok": true, "pending": p}
	case "pending.deny":
		res, err := s.db.Exec(`UPDATE pending SET state='denied', reason='ASK_DENIED', signer=? WHERE id=? AND state IN ('pending','approved')`, signer, r.ID)
		if n, _ := res.RowsAffected(); err != nil || n != 1 {
			return reply{"ok": false, "error": "no open ask " + r.ID}
		}
		s.finalize(r.ID)
		log.Printf("pending %s: denied by %s", r.ID, signer)
		return reply{"ok": true, "id": r.ID, "state": "denied"}
	case "pending.approve":
		return s.approve(r.ID, signer)
	}
	return fail("bad_request")
}

// approve is the approval transaction (§5.2): the nonce used once, pending to approved only while unexpired; then the
// execution. A row left approved by a rootd crash executes on the next approve, within the 15 min window.
// shortcut: the signer is the admin's SO_PEERCRED user, not an SSHSIG over H (#24, #303).
func (s *server) approve(id, signer string) reply {
	now := time.Now().UnixMilli()
	tx, err := s.db.Begin()
	if err != nil {
		return reply{"ok": false, "error": err.Error()}
	}
	defer tx.Rollback()
	var state, nonce string
	if err := tx.QueryRow(`SELECT state, nonce FROM pending WHERE id=?`, id).Scan(&state, &nonce); err != nil {
		return reply{"ok": false, "error": "no pending op " + id}
	}
	if state == "pending" {
		if _, err := tx.Exec(`INSERT INTO used_nonces(nonce, used_at) VALUES(?,?)`, nonce, now); err != nil {
			return reply{"ok": false, "reason": "approval_stale", "error": "approval_stale: its nonce is used"}
		}
		res, err := tx.Exec(`UPDATE pending SET state='approved', signer=?, approved_at=? WHERE id=? AND state='pending' AND expires_at > ?`,
			signer, now, id, now)
		if n, _ := res.RowsAffected(); err != nil || n != 1 {
			return reply{"ok": false, "reason": "approval_stale", "error": "approval_stale: the ask expired or is no longer pending"}
		}
	} else if state == "executing" {
		// an effect whose outcome nothing recorded (agentbox-git was down, or rootd lost its reply): settle it by
		// inspection, never by running it again, unless this process is running it right now
		tx.Rollback()
		if _, busy := s.inflight.Load(id); busy {
			return reply{"ok": false, "id": id, "state": state, "error": "running now"}
		}
		return s.reconcileRow(id)
	} else if state != "approved" {
		return reply{"ok": false, "id": id, "state": state, "error": "not pending: " + state}
	}
	if err := tx.Commit(); err != nil {
		return reply{"ok": false, "error": err.Error()}
	}
	log.Printf("pending %s: approved by %s", id, signer)
	return s.execute(id)
}

// finish moves an executing or approved row to its final state, with its reason code and result, and applies the
// audit classes to P (§5.2 Plaintext lifetime).
func (s *server) finish(id, state, reason string, result map[string]any) {
	var res any
	if result != nil {
		res = string(canonJSON(result))
	}
	var rs any
	if reason != "" {
		rs = reason
	}
	if _, err := s.db.Exec(`UPDATE pending SET state=?, reason=?, result=? WHERE id=?`, state, rs, res, id); err != nil {
		log.Printf("pending %s: %s: %v", id, state, err)
	}
	s.finalize(id)
}

// finalize replaces a final row's hash-class args with {sha256, len} and drops its drop-class ones.
func (s *server) finalize(id string) {
	var op string
	if s.db.QueryRow(`SELECT op FROM pending WHERE id=?`, id).Scan(&op) != nil {
		return
	}
	var p pendingP
	if json.Unmarshal([]byte(op), &p) != nil {
		return
	}
	o, ok := ops.Lookup(p.Name)
	if !ok {
		return
	}
	p.Args = ops.Classify(o.Args, p.Args)
	s.db.Exec(`UPDATE pending SET op=? WHERE id=?`, string(canonJSON(p)), id)
}

// refusal is an execution that stops before its effect: the row ends refused with code, and the admin sees why.
func (s *server) refusal(id string, d ops.Denial, why string) reply {
	reason := d.Code
	if d.What != "" {
		reason += ":" + d.What
	}
	s.finish(id, "refused", reason, nil)
	log.Printf("pending %s: refused %s: %s", id, reason, why)
	return reply{"ok": false, "id": id, "state": "refused", "reason": reason, "error": why}
}

// execute runs an approved row (§5.2 execute): claim it, re-check what it was bound to, INTENT, the effect on
// agentbox-git, RESULT.
func (s *server) execute(id string) reply {
	now := time.Now().UnixMilli()
	res, err := s.db.Exec(`UPDATE pending SET state='executing' WHERE id=? AND state='approved' AND approved_at > ?`, id, now-approvalTTL.Milliseconds())
	if n, _ := res.RowsAffected(); err != nil || n != 1 {
		s.db.Exec(`UPDATE pending SET state='expired' WHERE id=? AND state='approved'`, id)
		return reply{"ok": false, "id": id, "state": "expired", "error": "the approval is older than 15 min, or the op is not approved"}
	}
	s.inflight.Store(id, true)
	defer s.inflight.Delete(id)
	row, err := scanPending(s.db.QueryRow(`SELECT `+pendingCols+` FROM pending WHERE id=?`, id))
	var p pendingP
	var b git.Bound
	if err != nil || json.Unmarshal(row.Op, &p) != nil || json.Unmarshal(row.Bound, &b) != nil {
		return s.refusal(id, floor(ops.EffectFailed, "", ""), "the stored P does not parse")
	}
	o, _ := ops.Lookup(p.Name)
	stale := func(what, why string) reply {
		return s.refusal(id, ops.Deny(ops.Stale, what, ops.Slots{Op: p.Name, By: "floor"}), why)
	}
	// the re-checks (§5.2): the task, the remotes row, GitHub's view of the repo, the bound commits
	if _, live, done, err := s.taskAgent(p.Task); err != nil || !live && !done {
		return s.refusal(id, floor(ops.TaskEnded, "", p.Name), "the task ended other than completed")
	}
	if p.Name != "repo.merge" {
		rem, ok := s.remote(b.Remote, p.Agent)
		if !ok || rem.URL != b.URL || rem.NodeID != b.NodeID || rem.Project != b.Project {
			return stale("remote_changed", "the remotes row changed since the op was bound")
		}
		rep, err := s.gitOK(map[string]any{"call": "remote.lookup", "url": b.URL}, 2*time.Minute)
		if err != nil {
			return s.refusal(id, ops.Deny(ops.RemoteRejected, whatOf(rep, "unreachable"), ops.Slots{Op: p.Name, By: "floor"}), "GitHub re-check: "+err.Error())
		}
		if rep["nodeId"] != b.NodeID || rep["visibility"] != b.Visibility {
			return stale("remote_changed", fmt.Sprintf("GitHub has node %v %v, bound %s %s", rep["nodeId"], rep["visibility"], b.NodeID, b.Visibility))
		}
	}
	switch p.Name {
	case "repo.push":
		rep, err := s.gitOK(map[string]any{"call": "repo.check", "agent": p.Agent, "project": b.Project, "oid": b.OID}, time.Minute)
		if err != nil || rep["contains"] != true {
			return s.refusal(id, ops.Deny(ops.OidNotInRemoteRepo, "", ops.Slots{Op: p.Name, By: "floor"}), fmt.Sprintf("the OID is in no branch now: %v", err))
		}
	case "gh.pr.create":
		rep, err := s.gitOK(map[string]any{"call": "remote.ref", "agent": p.Agent, "project": b.Project, "url": b.URL, "ref": b.Ref}, 2*time.Minute)
		if err != nil {
			return s.refusal(id, ops.Deny(ops.RemoteRejected, whatOf(rep, "unreachable"), ops.Slots{Op: p.Name, By: "floor"}), "head check: "+err.Error())
		}
		switch str(rep, "oid") {
		case b.OID:
		case "":
			return s.refusal(id, ops.Deny(ops.RemoteRejected, "no_commits", ops.Slots{Op: p.Name, By: "floor"}), "the head ref is not on the remote")
		default:
			return stale("ref_moved", "the remote head ref moved since the op was bound")
		}
	}
	intent := map[string]any{"type": "INTENT", "opId": id, "name": p.Name, "origin": "gate", "signer": row.Signer, "args": ops.Classify(o.Args, p.Args),
		"agent": p.Agent, "task": p.Task, "chain": p.Chain, "taintEpochs": p.TaintEpochs, "ts": time.Now().UnixMilli()}
	if s.cfg.RawAudit {
		intent["args"] = p.Args // AGENTBOX_TEST_AUDIT_RAW: the sink must NACK it
	}
	if err := s.audit(intent); err != nil {
		var nack *auditNACK
		if errors.As(err, &nack) && nack.code == audit.CodeStale {
			return stale("taint_moved", "a taint epoch moved since the op was bound")
		}
		return s.refusal(id, floor(ops.AuditUnavailable, "", p.Name), "INTENT not ACKed: "+err.Error())
	}
	// the effect, once: agentbox-git refuses an id it already started
	rep, err := s.git(map[string]any{"call": "exec", "id": id, "name": p.Name, "agent": p.Agent, "task": p.Task, "args": p.Args, "bound": b}, 15*time.Minute)
	if err != nil {
		// whether the effect ran is unknown: reconcile decides, now and after any restart, and never runs it again
		log.Printf("pending %s: exec: %v: reconciling", id, err)
		return s.reconcileRow(id)
	}
	if rep["ok"] != true {
		var d ops.Denial
		switch {
		case rep["stale"] != nil:
			d = ops.Deny(ops.Stale, str(rep, "stale"), ops.Slots{Op: p.Name, By: "floor"})
		case rep["what"] != nil:
			d = ops.Deny(ops.RemoteRejected, str(rep, "what"), ops.Slots{Op: p.Name, By: "floor"})
		default:
			d = floor(ops.EffectFailed, "", p.Name)
		}
		// GitHub's and git's text goes to the DENY detail and the journal, never to the task (§6.3)
		detail := trunc(fmt.Sprint(rep["detail"], rep["error"]), 1024)
		s.denyRecord(d, p.Task, p.Agent, detail)
		return s.result(id, p, "failed", d, nil, detail)
	}
	out, _ := rep["outputs"].(map[string]any)
	return s.result(id, p, "executed", ops.Denial{}, out, "")
}

// whatOf is the REMOTE_REJECTED what agentbox-git named, or def.
func whatOf(rep map[string]any, def string) string {
	if w := str(rep, "what"); w != "" {
		return w
	}
	return def
}

// result writes RESULT and the row's final state. A RESULT auditd didn't ACK leaves the row executing: reconcile
// writes it after the next restart.
func (s *server) result(id string, p pendingP, status string, d ops.Denial, out map[string]any, detail string) reply {
	o, _ := ops.Lookup(p.Name)
	rec := map[string]any{"type": "RESULT", "opId": id, "status": status}
	reason := ""
	if d.Code != "" {
		reason = d.Code
		if d.What != "" {
			reason += ":" + d.What
		}
		rec["errorCode"] = d.Code
	}
	if out != nil {
		rec["outputs"] = ops.Classify(o.Out, out)
	}
	if err := s.audit(rec); err != nil {
		log.Printf("pending %s: the effect ended %s, but RESULT was not ACKed: %v; reconcile writes it at the next start", id, status, err)
		return reply{"ok": false, "id": id, "state": "executing", "error": "the effect ended " + status + ", but auditd did not ACK its RESULT"}
	}
	s.finish(id, status, reason, out)
	log.Printf("pending %s: %s %s %s", id, p.Name, status, reason)
	if status == "executed" {
		return reply{"ok": true, "id": id, "state": status, "result": out}
	}
	return reply{"ok": false, "id": id, "state": status, "reason": reason, "error": detail}
}

// denyRecord sends a floor DENY record (§9), unwaited.
func (s *server) denyRecord(d ops.Denial, task, agent, detail string) {
	now := time.Now().UnixMilli()
	r := map[string]any{"type": "DENY", "id": d.ID, "code": d.Code, "by": d.By, "op": d.Op, "task": task, "agent": agent, "count": 1,
		"first": now, "last": now, "detail": trunc(detail, 1024)}
	if d.What != "" {
		r["what"] = d.What
	}
	go func() {
		if err := s.audit(r); err != nil {
			log.Printf("DENY not audited: %v", err)
		}
	}()
}

// opState is auditd's record of op id (op.get): no INTENT, an INTENT alone, or its RESULT's status.
func (s *server) opState(id string) (intent bool, status string, err error) {
	q := s.auditQ
	if q == nil {
		q = func(r map[string]any) (map[string]any, error) { return auditCall(s.cfg.AuditSocket, r) }
	}
	rep, err := q(map[string]any{"type": "op.get", "opId": id})
	if err != nil {
		return false, "", err
	}
	if rep["ok"] != true {
		return false, "", fmt.Errorf("op.get: %v", rep["code"])
	}
	o, _ := rep["op"].(map[string]any)
	if o == nil {
		return false, "", nil
	}
	st, _ := o["status"].(string)
	return true, st, nil
}

// reconcileStart is recovery's first pass (§5.2), before rootd listens: every approved row past its window expires,
// every executing row with no INTENT is refused (nothing ran), and one with a RESULT takes its state. A row with an
// INTENT and no RESULT needs agentbox-git, which starts after rootd, so reconcileBrokers finishes it.
func (s *server) reconcileStart() {
	now := time.Now().UnixMilli()
	s.db.Exec(`UPDATE pending SET state='expired' WHERE (state='approved' AND approved_at <= ?) OR (state='pending' AND expires_at <= ?)`,
		now-approvalTTL.Milliseconds(), now)
	for _, id := range s.pendingIDs("executing") {
		intent, status, err := s.opState(id)
		switch {
		case err != nil:
			log.Printf("pending %s: op.get: %v: left executing", id, err)
		case !intent:
			s.finish(id, "refused", "BUSY", nil) // rootd stopped between the claim and the INTENT: nothing ran
			log.Printf("pending %s: no INTENT: refused", id)
		case status != "":
			s.finish(id, status, "", nil)
			log.Printf("pending %s: RESULT %s found", id, status)
		}
	}
}

func (s *server) pendingIDs(state string) []string {
	rows, err := s.db.Query(`SELECT id FROM pending WHERE state=? ORDER BY created_at`, state)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		out = append(out, id)
	}
	return out
}

// reconcileBrokers is recovery's second pass, once rootd is ready: each executing row's effect is found through
// agentbox-git, waiting for the service if it is not up yet, and the RESULT written.
func (s *server) reconcileBrokers() {
	for _, id := range s.pendingIDs("executing") {
		for try := 0; ; try++ {
			rep := s.reconcileRow(id)
			if rep["retry"] != true || try == 60 {
				break
			}
			time.Sleep(10 * time.Second)
		}
	}
}

// reconcileGap is how long reconcile waits before it lists again: GitHub's listings can lag (§5.3 step 4).
var reconcileGap = 30 * time.Second

// reconcileRow inspects one executing row: a RESULT already in the chain gives its state; else agentbox-git looks
// for the effect, twice, reconcileGap apart. Found: RESULT executed. Not found: indeterminate, and for gh.* a new
// pending P with a fresh nonce and the same marker. It never runs the effect.
func (s *server) reconcileRow(id string) reply {
	intent, status, err := s.opState(id)
	if err != nil {
		return reply{"ok": false, "id": id, "state": "executing", "retry": true, "error": "op.get: " + err.Error()}
	}
	if !intent {
		s.finish(id, "refused", "BUSY", nil)
		return reply{"ok": false, "id": id, "state": "refused"}
	}
	if status != "" {
		s.finish(id, status, "", nil)
		return reply{"ok": status == "executed", "id": id, "state": status}
	}
	row, err := scanPending(s.db.QueryRow(`SELECT `+pendingCols+` FROM pending WHERE id=?`, id))
	var p pendingP
	if err != nil || json.Unmarshal(row.Op, &p) != nil {
		return reply{"ok": false, "id": id, "error": "the stored P does not parse"}
	}
	var b json.RawMessage = row.Bound
	since := row.CreatedAt
	for try := 0; try < 2; try++ {
		if try > 0 {
			time.Sleep(reconcileGap)
		}
		rep, err := s.git(map[string]any{"call": "reconcile", "id": id, "name": p.Name, "agent": p.Agent, "args": p.Args, "bound": b, "since": since}, 10*time.Minute)
		if err != nil || rep["ok"] != true {
			log.Printf("pending %s: reconcile: %v %v", id, err, rep)
			return reply{"ok": false, "id": id, "state": "executing", "retry": true, "error": fmt.Sprintf("agentbox-git: %v %v", err, rep["detail"])}
		}
		if rep["found"] == true {
			out, _ := rep["outputs"].(map[string]any)
			log.Printf("pending %s: reconcile found the effect: RESULT executed", id)
			return s.result(id, p, "executed", ops.Denial{}, out, "")
		}
	}
	d := floor(ops.Indeterminate, "", p.Name)
	r := s.result(id, p, "indeterminate", d, nil, "the effect was not found on the remote")
	if strings.HasPrefix(p.Name, "gh.") && r["state"] == "indeterminate" {
		s.reoffer(row)
	}
	return r
}

// reoffer is §5.3 step 5's new pending P after an indeterminate gh.* write: the same op and marker, a fresh nonce and
// expiry. It uses no ask budget.
func (s *server) reoffer(row pendingRow) {
	id := ids.New(ids.Pending)
	now := time.Now().UnixMilli()
	exp := now + askTTL.Milliseconds()
	nb := make([]byte, 16)
	rand.Read(nb)
	nonce := hex.EncodeToString(nb)
	var p pendingP
	json.Unmarshal(row.Op, &p)
	h := sha(string(canonJSON(map[string]any{"op": json.RawMessage(row.Op), "bound": json.RawMessage(row.Bound), "nonce": nonce, "expiresAt": exp})))
	var key string
	s.db.QueryRow(`SELECT match_key FROM pending WHERE id=?`, row.ID).Scan(&key)
	// row was read before finalize hashed the stored body, so the re-offer keeps the bytes rootd bound
	if _, err := s.db.Exec(`INSERT INTO pending(id, task, agent, op, bound, h, nonce, state, match_key, expires_at, created_at)
		VALUES(?,?,?,?,?,?,?,'pending',?,?,?)`, id, row.Task, row.Agent, string(row.Op), string(row.Bound), h, nonce, key, exp, now); err != nil {
		log.Printf("pending %s: re-offer: %v", row.ID, err)
		return
	}
	log.Printf("pending %s: indeterminate; re-offered as %s (agentbox approve %s)", row.ID, id, id)
	if s.cfg.Alert != nil {
		s.cfg.Alert("agentbox: ask from "+row.Agent, p.Name+" "+row.ID+" is indeterminate; re-offered: agentbox approve "+id)
	}
}

// auditCall is one query on auditd's rootd socket; it returns the reply as sent.
func auditCall(sock string, rec map[string]any) (map[string]any, error) {
	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	b, _ := json.Marshal(rec)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.NewDecoder(c).Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// pushReport is the hook's push.report on resolve-git.sock (§6.3 Ref and commit taint): a push from a task whose
// effective taint is set taints every ref it updates, ACKed by auditd before the hook lets git update them. Credential
// patterns the hook found (gitleaks rules) raise an alert; the push still lands, since the hook refuses only the
// canary, the one sure sign.
func (s *server) pushReport(r request) reply {
	repoAgent, project, _ := strings.Cut(r.Repo, "/")
	agent, live, _, err := s.taskAgent(r.Task)
	if err != nil || !live || agent != repoAgent || !git.ValidProject(project) {
		return fail("task_ended")
	}
	tainted, _, err := s.effectiveTaint(r.Task)
	if err != nil {
		log.Printf("push.report task %s: taint.get: %v", r.Task, err)
		return fail("unavailable")
	}
	if tainted {
		for _, ref := range r.Refs {
			if !git.InNamespace(agent, ref) {
				return fail("bad_request")
			}
			if err := s.audit(map[string]any{"type": "TAINT", "subject": git.RefSubject(agent, project, ref), "source": "push:task:" + r.Task}); err != nil {
				log.Printf("push.report task %s: TAINT %s: %v", r.Task, ref, err)
				return fail("unavailable")
			}
		}
	}
	if len(r.Secrets) > 0 {
		var rules []string
		for _, x := range r.Secrets {
			if len(rules) < 10 && reRule.MatchString(x) {
				rules = append(rules, x)
			}
		}
		msg := fmt.Sprintf("task %s (agent %s) pushed a file with credential patterns (%s) to its repo %s; agentbox audit shows it", r.Task, agent,
			strings.Join(rules, ", "), project)
		log.Printf("ALERT %s", msg)
		go s.audit(map[string]any{"type": "ALERT", "reason": "push_secret", "task": r.Task, "rules": rules})
		if s.cfg.Alert != nil {
			s.cfg.Alert("agentbox: credential in a push", msg)
		}
	}
	return reply{"ok": true, "tainted": tainted}
}

var reRule = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

// canaryHit records a task that tried to send its canary out (#105): the task is tainted (ACKed), an ALERT goes to
// auditd and ntfy. The hook calls it on resolve-git.sock and keys on resolve-keys.sock (op llm, #291); rootd's own gh.*
// binder calls it directly.
func (s *server) canaryHit(task, op string) reply {
	agent, _, _, err := s.taskAgent(task)
	if err != nil || agent == "" {
		return fail("no_task")
	}
	if !reRule.MatchString(strings.ReplaceAll(op, ".", "-")) {
		op = "unknown"
	}
	if err := s.audit(map[string]any{"type": "TAINT", "subject": "task:" + task, "source": "canary:" + op}); err != nil {
		log.Printf("canary hit task %s: TAINT: %v", task, err)
	}
	what := "tried to send its canary credential out through " + op + "; the request was refused"
	if op == "llm" { // keys only alerts: the model request went on to the vendor
		what = "sent its canary credential to the LLM vendor in a model request; keys let the request through"
	}
	msg := fmt.Sprintf("task %s (agent %s) %s, and the task is tainted", task, agent, what)
	log.Printf("ALERT %s", msg)
	go s.audit(map[string]any{"type": "ALERT", "reason": "exfil_canary", "task": task, "op": op})
	if s.cfg.Alert != nil {
		if err := s.cfg.Alert("agentbox: canary, task "+task, msg); err != nil {
			log.Printf("alert not queued: %v", err)
		}
	}
	return reply{"ok": true}
}
