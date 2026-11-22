package rootd

import (
	"errors"
	"log"
	"os"

	"agentbox/internal/rootd/accounts"
	"agentbox/internal/rootd/witness"
	"agentbox/internal/taskenv"
)

// goPrivateSet is the admin op go.private.set{agent, patterns} (§5.3): INTENT, its ACK, the effect, RESULT. "" clears.
func (s *server) goPrivateSet(r request) reply {
	if !accounts.ValidName(r.Agent) || r.Patterns == nil {
		return reply{"ok": false, "error": "go.private.set needs agent and patterns"}
	}
	if err := taskenv.ValidGoPrivate(*r.Patterns); err != nil {
		return reply{"ok": false, "error": err.Error()}
	}
	id := newDenyID()
	if err := s.audit(map[string]any{"type": "INTENT", "opId": id, "name": r.Op, "origin": "admin",
		"args": map[string]string{"agent": r.Agent, "patterns": *r.Patterns}}); err != nil {
		return reply{"ok": false, "error": "audit: the INTENT was not ACKed, nothing changed: " + err.Error()}
	}
	changed, err := taskenv.WriteGoPrivate(s.cfg.EgressDir, r.Agent, *r.Patterns)
	status, detail := "executed", ""
	if err != nil {
		status, detail = "failed", err.Error()
	}
	aerr := s.audit(map[string]any{"type": "RESULT", "opId": id, "status": status, "detail": detail, "changed": changed})
	switch {
	case err != nil:
		return reply{"ok": false, "error": err.Error()}
	case aerr != nil:
		return reply{"ok": false, "changed": changed, "error": "the patterns changed, but the audit RESULT was not ACKed: " + aerr.Error()}
	}
	return reply{"ok": true, "changed": changed}
}

// openWitness is task.start's step (§4.2 Dispatch step 2): the FIFO, group ag-<agent>, held by rootd until closeWitness.
func (t *tasks) openWitness(task string, gid uint32) error {
	w, err := witness.Create(t.cfg.WitnessRoot, task, int(gid))
	if err != nil {
		return err
	}
	t.witMu.Lock()
	if t.wit == nil {
		t.wit = map[string]*witness.W{}
	}
	t.wit[task] = w
	t.witMu.Unlock()
	return nil
}

// closeWitness is task.stop's (Stop steps 2a and 4): once the task's cgroup is empty, drain, send WITNESS without
// waiting for the ACK, and remove the dir. The kept lines are checked against task_denials in weeks 9-10.
func (t *tasks) closeWitness(task string) (witness.Result, bool) {
	t.witMu.Lock()
	w := t.wit[task]
	delete(t.wit, task)
	t.witMu.Unlock()
	if w == nil {
		return witness.Result{}, false
	}
	res := w.Drain()
	if err := w.Remove(); err != nil {
		log.Printf("witness %s: %v", task, err)
	}
	rec := map[string]any{"type": "WITNESS", "task": task, "lines": res.Lines, "bad": res.Bad, "dropped": res.Dropped,
		"end": res.End, "incomplete": res.Incomplete}
	go func() {
		if err := t.audit(rec); err != nil {
			log.Printf("WITNESS %s not audited: %v", task, err)
		}
	}()
	return res, true
}

// reopenWitnesses runs at start, before resume: every witness a task still holds is reopened and marked incomplete,
// since lines written while rootd was down are lost. That gap is rootd's own, so it raises no alert.
func (t *tasks) reopenWitnesses() {
	live, err := t.live()
	if err != nil {
		log.Printf("witness: %v", err)
	}
	t.witMu.Lock()
	defer t.witMu.Unlock()
	if t.wit == nil {
		t.wit = map[string]*witness.W{}
	}
	for _, r := range live {
		id := r.Task
		w, err := witness.Reopen(t.cfg.WitnessRoot, id)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			log.Printf("witness %s: %v", id, err)
			continue
		}
		t.wit[id] = w
		log.Printf("witness %s: reopened after a restart, marked incomplete", id)
	}
}
