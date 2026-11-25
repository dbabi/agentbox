package rootd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"agentbox/internal/ops"
	"agentbox/internal/rootd/attach"
	"agentbox/internal/task"
)

// attachRequest reports whether line is an agent.attach on the admin socket: that connection turns into the session's
// byte stream once rootd answers it.
func attachRequest(line []byte) (request, bool) {
	var r request
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	return r, dec.Decode(&r) == nil && r.Op == "agent.attach"
}

// alert queues a high-priority ntfy message (Config.Alert); a failure only logs (the block already stands).
func (s *server) alert(agent, msg string) {
	if s.cfg.Alert == nil {
		return
	}
	if err := s.cfg.Alert("agentbox: attach "+agent, msg); err != nil {
		log.Printf("alert not queued: %v", err)
	}
}

// agentSeen is the agent's token versions: a later rescan still matches a token the CLI has since rotated.
func (s *server) agentSeen(agent string) *attach.Seen {
	v, _ := s.seen.LoadOrStore(agent, &attach.Seen{})
	return v.(*attach.Seen)
}

// rescan is attach.rescan: the whole workspace against every session-home token version rootd has seen. A clean scan
// lifts a standing block (a hit the admin removed, or an attach whose scan never ran). If rootd restarted since that
// attach, the versions it rotated away are gone from memory, so a clean scan lifts the block only with ack (the admin
// checked the workspace). The change to the block is an admin op (§9): see audited.
func (s *server) rescan(agent string, ack bool) reply {
	if !agentRe.MatchString(agent) {
		return reply{"ok": false, "error": "bad agent name"}
	}
	if _, ok := s.live.Load(agent); ok {
		return reply{"ok": false, "error": "the attach is live: rescan after it ends"}
	}
	b, ok, err := attach.Blocked(s.db, agent)
	if err != nil || !ok {
		return reply{"ok": err == nil, "blocked": false}
	}
	if b.Reason == attach.TaskNotEmpty {
		return s.rescanTask(b, ack)
	}
	if b.Reason == attach.Live {
		// rootd stopped mid-attach: its session must not outlive the scan. Like task.stop, this only removes
		// capability (the end of that agent.attach), so it doesn't wait for an ACK.
		s.cfg.Attach.Stop(agent, b.Session)
	}
	p := attach.AgentPaths(s.attachRoot(), agent, b.Session)
	seen := s.agentSeen(agent)
	ts, err := attach.Tokens(p.SessionHome)
	seen.Add(ts)
	if err != nil { // the scan can't know every token: the block stays until the file is readable
		return reply{"ok": false, "blocked": true, "error": escaped(err.Error()) + ": make it a regular JSON file, or remove it, then rescan"}
	}
	tokens, err := seen.All()
	if err != nil {
		return reply{"ok": false, "blocked": true, "error": err.Error()}
	}
	hits, err := attach.Scan(p.Workspace, time.Time{}, tokens)
	if err != nil {
		return reply{"ok": false, "error": escaped(err.Error())} // it can name a workspace path
	}
	if w, _ := s.watched.Load(agent); len(hits) == 0 && w != b.Session && !ack {
		log.Printf("attach.rescan %s: clean, but rootd restarted since session %s: block kept", agent, b.Session)
		return reply{"ok": true, "blocked": true, "error": "rootd restarted since this attach, so the token versions it saw are gone: " +
			"check the workspace by hand, then agentbox attach rescan --agent " + agent + " --ack-restart"}
	}
	return s.audited(agent, ack, func() (map[string]any, reply) {
		if err := attach.End(s.db, agent, b.Session, hits); err != nil {
			return nil, reply{"ok": false, "blocked": true, "error": err.Error()}
		}
		log.Printf("attach.rescan %s: %d hit(s), ack-restart %v", agent, len(hits), ack)
		return map[string]any{"hits": len(hits)}, reply{"ok": true, "blocked": len(hits) > 0, "hits": hits}
	})
}

// rescanTask lifts the TaskNotEmpty block once every leftover task's unit cgroup is gone or empty (§4.2 Stop step 2):
// each task.stop that left processes recorded its own row.
func (s *server) rescanTask(b attach.BlockRow, ack bool) reply {
	if s.tasks == nil {
		return reply{"ok": false, "blocked": true, "error": "no task registry"}
	}
	left, err := attach.Leftovers(s.db, b.Agent)
	if err != nil {
		return reply{"ok": false, "blocked": true, "error": err.Error()}
	}
	var still, empty []string
	for _, id := range left {
		var uid uint32
		if err := s.db.QueryRow(`SELECT uid FROM task_registry WHERE task=?`, id).Scan(&uid); err != nil {
			return reply{"ok": false, "blocked": true, "error": "no registry row for task " + id}
		}
		if populated(filepath.Join(s.tasks.cfg.Cgroup, task.CgroupDir(uid, id))) {
			still = append(still, id)
		} else {
			empty = append(empty, id)
		}
	}
	after := func() reply {
		if len(still) > 0 {
			return reply{"ok": true, "blocked": true, "error": "task(s) " + strings.Join(still, ", ") + " still have processes in their unit cgroups"}
		}
		if _, on, err := attach.Blocked(s.db, b.Agent); on || err != nil {
			return reply{"ok": err == nil, "blocked": true, "error": "another block stands: agentbox attach status"}
		}
		log.Printf("attach.rescan %s: no leftover task: block lifted", b.Agent)
		return reply{"ok": true, "blocked": false}
	}
	if len(empty) == 0 {
		return after()
	}
	return s.audited(b.Agent, ack, func() (map[string]any, reply) {
		done := []string{}
		for _, id := range empty {
			if err := attach.ClearTask(s.db, id); err != nil {
				return map[string]any{"tasks": done}, reply{"ok": false, "blocked": true, "error": err.Error()}
			}
			done = append(done, id)
			log.Printf("attach.rescan %s: task %s left no process", b.Agent, id)
		}
		return map[string]any{"tasks": done}, after()
	})
}

// audited runs change, attach.rescan's change to agent's task block, as an admin op (§9): INTENT, its ACK, change,
// RESULT with change's outputs (the hit count, never a hit's name: the agent picks those). With no ACK nothing
// changes, and the block stays.
func (s *server) audited(agent string, ack bool, change func() (map[string]any, reply)) reply {
	o, _ := ops.Lookup("attach.rescan")
	id := newDenyID()
	if err := s.audit(map[string]any{"type": "INTENT", "opId": id, "name": o.Name, "origin": "admin",
		"args": ops.Classify(o.Args, map[string]any{"name": agent, "ackRestart": ack})}); err != nil {
		return reply{"ok": false, "blocked": true, "error": "audit: the INTENT was not ACKed, the block stays: " + err.Error()}
	}
	out, rep := change()
	status, detail := "executed", ""
	if rep["ok"] != true {
		status, detail = "failed", fmt.Sprint(rep["error"])
	}
	if err := s.audit(map[string]any{"type": "RESULT", "opId": id, "status": status, "detail": detail, "outputs": ops.Classify(o.Out, out)}); err != nil {
		log.Printf("attach.rescan %s: RESULT not audited: %v", agent, err)
		if rep["ok"] == true {
			rep["ok"], rep["error"] = false, "the block changed, but its audit RESULT was not ACKed: "+err.Error()
		}
	}
	return rep
}

// escaped is s with each rune a terminal would not print as is (C0, C1, bidi and other format controls) written as a Go
// escape: an error can carry a name the agent chose, and the admin's terminal must show it, not act on it. A list of
// names is quoted instead, so no name can pass for two.
func escaped(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		} else {
			b.WriteString(strings.Trim(strconv.QuoteRuneToASCII(r), "'"))
		}
	}
	return b.String()
}

func (s *server) attachRoot() string {
	if s.cfg.AttachRoot != "" {
		return s.cfg.AttachRoot
	}
	return attach.Root
}
