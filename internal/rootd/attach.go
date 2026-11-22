package rootd

import (
	"bytes"
	"encoding/json"
	"log"
	"time"

	"agentbox/internal/rootd/attach"
)

// attachRequest reports whether line is an agent.attach on the admin socket: that connection turns into the session's
// byte stream once rootd answers it.
func attachRequest(line []byte) (request, bool) {
	var r request
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	return r, dec.Decode(&r) == nil && r.Op == "agent.attach"
}

// alert sends a high-priority ntfy message; a failure only logs (the block already stands).
func (s *server) alert(agent, msg string) {
	if s.cfg.Alert == nil {
		return
	}
	if err := s.cfg.Alert("agentbox: attach "+agent, msg); err != nil {
		log.Printf("alert not sent: %v", err)
		return
	}
	log.Printf("alert sent: %s", msg)
}

// agentSeen is the agent's token versions: a later rescan still matches a token the CLI has since rotated.
func (s *server) agentSeen(agent string) *attach.Seen {
	v, _ := s.seen.LoadOrStore(agent, &attach.Seen{})
	return v.(*attach.Seen)
}

// rescan is attach.rescan: the whole workspace against every session-home token version rootd has seen. A clean scan
// lifts a standing block (a hit the admin removed, or an attach whose scan never ran).
func (s *server) rescan(agent string) reply {
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
	if b.Reason == attach.Live {
		s.cfg.Attach.Stop(agent, b.Session) // rootd stopped mid-attach: its session must not outlive the scan
	}
	p := attach.AgentPaths(s.attachRoot(), agent, b.Session)
	seen := s.agentSeen(agent)
	seen.Add(attach.Tokens(p.SessionHome))
	hits, err := attach.Scan(p.Workspace, time.Time{}, seen.All())
	if err != nil {
		return reply{"ok": false, "error": err.Error()}
	}
	if err := attach.End(s.db, agent, b.Session, hits); err != nil {
		return reply{"ok": false, "error": err.Error()}
	}
	log.Printf("attach.rescan %s: %d hit(s)", agent, len(hits))
	return reply{"ok": true, "blocked": len(hits) > 0, "hits": hits}
}

func (s *server) attachRoot() string {
	if s.cfg.AttachRoot != "" {
		return s.cfg.AttachRoot
	}
	return attach.Root
}
