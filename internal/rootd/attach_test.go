package rootd

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentbox/internal/audit"
	"agentbox/internal/rootd/attach"
)

// §9: attach.rescan's change to a task block is an admin op, against the real auditd: INTENT (the sink takes it), its
// ACK, the change, RESULT with the hit count and never a hit's name. With auditd down a clean rescan, --ack-restart
// included, leaves the block; a rescan that changes nothing sends nothing.
func TestRescanIsAudited(t *testing.T) {
	root, dir := t.TempDir(), t.TempDir()
	db, err := OpenDB(filepath.Join(root, "rootd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := &audit.Server{Dir: dir, Seal: plainSeal{dir}, ReserveBytes: 1 << 20, Logf: t.Logf}
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	up := true
	s := &server{db: db, cfg: Config{AttachRoot: root}, audit: func(r map[string]any) error {
		if !up {
			return errors.New("connect: no such file or directory")
		}
		b, _ := json.Marshal(r)
		if rep := a.Handle("rootd", 0, 1, b); !rep.OK {
			return &auditNACK{rep.Code, rep.Detail}
		}
		return nil
	}}
	seg := func() string { b, _ := os.ReadFile(filepath.Join(dir, audit.SegName(1))); return string(b) }
	const tok = "gate-oauth-at-rescan-HHHHHHHHHHHHHHHHHHHHHH"
	p := attach.AgentPaths(root, "at", "ses_old")
	os.MkdirAll(filepath.Join(p.SessionHome, ".claude"), 0o700)
	os.MkdirAll(p.Workspace, 0o755)
	os.WriteFile(filepath.Join(p.SessionHome, ".claude", ".credentials.json"), []byte(`{"claudeAiOauth":{"accessToken":"`+tok+`"}}`), 0o600)
	leak := filepath.Join(p.Workspace, "hit-name-JJJJ.txt")
	os.WriteFile(leak, []byte(tok), 0o644)
	// the block an attach before a rootd restart left: its scan found the token, which is still in the workspace
	attach.Begin(db, "at", "ses_old", time.Now())
	attach.End(db, "at", "ses_old", []attach.Hit{{Path: "hit-name-JJJJ.txt"}})
	blocked := func() bool { _, on, _ := attach.Blocked(db, "at"); return on }

	if rep := s.rescan("at", false); rep["ok"] != true || rep["blocked"] != true {
		t.Fatalf("rescan with the token in the workspace: %v", rep)
	}
	if c := seg(); strings.Count(c, `"name":"attach.rescan"`) != 1 || !strings.Contains(c, `"args":{"ackRestart":false,"name":"at"}`) ||
		!strings.Contains(c, `"outputs":{"hits":1}`) || strings.Contains(c, "hit-name") || strings.Contains(c, tok) {
		t.Fatalf("chain after a hit: %s", c)
	}
	os.Remove(leak)
	up = false
	if rep := s.rescan("at", true); rep["ok"] != false || rep["blocked"] != true || !strings.Contains(rep["error"].(string), "INTENT was not ACKed") || !blocked() {
		t.Fatalf("clean rescan --ack-restart with auditd down: %v, blocked %v", rep, blocked())
	}
	up = true
	if rep := s.rescan("at", false); rep["blocked"] != true || !strings.Contains(rep["error"].(string), "--ack-restart") ||
		strings.Count(seg(), `"name":"attach.rescan"`) != 1 {
		t.Fatalf("clean rescan after a restart, no ack: %v, chain %s", rep, seg())
	}
	if rep := s.rescan("at", true); rep["ok"] != true || rep["blocked"] != false || blocked() {
		t.Fatalf("clean rescan --ack-restart: %v, blocked %v", rep, blocked())
	}
	if c := seg(); strings.Count(c, `"name":"attach.rescan"`) != 2 || !strings.Contains(c, `"args":{"ackRestart":true,"name":"at"}`) ||
		!strings.Contains(c, `"outputs":{"hits":0}`) || strings.Count(c, `"status":"executed"`) != 2 {
		t.Fatalf("chain after the lift: %s", c)
	}
}
