package rootd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agentbox/internal/audit"
	"agentbox/internal/denial"
)

// plainSeal creates segments without chattr, so the real auditd runs unprivileged in a test.
type plainSeal struct{ dir string }

func (p plainSeal) Create(seg uint64) error {
	return os.WriteFile(filepath.Join(p.dir, audit.SegName(seg)), nil, 0o600)
}
func (plainSeal) Seal(uint64, string) error { return nil }

// rootd's executor against the real auditd: INTENT (classes applied) is ACKed before the effect; an INTENT that
// carries an unhashed body is NACKed by the sink and the effect never runs; a request that fails its schema writes
// nothing at all.
func TestTaskOpIntentBeforeEffect(t *testing.T) {
	dir := t.TempDir()
	a := &audit.Server{Dir: dir, Seal: plainSeal{dir}, ReserveBytes: 1 << 20, Logf: t.Logf}
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ran := 0
	s := &server{cfg: Config{Effects: map[string]Effect{"file.write": func(string, map[string]any) (map[string]any, error) {
		ran++
		return nil, nil
	}}}, audit: func(r map[string]any) error {
		b, _ := json.Marshal(r)
		if rep := a.Handle("rootd", 0, 1, b); !rep.OK {
			return &auditNACK{rep.Code, rep.Detail}
		}
		return nil
	}}
	seg := func() string { b, _ := os.ReadFile(filepath.Join(dir, audit.SegName(1))); return string(b) }
	req := request{Op: "task.op", Name: "file.write", Task: "T1", Agent: "claude", Args: json.RawMessage(`{"path":"/srv/a/x","content":"top secret body"}`)}
	code := func(rep reply) denial.Code {
		if d, ok := rep["denial"].(denial.Denial); ok {
			return d.Code
		}
		return ""
	}

	if rep := s.taskOp(req); rep["ok"] != true || ran != 1 {
		t.Fatalf("clean op: %v, ran %d", rep, ran)
	}
	if strings.Contains(seg(), "top secret") || !strings.Contains(seg(), `"content":{"len":15,"sha256":"`) || !strings.Contains(seg(), `"status":"executed"`) {
		t.Fatalf("chain: %s", seg())
	}

	// a RESULT auditd does not ACK: the effect ran, but the op is not executed, so the agent is not told ok
	ack := s.audit
	s.audit = func(r map[string]any) error {
		if r["type"] == "RESULT" {
			return &auditNACK{audit.CodeUnavailable, ""}
		}
		return ack(r)
	}
	if rep := s.taskOp(req); rep["ok"] != false || code(rep) != denial.EffectFailed || ran != 2 {
		t.Fatalf("RESULT not ACKed: %v, ran %d", rep, ran)
	}
	s.audit = ack

	s.cfg.RawAudit = true
	if rep := s.taskOp(req); rep["ok"] != false || code(rep) != denial.EffectFailed || ran != 2 {
		t.Fatalf("unhashed body: %v, ran %d", rep, ran)
	}
	if strings.Contains(seg(), "top secret") {
		t.Fatal("the NACKed body reached the chain")
	}
	s.cfg.RawAudit = false

	before := seg()
	for _, c := range []struct {
		r    request
		want denial.Code
	}{
		{request{Op: "task.op", Name: "file.write", Task: "T1", Agent: "claude", Args: json.RawMessage(`{"path":"/srv/a/x"}`)}, denial.InvalidArgs},
		{request{Op: "task.op", Name: "file.write", Task: "T1", Agent: "claude", Args: json.RawMessage(`{"path":"p","content":"c","x":1}`)}, denial.InvalidArgs},
		{request{Op: "task.op", Name: "file.write", Task: "../T1", Agent: "claude", Args: req.Args}, denial.InvalidArgs},
		{request{Op: "task.op", Name: "secret.set", Task: "T1", Agent: "claude", Args: json.RawMessage(`{"name":"k","value":"v"}`)}, denial.UnknownOp},
		{request{Op: "task.op", Name: "app.start", Task: "T1", Agent: "claude", Args: json.RawMessage(`{"app":"a"}`)}, denial.UnknownOp},
	} {
		if rep := s.taskOp(c.r); code(rep) != c.want {
			t.Fatalf("%+v: %v, want %s", c.r, rep, c.want)
		}
	}
	if seg() != before || ran != 2 {
		t.Fatalf("a refused request wrote to the chain or ran (ran %d)", ran)
	}
}
