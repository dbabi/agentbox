package rootd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agentbox/internal/audit"
	"agentbox/internal/ops"
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
	req := request{Op: "task.op", Name: "file.write", Task: "T1", Agent: "claude", Chain: []string{"human:boxadmin", "agent:claude"},
		Args: json.RawMessage(`{"path":"/srv/a/x","content":"top secret body"}`)}
	// code is the denial's code, once it passes the in-task check (§5.6) for the request that got it
	code := func(r request, rep reply) string {
		d, ok := rep["denial"].(ops.Denial)
		if !ok {
			return ""
		}
		if _, _, ok := ops.CheckDenial(r.Name, r.Args, d.JSON()); !ok {
			t.Fatalf("%+v: the denial fails the in-task check: %s", r, d.JSON())
		}
		return d.Code
	}

	if rep := s.taskOp(req); rep["ok"] != true || ran != 1 {
		t.Fatalf("clean op: %v, ran %d", rep, ran)
	}
	if strings.Contains(seg(), "top secret") || !strings.Contains(seg(), `"content":{"len":15,"sha256":"`) || !strings.Contains(seg(), `"status":"executed"`) ||
		!strings.Contains(seg(), `"chain":["human:boxadmin","agent:claude"]`) {
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
	if rep := s.taskOp(req); rep["ok"] != false || code(req, rep) != "EFFECT_FAILED" || ran != 2 {
		t.Fatalf("RESULT not ACKed: %v, ran %d", rep, ran)
	}
	s.audit = ack

	s.cfg.RawAudit = true
	if rep := s.taskOp(req); rep["ok"] != false || code(req, rep) != "EFFECT_FAILED" || ran != 2 {
		t.Fatalf("unhashed body: %v, ran %d", rep, ran)
	}
	if strings.Contains(seg(), "top secret") {
		t.Fatal("the NACKed body reached the chain")
	}
	s.cfg.RawAudit = false

	before := seg()
	for _, c := range []struct {
		r    request
		want string
	}{
		{request{Op: "task.op", Name: "file.write", Task: "T1", Agent: "claude", Args: json.RawMessage(`{"path":"/srv/a/x"}`)}, "INVALID_ARGS"},
		{request{Op: "task.op", Name: "file.write", Task: "T1", Agent: "claude", Args: json.RawMessage(`{"path":"p","content":"c","x":1}`)}, "INVALID_ARGS"},
		{request{Op: "task.op", Name: "file.write", Task: "../T1", Agent: "claude", Args: req.Args}, "INVALID_ARGS"},
		// #222: the chain goes into the INTENT too, so it is held to rootd's grammar and length
		{request{Op: "task.op", Name: "file.write", Task: "T1", Agent: "claude", Chain: []string{"human:boxadmin", "agent:claude\n\x1b[2J"}, Args: req.Args}, "INVALID_ARGS"},
		{request{Op: "task.op", Name: "file.write", Task: "T1", Agent: "claude", Chain: strings.Fields(strings.Repeat("agent:claude ", maxChain+1)), Args: req.Args}, "INVALID_ARGS"},
		// UNKNOWN_OP is the gate's code: what the floor never runs (an op the gate should have refused, or one with no
		// effect yet) is FLOOR_NEVER{never_available}, by floor
		{request{Op: "task.op", Name: "secret.set", Task: "T1", Agent: "claude", Args: json.RawMessage(`{"name":"k","value":"v"}`)}, "FLOOR_NEVER"},
		{request{Op: "task.op", Name: "app.start", Task: "T1", Agent: "claude", Args: json.RawMessage(`{"app":"a"}`)}, "FLOOR_NEVER"},
		// C-G3: an LLM vendor host is never on a proxy list, whatever its case or a trailing dot
		{request{Op: "task.op", Name: "net.allow_domain", Task: "T1", Agent: "claude", Args: json.RawMessage(`{"host":"API.anthropic.com.","port":443,"reason":"r"}`)}, "FLOOR_NEVER vendor_host"},
		{request{Op: "task.op", Name: "net.allow_domain", Task: "T1", Agent: "claude", Args: json.RawMessage(`{"host":"api.openai.com","port":443,"reason":"r"}`)}, "FLOOR_NEVER vendor_host"},
		{request{Op: "task.op", Name: "net.allow_domain", Task: "T1", Agent: "claude", Args: json.RawMessage(`{"host":"registry.npmjs.org","port":443,"reason":"r"}`)}, "FLOOR_NEVER"},
	} {
		rep := s.taskOp(c.r)
		want, what, _ := strings.Cut(c.want, " ")
		if what == "" && want == "FLOOR_NEVER" {
			what = "never_available"
		}
		if code(c.r, rep) != want {
			t.Fatalf("%+v: %v, want %s", c.r, rep, c.want)
		}
		if d := rep["denial"].(ops.Denial); d.By != "floor" || d.What != what || strings.Contains(string(d.JSON()), "sk-") || strings.Contains(string(d.JSON()), "anthropic") {
			t.Fatalf("%+v: %s", c.r, d.JSON())
		}
	}
	if seg() != before || ran != 2 {
		t.Fatalf("a refused request wrote to the chain or ran (ran %d)", ran)
	}
}
