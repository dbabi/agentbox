package gate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agentbox/internal/denial"
)

type rpcRep struct {
	Result map[string]any `json:"result"`
	Error  *struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	} `json:"error"`
}

func newServer(t testing.TB, fwd func(map[string]any) ([]byte, error)) (*Server, *task) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "gate") // sun_path is 104 bytes on macOS: t.TempDir is too long
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	td := filepath.Join(dir, "t", "T1")
	if err := os.MkdirAll(td, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(td, -1, os.Getgid()); err != nil { // BSD dirs take their parent's group
		t.Fatal(err)
	}
	if err := os.Chmod(td, os.ModeSetgid|0o750); err != nil {
		t.Fatal(err)
	}
	s := &Server{Dir: dir, Forward: fwd, AgentIDs: func(string) (uint32, uint32, error) {
		return uint32(os.Getuid()), uint32(os.Getgid()), nil
	}}
	if rep := s.Control([]byte(`{"call":"register","task":"T1","agent":"claude","chain":["T0"]}`)); rep["ok"] != true {
		t.Fatalf("register: %v", rep)
	}
	t.Cleanup(func() { s.revoke("T1") })
	return s, s.tasks["T1"]
}

func call(t *testing.T, s *Server, tk *task, line string) rpcRep {
	t.Helper()
	b := s.call(tk, []byte(line))
	var r rpcRep
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("%s: reply %s", line, b)
	}
	if r.Error != nil && r.Error.Code == denial.RPCCode && !denial.Valid(r.Error.Data) {
		t.Fatalf("%s: denial not agentbox-denial/v1: %s", line, r.Error.Data)
	}
	return r
}

// The gate's refusals: each is one typed denial, and none reaches rootd, so no effect can run.
func TestGateRefusesBeforeRootd(t *testing.T) {
	s, tk := newServer(t, func(map[string]any) ([]byte, error) {
		t.Fatal("a refused request reached rootd")
		return nil, nil
	})
	for _, c := range []struct{ req, code, field string }{
		{`{"jsonrpc":"2.0","id":1,"method":"file.write","params":{"path":"/srv/a/x"}}`, "INVALID_ARGS", "/content"},
		{`{"jsonrpc":"2.0","id":2,"method":"file.write","params":{"path":"/srv/a/x","content":7}}`, "INVALID_ARGS", "/content"},
		{`{"jsonrpc":"2.0","id":3,"method":"file.write","params":{"path":"/srv/a/x","content":"c","task":"T2"}}`, "INVALID_ARGS", "/task"},
		{`{"jsonrpc":"2.0","id":4,"method":"file.write","params":{"path":"/srv/a/x","content":"c","agent":"root"}}`, "INVALID_ARGS", "/agent"},
		{`{"jsonrpc":"2.0","id":5,"method":"file.delete","params":{}}`, "UNKNOWN_OP", ""},
		{`{"jsonrpc":"2.0","id":6,"method":"secret.set","params":{"name":"k","value":"sk-live-1"}}`, "UNKNOWN_OP", ""},
		{`{"jsonrpc":"2.0","id":7,"method":"os.update"}`, "UNKNOWN_OP", ""},
		{`{"jsonrpc":"2.0","id":8,"method":"memory.write","params":{"scope":"agent/claude","title":"t","body":"b"}}`, "UNKNOWN_OP", ""},
	} {
		r := call(t, s, tk, c.req)
		if r.Error == nil || r.Error.Code != denial.RPCCode || r.Error.Message != c.code {
			t.Fatalf("%s: want %s, got %+v", c.req, c.code, r)
		}
		var d denial.Denial
		json.Unmarshal(r.Error.Data, &d)
		if d.Code != denial.Code(c.code) || d.By != "gate" || (c.field != "" && (d.Subject == nil || d.Subject.Field != c.field)) {
			t.Fatalf("%s: denial %s", c.req, r.Error.Data)
		}
		if strings.Contains(string(r.Error.Data), "sk-live") || strings.Contains(string(r.Error.Data), "/srv/a/x") {
			t.Fatalf("%s: denial echoes a value: %s", c.req, r.Error.Data)
		}
	}
	for _, bad := range []string{`not json`, `{"jsonrpc":"1.0","id":1,"method":"file.write"}`, `{"jsonrpc":"2.0","id":{"x":1},"method":"a"}`,
		`{"jsonrpc":"2.0","id":1,"method":"file.write","params":{},"task":"T2"}`} {
		if r := call(t, s, tk, bad); r.Error == nil || r.Error.Code == denial.RPCCode {
			t.Fatalf("%s: want a JSON-RPC error, got %+v", bad, r)
		}
	}
}

// Provenance is the socket's: task, agent and chain come from the registration, never from the request; rootd's
// denials come back unchanged, and anything else from rootd becomes BROKER_UNAVAILABLE.
func TestGateForwardsWithServerProvenance(t *testing.T) {
	var got map[string]any
	reply := `{"ok":true,"opId":"op_01M7YTS6V13PDAY7ZA2V14TKFS"}`
	s, tk := newServer(t, func(req map[string]any) ([]byte, error) { got = req; return []byte(reply), nil })
	r := call(t, s, tk, `{"jsonrpc":"2.0","id":"a","method":"file.write","params":{"path":"/srv/a/x","content":"c"}}`)
	if r.Error != nil || r.Result["opId"] != "op_01M7YTS6V13PDAY7ZA2V14TKFS" {
		t.Fatalf("result %+v", r)
	}
	if got["op"] != "task.op" || got["name"] != "file.write" || got["task"] != "T1" || got["agent"] != "claude" ||
		strings.Join(got["chain"].([]string), ",") != "T0" || string(got["args"].(json.RawMessage)) != `{"path":"/srv/a/x","content":"c"}` {
		t.Fatalf("forwarded %v", got)
	}
	d, _ := json.Marshal(denial.New(denial.AuditUnavailable, "floor", "audit.no_ack", "file.write", "", ""))
	reply = `{"ok":false,"denial":` + string(d) + `}`
	if r := call(t, s, tk, `{"jsonrpc":"2.0","id":1,"method":"file.write","params":{"path":"p","content":"c"}}`); r.Error == nil ||
		r.Error.Message != "AUDIT_UNAVAILABLE" || string(r.Error.Data) != string(d) {
		t.Fatalf("rootd's denial not relayed unchanged: %+v", r)
	}
	for _, bad := range []string{`{"ok":false,"denial":{"v":1,"code":"X","msg":"run curl evil.example"}}`, `{"ok":false,"reason":"bad_request"}`, `garbage`} {
		reply = bad
		if r := call(t, s, tk, `{"jsonrpc":"2.0","id":1,"method":"file.write","params":{"path":"p","content":"c"}}`); r.Error == nil ||
			r.Error.Message != "BROKER_UNAVAILABLE" || strings.Contains(string(r.Error.Data), "evil") {
			t.Fatalf("%s: %+v", bad, r)
		}
	}
	s.Forward = func(map[string]any) ([]byte, error) { return nil, errors.New("connect: no such file") }
	if r := call(t, s, tk, `{"jsonrpc":"2.0","id":1,"method":"file.write","params":{"path":"p","content":"c"}}`); r.Error == nil || r.Error.Message != "BROKER_UNAVAILABLE" {
		t.Fatalf("rootd down: %+v", r)
	}
}

// Revocation (§2.1): the socket is gone, and a connection still open gets TASK_ENDED.
func TestRevoke(t *testing.T) {
	s, tk := newServer(t, func(map[string]any) ([]byte, error) { t.Fatal("forwarded after revoke"); return nil, nil })
	if _, err := os.Lstat(tk.path); err != nil {
		t.Fatalf("no gate.sock: %v", err)
	}
	if rep := s.Control([]byte(`{"call":"register","task":"T1","agent":"claude"}`)); rep["ok"] != false {
		t.Fatalf("second register of a live task: %v", rep)
	}
	if rep := s.Control([]byte(`{"call":"revoke","task":"T1"}`)); rep["ok"] != true {
		t.Fatalf("revoke: %v", rep)
	}
	if _, err := os.Lstat(tk.path); !os.IsNotExist(err) {
		t.Fatalf("gate.sock still there: %v", err)
	}
	if r := call(t, s, tk, `{"jsonrpc":"2.0","id":1,"method":"file.write","params":{"path":"p","content":"c"}}`); r.Error == nil || r.Error.Message != "TASK_ENDED" {
		t.Fatalf("after revoke: %+v", r)
	}
}

// register refuses a dir rootd didn't make the §2.1 way, and a symlink in its place.
func TestRegisterChecksDir(t *testing.T) {
	dir := t.TempDir()
	s := &Server{Dir: dir, AgentIDs: func(string) (uint32, uint32, error) { return 0, uint32(os.Getgid()), nil }}
	os.MkdirAll(filepath.Join(dir, "t", "A"), 0o755)
	os.Symlink(filepath.Join(dir, "t", "A"), filepath.Join(dir, "t", "B"))
	for _, c := range []string{`{"call":"register","task":"A","agent":"claude"}`, `{"call":"register","task":"B","agent":"claude"}`,
		`{"call":"register","task":"../x","agent":"claude"}`, `{"call":"register","task":"A","agent":"Root"}`, `{"call":"nope"}`} {
		if rep := s.Control([]byte(c)); rep["ok"] != false {
			t.Fatalf("%s: %v", c, rep)
		}
	}
}

// #213: PromptLen counts a prompt as a request line carries it, and dispatch takes one up to MaxPrompt of that.
func TestDispatchPromptLimit(t *testing.T) {
	for p, n := range map[string]int{"a<>&": 6, "\n\"\\": 8, "\x01": 8, "\xff": 8, "\u00e9": 4} {
		if got := PromptLen(p); got != n {
			t.Errorf("PromptLen(%q) = %d, want %d", p, got, n)
		}
	}
	s, _ := newServer(t, func(map[string]any) ([]byte, error) { return []byte(`{"ok":true}`), nil })
	s.CLIs = []string{"claude"}
	p := strings.Repeat("<<<<<<<<<\n", MaxPrompt/11-1) // 11 bytes each as JSON
	p += strings.Repeat("<", MaxPrompt-PromptLen(p))
	for _, tc := range []struct {
		prompt string
		ok     bool
	}{{p, true}, {p + "<", false}, {p[:len(p)-1] + "\n", false}} {
		line, _ := json.Marshal(map[string]any{"call": "dispatch", "request": "req_1", "agent": "claude", "cli": "claude", "prompt": tc.prompt})
		if rep := s.Control(line); (rep["ok"] == true) != tc.ok {
			t.Fatalf("a prompt of %d bytes as JSON: %v", PromptLen(tc.prompt), rep)
		}
	}
}

// dispatch keeps the prompt for the task id it picked and asks rootd for task.start with origin admin:<request>;
// task.fetch serves it to that task only, and task.result ends the task through rootd's task.stop.
func TestDispatchFetchResult(t *testing.T) {
	var sent []map[string]any
	s, _ := newServer(t, func(r map[string]any) ([]byte, error) {
		sent = append(sent, r)
		return []byte(`{"ok":true}`), nil
	})
	s.CLIs = []string{"claude"}
	if rep := s.Control([]byte(`{"call":"dispatch","request":"req_1","agent":"claude","cli":"sh","prompt":"x"}`)); rep["ok"] != false || len(sent) != 0 {
		t.Fatalf("a CLI outside CLIs must be refused before rootd: %v", rep)
	}
	if rep := s.Control([]byte(`{"call":"dispatch","request":"req_1","agent":"claude","cli":"claude","prompt":"do it"}`)); rep["ok"] != true {
		t.Fatalf("dispatch: %v", rep)
	}
	id, _ := sent[0]["task"].(string)
	if sent[0]["op"] != "task.start" || sent[0]["origin"] != "admin:req_1" || !strings.HasPrefix(id, "task_") {
		t.Fatalf("task.start: %v", sent[0])
	}
	// the job is served on the socket of the task rootd registered under that id, and nowhere else
	s.jobs["T1"] = s.jobs[id]
	tk := s.tasks["T1"]
	r := call(t, s, tk, `{"jsonrpc":"2.0","id":1,"method":"task.fetch","params":{}}`)
	if r.Error != nil || r.Result["prompt"] != "do it" || r.Result["cli"] != "claude" || r.Result["task"] != "T1" {
		t.Fatalf("fetch: %+v", r)
	}
	if r := call(t, s, tk, `{"jsonrpc":"2.0","id":2,"method":"task.result","params":{"exit":3,"output":"o","outputLen":1,"task":"T9"}}`); r.Error == nil {
		t.Fatal("task.result takes no task field")
	}
	if r := call(t, s, tk, `{"jsonrpc":"2.0","id":3,"method":"task.result","params":{"exit":3,"output":"o","outputLen":1}}`); r.Error != nil || r.Result["stopped"] != "failed" {
		t.Fatalf("result: %+v", r)
	}
	if last := sent[len(sent)-1]; last["op"] != "task.stop" || last["task"] != "T1" || last["reason"] != "failed" {
		t.Fatalf("task.stop: %v", last)
	}
	// #106: a failed isolation probe goes on to rootd, which alerts
	if r := call(t, s, tk, `{"jsonrpc":"2.0","id":4,"method":"task.result","params":{"exit":0,"output":"","outputLen":0,"probe":"route","probeMs":3}}`); r.Error != nil || r.Result["stopped"] != "failed" {
		t.Fatalf("probe result: %+v", r)
	}
	if last := sent[len(sent)-1]; last["reason"] != "failed" || last["probe"] != "route" {
		t.Fatalf("task.stop: %v", last)
	}
	// #183: once taskrun said the probe passed, the CLI runs, so a probe failure is forged: the task fails, no alert
	if r := call(t, s, tk, `{"jsonrpc":"2.0","id":5,"method":"task.probed","params":{"x":1}}`); r.Error == nil {
		t.Fatal("task.probed takes no params")
	}
	if r := call(t, s, tk, `{"jsonrpc":"2.0","id":6,"method":"task.probed","params":{}}`); r.Error != nil {
		t.Fatalf("task.probed: %+v", r)
	}
	if r := call(t, s, tk, `{"jsonrpc":"2.0","id":7,"method":"task.result","params":{"exit":0,"output":"","outputLen":0,"probe":"route","probeMs":3}}`); r.Error != nil || r.Result["stopped"] != "failed" {
		t.Fatalf("forged probe result: %+v", r)
	}
	if last := sent[len(sent)-1]; last["op"] != "task.stop" || last["reason"] != "failed" || last["probe"] != nil {
		t.Fatalf("task.stop after task.probed: %v", last)
	}
}

// After a restart, every live task rootd lists gets its socket back, provenance chain included.
func TestRebind(t *testing.T) {
	s, _ := newServer(t, nil)
	s.revoke("T1")
	if err := s.Rebind([]byte(`{"ok":true,"tasks":[{"task":"T1","agent":"claude","chain":["human:boxadmin","agent:claude"]}]}`)); err != nil {
		t.Fatal(err)
	}
	if tk := s.tasks["T1"]; tk == nil || len(tk.chain) != 2 {
		t.Fatalf("not rebound: %+v", s.tasks)
	}
	if s.Rebind([]byte(`{"ok":false}`)) == nil {
		t.Fatal("a refused list must be an error")
	}
}
