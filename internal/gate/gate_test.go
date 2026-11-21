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

func newServer(t *testing.T, fwd func(map[string]any) ([]byte, error)) (*Server, *task) {
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
