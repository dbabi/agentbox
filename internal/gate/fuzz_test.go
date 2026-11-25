package gate

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"testing"

	"agentbox/internal/ops"
)

func quietLog(f *testing.F) {
	log.SetOutput(io.Discard)
	f.Cleanup(func() { log.SetOutput(os.Stderr) })
}

// FuzzCall is a task's request line on its gate socket and rootd's reply line (issue #10). The reply is one JSON-RPC
// object; a refusal carries an agentbox-denial/v1 that passes the in-task check for that request; only an
// agent-callable, rootd-run op whose args pass the registry schema reaches rootd, with the socket's provenance.
func FuzzCall(f *testing.F) {
	quietLog(f)
	var fwd map[string]any
	var reply []byte
	s, tk := newServer(f, func(req map[string]any) ([]byte, error) { fwd = req; return reply, nil })
	d := ops.Deny(ops.AuditUnavailable, "", ops.Slots{Op: "file.write", By: "floor"}).JSON()
	for _, c := range [][2]string{
		{`{"jsonrpc":"2.0","id":"a","method":"file.write","params":{"path":"/srv/a/x","content":"c"}}`, `{"ok":true,"opId":"op_01M7YTS6V13PDAY7ZA2V14TKFS","result":{"n":1}}`},
		{`{"jsonrpc":"2.0","id":1,"method":"file.write","params":{"path":"p","content":"c"}}`, `{"ok":false,"denial":` + string(d) + `}`},
		{`{"jsonrpc":"2.0","id":1,"method":"file.write","params":{"path":"p","content":"c","task":"T2"}}`, `garbage`},
		{`{"jsonrpc":"2.0","id":-1,"method":"os.update"}`, `{"ok":false,"denial":{"v":1,"code":"X"}}`},
		{`{"jsonrpc":"2.0","id":null,"method":"file.write"}{"x":1}`, `{"ok":true}`},
	} {
		f.Add([]byte(c[0]), []byte(c[1]))
	}
	f.Fuzz(func(t *testing.T, line, rep []byte) {
		fwd, reply = nil, rep
		out := s.call(tk, line)
		var r struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Result  json.RawMessage `json:"result"`
			Error   *struct {
				Code    int             `json:"code"`
				Message string          `json:"message"`
				Data    json.RawMessage `json:"data"`
			} `json:"error"`
		}
		if err := json.Unmarshal(out, &r); err != nil || r.JSONRPC != "2.0" || (r.Error == nil) == (r.Result == nil) {
			t.Fatalf("reply %s: %v", out, err)
		}
		if r.Error != nil && r.Error.Code == ops.RPCDenial && !inTask(line, r.Error.Message, r.Error.Data) {
			t.Fatalf("%s: the denial fails the in-task check: %s", line, out)
		}
		if fwd == nil {
			return
		}
		o, ok := ops.Lookup(fwd["name"].(string))
		if !ok || !o.AgentCallable() || !o.Rootd || fwd["task"] != "T1" || fwd["agent"] != "claude" {
			t.Fatalf("%s forwarded %v", line, fwd)
		}
		if _, aerr := o.ValidateArgs(fwd["args"].(json.RawMessage)); aerr != nil {
			t.Fatalf("%s forwarded args that fail the schema: %v", line, aerr)
		}
	})
}

// FuzzControl is rootd's line on svc-gate.sock: nothing but a well-formed register, revoke or list succeeds.
func FuzzControl(f *testing.F) {
	quietLog(f)
	s := &Server{Dir: f.TempDir(), AgentIDs: func(string) (uint32, uint32, error) { return 0, 0, os.ErrNotExist }}
	for _, l := range []string{`{"call":"register","task":"T1","agent":"claude","chain":["T0"]}`, `{"call":"revoke","task":"T1"}`,
		`{"call":"list"}`, `{"call":"register","task":"../x","agent":"a"}`, `{"call":"list","x":1}`} {
		f.Add([]byte(l))
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		rep := s.Control(line)
		if rep["ok"] == true {
			if _, ok := rep["tasks"]; !ok {
				t.Fatalf("%q: %v", line, rep)
			}
		}
		if _, err := json.Marshal(rep); err != nil {
			t.Fatal(err)
		}
	})
}
