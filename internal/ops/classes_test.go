package ops

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateArgs(t *testing.T) {
	for _, c := range []struct{ op, args, field, expect string }{
		{"file.write", `{"path":"/srv/a/x","content":"hi"}`, "", ""},
		{"file.write", `{"path":"/srv/a/x"}`, "/content", "a required string"},
		{"file.write", `{"path":"/srv/a/x","content":1}`, "/content", "a string"},
		{"file.write", `{"path":"/srv/a/x","content":"hi","task":"T2"}`, "/task", "no such field"},
		{"file.write", `{"path":"/srv/a/x","content":"hi","\u001b[31m":1}`, "/~x", "no such field"},
		{"file.write", `[1]`, "", "an object"},
		{"file.write", `{"path":"a","content":"b"} {}`, "", "a JSON object"},
		{"file.write", `{"path":"/srv/a/x","content":"hi","content":"ho"}`, "", "a JSON object"},
		{"file.write", `{"path":"` + strings.Repeat("p", MaxKeep+1) + `","content":"hi"}`, "/path", "no string over 1024 bytes"},
		{"file.write", `{"path":"/srv/a/x","content":"` + strings.Repeat("c", MaxKeep+1) + `"}`, "", ""},
		{"ask.quote", `{"ops":[{"name":"file.write","args":{"path":"` + strings.Repeat("p", MaxKeep+1) + `","content":"c"}}]}`, "/ops/0/args/path", "no string over 1024 bytes"},
		{"app.logs", `{"app":"a","lines":1.5}`, "/lines", "an integer"},
		{"gh.pr.comment", `{"remote":"r","number":1,"body":"x agentbox-op: y"}`, "/body", "no agentbox-op: marker"},
		{"ask.quote", `{"ops":[{"name":"file.write","args":{"path":"p","content":"c"}}]}`, "", ""},
		{"ask.quote", `{"ops":[]}`, "/ops", "1 to 8 {name, args} items"},
		{"ask.quote", `{"ops":[{"name":"secret.set","args":{"name":"n","value":"v"}}]}`, "/ops/0/name", "an op an agent may call"},
		{"ask.quote", `{"ops":[{"name":"ask.quote","args":{"ops":[]}}]}`, "/ops/0/name", "an op an agent may call"},
		{"ask.quote", `{"ops":[{"name":"file.write","args":{"path":"p"}}]}`, "/ops/0/args/content", "a required string"},
	} {
		o, _ := Lookup(c.op)
		_, e := o.ValidateArgs([]byte(c.args))
		if c.field == "" && c.expect == "" {
			if e != nil {
				t.Errorf("%s %s: %v", c.op, c.args, e)
			}
			continue
		}
		if e == nil || e.Field != c.field || e.Expect != c.expect {
			t.Errorf("%s %s: got %v, want %s: %s", c.op, c.args, e, c.field, c.expect)
		}
	}
}

// sample gives every field of fs a value of its type, so Classify then CheckAudit runs over every registry op.
func sample(fs []Field) map[string]any {
	m := map[string]any{}
	for _, f := range fs {
		switch {
		case f.Audit == Members:
			m[f.Name] = []any{map[string]any{"name": "gh.pr.create", "args": sample(mustOp("gh.pr.create").Args)}}
		case f.Type == "string":
			m[f.Name] = "secret-value-" + f.Name
		case f.Type == "integer":
			m[f.Name] = json.Number("7")
		case f.Type == "array":
			m[f.Name] = []any{"secret-value-" + f.Name}
		default:
			m[f.Name] = map[string]any{"k": "secret-value-" + f.Name}
		}
	}
	return m
}

func mustOp(n string) Op { o, _ := Lookup(n); return o }

// Every op's args and outputs, with classes applied, pass the sink check, and no hash or drop value survives; the
// unclassified args of any op with a hash or drop field fail it.
func TestClassifyPassesSink(t *testing.T) {
	for _, o := range Registry {
		for _, fs := range [][]Field{o.Args, o.Out} {
			raw := sample(fs)
			b, _ := json.Marshal(Classify(fs, raw))
			v, _ := Decode(b)
			if err := CheckAudit(fs, v, ""); err != nil {
				t.Errorf("%s: classified %s fails the sink: %v", o.Name, b, err)
			}
			secret := false
			for _, f := range fs {
				if f.Audit == Hash || f.Audit == Drop || f.Audit == Members {
					secret = true
					if strings.Contains(string(b), "secret-value-"+f.Name) {
						t.Errorf("%s: %s survived classification: %s", o.Name, f.Name, b)
					}
				}
			}
			b, _ = json.Marshal(raw)
			v, _ = Decode(b)
			if err := CheckAudit(fs, v, ""); secret && err == nil {
				t.Errorf("%s: unclassified %s passes the sink", o.Name, b)
			}
		}
	}
}
