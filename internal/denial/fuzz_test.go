package denial

import (
	"encoding/json"
	"testing"
)

// FuzzNew: whatever a request puts in op, field and expect, New's denial passes Valid (issue #10).
func FuzzNew(f *testing.F) {
	f.Add("INVALID_ARGS", "gate", "gate.schema", "file.write", "/content", "string")
	f.Add("NOPE", "root", "x", "\x1b[2J", "/a/~x/b", string(make([]byte, 2000)))
	f.Add("INVALID_ARGS", "gate", "gate.schema", "a.b.c.d", "/"+string(make([]byte, 64)), "\u202e")
	f.Fuzz(func(t *testing.T, code, by, rule, op, field, expect string) {
		b, err := json.Marshal(New(Code(code), by, rule, op, field, expect))
		if err != nil || !Valid(b) {
			t.Fatalf("New gave an invalid denial: %s %v", b, err)
		}
	})
}

// FuzzValid: a denial Valid accepts (rootd's, relayed by the gate) decodes and re-encodes to one that still passes.
func FuzzValid(f *testing.F) {
	for _, c := range []Code{InvalidArgs, UnknownOp, TaskEnded, AuditUnavailable, EffectFailed, BrokerUnavailable} {
		b, _ := json.Marshal(New(c, "gate", "gate.schema", "file.write", "/path", "absolute path"))
		f.Add(b)
	}
	f.Add([]byte(`{"v":1,"id":"dn_01ARZ3NDEKTSV4RRFFQ69G5FAV","code":"UNKNOWN_OP","by":"gate","rule":"gate.x","next":"stop","msg":"No op by this name may be called from a task.","remedy":null,"remedy":[]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if !Valid(raw) {
			return
		}
		var d Denial
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatalf("Valid accepted %q that does not decode: %v", raw, err)
		}
		b, _ := json.Marshal(d)
		if !Valid(b) {
			t.Fatalf("Valid accepted %q but not its re-encoding %s", raw, b)
		}
	})
}
