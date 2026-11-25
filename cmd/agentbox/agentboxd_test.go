package main

import (
	"strings"
	"testing"

	"agentbox/internal/ops"
)

// #221: gate call fails on a denial the in-task check refuses: the legacy shape, one for another op, or a message that
// is not its code; a valid denial, a result and a non-denial error pass.
func TestGateCallChecksDenial(t *testing.T) {
	req := []byte(`{"jsonrpc":"2.0","id":1,"method":"file.write","params":{"path":"p","content":"c"}}`)
	rpc := func(msg string, d []byte) []byte {
		return []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32010,"message":"` + msg + `","data":` + string(d) + `}}`)
	}
	d := ops.Deny(ops.AuditUnavailable, "", ops.Slots{Op: "file.write", By: "floor"}).JSON()
	for _, ok := range [][]byte{rpc("AUDIT_UNAVAILABLE", d), []byte(`{"jsonrpc":"2.0","id":1,"result":{"opId":"op_1"}}`),
		[]byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}`)} {
		if err := checkDenial(req, ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	legacy := []byte(`{"v":1,"id":"dn_01M7YTS6V13PDAY7ZA2V14TKFS","code":"INVALID_ARGS","by":"gate","rule":"gate.schema","op":"file.write",` +
		`"next":"fix","subject":{"field":"/content"},"msg":"x","remedy":[{"fix":{"field":"/content","expect":"a required string"}}]}`)
	other := ops.Deny(ops.AuditUnavailable, "", ops.Slots{Op: "app.start", By: "floor"}).JSON()
	for _, bad := range [][]byte{rpc("INVALID_ARGS", legacy), rpc("AUDIT_UNAVAILABLE", other), rpc("BUSY", d)} {
		if err := checkDenial(req, bad); err == nil || !strings.Contains(err.Error(), "in-task check") {
			t.Errorf("%s: %v", bad, err)
		}
	}
}
