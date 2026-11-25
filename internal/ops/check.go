package ops

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"agentbox/internal/ids"
)

// CheckDenial is the in-task check of a gate denial (§5.6 Integrity), run by the in-task agentbox binary before any
// tool or model sees the reply. req is the request it sent. ok=false means the reply failed: the caller shows the
// returned BROKER_UNAVAILABLE{gate} instead and writes the returned witness line.
func CheckDenial(op string, args []byte, reply []byte) (d Denial, witness string, ok bool) {
	d, err := ParseDenial(reply)
	if err == nil {
		err = matchRequest(d, op, args)
	}
	if err != nil {
		bad := Deny(BrokerUnavailable, "gate", Slots{Op: op, By: "forwarder"})
		return bad, WitnessMalformed(bad), false
	}
	return d, WitnessLine(d), true
}

// CheckAskReply is the in-task check of a successful ask.quote or ask.status reply to the request args it sent. It
// returns the reply re-encoded. ok=false means the reply failed: as for CheckDenial, the caller shows the returned
// BROKER_UNAVAILABLE{gate} instead and writes the returned witness line.
func CheckAskReply(op string, args, reply []byte) (out []byte, d Denial, witness string, ok bool) {
	err := errors.New("not an ask read")
	switch op {
	case "ask.quote":
		var req struct {
			Ops []json.RawMessage `json:"ops"`
		}
		json.Unmarshal(args, &req)
		out, err = CheckQuoteReply(reply, len(req.Ops))
	case "ask.status":
		out, err = CheckStatusReply(reply)
	}
	if err != nil {
		d = Deny(BrokerUnavailable, "gate", Slots{Op: op, By: "forwarder"})
		return nil, d, WitnessMalformed(d), false
	}
	return out, Denial{}, "", true
}

// matchRequest: the denial names the op it was for, and its subject only fields of that request.
func matchRequest(d Denial, op string, args []byte) error {
	if d.Op != "" && d.Op != op {
		return fmt.Errorf("denial for %s answers %s", d.Op, op)
	}
	if d.Code == "ASK_DENIED" && d.Pending == "" {
		return fmt.Errorf("ASK_DENIED without the denied row's id")
	}
	if d.Code == "NEEDS_SIGNATURE" && !ids.Is(ids.Pending, d.ID) {
		return fmt.Errorf("NEEDS_SIGNATURE without a pending id")
	}
	if d.Subject == nil {
		return nil
	}
	var m map[string]json.RawMessage
	json.Unmarshal(args, &m)
	got, want := *d.Subject, SubjectFrom(op, m)
	if got.Pointer != "" && !pointerIn(got.Pointer, op, m) {
		return fmt.Errorf("pointer %s is not in the request", got.Pointer)
	}
	got.Pointer = ""
	for _, f := range []struct{ g, w string }{{got.Host, want.Host}, {got.Ref, want.Ref}, {got.OID, want.OID}, {got.Remote, want.Remote},
		{got.App, want.App}, {got.Snapshot, want.Snapshot}, {got.Package, want.Package}, {got.Unit, want.Unit}, {got.Model, want.Model}} {
		if f.g != "" && f.g != f.w {
			return fmt.Errorf("subject %q differs from the request", f.g)
		}
	}
	if got.Port != 0 && got.Port != want.Port {
		return fmt.Errorf("subject port differs from the request")
	}
	return nil
}

// pointerIn: the pointer's first segment is a key the request sent or an arg the op declares.
func pointerIn(p, op string, args map[string]json.RawMessage) bool {
	seg := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 2)[0]
	if _, ok := args[seg]; ok {
		return true
	}
	o, _ := opDef(op)
	return slices.ContainsFunc(o.Args, func(f Field) bool { return f.Name == seg })
}

// Witness lines (§5.6 Witness): `<id> <op> <code> <by>`, a malformed reply's line, and taskrun's END.
var reWitness = regexp.MustCompile(`^(?:((?:dn|pnd)_[0-7][0-9A-HJKMNP-TV-Z]{25}) (-|[a-z]+(?:\.[a-z_]+)+) ([A-Z][A-Z_]{1,40}) ([a-z]{3,9})( malformed)?|END ([0-9a-f]{64}))$`)

// WitnessLine is the line a forwarder or agentbox mcp writes for a denial the task saw.
func WitnessLine(d Denial) string {
	op := d.Op
	if op == "" {
		op = "-"
	}
	return d.ID + " " + op + " " + d.Code + " " + d.By
}

// WitnessMalformed is the line for a gate reply that failed the in-task check.
func WitnessMalformed(d Denial) string { return WitnessLine(d) + " malformed" }

// WitnessEntry is one parsed witness line.
type WitnessEntry struct {
	ID, Op, Code, By string
	Malformed        bool
	End              string // the sha256 of the posted result, on the END line
}

// ParseWitness is rootd's one anchored pattern over a witness line. A line that doesn't match, or names a code or
// enforcer not in the table, is an error.
func ParseWitness(line string) (WitnessEntry, error) {
	m := reWitness.FindStringSubmatch(line)
	if m == nil {
		return WitnessEntry{}, fmt.Errorf("not a witness line")
	}
	if m[6] != "" {
		return WitnessEntry{End: m[6]}, nil
	}
	if _, ok := LookupCode(m[3]); !ok || !slices.Contains(enforcers, m[4]) {
		return WitnessEntry{}, fmt.Errorf("unknown code or enforcer")
	}
	if m[2] != "-" && !reOpName.MatchString(m[2]) {
		return WitnessEntry{}, fmt.Errorf("bad op")
	}
	return WitnessEntry{ID: m[1], Op: m[2], Code: m[3], By: m[4], Malformed: m[5] != ""}, nil
}
