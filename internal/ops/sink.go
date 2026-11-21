package ops

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"agentbox/internal/ids"
)

// DenyRecord is a DENY audit record without its type (§9, gen/audit-deny.v1.json).
type DenyRecord struct {
	ID      string                     `json:"id"`
	Code    string                     `json:"code"`
	What    string                     `json:"what,omitempty"`
	By      string                     `json:"by"`
	Task    string                     `json:"task,omitempty"`
	Agent   string                     `json:"agent,omitempty"`
	Op      string                     `json:"op,omitempty"`
	Subject *Subject                   `json:"subject,omitempty"`
	Args    map[string]json.RawMessage `json:"args,omitempty"`
	Detail  string                     `json:"detail,omitempty"` // for humans only; never returned by the query call
	Count   int64                      `json:"count"`
	First   int64                      `json:"first"`
	Last    int64                      `json:"last"`
}

type denyFlood struct {
	Task  string `json:"task,omitempty"`
	By    string `json:"by"`
	Count int64  `json:"count"`
}

const maxKeep = 1024 // §9: a keep string over 1 KiB is NACKed

// CheckDenyRecord is auditd's sink check of a DENY or DENY_FLOOD body (the record minus its type): the closed schema,
// a known code and what, and the op's audit classes on any args. Other types pass.
func CheckDenyRecord(typ string, body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	switch typ {
	case "DENY_FLOOD":
		var f denyFlood
		if err := dec.Decode(&f); err != nil {
			return err
		}
		if !slices.Contains(enforcers, f.By) || f.Count < 1 || f.Task != "" && !ids.Is(ids.Task, f.Task) {
			return errors.New("DENY_FLOOD needs a known enforcer, a count and a task id")
		}
		return nil
	case "DENY":
	default:
		return nil
	}
	var r DenyRecord
	if err := dec.Decode(&r); err != nil {
		return err // an unknown field, such as a free-text reason, lands here
	}
	def := codeDefs[r.Code]
	switch {
	case def == nil:
		return fmt.Errorf("unknown code %q", r.Code)
	case r.What != "" && !slices.ContainsFunc(def.Whats, func(x What) bool { return x.Name == r.What }):
		return fmt.Errorf("what %q is not in %s's list", r.What, r.Code)
	case !ids.Is(ids.Denial, r.ID) && !ids.Is(ids.Pending, r.ID):
		return errors.New("id is not dn_ or pnd_ ULID")
	case !slices.Contains(enforcers, r.By):
		return fmt.Errorf("unknown enforcer %q", r.By)
	case r.Task != "" && !ids.Is(ids.Task, r.Task), r.Agent != "" && !reAgent.MatchString(r.Agent):
		return errors.New("bad task or agent")
	case r.Subject != nil && *r.Subject != r.Subject.clean():
		return errors.New("a subject field fails its grammar")
	case len(r.Detail) > maxKeep:
		return errors.New("detail over 1 KiB")
	case r.Count < 1 || r.First < 0 || r.Last < r.First:
		return errors.New("bad count or times")
	}
	if r.Args != nil || r.Op != "" {
		if _, ok := opDef(r.Op); !ok {
			return fmt.Errorf("unknown op %q", r.Op)
		}
	}
	if r.Args != nil {
		b, _ := json.Marshal(r.Args)
		return CheckAuditArgs(r.Op, b)
	}
	return nil
}

// CheckAuditArgs checks an op's args as logged (§9 Enforcement at the sink): no drop field, every hash field in
// {sha256, len} form, no keep string over 1 KiB, no field the op doesn't declare. A members-class array's items are
// checked against their own op's classes.
func CheckAuditArgs(op string, args []byte) error {
	o, ok := opDef(op)
	if !ok {
		return fmt.Errorf("unknown op %q", op)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(args, &m); err != nil {
		return errors.New("args: not an object")
	}
	for k, raw := range m {
		i := slices.IndexFunc(o.Args, func(f Field) bool { return f.Name == k })
		if i < 0 {
			return fmt.Errorf("%s.%s: not a declared arg", op, k)
		}
		f := o.Args[i]
		switch f.Audit {
		case Drop:
			return fmt.Errorf("%s.%s: a drop field is never logged", op, k)
		case Hash:
			var h struct {
				SHA256 string `json:"sha256"`
				Len    *int64 `json:"len"`
			}
			d := json.NewDecoder(bytes.NewReader(raw))
			d.DisallowUnknownFields()
			if d.Decode(&h) != nil || len(h.SHA256) != 64 || !reOID.MatchString(h.SHA256) || h.Len == nil || *h.Len < 0 {
				return fmt.Errorf("%s.%s: a hash field must be {sha256, len}", op, k)
			}
		case Keep:
			if len(raw) > maxKeep+2 {
				return fmt.Errorf("%s.%s: keep value over 1 KiB", op, k)
			}
		case Members:
			var items []struct {
				Name string          `json:"name"`
				Args json.RawMessage `json:"args"`
			}
			if json.Unmarshal(raw, &items) != nil {
				return fmt.Errorf("%s.%s: not a member list", op, k)
			}
			for _, it := range items {
				if err := CheckAuditArgs(it.Name, it.Args); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
