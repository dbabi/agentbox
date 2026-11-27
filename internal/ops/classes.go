package ops

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// MaxKeep is the longest keep-class string an audit record may carry (§9 "Enforcement at the sink").
const MaxKeep = 1024

// Lookup returns the registry op called name.
func Lookup(name string) (Op, bool) {
	for _, o := range Registry {
		if o.Name == name {
			return o, true
		}
	}
	return Op{}, false
}

// AgentCallable is false for ops no agent may submit on a gate socket: admin ops and Human-only ops (§5.6 UNKNOWN_OP).
func (o Op) AgentCallable() bool { return o.Class != Admin && !o.Human }

// ArgError is a schema failure: Field is the JSON pointer, Expect one of the denial's INVALID_ARGS expect values
// (§5.6). Neither holds a request value.
type ArgError struct{ Field, Expect string }

func (e *ArgError) Error() string { return e.Field + ": expected " + e.Expect }

// Denial is the INVALID_ARGS that enforcer by (gate or floor) returns for e on op: the pointer and the expected kind.
func (e *ArgError) Denial(op, by string) Denial {
	return Deny(InvalidArgs, "", Slots{Op: op, By: by, Subject: Subject{Pointer: e.Field}, Expect: e.Expect})
}

func decode(raw []byte) (any, error) {
	v, err := decodeTree(raw)
	if err != nil {
		return nil, err
	}
	// Go keeps the last copy of a repeated key, so a check of v would pass bytes whose first copy is still forwarded
	// or stored; noDupKeys runs after Decode, which bounds the depth.
	if err := noDupKeys(raw); err != nil {
		return nil, err
	}
	return v, nil
}

func decodeTree(raw []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	// More is false at a stray } or ], so check the rest is JSON whitespace, as json.Unmarshal (the in-task check's
	// parser) does.
	if len(bytes.TrimLeft(raw[d.InputOffset():], " \t\r\n")) != 0 {
		return nil, fmt.Errorf("trailing data")
	}
	return v, nil
}

// DecodeLimited is Decode for a body nothing has checked yet: a token walk first refuses a repeated key, nesting
// deeper than depth and more than values values (ErrTooDeep, ErrTooMany), so no tree is built for a body past its
// caps. A tree costs tens of bytes per value, whatever the bytes it came from.
func DecodeLimited(raw []byte, depth, values int) (any, error) {
	if err := walkJSON(raw, depth, values); err != nil {
		return nil, err
	}
	return decodeTree(raw)
}

// ValidateArgs is the gate's and the floor's schema check (§5.2, §5.6): raw is an object with every required field
// of o, no other field, each of its declared type, and no keep-class string over MaxKeep (the sink would NACK it). A
// body field may not hold the op marker, which only rootd appends (§5.3). A members field holds 1 to 8 {name, args}
// items: each name an op memberOK allows (a quotable op; for ask.batch, one with a batch shape), each args checked
// against that op's own schema. The decoded args come back with numbers as json.Number.
func (o Op) ValidateArgs(raw []byte) (map[string]any, *ArgError) {
	v, err := decode(raw)
	if err != nil {
		return nil, &ArgError{"", "object"}
	}
	return checkFields(o, v, "", true)
}

func checkFields(o Op, v any, at string, nested bool) (map[string]any, *ArgError) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, &ArgError{at, "object"}
	}
	for k := range m {
		if fieldOf(o.Args, k) == nil {
			return nil, &ArgError{at + "/" + Escape(k), "absent"}
		}
	}
	for _, f := range o.Args {
		x, ok := m[f.Name]
		p := at + "/" + f.Name
		if !ok {
			if !f.Opt {
				return nil, &ArgError{p, "present"}
			}
			continue
		}
		if e := checkType(o, f, x, p, nested); e != nil {
			return nil, e
		}
	}
	return m, nil
}

func checkType(o Op, f Field, x any, p string, nested bool) *ArgError {
	if f.Audit == Keep && CheckKeep(x, p) != nil {
		return &ArgError{p, "valid"} // a string over MaxKeep
	}
	switch f.Type {
	case "string":
		s, ok := x.(string)
		if !ok {
			return &ArgError{p, "string"}
		}
		if f.Name == "body" && bytes.Contains([]byte(s), []byte("agentbox-op:")) {
			return &ArgError{p, "valid"}
		}
	case "integer":
		n, ok := x.(json.Number)
		if !ok {
			return &ArgError{p, "integer"}
		}
		if _, err := strconv.ParseInt(string(n), 10, 64); err != nil {
			return &ArgError{p, "integer"}
		}
	case "boolean":
		if _, ok := x.(bool); !ok {
			return &ArgError{p, "boolean"}
		}
	case "object":
		if _, ok := x.(map[string]any); !ok {
			return &ArgError{p, "object"}
		}
	case "array":
		a, ok := x.([]any)
		if !ok {
			return &ArgError{p, "array"}
		}
		if f.Audit != Members {
			return nil
		}
		if !nested || len(a) < 1 || len(a) > 8 {
			return &ArgError{p, "array"} // 1 to 8 items
		}
		for i, it := range a {
			ip := p + "/" + strconv.Itoa(i)
			mm, ok := it.(map[string]any)
			if !ok || len(mm) != 2 {
				return &ArgError{ip, "object"} // exactly {name, args}
			}
			name, _ := mm["name"].(string)
			if !memberOK(o, name) {
				return &ArgError{ip + "/name", "valid"}
			}
			mo, _ := Lookup(name)
			if _, e := checkFields(mo, mm["args"], ip+"/args", false); e != nil {
				return e
			}
		}
	}
	return nil
}

func fieldOf(fs []Field, name string) *Field {
	for i := range fs {
		if fs[i].Name == name {
			return &fs[i]
		}
	}
	return nil
}

// Escape is RFC 6901 for one reference token; tokens outside [A-Za-z0-9_] become "~x" so a pointer never carries an
// agent's free text.
var token = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

func Escape(k string) string {
	if token.MatchString(k) {
		return k
	}
	return "~x"
}

// Hashed is the audit form of a hash-class value: the SHA-256 of its bytes (a string's UTF-8, anything else its compact
// JSON) and their length.
func Hashed(v any) map[string]any {
	var b []byte
	if s, ok := v.(string); ok {
		b = []byte(s)
	} else {
		b, _ = json.Marshal(v)
	}
	sum := sha256.Sum256(b)
	return map[string]any{"sha256": hex.EncodeToString(sum[:]), "len": len(b)}
}

// Classify applies the audit classes of fs to m (§9 "args (classes applied)"): keep stays, hash becomes {sha256, len},
// drop is removed, and members items take their own op's classes. m is not changed.
func Classify(fs []Field, m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		f := fieldOf(fs, k)
		switch {
		case f == nil, f.Audit == Drop:
		case f.Audit == Hash:
			out[k] = Hashed(v)
		case f.Audit == Members:
			a, _ := v.([]any)
			items := make([]any, 0, len(a))
			for _, it := range a {
				mm, _ := it.(map[string]any)
				name, _ := mm["name"].(string)
				args, _ := mm["args"].(map[string]any)
				mo, _ := Lookup(name)
				items = append(items, map[string]any{"name": name, "args": Classify(mo.Args, args)})
			}
			out[k] = items
		default:
			out[k] = v
		}
	}
	return out
}

var hexSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)

// CheckAudit is auditd's sink check of one record's args or outputs against fs (§9): it fails on a drop-class field,
// a hash-class field not in {sha256, len} form, an undeclared field (its class is unknown), or a string over MaxKeep.
// The error names the field's pointer, never its value.
func CheckAudit(fs []Field, v any, at string) error {
	if v == nil {
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: not an object", orRoot(at))
	}
	for k, x := range m {
		p := at + "/" + Escape(k)
		f := fieldOf(fs, k)
		switch {
		case f == nil:
			return fmt.Errorf("%s: undeclared field", p)
		case f.Audit == Drop:
			return fmt.Errorf("%s: drop-class field present", p)
		case f.Audit == Hash:
			h, ok := x.(map[string]any)
			n, nok := h["len"].(json.Number)
			s, _ := h["sha256"].(string)
			if !ok || len(h) != 2 || !nok || !hexSHA.MatchString(s) {
				return fmt.Errorf("%s: hash-class field not in {sha256, len} form", p)
			}
			if i, err := strconv.ParseInt(string(n), 10, 64); err != nil || i < 0 {
				return fmt.Errorf("%s: hash-class field not in {sha256, len} form", p)
			}
		case f.Audit == Members:
			a, ok := x.([]any)
			if !ok {
				return fmt.Errorf("%s: members not an array", p)
			}
			for i, it := range a {
				ip := p + "/" + strconv.Itoa(i)
				mm, ok := it.(map[string]any)
				name, _ := mm["name"].(string)
				mo, found := Lookup(name)
				if !ok || !found || len(mm) != 2 {
					return fmt.Errorf("%s: not {name, args} of a registry op", ip)
				}
				if err := CheckAudit(mo.Args, mm["args"], ip+"/args"); err != nil {
					return err
				}
			}
		default:
			if err := CheckKeep(x, p); err != nil {
				return err
			}
		}
	}
	return nil
}

// CheckKeep fails on any string in v longer than MaxKeep bytes. It builds the pointer only for a string that fails:
// a pointer per level would cost O(depth^2) bytes, and a task chooses the depth.
func CheckKeep(v any, at string) error {
	path := overKeep(v)
	if path == nil {
		return nil
	}
	slices.Reverse(path)
	return fmt.Errorf("%s: keep-class string over %d bytes", orRoot(at+strings.Join(path, "")), MaxKeep)
}

// overKeep returns the pointer segments of a string over MaxKeep in v, innermost first, or nil if there is none.
func overKeep(v any) []string {
	switch x := v.(type) {
	case string:
		if len(x) > MaxKeep {
			return []string{}
		}
	case []any:
		for i, e := range x {
			if p := overKeep(e); p != nil {
				return append(p, "/"+strconv.Itoa(i))
			}
		}
	case map[string]any:
		for k, e := range x {
			if p := overKeep(e); p != nil {
				return append(p, "/"+Escape(k))
			}
		}
	}
	return nil
}

func orRoot(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

// Decode parses one JSON value with numbers as json.Number, the form ValidateArgs and CheckAudit take.
func Decode(raw []byte) (any, error) { return decode(raw) }
