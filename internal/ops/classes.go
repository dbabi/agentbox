package ops

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
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

// ArgError is a schema failure: Field is the JSON pointer, Expect a static description. Neither holds a request value.
type ArgError struct{ Field, Expect string }

func (e *ArgError) Error() string { return e.Field + ": expected " + e.Expect }

func decode(raw []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if d.More() {
		return nil, fmt.Errorf("trailing data")
	}
	// Go keeps the last copy of a repeated key, so a check of v would pass bytes whose first copy is still forwarded
	// or stored; noDupKeys runs after Decode, which bounds the depth.
	if err := noDupKeys(raw); err != nil {
		return nil, err
	}
	return v, nil
}

// ValidateArgs checks raw against o's args schema: an object with every required field, no other field, each of its
// declared type, no keep-class string over MaxKeep (the sink would NACK it); a members field holds 1 to 8 {name, args} items of agent-callable ops, each checked against its own
// schema. It is the gate's and the floor's check (§5.2); the decoded args come back with numbers as json.Number.
func (o Op) ValidateArgs(raw []byte) (map[string]any, *ArgError) {
	v, err := decode(raw)
	if err != nil {
		return nil, &ArgError{"", "a JSON object"}
	}
	m, aerr := checkFields(o.Args, v, "", true)
	return m, aerr
}

func checkFields(fs []Field, v any, at string, nested bool) (map[string]any, *ArgError) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, &ArgError{at, "an object"}
	}
	for k := range m {
		if fieldOf(fs, k) == nil {
			return nil, &ArgError{at + "/" + Escape(k), "no such field"}
		}
	}
	for _, f := range fs {
		x, ok := m[f.Name]
		p := at + "/" + f.Name
		if !ok {
			if !f.Opt {
				return nil, &ArgError{p, "a required " + f.Type}
			}
			continue
		}
		if e := checkType(f, x, p, nested); e != nil {
			return nil, e
		}
	}
	return m, nil
}

func checkType(f Field, x any, p string, nested bool) *ArgError {
	if f.Audit == Keep && CheckKeep(x, p) != nil {
		return &ArgError{p, fmt.Sprintf("no string over %d bytes", MaxKeep)}
	}
	switch f.Type {
	case "string":
		s, ok := x.(string)
		if !ok {
			return &ArgError{p, "a string"}
		}
		if f.Name == "body" && bytes.Contains([]byte(s), []byte("agentbox-op:")) {
			return &ArgError{p, "no agentbox-op: marker"} // §5.6: the op marker is rootd's (§5.3)
		}
	case "integer":
		n, ok := x.(json.Number)
		if !ok {
			return &ArgError{p, "an integer"}
		}
		if _, err := strconv.ParseInt(string(n), 10, 64); err != nil {
			return &ArgError{p, "an integer"}
		}
	case "object":
		if _, ok := x.(map[string]any); !ok {
			return &ArgError{p, "an object"}
		}
	case "array":
		a, ok := x.([]any)
		if !ok {
			return &ArgError{p, "an array"}
		}
		if f.Audit != Members {
			return nil
		}
		if !nested || len(a) < 1 || len(a) > 8 {
			return &ArgError{p, "1 to 8 {name, args} items"}
		}
		for i, it := range a {
			ip := p + "/" + strconv.Itoa(i)
			mm, ok := it.(map[string]any)
			if !ok || len(mm) != 2 {
				return &ArgError{ip, "{name, args}"}
			}
			name, _ := mm["name"].(string)
			mo, ok := Lookup(name)
			if !ok || !mo.AgentCallable() || hasMembers(mo) {
				return &ArgError{ip + "/name", "an op an agent may call"}
			}
			if _, e := checkFields(mo.Args, mm["args"], ip+"/args", false); e != nil {
				return e
			}
		}
	}
	return nil
}

func hasMembers(o Op) bool {
	for _, f := range o.Args {
		if f.Audit == Members {
			return true
		}
	}
	return false
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

// CheckKeep fails on any string in v longer than MaxKeep bytes.
func CheckKeep(v any, at string) error {
	switch x := v.(type) {
	case string:
		if len(x) > MaxKeep {
			return fmt.Errorf("%s: keep-class string over %d bytes", orRoot(at), MaxKeep)
		}
	case []any:
		for i, e := range x {
			if err := CheckKeep(e, at+"/"+strconv.Itoa(i)); err != nil {
				return err
			}
		}
	case map[string]any:
		for k, e := range x {
			if err := CheckKeep(e, at+"/"+Escape(k)); err != nil {
				return err
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
