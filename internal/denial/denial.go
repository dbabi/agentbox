// Package denial builds agentbox-denial/v1 objects (ARCHITECTURE.md §5.6) for the codes the week-4 gate and rootd's
// executor return, and mints <kind>_<ULID> ids (§5.1).
//
// shortcut: a hand-kept table of the 7 codes week 4 returns; issue #11's generated codes table, ops.Deny and
// gen/denial.v1.json replace it, and every caller moves to ops.Deny then.
package denial

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"regexp"
	"time"
)

// Code is a §5.6 denial code.
type Code string

const (
	InvalidArgs       Code = "INVALID_ARGS"
	UnknownOp         Code = "UNKNOWN_OP"
	TaskEnded         Code = "TASK_ENDED"
	AuditUnavailable  Code = "AUDIT_UNAVAILABLE"
	EffectFailed      Code = "EFFECT_FAILED"
	BrokerUnavailable Code = "BROKER_UNAVAILABLE"
	Busy              Code = "BUSY"
	// RPCCode is the gate JSON-RPC error code of a denial: message = code; data = the denial (§5.6 Surfaces).
	RPCCode = -32010
	maxLen  = 1024
)

type spec struct{ next, msg string }

// The registry part each code needs here: next and its one fixed sentence.
var codes = map[Code]spec{
	InvalidArgs:       {"fix", "The request does not match the op's schema; fix the field named in subject."},
	UnknownOp:         {"stop", "No op by this name may be called from a task."},
	TaskEnded:         {"stop", "This task has ended; its gate socket no longer accepts requests."},
	AuditUnavailable:  {"retry", "The audit log did not acknowledge the op, so nothing ran; retry later."},
	EffectFailed:      {"human", "The op did not complete; report the code and id to a human."},
	BrokerUnavailable: {"retry", "The gate could not reach its executor; nothing ran; retry later."},
	Busy:              {"retry", "The box is busy, so nothing ran; retry later."},
}

// Remedy is one §5.6 remedy entry.
type Remedy struct {
	Fix   *Fix      `json:"fix,omitempty"`
	Retry *Retry    `json:"retry,omitempty"`
	Human *Human    `json:"human,omitempty"`
	None  *struct{} `json:"none,omitempty"`
}

type Fix struct {
	Field  string `json:"field"`
	Expect string `json:"expect"`
}

type Retry struct {
	AfterMs int `json:"afterMs"`
}

type Human struct{}

// Subject holds the caller's own structural fields that passed their grammar (§5.6).
type Subject struct {
	Field string `json:"field,omitempty"` // a JSON pointer
}

// Denial is agentbox-denial/v1.
type Denial struct {
	V       int      `json:"v"`
	ID      string   `json:"id"`
	Code    Code     `json:"code"`
	By      string   `json:"by"`
	Rule    string   `json:"rule"`
	Op      string   `json:"op,omitempty"`
	Next    string   `json:"next"`
	Subject *Subject `json:"subject,omitempty"`
	Msg     string   `json:"msg"`
	Remedy  []Remedy `json:"remedy"`
}

var (
	opName    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}(\.[a-z][a-z0-9_]{0,31}){0,3}$`)
	pointer   = regexp.MustCompile(`^(/([A-Za-z0-9_]{1,64}|~x)){0,8}$`)
	byRe      = regexp.MustCompile(`^(gate|cedar|floor|proxy|keys|git|forwarder)$`)
	ruleRe    = regexp.MustCompile(`^[a-z]{1,16}\.[a-z_]{1,40}$`) // a static rule name: gate.schema, floor.not_built
	expect    = regexp.MustCompile(`^[ -~]{1,64}$`)
	printable = regexp.MustCompile(`^[ -~]*$`)
)

// New is the constructor: a slot that fails its grammar is dropped and the code is kept (§5.6). by and rule are static
// names; op, field and expect are checked, since op and field come from the request.
func New(code Code, by, rule, op, field, expectText string) Denial {
	s, ok := codes[code]
	if !ok {
		code, s = EffectFailed, codes[EffectFailed]
	}
	d := Denial{V: 1, ID: NewID("dn"), Code: code, By: by, Rule: rule, Next: s.next, Msg: s.msg}
	if !byRe.MatchString(d.By) {
		d.By = "gate"
	}
	if !ruleRe.MatchString(d.Rule) {
		d.Rule = d.By + ".none"
	}
	if opName.MatchString(op) {
		d.Op = op
	}
	switch code {
	case InvalidArgs:
		if pointer.MatchString(field) {
			d.Subject = &Subject{Field: field}
			if expect.MatchString(expectText) {
				d.Remedy = append(d.Remedy, Remedy{Fix: &Fix{field, expectText}})
			}
		}
	case AuditUnavailable, BrokerUnavailable:
		d.Remedy = append(d.Remedy, Remedy{Retry: &Retry{AfterMs: 30000}})
	case Busy:
		d.Remedy = append(d.Remedy, Remedy{Retry: &Retry{AfterMs: 60000}})
	case EffectFailed:
		d.Remedy = append(d.Remedy, Remedy{Human: &Human{}})
	}
	if len(d.Remedy) == 0 {
		d.Remedy = []Remedy{{None: &struct{}{}}}
	}
	if b, _ := json.Marshal(d); len(b) > maxLen || !printable.Match(b) {
		d.Subject, d.Remedy, d.Op = nil, []Remedy{{None: &struct{}{}}}, ""
	}
	return d
}

// Valid is the shape check of a received denial (relayed from rootd, or in a test): every field from this package's
// grammars, printable ASCII, at most 1 KiB, encoded as json.Marshal encodes it.
func Valid(raw []byte) bool {
	if len(raw) > maxLen || !printable.Match(raw) {
		return false
	}
	var d Denial
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&d) != nil || d.V != 1 || !idRe.MatchString(d.ID) || !byRe.MatchString(d.By) || !ruleRe.MatchString(d.Rule) {
		return false
	}
	// only the canonical encoding: no trailing data, duplicate keys or case-folded names, which a stricter reader
	// downstream of the gate would read differently
	if b, err := json.Marshal(d); err != nil || !bytes.Equal(b, raw) {
		return false
	}
	s, ok := codes[d.Code]
	return ok && s.next == d.Next && s.msg == d.Msg && (d.Op == "" || opName.MatchString(d.Op)) &&
		(d.Subject == nil || pointer.MatchString(d.Subject.Field))
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var idRe = regexp.MustCompile(`^[a-z]{2,8}_[0-9A-HJKMNP-TV-Z]{26}$`)

// NewID mints <kind>_<ULID>: 48 bits of Unix milliseconds and 80 bits from crypto/rand, Crockford base32.
func NewID(kind string) string {
	var b [16]byte
	ms := uint64(time.Now().UnixMilli())
	for i := 0; i < 6; i++ {
		b[i] = byte(ms >> (40 - 8*i))
	}
	rand.Read(b[6:])
	out := make([]byte, 26)
	// 128 bits as 26 base32 digits, most significant first (the first digit holds 3 bits)
	var hi, lo uint64
	for i := 0; i < 8; i++ {
		hi = hi<<8 | uint64(b[i])
		lo = lo<<8 | uint64(b[8+i])
	}
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return kind + "_" + string(out)
}

// IsID reports whether s is a <kind>_<ULID> id.
func IsID(s string) bool { return idRe.MatchString(s) }
