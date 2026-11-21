package ops

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"agentbox/internal/ids"
)

// Denial is the one agent-facing refusal shape (ARCHITECTURE.md §5.6, gen/denial.v1.json). Every string in it is a
// release constant, an id, or one of the caller's own fields that passed its grammar.
type Denial struct {
	V         int      `json:"v"`
	ID        string   `json:"id"`
	Code      string   `json:"code"`
	By        string   `json:"by"`
	Rule      string   `json:"rule,omitempty"`
	Op        string   `json:"op,omitempty"`
	Next      Next     `json:"next"`
	Subject   *Subject `json:"subject,omitempty"`
	What      string   `json:"what,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	Taint     *Taint   `json:"taint,omitempty"`
	Limit     *int64   `json:"limit,omitempty"`
	ResetsAt  *int64   `json:"resetsAt,omitempty"`
	AsksLeft  *int64   `json:"asksLeft,omitempty"`
	Pending   string   `json:"pending,omitempty"`
	Open      []string `json:"open,omitempty"`
	Channel   string   `json:"channel,omitempty"`
	ExpiresAt *int64   `json:"expiresAt,omitempty"`
	Notified  *bool    `json:"notified,omitempty"`
	AfterMs   *int64   `json:"afterMs,omitempty"`
	Msg       string   `json:"msg"`
	Remedy    []Remedy `json:"remedy"`
}

// Subject is the caller's own structural fields (§5.6 Shape). Each has a grammar; Deny drops a field that fails it.
type Subject struct {
	Host     string `json:"host,omitempty"`
	Port     int64  `json:"port,omitempty"`
	Ref      string `json:"ref,omitempty"`
	OID      string `json:"oid,omitempty"`
	Remote   string `json:"remote,omitempty"`
	App      string `json:"app,omitempty"`
	Snapshot string `json:"snapshot,omitempty"`
	Pointer  string `json:"pointer,omitempty"`
	Package  string `json:"package,omitempty"`
	Unit     string `json:"unit,omitempty"`
	Model    string `json:"model,omitempty"`
}

// Taint is the one agent-facing taint shape (§8, R10).
type Taint struct {
	Tainted        bool `json:"tainted"`
	WorkspaceBound bool `json:"workspaceBound"`
}

// Remedy is one static remedy (§5.6): the kind and only the fields that kind uses.
type Remedy struct {
	Kind      RemedyKind  `json:"kind"`
	Op        string      `json:"op,omitempty"`
	Args      *RemedyArgs `json:"args,omitempty"`
	Approval  string      `json:"approval,omitempty"`
	Field     string      `json:"field,omitempty"`
	Expect    string      `json:"expect,omitempty"`
	Pending   string      `json:"pending,omitempty"`
	ExpiresAt *int64      `json:"expiresAt,omitempty"`
	Notified  *bool       `json:"notified,omitempty"`
	HumanCmd  string      `json:"human,omitempty"`
	AfterMs   int64       `json:"afterMs,omitempty"`
	Admin     string      `json:"admin,omitempty"`
}

// RemedyArgs are the args of a remedy op: only net.allow_domain has any, and they are the subject's host and port.
type RemedyArgs struct {
	Host string `json:"host"`
	Port int64  `json:"port"`
}

// Slots are what a producer passes to Deny. Only grammar-checked values reach the denial; a slot the code doesn't
// declare is dropped.
type Slots struct {
	Op        string
	By        string
	Rule      string
	Subject   Subject
	Reason    string
	Taint     *Taint
	Limit     *int64
	ResetsAt  *int64
	AsksLeft  *int64
	Pending   string // NEEDS_SIGNATURE: the pending (or batch) id, used as the denial id; ASK_DENIED, STALE: the row named
	Open      []string
	ExpiresAt *int64
	Notified  *bool
	Expect    string
}

// Limits of the shape (§5.6).
const (
	MaxDenial = 1024
	MaxMsg    = 200
)

// Cedar rules an agent may see (leak rule 5).
var cedarRules = []string{"cedar.hop-limit", "cedar.memory-procedural-never", "cedar.chain", "cedar.custom"}

// INVALID_ARGS expect values, and the fixed expect strings of other codes: a closed list, so expect carries no text.
var expects = []string{"string", "integer", "boolean", "array", "object", "present", "absent", "valid", "refs/heads/agent/<name>/*",
	"an OID pushed through :8082", "use :8081", "use CONNECT"}

var (
	reLabel   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	reTLD     = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`) // a letter first: an IPv4 literal is never a host
	reRef     = regexp.MustCompile(`^refs/heads/[A-Za-z0-9_][A-Za-z0-9._/-]{0,199}$`)
	reOID     = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	reRemote  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	reApp     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	rePointer = regexp.MustCompile(`^(/([A-Za-z][A-Za-z0-9_]{0,63}|[0-9]{1,3})){1,6}$`)
	rePackage = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,62}$`)
	reUnit    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._-]{0,127}\.(service|socket|timer|target|path|mount)$`)
	reModel   = regexp.MustCompile(`^[a-z0-9][a-z0-9.:-]{0,63}$`)
	reOpName  = regexp.MustCompile(`^[a-z]+(\.[a-z_]+)+$`)
)

// ValidHost is the A-label grammar: lowercase LDH labels, at most 253 bytes, the last label starting with a letter.
func ValidHost(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	l := strings.Split(h, ".")
	for _, x := range l[:len(l)-1] {
		if !reLabel.MatchString(x) {
			return false
		}
	}
	return reTLD.MatchString(l[len(l)-1])
}

func validRef(r string) bool {
	return reRef.MatchString(r) && !strings.Contains(r, "..") && !strings.Contains(r, "//") && !strings.HasSuffix(r, "/") &&
		!strings.HasSuffix(r, ".lock") && !strings.HasSuffix(r, ".")
}

// Clean drops every subject field that fails its grammar.
func (s Subject) Clean() Subject { return s.clean() }

func (s Subject) clean() Subject {
	keep := func(v string, ok bool) string {
		if ok {
			return v
		}
		return ""
	}
	s.Host = keep(s.Host, ValidHost(s.Host))
	if s.Port < 1 || s.Port > 65535 {
		s.Port = 0
	}
	s.Ref = keep(s.Ref, validRef(s.Ref))
	s.OID = keep(s.OID, reOID.MatchString(s.OID))
	s.Remote = keep(s.Remote, reRemote.MatchString(s.Remote))
	s.App = keep(s.App, reApp.MatchString(s.App))
	s.Snapshot = keep(s.Snapshot, ids.Is(ids.Snap, s.Snapshot))
	s.Pointer = keep(s.Pointer, rePointer.MatchString(s.Pointer))
	s.Package = keep(s.Package, rePackage.MatchString(s.Package))
	s.Unit = keep(s.Unit, reUnit.MatchString(s.Unit))
	s.Model = keep(s.Model, reModel.MatchString(s.Model))
	return s
}

func opDef(name string) (Op, bool) {
	for _, o := range Registry {
		if o.Name == name {
			return o, true
		}
	}
	return Op{}, false
}

// channelOf is the only source of a NEEDS_SIGNATURE channel: reversible is the only phone input (§5.4).
func channelOf(o Op) string {
	if o.Reversible {
		return "cli_or_phone"
	}
	return "cli"
}

func nonNeg(p *int64) *int64 {
	if p == nil || *p < 0 {
		return nil
	}
	v := *p
	return &v
}

// roundUp15 rounds a reset time (ms) up to 15 minutes (§5.6: resetsAt is rounded so it can't time a sibling).
func roundUp15(p *int64) *int64 {
	p = nonNeg(p)
	if p == nil {
		return nil
	}
	const q = 15 * 60 * 1000
	v := (*p + q - 1) / q * q
	return &v
}

// Deny is the only constructor of a denial (§5.6). It never fails: a slot that fails its grammar, or that the code
// doesn't declare, is dropped and the code is kept. The one exception is a NEEDS_SIGNATURE with no pnd_ id or no
// Cedar op: its id is the pending ask the agent waits on, so without one it is BROKER_UNAVAILABLE.
func Deny(c Code, what string, s Slots) Denial {
	def := codeDefs[c.name]
	if def == nil {
		panic("ops: Deny with a code not in CodeTable: " + c.name) // impossible: Code values come only from codes_gen.go
	}
	op, opOK := opDef(s.Op)
	opOK = opOK && op.Group != "" // denial.v1.json's op enum is the Cedar actions
	if def.Name == "NEEDS_SIGNATURE" && (!opOK || !ids.Is(ids.Pending, s.Pending)) {
		return Deny(BrokerUnavailable, "", Slots{Op: s.Op, By: "forwarder"})
	}
	has := func(slot string) bool { return slices.Contains(def.Slots, slot) }
	d := Denial{V: 1, Code: def.Name, By: def.By[0], Next: def.Next}
	if slices.Contains(def.By, s.By) {
		d.By = s.By
	}
	if opOK {
		d.Op = op.Name
	}
	if d.By == "cedar" && slices.Contains(cedarRules, s.Rule) {
		d.Rule = s.Rule
	}
	if has(slotWhat) {
		for _, x := range def.Whats {
			if x.Name == what {
				d.What, d.Next = x.Name, x.Next
			}
		}
	}
	if sub := s.Subject.clean(); sub != (Subject{}) {
		d.Subject = &sub
	}
	if has(slotReason) && (s.Reason == "tainted" || s.Reason == "signed") {
		d.Reason = s.Reason
	}
	if has(slotTaint) && s.Taint != nil {
		t := *s.Taint
		d.Taint = &t
	}
	if has(slotLimit) {
		d.Limit = nonNeg(s.Limit)
	}
	if has(slotResetsAt) {
		d.ResetsAt = roundUp15(s.ResetsAt)
	}
	if has(slotAsksLeft) {
		d.AsksLeft = nonNeg(s.AsksLeft)
	}
	if has(slotPending) && ids.Is(ids.Pending, s.Pending) {
		d.Pending = s.Pending
	}
	if has(slotOpen) && d.What == "task_open" {
		for _, id := range s.Open {
			if ids.Is(ids.Pending, id) && len(d.Open) < 3 && !slices.Contains(d.Open, id) {
				d.Open = append(d.Open, id)
			}
		}
	}
	if has(slotExpiresAt) {
		d.ExpiresAt = nonNeg(s.ExpiresAt)
	}
	if has(slotNotified) && s.Notified != nil {
		n := *s.Notified
		d.Notified = &n
	}
	if has(slotAfterMs) && def.AfterMs > 0 {
		a := int64(def.AfterMs)
		d.AfterMs = &a
	}
	d.ID = ids.New(ids.Denial)
	if def.Name == "NEEDS_SIGNATURE" {
		d.ID, d.Channel = s.Pending, channelOf(op)
	}
	expect := ""
	if has(slotExpect) && slices.Contains(expects, s.Expect) {
		expect = s.Expect
	}
	render(&d, def, expect)
	return fit(d)
}

// render fills msg and remedy from the table: they hold no byte the caller chose except grammar-checked slots.
func render(d *Denial, def *CodeDef, expect string) {
	d.Msg = renderMsg(d, def)
	kinds := def.Remedy
	if k, ok := def.WhatRemedy[d.What]; ok {
		kinds = k
	}
	d.Remedy = nil
	for _, k := range kinds {
		r := Remedy{Kind: k}
		switch k {
		case RemOp:
			switch {
			case def.Name == "EGRESS_NOT_ALLOWLISTED":
				r.Op, r.Approval = "net.allow_domain", "cli"
				if d.Subject != nil && d.Subject.Host != "" && d.Subject.Port != 0 {
					r.Args = &RemedyArgs{d.Subject.Host, d.Subject.Port}
				}
			case d.Op != "":
				o, _ := opDef(d.Op)
				r.Op, r.Approval = d.Op, channelOf(o)
			default:
				continue
			}
		case RemFix:
			if d.Subject != nil {
				r.Field = d.Subject.Pointer
			}
			r.Expect = expect
		case RemWait:
			r.Pending, r.ExpiresAt, r.Notified, r.Approval = d.ID, d.ExpiresAt, d.Notified, d.Channel
			r.HumanCmd = def.Admin + " " + d.ID
		case RemPoll:
			r.Op, r.AfterMs = "ask.status", int64(def.AfterMs)
		case RemRetry:
			r.AfterMs = int64(def.AfterMs)
		case RemHuman:
			r.Admin = def.Admin
		}
		d.Remedy = append(d.Remedy, r)
	}
	if len(d.Remedy) == 0 {
		d.Remedy = []Remedy{{Kind: RemNone}}
	}
}

func renderMsg(d *Denial, def *CodeDef) string {
	op := d.Op
	if op == "" {
		op = "This request"
	}
	num := func(p *int64) string {
		if p == nil {
			return "?"
		}
		return strconv.FormatInt(*p, 10)
	}
	tm := "?"
	if d.ExpiresAt != nil {
		tm = time.UnixMilli(*d.ExpiresAt).UTC().Format(time.RFC3339)
	}
	m := strings.NewReplacer("{op}", op, "{id}", d.ID, "{channel}", d.Channel, "{time}", tm, "{limit}", num(d.Limit),
		"{afterMs}", num(d.AfterMs)).Replace(def.Msg)
	if len(m) > MaxMsg {
		m = m[:MaxMsg]
	}
	return m
}

// fit keeps a denial within MaxDenial by dropping the subject; nothing else can grow (every other field is short and
// fixed), and a test pins the worst case.
func fit(d Denial) Denial {
	if b, _ := json.Marshal(d); len(b) <= MaxDenial || d.Subject == nil {
		return d
	}
	d.Subject = nil
	for i := range d.Remedy {
		d.Remedy[i].Args, d.Remedy[i].Field = nil, ""
	}
	return d
}

// JSON is the denial's wire form.
func (d Denial) JSON() []byte {
	b, err := json.Marshal(d)
	if err != nil {
		panic(err) // fixed types
	}
	return b
}

// printable reports whether b is printable ASCII (0x20-0x7E) only.
func printable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// ParseDenial reads a denial strictly: printable ASCII, at most MaxDenial bytes, no unknown field, and every field
// exactly what Deny would build from the same slots. So a denial that parses carries only table text and
// grammar-checked values.
func ParseDenial(b []byte) (Denial, error) {
	if len(b) > MaxDenial || !printable(b) {
		return Denial{}, errors.New("not printable ASCII of at most 1 KiB")
	}
	var d Denial
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return Denial{}, err
	}
	if dec.More() {
		return Denial{}, errors.New("trailing data")
	}
	c, ok := LookupCode(d.Code)
	if !ok || d.V != 1 {
		return Denial{}, fmt.Errorf("unknown code %q or version", d.Code)
	}
	if !ids.Is(ids.Denial, d.ID) && !(d.Code == "NEEDS_SIGNATURE" && ids.Is(ids.Pending, d.ID)) {
		return Denial{}, errors.New("bad id")
	}
	want := rebuild(c, d)
	if !bytes.Equal(want.JSON(), d.JSON()) {
		return Denial{}, errors.New("a field differs from what the registry builds")
	}
	return d, nil
}

// rebuild runs Deny on d's own slots and keeps d's id: a field Deny would drop or render differently makes it differ.
func rebuild(c Code, d Denial) Denial {
	s := Slots{Op: d.Op, By: d.By, Rule: d.Rule, Reason: d.Reason, Taint: d.Taint, Limit: d.Limit, ResetsAt: d.ResetsAt,
		AsksLeft: d.AsksLeft, Pending: d.Pending, Open: d.Open, ExpiresAt: d.ExpiresAt, Notified: d.Notified}
	if d.Subject != nil {
		s.Subject = *d.Subject
	}
	if d.Code == "NEEDS_SIGNATURE" {
		s.Pending = d.ID
	}
	for _, r := range d.Remedy {
		if r.Kind == RemFix {
			s.Expect = r.Expect
		}
	}
	x := Deny(c, d.What, s)
	x.ID = d.ID
	render(&x, codeDefs[x.Code], s.Expect)
	return x
}

// SubjectFrom takes the subject from a request's own args: only keep-class structural fields, by name (§5.6 leak rule
// 1). Free-text, hash- and drop-class args never reach it.
func SubjectFrom(op string, args map[string]json.RawMessage) Subject {
	o, ok := opDef(op)
	if !ok {
		return Subject{}
	}
	var s Subject
	for _, f := range o.Args {
		raw, ok := args[f.Name]
		if !ok || f.Audit != Keep {
			continue
		}
		var v string
		var n int64
		if f.Type == "integer" {
			if json.Unmarshal(raw, &n) != nil {
				continue
			}
		} else if json.Unmarshal(raw, &v) != nil {
			continue
		}
		switch f.Name {
		case "host":
			s.Host = v
		case "port":
			s.Port = n
		case "ref", "head":
			s.Ref = v
		case "oid", "srcOid":
			s.OID = v
		case "remote":
			s.Remote = v
		case "app":
			s.App = v
		case "package":
			s.Package = v
		case "unit":
			s.Unit = v
		case "id":
			if op == "workspace.restore" {
				s.Snapshot = v
			}
		}
	}
	return s.clean()
}

// The MCP and gate JSON-RPC surfaces (§5.6 Surfaces).
const (
	DenialPrefix = "agentbox-denial/v1 "
	RPCDenial    = -32010
)

// MCPResult is the tools/call result for a denial: isError and one text block, msg then the JSON. A quarantined
// memory write was stored, so it is not an error.
func MCPResult(d Denial) []byte {
	type text struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	b, _ := json.Marshal(struct {
		Content []text `json:"content"`
		IsError bool   `json:"isError"`
	}{[]text{{"text", d.Msg + "\n" + DenialPrefix + string(d.JSON())}}, d.Code != "MEMORY_QUARANTINED"})
	return b
}

// RPCError is the gate's JSON-RPC error object for a denial.
func RPCError(d Denial) []byte {
	b, _ := json.Marshal(struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    Denial `json:"data"`
	}{RPCDenial, d.Code, d})
	return b
}

// HTTPStatus is the code's HTTP status for the proxy, keys and git surfaces.
func HTTPStatus(c Code) int { return codeDefs[c.name].HTTP }
