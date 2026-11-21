package ops

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/format"
	"regexp"
	"slices"
	"strings"
)

// The files generated from the codes table and the ask registry fields (§5.1, §5.6).
const (
	DenialFile = "denial.v1.json"     // the denial schema, shipped
	DenyFile   = "audit-deny.v1.json" // the DENY and DENY_FLOOD audit record schemas, shipped
	AskFile    = "ask.v1.json"        // the ask.quote and ask.status reply schemas and the ask.batch shapes, shipped
	// Repo-relative, not shipped.
	GoldenFile    = "gen/codes.golden"
	CodesGoFile   = "internal/ops/codes_gen.go"
	DenialDocFile = "docs/denials.md"
)

// goName is a code's Go name: INVALID_ARGS is InvalidArgs.
func goName(code string) string {
	var b strings.Builder
	for _, w := range strings.Split(strings.ToLower(code), "_") {
		b.WriteString(strings.ToUpper(w[:1]) + w[1:])
	}
	return b.String()
}

func codesGo(t []CodeDef) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "// %s\n\npackage ops\n\n// The denial codes (§5.6), one per CodeTable row.\nvar (\n", header)
	for _, c := range t {
		fmt.Fprintf(&b, "\t%s = Code{%q}\n", goName(c.Name), c.Name)
	}
	b.WriteString(")\n\n// genCodes is every generated code in table order; Validate checks it against CodeTable.\nvar genCodes = []Code{")
	for i, c := range t {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(goName(c.Name))
	}
	b.WriteString("}\n")
	out, err := format.Source(b.Bytes())
	if err != nil {
		panic(err)
	}
	return out
}

func golden(t []CodeDef) []byte {
	var b bytes.Buffer
	for _, c := range t {
		b.WriteString(c.Name + "\n")
	}
	return b.Bytes()
}

// AppendOnly checks that the new golden list only appends to the old one: codes are never renamed, removed or
// reordered (§5.1).
func AppendOnly(old, new []byte) error {
	o, n := strings.Fields(string(old)), strings.Fields(string(new))
	if len(n) < len(o) || !slices.Equal(n[:len(o)], o) {
		return errors.New("codes are append-only: gen/codes.golden must stay a prefix of the codes table")
	}
	return nil
}

type js = map[string]any

func enum[T ~string](v []T) js { return js{"type": "string", "enum": v} }

// Grammars as JSON schema patterns; the Go checks in denial.go are the ones enforced.
var subjectSchema = js{"type": "object", "additionalProperties": false, "properties": js{
	"host":     js{"type": "string", "maxLength": 253, "pattern": `^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`},
	"port":     js{"type": "integer", "minimum": 1, "maximum": 65535},
	"ref":      js{"type": "string", "pattern": reRef.String()},
	"oid":      js{"type": "string", "pattern": reOID.String()},
	"remote":   js{"type": "string", "pattern": reRemote.String()},
	"app":      js{"type": "string", "pattern": reApp.String()},
	"snapshot": js{"type": "string", "pattern": `^snap_[0-7][0-9A-HJKMNP-TV-Z]{25}$`},
	"pointer":  js{"type": "string", "pattern": rePointer.String()},
	"package":  js{"type": "string", "pattern": rePackage.String()},
	"unit":     js{"type": "string", "pattern": reUnit.String()},
	"model":    js{"type": "string", "pattern": reModel.String()},
}}

var (
	idPnd     = js{"type": "string", "pattern": `^pnd_[0-7][0-9A-HJKMNP-TV-Z]{25}$`}
	nonNegInt = js{"type": "integer", "minimum": 0}
	boolean   = js{"type": "boolean"}
	taintSch  = js{"type": "object", "additionalProperties": false, "required": []string{"tainted", "workspaceBound"},
		"properties": js{"tainted": boolean, "workspaceBound": boolean}}
)

func codeNames(t []CodeDef) []string {
	n := make([]string, len(t))
	for i, c := range t {
		n[i] = c.Name
	}
	return n
}

func allWhats(t []CodeDef) []string {
	var w []string
	for _, c := range t {
		for _, x := range c.Whats {
			if !slices.Contains(w, x.Name) {
				w = append(w, x.Name)
			}
		}
	}
	slices.Sort(w)
	return w
}

// channels is every signed op's NEEDS_SIGNATURE channel, from reversible (§5.4).
func channels(reg []Op) map[string]string {
	m := map[string]string{}
	for _, o := range cedarOps(reg) {
		if o.Sig != SigNone {
			m[o.Name] = channelOf(o)
		}
	}
	return m
}

func denialSchema(reg []Op, t []CodeDef) []byte {
	codes := js{}
	for _, c := range t {
		wh := js{}
		for _, x := range c.Whats {
			wh[x.Name] = x.Next
		}
		codes[c.Name] = js{"next": c.Next, "by": c.By, "http": c.HTTP, "msg": c.Msg, "whats": wh, "slots": c.Slots, "remedy": c.Remedy}
	}
	remedy := js{"type": "object", "additionalProperties": false, "required": []string{"kind"}, "properties": js{
		"kind": enum([]RemedyKind{RemOp, RemFix, RemWait, RemPoll, RemRetry, RemHuman, RemNone}), "op": enum(names(cedarOps(reg))),
		"args": js{"type": "object", "additionalProperties": false, "required": []string{"host", "port"},
			"properties": js{"host": subjectSchema["properties"].(js)["host"], "port": subjectSchema["properties"].(js)["port"]}},
		"approval": enum([]string{"cli", "cli_or_phone"}), "field": subjectSchema["properties"].(js)["pointer"], "expect": enum(expects),
		"pending": js{"type": "string", "pattern": `^(dn|pnd)_[0-7][0-9A-HJKMNP-TV-Z]{25}$`}, "expiresAt": nonNegInt, "notified": boolean,
		"human": js{"type": "string", "pattern": `^agentbox approve pnd_[0-7][0-9A-HJKMNP-TV-Z]{25}$`}, "afterMs": nonNegInt,
		"admin": js{"type": "string", "pattern": `^agentbox [a-z ]{1,40}$`}}}
	doc := js{
		"$schema": "https://json-schema.org/draft/2020-12/schema", "$comment": header + " ARCHITECTURE.md §5.6.",
		"title": "agentbox denial v1", "type": "object", "additionalProperties": false, "maxLength": MaxDenial,
		"required": []string{"v", "id", "code", "by", "next", "msg", "remedy"},
		"properties": js{
			"v": js{"const": 1}, "id": js{"type": "string", "pattern": `^(dn|pnd)_[0-7][0-9A-HJKMNP-TV-Z]{25}$`}, "code": enum(codeNames(t)),
			"by": enum(enforcers), "rule": enum(cedarRules), "op": enum(names(cedarOps(reg))), "next": enum([]Next{Fix, Wait, Ask, Retry, Human, Stop}),
			"subject": subjectSchema, "what": enum(allWhats(t)), "reason": enum([]string{"tainted", "signed"}), "taint": taintSch,
			"limit": nonNegInt, "resetsAt": nonNegInt, "asksLeft": nonNegInt, "pending": idPnd,
			"open": js{"type": "array", "maxItems": 3, "items": idPnd}, "channel": enum([]string{"cli", "cli_or_phone"}),
			"expiresAt": nonNegInt, "notified": boolean, "afterMs": nonNegInt,
			"msg":    js{"type": "string", "maxLength": MaxMsg, "pattern": `^[ -~]*$`},
			"remedy": js{"type": "array", "minItems": 1, "maxItems": 3, "items": remedy},
		},
		"x-agentbox-codes":    codes,
		"x-agentbox-channels": channels(reg),
	}
	return marshal(doc)
}

func denySchema(reg []Op, t []CodeDef) []byte {
	keep1k := js{"type": "string", "maxLength": 1024}
	doc := js{
		"$schema": "https://json-schema.org/draft/2020-12/schema", "$comment": header + " ARCHITECTURE.md §9: what auditd's sink accepts.",
		"DENY": js{"type": "object", "additionalProperties": false, "required": []string{"id", "code", "by", "count", "first", "last"},
			"properties": js{"id": js{"type": "string", "pattern": `^(dn|pnd)_[0-7][0-9A-HJKMNP-TV-Z]{25}$`}, "code": enum(codeNames(t)),
				"what": enum(allWhats(t)), "by": enum(enforcers), "task": js{"type": "string", "pattern": `^task_[0-7][0-9A-HJKMNP-TV-Z]{25}$`},
				"agent": js{"type": "string", "pattern": reAgent.String()}, "op": enum(names(sorted(reg))), "subject": subjectSchema,
				"args":   js{"type": "object", "description": "the op's args with its audit classes applied: hash fields as {sha256, len}, no drop field"},
				"detail": keep1k, "count": js{"type": "integer", "minimum": 1}, "first": nonNegInt, "last": nonNegInt}},
		"DENY_FLOOD": js{"type": "object", "additionalProperties": false, "required": []string{"by", "count"},
			"properties": js{"task": js{"type": "string", "pattern": `^task_[0-7][0-9A-HJKMNP-TV-Z]{25}$`}, "by": enum(enforcers),
				"count": js{"type": "integer", "minimum": 1}}},
	}
	return marshal(doc)
}

func askSchema(reg []Op) []byte {
	asks := js{"type": "object", "additionalProperties": false, "required": []string{"max", "used", "granted", "open", "openBatch", "left"},
		"properties": js{"max": nonNegInt, "used": nonNegInt, "granted": nonNegInt, "open": nonNegInt, "openBatch": nonNegInt, "left": nonNegInt}}
	var states, shapes, batchOps []string
	states = askStates
	for s := range Shapes {
		shapes = append(shapes, s)
	}
	slices.Sort(shapes)
	var admission []string
	for _, x := range codeDefs["ADMISSION_REJECTED"].Whats {
		admission = append(admission, x.Name)
	}
	var quotable, exact []string
	for _, o := range sorted(reg) {
		if len(o.Batch) > 0 {
			batchOps = append(batchOps, o.Name)
		}
		if o.Quotable {
			quotable = append(quotable, o.Name)
		}
		if o.Exact {
			exact = append(exact, o.Name)
		}
	}
	reasons := append([]string{"tainted", "signed", "unchecked", "shared_scope", "already_allowed"}, codeNames(CodeTable)...)
	quote := js{"type": "object", "additionalProperties": false, "required": []string{"items", "asks", "taint"}, "properties": js{
		"items": js{"type": "array", "minItems": 1, "maxItems": QuoteMaxItems, "items": js{"type": "object", "additionalProperties": false,
			"required": []string{"cost", "exact"}, "properties": js{"cost": enum(quoteCosts), "reason": enum(reasons), "exact": boolean,
				"shape": enum(shapes)}}},
		"batch": js{"type": "object", "additionalProperties": false, "required": []string{"ok"},
			"properties": js{"ok": boolean, "shape": enum(shapes), "asks": js{"const": 1}, "what": enum(admission)}},
		"asks": asks, "taint": taintSch}}
	member := js{"type": "object", "additionalProperties": false, "required": []string{"idx", "id", "op", "state"},
		"properties": js{"idx": nonNegInt, "id": idPnd, "op": enum(batchOps), "state": enum(states), "code": enum(codeNames(CodeTable))}}
	status := js{"type": "object", "additionalProperties": false, "required": []string{"asks", "taint", "open"}, "properties": js{
		"asks": asks, "taint": taintSch, "open": js{"type": "array", "maxItems": 3, "items": idPnd},
		"ask": js{"type": "object", "additionalProperties": false, "required": []string{"id", "op", "state", "channel", "expiresAt"},
			"properties": js{"id": idPnd, "op": enum(names(cedarOps(reg))), "state": enum(states), "code": enum(codeNames(CodeTable)),
				"channel": enum([]string{"cli", "cli_or_phone"}), "expiresAt": nonNegInt,
				"result": js{"type": "object", "additionalProperties": false, "description": "agentbox-generated outputs only (§5.3)",
					"properties": js{"oid": js{"type": "string", "pattern": reOID.String()}, "headOid": js{"type": "string", "pattern": reOID.String()},
						"digest": js{"type": "string", "pattern": "^[0-9a-f]{64}$"}, "gen": nonNegInt, "remote": js{"type": "string", "pattern": reRemote.String()}}},
				"members": js{"type": "array", "maxItems": 1 + BatchMaxReplies, "items": member}}}}}
	shapeDoc := js{}
	for _, s := range shapes {
		shapeDoc[s] = js{"members": Shapes[s].Members, "privateRemote": Shapes[s].Private}
	}
	doc := js{
		"$schema": "https://json-schema.org/draft/2020-12/schema", "$comment": header + " ARCHITECTURE.md §5.1, §5.2, §5.4.",
		"ask.quote": quote, "ask.status": status,
		"ask.batch": js{"shapes": shapeDoc, "maxReplies": BatchMaxReplies, "memberTextBytes": BatchMemberText, "batchTextBytes": BatchText},
		"quotable":  quotable, "alwaysExact": exact,
	}
	return marshal(doc)
}

func denialDocs(t []CodeDef) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "<!-- %s -->\n# Denial codes\n\nEvery code an agent can see, from `internal/ops/codes.go` (ARCHITECTURE.md §5.6). This is also the `agentbox why` text. Codes are append-only.\n\n", header)
	b.WriteString("| Code | next | By | HTTP | Message | what (next) | Remedy | Notes |\n|---|---|---|---|---|---|---|---|\n")
	for _, c := range t {
		var wh []string
		for _, x := range c.Whats {
			wh = append(wh, fmt.Sprintf("`%s` (%s)", x.Name, x.Next))
		}
		var rem []string
		for _, k := range c.Remedy {
			s := string(k)
			if k == RemHuman && c.Admin != "" {
				s += "{" + c.Admin + "}"
			}
			rem = append(rem, s)
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %d | %s | %s | %s | %s |\n", c.Name, c.Next, strings.Join(c.By, ", "), c.HTTP, c.Msg,
			strings.Join(wh, ", "), strings.Join(rem, ", "), c.Note)
	}
	return b.Bytes()
}

// validateCodes is the codes half of the startup check: the table, the generated constants and every channel agree.
func validateCodes(t []CodeDef, gen []Code) []error {
	var errs []error
	if !slices.Equal(codeNames(t), func() []string {
		n := make([]string, len(gen))
		for i, c := range gen {
			n[i] = c.name
		}
		return n
	}()) {
		errs = append(errs, errors.New("codes: the generated constants do not match CodeTable one to one (run go generate ./internal/ops)"))
	}
	seen := map[string]bool{}
	for _, c := range t {
		bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf("code %s: %s", c.Name, fmt.Sprintf(f, a...))) }
		if seen[c.Name] || !reCode.MatchString(c.Name) {
			bad("bad or repeated name")
		}
		seen[c.Name] = true
		if len(c.By) == 0 || len(c.Remedy) == 0 || len(c.Remedy) > 3 || c.Msg == "" || len(c.Msg) > MaxMsg || !printable([]byte(c.Msg)) {
			bad("needs enforcers, 1 to 3 remedies and a printable message of at most %d bytes", MaxMsg)
		}
		for _, by := range c.By {
			if !slices.Contains(enforcers, by) {
				bad("unknown enforcer %q", by)
			}
		}
		if (len(c.Whats) > 0) != slices.Contains(c.Slots, slotWhat) {
			bad("a what list and the what slot go together")
		}
		for k := range c.WhatRemedy {
			if !slices.ContainsFunc(c.Whats, func(x What) bool { return x.Name == k }) {
				bad("remedy for unknown what %q", k)
			}
		}
		if slices.Contains(c.Remedy, RemRetry) && c.AfterMs == 0 {
			bad("a retry remedy needs afterMs")
		}
	}
	return errs
}

var (
	reCode  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,40}$`)
	reAgent = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
)

// checkChannels reads the channel map of a shipped denial schema: every channel must equal its op's reversible flag.
func checkChannels(reg []Op, b []byte) error {
	var d struct {
		C map[string]string `json:"x-agentbox-channels"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return err
	}
	want := channels(reg)
	for op, ch := range d.C {
		if want[op] != ch {
			return fmt.Errorf("NEEDS_SIGNATURE channel %q for %s disagrees with its reversible flag", ch, op)
		}
	}
	if len(d.C) != len(want) {
		return errors.New("the NEEDS_SIGNATURE channel map does not cover every signed op")
	}
	return nil
}
