package ops

// The denial codes table (ARCHITECTURE.md §5.6). Append-only: gen/codes.golden pins the order, and opsgen refuses to
// rewrite it unless the old list is a prefix of the new one. A bad early name gets an alias row, never a rename.

// Code is a denial code. Its one field is unexported, so the generated values in codes_gen.go are the only codes that
// exist and Deny can take no other.
type Code struct{ name string }

func (c Code) String() string { return c.name }

// Next is what the agent should do (§5.6).
type Next string

const (
	Fix   Next = "fix"   // change the request
	Wait  Next = "wait"  // a human is deciding: agentbox ask wait <id>
	Ask   Next = "ask"   // you may submit the remedy op; a human signs it
	Retry Next = "retry" // after afterMs
	Human Next = "human" // only a human can unblock: report the code and id, and go on without it
	Stop  Next = "stop"  // never retry
)

// Enforcers, the denial's by field.
var enforcers = []string{"gate", "cedar", "floor", "proxy", "keys", "git", "forwarder"}

// What is one entry of a code's closed what list, with its own next.
type What struct {
	Name string
	Next Next
}

// RemedyKind is one of the static remedies of §5.6.
type RemedyKind string

const (
	RemOp    RemedyKind = "op"
	RemFix   RemedyKind = "fix"
	RemWait  RemedyKind = "wait"
	RemPoll  RemedyKind = "poll"
	RemRetry RemedyKind = "retry"
	RemHuman RemedyKind = "human"
	RemNone  RemedyKind = "none"
)

// CodeDef is one row of the table. Msg is one fixed sentence; its only placeholders are {op}, {id}, {channel},
// {time}, {limit} and {afterMs}, filled from grammar-checked slots. Slots lists the slots beyond the common ones (op,
// subject, rule) that a denial of this code may carry. Remedy and Admin are static per code; Whats may override the
// remedy kind per what through WhatRemedy.
type CodeDef struct {
	Name       string
	Next       Next // when the denial carries no what (or one not in Whats)
	By         []string
	HTTP       int
	Msg        string
	Whats      []What
	Slots      []string
	Remedy     []RemedyKind
	WhatRemedy map[string][]RemedyKind
	Admin      string // the human command of a human remedy
	AfterMs    int    // the fixed retry or poll delay, when the code has one
	Note       string // the docs column
}

// The optional slots a code may declare.
const (
	slotWhat      = "what"
	slotReason    = "reason"
	slotTaint     = "taint"
	slotLimit     = "limit"
	slotResetsAt  = "resetsAt"
	slotAsksLeft  = "asksLeft"
	slotPending   = "pending"
	slotOpen      = "open"
	slotChannel   = "channel"
	slotExpiresAt = "expiresAt"
	slotNotified  = "notified"
	slotAfterMs   = "afterMs"
	slotExpect    = "expect"
)

func w(name string, n Next) What { return What{name, n} }

func ws(n Next, names ...string) []What {
	out := make([]What, len(names))
	for i, s := range names {
		out[i] = What{s, n}
	}
	return out
}

func cat(l ...[]What) []What {
	var out []What
	for _, x := range l {
		out = append(out, x...)
	}
	return out
}

var (
	gateFloor = []string{"gate", "floor"}
	floorOnly = []string{"floor"}
	anyBy     = enforcers
	rnone     = []RemedyKind{RemNone}
	rhuman    = []RemedyKind{RemHuman}
	rretry    = []RemedyKind{RemRetry}
	rfix      = []RemedyKind{RemFix}
	rop       = []RemedyKind{RemOp}
)

// CodeTable is the v1 table: 36 codes, in golden order.
var CodeTable = []CodeDef{
	{Name: "INVALID_ARGS", Next: Fix, By: gateFloor, HTTP: 400, Msg: "{op} has an invalid argument: fix the field named in remedy.",
		Slots: []string{slotExpect}, Remedy: rfix, Note: "`field` (JSON pointer) and `expect`; never the value; also a body that contains `agentbox-op:`"},
	{Name: "UNKNOWN_OP", Next: Stop, By: []string{"gate"}, HTTP: 400, Msg: "This op does not exist or no agent may call it.", Remedy: rnone,
		Note: "also any op no agent may call"},
	{Name: "TASK_ENDED", Next: Stop, By: anyBy, HTTP: 409, Msg: "This task has ended.", Remedy: rnone},
	{Name: "NOT_FOUND_OR_NOT_OWNED", Next: Stop, By: []string{"gate", "cedar", "floor", "git"}, HTTP: 404,
		Msg: "{op}: no such item among yours.", Remedy: rnone, Note: "one path (§5.2); at receipt + 200 ms"},
	{Name: "DENIED_POLICY", Next: Stop, By: []string{"cedar"}, HTTP: 403, Msg: "{op} is denied by policy.", Remedy: rnone,
		Note: "`rule` per leak rule 5"},
	{Name: "POLICY_ERROR", Next: Human, By: []string{"cedar"}, HTTP: 500, Msg: "Policy evaluation failed, so {op} is denied.", Remedy: rhuman,
		Admin: "agentbox policy check", Note: "evaluation error; fails closed"},
	{Name: "MEMORY_QUARANTINED", Next: Human, By: []string{"gate"}, HTTP: 202, Msg: "The fact was stored in quarantine; a human may release it.",
		Remedy: rhuman, Admin: "agentbox memory review", Note: "the write was stored in quarantine; MCP `isError: false`"},
	{Name: "CAP_REACHED", Next: Human, By: []string{"gate", "floor", "git"}, HTTP: 429, Msg: "{op} is over a cap of {limit}.",
		Whats: cat(ws(Human, "memory_writes_task", "memory_rows", "memory_bytes", "bus_messages", "artifacts", "push_bytes_day"),
			ws(Stop, "quote_items_task", "quote_items_trace")),
		Slots: []string{slotWhat, slotLimit, slotResetsAt}, Remedy: rhuman, WhatRemedy: map[string][]RemedyKind{"quote_items_task": rnone, "quote_items_trace": rnone},
		Admin: "agentbox budget set"},
	{Name: "BUS_REFUSED", Next: Stop, By: []string{"gate"}, HTTP: 409, Msg: "{op} is refused by a bus limit.",
		Whats: ws(Stop, "hop", "children", "cycle", "deadline", "parent_ended", "not_cancelable"), Slots: []string{slotWhat}, Remedy: rnone},
	{Name: "LEASE_HELD", Next: Retry, By: []string{"gate"}, HTTP: 409, Msg: "The lease is held; retry after {afterMs} ms.",
		Slots: []string{slotAfterMs}, Remedy: rretry, AfterMs: 30000, Note: "`afterMs` 30000; never names the holder"},
	{Name: "NEEDS_SIGNATURE", Next: Wait, By: floorOnly, HTTP: 202,
		Msg:    "{op} waits for a human ({channel}) until {time}. It stays open if your task ends normally. Run: agentbox ask wait {id}.",
		Slots:  []string{slotReason, slotTaint, slotChannel, slotExpiresAt, slotNotified, slotAsksLeft},
		Remedy: []RemedyKind{RemWait, RemPoll}, Admin: "agentbox approve", AfterMs: 30000, Note: "see Asks; at receipt + 2 s"},
	{Name: "ASK_DENIED", Next: Stop, By: floorOnly, HTTP: 403, Msg: "A human denied this ask in this task; do not ask again.",
		Slots: []string{slotPending}, Remedy: rnone, Note: "a human denied this match key in this task; carries the denied row's id"},
	{Name: "ASK_EXPIRED", Next: Ask, By: floorOnly, HTTP: 410, Msg: "The ask for {op} expired; a new ask counts against your budget.",
		Slots: []string{slotAsksLeft}, Remedy: rop},
	{Name: "ASK_CAP", Next: Human, By: floorOnly, HTTP: 429, Msg: "{op} is over an ask cap.",
		Whats: cat([]What{w("task_open", Wait)}, ws(Human, "task_budget", "agent_24h", "agent_ops_24h")),
		Slots: []string{slotWhat, slotOpen, slotResetsAt, slotAsksLeft}, Remedy: rhuman,
		WhatRemedy: map[string][]RemedyKind{"task_open": {RemPoll}}, Admin: "agentbox budget set", AfterMs: 30000},
	{Name: "STALE", Next: Human, By: floorOnly, HTTP: 409, Msg: "{op} is stale: what it was bound to has changed.",
		Whats: cat(ws(Fix, "ref_moved", "cas_changed", "stale_base"), ws(Ask, "policy_changed", "signer_revoked", "approval_expired"),
			[]What{w("taint_moved", Wait), w("remote_changed", Human)}),
		Slots: []string{slotWhat, slotPending}, Remedy: rhuman,
		WhatRemedy: map[string][]RemedyKind{"ref_moved": rfix, "cas_changed": rfix, "stale_base": rfix, "policy_changed": rop,
			"signer_revoked": rop, "approval_expired": rop, "taint_moved": {RemPoll}},
		Admin: "agentbox task show", AfterMs: 30000},
	{Name: "BUSY", Next: Retry, By: floorOnly, HTTP: 503, Msg: "The box is busy; retry after {afterMs} ms.", Slots: []string{slotAfterMs},
		Remedy: rretry, AfterMs: 60000, Note: "OS lock, box CAS-binding cap, disk reserve, box daemon-ask pool; no sub-reason"},
	{Name: "ADMISSION_REJECTED", Next: Fix, By: floorOnly, HTTP: 400, Msg: "{op} is refused at admission.",
		Whats: cat(ws(Fix, "closure_too_large", "context_too_large"), []What{w("own_cas_pending", Wait)},
			ws(Fix, "batch_shape", "batch_remote_not_private", "batch_text_cap", "batch_member_open"), []What{w("batch_open", Wait)}),
		Slots: []string{slotWhat, slotLimit, slotPending}, Remedy: rfix,
		WhatRemedy: map[string][]RemedyKind{"own_cas_pending": {RemPoll}, "batch_open": {RemPoll}}, AfterMs: 30000},
	{Name: "FLOOR_NEVER", Next: Stop, By: floorOnly, HTTP: 403, Msg: "{op} is never allowed on this box.",
		Whats: ws(Stop, "protected_package", "protected_unit", "exposure_443", "vendor_host", "never_available"), Slots: []string{slotWhat}, Remedy: rnone},
	{Name: "HUMAN_ONLY", Next: Human, By: floorOnly, HTTP: 403, Msg: "Only a human can do this.", Whats: ws(Human, "deputy_host"),
		Slots: []string{slotWhat}, Remedy: rhuman, Admin: "agentbox egress allow"},
	{Name: "REF_OUTSIDE_NAMESPACE", Next: Fix, By: []string{"floor", "git"}, HTTP: 403, Msg: "Push only refs under refs/heads/agent/<your name>/.",
		Slots: []string{slotExpect}, Remedy: rfix, Note: "expect `refs/heads/agent/<name>/*`"},
	{Name: "OID_NOT_IN_REMOTE_REPO", Next: Fix, By: floorOnly, HTTP: 400, Msg: "The commit is not in the remote repo: push it through :8082 first.",
		Slots: []string{slotExpect}, Remedy: rfix},
	{Name: "REMOTE_REJECTED", Next: Human, By: floorOnly, HTTP: 502, Msg: "The remote refused {op}.",
		Whats: cat(ws(Fix, "pr_exists", "no_commits"), []What{w("ruleset", Stop)}, ws(Human, "not_found", "other"), ws(Retry, "rate_limited", "unreachable")),
		Slots: []string{slotWhat, slotAfterMs}, Remedy: rhuman,
		WhatRemedy: map[string][]RemedyKind{"pr_exists": rfix, "no_commits": rfix, "ruleset": rnone, "rate_limited": rretry, "unreachable": rretry},
		Admin:      "agentbox task show", AfterMs: 60000, Note: "no GitHub text or status"},
	{Name: "EFFECT_FAILED", Next: Human, By: floorOnly, HTTP: 500, Msg: "{op} failed while running.", Remedy: rhuman, Admin: "agentbox task show",
		Note: "no effect output"},
	{Name: "INDETERMINATE", Next: Human, By: floorOnly, HTTP: 500, Msg: "It is unknown whether {op} took effect; a human resolves it.",
		Remedy: rhuman, Admin: "agentbox op resolve"},
	{Name: "BATCH_ABORTED", Next: Ask, By: floorOnly, HTTP: 409, Msg: "An earlier member of the batch failed or was refused; {op} never ran.",
		Remedy: rop},
	{Name: "NESTED_SUBVOLUME", Next: Human, By: floorOnly, HTTP: 409, Msg: "The workspace holds a nested subvolume, so {op} is refused.",
		Remedy: rhuman, Admin: "agentbox workspace check", Note: "name kept from §4.1"},
	{Name: "AUDIT_UNAVAILABLE", Next: Retry, By: []string{"floor", "proxy", "keys", "git"}, HTTP: 503,
		Msg: "The audit log is unavailable; retry after {afterMs} ms.", Slots: []string{slotAfterMs}, Remedy: rretry, AfterMs: 30000,
		Note: "auditd down or in disk-full mode"},
	{Name: "EGRESS_NOT_ALLOWLISTED", Next: Ask, By: []string{"proxy"}, HTTP: 403, Msg: "This host:port is not on your egress list.",
		Whats: []What{w("deputy_host", Human)}, Slots: []string{slotWhat}, Remedy: rop,
		WhatRemedy: map[string][]RemedyKind{"deputy_host": rhuman}, Admin: "agentbox egress allow",
		Note: "remedy `net.allow_domain{host, port}`, CLI; for a deputy host, `human{agentbox egress allow}`"},
	{Name: "EGRESS_WRONG_ROUTE", Next: Fix, By: []string{"proxy"}, HTTP: 400, Msg: "Wrong route for this request.",
		Whats: ws(Fix, "llm_vendor", "plain_http"), Slots: []string{slotWhat, slotExpect}, Remedy: rfix, Note: "`llm_vendor` (use `:8081`), `plain_http`"},
	{Name: "EGRESS_NAME_REJECTED", Next: Stop, By: []string{"proxy"}, HTTP: 403, Msg: "This name does not resolve to a public address.",
		Whats: ws(Stop, "non_public"), Slots: []string{slotWhat}, Remedy: rnone, Note: "`non_public` only; no IP, no check name"},
	{Name: "EGRESS_RESOLVE_FAILED", Next: Retry, By: []string{"proxy"}, HTTP: 502, Msg: "The name could not be resolved.",
		Whats: []What{w("no_such_name", Fix), w("unavailable", Retry)}, Slots: []string{slotWhat, slotAfterMs}, Remedy: rretry,
		WhatRemedy: map[string][]RemedyKind{"no_such_name": rfix}, AfterMs: 10000},
	{Name: "EGRESS_DIAL_FAILED", Next: Retry, By: []string{"proxy"}, HTTP: 504, Msg: "The connection to the host failed; retry after {afterMs} ms.",
		Whats: ws(Retry, "timeout", "refused", "blocked"), Slots: []string{slotWhat, slotAfterMs}, Remedy: rretry, AfterMs: 10000},
	{Name: "KEYS_REQUEST_REJECTED", Next: Human, By: []string{"keys"}, HTTP: 403, Msg: "The LLM request has a field this box does not allow.",
		Whats: cat(ws(Fix, "max_tokens", "server_tool", "dropped_field"),
			ws(Human, "endpoint", "field", "block_type", "tool_type", "url_field", "source_type", "beta_header", "model")),
		Slots: []string{slotWhat, slotLimit}, Remedy: rhuman,
		WhatRemedy: map[string][]RemedyKind{"max_tokens": rfix, "server_tool": rfix, "dropped_field": rfix}, Admin: "agentbox task show"},
	{Name: "KEYS_BUDGET", Next: Human, By: []string{"keys"}, HTTP: 429, Msg: "Your LLM budget is spent.", Whats: ws(Human, "agent", "trace"),
		Slots: []string{slotWhat, slotResetsAt}, Remedy: rhuman, Admin: "agentbox budget set", Note: "own day share or trace only"},
	{Name: "KEYS_UPSTREAM", Next: Retry, By: []string{"keys"}, HTTP: 502, Msg: "The LLM vendor could not be reached.",
		Whats: cat(ws(Retry, "unreachable", "timeout"), []What{w("auth", Human)}), Slots: []string{slotWhat, slotAfterMs}, Remedy: rretry,
		WhatRemedy: map[string][]RemedyKind{"auth": rhuman}, Admin: "agentbox secret set", AfterMs: 10000},
	{Name: "BROKER_UNAVAILABLE", Next: Retry, By: []string{"forwarder"}, HTTP: 503, Msg: "A box service is unavailable; retry after {afterMs} ms.",
		Whats: ws(Retry, "gate", "egress", "llm", "git"), Slots: []string{slotWhat, slotAfterMs}, Remedy: rretry, AfterMs: 5000,
		Note: "also a gate reply that fails the in-task check"},
}

// codeDefs indexes CodeTable by name.
var codeDefs = func() map[string]*CodeDef {
	m := map[string]*CodeDef{}
	for i := range CodeTable {
		m[CodeTable[i].Name] = &CodeTable[i]
	}
	return m
}()

// LookupCode returns the generated Code named n.
func LookupCode(n string) (Code, bool) {
	for _, c := range genCodes {
		if c.name == n {
			return c, true
		}
	}
	return Code{}, false
}
