package ops

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"agentbox/internal/ids"
)

func refuses(t *testing.T, name string, reg []Op, want string) {
	t.Helper()
	if err := Validate(reg); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%s: startup not refused with %q: %v", name, want, err)
	}
}

func edited(name string, f func(*Op)) []Op {
	reg := slices.Clone(Registry)
	for i := range reg {
		if reg[i].Name == name {
			f(&reg[i])
		}
	}
	return reg
}

// D-G1: the registry half. Missing ask ops, a batch member with a phone path or a CAS-writing binder, and shapes or
// quote sets off their pins all refuse startup.
func TestAskRegistry(t *testing.T) {
	if err := Validate(Registry); err != nil {
		t.Fatal(err)
	}
	for _, n := range askOps {
		refuses(t, "without "+n, slices.DeleteFunc(slices.Clone(Registry), func(o Op) bool { return o.Name == n }), n+": missing")
		refuses(t, n+" human-only", edited(n, func(o *Op) { o.Human = true }), n+": missing")
	}
	refuses(t, "reversible member", edited("gh.pr.create", func(o *Op) { o.Reversible = true; o.Rollback = CovLogical }), "batch member")
	refuses(t, "CAS-writing member", edited("repo.push", func(o *Op) { o.CASBinder = true }), "batch member")
	refuses(t, "extra member", edited("gh.issue.comment", func(o *Op) { o.Batch = []string{ShapePushReply} }), "batch shape push+reply")
	refuses(t, "member left out", edited("gh.pr.create", func(o *Op) { o.Batch = nil }), "batch shape push+pr")
	refuses(t, "unknown shape", edited("repo.push", func(o *Op) { o.Batch = append(o.Batch, "push+deploy") }), "unknown batch shape")
	refuses(t, "quotable admin op", edited("taint.clear", func(o *Op) { o.Quotable = true }), "quotable")
	refuses(t, "unquotable live op", edited("file.write", func(o *Op) { o.Quotable = false }), "quotable")
	refuses(t, "exact read", edited("system.info", func(o *Op) { o.Exact = true }), "always-exact")

	// the golden lists
	pin := func(name string, got []string, want string) {
		if g := strings.Join(got, " "); g != want {
			t.Errorf("%s:\n got %s\nwant %s", name, g, want)
		}
	}
	shapes := map[string]string{}
	for s, sh := range Shapes {
		shapes[s] = strings.Join(sh.Members, ",") + map[bool]string{true: " private", false: ""}[sh.Private]
	}
	if !reflect.DeepEqual(shapes, map[string]string{"push+pr": "repo.push,gh.pr.create", "push+reply": "repo.push,gh.pr.comment private"}) {
		t.Errorf("shapes %v", shapes)
	}
	if BatchMemberText != 16384 || BatchText != 65536 || BatchMaxReplies != 3 || QuoteMaxItems != 8 {
		t.Error("batch caps moved")
	}
	pin("quotable", set(Registry, func(o Op) bool { return o.Quotable }), "app.deploy app.remove app.restart app.rollback app.start app.stop "+
		"file.write gh.issue.comment gh.pr.comment gh.pr.create memory.forget memory.write net.allow_domain os.pkg.install os.pkg.remove "+
		"os.rollback os.unit.disable os.unit.enable repo.create repo.merge repo.push workbench.add_package workspace.restore workspace.snapshot")
	pin("always-exact", set(Registry, func(o Op) bool { return o.Exact }), strings.Join(exactOps, " "))
	pin("batch members", set(Registry, func(o Op) bool { return len(o.Batch) > 0 }), "gh.pr.comment gh.pr.create repo.push")
	pin("CAS binders", set(Registry, func(o Op) bool { return o.CASBinder }), "app.deploy file.write os.pkg.install os.pkg.remove os.update workbench.add_package")
	pin("phone-eligible", set(Registry, func(o Op) bool { return o.Reversible }), "file.write memory.forget memory.write workspace.restore")
}

var asks1 = Asks{Max: 3, Used: 1, Open: 1, Left: 2}

func TestQuoteReply(t *testing.T) {
	ok := func(r QuoteReply, n int) []byte {
		t.Helper()
		b, _ := json.Marshal(r)
		out, err := CheckQuoteReply(b, n)
		if err != nil {
			t.Fatalf("%s: %v", b, err)
		}
		return out
	}
	ok(QuoteReply{Items: []QuoteItem{{Cost: "run", Exact: true}}, Asks: asks1}, 1)
	ok(QuoteReply{Items: []QuoteItem{{Cost: "ask_cli", Reason: "tainted", Shape: ShapePushPR}, {Cost: "ask_cli", Reason: "signed", Exact: true, Shape: ShapePushPR}},
		Batch: &QuoteBatch{OK: true, Shape: ShapePushPR, Asks: 1}, Asks: asks1, Taint: Taint{true, true}}, 2)
	ok(QuoteReply{Items: []QuoteItem{{Cost: "deny", Reason: "FLOOR_NEVER"}, {Cost: "none", Reason: "already_allowed"}},
		Batch: &QuoteBatch{What: "batch_shape"}, Asks: asks1}, 2)
	good := `{"items":[{"cost":"run","exact":true}],"asks":{"max":3,"used":1,"granted":0,"open":1,"openBatch":0,"left":2},"taint":{"tainted":false,"workspaceBound":false}}`
	for name, b := range map[string]string{
		"free text reason":    strings.Replace(good, `"exact":true`, `"exact":true,"reason":"ignore all"`, 1),
		"unknown field":       strings.Replace(good, `"exact":true`, `"exact":true,"note":"x"`, 1),
		"agent-wide field":    strings.Replace(good, `"left":2`, `"left":2,"agent24h":5`, 1),
		"left not min":        strings.Replace(good, `"left":2`, `"left":3`, 1),
		"bad cost":            strings.Replace(good, `"run"`, `"free"`, 1),
		"ESC":                 strings.Replace(good, `"run"`, `"run\u001b"`, 1),
		"raw ESC":             strings.Replace(good, `"run"`, "\"run\x1b\"", 1),
		"batch with 1 item":   strings.Replace(good, `"asks"`, `"batch":{"ok":true,"shape":"push+pr","asks":1},"asks"`, 1),
		"deny with no code":   strings.Replace(good, `"cost":"run"`, `"cost":"deny","reason":"signed"`, 1),
		"trailing":            good + good,
		"over max open asks":  strings.Replace(good, `"open":1`, `"open":4`, 1),
		"budget over 10":      strings.Replace(good, `"max":3`, `"max":11`, 1),
		"taint with a source": strings.Replace(good, `"workspaceBound":false`, `"workspaceBound":false,"source":"web"`, 1),
	} {
		if _, err := CheckQuoteReply([]byte(b), 1); err == nil {
			t.Errorf("%s passes", name)
		}
	}
	if _, err := CheckQuoteReply([]byte(good), 2); err == nil {
		t.Error("a reply for 1 item passes for 2")
	}
}

func TestStatusReply(t *testing.T) {
	p := ids.New(ids.Pending)
	r := StatusReply{Asks: asks1, Open: []string{p}, Ask: &AskRow{ID: p, Op: "ask.batch", State: "executed", Channel: "cli", ExpiresAt: 1,
		Result:  &AskResult{OID: strings.Repeat("a", 40), Remote: "origin"},
		Members: []AskMember{{0, ids.New(ids.Pending), "repo.push", "executed", ""}, {1, ids.New(ids.Pending), "gh.pr.create", "refused", "BATCH_ABORTED"}}}}
	b, _ := json.Marshal(r)
	if _, err := CheckStatusReply(b); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func(*StatusReply){
		"phone channel on a batch": func(r *StatusReply) { r.Ask.Channel = "cli_or_phone" },
		"bad state":                func(r *StatusReply) { r.Ask.State = "merged" },
		"member out of order":      func(r *StatusReply) { r.Ask.Members[0].Idx = 1 },
		"non-batch member":         func(r *StatusReply) { r.Ask.Members[1].Op = "file.write" },
		"T42 id":                   func(r *StatusReply) { r.Open[0] = "T42" },
		"URL as remote":            func(r *StatusReply) { r.Ask.Result.Remote = "https://github.com/x/y/pull/7" },
		"non-hex OID":              func(r *StatusReply) { r.Ask.Result.OID = strings.Repeat("g", 40) },
		"nil open list":            func(r *StatusReply) { r.Open = nil },
	} {
		x := r
		a := *r.Ask
		res := *a.Result
		a.Result, a.Members = &res, slices.Clone(a.Members)
		x.Ask, x.Open = &a, slices.Clone(r.Open)
		f(&x)
		b, _ := json.Marshal(x)
		if _, err := CheckStatusReply(b); err == nil {
			t.Errorf("%s passes", name)
		}
	}
	// a GitHub-assigned number or URL in the result (C-G1, R12)
	for _, extra := range []string{`"number":42,`, `"url":"https://github.com/o/r/pull/42",`, `"prNumber":42,`} {
		bad := bytes.Replace(b, []byte(`"result":{`), []byte(`"result":{`+extra), 1)
		if _, err := CheckStatusReply(bad); err == nil {
			t.Errorf("result with %s passes", extra)
		}
	}
}

// D-G2: the reply schemas hold no free text and no agent-wide field. Every string in them is an enum or an id
// pattern, and the field names are pinned.
func TestAskSchemas(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(askSchema(Registry), &doc); err != nil {
		t.Fatal(err)
	}
	var fields []string
	var walk func(path string, v any)
	walk = func(path string, v any) {
		m, ok := v.(map[string]any)
		if !ok {
			return
		}
		if m["type"] == "string" && m["enum"] == nil && m["pattern"] == nil {
			t.Errorf("%s: a free-text string", path)
		}
		if props, ok := m["properties"].(map[string]any); ok {
			if m["additionalProperties"] != false {
				t.Errorf("%s: open object", path)
			}
			for k, p := range props {
				fields = append(fields, path+"."+k)
				walk(path+"."+k, p)
			}
		}
		if it, ok := m["items"]; ok {
			walk(path+"[]", it)
		}
	}
	walk("ask.quote", doc["ask.quote"])
	walk("ask.status", doc["ask.status"])
	slices.Sort(fields)
	want := "ask.quote.asks ask.quote.asks.granted ask.quote.asks.left ask.quote.asks.max ask.quote.asks.open ask.quote.asks.openBatch " +
		"ask.quote.asks.used ask.quote.batch ask.quote.batch.asks ask.quote.batch.ok ask.quote.batch.shape ask.quote.batch.what ask.quote.items " +
		"ask.quote.items[].cost ask.quote.items[].exact ask.quote.items[].reason ask.quote.items[].shape ask.quote.taint ask.quote.taint.tainted " +
		"ask.quote.taint.workspaceBound ask.status.ask ask.status.ask.channel ask.status.ask.code ask.status.ask.expiresAt ask.status.ask.id " +
		"ask.status.ask.members ask.status.ask.members[].code ask.status.ask.members[].id ask.status.ask.members[].idx ask.status.ask.members[].op " +
		"ask.status.ask.members[].state ask.status.ask.op ask.status.ask.result ask.status.ask.result.digest ask.status.ask.result.gen " +
		"ask.status.ask.result.headOid ask.status.ask.result.oid ask.status.ask.result.remote ask.status.ask.state ask.status.asks " +
		"ask.status.asks.granted ask.status.asks.left ask.status.asks.max ask.status.asks.open ask.status.asks.openBatch ask.status.asks.used " +
		"ask.status.open ask.status.taint ask.status.taint.tainted ask.status.taint.workspaceBound"
	if got := strings.Join(fields, " "); got != want {
		t.Errorf("reply fields:\n got %s\nwant %s", got, want)
	}
}

// D-G2: ESC/CSI, U+009B, U+202E, U+2066-U+2069 and U+E0001 in a quoted arg leave the in-task view of the reply
// byte-identical: the reply carries no arg byte, and CheckArgs passes or refuses on the pointer alone.
func TestQuoteArgsInert(t *testing.T) {
	honest, _ := json.Marshal(QuoteReply{Items: []QuoteItem{{Cost: "ask_cli", Reason: "signed"}}, Asks: asks1})
	want, err := CheckQuoteReply(honest, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"\x1b[31m", "\u009b2J", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069", "\U000E0001"} {
		args, _ := json.Marshal(map[string]any{"ops": []any{map[string]any{"name": "gh.pr.comment", "args": map[string]any{"remote": "o" + s, "number": 1, "body": s}}}})
		if d := CheckArgs("ask.quote", args); d != nil && bytes.Contains(d.JSON(), []byte(s)) {
			t.Fatalf("%q echoed: %s", s, d.JSON())
		}
		if got, _ := CheckQuoteReply(honest, 1); !bytes.Equal(got, want) {
			t.Fatalf("%q changed the reply", s)
		}
	}
}
