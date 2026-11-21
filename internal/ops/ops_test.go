package ops

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const genDir = "../../gen"

// TestGenerated is the golden test: the checked-in generated files are what the registry generates now.
func TestGenerated(t *testing.T) {
	for name, want := range Generate(Registry) {
		p := filepath.Join(genDir, name)
		if name == DocsFile {
			p = filepath.Join("../..", name)
		}
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s is stale (%v): run go generate ./internal/ops", p, err)
		}
	}
	if err := Check(genDir); err != nil {
		t.Fatal(err)
	}
}

func set(reg []Op, keep func(Op) bool) []string {
	var n []string
	for _, o := range sorted(reg) {
		if keep(o) {
			n = append(n, o.Name)
		}
	}
	return n
}

func TestGoldenSets(t *testing.T) {
	for _, c := range []struct {
		name string
		keep func(Op) bool
		want string
	}{
		{"phone-eligible (reversible)", func(o Op) bool { return o.Reversible }, "file.write memory.forget memory.write workspace.restore"},
		{"taintsOutput", func(o Op) bool { return o.TaintsOutput }, "app.logs gh.issue.read gh.pr.read"},
		{"workspaceBindable", func(o Op) bool { return o.WorkspaceBindable }, "memory.forget memory.write"},
		{"bus and memory ops", func(o Op) bool { return strings.HasPrefix(o.Name, "bus.") || strings.HasPrefix(o.Name, "memory.") },
			"bus.agents.list bus.inbox.ack bus.inbox.read bus.lease.acquire bus.lease.heartbeat bus.lease.release bus.message.send " +
				"bus.task.cancel bus.task.claim bus.task.get bus.task.send bus.task.update memory.forget memory.purge memory.read memory.review memory.write"},
		{"not Cedar-gated", func(o Op) bool { return o.Group == "" },
			"agent.add agent.attach agent.remove agent.skills.set approver.add approver.remove budget.set cache.purge go.private.set memory.purge " +
				"memory.review op.resolve passkey.confirm passkey.register passkey.revoke pending.deny policy.set procedural.set push.policy.set " +
				"remote.set secret.set taint.clear update.policy.set"},
		{"Cedar but no MCP tool", func(o Op) bool { return o.Group != "" && !slices.Contains(names(mcpOps(Registry)), o.Name) }, "os.update"},
		{"remote writes", func(o Op) bool { return o.Rollback == CovExternal || o.Name == "repo.push" }, "gh.issue.comment gh.pr.comment gh.pr.create repo.push"},
	} {
		if got := strings.Join(set(Registry, c.keep), " "); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
	for _, n := range []string{"ask.quote", "ask.status", "ask.batch"} {
		if !slices.Contains(names(mcpOps(Registry)), n) {
			t.Errorf("%s is not an MCP tool", n)
		}
	}
}

// TestAuditClasses pins every non-keep field (§9 defaults).
func TestAuditClasses(t *testing.T) {
	var got []string
	for _, o := range sorted(Registry) {
		for _, f := range o.Args {
			if f.Audit != Keep {
				got = append(got, o.Name+"."+f.Name+"="+string(f.Audit))
			}
		}
		for _, f := range o.Out {
			if f.Audit != Keep {
				got = append(got, o.Name+".out."+f.Name+"="+string(f.Audit))
			}
		}
	}
	want := "app.logs.out.log=hash file.write.content=hash gh.issue.comment.body=hash gh.issue.read.out.issue=hash gh.pr.comment.body=hash gh.pr.create.title=hash " +
		"gh.pr.create.body=hash gh.pr.read.out.pr=hash memory.write.title=hash memory.write.body=hash secret.set.value=drop"
	if g := strings.Join(got, " "); g != want {
		t.Errorf("non-keep fields:\n got %s\nwant %s", g, want)
	}
}

func TestAskLines(t *testing.T) {
	for name, want := range map[string]string{"app.status": askNever, "bus.task.send": askNever, "file.write": askPhone, "memory.write": askPhone,
		"workspace.restore": askPhone, "gh.pr.create": askAlways, "ask.batch": askAlways, "repo.push": askPush} {
		i := slices.IndexFunc(Registry, func(o Op) bool { return o.Name == name })
		if got := askLine(Registry[i]); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
}

func edit(name string, f func(*Op)) []Op {
	reg := slices.Clone(Registry)
	for i := range reg {
		if reg[i].Name == name {
			f(&reg[i])
		}
	}
	return reg
}

func TestValidateRefuses(t *testing.T) {
	if err := Validate(Registry); err != nil {
		t.Fatal(err)
	}
	for name, reg := range map[string][]Op{
		"reversible without coverage": edit("repo.push", func(o *Op) { o.Reversible = true }),
		"reversible with n/a":         edit("app.start", func(o *Op) { o.Reversible = true; o.Rollback = CovNA }),
		"taintsOutput with keep out":  edit("gh.pr.read", func(o *Op) { o.Out = fields(obj("pr")) }),
		"taintsOutput on a write":     edit("file.write", func(o *Op) { o.TaintsOutput = true; o.Out = fields(str("x").hash()) }),
		"bindable rootd op":           edit("file.write", func(o *Op) { o.WorkspaceBindable = true }),
		"unsigned live op":            edit("gh.pr.create", func(o *Op) { o.Sig = SigNone }),
		"signed read":                 edit("app.status", func(o *Op) { o.Sig = SigAlways }),
		"wrong group":                 edit("memory.write", func(o *Op) { o.Group = GSafe }),
		"admin op as Cedar action":    edit("secret.set", func(o *Op) { o.Group = GSideEffect }),
		"agent op with no resource":   edit("app.start", func(o *Op) { o.Resource = nil }),
		"tool with no description":    edit("app.start", func(o *Op) { o.Desc = "" }),
		"duplicate field":             edit("file.write", func(o *Op) { o.Args = append(o.Args, str("path")) }),
		"bad audit class":             edit("file.write", func(o *Op) { o.Args = fields(str("path"), Field{Name: "content", Type: "string"}) }),
		"duplicate op":                append(slices.Clone(Registry), Registry[0]),
		"bad name":                    append(slices.Clone(Registry), admin("Bad", SigNone)),
	} {
		if err := Validate(reg); err == nil {
			t.Errorf("%s: Validate passed", name)
		}
	}
}

func copyGen(t *testing.T) string {
	d := t.TempDir()
	for _, f := range []string{CedarFile, SchemaFile, MCPFile} {
		b, err := os.ReadFile(filepath.Join(genDir, f))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(d, f), b, 0o644)
	}
	return d
}

// TestCheckRefuses is the gate's unit half: every kind of registry mismatch refuses startup.
func TestCheckRefuses(t *testing.T) {
	rewrite := func(f, old, new string) func(string) {
		return func(d string) {
			p := filepath.Join(d, f)
			b, _ := os.ReadFile(p)
			if !bytes.Contains(b, []byte(old)) {
				t.Fatalf("%s: no %q", f, old)
			}
			os.WriteFile(p, bytes.Replace(b, []byte(old), []byte(new), 1), 0o644)
		}
	}
	for name, c := range map[string]struct {
		tamper func(string)
		reg    []Op
		want   string
	}{
		"one byte":            {tamper: rewrite(CedarFile, "Bool", "Boo1"), want: "differs"},
		"action dropped":      {tamper: rewrite(CedarFile, `  action "file.write" in [SideEffect] appliesTo { principal: [Agent, Human], resource: [Path], context: Ctx };`+"\n", ""), want: "missing file.write"},
		"action added":        {tamper: rewrite(CedarFile, "}\n", `  action "file.delete" in [SideEffect] appliesTo { principal: [Agent, Human], resource: [Path], context: Ctx };`+"\n}\n"), want: "extra file.delete"},
		"action renamed":      {tamper: rewrite(CedarFile, `"bus.task.send"`, `"task.delegate"`), want: "missing bus.task.send, extra task.delegate"},
		"schema renamed":      {tamper: rewrite(SchemaFile, `"memory.write": {`, `"memory.propose": {`), want: "missing memory.write, extra memory.propose"},
		"audit class changed": {tamper: rewrite(SchemaFile, `"x-agentbox-audit": "drop"`, `"x-agentbox-audit": "keep"`), want: "differs"},
		"tool renamed":        {tamper: rewrite(MCPFile, `"name": "ask.quote"`, `"name": "ask.quot"`), want: "missing ask.quote, extra ask.quot"},
		"tool duplicated":     {tamper: rewrite(MCPFile, `"name": "ask.quote"`, `"name": "ask.status"`), want: "missing ask.quote"},
		"bad JSON":            {tamper: func(d string) { os.WriteFile(filepath.Join(d, MCPFile), []byte("{"), 0o644) }, want: "unexpected end"},
		"file missing":        {tamper: func(d string) { os.Remove(filepath.Join(d, SchemaFile)) }, want: "no such file"},
		"extra file":          {tamper: func(d string) { os.WriteFile(filepath.Join(d, "x.json"), nil, 0o644) }, want: "not a generated file"},
		"registry has more":   {reg: append(slices.Clone(Registry), admin("extra.op", SigNone)), want: "missing extra.op"},
		"registry invalid":    {reg: edit("repo.push", func(o *Op) { o.Reversible = true }), want: "reversible"},
	} {
		d := copyGen(t)
		if c.tamper != nil {
			c.tamper(d)
		}
		reg := c.reg
		if reg == nil {
			reg = Registry
		}
		err := CheckFiles(reg, d)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error with %q", name, err, c.want)
		}
	}
}
