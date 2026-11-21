package ops

//go:generate go run ./opsgen ../..

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// The generated files rootd and agentboxd check, in the release's gen/ dir.
const (
	CedarFile  = "cedar.schema"
	SchemaFile = "ops.schema.json"
	MCPFile    = "mcp-tools.json"
	// DocsFile is repo-relative; it is not shipped, so only the golden test checks it.
	DocsFile = "docs/ops.md"
)

// Shipped is every file a release ships in gen/, and all that CheckFiles allows there.
var Shipped = []string{CedarFile, SchemaFile, MCPFile}

const header = "Code generated from internal/ops/registry.go by go generate; DO NOT EDIT."

// The ask-cost lines that start every MCP tool description (§5.1).
const (
	askNever  = "Never asks a human."
	askPhone  = "Asks (1 of your task's ask budget) when this task is tainted or policy requires; CLI or phone."
	askAlways = "Always asks (1 of your task's ask budget); laptop CLI only."
	// Not in §5.1's list: the two signature rules its three lines misstate (app.deploy, workspace.restore).
	askChanged     = "Asks (1 of your task's ask budget) when the manifest or exposure changes or this task is tainted; laptop CLI only."
	askAlwaysPhone = "Always asks (1 of your task's ask budget); CLI or phone."
	askPush        = "Asks unless a standing push policy covers this private remote and the task is clean; CLI only. Send it with its PR as one ask.batch."
)

// The rollback coverage a reversible op needs (§5.1 Reversible check).
var reversibleCov = []Coverage{CovLogical, CovWS, CovCAS}

var reName = regexp.MustCompile(`^[a-z]+(\.[a-z_]+)+$`)

// Validate is the registry's own startup check (§5.1): the field rules that hold for every op, whatever the generated
// files say. Each error names the op.
func Validate(reg []Op) error {
	var errs []error
	bad := func(o Op, f string, a ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", o.Name, fmt.Sprintf(f, a...)))
	}
	seen := map[string]bool{}
	for _, o := range reg {
		if !reName.MatchString(o.Name) {
			bad(o, "bad op name")
		}
		if seen[o.Name] {
			bad(o, "declared twice")
		}
		seen[o.Name] = true
		want := map[Class][]Group{Read: {GRead, GCoord}, Coord: {GCoord}, Safe: {GSafe}, Live: {GSideEffect}, OS: {GSideEffect},
			Agentboxd: {GSideEffect}, Admin: {""}}[o.Class]
		if want == nil {
			bad(o, "unknown class %q", o.Class)
		} else if !slices.Contains(want, o.Group) {
			bad(o, "class %s with Cedar group %q", o.Class, o.Group)
		}
		if (o.Group == "") != (len(o.Resource) == 0) {
			bad(o, "a Cedar action needs a resource type, and an admin op has none")
		}
		if tool := o.Group != "" && !o.Human; tool == (o.Desc == "") {
			bad(o, "every op an agent may submit needs a description, and no other op has one")
		}
		switch o.Class {
		case Read, Coord, Safe:
			if o.Sig != SigNone {
				bad(o, "a %s op never needs a signature", o.Class)
			}
		case Live, OS, Agentboxd:
			if o.Sig == SigNone || o.Sig == "" {
				bad(o, "the taint rule needs a signature on every tainted %s op (§5.3)", o.Class)
			}
		}
		if o.Sig != SigNone && len(o.Bound) == 0 {
			bad(o, "a signed op needs bound inputs for H (§5.1)")
		}
		if o.Reversible && !slices.Contains(reversibleCov, o.Rollback) {
			bad(o, "reversible with rollback coverage %q (needs logical, workspace or CAS-revert)", o.Rollback)
		}
		if o.TaintsOutput && (o.Class != Read || len(o.Out) == 0) {
			bad(o, "taintsOutput is for read ops with declared outputs")
		}
		for _, f := range o.Out {
			if o.TaintsOutput && f.Audit == Keep {
				bad(o, "output %s of a tainting read must be hash or drop class (§9)", f.Name)
			}
		}
		if o.WorkspaceBindable && (o.Rollback != CovLogical || o.Rootd || o.Group != GSideEffect) {
			bad(o, "workspaceBindable needs logical rollback, agentboxd alone executing it and no remote effect (§5.1)")
		}
		for _, fs := range [][]Field{o.Args, o.Out} {
			seen := map[string]bool{}
			for _, f := range fs {
				if seen[f.Name] {
					bad(o, "field %s declared twice", f.Name)
				}
				seen[f.Name] = true
				if !slices.Contains([]string{"string", "integer", "boolean", "array", "object"}, f.Type) {
					bad(o, "field %s: unknown type %q", f.Name, f.Type)
				}
				if !slices.Contains([]Audit{Keep, Hash, Drop, Members}, f.Audit) {
					bad(o, "field %s: unknown audit class %q", f.Name, f.Audit)
				}
				if (f.Audit == Members) != (f.Name == "ops") || f.Audit == Members && f.Type != "array" {
					bad(o, "field %s: an array of other ops (ops) is members class, and nothing else is (§9)", f.Name)
				}
			}
		}
	}
	return errors.Join(errs...)
}

func sorted(reg []Op) []Op {
	s := slices.Clone(reg)
	sort.Slice(s, func(i, j int) bool { return s[i].Name < s[j].Name })
	return s
}

// cedarOps are the Cedar actions: every op with a group. mcpOps are the MCP tools: those an agent may submit.
func cedarOps(reg []Op) []Op {
	return slices.DeleteFunc(sorted(reg), func(o Op) bool { return o.Group == "" })
}

func mcpOps(reg []Op) []Op {
	return slices.DeleteFunc(cedarOps(reg), func(o Op) bool { return o.Human })
}

func names(reg []Op) []string {
	n := make([]string, len(reg))
	for i, o := range reg {
		n[i] = o.Name
	}
	return n
}

func cedar(reg []Op) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "// %s\n// ARCHITECTURE.md §5.1, Appendix D.\nnamespace Agentbox {\n%s  action Read, Safe, SideEffect, Coordination;\n", header, cedarHead)
	for _, o := range cedarOps(reg) {
		p := "Agent, Human"
		if o.Human {
			p = "Human"
		}
		fmt.Fprintf(&b, "  action %q in [%s] appliesTo { principal: [%s], resource: [%s], context: Ctx };\n", o.Name, o.Group, p, strings.Join(o.Resource, ", "))
	}
	b.WriteString("}\n")
	return b.Bytes()
}

type prop struct {
	Type  string  `json:"type"`
	Audit Audit   `json:"x-agentbox-audit"`
	Items *member `json:"items,omitempty"`
}

// member is the item schema of a members-class array: args are classed by op name's own args schema.
type member struct {
	Type     string         `json:"type"`
	Props    map[string]typ `json:"properties"`
	Required []string       `json:"required"`
}

type typ struct {
	Type string `json:"type"`
}

var memberItem = &member{"object", map[string]typ{"name": {"string"}, "args": {"object"}}, []string{"name", "args"}}

type schema struct {
	Schema     string          `json:"$schema,omitempty"`
	Type       string          `json:"type"`
	Props      map[string]prop `json:"properties"`
	Required   []string        `json:"required,omitempty"`
	Additional bool            `json:"additionalProperties"`
}

func objSchema(fs []Field, top bool) schema {
	s := schema{Type: "object", Props: map[string]prop{}}
	if top {
		s.Schema = "https://json-schema.org/draft/2020-12/schema"
	}
	for _, f := range fs {
		p := prop{Type: f.Type, Audit: f.Audit}
		if f.Audit == Members {
			p.Items = memberItem
		}
		s.Props[f.Name] = p
		if !f.Opt {
			s.Required = append(s.Required, f.Name)
		}
	}
	return s
}

func marshal(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err) // only fixed types above
	}
	return append(b, '\n')
}

func schemas(reg []Op) []byte {
	doc := struct {
		Comment string            `json:"$comment"`
		Args    map[string]schema `json:"args"`
		Outputs map[string]schema `json:"outputs"`
	}{header + " ARCHITECTURE.md §5.1, §9: x-agentbox-audit is the field's audit class.", map[string]schema{}, map[string]schema{}}
	for _, o := range reg {
		doc.Args[o.Name] = objSchema(o.Args, true)
		if len(o.Out) > 0 {
			doc.Outputs[o.Name] = objSchema(o.Out, true)
		}
	}
	return marshal(doc)
}

// askLine is the op's ask-cost line. A reversible op is the only kind a phone may approve (§5.4).
func askLine(o Op) string {
	switch {
	case o.Sig == SigNone:
		return askNever
	case o.Sig == SigPolicy:
		return askPush
	case o.Sig == SigChanged:
		return askChanged
	case o.Reversible && o.Sig == SigAlways:
		return askAlwaysPhone
	case o.Reversible:
		return askPhone
	}
	return askAlways
}

type tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema schema `json:"inputSchema"`
}

func mcp(reg []Op) []byte {
	doc := struct {
		Comment string `json:"$comment"`
		Tools   []tool `json:"tools"`
	}{Comment: header + " ARCHITECTURE.md §5.1: the MCP tools/list entries."}
	for _, o := range mcpOps(reg) {
		doc.Tools = append(doc.Tools, tool{o.Name, askLine(o) + " " + o.Desc, objSchema(o.Args, false)})
	}
	return marshal(doc)
}

func yes(b bool) string {
	if b {
		return "yes"
	}
	return ""
}

func fieldList(fs []Field) string {
	var s []string
	for _, f := range fs {
		n := f.Name
		if f.Opt {
			n += "?"
		}
		if f.Audit != Keep {
			n += " (" + string(f.Audit) + ")"
		}
		s = append(s, n)
	}
	return strings.Join(s, ", ")
}

func docs(reg []Op) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "<!-- %s -->\n# Op registry\n\nEvery op, from `internal/ops/registry.go` (ARCHITECTURE.md §5.1, §5.3). Args and outputs show their audit class when it is not `keep` (§9).\n\n", header)
	b.WriteString("| Op | Class | Cedar group | Resource | Args | Outputs | Signature | Bound inputs | Rollback coverage | Reversible | Taints output | Workspace-bindable | Reaches rootd |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, o := range sorted(reg) {
		g, res, bound := string(o.Group), strings.Join(o.Resource, ", "), strings.Join(o.Bound, "; ")
		if g == "" {
			g = "n/a"
		}
		if o.Human {
			res += " (human only)"
		}
		if o.ResourceFrom != "" {
			res += " from `" + o.ResourceFrom + "`"
		}
		if bound == "" {
			bound = "n/a"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", o.Name, o.Class, g, res, fieldList(o.Args),
			fieldList(o.Out), o.Sig, bound, o.Rollback, yes(o.Reversible), yes(o.TaintsOutput), yes(o.WorkspaceBindable), yes(o.Rootd))
	}
	return b.Bytes()
}

// Generate returns every generated file, keyed by its name in gen/ (DocsFile is repo-relative).
func Generate(reg []Op) map[string][]byte {
	return map[string][]byte{CedarFile: cedar(reg), SchemaFile: schemas(reg), MCPFile: mcp(reg), DocsFile: docs(reg)}
}

var reAction = regexp.MustCompile(`(?m)^  action "([^"]+)"`)

// fileNames reads the op names a generated file declares.
func fileNames(name string, b []byte) ([]string, error) {
	var n []string
	switch name {
	case CedarFile:
		for _, m := range reAction.FindAllSubmatch(b, -1) {
			n = append(n, string(m[1]))
		}
	case SchemaFile:
		var d struct{ Args map[string]json.RawMessage }
		if err := json.Unmarshal(b, &d); err != nil {
			return nil, err
		}
		for k := range d.Args {
			n = append(n, k)
		}
	case MCPFile:
		var d struct{ Tools []struct{ Name string } }
		if err := json.Unmarshal(b, &d); err != nil {
			return nil, err
		}
		for _, t := range d.Tools {
			n = append(n, t.Name)
		}
	}
	slices.Sort(n)
	return n, nil
}

// diff names what one sorted name list has and the other lacks.
func diff(want, got []string) string {
	var s []string
	for _, w := range want {
		if !slices.Contains(got, w) {
			s = append(s, "missing "+w)
		}
	}
	for _, g := range got {
		if !slices.Contains(want, g) {
			s = append(s, "extra "+g)
		}
	}
	if len(got) != len(slices.Compact(slices.Clone(got))) {
		s = append(s, "a name declared twice")
	}
	return strings.Join(s, ", ")
}

// CheckFiles is the startup bijection check (§5.1) of reg against the generated files in dir: reg passes Validate, dir
// holds exactly the three generated files, each declares exactly reg's ops, and each is byte-identical to what reg
// generates now.
func CheckFiles(reg []Op, dir string) error {
	if err := Validate(reg); err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	gen := Generate(reg)
	want := map[string][]string{CedarFile: names(cedarOps(reg)), SchemaFile: names(sorted(reg)), MCPFile: names(mcpOps(reg))}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if _, ok := want[e.Name()]; !ok {
			return fmt.Errorf("%s: not a generated file", filepath.Join(dir, e.Name()))
		}
	}
	for _, f := range Shipped {
		p := filepath.Join(dir, f)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		got, err := fileNames(f, b)
		if err != nil {
			return fmt.Errorf("%s: %v", p, err)
		}
		if d := diff(want[f], got); d != "" {
			return fmt.Errorf("%s does not match the registry one to one: %s", p, d)
		}
		if !bytes.Equal(b, gen[f]) {
			return fmt.Errorf("%s differs from what the registry generates (run go generate ./internal/ops)", p)
		}
	}
	return nil
}

// Check is CheckFiles for this binary's Registry.
func Check(dir string) error { return CheckFiles(Registry, dir) }
