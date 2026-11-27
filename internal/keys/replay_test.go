package keys

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The replay corpus (#18): the requests the pinned Claude Code and Codex sent in hack/keys-gate.sh, through the
// in-task forwarder to keys and on to the vendors' stand-in, which keeps each body. -record turns that file into
// testdata/replay: the shape of each request with its text replaced (every string but the closed-vocabulary ones the
// schema reads), so the corpus holds no prompt, tool description or system text. TestReplay checks that keys passes
// every one; TestReplayPins ties the corpus to the CLI versions the gates pin, so a version bump fails here until the
// keys gate runs again with the new CLI and the corpus is recorded anew.
var record = flag.String("record", "", "hack/keys-gate.sh's .vm/keysgate/requests.jsonl: write testdata/replay from it")

type replayed struct {
	CLI   string          `json:"cli"`
	Path  string          `json:"path"`
	Query string          `json:"query"`
	Beta  []string        `json:"beta"`
	Body  json.RawMessage `json:"body"`
}

// keep are the keys whose string values the schema reads; every other string becomes "x".
var keep = []string{"type", "role", "model", "effort", "display", "ttl", "detail", "verbosity", "summary", "generate_summary",
	"service_tier", "truncation", "tool_choice", "include", "prompt_cache_retention", "status", "mode"}

func scrub(v any, parent string) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			x[k] = scrub(e, k)
		}
		return x
	case []any:
		for i, e := range x {
			x[i] = scrub(e, parent)
		}
		return x
	case string:
		switch {
		case slices.Contains(keep, parent):
			return x
		case strings.HasPrefix(x, "data:"):
			return "data:x"
		}
		return "x"
	}
	return v
}

var reUA = regexp.MustCompile(`^(claude-cli|codex_cli_rs|codex_exec)/([0-9][0-9.]*)`)

func TestReplay(t *testing.T) {
	dir := filepath.Join("testdata", "replay")
	if *record != "" {
		writeReplay(t, dir)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) == 0 {
		t.Fatal("no replay corpus: run hack/keys-gate.sh checks, then go test ./internal/keys -run TestReplay -record <.vm/keysgate/requests.jsonl>")
	}
	clis := map[string]int{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var r replayed
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		ep, ok := endpoints[map[string]string{"/v1/messages": "/anthropic", "/v1/messages/count_tokens": "/anthropic"}[r.Path]+r.Path]
		if !ok {
			ep, ok = endpoints["/openai"+r.Path]
		}
		if !ok || !(r.Query == "" || ep.betaQuery && r.Query == "beta=true") {
			t.Errorf("%s: %s %s?%s is no keys endpoint", f, r.CLI, r.Path, r.Query)
			continue
		}
		if rj := checkBetas(r.Beta, betas); rj != nil {
			t.Errorf("%s: %s: beta refused: %+v", f, r.CLI, *rj)
		}
		body := []byte(r.Body)
		if string(body) == "null" {
			body = nil
		}
		if _, rj := validate(ep, body, nil); rj != nil {
			t.Errorf("%s: %s: refused: %+v", f, r.CLI, *rj)
		}
		clis[strings.Fields(r.CLI)[0]]++
	}
	if clis["claude-cli"] == 0 || clis["codex_cli_rs"]+clis["codex_exec"] == 0 {
		t.Errorf("the corpus needs both CLIs: %v", clis)
	}
}

// writeReplay keeps the CLIs' requests from the stand-in's record, scrubbed, one file each.
func writeReplay(t *testing.T, dir string) {
	b, err := os.ReadFile(*record)
	if err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var rec struct {
			Path, Query string
			Headers     map[string]string
			Body        json.RawMessage
		}
		if json.Unmarshal([]byte(l), &rec) != nil {
			continue
		}
		m := reUA.FindStringSubmatch(rec.Headers["user-agent"])
		if m == nil {
			continue // the gate's own curl requests
		}
		var body any
		json.Unmarshal(rec.Body, &body)
		sb, _ := json.Marshal(scrub(body, ""))
		var beta []string
		if v := rec.Headers["anthropic-beta"]; v != "" {
			beta = []string{v}
		}
		out, _ := json.MarshalIndent(replayed{CLI: m[1] + " " + m[2], Path: rec.Path, Query: rec.Query, Beta: beta, Body: sb}, "", " ")
		n++
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%02d-%s.json", n, m[1])), append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("recorded %d requests into %s", n, dir)
}

// TestReplayPins: the corpus was recorded with the CLI versions hack/keys-gate.sh and hack/cli-gate.sh pin.
func TestReplayPins(t *testing.T) {
	pins := map[string]string{}
	for _, g := range []string{"keys-gate.sh", "cli-gate.sh"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "hack", g))
		if err != nil {
			t.Fatal(err)
		}
		cc := regexp.MustCompile(`CC=anthropic-ai-claude-code-linux-arm64-([0-9.]+)\.tgz`).FindSubmatch(b)
		cx := regexp.MustCompile(`CX=openai-codex-([0-9.]+)-linux-arm64\.tgz`).FindSubmatch(b)
		if cc == nil || cx == nil {
			t.Fatalf("%s: no CC= or CX= pin", g)
		}
		for k, v := range map[string]string{"claude-cli": string(cc[1]), "codex": string(cx[1])} {
			if p, ok := pins[k]; ok && p != v {
				t.Fatalf("%s pins %s %s, another gate %s", g, k, v, p)
			}
			pins[k] = v
		}
	}
	files, _ := filepath.Glob(filepath.Join("testdata", "replay", "*.json"))
	for _, f := range files {
		var r replayed
		b, _ := os.ReadFile(f)
		json.Unmarshal(b, &r)
		name, ver, _ := strings.Cut(r.CLI, " ")
		if strings.HasPrefix(name, "codex") {
			name = "codex"
		}
		if pins[name] != ver {
			t.Errorf("%s was recorded with %s, but the gates pin %s %s: run hack/keys-gate.sh checks and record the corpus again", f, r.CLI, name, pins[name])
		}
	}
}
