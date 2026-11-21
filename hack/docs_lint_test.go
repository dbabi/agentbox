package hack

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// runDocsLint runs docs-lint.sh under dash on the given files and returns its findings, one "file:line: rule" each.
func runDocsLint(t *testing.T, files ...string) []string {
	t.Helper()
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash not installed")
	}
	out, err := exec.Command(dash, append([]string{"docs-lint.sh"}, files...)...).Output()
	if _, ok := err.(*exec.ExitError); err != nil && !ok {
		t.Fatal(err)
	}
	if (err == nil) != (len(out) == 0) {
		t.Fatalf("exit status %v does not match the findings:\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if lines[0] == "" {
		return nil
	}
	return lines
}

// TestDocsLintRules: each rule fires on its bad line, and only there. Evidence in a fenced code block or in
// Testing-and-Gates.md passes.
func TestDocsLintRules(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "exists.md"), nil, 0o644)
	bad := []struct{ rule, line string }{
		{"plan-version", "This follows design v5.3."},
		{"staffing", "Two engineers build it."},
		{"schedule", "The 16-week plan ends in March."},
		{"phase-weeks", "The rows are phases, not weeks."},
		{"proposal-letter", "Proposal B adds a cache."},
		{"planning-record", "See LEDGER.md for the reason."},
		{"finding-id", "This fixes finding-12."},
		{"plan-section", "As in plan §4.2."},
		{"author-path", "Run it from /" + "Users/someone/src."},
		{"private-key", "-----BEGIN " + "OPENSSH PRIVATE KEY-----"},
		{"commit-evidence", "The gate passed at `fb89de4`."},
		{"suite-id", "The w3-firewall suite runs it."},
		{"gate-count", "All 54 checks passed."},
		{"broken-link", "Read [the guide](missing.md)."},
	}
	good := []string{
		"# A page",
		"Read [the guide](exists.md#a-heading), [the site](https://example.com) and [the top](#a-page).",
		"<img src=\"exists.md\" alt=\"\">",
		"Install Ubuntu Server 26.04.1 with agentbox v0.0.1. The taint ledger keeps every row.",
		"```sh",
		"git show fb89de4 # at `fb89de4`, the w3-firewall suite: 54 checks passed",
		"[nothing](missing-in-code.md)",
		"```",
		"[ref]: exists.md",
	}
	var text []string
	var want []string
	for i, b := range bad {
		text = append(text, b.line)
		f := filepath.Join(dir, "page.md") + ":" + strconv.Itoa(i+1) + ": " + b.rule
		if b.rule == "broken-link" {
			f += " missing.md"
		}
		want = append(want, f)
	}
	text = append(text, good...)
	page := filepath.Join(dir, "page.md")
	os.WriteFile(page, []byte(strings.Join(text, "\n")+"\n"), 0o644)
	got := runDocsLint(t, page)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	tg := filepath.Join(dir, "Testing-and-Gates.md")
	os.WriteFile(tg, []byte("| `w3-firewall` | Passed: 54 checks passed | at `fb89de4` |\n"), 0o644)
	if got := runDocsLint(t, tg); got != nil {
		t.Errorf("evidence in Testing-and-Gates.md must pass: %q", got)
	}
}

// TestDocsLintFirstReadme: the first public README is the reference. Only its schedule lines break the standard.
func TestDocsLintFirstReadme(t *testing.T) {
	f := filepath.Join("testdata", "docs-lint", "readme-first.md")
	var got []string
	for _, l := range runDocsLint(t, f) {
		if !strings.Contains(l, ": broken-link ") { // its links point at files that have moved since
			got = append(got, l)
		}
	}
	sort.Strings(got)
	want := []string{f + ":23: schedule", f + ":265: schedule", f + ":267: schedule"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestDocsLintRepo: the docs in this checkout pass.
func TestDocsLintRepo(t *testing.T) {
	if got := runDocsLint(t); got != nil {
		t.Errorf("hack/docs-lint.sh fails on the repo docs:\n%s", strings.Join(got, "\n"))
	}
}
