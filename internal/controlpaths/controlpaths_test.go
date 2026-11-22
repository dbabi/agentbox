package controlpaths

import (
	"slices"
	"testing"
)

// A-G2: lockfile-only changes need no --ack-control-changes; a planted .mcp.json still does.
func TestChanged(t *testing.T) {
	if c := Changed([]string{"go.mod", "go.sum", "web/package-lock.json", "proj/go.sum", "src/agents.md.go"}); len(c) != 0 {
		t.Fatalf("lockfiles are control paths: %q", c)
	}
	got := Changed([]string{"go.sum", "proj/.mcp.json", ".claude/skills/x/SKILL.md", "p/.git/hooks/pre-commit", "CLAUDE.md", "a/AGENTS.md", ".envrc", "x/.devcontainer/devcontainer.json"})
	want := []string{"proj/.mcp.json", ".claude/skills/x/SKILL.md", "p/.git/hooks/pre-commit", "CLAUDE.md", "a/AGENTS.md", ".envrc", "x/.devcontainer/devcontainer.json"}
	if !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
}
