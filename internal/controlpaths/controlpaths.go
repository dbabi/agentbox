// Package controlpaths is the workspace control-path list (ARCHITECTURE.md §4.2 "Workspace control files can't steer
// later tasks"): the files an agent CLI reads as config or instructions. A change to one needs an explicit
// acknowledgement at `taint review` and `agent.attach` (--ack-control-changes). Lockfiles (go.mod, go.sum,
// package-lock.json, ...) are not control paths; the dependency report covers them (§7).
package controlpaths

import (
	"slices"
	"strings"
)

var (
	// Dirs are control paths with everything under them, at any depth of the workspace (one repo per project dir).
	Dirs = []string{".claude", ".codex", ".opencode", ".git", ".devcontainer"}
	// Files are control paths by base name, at any depth.
	Files = []string{".mcp.json", "CLAUDE.md", "AGENTS.md", ".envrc"}
)

// Is reports whether a workspace-relative, slash-separated path is a control path.
func Is(p string) bool {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range segs {
		if slices.Contains(Dirs, s) || (i == len(segs)-1 && slices.Contains(Files, s)) {
			return true
		}
	}
	return false
}

// Changed returns the control paths among changed, in order.
func Changed(changed []string) []string {
	var out []string
	for _, p := range changed {
		if Is(p) {
			out = append(out, p)
		}
	}
	return out
}
