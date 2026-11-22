package ops

import "strings"

// FixedLines are the eight lines every generated CLAUDE.md and AGENTS.md carries (ARCHITECTURE.md §8 Exports). They
// are release constants, not memory, so they are the same for every agent.
var FixedLines = []string{
	"Blocked actions return agentbox-denial/v1 <JSON> (an MCP tool error, an HTTP error body, or a git remote: line). Act on its next field.",
	"next: fix = change the request; wait = a human is deciding, run agentbox ask wait <id>; ask = you may submit the remedy op; retry = after afterMs; human or stop = don't retry, report it.",
	"A call that fails with no detail (bare 403, CONNECT tunnel failed, timeout, name resolution failure): run agentbox why.",
	"Before acting, quote your whole plan once with ask.quote. Send a push and its PR (or, on a private remote, a push and its replies to one PR) as one ask.batch.",
	"Your task has a small ask budget; ask.status shows it. Don't submit an op again while it is open. If an ask is denied or the budget is spent, stop at the local branch and report.",
	"Open asks stay open if your task ends normally, until they expire. They die if your task fails or is canceled.",
	"Go modules come from a read-only cache. If go reports GOPROXY=off, this agent has no module access: report it; only a human can enable it.",
	"List every blocked action in your final result as op, code and id.",
}

// Exports are the generated instruction files in control/exports/<agent>/ (§8 Exports), each ending with the fixed
// lines. Claude's CLAUDE.md imports the procedural export; INSTRUCTIONS.md itself is memory's (weeks 13-14).
func Exports() map[string][]byte {
	fixed := strings.Join(FixedLines, "\n") + "\n"
	return map[string][]byte{
		"CLAUDE.md": []byte("@/opt/agentbox/exports/INSTRUCTIONS.md\n\n" + fixed),
		"AGENTS.md": []byte(fixed),
	}
}
