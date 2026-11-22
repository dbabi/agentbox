package taskrun

import (
	"fmt"
	"io"
	"strings"

	"agentbox/internal/ops"
)

// Errno is the fixed guidance `agentbox why --errno <E>` prints for limits that carry no denial code (§5.6 Surfaces).
var Errno = map[string]string{
	"EOPNOTSUPP": "The task's seccomp profile refuses btrfs ioctls (subvolume, snapshot, clone). " +
		"Copy files instead: cp --reflink=auto falls back to a plain copy. Snapshots come only from workspace ops.",
	"EDQUOT": "This agent's disk quota is full. Delete files you made in /workspace, or report it: only a human can raise the quota.",
	"EROFS": "Only /workspace, /tmp and $HOME are writable in a task. Everything else, including the socket and witness " +
		"dirs under /run/agentbox, is read-only.",
	"ENETUNREACH": "Tasks have no network of their own. HTTPS goes through HTTPS_PROXY=http://127.0.0.1:8080 (already " +
		"set); the LLM through 127.0.0.1:8081 and git through 127.0.0.1:8082.",
	"EAI_AGAIN": "Tasks have no DNS: a direct name lookup fails at once. Use HTTPS_PROXY (already set), which resolves " +
		"allowlisted names for you. A refused name returns a denial; run agentbox why.",
	"EAGAIN": "The task hit its process limit (pids). Wait for child processes to exit, or run fewer at once.",
}

// Why is `agentbox why [<CODE> | --errno <E>]`: the task's recent denials, a code's fixed guidance, or an errno's. It
// makes no gate call.
func Why(out io.Writer, args []string) error {
	switch {
	case len(args) == 0:
		ds := Recent(LogPath(), 10)
		if len(ds) == 0 {
			fmt.Fprintln(out, "No denials logged in this task. For a call that failed with only an errno, run: agentbox why --errno <E>")
		}
		for _, d := range ds {
			printDenial(out, d)
		}
		return nil
	case len(args) == 2 && args[0] == "--errno":
		g, ok := Errno[strings.ToUpper(args[1])]
		if !ok {
			return fmt.Errorf("why: no guidance for errno %q (known: EOPNOTSUPP, EDQUOT, EROFS, ENETUNREACH, EAI_AGAIN, EAGAIN)", args[1])
		}
		fmt.Fprintf(out, "%s: %s\n", strings.ToUpper(args[1]), g)
		return nil
	case len(args) == 1 && !strings.HasPrefix(args[0], "-"):
		for _, c := range ops.CodeTable {
			if c.Name == args[0] {
				fmt.Fprintf(out, "%s: next %s. %s\n", c.Name, c.Next, c.Msg)
				for _, w := range c.Whats {
					fmt.Fprintf(out, "  what %s: next %s\n", w.Name, w.Next)
				}
				fmt.Fprintf(out, "  %s\n", nextHelp[c.Next])
				return nil
			}
		}
		return fmt.Errorf("why: unknown code %q", args[0])
	}
	return fmt.Errorf("usage: agentbox why [<CODE> | --errno <E>]")
}

// nextHelp is the second fixed line of the generated CLAUDE.md and AGENTS.md, one move at a time.
var nextHelp = map[ops.Next]string{
	ops.Fix: "fix: change the request.", ops.Wait: "wait: a human is deciding; run agentbox ask wait <id>.",
	ops.Ask: "ask: you may submit the remedy op; a human signs it.", ops.Retry: "retry: after afterMs.",
	ops.Human: "human: don't retry; report the code and id, and go on without it.", ops.Stop: "stop: don't retry; report it.",
}

// printDenial shows one logged denial. The log is task-writable help text, so only printable ASCII is shown.
func printDenial(out io.Writer, d ops.Denial) {
	line := d.Code
	if d.What != "" {
		line += "{" + d.What + "}"
	}
	line += " next=" + string(d.Next) + " by=" + d.By + " id=" + d.ID
	if d.Op != "" {
		line += " op=" + d.Op
	}
	if s := d.Subject; s != nil && s.Host != "" {
		line += fmt.Sprintf(" host=%s:%d", s.Host, s.Port)
	}
	fmt.Fprintln(out, safe(line))
	fmt.Fprintln(out, "  "+safe(d.Msg))
	for _, r := range d.Remedy {
		rem := "  remedy: " + string(r.Kind)
		switch {
		case r.Op != "" && r.Args != nil:
			rem += fmt.Sprintf(" %s{host: %s, port: %d} (%s)", r.Op, r.Args.Host, r.Args.Port, r.Approval)
		case r.Op != "":
			rem += " " + r.Op
		case r.AfterMs > 0:
			rem += fmt.Sprintf(" after %d ms", r.AfterMs)
		case r.Admin != "":
			rem += " (a human runs: " + r.Admin + ")"
		}
		fmt.Fprintln(out, safe(rem))
	}
}

func safe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, s)
}
