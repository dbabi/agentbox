package main

import (
	"errors"
	"flag"
	"os"

	"agentbox/internal/taskrun"
)

// cmdGoPrivate is go.private.set (§5.3), an admin op on rootd-admin.sock.
func cmdGoPrivate(args []string) error {
	if len(args) == 0 || args[0] != "set" {
		return errors.New("goprivate: expected set")
	}
	fs := flag.NewFlagSet("goprivate set", flag.ContinueOnError)
	agent := fs.String("agent", "", "agent name")
	patterns := fs.String("patterns", "", "comma-separated module path globs (GOPRIVATE); \"\" clears them")
	if err := parse(fs, args[1:]); err != nil {
		return err
	}
	if *agent == "" {
		return errors.New("goprivate set: --agent is required")
	}
	return adminCall(map[string]any{"op": "go.private.set", "agent": *agent, "patterns": *patterns}, "goprivate")
}

func cmdWhy(args []string) error { return taskrun.Why(os.Stdout, args) }
