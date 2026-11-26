package main

import (
	"errors"
	"flag"
	"io"
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

// cmdCache is cache.purge's CLI: the agent's Go module cache empties, its fills in flight cancelled.
func cmdCache(args []string) error {
	if len(args) == 0 || args[0] != "purge" {
		return errors.New("cache: expected purge")
	}
	fs := flag.NewFlagSet("cache purge", flag.ContinueOnError)
	agent := fs.String("agent", "", "agent name")
	if err := parse(fs, args[1:]); err != nil {
		return err
	}
	if *agent == "" {
		return errors.New("cache purge: --agent is required")
	}
	return adminCall(map[string]any{"op": "cache.purge", "agent": *agent}, "cache purge")
}

// cmdBudget is budget.set's CLI: the whole budgets.toml, from --file or standard input.
func cmdBudget(args []string) error {
	if len(args) == 0 || args[0] != "set" {
		return errors.New("budget: expected set")
	}
	fs := flag.NewFlagSet("budget set", flag.ContinueOnError)
	file := fs.String("file", "", "the new budgets.toml (default: standard input)")
	if err := parse(fs, args[1:]); err != nil {
		return err
	}
	var b []byte
	var err error
	if *file == "" {
		b, err = io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
	} else {
		b, err = os.ReadFile(*file)
	}
	if err != nil {
		return err
	}
	return adminCall(map[string]any{"op": "budget.set", "budgets": string(b)}, "budget set")
}

func cmdWhy(args []string) error { return taskrun.Why(os.Stdout, args) }
