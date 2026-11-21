package main

import (
	"flag"
	"fmt"
	"os"

	"agentbox/internal/sockets"
)

// cmdSockets is `agentbox sockets check`: the live box against the §2.1 inventory, one line per mismatch.
func cmdSockets(args []string) error {
	if len(args) == 0 || args[0] != "check" {
		return fmt.Errorf("sockets: expected check\n%s", usage)
	}
	fs := flag.NewFlagSet("sockets check", flag.ContinueOnError)
	root := fs.String("root", "/", "the tree to check")
	if err := parse(fs, args[1:]); err != nil {
		return err
	}
	bad := sockets.Check(*root, sockets.Inventory())
	for _, b := range bad {
		fmt.Println(b)
	}
	if len(bad) > 0 {
		return fmt.Errorf("sockets check: %d mismatches with the §2.1 inventory", len(bad))
	}
	fmt.Fprintln(os.Stderr, "sockets check: the box matches the §2.1 inventory")
	return nil
}
