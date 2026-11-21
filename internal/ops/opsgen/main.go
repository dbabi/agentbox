// Command opsgen writes the files generated from the op registry and the codes table (go generate ./internal/ops)
// under the repo root given as its one argument: gen/ (the shipped schemas and codes.golden), docs/ops.md,
// docs/denials.md and internal/ops/codes_gen.go. It refuses to rewrite codes.golden except by appending.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"agentbox/internal/ops"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: opsgen <repo root>")
		os.Exit(2)
	}
	if err := ops.Validate(ops.Registry); err != nil {
		fmt.Fprintln(os.Stderr, "opsgen:", err)
		os.Exit(1)
	}
	for name, b := range ops.Generate(ops.Registry) {
		p := filepath.Join(os.Args[1], name)
		if !strings.Contains(name, "/") {
			p = filepath.Join(os.Args[1], "gen", name)
		}
		if name == ops.GoldenFile {
			if old, err := os.ReadFile(p); err == nil {
				if err := ops.AppendOnly(old, b); err != nil {
					fmt.Fprintln(os.Stderr, "opsgen:", err)
					os.Exit(1)
				}
			}
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "opsgen:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "opsgen:", err)
			os.Exit(1)
		}
	}
}
