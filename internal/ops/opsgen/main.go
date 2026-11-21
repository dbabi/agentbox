// Command opsgen writes the files generated from the op registry (go generate ./internal/ops): gen/cedar.schema,
// gen/ops.schema.json, gen/mcp-tools.json and docs/ops.md, under the repo root given as its one argument.
package main

import (
	"fmt"
	"os"
	"path/filepath"

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
		if name != ops.DocsFile {
			p = filepath.Join(os.Args[1], "gen", name)
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
