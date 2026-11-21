# agentbox site: shared content and the terminal app

One content source feeds the website and the terminal app.

- `content/NN-slug.md`: one file per tab. Front matter (`key`, `slug`, `title`, `pose`, `sources`), then a line subset: `# comment`, `$ command`, `- bullet`, `1. step`, `> CAUTION: text`, `[text](url)` links, `[built]` style status tags, ``` blocks and `{{palette}}`.
- `content/snib/`: byte-for-byte copies of the mascot grids. A test fails if they drift from `mascot/`.
- `content/content.go`: parses the pages once. It lives next to the files because `go:embed` cannot reach outside its directory.
- `internal/snib`: adds the Highlight die-cut ring and renders a pose as 24-bit half blocks, ASCII or inline SVG.

Each page lists its `sources`. A test checks that every source path exists. When a source doc changes, review the page.

```sh
go test ./...
go run . -plain security     # plain text, for screen readers and pipes
go run . -art guarding       # Snib only; NO_COLOR=1 gives the ASCII map
go test ./internal/snib -update   # rewrite the render goldens, then review the diff
```

This module is separate from the OS module, so the OS module keeps its own dependency list.
