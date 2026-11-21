# agentbox site: shared content and the terminal app

One content source feeds the website and the terminal app.

- `content/NN-slug.md`: one file per tab. Front matter (`key`, `slug`, `title`, `pose`, `sources`), then a line subset: `# comment`, `$ command`, `- bullet`, `1. step`, `> CAUTION: text`, `[text](url)` links, `[built]` style status tags, ``` blocks and `{{palette}}`.
- `content/snib/`: byte-for-byte copies of the mascot grids. A test fails if they drift from `mascot/`.
- `content/content.go`: parses the pages once. It lives next to the files because `go:embed` cannot reach outside its directory.
- `internal/snib`: adds the Highlight die-cut ring and renders a pose as 24-bit half blocks, ASCII or inline SVG.
- `internal/tui`: the Bubble Tea app. Tabs on top, one pane, a status and prompt line. Press `?` for the keys.
- `internal/serve`: the same app over SSH with Charm Wish.

Each page lists its `sources`. A test checks that every source path exists. When a source doc changes, review the page.

```sh
go test ./...
go run .                     # the terminal app; -page security starts on a tab, -motion=false stops the idle loop
go run . -plain security     # plain text, for screen readers and pipes
go run . -art guarding       # Snib only; NO_COLOR=1 gives the ASCII map
go test ./internal/snib -update   # rewrite the render goldens, then review the diff
```

## Colour

Colours are the Snib palette hexes. Bubble Tea downsamples them to 256 or 16 colours when the terminal needs it.
With NO_COLOR or a dumb terminal, Snib becomes an ASCII map. The active tab always has brackets and the cursor
line always has a `▌` bar, so no state depends on colour.

## SSH

```sh
go run . serve               # listens on 127.0.0.1:23234
ssh -p 23234 -t 127.0.0.1 security
```

The server is for anonymous readers, so it has no login. It is locked down in code:

- It listens on 127.0.0.1 by default. `-listen` or `AGENTBOX_SITE_LISTEN` can change that, and it logs a warning
  for a non-loopback address. Nothing here deploys it.
- The host key is a new in-memory ed25519 key per start. `-host-key <path>` uses a file instead, and is refused
  inside a git work tree. `.gitignore` lists `id_ed25519*`.
- Sessions get only the read-only TUI, and a PTY is required. The only exec commands are the 7 page names.
  There is no shell, no port forwarding, no subsystem (so no SFTP or SCP) and no agent forwarding. The SSH library
  still answers "yes" to an agent request, but the server never opens an agent channel. A test checks this.
- Limits: 32 open connections, one session per connection, 5 new sessions per IP then 1 per second, a 10 s
  handshake, a 120 s idle cutoff and a 30 min cap. The window size the client sends is capped at 500x300, and
  prompt input at 64 characters. The TUI shows a sleeping Snib after 110 s with no key and ends the session 10 s later.
- Session logs hold the start, the end, the duration, the end reason (`refused` for an exec, a missing PTY or a
  second session) and the first 8 hex of a salted SHA-256 of the remote IP. They never hold the command, env,
  keys, terminal type or typed input. The SSH library logs the remote address on a panic; `serve` redacts it.

## Dependencies

Dependencies are pinned in `go.mod` and `go.sum`. To change one:

```sh
go get <module>@<version> && go mod tidy
```

On a network that cannot reach proxy.golang.org, prefix both with `GOPROXY=direct GONOSUMDB=charm.land,github.com/charmbracelet`.

This module is separate from the OS module, so the OS module keeps its own dependency list. CI runs gofmt, vet,
tests, staticcheck and govulncheck on it in the `site` job.

Every dependency is MIT, BSD-3-Clause or Apache-2.0, except `github.com/hashicorp/golang-lru/v2`, which is MPL-2.0
and used unmodified. `rivo/uniseg`,
`charmbracelet/ultraviolet` and `golang.org/x/exp` are pseudo-versions because charm's own `go.mod` pins them so.

`go run github.com/dbabi/agentbox/site/tui@latest` resolves to the default branch, so it works only once this
module is on `main`.

## The website

`cmd/sitegen` renders the same pages to static HTML in `site/web`: one page per tab, plus `404.html`, `style.css` and `keys.js`. There is no framework, no npm, no webfont and no request to another site. Every page works with JavaScript off. With it on, `keys.js` adds the line cursor (j/k), the prompt (/), copy (enter, c), help (?) and the snib-page motion toggle (m).

```sh
go run ./cmd/sitegen        # after any change to content/, then commit site/web
go test ./cmd/sitegen       # fails if site/web is stale
go run ./cmd/preview        # serves site/web on http://127.0.0.1:8080/ only
```

`404.html` uses root-absolute paths and there is no `og:image` until `baseURL` in `cmd/sitegen` is set. Both need a base URL before any deploy.

Colors are the Snib palette. Dark is the default; a light scheme follows `prefers-color-scheme`. Motion stops under `prefers-reduced-motion`. Nothing here is deployed.
