# Agent instructions

These rules apply to Codex, Claude and every other agent working in this repository.

## Docs

- Every change to `README.md`, `SECURITY.md`, `docs/THREAT-MODEL.md`, `docs/wiki/*.md` or `mascot/README.md` follows [docs/STYLE.md](docs/STYLE.md).
- Run `hack/docs-lint.sh` before you push a docs change. It must pass. CI runs it in the `lint` job.
- To review a docs change, follow [.claude/skills/docs-review/SKILL.md](.claude/skills/docs-review/SKILL.md).

## Changes

The full flow is in [docs/wiki/Contributing.md](docs/wiki/Contributing.md). In short:

1. Every change starts with a GitHub issue.
2. Branch from `main` as `issue-<n>-<slug>`. Never push to `main`.
3. Run `go vet ./... && go test ./...`, and the VM gate for any change to the install, boot or `os apply`.
4. Open a pull request with `Closes #<n>` in the body.
5. Merge only when the `test` and `lint` jobs are green. Squash merge.
