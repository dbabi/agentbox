---
name: docs-review
description: Review a change to agentbox's reader-facing docs (README.md, SECURITY.md, docs/THREAT-MODEL.md, docs/wiki/*.md, mascot/README.md) against docs/STYLE.md. Use for any docs diff or PR, or when asked to check the README or wiki.
---

# Review a docs change

The standard is `docs/STYLE.md`. Read it first. The reader is a developer who has never heard of agentbox.

## Steps

1. Find the change: `git diff origin/main...HEAD -- '*.md'`, or the PR diff. Read each changed page in full, not just the diff.
2. Run `hack/docs-lint.sh`. Every line it prints is a finding. Fix the cause, not the pattern: move evidence to `docs/wiki/Testing-and-Gates.md`, drop planning jargon, fix the link.
3. Read the README top to bottom as a newcomer. Stop at every term, ID or reference you would not know. Each one is a finding unless the page explains it.
4. Go through the review checklist at the end of `docs/STYLE.md`, item by item.
5. Check every claim that something is built, done, tested or works today:
   - Find the code: `cmd/agentbox/`, `internal/`, `install/`, `hack/`, `systemd/`.
   - Find the result in `docs/wiki/Testing-and-Gates.md` or `docs/wiki/Roadmap.md`.
   - If neither backs the claim, it is a finding. Say what the code shows.
6. Check that each command states its machine and prerequisites, and that a destructive one carries a warning.

## Output

One finding per line, most important first:

```text
README.md:41: <what is wrong, in one short sentence>
  fix: <the full replacement line>
```

Use `DELETE` as the fix to remove a line. If a fix moves text to another page, name the page and give the line to add there.
End with one line: `lint: pass` or `lint: fail`, and the number of findings.
Do not rewrite pages you were not asked to change. Do not report style preferences that the standard does not cover.
