# Docs standard

This standard covers every page a reader sees: `README.md`, `SECURITY.md`, `docs/THREAT-MODEL.md`, `docs/wiki/*.md` and `mascot/README.md`.
`docs/design/` is the design record. It may hold internal detail, but the privacy rule (rule 6) applies there too.

The first public README (commit `a73cfa4`) is the reference for tone and shape.
Copy its tone, not its facts or its schedule.

## Who the reader is

A developer who has never heard of agentbox.
They want to know, in this order: what it is, whether it works yet, why they would want it, and how to try it.
They do not know our plan, our design records, our test names or our history, and they should not need to.

## Rules

1. **Describe what it does, not how we plan it.**
   Leave out design revisions ("v5.3"), staffing ("two engineers"), work estimates ("20 weeks"), proposal letters, finding and round IDs, planning logs and plan section numbers.
   Product versions, public issue numbers, procedure steps and run times are fine.
2. **Status is a promise.**
   "Works today" says what a reader can do now, and where. "Not yet" says what is missing.
   At most five bullets in each. Longer feature lists go in Features or the wiki.
   Built scaffolding is not a working guarantee. Mark planned guarantees as planned.
3. **Keep what the reader needs, move the rest.**
   Keep the details needed to install, run, recover or judge security: commands, expected output and what was tested where.
   Architecture may name the main components. Explain any term a newcomer would not know.
   Move background mechanics, unit names, config keys and command lists to the wiki.
4. **Evidence lives in one place.**
   Test results, build comparisons, suite and gate IDs, pass counts and commit hashes go in `docs/wiki/Testing-and-Gates.md`.
   Other pages link there instead.
5. **Plain words.**
   One idea per sentence, active voice, about 20 words or fewer. No hype, superlatives or emoji.
   If a sentence explains how to read our own table ("rows are phases, not weeks"), fix the table instead.
   State each limit once, plainly. Do not hedge every line.
6. **Nothing private.**
   No secrets, private personal data, employer names or URLs, internal hostnames, or author-specific local paths, in any page or commit.
   Public project handles, the security contact, attribution and generic paths on the box (such as `/var/lib/agentbox`) are fine.
7. **Commands and links work.**
   State the prerequisites, the target machine and any values to substitute before a command.
   Warn before a destructive command, every time it appears.
   Every relative link and image points to a file that exists.

## README shape

Keep this order: banner and badges (optional), a one-line pitch, the early-alpha warning, What is agentbox, Status (Works today, Not yet), Why, Quickstart (Mac VM, real hardware), Features (Built; Designed, not built), Architecture (one small diagram of the main parts and trust boundaries), Security model (short table and a link), Roadmap, Contributing, License, Acknowledgements.

The README must stand alone. Design records are optional reading, not a prerequisite.

The roadmap is an ordered list of milestones. Each one has a status: done, in progress, next or planned.
No dates, week numbers or staffing.

## Wiki pages

Wiki pages may go deeper: flags, file paths, unit names, limits and recovery steps.
Planning jargon is still out (rule 1), and evidence stays in `Testing-and-Gates.md` (rule 4).
Wiki pages link to each other by file name, for example `[Roadmap](Roadmap.md)`.

## How it is checked

`hack/docs-lint.sh` runs in CI. It fails on known planning jargon, evidence outside `Testing-and-Gates.md`, private paths and keys, and relative links that do not resolve.
It is a regression guard, not a judge of prose. People (and the docs-review skill in `.claude/skills/docs-review/`) check claims, relevance and wording.

## Review checklist

Check every item before a docs change merges:

- [ ] `hack/docs-lint.sh` passes.
- [ ] A newcomer can read the README top to bottom without knowing our plan or history.
- [ ] Every "built", "done" or "works today" claim matches the code or `Testing-and-Gates.md`.
- [ ] Works today and Not yet have five bullets or fewer, and describe what a reader can or cannot do.
- [ ] No design revisions, staffing, schedules, proposal or finding IDs, or plan section numbers.
- [ ] No commit hashes, suite IDs or pass counts outside `Testing-and-Gates.md`.
- [ ] Every roadmap item has one status: done, in progress, next or planned.
- [ ] No sentence explains how to read our own table or plan.
- [ ] Each command states its prerequisites and machine, and runs as written. Destructive ones carry a warning.
- [ ] Unfamiliar terms are explained, or link to a page that does.
- [ ] Nothing private: no secrets, personal data, employer names or local paths.
