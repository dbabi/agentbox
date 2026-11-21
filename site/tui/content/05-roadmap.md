---
key: 5
slug: roadmap
title: roadmap
pose: thinking
sources: docs/wiki/Roadmap.md, docs/design/PLAN.md
---
# plan v5.3: about 20 weeks with two engineers. rows are phases, not calendar weeks.
# each milestone ends with a gate that must pass before the next starts.
```
[###.................] weeks 1-3 of 20 built
```
# weeks 1-3 of 20 are built. weeks 4-16 are designed, not built.

[passed] 1-2   seed, encrypted install, recovery key, A/B generations, os apply, signed releases, zero-touch ISO
[passed] 3     firewall, disk quotas, audit daemon, rootd skeleton and resolver, ntfy
[next] 4       operation registry, agentboxd gate, fuzzers, denial codes
[planned] 5-6  agent accounts, one network-less container per task, Go in the task image
[planned] 7-8  brokers: proxy with a read-only Go module cache, keys, git
[planned] 9-10 Cedar policy, signed approvals, phone passkeys, an ask budget
[planned] 11-12 apps, file writes, package installs and nightly updates as new generations
[planned] 13-14 agent bus and shared memory, bound to workspaces
[planned] 15-16 benchmark, external threat-model review, signed release

# what has not run
- [not run] the install and os apply checks on a real x86 PC.
- [not run] an amd64 UEFI install, anywhere.
- [not run] the week-3 gates in tpm2, tpm2+tang and on amd64. they ran in none mode on arm64 UEFI only.
- [not run] power cuts during os apply in none and tpm2+tang modes.

# known gaps
- no inbound filtering. not in the plan yet. keep the box on a network you trust.
- no automatic OS updates. weeks 11-12.
- no signed approvals. weeks 9-10.
- no way to update agentbox on an installed box. a new release means a reinstall. out of scope for v1.
- [Roadmap](https://github.com/dbabi/agentbox/blob/main/docs/wiki/Roadmap.md)
