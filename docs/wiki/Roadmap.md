agentbox is early alpha. It is not for production use.

Weeks 1-3 of the build plan are built: the installer, the OS layer, and the first host services (the firewall, the audit daemon, the root daemon's skeleton and resolver, disk quotas and packaged ntfy). The agent runtime is designed but not built. No AI agent can run on agentbox yet.

This page follows build plan v5.3, [`PLAN.md`](../design/PLAN.md) in `docs/design/`. It matches [`ARCHITECTURE.md`](../design/ARCHITECTURE.md) v5.3. Status is as of the time of writing (2026-11-21).

Two terms used below:

- **Taint** marks a task that has read untrusted content, such as a package registry, a web page or a GitHub issue. Taint is sticky. Only a human clears it.
- **An ask** is an agent request that waits for a human signature. One signature answers one ask.

## Milestones

The plan has nine milestones. Each one ends with a gate: a set of tests that must pass before the next milestone starts. The rows are numbered by phase, 1-16. They are not calendar weeks: with two engineers the whole plan takes about 20 weeks, and one engineer would need about 34. v5.3 adds about 39 engineer-days for proposals A-D ([below](#v53-what-changed)).

| Weeks | What it builds | Gate examples | Status |
|---|---|---|---|
| 1-2 | Seed generator; unattended install with optional disk encryption; recovery key; btrfs A/B OS generations with unattended fallback; release pipeline and signed firstboot install; zero-touch install ISO; power-cut tests | Unattended first boot in both TPM modes. Broken updates and power cuts fall back with no console input. The install and `os apply` checks on a real x86 PC. | **Built.** The gate passed in QEMU VMs at `e2e53af` and `61acfc7`, except the install and `os apply` checks on a real x86 PC, which have not run. |
| 3 | Host firewall (nftables) with `fwcheck`; btrfs quotas with a disk reserve and a content-store cap; the audit daemon, with a hash-chained log, taint epochs and a disk-full mode; the root daemon's skeleton, name resolver and audit-log sealing; packaged ntfy on a Unix socket. v5.3: auditd never deletes taint rows | An altered firewall stops agents from starting. With the audit daemon down, nothing runs. A broker reaches only addresses rootd resolved. `nft flush ruleset` is repaired within 60 s, with an alert. | **Built.** Every gate item passed in QEMU VMs at `fb89de4` ([Testing and Gates](Testing-and-Gates.md#week-3-gates)). Ran in `none` mode on arm64 UEFI only. |
| 4 | One registry of every operation, with generated code and schemas; the request gate in `agentboxd`; the socket layout as code; fuzzers for every parser. v5.3: denial codes, batch and quote fields | A registry mismatch stops startup. 24 hours of fuzzing find no crash. | Designed, not built |
| 5-6 | Agent accounts with disk quotas; one disposable container per task, with no network and a fresh HOME; a seccomp profile that blocks btrfs ioctls; task stop; interactive sessions in a separate home. v5.3: Go in the task image, HTTP-aware forwarders, `agentbox why` | Claude Code or Codex hooks and MCP config that one task plants don't run in the next task. A task's leftover processes are gone within 20 s of its timeout. | Designed, not built |
| 7-8 | Brokers: a proxy that holds no secrets, a keys broker for LLM API keys and budgets, and a git service that holds the GitHub token. v5.3: the proxy's read-only Go module cache, denial formats | No credential of any kind exists inside a task. Rebinding, raw IP, LAN and metadata-address attempts fail. | Designed, not built |
| 9-10 | Cedar policies (Cedar is an open-source policy language); the floor (the minimum rules the root daemon enforces; policy can only make them stricter); pending operations bound to exact inputs, such as commit IDs and package hashes; approvals signed with an SSH key on the laptop; phone approvals with a passkey, for low-risk operations only. v5.3: the ask budget, `ask.quote`, `ask.status` and `ask.batch`; `agentbox egress allow` | Race, replay and argument swap fail. A phone approval of a laptop-only operation is refused. | Designed, not built |
| 11-12 | Apps in pods with no network, built offline; file writes; agent operations for package changes and nightly updates, built on the weeks 1-2 generations, with a floor of protected packages; workspace snapshots; a local-model "decide" helper. v5.3: snapshot taint at RESULT | Protected packages can't be removed or downgraded. A nightly update with a kernel upgrade commits. | Designed, not built |
| 13-14 | Agent-to-agent task bus; shared memory with quarantine and taint. v5.3: memory notes bound to a workspace | A poisoned memory fact never reaches instructions. Reading a tainted fact taints the reader. | Designed, not built |
| 15-16 | Benchmark: 30 graded tasks, plus 20 injection, 10 poisoning, 10 deputy, 10 OS rollback and 10 approval-drift tasks; an external threat-model review; a signed release | At least 90% of stock Ubuntu's task success. 0 exfiltrations. 0 floor bypasses. At most 1 ask per delivered change, plus 1 per new egress host ([see below](#v53-what-changed)). | Designed, not built |

## Weeks 1-2: what passed

All gates ran in QEMU VMs on an Apple Silicon Mac. Most ran on arm64 UEFI with Secure Boot on. The BIOS gates ran on amd64 under software emulation, and they now also run under KVM in CI.

- Unattended install in all three encryption modes: `none`, `tpm2` and `tpm2+tang`.
- With Tang down, the disk stays locked. With Tang back, it unlocks with no input. A typed recovery key also unlocks it.
- Two disks with the same serial stop the install before any disk write.
- Repeated `os apply` cycles build, boot and commit new generations. One cycle upgrades the kernel. The oldest generation is pruned, and the previous generation still boots.
- Broken trial generations fall back with no console input. The tests break GRUB, the initrd and fstab, add a unit that blocks boot forever, and empty the GRUB environment block.
- Power cuts at five points during `os apply`, plus one right after it returns, leave a bootable box. The cut right after it returns has run only on a fix branch so far.
- Firstboot refuses a tampered release, an older signed release and a wrong-key signature. It installs nothing in each case.

## Weeks 1-2: what has not run

| Item | State |
|---|---|
| The install and `os apply` checks on a real x86 PC, the last step of the weeks 1-2 gate | Not run. No real hardware has run agentbox. |
| amd64 UEFI install | Not run anywhere. |
| `tpm2+tang` install on the amd64 BIOS VM | Not run. The BIOS gates ran `none` and `tpm2` only. |
| `os apply` on amd64 | One passing run on the amd64 BIOS VM. It ran on a fix branch before the branch merged. |
| Power cuts during `os apply` in `none` and `tpm2+tang` modes | Not run. QMP power cuts ran in `tpm2` mode only. |

## Week 3: what passed

Every week-3 gate ran on a fresh `none`-mode install, arm64 UEFI, Secure Boot on. All four week-3 suites and the four weeks 1-2 smoke suites passed at `fb89de4`, after a review whose 10 findings were fixed on `main` (`7ec99b1` to `fb89de4`).

- An altered firewall (9 kinds of change) keeps the agent stand-in from starting, and a firewall restart repairs each one. Reload, restart and reboot keep the sets rootd filled.
- `nft flush ruleset`: the table was back in 50 s, with `agentbox: ALERT: firewall altered`.
- With auditd stopped or hung, no effect runs. A taint clear from any socket but rootd's admin path is rejected, and the subject stays tainted.
- A full disk still lets admin operations such as `taint.clear` and `agent.remove` run. A torn log tail, a backward clock step across midnight and a crash at each sealing step don't stop acknowledgements, and `agentbox audit verify` passes after each.
- A broker reaches only the address and port that rootd resolved for it. A keys flow survives its element's expiry and is cut when its entry is removed.
- 200 root connections to `127.0.0.1:43100` succeed. Other users, other reserved ports and `[::1]` get a reset.
- The `2/0` quota keeps its reserve: a writer at its limit gets `EDQUOT`, and system state keeps writing.
- ntfy runs as `_ntfy` on a Unix socket only. ntfy under any other user keeps the agent stand-in from starting.

## Week 3: what has not run

| Item | State |
|---|---|
| The week-3 gates in `tpm2`, `tpm2+tang` and on amd64 BIOS | Not run. The week-3 code doesn't touch unlock or boot, and the weeks 1-2 smoke suites still pass in `tpm2` and `tpm2+tang`. |
| Hiding systemd-resolved's Unix interfaces from the broker users | Not built: the broker units don't exist yet. A residual in the threat model until they land (weeks 7-8). |
| The resolver's `unavailable` reason when systemd-resolved is down | No gate check. |

## Known gaps

| Gap today | Where the plan closes it |
|---|---|
| The host firewall filters outbound traffic from agentbox's service users only. It has no inbound rules, so SSH and any other listener are open to the LAN. | Not in the plan yet. Keep the box on a network you trust. |
| No agent support. The design targets Claude Code, Codex and opencode as agent CLIs. | Weeks 5-8 |
| The test VM can reach services on the host's loopback through `10.0.2.2`. | Before weeks 5-6: a restricted VM network |
| No signed approvals. Today an admin approves an OS change by passing the plan's SHA-256 to `os apply` as root. | Weeks 9-10 |
| No automatic OS updates. apt's daily timers are masked. Updates happen only when an admin runs `os plan` and `os apply`. | Weeks 11-12: nightly updates |
| No command to boot or pin an older generation. Fallback after a failed update is automatic. | Weeks 11-12: a signed rollback operation |
| No way to update the agentbox release on an installed box. A new release means a reinstall. | Out of scope for v1 |

## v5.3: what changed

v5.3 adopted four proposals from [`PROPOSALS-v5.3.md`](../design/PROPOSALS-v5.3.md) on 2026-11-20. Each one lands across the milestones above:

- **A. A read-only Go module cache.** Go module downloads stay warm after the first Go task in each taint epoch. The cache is read-only to tasks and ends at the next `taint.clear` (weeks 5-8, 9-10, 13-14).
- **B. Workspace-bound memory notes.** A task's own notes, bound to its workspace, are readable by later tasks of the same taint epoch with no ask and no review. Week 3 built B's first part: auditd never deletes a taint row. The rest lands in weeks 4 and 9-14.
- **C. Structured denials.** Every refusal has a stable code, a next move, and the one operation or human command that would unblock it. `agentbox why` explains a denial (weeks 4-14).
- **D. A visible ask budget.** Each task sees its ask budget. `ask.quote` shows what a plan will cost before the agent acts, and `ask.batch` lets one signature cover a push and its pull request (weeks 4, 9-10, 13-14).

It rejected proposal E, the delivery lane, which would have let a tainted task push a branch and open a draft pull request on an enrolled private remote with no ask. v5.3 weakens no control in the threat model.

v5.3 also changed the weeks 15-16 gate. The old target was at most 5 asks per 100 tasks. The new target is at most 1 ask per delivered change (a push and its pull request batched into one signature), plus 1 per new egress host. A model of the v5.3 rules gives about 109 asks per 100 tasks (108.7), reported but not gated. The agent runtime is not built, so no ask rate has been measured.

## See also

- [Home](README.md)
- [Testing and Gates](Testing-and-Gates.md): each gate, what it proves, and its result.
- The threat model: [`docs/THREAT-MODEL.md`](../../docs/THREAT-MODEL.md) in the repository.
