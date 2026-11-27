agentbox is early alpha. It is not for production use.

Milestones 1 and 2 are built: the installer, the OS layer, and the first host services (the firewall, the audit daemon, the root daemon's skeleton and resolver, disk quotas and packaged ntfy). Milestone 3, the operation registry and the request gate, is built and its VM gates passed. Its 24-hour fuzz run is pending, so it stays in progress. Milestone 4 is done: agent accounts, one sealed container per task, and interactive sessions. The brokers, policy and approvals are designed but not built. So a task can start an agent CLI, but it can't reach a model yet.

The full design is in [`docs/design/`](../design/). Status is as of the time of writing (2026-11-25).

Two terms used below:

- **Taint** marks a task that has read untrusted content, such as a package registry, a web page or a GitHub issue. Taint is sticky. Only a human clears it.
- **An ask** is an agent request that waits for a human signature. One signature answers one ask.

## Milestones

agentbox is built in nine milestones, in this order. Each one ends with a gate: a set of tests that must pass before the next milestone starts.

| # | What it builds | Gate examples | Status |
|---|---|---|---|
| 1. Installer and safe OS updates | Seed generator; unattended install with optional disk encryption; recovery key; btrfs A/B OS generations with unattended fallback; release pipeline and signed firstboot install; zero-touch install ISO; power-cut tests | Unattended first boot in both TPM modes. Broken updates and power cuts fall back with no console input. The install and `os apply` checks on a real x86 PC. | **Done.** The gate passed in QEMU VMs ([Testing and Gates](Testing-and-Gates.md#milestone-1)), except the install and `os apply` checks on a real x86 PC, which have not run. |
| 2. Firewall, audit log, root daemon | Host firewall (nftables) with `fwcheck`; btrfs quotas with a disk reserve and a content-store cap; the audit daemon, with a hash-chained log, taint epochs that never lose a row, and a disk-full mode; the root daemon's skeleton, name resolver and audit-log sealing; packaged ntfy on a Unix socket | An altered firewall stops agents from starting. With the audit daemon down, nothing runs. A broker reaches only addresses rootd resolved. `nft flush ruleset` is repaired within 60 s, with an alert. | **Done.** Every gate item passed in QEMU VMs ([Testing and Gates](Testing-and-Gates.md#milestone-2-gates)). Ran in `none` mode only: on arm64 UEFI, and on amd64 BIOS in a weekly CI job. |
| 3. Operation registry and request gate | One registry of every operation, with generated code and schemas; the request gate in `agentboxd`; stable denial codes; the socket layout as code; fuzzers for every parser | A registry mismatch stops startup. An audit record with a secret or an unhashed body is refused, and nothing runs. 24 hours of fuzzing find no crash. | **In progress.** Built, and the VM gates passed ([Testing and Gates](Testing-and-Gates.md#milestone-3)). The 24-hour fuzz run is pending. |
| 4. Agent accounts and one sealed container per task | Agent accounts with disk quotas; one disposable container per task, with no network, a fresh HOME and Go in the image; a seccomp profile that blocks btrfs ioctls; task stop; interactive sessions in a separate home; `agentbox why` to explain a denial | Claude Code or Codex hooks and MCP config that one task plants don't run in the next task. A task's leftover processes are gone within 20 s of its timeout. | **Done.** Every gate item passed in QEMU VMs ([Testing and Gates](Testing-and-Gates.md#milestone-4)). Ran in `none` mode on arm64 UEFI only. |
| 5. Brokers | A proxy that holds no secrets, with a read-only Go module cache; a keys broker for LLM API keys and budgets; a git service that holds the GitHub token | No credential of any kind exists inside a task. Rebinding, raw IP, LAN and metadata-address attempts fail. | **In progress.** The proxy and the dialer the brokers share are built, and their VM gates passed ([Testing and Gates](Testing-and-Gates.md#milestone-5)): rebinding, raw IP, UDP, IPv6, LAN and metadata-address attempts through the proxy fail. The Go module cache, the keys broker and the git service are designed, not built. |
| 6. Signed approvals | Cedar policies (Cedar is an open-source policy language); the floor (the minimum rules the root daemon enforces; policy can only make them stricter); pending operations bound to exact inputs, such as commit IDs and package hashes; approvals signed with an SSH key on the laptop; phone approvals with a passkey, for low-risk operations only; a visible ask budget, with `ask.quote`, `ask.status` and `ask.batch`; a signed `agentbox egress allow` (an unsigned admin form is built) | Race, replay and argument swap fail. A phone approval of a laptop-only operation is refused. | Designed, not built |
| 7. Apps and OS updates by agents | Apps in pods with no network, built offline; file writes; agent operations for package changes and nightly updates, built on the milestone 1 generations, with a floor of protected packages; operations for agents to snapshot and restore a workspace; a local-model "decide" helper | Protected packages can't be removed or downgraded. A nightly update with a kernel upgrade commits. | Designed, not built |
| 8. Agent bus and shared memory | Agent-to-agent task bus; shared memory with quarantine and taint; memory notes bound to a workspace | A poisoned memory fact never reaches instructions. Reading a tainted fact taints the reader. | Designed, not built |
| 9. Benchmark and first signed release | Benchmark: 30 graded tasks, plus 20 injection, 10 poisoning, 10 deputy, 10 OS rollback and 10 approval-drift tasks; an external threat-model review; the first signed release | At least 90% of stock Ubuntu's task success. 0 exfiltrations. 0 floor bypasses. At most 1 ask per delivered change, plus 1 per new egress host ([see below](#features-that-span-milestones)). | Designed, not built |

## Milestone 1: what passed

All gates ran in QEMU VMs on an Apple Silicon Mac. Most ran on arm64 UEFI with Secure Boot on. The BIOS gates ran on amd64 under software emulation, and they now also run under KVM in CI.

- Unattended install in all three encryption modes: `none`, `tpm2` and `tpm2+tang`.
- With Tang down, the disk stays locked. With Tang back, it unlocks with no input. A typed recovery key also unlocks it.
- Two disks with the same serial stop the install before any disk write.
- Repeated `os apply` cycles build, boot and commit new generations. One cycle upgrades the kernel. The oldest generation is pruned, and the previous generation still boots.
- Broken trial generations fall back with no console input. The tests break GRUB, the initrd and fstab, add a unit that blocks boot forever, and empty the GRUB environment block.
- Power cuts at five points during `os apply`, plus one right after it returns, leave a bootable box. The cut right after it returns has run only on a fix branch so far.
- Firstboot refuses a tampered release, an older signed release and a wrong-key signature. It installs nothing in each case.

## Milestone 1: what has not run

| Item | State |
|---|---|
| The install and `os apply` checks on a real x86 PC, the last step of the milestone 1 gate | Not run. No real hardware has run agentbox. |
| amd64 UEFI install | Not run anywhere. |
| `tpm2+tang` install on the amd64 BIOS VM | Not run. The BIOS gates ran `none` and `tpm2` only. |
| `os apply` on amd64 | One passing run on the amd64 BIOS VM. It ran on a fix branch before the branch merged. |
| Power cuts during `os apply` in `none` and `tpm2+tang` modes | Not run. QMP power cuts ran in `tpm2` mode only. |

## Milestone 2: what passed

Every milestone 2 gate ran on a fresh `none`-mode install, arm64 UEFI, Secure Boot on. All four milestone 2 suites and the four milestone 1 smoke suites passed after a review whose problems were fixed. The milestone 2 gates also pass on amd64 BIOS, in a weekly CI job. [Testing and Gates](Testing-and-Gates.md#milestone-2) lists each result and the commit it ran at.

- An altered firewall (9 kinds of change) keeps the agent stand-in from starting, and a firewall restart repairs each one. Reload, restart and reboot keep the sets rootd filled.
- `nft flush ruleset`: the table was back in 50 s, with `agentbox: ALERT: firewall altered`.
- With auditd stopped or hung, no effect runs. A taint clear from any socket but rootd's admin path is rejected, and the subject stays tainted.
- On a full disk, the audit daemon refuses every record except the admin operation records that only rootd may send, such as `taint.clear` and `agent.remove`. A torn log tail, a backward clock step across midnight and a crash at each sealing step don't stop acknowledgements, and `agentbox audit verify` passes after each.
- A process under a broker's user reaches only the address and port that rootd resolved for it. An open connection under the keys broker's user keeps working after its address expires from the firewall set. Removing its allowlist entry cuts it.
- 200 root connections to `127.0.0.1:43100` succeed. Other users, other reserved ports and `[::1]` get a reset.
- The `2/0` quota keeps its reserve: a writer at its limit gets `EDQUOT`, and system state keeps writing.
- ntfy runs as `_ntfy` on a Unix socket only. ntfy under any other user keeps the agent stand-in from starting.

## Milestone 2: what has not run

| Item | State |
|---|---|
| The milestone 2 gates in `tpm2` and `tpm2+tang` | Not run. The milestone 2 code doesn't touch unlock or boot, and the milestone 1 smoke suites still pass in `tpm2` and `tpm2+tang`. |
| Hiding systemd-resolved's Unix interfaces from the broker users | Not built: the broker units don't exist yet. A residual in the threat model until they land (milestone 5). |
| The resolver's `unavailable` reason when systemd-resolved is down | No gate check. |

## Milestone 3: what passed

Every milestone 3 gate ran on a fresh `none`-mode install, arm64 UEFI, Secure Boot on. The tests for milestones 1 and 2 also passed again on the same code. The milestone 3 gates also pass on amd64 BIOS, in a weekly CI job. [Testing and Gates](Testing-and-Gates.md#milestone-3) lists each result and the commit it ran at.

- The root daemon starts only when the policy schema, the JSON schemas and the MCP tool list match the registry. Each of five planted mismatches stops it, and the journal names the mismatch.
- `agentboxd` gives each task a socket that only that task's agent user can use. A valid request runs in order: the audit log records it with its body hashed, then it runs, then its result is recorded.
- A request with bad arguments, a forged caller or an operation no agent may call gets a typed denial, and nothing is recorded or run.
- The audit log refuses a record with an unhashed body or a secret, and the operation does not run. No refused value is left in the audit directory.
- The sockets and their directories on the box match the inventory in code, before and after a reboot. A wrong mode, a wrong owner and a stray file are each reported.
- Fuzz tests cover the parsers for seeds, keys, apt and GRUB output, firewall sets, audit records, agent requests, denials and more. Short runs on macOS found bugs. A longer run found one more: rootd's reader for the firewall's sets accepted an IPv6 address with a `%` zone suffix. All are fixed, and each crash input is kept as a test.
- The nightly fuzz job runs the fuzz tests on Linux, 3 hours each. No run has crashed so far.

## Milestone 3: what has not run

| Item | State |
|---|---|
| 24 hours of fuzzing with no crash | Pending. No commit has had 24 CPU-hours of fuzzing on every fuzz test yet ([the 24 h gate](Testing-and-Gates.md#the-24-h-gate)). |
| The milestone 3 gates in `tpm2` and `tpm2+tang` | Not run. The milestone 3 code doesn't touch unlock or boot. |
| The `agentbox mcp` command for agent CLIs | Not built. The error mapping it will use is built and tested. |

## Milestone 4: what passed

Every milestone 4 gate ran on a fresh `none`-mode install, arm64 UEFI, Secure Boot on. The tests for milestones 1-3 also passed again, after one fix. [Testing and Gates](Testing-and-Gates.md#milestone-4) lists each result and the commit it ran at.

- `agentbox agent add` makes one Linux account per agent, with its own uid, sub-id range, disk quota and limits. An agent at its quota gets `EDQUOT`, and system state keeps writing. A removed agent's uid and sub-id range are never reused.
- `agentbox task new` runs each task in its own rootless podman container: no network, no capabilities, a read-only root, a seccomp profile and a fresh home directory. Hooks and MCP config that one task plants don't reach the next task. A tainted task makes the next task on that workspace start tainted.
- A task's leftover processes are gone within 20 s of its timeout or of `agentbox task stop`. Canceling a task removes its container and sockets within 5 s, also with the audit daemon stopped. btrfs ioctls from a task fail with `EOPNOTSUPP`.
- Each task gets a fixed environment: no DNS, quiet npm and pip, Go settings that follow the agent's allowlist, and local forwarders that retry while a broker restarts. `agentbox why` explains a recent denial.
- `agentbox attach` opens an interactive session with a separate, persistent home. Planted hooks, MCP servers and shell startup files don't run in it. Its output is filtered, and tasks stay blocked until a scan finds no copy of its login token in the workspace.
- More landed after the milestone closed, each with gate checks:
  - `agentbox task undo` restores a workspace from the snapshot taken when a task started.
  - Each task checks its own network boundary from inside before the agent CLI starts.
  - The seccomp profile allows only the socket families tasks need.
  - System policy files keep Claude Code and Codex from running workspace hooks, MCP servers and plugins.
  - rootd pauses the agents while btrfs repairs its quota counts.
  - rootd scans the workspace for credentials before an agent's first task and at each egress grant. A hit blocks the task, or refuses a grant for a host it works against, until an admin acknowledges it.
  - rootd checks the task image against the release's checksums before it loads it, and refuses an image with unsafe settings. Fuzz tests cover this check.

## Milestone 4: what has not run

| Item | State |
|---|---|
| Brokers | Not built (milestone 5). The gates use stand-ins that bind the same per-task sockets. |
| The full task image, with Go and the agent CLIs | Not built into the box yet (milestone 7). By default a task runs a small root file system with the host's `/usr`, read-only. The task env gate builds a test image with Go. The gates run Claude Code and Codex from the host. opencode is not supported: its current release can't stop a workspace plugin (issue #164). |
| A skill's frontmatter hook in a task | Not provable yet: it needs a model reply. The gate checks only the setting that turns hooks off. |
| A network path for attach sessions | Not built (issue #90). A real Claude login can't reach its servers from an attach yet. |
| The milestone 4 gates in `tpm2`, `tpm2+tang` and on amd64 BIOS | Not run. The milestone 4 code doesn't touch unlock or boot. |

## Known gaps

| Gap today | Where the plan closes it |
|---|---|
| Rootful Docker publishes ports past the host firewall. | Not in the plan. Use rootless podman. |
| No task can reach a model or the internet yet, and no agent CLI is in the task image. The design targets Claude Code and Codex. | Milestone 5: the brokers |
| No signed approvals. Today an admin approves an OS change by passing the plan's SHA-256 to `os apply` as root. | Milestone 6 |
| No automatic OS updates. apt's daily timers are masked. Updates happen only when an admin runs `os plan` and `os apply`. | Milestone 7: nightly updates |
| No command to boot or pin an older generation. Fallback after a failed update is automatic. | Milestone 7: a signed rollback operation |
| No way to update the agentbox release on an installed box. A new release means a reinstall. | Out of scope for the first release |

## Features that span milestones

Some features land in parts across several milestones:

- **A read-only Go module cache.** Go module downloads stay warm after the first Go task in each taint epoch. The cache is read-only to tasks and ends at the next `taint.clear` (milestones 4-6 and 8).
- **Workspace-bound memory notes.** A task's own notes, bound to its workspace, are readable by later tasks of the same taint epoch with no ask and no review. Milestone 2 built the first part: auditd never deletes a taint row. The rest lands in milestones 3 and 6-8.
- **Structured denials.** Every refusal has a stable code, a next move, and the one operation or human command that would unblock it. `agentbox why` explains a denial (milestones 3-8).
- **A visible ask budget.** Each task sees its ask budget. `ask.quote` shows what a plan will cost before the agent acts, and `ask.batch` lets one signature cover a push and its pull request (milestones 3, 6 and 8).

The benchmark in milestone 9 aims for at most 1 ask per delivered change (a push and its pull request batched into one signature), plus 1 per new egress host. A model of the current design gives about 109 asks per 100 tasks, reported but not gated. The agent runtime is not built, so no ask rate has been measured.

## See also

- [Home](README.md)
- [Testing and Gates](Testing-and-Gates.md): each gate, what it proves, and its result.
- The threat model: [`docs/THREAT-MODEL.md`](../../docs/THREAT-MODEL.md) in the repository.
