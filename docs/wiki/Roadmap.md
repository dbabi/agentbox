agentbox is early alpha. It is not for production use.

Weeks 1-2 of a 16-week build plan are built: the installer and the OS layer. The agent runtime is designed but not built. No AI agent can run on agentbox yet.

This page follows build plan v5.2. The plan and the v5.3 proposals live in the design notes, which are not yet published. Status is as of the time of writing.

Two terms used below:

- **Taint** marks a task that has read untrusted content, such as a package registry, a web page or a GitHub issue. Taint is sticky. Only a human clears it.
- **An ask** is an agent request that waits for a human signature. One signature answers one ask.

## Milestones

The plan has nine milestones. Each one ends with a gate: a set of tests that must pass before the next milestone starts. The weeks assume two engineers. One engineer would need about 26 weeks.

| Weeks | What it builds | Gate examples | Status |
|---|---|---|---|
| 1-2 | Seed generator; unattended install with optional disk encryption; recovery key; btrfs A/B OS generations with unattended fallback; release pipeline and signed firstboot install; zero-touch install ISO; power-cut tests | Unattended first boot in both TPM modes. Broken updates and power cuts fall back with no console input. The install and `os apply` checks on a real x86 PC. | **Built.** The gate passed in QEMU VMs, except the install and `os apply` checks on a real x86 PC, which have not run. |
| 3 | Host firewall (nftables) with a check every 60 s; btrfs quotas with a disk reserve; the audit daemon, with a hash-chained log and a taint ledger; the root daemon's skeleton and name resolver; packaged ntfy for notifications | An altered firewall stops agents from starting. With the audit daemon down, nothing runs. | Designed, not built |
| 4 | One registry of every operation, with generated code and schemas; the request gate in `agentboxd`; the socket layout as code; fuzzers for every parser | A registry mismatch stops startup. 24 hours of fuzzing find no crash. | Designed, not built |
| 5-6 | Agent accounts with disk quotas; one disposable container per task, with no network and a fresh HOME; a seccomp profile that blocks btrfs ioctls; task stop; interactive sessions in a separate home | Claude Code or Codex hooks and MCP config that one task plants don't run in the next task. A task's leftover processes are gone within 20 s of its timeout. | Designed, not built |
| 7-8 | Brokers: a proxy that holds no secrets, a keys broker for LLM API keys and budgets, and a git service that holds the GitHub token | No credential of any kind exists inside a task. Rebinding, raw IP, LAN and metadata-address attempts fail. | Designed, not built |
| 9-10 | Cedar policies (Cedar is an open-source policy language); the floor (the minimum rules the root daemon enforces; policy can only make them stricter); pending operations bound to exact inputs, such as commit IDs and package hashes; approvals signed with an SSH key on the laptop; phone approvals with a passkey, for low-risk operations only | Race, replay and argument swap fail. A phone approval of a laptop-only operation is refused. | Designed, not built |
| 11-12 | Apps in pods with no network, built offline; file writes; agent operations for package changes and nightly updates, built on the weeks 1-2 generations, with a floor of protected packages; workspace snapshots; a local-model "decide" helper | Protected packages can't be removed or downgraded. A nightly update with a kernel upgrade commits. | Designed, not built |
| 13-14 | Agent-to-agent task bus; shared memory with quarantine and taint | A poisoned memory fact never reaches instructions. Reading a tainted fact taints the reader. | Designed, not built |
| 15-16 | Benchmark: 30 graded tasks, plus 20 injection, 10 poisoning, 10 deputy, 10 OS rollback and 10 approval-drift tasks; an external threat-model review; a signed release | At least 90% of stock Ubuntu's task success. 0 exfiltrations. 0 floor bypasses. At most 5 asks per 100 tasks ([see below](#proposed-for-v53-not-adopted)). | Designed, not built |

## Weeks 1-2: what passed

All gates ran in QEMU VMs on an Apple Silicon Mac. Most ran on arm64 UEFI with Secure Boot on. The BIOS gates ran on amd64 under software emulation.

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

## Known gaps

| Gap today | Where the plan closes it |
|---|---|
| No host firewall. The install masks `nftables.service`. | Week 3 |
| No agent support. The design targets Claude Code, Codex and opencode as agent CLIs. | Weeks 5-8 |
| The test VM can reach services on the host's loopback through `10.0.2.2`. | Before weeks 5-6: a restricted VM network |
| No signed approvals. Today an admin approves an OS change by passing the plan's SHA-256 to `os apply` as root. | Weeks 9-10 |
| No automatic OS updates. apt's daily timers are masked. Updates happen only when an admin runs `os plan` and `os apply`. | Weeks 11-12: nightly updates |
| No command to boot or pin an older generation. Fallback after a failed update is automatic. | Weeks 11-12: a signed rollback operation |
| No way to update the agentbox release on an installed box. A new release means a reinstall. | Out of scope for v1 |

## Proposed for v5.3 (not adopted)

v5.3 is a set of design proposals. None of them is adopted. None of them is built. The weeks 1-2 code does not change.

The weeks 15-16 gate allows at most 5 asks per 100 tasks. A model of the v5.2 rules gives about 183 asks per 100 tasks (182.7). The agent runtime is not built, so no ask rate has been measured. The proposals aim to cut the number of asks.

## See also

- [Home](README.md)
- The threat model: `docs/THREAT-MODEL.md` in the repository.
