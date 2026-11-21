# agentbox wiki

<img src="https://github.com/dbabi/agentbox/raw/main/mascot/agentbox-mascot.png" alt="The agentbox mascot, a pixel-art character" width="128">

> **Early alpha. Not for production use.** agentbox runs no AI agents yet. It has run only in QEMU virtual machines, never on real hardware.

agentbox aims to be a headless operating system that is a home for AI coding agents.
It is built on stock Ubuntu Server 26.04.

In the design, each task runs in a disposable container with no network and no credentials.
Anything that touches the host, secrets, the network, other agents or shared memory goes through typed operations.
Policy checks each operation, and an audit log records it.
Risky operations wait for a human to sign them.
The agent layer is not built yet. Its first host services are built: the firewall, the audit log, the root daemon's resolver and the checks for agent requests.

Today agentbox is an installer, an OS layer and those host services. No agent can send a request yet, because task containers are not built.
It installs Ubuntu unattended. Disk encryption is on by default, and `--encryption none` turns it off.
It keeps the OS in btrfs A/B generations.
A package change that fails to boot, or fails its health check, falls back on its own.

## What this wiki covers

- How to try agentbox in a VM, then install it on a PC.
- How the built parts work: disk encryption, recovery, OS generations, the release pipeline and the tests.
- The design for the parts that are not built yet, and the plan to build them.
- How to contribute.

Two words mark the state of each part:

- **Built:** the code exists and has passed its tests in QEMU VMs.
- **Designed:** the design notes in [`docs/design/`](../design/ARCHITECTURE.md) describe it, but there is no code yet.

[Testing and Gates](Testing-and-Gates.md) names the commit that each test result comes from.

## Status

At the time of writing (2026-11-21), milestones 1 and 2 of 9 are built. Milestone 3, the checks for agent requests, is built and its VM tests passed. Its 24-hour fuzz run is still pending.
The real-hardware test has not run yet.

Built:

- An unattended install of Ubuntu Server 26.04. Disk encryption is `tpm2+tang` (the default), `tpm2`, or `none` for no encryption.
- An offline recovery key for the encrypted modes.
- btrfs A/B OS generations. A package change is built offline into a new generation. That generation boots once as a trial, and a health check commits it. Anything else falls back to the committed generation, with no console input.
- Power-cut tests. In `tpm2` mode, QMP power cuts at five points during `os apply`, plus one right after it returns, each left a generation that boots. The cut right after it returns has run only on a fix branch so far. A write-by-write replay of one logged apply also passed. After every write to the boot partition, GRUB still found the entry it boots, with its kernel and initrd. [Testing and Gates](Testing-and-Gates.md) lists what these tests do not model.
- Releases you build and sign yourself with `make release`. At first boot, the box checks a pinned SHA-256 and then your minisign signature. It installs nothing unless both checks pass. There is no official release yet.
- A zero-touch install from two USB sticks: a remastered Ubuntu ISO and a seed ISO.
- A host firewall (milestone 2). An nftables table holds each agentbox service user to its own destinations. `fwcheck` checks it about every 50 seconds, restores an altered table, and keeps agent units from starting while it fails.
- An audit daemon (milestone 2). It records each operation durably before the operation runs, in a hash-chained log, and keeps a taint ledger. `agentbox audit verify` checks the chain.
- A root daemon skeleton (milestone 2). It resolves names for the brokers, fills their firewall sets, and seals finished audit segments.
- Disk quotas with a reserve for the system, and packaged ntfy on a Unix socket only (milestone 2).
- An operation registry (milestone 3). One list declares every operation an agent may request. The policy schema, the JSON schemas and the MCP tool list are generated from it, and the root daemon refuses to start if they differ.
- Request checks in `agentboxd` (milestone 3). Each task gets its own socket. A request with bad arguments, a forged caller or an operation no agent may call is refused with a stable denial code. The audit log refuses a record that holds a secret or an unhashed body, and then nothing runs.
- The socket layout as code (milestone 3). `agentbox sockets check` compares every socket and directory on the box with it.

Not built yet:

- The agent runtime: task containers, brokers, policy, approvals, the agent bus and shared memory. No AI agent can run on agentbox yet.
- Inbound filtering. The host firewall has an output chain only, so SSH and any other listener are open to the LAN.
- Automatic security updates. Today an admin runs `os plan` and `os apply` by hand.
- Updating agentbox itself on an installed box. This is out of scope for the first release. A new release means a reinstall.

Where it has run: QEMU VMs on an Apple Silicon Mac.
Most gates ran on an arm64 UEFI VM with Secure Boot on.
Some gates also ran on an amd64 legacy BIOS VM.
The milestone 2 and 3 gates ran in `none` mode on arm64 UEFI only.
No amd64 UEFI install has run yet.
No real machine has run agentbox yet.

## Pages

| Page | What it covers | State |
|---|---|---|
| [Getting Started](Getting-Started.md) | From zero to a passing install test in a QEMU VM on an Apple Silicon Mac. Then a first install on a real PC. | Built; the real-PC part has not run |
| [FAQ](FAQ.md) | Short answers: why Ubuntu and btrfs, which agents it will run, whether it is ready for production. | n/a |
| [Installing on Real Hardware](Installing-on-Real-Hardware.md) | The zero-touch USB install on a PC: the disk serial, a real seed, BIOS or UEFI, Secure Boot. | Built, not yet run on real hardware |
| [Encryption and Recovery](Encryption-and-Recovery.md) | The three encryption modes, what each protects against, the recovery key, and what happens when Tang is down. | Built |
| [Generations and Updates](Generations-and-Updates.md) | btrfs A/B generations, `os plan` and `os apply`, trial boots, health commits, fallback and retention. | Built |
| [Release Pipeline](Release-Pipeline.md) | `make release`, the signed tarball, the SHA-256 pin in the seed, and firstboot. | Built |
| [Architecture](Architecture.md) | The target design: the services, task containers, approvals, network and secrets, the agent bus, memory and audit. | Mostly designed; the OS layer, firewall, audit, rootd skeleton and request checks are built |
| [Security Model](Security-Model.md) | The threat model: what agentbox defends against, trust boundaries, accepted risks, and how to report a vulnerability. | Mostly designed |
| [Roadmap](Roadmap.md) | The milestones in order, with the state of each. | Milestones 1 and 2 built; milestone 3 in progress |
| [Testing and Gates](Testing-and-Gates.md) | Unit tests, fuzz tests, the VM gates (milestones 1-3), power-cut tests, what each gate proves, and the results. | Built |
| [Contributing](Contributing.md) | Dev setup, repo layout, code style, tests and commit style. | n/a |

## Where to start

### If you are curious

1. Read the [README](https://github.com/dbabi/agentbox) for a summary and the quick start.
2. [Architecture](Architecture.md): the target design, with each part marked built or designed.
3. [Roadmap](Roadmap.md): what each milestone adds.
4. [FAQ](FAQ.md): short answers to common questions.
5. The [website](https://dbabi.github.io/agentbox-web/): the same summary as a terminal-style page. Its source is in [dbabi/agentbox-web](https://github.com/dbabi/agentbox-web).

To look at the CLI without a VM, you need Go 1.26 or later:

```sh
git clone https://github.com/dbabi/agentbox.git
cd agentbox
go build -o bin/agentbox ./cmd/agentbox
bin/agentbox --help
```

The usage also lists `os` commands.
They run only on an installed box, as root.

### If you want to install it

Try it in a VM first.

1. Read [Status](#status) above. No agents run yet. The firewall has no inbound rules, and there are no automatic updates.
2. [Getting Started](Getting-Started.md): install agentbox in a QEMU VM on an Apple Silicon Mac.
3. [Encryption and Recovery](Encryption-and-Recovery.md): choose `tpm2+tang`, `tpm2` or `none`. For an encrypted mode, make the recovery key pair before you install.
4. [Installing on Real Hardware](Installing-on-Real-Hardware.md): the zero-touch USB install. It has not run on real hardware yet.
5. [Generations and Updates](Generations-and-Updates.md): change packages with `os plan` and `os apply`, not `apt`.

Before you install on a real machine:

- The install wipes the whole target disk. It picks that disk by its exact udev `ID_SERIAL`, which you pass as `--disk-serial`. If the serial matches no disk, or more than one, the install stops before it writes anything.
- The seed holds your admin password hash. Keep the seed files private.
- Keep `recovery.key` offline. If the box cannot unlock its disk on its own and `recovery.key` is lost, the data is gone.

### If you want to contribute

1. [Contributing](Contributing.md): setup, repo layout, code style and commit style.
2. [Testing and Gates](Testing-and-Gates.md): how to run the unit tests and the VM gates.
3. [Architecture](Architecture.md): where your change fits in the design.
4. [Roadmap](Roadmap.md): what each milestone adds.

The code is Go: the standard library plus `golang.org/x/sys` and the pure-Go SQLite driver `modernc.org/sqlite`.
The installer and the VM gate scripts are POSIX `sh`. One test tool, `hack/verify-seed.py`, is Python 3.
Run the unit tests from the repo root:

```sh
go vet ./... && go test ./...
```

Most VM gates need an Apple Silicon Mac.

### If you review security

1. [Security Model](Security-Model.md): what agentbox defends against, and the risks it accepts.
2. The repo's one-page threat model: [`docs/THREAT-MODEL.md`](../../docs/THREAT-MODEL.md).
3. [Encryption and Recovery](Encryption-and-Recovery.md): what each mode protects against, and what it does not.
4. [Release Pipeline](Release-Pipeline.md): how the box checks a release before it installs it.
5. [Generations and Updates](Generations-and-Updates.md) and [Testing and Gates](Testing-and-Gates.md): how OS changes are built, and what the gates cover and do not cover.

Most of the threat model covers parts that are not built yet. The full design is in [`docs/design/`](../design/ARCHITECTURE.md).
Report vulnerabilities privately. [Security Model](Security-Model.md) says how.

## Words used in this wiki

| Word | Meaning |
|---|---|
| operator machine | Your own computer, macOS or Linux. You build agentbox, make keys and render seeds there. |
| box | The machine agentbox is installed on. |
| seed | The autoinstall files that `agentbox seed` writes: `user-data` and `meta-data`, plus an ISO labeled `cidata` with `--iso`. It holds the admin password hash. |
| generation | One bootable copy of the OS: a btrfs subvolume `@gen-N` with its own kernels and initrds. |
| committed generation | The generation the box boots by default. Fallback returns to it. |
| trial boot | The one-time boot of a new generation. A health check commits it. Anything else falls back. |
| firstboot | The service that downloads, checks and installs the signed agentbox release after the install. It retries until it succeeds. |
| gate | A scripted end-to-end test in a QEMU VM. It prints one PASS or FAIL line per check. |

Questions and bug reports: open an issue in the [repository](https://github.com/dbabi/agentbox/issues).
