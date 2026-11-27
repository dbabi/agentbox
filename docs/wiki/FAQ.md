Short answers to common questions. For an overview, start at [Home](README.md).

agentbox is early alpha. Answers about policy and signed approvals describe the design. Those parts are not built yet. The egress proxy, the LLM keys broker and the git service are built.

## The basics

### Is agentbox production ready?

No. It is early alpha. Do not use it for production, or for data you cannot afford to lose.

At the time of writing:

- Milestones 1, 2 and 4 of 9 are built: the installer, the OS layer, the first host services (a firewall, an audit daemon and a root daemon), agent accounts and task containers. Milestone 3, the request checks, waits for its 24-hour fuzz run.
- No AI agent can do useful work on it yet: no task can reach a model.
- It has run only in QEMU virtual machines. No real hardware has run it.
- Inbound, the host firewall drops new connections, except SSH from the address ranges in the seed and Tailscale traffic (everything on `tailscale0`, and UDP port 41641 from any address). By default the SSH ranges are the private LAN ranges, `100.64.0.0/10` (Tailscale's range) and IPv6 link-local. [Security Model](Security-Model.md) lists the other exceptions.
- There are no automatic security updates: apt's daily timers are masked. Packages do not change on their own. To change them, an admin runs `agentbox os plan`, then `agentbox os apply`, as root on the box. The binary is not on `PATH`, so give its full path, for example `sudo /var/lib/agentbox/current/bin/agentbox os plan --install <pkg>`.
- An installed box cannot update its agentbox release. A new release means a reinstall.

### Which agents run in it?

None yet. Tasks can start an agent CLI, but no task can reach a model until the brokers are built.

Tasks run two agent CLIs: Claude Code and Codex. opencode is not supported: its current release can't stop a workspace plugin from running. The plan for running them:

- Each task runs in its own disposable podman container. The container has no network and a temporary home directory. This part is built.
- No credential exists inside a task. Broker services outside the container hold the LLM API keys and the GitHub token.
- Every action that touches the host, secrets, the network, other agents or shared memory is a typed operation. Policy checks it, and the audit log records it. Risky operations wait for your approval.

The rest comes in milestones 5 to 8 (see [Roadmap](Roadmap.md)). Milestones 2 to 4 built what it relies on: the firewall, the audit daemon, the root daemon's resolver, the request checks and the task containers.

### Can tasks use my Claude or ChatGPT subscription?

No. Tasks use API keys only, which the keys broker holds and adds to each request. A subscription login, including the one-year token from `claude setup-token`, is not supported in tasks. Codex tasks also use an OpenAI API key. opencode is not supported (see above). An interactive session can keep its own login in `session-home`.

### How is it different from a dev container?

A dev container gives one project a repeatable set of tools. It runs on your workstation or on a hosted dev service. It usually has full network access. It sees whatever credentials you mount or forward into it.

agentbox is the operating system of a dedicated machine. Its goal is to let agents run unattended, with real credentials on the box but out of the agents' reach.

| | Dev container | agentbox |
|---|---|---|
| Runs on | Your workstation or a hosted dev service | A dedicated machine that agentbox installs from scratch |
| Covers | One project's tools | The whole OS: install, disk encryption, OS changes, automatic fallback |
| Network in the container | Usually full access | None (built) |
| Credentials in the container | Whatever you mount or forward | None. Brokers outside the container hold them (planned) |
| Effects outside the container | Whatever its network and mounts allow | Only typed operations. The request checks and the audit log are built. Policy and the operations themselves are planned. |
| OS package changes | Rebuild the image | Built offline into a new OS generation, kept only if it boots healthy (built) |

Inside its task container, an agent runs without permission prompts. It can write to its workspace and to a temporary home directory. The container is thrown away when the task ends. This part is built, but no task can reach a model yet.

## Design choices

### Why Ubuntu Server?

agentbox is not a new Linux distribution. It is stock Ubuntu Server 26.04 LTS. agentbox adds an unattended install and an OS layer that builds package changes offline and falls back if they fail to boot or fail the health check.

- **Agents know it.** The bet is that agents work best on a common, well-documented Linux, with the tools and paths they have seen most.
- **The base is not the product.** A new distribution means drivers, patching and hardware support. None of that is what agentbox adds.
- **Packages come from Ubuntu.** Every package the installer adds comes from the signed Ubuntu archive, for amd64 and arm64.
- **The boot chain stays stock.** The zero-touch USB changes only GRUB's config file and its checksum entry on Ubuntu's own ISO. The signed shim and GRUB stay as shipped. The stick boots the same path as the stock ISO, Secure Boot included. So far, Secure Boot has been tested only on arm64 VMs.
- **It is headless, with long-term support.** Ubuntu Server has no desktop. 26.04 is a long-term support (LTS) release.

### Why not NixOS or an immutable distro?

Both were considered. NixOS and image-based systems such as bootc have atomic updates and rollback built in. agentbox chose stock Ubuntu for the agents: the bet is that they do best on the most common, best-documented Linux.

agentbox keeps the main idea of those systems:

- `agentbox os apply` builds a package change offline into a new OS generation. It does not change the running system's packages.
- The new generation boots once. It becomes the default only if a health check passes.
- If it fails to boot or fails the check, the box falls back to the last good generation with no console input.

This part is built and tested in QEMU VMs.

Unlike an immutable distro, the root filesystem stays writable. Make package changes with `agentbox os plan` and `agentbox os apply`, not plain `apt`. If packages change between the two, `agentbox os apply` refuses with `stale_base`.

### Why btrfs?

btrfs makes OS generations cheap. It also keeps the OS and your data apart, in one pool.

- Each OS generation is a btrfs subvolume. `agentbox os apply` starts a new one with a copy-on-write snapshot of the running generation, so the copy is fast and small.
- Data that must survive a fallback lives in its own subvolumes. They include `/home`, `/var/log`, `/srv` and `/var/lib/agentbox`. A fallback does not touch them.
- All subvolumes share one pool with zstd compression. In the encrypted modes, that pool sits inside one LUKS2 volume.
- btrfs quotas keep a disk reserve: one parent quota group, `2/0`, caps every store agents and apps can fill, so the OS and agentbox's control state always have room (built in milestone 2). Each agent also gets its own quota group under `2/0`, with its own limit (built in milestone 4).
- Before each task starts, agentbox takes a read-only snapshot of the agent's workspace. `agentbox task undo` restores the workspace from it (built).

The power-cut test harness replays the VM disk at each flush. It runs `btrfs check --readonly` on every replayed state. At the time of writing, every checked state passed. Those checks ran only on an unencrypted (`none`) disk. The harness does not model writes that land out of order between flushes, torn (partly written) sectors, or disks that ignore flushes. [Testing and Gates](Testing-and-Gates.md) has the full list.

### Why no PCR 7?

agentbox binds the disk key to the TPM with no PCR policy. This is on purpose.

PCR 7 records the Secure Boot state. Binding to it would not help against the threats agentbox targets, and it can break unattended unlock:

- **It does not stop a thief.** Any boot medium signed with the same keys, such as a stock Ubuntu live USB, gives the same PCR 7 value.
- **It does not cover the initrd.** The initrd sits on the unencrypted boot partition, and PCR 7 does not measure it.
- **It breaks unattended unlock.** PCR 7 changes when the Secure Boot databases, the revocation list (dbx) or SBAT update. That state lives in the firmware and on the one EFI system partition that all generations share. So one update would stop unattended unlock for every generation at once, and falling back would not help.

What protects the disk instead, in the encrypted modes:

| Threat | Covered by |
|---|---|
| Someone takes the disk | The TPM binding. The disk does not unlock without its own TPM, or your recovery key. |
| Someone takes the whole machine | Only `tpm2+tang`. Away from your LAN, the Tang server is out of reach, so the disk stays locked. |
| Someone stays on your LAN with physical access | Not covered. |

With `none`, nothing does.

The planned path after the first version is a unified kernel image (UKI) with a signed PCR 11 policy. The [threat model](../../docs/THREAT-MODEL.md) lists the other accepted risks.

## Where it runs

### Can I run it in the cloud?

Not today. No cloud provider's VM has booted agentbox. It is designed for a dedicated machine on your own network.

- The installer boots the Ubuntu Server ISO and wipes one disk, matched by its exact serial. Most cloud VMs boot from a provider image, not from an installer ISO.
- The encrypted modes need a TPM 2.0. The default mode, `tpm2+tang`, also needs a Tang server on the same LAN, at a private IPv4 address.
- The disk encryption targets disk removal and whole-machine theft. Those are threats to a box you own.
- The host firewall takes SSH from private LAN ranges by default. Do not give the box a public IP address.

So far, agentbox has run only in QEMU VMs: on an Apple Silicon Mac, and under KVM on CI's amd64 Linux runners.

### Does it need the internet?

Yes, for the install and for package changes. The first boot also needs your release URL. Apart from package changes and ntfy's link to `ntfy.sh`, agentbox itself needs no internet after first boot. No test has run a box offline yet.

| When | What it must reach |
|---|---|
| Install | Wired Ethernet with DHCP, and HTTP access to the Ubuntu archive. At the time of writing (Ubuntu 26.04.1), the installer downloads from `archive.ubuntu.com` (or a country mirror it picks, such as `<country>.archive.ubuntu.com`) and `security.ubuntu.com`, on both amd64 and arm64. On arm64, agentbox's pre-install check also contacts `ports.ubuntu.com`. Several required packages are not on the ISO. If the archive does not answer when the install starts, the install stops before it writes to any disk (not yet tested in a VM). If the connection drops later, the install fails on a disk it has already wiped. |
| First boot | The release URL from the seed, over HTTPS, and the Ubuntu archive: the release's `install.sh` installs the `ntfy` package. Firstboot retries 60 seconds after each failure, with no limit. |
| After first boot | ntfy reaches `ntfy.sh` on port 443, for phone push. The firewall lets `_ntfy` reach only the addresses rootd resolved for that name. |
| `agentbox os plan` | The Ubuntu archive, to download the packages for the change. `agentbox os apply` then installs them with no network. |
| Disk unlock at each boot | `tpm2+tang`: the Tang server on your LAN. `tpm2` and `none`: nothing. |

Two more points:

- A new generation commits only if the box has an IPv4 default route. That is part of the health check.
- Agent tasks get no network at all (built). In the design, brokers reach allowlisted hosts for them, so agents that use hosted LLM APIs will still need the internet.
