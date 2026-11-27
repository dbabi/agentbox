<p align="center"><img src="mascot/banner.png" alt="agentbox banner with the pixel-art mascot" width="640"></p>

<p align="center">
  <a href="https://github.com/dbabi/agentbox/actions/workflows/ci.yml"><img src="https://github.com/dbabi/agentbox/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/dbabi/agentbox/security/code-scanning"><img src="https://github.com/dbabi/agentbox/actions/workflows/github-code-scanning/codeql/badge.svg" alt="CodeQL"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/dbabi/agentbox" alt="License: Apache-2.0"></a>
  <a href="go.mod"><img src="https://img.shields.io/github/go-mod/go-version/dbabi/agentbox" alt="Go version"></a>
  <a href="docs/wiki/Roadmap.md"><img src="https://img.shields.io/badge/status-early%20alpha-orange" alt="Status: early alpha"></a>
</p>

# agentbox

> [!WARNING]
> **Early alpha. Not for production use.** Tested only in QEMU VMs. No AI agent can do useful work on it yet. Tasks reach a model only through the keys broker, which has never run with a real API key. The git service has never reached GitHub itself.

A headless OS for AI coding agents, built on stock Ubuntu Server 26.04. Early alpha: agent accounts, sealed task containers, the egress proxy, the LLM keys broker and the git service are built. Policy and signed approvals are designed, not built.

[Getting started][gs] · [Architecture][arch] · [Security model][sec] · [Roadmap][road] · [Wiki][wiki]

Website: https://dbabi.github.io/agentbox-web/. It is also a terminal app, and its source is in [dbabi/agentbox-web](https://github.com/dbabi/agentbox-web).

## What is agentbox

agentbox aims to be an OS where AI agents can work safely. The design rests on four rules. Three are built today:

- **No credentials in tasks (built).** LLM API keys stay in the keys broker, and the GitHub token in the git service. A task holds only a fake key, and sending it out raises an alert.
- **No network for agents (built).** Each task runs in a disposable container with no network. Traffic leaves only through the brokers: the egress proxy, the keys broker and the git service.
- **A human signs risky actions (designed).** The box will run a risky operation only after you sign it. The signature will cover its exact inputs, such as commit IDs and package hashes. Until then, each write to GitHub waits for an admin's approval on the box.
- **OS changes fall back on failure (built).** An OS change builds offline into a new generation. The box keeps it only if it boots healthy. Otherwise it boots the last good generation.

## Status

The installer, safe OS updates, the first host services (firewall, audit log, root daemon), the checks for agent requests, agent accounts, sealed task containers, the egress proxy and its Go module cache, the LLM keys broker and the git service are built. The request checks still need one 24-hour fuzz run. The keys broker has run only against a stand-in for the vendors, the git service only against a stand-in for GitHub, and the Go module cache only against a stand-in for the Go module proxy. agentbox has run only in QEMU virtual machines, never on real hardware. Everything after the OS layer has been tested only in unencrypted VMs. Agent accounts and tasks ran on arm64 UEFI only; the host services and request checks also ran on amd64 BIOS.

**Works today**, in VMs on an Apple Silicon Mac:

- Unattended install of Ubuntu Server 26.04.1 from one seed, with disk encryption and a recovery key. Zero-touch installs work on arm64 UEFI with Secure Boot on, and on amd64 legacy BIOS.
- A/B OS generations: a package change builds offline, boots once, and stays only if healthy.
- Releases you build and sign yourself with `make release`. First boot checks them against a pinned SHA-256 and your minisign key. There is no official release yet.
- A host firewall that limits each agentbox service to its allowed destinations. Inbound, it drops new connections except SSH from the seed's address ranges and Tailscale traffic.
- Agent accounts and sealed tasks. `agentbox task new` runs each task in a disposable container with no network and a fresh home. Its HTTPS goes only through the egress proxy, to the hosts on its agent's allowlist. It pushes to its agent's own git repos on the box, and each write to GitHub waits for your approval. `agentbox attach` opens a filtered interactive session.

**Not yet:**

- Policy, signed approvals, the agent bus and memory. All of them are designed. None of them is built.
- A model request with a real API key, or a push to GitHub itself. The brokers' tests use stand-ins for the vendors and GitHub.
- Real hardware. amd64 UEFI has not run anywhere.
- Automatic security updates.
- Updating agentbox itself on an installed box. This is out of scope for the first release. A new release means a reinstall.

## Why

- **Agents read untrusted text all day.** Web pages, issues and package READMEs can carry prompt injection. A hijacked task should find nothing to steal and no way to send it out.
- **Secrets belong outside the task.** In the design, brokers hold the keys and act for the task. A task cannot leak a key it never had.
- **Some actions need a person.** A push or an OS change should run only after a human approves that exact operation.
- **Updates must not break the box.** A new OS generation boots once and stays only if healthy. Otherwise the box falls back on its own.
- **Stock parts.** agentbox uses the stock Ubuntu Server installer, archive and packages. There is no custom distro. You trust Ubuntu's packages plus agentbox's own install, boot and update scripts, which are in this repo.

## Quickstart

### On an Apple Silicon Mac (VM)

These steps follow part 1 of [Getting started][gs]. You need [Homebrew](https://brew.sh), an internet connection and about 12 GB free for `.vm/`.

1. Install the tools and get the code.
   ```sh
   brew install go qemu xorriso minisign uv pkg-config
   git clone https://github.com/dbabi/agentbox.git
   cd agentbox
   ```
   For the encrypted gates, also run `brew install swtpm podman`. `make` and `ar` come with the Xcode Command Line Tools (`xcode-select --install`). If `command -v sha256sum` prints nothing, put a `sha256sum` on your `PATH`, for example from GNU coreutils.
2. Get the pinned Ubuntu ISO and check it.
   ```sh
   mkdir -p .vm
   curl -fL -o .vm/ubuntu-26.04.1-live-server-arm64.iso \
     https://cdimage.ubuntu.com/releases/26.04.1/release/ubuntu-26.04.1-live-server-arm64.iso
   (cd .vm && grep live-server-arm64.iso ../hack/SHA256SUMS | shasum -a 256 -c)
   ```
   The last command prints `ubuntu-26.04.1-live-server-arm64.iso: OK`. If the download returns 404, use https://old-releases.ubuntu.com/releases/26.04.1/ubuntu-26.04.1-live-server-arm64.iso.
3. Build the CLI and run the unit tests.
   ```sh
   go build -o bin/agentbox ./cmd/agentbox
   ./bin/agentbox version
   go vet ./... && go test ./...
   ```
   `version` prints `dev` for a plain build.
4. Optional: [Getting started, step 5][gs-dry] renders a test seed with no VM, in about a minute.
5. Run the install gate.
   ```sh
   caffeinate -i hack/gate.sh none
   ```
   The gate makes its own throwaway keys and seed. It installs the VM, boots it and checks it, in about 9-17 minutes. `caffeinate -i` stops idle sleep only, not the sleep that closing the lid starts. Keep the Mac on power with the lid open until the gate ends. On success, the gate prints `gate none: all checks passed`. Each check is listed in `.vm/gate-none.txt`.

Next, `caffeinate -i hack/gate.sh tpm2` tests an encrypted install. `caffeinate -i hack/apply-gate.sh tpm2 install setup cycles` builds, boots and commits new OS generations (about 30 minutes). The tpm2 gates need `brew install swtpm` from step 1. See [Getting started][gs] and [Testing and gates][tests].

### On real hardware (zero-touch USB)

> [!CAUTION]
> No real machine has run agentbox yet. The install erases the disk you name by its serial, with no prompt.

You need two USB sticks and a target machine: amd64 (UEFI or legacy BIOS) or arm64 (UEFI). The machine needs one target disk, and wired Ethernet with DHCP and internet access. The encrypted modes also need a TPM 2.0.

On the operator machine, build `bin/agentbox` as in Mac steps 1 and 3. On a Mac, the password hash in step 1 also needs `brew install podman`. The operator commands also work on Linux.

1. **Make your keys and a release, then host it.** From the top of the checkout:
   ```sh
   ./bin/agentbox recovery keygen --out ~/agentbox-keys
   minisign -G -p ~/agentbox-keys/minisign.pub -s ~/agentbox-keys/minisign.key
   make release VERSION=0.0.1 MINISIGN_KEY="$HOME/agentbox-keys/minisign.key"
   ```
   - `recovery keygen` writes `recovery.key` and `recovery.pub`. The seed needs only `recovery.pub`. `recovery.key` can unlock the box's disk, so keep it offline.
   - `minisign -G` asks for a password for the release signing key. `make release` asks for it again.
   - `make release` writes `dist/agentbox-0.0.1.tgz` and `dist/agentbox-0.0.1.tgz.minisig`. Then it prints the `--release-sha256` value.
   - Upload both files side by side to an HTTPS server with a CA-trusted certificate. First boot fetches the tarball's URL plus `.minisig`. The URL must not have a query string.

   Then make the admin password hash. On a Mac, run `mkpasswd` in a container. If `podman machine list` already shows a machine, skip `podman machine init`. If that machine is `Currently running`, also skip `podman machine start`.
   ```sh
   podman machine init
   podman machine start
   podman run --rm -it docker.io/library/ubuntu:26.04 sh -c 'apt-get update -qq && apt-get install -qq -y whois >/dev/null && mkpasswd -m yescrypt'
   ```
   It asks for the password and prints a hash that starts with `$y$`. On Debian or Ubuntu, run `mkpasswd -m yescrypt` directly (package `whois`).
2. **Make the install stick.** Download the pinned ISO and add the zero-touch boot option. For amd64:
   ```sh
   curl -fLO https://releases.ubuntu.com/26.04.1/ubuntu-26.04.1-live-server-amd64.iso
   hack/remaster-iso.sh ubuntu-26.04.1-live-server-amd64.iso agentbox-amd64.iso
   ```
   For arm64, use the ISO from Mac step 2:
   ```sh
   hack/remaster-iso.sh .vm/ubuntu-26.04.1-live-server-arm64.iso agentbox-arm64.iso
   ```
   These files are 26.04.1. After a newer point release, both files move to `https://old-releases.ubuntu.com/releases/26.04.1/`. The scripts accept only the pinned 26.04.1 ISOs.

   Write `agentbox-amd64.iso` or `agentbox-arm64.iso` to a USB stick of 4 GB or more. On a Mac, replace `N` with the stick's number from `diskutil list external`. For arm64, use `if=agentbox-arm64.iso`. On Linux, use the commands in step 4 of [Installing on real hardware][hw].

   **`dd` erases the device you name without asking. Check the disk number twice.**
   ```sh
   diskutil list external
   diskutil unmountDisk /dev/diskN
   sudo dd if=agentbox-amd64.iso of=/dev/rdiskN bs=4m
   diskutil eject /dev/diskN
   ```
3. **Read the disk serial.** Boot the target from that stick, with no seed stick. The installer then waits for you. Open its shell (F2, or Help, then Enter shell) and run:
   ```sh
   lsblk -d -o NAME,SIZE,MODEL,TRAN
   udevadm info --query=property --property=ID_SERIAL --value /dev/nvme0n1
   [ -d /sys/firmware/efi ] && echo uefi || echo bios
   test -c /dev/tpmrm0 && echo tpm2 || echo no-tpm
   ```
   Pick the disk to erase by its size and model. USB sticks show `usb` under `TRAN`. Put that disk's name in the `udevadm` line, for example `/dev/sda`. Use the full `ID_SERIAL` that `udevadm` prints. Do not use the `SERIAL` column of `lsblk`: it is a short form and never matches.
4. **Render the real seed on the operator machine.** Use the keys, the release and the password hash from step 1, and the values from step 3. Replace each `<...>` with your value. Keep the single quotes: the hash contains `$` signs.
   ```sh
   ./bin/agentbox seed \
     --disk-serial '<ID_SERIAL from step 3>' \
     --boot '<uefi or bios from step 3>' \
     --encryption tpm2 --recovery-pub ~/agentbox-keys/recovery.pub \
     --ssh-key "$(cat ~/.ssh/id_ed25519.pub)" \
     --password-hash '<the $y$ hash>' \
     --minisign-pubkey "$(sed -n 2p ~/agentbox-keys/minisign.pub)" \
     --release-url '<https URL of agentbox-0.0.1.tgz>' \
     --release-sha256 '<64 hex digits from make release>' \
     --out seed --iso seed.iso
   uv run --with pyyaml python3 -I hack/verify-seed.py seed/user-data
   ```
   - With no TPM, use `--encryption none` and leave out `--recovery-pub`.
   - No `~/.ssh/id_ed25519.pub`? `ssh-keygen -t ed25519` makes one.
   - `seed/user-data` and `seed.iso` hold your password hash. Keep them private.

   Write `seed.iso` to the second stick with the `dd` commands from step 2. Use `if=seed.iso` and the seed stick's disk number. The same warning applies.
5. **Install.** Check that USB is not first in the permanent boot order. With both sticks in, a USB-first order reinstalls at every boot. Plug in both sticks. Boot the ISO stick once from the firmware's one-time boot menu. Pick the same kind of entry, UEFI or legacy, that you used in step 3. The stick's GRUB menu then waits 30 seconds, which gives you a chance to stop.
6. **Find the box and save the recovery blob.** Find the box's address in your router's DHCP list, or run `ip -4 -br addr` on its console. On the console, `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` prints the host key fingerprint. Compare it with the one ssh shows when you first connect. In the commands below, replace `<box-ip>` with the address.

   In an encrypted mode, copy the recovery blob next to `recovery.key`. Run this on the operator machine:
   ```sh
   scp boxadmin@<box-ip>:/bootpart/agentbox/recovery.bin ~/agentbox-keys/
   ```
7. **Try an OS change.** Log in, then check that first boot installed the release. The second command runs on the box:
   ```sh
   ssh boxadmin@<box-ip>
   test -e /var/lib/agentbox/.firstboot-done && echo firstboot done || echo firstboot not done
   ```
   If it prints `firstboot not done`, `sudo journalctl -u agentbox-firstboot` shows why. Then plan a change with `os plan`. Replace `<H>` with the plan hash it prints before you run `os apply`. The binary is not on `PATH`.
   ```sh
   sudo /var/lib/agentbox/current/bin/agentbox os plan --reinstall --install base-files   # prints plan sha256: <H>
   sudo /var/lib/agentbox/current/bin/agentbox os apply --approve <H>                     # reboots into the trial
   ```
   The new generation boots once. The health timer commits it about a minute after boot. If the trial fails, the box falls back to the last good generation by itself.

`tpm2+tang` is the default and recommended mode. It also needs a Tang server on your LAN. Only the test Tang container has been tested so far. If Tang is down at boot, the box cannot unlock by itself. It reboots about every 8 minutes until Tang is back or you type the 48-digit disk key. `agentbox recovery decrypt` gets that key from recovery.bin with recovery.key. See [Installing on real hardware][hw], [Encryption and recovery][enc] and [Generations and updates][gens].

## Features

### Built

| Feature | What it does |
|---|---|
| `agentbox seed` | Checks every input, then writes the autoinstall seed and an optional `cidata` ISO. It lists every problem at once. |
| Unattended install | Installs stock Ubuntu Server 26.04.1 with no console input. It stops before any disk write unless the serial matches exactly one disk and the Ubuntu archive answers. Encrypted modes also need a TPM 2.0. |
| Disk encryption | Three modes. `tpm2+tang`: LUKS2, unlocked by clevis with the TPM 2.0 and a Tang server. `tpm2`: LUKS2, unlocked by the TPM 2.0 alone. `none`: no encryption. |
| Recovery key | The 48-digit disk key, encrypted to your offline RSA-4096 key. `agentbox recovery decrypt` gets it back. |
| A/B generations | Each OS version is a btrfs subvolume, plus its own `/boot` directory on the unencrypted boot partition. `/home`, `/var/log`, `/srv` and agentbox data live outside it. |
| `os plan` and `os apply` | Plans a package change. Then it builds the change offline, in a network-less `systemd-nspawn` container, from the exact `.deb` files you approved. |
| Trial boot and fallback | A new generation boots once and commits only if healthy. A broken trial falls back with no console input. |
| Release pipeline | `make release` builds a signed tarball. First boot checks its pinned SHA-256, then its signature. See [Release pipeline][rel]. |
| Zero-touch ISO | `hack/remaster-iso.sh` adds `autoinstall ds=nocloud` to the stock ISO's boot menu. It changes only GRUB's config and its checksum line. |
| Host firewall | Limits outbound traffic for each agentbox service. If the rules change, it alerts and restores them. |
| Audit log | Stores each record on disk before it acknowledges it. `agentbox audit verify` checks the log's hash chain. |
| Broker network setup | Resolves the allowed destinations for the brokers. Refuses private and special-purpose addresses. |
| Egress proxy | Carries each task's HTTPS to the hosts on its agent's allowlist. It holds no secrets, dials only the addresses the root daemon checked, and records taint on the task before any byte flows. |
| Go module cache | Keeps each agent's downloaded Go modules, so its next Go task skips the downloads. Only the proxy writes it, and only with files that match Go's signed checksum database. Each use taints the task first, as a download would. |
| Keys broker | Holds the LLM API keys, encrypted on disk, and adds them to each task's model requests. It checks every request against a closed list of fields and against the agent's budget. A reply that carries the key back never reaches the task. |
| Git service | Hosts each agent's git repos on the box. A root-owned hook keeps pushes in the agent's own branches and under a daily cap. Each write to GitHub waits for an admin's approval, and runs once. It holds the GitHub token, encrypted on disk. See [Git and GitHub][git]. |
| Disk limits | Caps the disk space agent data can use, and keeps a reserve for system services. |
| Notifications | The Ubuntu `ntfy` package. It takes only local requests, and can reach only `ntfy.sh`. |
| Operation registry | One list of every operation an agent may request. The policy schema, the JSON schemas and the MCP tool list are generated from it. The root daemon refuses to start if any of them differ. |
| Agent accounts | `agentbox agent add` makes one Linux account per agent, with its own uid, sub-id range, disk quota and limits. A removed agent's ids are never reused. |
| Task containers | `agentbox task new` runs each task in a disposable rootless podman container: no network, no capabilities, a read-only root, a seccomp profile and a fresh home. Leftover processes are killed at the end. Each task start snapshots the workspace, and `agentbox task undo` puts it back. |
| Task environment | Each task gets no DNS, quiet package managers and Go settings that follow its allowlist. `agentbox why` explains a recent denial. |
| Interactive sessions | `agentbox attach` runs an agent CLI or a shell in a container, with a separate persistent home. Planted hooks don't run, the output is filtered, and tasks wait for a token scan. |
| Request checks | `agentboxd` gives each task its own socket. It checks each request's caller and arguments before anything privileged runs. A refused request gets a stable denial code, never the raw input. |
| Socket layout | Every service socket and directory, with its owner and mode, is defined in code. `agentbox sockets check` compares the box with it. |
| Test harness | Checks installs, OS changes, power cuts and the host services in throwaway QEMU VMs. See [Testing and gates][tests]. |

### Designed, not built

| Feature | Plan |
|---|---|
| Policy and approvals | Cedar policy. You will sign approvals on your laptop with an SSH key. A phone passkey will cover only low-risk requests. The box will run only the operation you signed. |
| Agent bus and memory | Messages between agents. Shared memory with quarantine and taint. |
| OS updates | Nightly package updates will build into a new generation. Protected packages can't be removed. |

## Architecture

```text
   laptop: agentbox CLI                 phone: passkey
   (designed) signs approvals           (designed) low-risk
   over SSH                             asks only
             |                                   |
+------------v-----------------------------------v-----------------+
| agentbox host: stock Ubuntu Server 26.04                         |
|                                                                  |
|  DESIGNED, NOT BUILT (except where marked)                       |
|  agentboxd        policy, agent bus, shared memory               |
|  agentbox-rootd   signed operations, bound to their exact inputs |
|                                                                  |
|  +----------------------+  unix sockets  +---------------------+ |
|  | task container       |--------------->| brokers             |----> internet
|  | (built) no network,  |                | (built) proxy, no   | |
|  | fresh HOME each task |                |   secrets           | |
|  +----------------------+                | (built) keys, LLM   | |
|                                          |   API keys          | |
|                                          | (built) git, GitHub | |
|                                          |   token             | |
|                                          +---------------------+ |
|                                                                  |
|  BUILT TODAY                                                     |
|  agentboxd        request checks: caller, arguments, denials     |
|  agentbox-rootd   agent accounts, task start and stop, attach,   |
|                   allowed broker destinations                    |
|  agentbox-auditd  hash-chained audit log and taint ledger        |
|  Firewall         outbound rules per service,                    |
|                   restores configured rules after changes        |
|  Disk limits      caps agent data; reserves system space         |
|  OS generations   offline build and one trial boot,              |
|                   keep if healthy; automatic fallback            |
|  Releases         signed tarball, checked at first boot          |
|  Disk             LUKS2 + clevis (TPM 2.0, Tang), recovery key   |
+------------------------------------------------------------------+
```

All agentbox services are subcommands of one Go binary, `agentbox`. Today it prepares installs, manages OS generations, checks audit logs, checks agent requests and runs task containers. The [Architecture][arch] page walks through the design part by part.

## Security model

The design treats prompt injection as the most likely attack. It also plans for a compromised agent tool, a thief, someone on your LAN, and bugs in agentbox itself. It has seven rules. The table shows which are built:

| Rule | Status |
|---|---|
| 1. Tasks have no network. | Built and tested. The egress proxy, the keys broker and the git service carry a task's traffic. |
| 2. No credential exists inside a task. | Built and tested for the LLM API keys and the GitHub token. |
| 3. Agents never change the running OS. Changes build offline into a new generation, which commits only after a health check. | Generations built and tested. The agent side is designed. |
| 4. Privileged operations run only with the exact inputs a human signed. | Designed |
| 5. Taint is sticky. Work that touched untrusted content stays marked until a human clears it. | Partly built. A tainted task taints its workspace, and the next task there starts tainted. Every connection through the egress proxy taints its task, and so do a use of the Go module cache and a model request that uses a vendor web tool. A tainted task's push taints the branches it updates, and a merge carries that taint into `main`. |
| 6. Nothing persists between tasks except the tainted workspace. | Built and tested. The one other store that outlives a task is each agent's Go module cache. Tasks can't write it, it holds only public module files that match Go's signed checksum database, and a task can read it only once it is tainted. |
| 7. The seed and logs hold no plaintext secrets. | Built and tested |

Known limits of what is built today:

- In `tpm2` mode, a thief with the whole machine can unlock the disk. Use `tpm2+tang`.
- In `tpm2+tang` mode, an attacker who stays on your LAN with physical access can unlock it too.
- A signed but malicious package in a plan you approve runs as root at the trial boot. Fallback covers crashes, not hostile code.
- The admin account is root-equivalent. The seed holds its password hash, so keep the seed private.
- The host firewall takes SSH only from the address ranges in the seed. By default those are the private LAN ranges, the Tailscale range and link-local. Do not give the box a public IP address.
- Rootful Docker is unsupported. The ports it publishes bypass the host firewall.
- There are no automatic security updates.
- All tasks share the host kernel. A kernel exploit escapes the container.

Read the one-page [threat model](docs/THREAT-MODEL.md) and the [Security model][sec] page.

## Roadmap

agentbox is built in milestones, in this order. Each one ends with tests that must pass before the next one starts. The [Roadmap][road] page has the details.

1. **Installer and safe OS updates: done.** Encrypted installs, recovery keys, signed releases and package changes with automatic fallback. Tested in VMs only.
2. **Firewall and audit log: done.** Outbound limits for agentbox services, an audit log you can verify, disk limits and local notifications. Tested in VMs only.
3. **Checks for agent requests: in progress.** Built and tested in VMs. Each agent request is checked against one list of allowed operations before anything privileged runs. A 24-hour fuzz run is the last step.
4. **Isolated tasks: done.** Agent accounts, one disposable container per task with no network, and interactive sessions. Tested in VMs only.
5. **Brokers: in progress.** The egress proxy, the keys broker and the git service are built and tested in VMs. They connect only to addresses the root daemon checked. LLM API keys stay outside tasks, in the keys broker, and the GitHub token in the git service. The proxy also keeps a read-only Go module cache for each agent.
6. **Signed approvals: planned.** Risky actions will need your SSH signature. A phone passkey will cover low-risk requests.
7. **Apps and OS updates by agents: planned.** Agents will request app installs, file changes and package updates. OS changes will build offline into new generations.
8. **Agent bus and shared memory: planned.** Tasks will hand work to each other. Facts from untrusted sources will stay marked.
9. **Benchmark and first release: planned.** Benchmark results, an external security review and the first official signed release.

## Contributing

agentbox is early, and the design still changes. Issues and pull requests are welcome.

- Read [Contributing][contrib] for the dev setup and code style. The code is Go. The installer and the VM scripts are POSIX `sh`. The seed checker is Python, run with `uv`.
- Run `go vet ./... && go test ./...` before you send a change.
- For a change to the installer or to `os apply`, also run the matching VM gate.
- Report security problems privately, as [SECURITY.md](SECURITY.md) and [Reporting a vulnerability][report] describe. Do not put any details in a public issue.

## License

Apache-2.0. See [LICENSE](LICENSE).

## Acknowledgements

agentbox stands on the work of many open-source projects. It builds on Ubuntu Server and its installer, subiquity and curtin. Disk unlock at boot uses clevis and Tang. Every test VM runs on QEMU. The encrypted ones use swtpm as their TPM. It also relies on systemd, btrfs, GRUB, dracut, cryptsetup, minisign, xorriso and podman.

<p align="center"><img src="mascot/agentbox-mascot.png" alt="The agentbox mascot in pixel art" width="128"></p>

[wiki]: docs/wiki/README.md
[gs]: docs/wiki/Getting-Started.md
[gs-dry]: docs/wiki/Getting-Started.md#step-5-render-a-test-seed-dry-run-no-vm
[hw]: docs/wiki/Installing-on-Real-Hardware.md
[enc]: docs/wiki/Encryption-and-Recovery.md
[gens]: docs/wiki/Generations-and-Updates.md
[tests]: docs/wiki/Testing-and-Gates.md
[rel]: docs/wiki/Release-Pipeline.md
[arch]: docs/wiki/Architecture.md
[sec]: docs/wiki/Security-Model.md
[road]: docs/wiki/Roadmap.md
[git]: docs/wiki/Git-and-GitHub.md
[contrib]: docs/wiki/Contributing.md
[report]: docs/wiki/Security-Model.md#reporting-a-vulnerability
