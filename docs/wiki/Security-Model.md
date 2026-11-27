> **Early alpha. Not for production use.** Today agentbox is an installer, an OS layer, the first host services (a firewall, an audit daemon and a root daemon), agent accounts, sealed task containers, the egress proxy and the LLM keys broker. The git service, policy and approvals hold most of the rest of the security design, and they are not built. No external security review has happened yet.

This page summarizes the agentbox threat model. It covers what agentbox protects, who it defends against, the trust boundaries, and the risks that remain.

To report a vulnerability, go to [Reporting a vulnerability](#reporting-a-vulnerability).

The repository has a one-page threat model for the full design: [`docs/THREAT-MODEL.md`](../../docs/THREAT-MODEL.md).

This page uses the two status words from [Home](README.md):

- **Built:** the code exists and has passed its tests in QEMU VMs.
- **Designed:** the design in [`docs/design/`](../design/ARCHITECTURE.md) describes it, but there is no code yet.

Milestone numbers refer to the ordered list on the [Roadmap](Roadmap.md). Milestones 1, 2 and 4 are built. Milestone 3 is built and waits only for its 24-hour fuzz run. v1 is the first release, and v2 is the version after it. Facts on this page describe the `main` branch at the time of writing.

Contents:

- [What agentbox protects](#what-agentbox-protects)
- [Who attacks, and how](#who-attacks-and-how)
- [Trust boundaries](#trust-boundaries)
- [What is enforced today](#what-is-enforced-today)
- [Design invariants](#design-invariants)
- [Residual risks](#residual-risks)
- [Advice for testers](#advice-for-testers)
- [Reporting a vulnerability](#reporting-a-vulnerability)

## What agentbox protects

The design protects four things:

1. **The host:** the OS generations, the boot chain, and other users.
2. **Secrets:** LLM API keys, the GitHub token, Tailscale and ntfy credentials, and the disk encryption (LUKS) key.
3. **The owner's data and LAN:** files in `/srv` and in workspaces, plus the devices on the home network.
4. **Integrity:** of approvals, the audit log and shared memory.

Built controls cover part of this today:

- the LUKS key, and the data on the encrypted disk;
- the LLM API keys, which only the keys broker can read, and which a task never holds;
- the agentbox release that firstboot installs;
- the integrity of OS package changes;
- outbound traffic from agentbox's own service users, which the host firewall holds to the addresses rootd resolved;
- inbound traffic, which the host firewall drops, except replies to the box's own connections, SSH from the seed's address ranges, Tailscale traffic, DHCP replies, and IPv6 neighbor discovery and multicast listener queries;
- an audit log that records each rootd effect before it runs, and a taint ledger that only rootd's admin path can clear;
- the host and other agents, from code in a task: each task runs under its agent's own account, in a disposable container with no network, no capabilities and a seccomp profile;
- the LAN and the metadata address, from a task's egress: the proxy reaches only the agent's allowlisted hosts, at addresses rootd checked;
- the admin's terminal and later tasks, from an interactive session: its output is filtered, and tasks wait until a scan finds no copy of its login token.

Everything else depends on parts that are designed, not built.

## Who attacks, and how

| Attacker | Way in | Defense today | Planned |
|---|---|---|---|
| Prompt injection, the most likely attacker | Web pages, package READMEs, issues and pull requests, logs, other agents' messages, shared memory | Tasks are sealed: no network, and nothing but the workspace carries over to the next task. A task reaches the internet only through the egress proxy, to its agent's allowlist, and a model only through the keys broker. The proxy taints each task it connects. An agent you run outside a task is not confined. | The git service, policy and approvals (milestones 5-8) |
| A compromised agent CLI or dependency | Code that runs inside a task | One disposable rootless container per task, with no network, no capabilities and a seccomp profile. **Built.** All tasks share the host kernel. | microVM tasks (v2) |
| A thief | The disk alone, or the whole powered-off machine | Disk encryption. **Built.** | A signed PCR 11 policy for `tpm2` mode (v2) |
| Someone on your LAN or Tailscale network | Open ports, the approval page | SSH accepts keys only. The host firewall drops inbound traffic by default. From the LAN it accepts SSH only from the seed's `--ssh-from` ranges. Besides SSH and replies to the box's own connections, it lets in only DHCP replies, IPv6 neighbor discovery and multicast listener queries, and Tailscale's UDP port 41641. It accepts everything that arrives over Tailscale. Tailscale and the approval page are not installed or built. | The approval page comes in milestone 6. Each approval needs a passkey, and the page handles low-risk operations only. |
| A bug in agentbox's own code | Today: the seed generator, the installer, firstboot, `agentbox os`, and the parsers in rootd, auditd, agentboxd, the proxy and the keys broker. Designed: the parsers in the git service and in the local model server. | Strict input checks in `agentbox seed`. OS changes build offline. agentbox itself listens on no network port. Fuzz tests for the built services' parsers. The 24-hour fuzz run is pending (milestone 3). | Fuzz tests for the git service's parsers as it is built. The local model server runs with no network and no secrets. |

## Trust boundaries

A trust boundary is a place where data or control passes between parts that trust each other differently.

### Built today

| Boundary | What crosses it | Control today |
|---|---|---|
| Operator machine to box, through the seed | SSH keys, the password hash, release pins, the recovery public key, the Tang URL and thumbprint | `agentbox seed` checks every input. It writes the seed files with mode 0600. The seed is not signed: whoever writes it controls the box. |
| Release host to box | The agentbox release tarball | Firstboot checks the seed's SHA-256 pin, then the minisign signature. It downloads over HTTPS only. |
| Ubuntu archive to box | `.deb` packages | apt checks the archive's signed index. `os plan` records each `.deb` SHA-256, and `os apply` checks them again. |
| Running generation to a new generation | Package changes | An offline build in `systemd-nspawn`, with a private user-ID range and no network. One trial boot, then a commit only if the health check passes. |
| OS generation to persistent data | `/home`, `/var/log`, `/srv`, `/var/lib/agentbox` | This data lives outside the generations. A fallback does not roll it back. |
| Disk to thief | The disk, or the whole machine | LUKS2, unlocked by clevis with the TPM 2.0 chip, or with the TPM plus Tang |
| LAN to box | SSH, and Tang requests during boot | SSH accepts keys only. The host firewall drops inbound traffic by default. From the LAN it accepts SSH only from the seed's `--ssh-from` ranges. The default is the private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), `100.64.0.0/10` and IPv6 link-local (`fe80::/10`). `100.64.0.0/10` is Tailscale's range, and ISPs also use it for carrier-grade NAT. From any address, the firewall accepts replies to the box's own connections and Tailscale's UDP port 41641. The same goes for DHCP replies (DHCPv6 only from link-local), IPv6 neighbor discovery and multicast listener queries. A port that a service opens stays closed to the LAN. `fwcheck` checks the input chain and the SSH ranges like the rest of the table. |
| Tailnet to box | Everything that arrives on the `tailscale0` interface | The host firewall accepts all of it, on every port. agentbox does not install Tailscale yet. |
| agentbox service users to the network | Outbound connections from the broker uids and `_ntfy` | The `inet agentbox` nftables table: each uid reaches only the address and port pairs in its own set. Private and special-purpose ranges are dropped unless that exact uid, address and port is on an allow list. Only rootd fills the sets, from names it resolved. `fwcheck` restores an altered table within 60 s, and agent units can't start while it fails. |
| Producers to the audit log | Audit records | One socket per producer, checked with `SO_PEERCRED`. auditd acknowledges a record only after it is on disk, and the effect waits for that. rootd seals each finished segment immutable. |
| Console to box | The keyboard and boot media | Console login needs the admin password. GRUB has no password. |
| Container to host kernel | Task code | One rootless podman container per task, under the agent's own uid and sub-id range: no network, no capabilities, `no-new-privileges`, a read-only root and a seccomp profile. The profile blocks btrfs ioctls, namespace creation and 32-bit compat syscalls, and allows only Unix, IPv4, IPv6 and routing netlink sockets. All tasks share the host kernel. |
| Task to the internet, through the proxy | HTTPS `CONNECT` requests | The proxy checks each target against the agent's allowlist and holds no secrets. It dials only the addresses rootd checked, and auditd records the task's taint before any byte flows. |
| Task to the LLM vendors, through the keys broker | Model requests and replies | A closed schema for each endpoint. The key is added outside the task. auditd records each request before it leaves. A reply that carries the key never reaches the task. |
| Task to its own sockets | Requests from task code | rootd creates a socket directory for each task, and revokes it when the task ends. agentboxd checks the caller of each request from the socket. |
| Interactive session to the admin's terminal | Session output | rootd relays it through a filter that drops clipboard writes, DCS strings, and the device attribute, status and window report requests. |

agentbox trusts these anchors today:

- Ubuntu's archive signing keys, for every package.
- The SHA-256 pins in `hack/SHA256SUMS`, for the stock Ubuntu ISO.
- Your minisign key and the seed's SHA-256 pin, for the agentbox release.
- Your recovery key pair, for the LUKS key.
- Your Tang server, for unattended unlock in `tpm2+tang`.
- The seed itself, which carries your SSH keys, password hash, release pins and recovery public key.

### Designed, not built

In the design, `agentboxd` is the gate and policy daemon, and `agentbox-rootd` (rootd) is the root executor. `approvald` serves the phone approval page.

| Boundary | Planned control |
|---|---|
| agentboxd to rootd | For operations that need a signature, rootd runs only the stored operation a human signed, bound to its exact inputs. |
| Agent to agent | A typed message bus with provenance and sticky taint. |
| Model to policy | Models propose, and code decides. No model output grants a permission. |
| Memory to prompts | Shared memory with quarantine and taint. |
| Phone to approvald | Phone approvals with a passkey, for low-risk operations only. |

Taint marks work that has touched untrusted content.

## What is enforced today

### Disk encryption

The seed's `--encryption` flag picks the mode. The default is `tpm2+tang`. [Encryption and Recovery](Encryption-and-Recovery.md) has the details.

| Mode | Unlocks with | Protects against | Does not protect against |
|---|---|---|---|
| `tpm2+tang` (default, recommended) | The TPM 2.0 chip and a Tang server on your LAN. Both are needed. | A removed disk. Theft of the whole machine, when it starts away from your LAN. | Someone who stays on your LAN with physical access |
| `tpm2` | The TPM 2.0 chip alone | A disk removed or thrown away without its TPM and board | Theft of the whole machine |
| `none` | Nothing: no encryption | Nothing | Everything |

- The root file system is btrfs inside LUKS2. clevis unlocks it in the initramfs, with no input.
- In `tpm2+tang`, clevis splits the key between the TPM and Tang, with a threshold of 2. The seed pins the Tang key thumbprint.
- The TPM binding has no PCR policy. Booting any Microsoft- or Canonical-signed medium, such as a stock Ubuntu USB stick, reproduces PCR 7, so PCR 7 adds nothing against these threats. It would also break unattended unlock after Secure Boot database updates.
- The Tang URL must be plain `http://` to a private IPv4 address: 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16. The initramfs has no DNS resolver and no CA bundle. `agentbox seed` refuses host names, `https` and public addresses.
- Tang never receives the disk key, so plain HTTP is part of its design.
- `agentbox seed` prints a warning for `tpm2` and for `none`.
- In the encrypted modes, the install stops before any disk write if it finds no TPM 2.0 (not yet tested in a VM).

The VM gates check these, with a software TPM (swtpm): unattended unlock in `tpm2` and `tpm2+tang`; no unlock while Tang is down; unlock with a typed recovery key; and unlock with no input once Tang is back. No hardware TPM has been tested.

### Recovery key

- `agentbox recovery keygen --out DIR` makes an RSA-4096 key pair on the operator machine. It writes `recovery.key` with mode 0600. Keep that file offline.
- keygen refuses to overwrite key files. It also refuses a directory that other users can write.
- The installer makes the LUKS key: 48 random digits, in tmpfs only.
- It encrypts that key to your public key (RSA-OAEP with SHA-256), as `/bootpart/agentbox/recovery.bin`. Then it shreds the tmpfs copy.
- `recovery.bin` is useless without `recovery.key`.

### Release integrity

- `make release` signs the release tarball with minisign.
- The seed pins the release URL, the tarball's SHA-256 and the minisign public key.
- Firstboot downloads over HTTPS. It follows redirects only to HTTPS, and it accepts at most 64 MiB per file.
- It checks the SHA-256 pin first, then the signature. A valid signature alone would accept any older signed release. The pin stops a rollback to an old release.
- If either check fails, firstboot installs nothing. It retries every 60 s.
- Every install gate serves firstboot a tampered tarball, an older signed release, and a release signed by another key. Firstboot refuses all three.
- `hack/remaster-iso.sh` and `hack/vm.sh install` refuse a stock Ubuntu ISO that does not match its pin in `hack/SHA256SUMS`.
- Release builds are reproducible: a CI build on Linux and a rebuild on a Mac with the same Go version gave byte-identical tarballs. `hack/sign-release.sh` signs only when they match.

[Release Pipeline](Release-Pipeline.md) has the details.

### OS changes

`os plan` and `os apply` change packages without changing the running generation. Both run as root on the box. [Generations and Updates](Generations-and-Updates.md) has the details.

1. `os plan` resolves the change against a copy of the running generation's package state. It downloads every `.deb` and checks it against apt's signed index. It prints every action and every `.deb` SHA-256. It installs nothing.
2. The plan's SHA-256 is the approval. `os apply --approve <plan sha256>` builds exactly that plan. It refuses if the installed packages changed since the plan.
3. The build clones the running generation. It runs apt inside `systemd-nspawn`, with a private user-ID range and no network. apt sees only the approved `.deb` files, checked again by SHA-256. Service starts and GRUB writes are blocked.
4. Every new initrd must hold the modules that unlock and mount the root file system. If one does not, the build is discarded.
5. The new generation boots once. It becomes the committed generation only after a health check passes. Otherwise the box falls back to the committed generation, with no console input.

This protects the box from a broken update. It does not protect the box from a hostile package. Once the trial generation boots, its code runs as real root. See [Residual risks](#residual-risks).

### Secrets in the seed and logs

- The seed holds public keys and the admin password hash. It holds no plaintext secrets.
- `agentbox seed` writes `user-data`, `meta-data` and `seed.iso` with mode 0600.
- The password hash must be yescrypt, or sha512-crypt with at least 100000 rounds. The seed must resist offline guessing, so `agentbox seed` refuses `openssl passwd -6` hashes (5000 rounds).
- The installer deletes its copy of the seed, and the install configs it generated, before it saves its logs.
- The install gate checks that no password hash appears under `/var/log`, and that the installer's LUKS keyfile is shredded.
- It also checks that the LUKS key is in no file under `/var/log`, `/etc`, `/bootpart` or `/boot`.

### Login

- SSH accepts key login only. Password login over SSH is off.
- From the LAN, the host firewall accepts SSH only from the seed's `--ssh-from` ranges.
- The seed accepts these SSH key types: `ssh-ed25519`, `sk-ssh-ed25519@openssh.com` (FIDO security keys), `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, and `ssh-rsa` of 3072 bits or more.
- The admin password works only on the console and for `sudo`.
- Ubuntu's root account stays locked.

### Boot

- The initramfs never opens a shell (`rd.shell=0`). It reboots instead (`rd.emergency=reboot`). These settings keep a failed boot from waiting for input. They do not stop someone at the console. GRUB has no password, so anyone at the keyboard can edit the kernel command line.
- Emergency and rescue mode reboot after 120 s. A failed boot does not wait for console input.
- agentbox installs and boots with Secure Boot on. This has run only in an arm64 UEFI VM. On UEFI, the install gate checks that shim accepts every installed kernel.
- Disk unlock does not depend on Secure Boot. Secure Boot checks the boot loader and the kernel, not the initrd.

## Design invariants

The design sets seven rules, and tests must prove each one. Most of them depend on the agent runtime.

| # | Rule | Status |
|---|---|---|
| 1 | Tasks have no network. | **Built** and gate-proven for task containers (milestone 4) and for the proxy and the keys broker (milestone 5). The firewall that confines the brokers is built (milestone 2). The git service is designed. |
| 2 | No credential exists inside a task. | **Built** and gate-proven for the LLM API keys (milestone 5): a task holds only a placeholder key, and the keys broker adds the real one. The GitHub token waits for the git service. |
| 3 | Agents never change the running OS. OS changes are built offline into a new generation, and committed only after a health check. | The generation mechanism is **built** and gate-proven. Agents and their path to it are designed. |
| 4 | rootd runs only the stored operation a human signed. | Designed. Today, root approves a plan by passing its SHA-256 to `os apply`. |
| 5 | Taint is sticky. Only a human clears it. | The ledger is **built** (milestone 2): a clear from any socket but rootd's admin path is rejected, and the row stays with its epoch moved on. A tainted task taints its workspace, and the next task there starts tainted (milestone 4). The proxy taints each task it connects, and the keys broker taints a task that uses a vendor web tool (milestone 5). The rest of what sets taint is designed. |
| 6 | Nothing persists between tasks except the tainted workspace. | **Built** and gate-proven for task containers (milestone 4) |
| 7 | The seed and logs contain no plaintext secrets. | **Built** and gate-proven. The seed holds the password hash, so keep it private. |

## Residual risks

These are the known risks. They are listed so you can decide where agentbox fits. A report that finds a way past one of the stated limits is still welcome.

### In the built parts

**Outside tasks: no sandbox, and a firewall that trusts the tailnet**

- agentbox confines only tasks and interactive sessions. Any other program you run on the box is a normal Linux process.
- Outbound, the host firewall (milestone 2) filters only agentbox's own service users. It does not filter your admin account or root.
- Inbound, it accepts everything that arrives on `tailscale0`. Once Tailscale runs, every port that a service opens is reachable from every device on your tailnet.
- The default `--ssh-from` ranges hold every private LAN range and `100.64.0.0/10`, so any device on your LAN can reach SSH. ISPs also use `100.64.0.0/10` for carrier-grade NAT, so on such an uplink other customers can reach SSH too. Narrow the ranges with `--ssh-from` when you make the seed.
- UDP port 41641 is open from any address, for Tailscale's direct connections.
- Rootful Docker is unsupported. The ports it publishes go through the forward hook, which the host firewall does not filter.
- The brokers don't exist yet, so nothing yet hides systemd-resolved's local Varlink and D-Bus interfaces from the broker uids. The broker units will do that (`docs/THREAT-MODEL.md` lists it).
- While the disk is full, auditd refuses best-effort records such as denials, so those leave no audit record.
- The milestone 2 gates ran in `none` mode only, on arm64 UEFI and amd64 BIOS, not in the encrypted modes.

**Tasks and interactive sessions**

- All tasks share the host kernel. A kernel exploit escapes the container. The v2 plan is microVM tasks.
- The token scan after a session looks for each token as written, in the first 256 MiB of each file. An encoded token, one spliced together inside a git delta, or one further into a file is missed.
- The session output filter passes a charset switch (`ESC %`), after which some terminals obey control codes the filter does not see, such as a clipboard write. It also passes report requests other than the ones it drops, such as a terminal version query (issue #210).
- A file that a workspace git config pulls in with `include.path` is not a control path. After you acknowledge the include line, that file can change with no new acknowledgement (issue #193).
- Only listed files in `session-home` are control paths: the CLIs' instruction files and what the shells, editors, pagers, Python, ssh, git and go read at startup.
  Another tool's per-user config, or a cache that a tool trusts, is not. A session can plant one, and a later attach runs it when you use that tool.
- The milestone 4 gates ran in `none` mode on arm64 UEFI only, with stand-in brokers.

**Updates**

- There are no automatic security updates. The seed masks apt's daily timers. Packages do not change on their own. Change them only with `os plan` and `os apply`. A direct `apt` run changes the running generation in place, outside A/B, and makes an existing plan fail with `stale_base`. The nightly `os.update` is planned for milestone 7.
- agentbox itself has no update path on an installed box. A fix to agentbox needs a reinstall. Do not run `install.sh` by hand: that skips the SHA-256 pin and the signature check. A release-update path is out of scope for v1.
- `os apply` regenerates `grub.cfg`, but it never runs `grub-install` and never writes the EFI system partition. So shim and GRUB package updates do not reach the boot loader. The design adds a boot-chain step after a commit that changes boot packages, outside A/B. It is not built.
- Firmware and Secure Boot revocation (dbx) updates do not run on their own. `secureboot-db.service` is masked, and `fwupd` only refreshes its metadata.

**Packages and approvals**

- A signed but malicious package in an approved plan runs as root at the trial boot. It can read the LUKS key and rewrite `/bootpart` and the EFI system partition. A/B fallback covers crashes, not hostile code. The v2 plan is a measured trial boot.
- There is no protected-package floor yet. agentbox does not stop a plan from removing a package the box needs, such as `openssh-server`. Read every line of a plan before you approve it. The floor is planned for milestone 7.
- Approval is one step by root today: pass the plan's SHA-256 to `os apply`. Signed approvals are planned for milestone 6.

**Accounts and the seed**

- The admin account is root-equivalent: the installer adds it to the `sudo` group. Whoever controls the admin account can become root.
- The seed is not signed. Whoever can change `user-data` or `seed.iso` before the install chooses the box's SSH keys, password hash and release.
- Whoever can read the seed has the password hash, and can try to guess the password offline.

**Physical access**

- In `tpm2` mode, the TPM unlocks the disk for any boot. A thief with the whole machine can get the data. One way is to change the initrd on the unencrypted `/bootpart` so that it captures the key. Use `tpm2+tang` instead. The v2 plan is a unified kernel image (UKI) with a signed PCR 11 policy.
- `tpm2+tang` does not protect against someone who stays on your LAN with physical access.
- If a thief also takes your Tang server, or can reach it from elsewhere, `tpm2+tang` protects no more than `tpm2`.
- GRUB has no password. Anyone at the console can change the kernel command line at boot. In `tpm2` mode, or in `tpm2+tang` while Tang is reachable, an edited command line can give a root shell with the disk unlocked. No test has tried this.
- `/bootpart` is not encrypted. It holds the kernels, initrds, GRUB files and `recovery.bin`. On UEFI, the EFI system partition is not encrypted either.
- With `--encryption none`, the LLM API keys are encrypted on disk with a host key that sits on the same unencrypted disk. Anyone who reads the disk can decrypt them. In the TPM modes the TPM holds that key, with no PCR policy, so whoever can boot the machine can decrypt them too.

**Availability and recovery**

- With `tpm2+tang`, a Tang outage stops unattended boot. The box reboots in a loop of about 8 minutes, until Tang is back or someone types the recovery key.
- If the TPM or Tang can no longer unlock the disk, and you lose `recovery.key` or every copy of `recovery.bin`, the data is gone.
- After a cleared TPM or a board swap, the design says to unlock with the recovery key and then run `clevis luks regen`. No test covers this yet.

**Test coverage**

- agentbox has run only in QEMU VMs. The encrypted modes used a software TPM (swtpm). No real hardware has run agentbox.
- amd64 UEFI has not run anywhere. Secure Boot has run only in an arm64 VM.
- No external review has happened. An external review of the threat model is planned for milestone 9.
- The QEMU test VM reaches the host's `127.0.0.1` only on the Tang and release-serve ports. It can still reach the host's LAN.
- `--dev` seeds are for the QEMU VM only. They also accept a plain `http://10.0.2.2:PORT` release URL. Firstboot still checks the pin and the signature.
- The gates use a throwaway admin password (`x`) and throwaway keys in `.vm/keys` and `.vm/id_vm`. Never use them for a real box.

### In the designed parts

When the agent runtime is built, the design accepts these risks for v1:

- A connection to an allowlisted host on a CDN can reach other sites on the same CDN (domain fronting). An allowlisted host that accepts uploads can also receive data.
- Root can tamper with the audit log on the box. The fix is to ship audit records off the box.
- Root can always remove confinement. After a root-level firewall flush, brokers are unconfined for up to 60 s, until the next check.
- A compromised agentbox service can weaken specific checks. Two examples: a broker that omits taint, and an approval daemon that swaps in its own passkey during the 120 s registration window, if you then confirm it. Each case has a planned v2 change.
- A phone approval page can mislead you about a low-risk operation. Model labels can also bias a human reviewer.

The full list, with upgrade paths, is in [`docs/THREAT-MODEL.md`](../../docs/THREAT-MODEL.md).

## Advice for testers

Before the install:

1. Use `--encryption tpm2+tang`, the default. Keep the Tang server reachable from your LAN only. agentbox has not tested a real Tang server. [Encryption and Recovery](Encryption-and-Recovery.md) has untested setup steps.
2. Make the recovery key pair on the operator machine with `./bin/agentbox recovery keygen --out ~/agentbox-keys`. Run it from the repo root. Keep `recovery.key` offline.
3. Use a strong admin password. On Debian or Ubuntu, `mkpasswd -m yescrypt` makes the hash (package `whois`).
4. Guard the admin SSH key like a root key. The seed also accepts a FIDO security key (`sk-ssh-ed25519@openssh.com`). No test has used one yet.

After the install:

5. Copy `recovery.bin` off the box, and keep it with `recovery.key`. Use your admin name if you changed `--admin`:

   ```sh
   scp boxadmin@<box-ip>:/bootpart/agentbox/recovery.bin ~/agentbox-keys/
   ```

6. Remove the install stick and the seed stick. Keep any copies of `user-data` and `seed.iso` private.
7. Keep the box on a network you trust. The host firewall accepts SSH from every private LAN range and `100.64.0.0/10` unless you narrow `--ssh-from`, and everything from your tailnet once Tailscale runs.
8. Apply updates yourself, and read every plan before you approve it. `os plan` takes package names. It has no option yet to plan every pending update at once. `os apply` reboots into the trial generation unless you pass `--no-reboot`:

   ```sh
   sudo /var/lib/agentbox/current/bin/agentbox os plan --install <package>
   sudo /var/lib/agentbox/current/bin/agentbox os apply --approve <plan sha256>
   ```

9. Do not run untrusted code on the box, or in the test VM.

## Reporting a vulnerability

Report security problems privately. Do not put any details in a public issue.

How to report:

1. Open the repository's **Security and quality** tab, or find it under the **...** menu.
2. Choose **Report a vulnerability**. The direct link is `https://github.com/dbabi/agentbox/security/advisories/new`.

GitHub can rename the tab; the direct link stays the same.

If you see no **Report a vulnerability** button, open an issue that asks for a security contact. Put no details in it.

The repository's `SECURITY.md` has the same text. GitHub shows it on the report form.

Include:

- the commit you tested (`git rev-parse --short HEAD`), or the release version the box runs (`sudo /var/lib/agentbox/current/bin/agentbox version`);
- the seed's `--encryption` and `--boot` values;
- where it ran: a QEMU VM or real hardware, and the CPU architecture;
- the steps to reproduce;
- what an attacker gains.

Never send:

- `recovery.key` or `luks.key`;
- a real `user-data` or `seed.iso`, because they hold your password hash;
- private SSH or minisign keys.

Remove any disk serials, host names and addresses that you do not want to share.

In scope: the code in the repository. That covers `agentbox seed`, the installer it renders, firstboot and `install.sh`. It also covers the host services (the firewall, auditd, rootd and agentboxd), task containers, interactive sessions, `agentbox os`, `agentbox recovery`, `make release`, and the test harness, which runs on your machine.

Out of scope:

- parts that are designed but not built (open a normal issue for design feedback);
- bugs in Ubuntu packages (report those to Ubuntu);
- the residual risks on this page, unless you find a way past a stated limit.

What to expect: agentbox is an early alpha with no releases. A fix to agentbox needs a reinstall.

There is no bug bounty. Replies are best effort, with no fixed response time. Please give the maintainers time to fix a problem before you publish it.

## See also

- [Encryption and Recovery](Encryption-and-Recovery.md): the modes, the recovery key, and Tang outages.
- [Generations and Updates](Generations-and-Updates.md): `os plan`, `os apply`, trial boots and fallback.
- [Release Pipeline](Release-Pipeline.md): how the box checks a release before it installs it.
- [Architecture](Architecture.md): the full design, with each part marked built or designed.
- [Testing and Gates](Testing-and-Gates.md): what each gate proves, and what it does not.
