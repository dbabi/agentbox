# agentbox threat model (one page)

Source of truth: [`docs/design/ARCHITECTURE.md`](design/ARCHITECTURE.md), §10. Update both together.

## What we protect
1. **The host:** the OS generations, the boot chain, and other users.
2. **Secrets:** LLM API keys, the GitHub token, Tailscale and ntfy credentials, the LUKS key.
3. **The owner's data and LAN:** files in `/srv` and workspaces, plus devices on the home network.
4. **Integrity of approvals, audit, and memory.**

## Who attacks, and through what
| Attacker | Entry point |
|---|---|
| Prompt injection (most likely) | Web pages, package READMEs, issues and PRs, logs, other agents' messages, memory |
| A compromised agent CLI or dependency | Code running inside a task container |
| Thief | The disk alone, or the whole powered-off machine |
| Someone on the LAN or tailnet | Exposed ports, the approval page |
| A bug in our own services | Parsers in agentboxd, proxy, keys, git, approvald and auditd; llama-server's tokenizer, chat template and grammar in agentbox-llm |

## Trust boundaries
- internet ↔ proxy
- container ↔ host kernel
- task ↔ its own sockets
- agentboxd ↔ rootd
- agent ↔ agent
- model ↔ policy
- memory ↔ prompts
- phone ↔ approvald
- disk ↔ thief
- OS generation ↔ persistent state

## Non-negotiables (tests must prove each)
1. Tasks have **no network** (`Network=none`). Egress goes only through the task's own Unix sockets.
2. **No credential exists inside a task.** Keys live in `agentbox-keys`, and the GitHub token lives in `agentbox-git`.
3. **Agents never mutate the running OS.** Changes are built offline into a new generation and committed only after a health check.
4. **rootd executes only the stored operation a human signed**, bound to its immutable inputs and re-checked at execution.
5. **Taint is sticky.** Only a human clears it, after reviewing the diff, with control files called out first.
6. **Nothing persists between tasks** except the sticky-tainted workspace, and each agent's read-only Go module cache. Only the proxy writes the cache, with public module files that the Go checksum database binds to their version, and a task can read it only once it is tainted.
7. **The seed and logs contain no plaintext secrets.** The seed holds the admin password hash (yescrypt, e.g. from `mkpasswd -m yescrypt`, or sha512-crypt with 100000+ rounds): keep it private. The LUKS key exists only in installer tmpfs and in `recovery.bin`, encrypted to the owner's offline RSA key.

## Accepted residuals (v1)
| Residual | Upgrade path |
|---|---|
| Shared-kernel exploits | v2: microVM tasks |
| Whole-machine theft in `tpm2` mode | Use `tpm2+tang`; v2: UKI with a signed PCR 11 policy |
| An attacker who stays on your LAN with physical access (`tpm2+tang`) | |
| Boot-chain package updates aren't A/B | |
| A signed but malicious package in an approved closure runs as root at the trial boot: it can read the LUKS key and rewrite `/bootpart` and the ESP (A/B fallback covers crashes, not hostile code) | v2: UKI + PCR 11 measured trial boot |
| CDN fronting, and write-capable hosts you allowlist | |
| Root tampering with on-box audit | Ship audit off-box |
| Misleading phone page for *reversible* ops | |
| Model labels can bias a reviewer (bounded: P's deterministic rendering always comes first, §5.5) | |
| An approvald compromised in memory during the 120 s passkey registration window can swap in its own credential; once the human confirms it, it can approve reversible ops until `passkey.revoke` | v2: attested-only mode for hardware keys |
| The `admin` uid is root-equivalent (subiquity adds it to `sudo`), and admin ops need only `SO_PEERCRED` membership: CLI signatures don't protect against a compromised admin account | v2: no `sudo` for admin; admin ops become signed pending P |
| A compromised agentboxd acts as any untainted agent for unsigned floor ops, and can skip READ-INTENT on bus and memory reads | v2: an `agentbox-gate` service (own uid) serves the per-task gate sockets; rootd issues per-task gate MAC keys and applies bus and memory READ-INTENT itself |
| A compromised proxy, keys or git can omit taint for content it delivers | v2: a second taint check at the task gate on response classes |
| A compromised auditd can forge ACKs and mask taint until off-box verification catches it | v2: rootd keeps its own append-only taint record and refuses on regression |
| A compromised agentboxd or broker can write audit records that pass for rootd's, such as an ALERT, or the INTENT and RESULT of an admin op: auditd ties only two ops, `taint.clear` and `workspace.restore`, to rootd | Issue #211: tie each op and record type to the producer that writes it |
| A rootd crash in the middle of an admin op, such as `task undo` or `egress allow`, a stop while one runs for more than 60 s, or auditd going down while one runs, can end it after its INTENT is ACKed: no RESULT says whether the effect ran, and the next start doesn't reconcile it | rootd records each admin op in `rootd.db` and reconciles it at the next start |
| While the disk is full (below the audit reserve), auditd refuses DENY and other best-effort records with `DISK_FULL`: denials in that window leave no audit record, only the critical disk-full alert | Ship audit off-box |
| The workspace credential scan runs before an agent's first task and at each egress grant. A credential written after it, encoded, only in git history or past a file's first 16 MiB is missed, and so is one that no vendored rule describes | |
| A credential in the workspace that works against a host allowed before the credential was written stays usable until the next grant or first-task scan finds it | |
| An egress grant that an admin acknowledges with `--ack-secrets <n>`, though its scan found a credential for the new host, takes effect at once: a running task can use that credential. The grant checks only that `<n>` equals the number of credentials its own scan finds, not which ones. So a credential swapped in after the refusal is granted too. A task's acknowledgement covers a file, line and rule, not the credential. A grant never names a private key | Issue #224 |
| The post-attach token scan finds a token as written, not encoded. It reads the first 256 MiB of a file and 1 GiB of what its git objects inflate to, and a packed git delta's inserted bytes without rebuilding it from its base: an agent that encodes the token, splices it from copies or puts it past those limits evades it | The review diff (§7) |
| A file that a workspace git config pulls in with `include.path` or `includeIf` is not a control path: once the include line is acknowledged, the included file can change with no new acknowledgement | Issue #193: treat include targets as control paths |
| In session-home, only the CLIs' instruction files and what the shells, editors, pagers, Python, ssh, git and go read at startup are control paths: another tool's per-user config, or a cache a tool trusts, can carry code from one attach to a later one | Give each session a fresh HOME that holds only the CLIs' own state from session-home |
| The attach output filter passes a charset switch (`ESC %`), after which some terminals obey control codes it doesn't see, such as a clipboard write. Of the terminal report requests, it drops only `CSI c`, `n` and `t`: a version query still gets an answer | Issue #210 |
| Root can always remove confinement: after a root-level flush, brokers are unconfined for up to 60 s, until the next `fwcheck` | |
| The host firewall accepts everything on `tailscale0`: once Tailscale runs, every listener on the box is open to every device on the tailnet | |
| With no `--ssh-from`, SSH is open on every interface to the private ranges, `100.64.0.0/10` and IPv6 link-local. ISPs also use `100.64.0.0/10` for carrier-grade NAT, so on such an uplink other customers can reach SSH | `--ssh-from` with your LAN only; issue #219 |
| One duplicate `gh.*` comment or PR, if a human re-approves an indeterminate op whose first POST landed late | |
| Until laptop signatures land, approving a remote write, a merge or a PR is an `agentbox-admin` call on `rootd-admin.sock`: anyone with the admin login approves, and nothing binds the approval to what the human read | Issue #24: SSHSIG approvals over H |
| The per-task canary is a detection aid: a task can send it out encoded in a way the scan doesn't cover, or through a proxy tunnel. In a model request it only alerts, and the request still reaches the vendor. Bus messages and memory writes aren't scanned for it yet. A credential pattern in a push only alerts | Issue #292: bus and memory refuse it (milestone 8) |
| In `none` mode, the host key that encrypts the brokers' credentials (the LLM API keys and the GitHub token) sits on the same unencrypted disk | Use a `tpm2` mode |
| Jev egress when enabled | |
| Approximate metering for subscription sessions | |
| Until `osbuild-fetch@` lands, `agentbox os plan` runs apt as root on the host; apt's update hooks are cleared, but `apt-get update` and download output, and a closure-mismatch error, reach the admin's terminal raw (the approval listing quotes every origin) | Weeks 11–12: `osbuild-fetch@` |
| The stock `10_linux` entries stay in `grub.cfg`: nothing selects them unattended, but one booted by hand runs the btrfs top level without `rootflags` and leaves `recordfail` set | |
| `ua-timer`, `motd-news`, `apport-autoreport` and `update-notifier-download` stay enabled and contact the network (they change no packages) | |
| Ubuntu's podman 5.7 lacks the fix for GHSA-pggw-qqjf-6cxw (podman 5.8.10), where a crafted image matches another image's digest with other layers and config. rootd checks every blob of the task image itself before `podman load` and pins it by its config digest. App images are not built yet, so nothing checks them | Ubuntu's podman with the fix; app images through the same check (#173) |
| The low-severity findings of the November 2026 code review that are still open: hardening, test and docs gaps, listed by area | Issues #209 to #224 |

## Test-model limits (what the gates can't show)
| Limit | Effect |
|---|---|
| QEMU 11.1's NVMe controller ignores FUA | In an NVMe power-cut log, FUA writes are never flush marks: the replay at the last flush can be the disk just before the final journal commit. Use `DISKBUS=virtio` for exact durability points. |
| blklogwrites once left a 15.7 MiB hole in a virtio install log (cause unknown) | `replay-log`, `powercut.sh check` and `boot` fail loudly at a hole |
| Power-cut replay needs a plain btrfs partition | Encrypted disks are not replayed: `powercut-fidelity` runs in `none`. QMP cuts (`os-apply-powercuts-tpm2`) run in `tpm2` only. `vm.sh cut` models only a disk with no volatile write cache. |
| The test VM's network (`hack/vmnet`) still reaches the Mac's LAN | It reaches the Mac's `127.0.0.1` only on the Tang and release-serve ports. `gate.sh` checks that a loopback listener with no forward sees nothing, even from frames that root in the VM writes by hand. |
| The arm64 VM has no hardware watchdog | arm64 tests softdog only; the i6300esb path runs on amd64. Watchdog detection on real x86 hardware is unit-tested only (the old-PC gate checks it). |
| The milestone 4 gates use stand-in brokers | Broker restart, outage and retry checks run against stubs that bind the same per-task sockets. No task reaches a model or the internet in a gate. |
| A skill's frontmatter hook needs a model reply to fire | The tasks gate checks only the setting that turns hooks off. |
| HVF guests stop while the Mac sleeps | Long gates need AC power and an open lid; `vm.sh` does not count sleep against the install timeout. |
