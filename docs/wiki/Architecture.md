# Architecture

> **Early alpha. Not for production use.** No AI agent can do useful work on agentbox yet: tasks can't reach a model. Milestones 1, 2 and 4 of 9 are built: the installer, the OS layer, the first host services (the firewall, the audit daemon and a skeleton of the root daemon), agent accounts, task containers and interactive sessions. Milestone 3, the operation registry and the request checks, is built; its 24-hour fuzz run is pending. The rest of the agent runtime on this page is designed, not built.

This page explains the target design of agentbox for newcomers.
The full design is in [`docs/design/`](../design/).

Two words mark the state of each part:

- **Built:** the code is on `main`, and its test gates have passed in QEMU VMs ([Testing and Gates](Testing-and-Gates.md) says where and when). No real hardware has run it yet.
- **Designed:** the design in `docs/design/` describes it, but there is no code yet.

Milestone numbers refer to the ordered list on the [Roadmap](Roadmap.md). The plan can change.
[Testing and Gates](Testing-and-Gates.md) says what each test gate proves.

## At a glance

| Part | Status | Milestone |
|---|---|---|
| Unattended install, disk encryption, recovery key | Built | 1 |
| btrfs A/B OS generations: `os plan`, `os apply`, health commit, unattended fallback | Built | 1 |
| Signed release pipeline and firstboot install | Built | 1 |
| Zero-touch install ISO, QEMU test harness, power-cut tests | Built | 1 |
| Firewall, disk quotas, audit daemon, rootd skeleton and resolver, ntfy | Built | 2 |
| Operation registry, the agentboxd request gate, denial codes, the socket layout as code | Built (24-hour fuzz run pending) | 3 |
| Agent accounts, task containers, interactive sessions | Built | 4 |
| Brokers: proxy and its Go module cache, keys, git | Built (24-hour fuzz run pending) | 5 |
| Cedar policy, rootd floor, signed approvals | Designed | 6 |
| Apps, file writes, workspace ops, OS ops for agents, nightly updates, decide | Designed | 7 |
| Agent bus and shared memory | Designed | 8 |
| Benchmark, external threat-model review, the first signed release | Designed | 9 |

## The big picture

agentbox aims to be a headless OS that is a home for AI coding agents.
It is built on stock Ubuntu Server 26.04.
In the design, an agent has full freedom inside a disposable task container.
The container has no network and holds no credentials.
Anything that touches the host, secrets, the network, other agents or shared memory goes through a typed operation.
Policy checks each operation, and an audit log records it.
Risky operations wait for a human to sign them.

```
 laptop: agentbox CLI, your SSH signing key       phone: passkey
                 |                                       |
                 | SSH                                   | ntfy link, tailnet HTTPS
                 v                                       v
+----------------------------------- the box -----------------------------------+
|  agentbox-rootd      root. The only executor: pending ops, tasks, generations |
|  agentboxd           task gate, Cedar policy, agent bus, memory, decide       |
|  agentbox-auditd     hash-chained audit log and taint ledger                  |
|  agentbox-approvald  phone approval page. Holds no keys                       |
|  brokers             proxy (no secrets), keys (LLM keys), git (GitHub token)  |
|                                                                               |
|  +--- task container, one per task ---+                                       |
|  |  agent CLI, no network             |--> its own Unix sockets:              |
|  |  fresh HOME, workspace mounted     |    gate, proxy, keys, git             |
|  +------------------------------------+                                       |
+-------------------------------------------------------------------------------+
|  OS layer (Built): Ubuntu Server 26.04, encrypted disk, btrfs A/B generations |
+-------------------------------------------------------------------------------+
```

The design has two layers:

1. **The OS layer (Built).** It installs Ubuntu, encrypts the disk and keeps the OS in btrfs A/B generations.
2. **The agent runtime (Mostly designed).** It runs each task in its own container. A few small services decide what the task may do outside that container.

In the diagram, everything above the OS layer is designed, with these exceptions:
`agentbox-auditd`, the host firewall, and a skeleton of `agentbox-rootd` (its name resolver, the brokers' firewall sets and audit-segment sealing), built in milestone 2;
the task gate in `agentboxd`, built in milestone 3;
the task container, with rootd's agent accounts, task start and stop, and attach sessions, built in milestone 4;
and the proxy, built in milestone 5.
None of the other services exists yet.

## Principles

These eight rules shape the whole design.

1. **Models propose, code decides.**
   No model output grants a permission.
   A model can only add friction, such as an extra approval.
   *Designed (milestones 6-7).*
2. **Agents never change the running OS.**
   OS changes are installed offline into a copy of the OS, called a generation.
   The box boots the new generation once, and keeps it only if a health check passes.
   *Built for the admin today. The path for agents is designed (milestone 7).*
3. **No network for agents or apps.**
   Task containers have no network at all.
   Traffic leaves only through the task's own Unix sockets, to the brokers.
   Brokers may connect only to addresses that rootd resolved for allowlisted names.
   *Built in part: the firewall and rootd's resolver (milestone 2), task containers with no network (milestone 4), and the proxy, the keys broker and the git service (milestone 5).*
4. **The executor owns the floor.**
   `agentbox-rootd` stores every pending operation, bound to its exact inputs, such as commit IDs and package hashes.
   When an operation needs approval, rootd runs only the stored copy that a human signed.
   It checks the state again before it runs.
   *Designed (milestone 6).*
5. **No credentialed writes outside the registry.**
   Tasks hold no credentials.
   Every write that needs one, such as a git push or a pull request, is a registry operation that a broker carries out.
   *Designed (milestones 3-6).*
6. **Tasks are disposable.**
   Each task gets its own container, home directory and sockets.
   Nothing the task writes outside its workspace survives the task.
   *Built (milestone 4).*
7. **Taint is sticky.**
   Content from an untrusted source marks, or taints, the task that reads it.
   The mark spreads to what the task touches.
   Only a human can clear it.
   *Built in part: auditd's taint ledger, where only rootd's admin path clears a subject (milestone 2), taint that spreads from a task to its workspace and the next task (milestone 4), and the taint the proxy and the keys broker set (milestone 5). The rest of what sets taint is designed (milestones 5-8).*
8. **Honest guarantees.**
   The design states what each operation's rollback covers.
   It states the limits of disk encryption and of phone approvals.
   *Built in part: `agentbox seed` prints a warning for the weaker `tpm2` and `none` modes.*

## The OS layer

**Status:** Built, except where a line says Designed.

At the time of writing, it has run in QEMU VMs on arm64 UEFI with Secure Boot on, and on amd64 legacy BIOS.
`os apply` has passed its gates on arm64 UEFI.
On amd64 BIOS it has one passing run so far.
Power cuts during `os apply` were tested in `tpm2` mode only.
amd64 UEFI and real hardware have not run yet.

### Install

- `agentbox seed` validates every input, then writes an autoinstall seed.
  The stock Ubuntu Server installer reads it and installs unattended once `autoinstall` is on its kernel command line.
- The install picks the target disk by its exact udev `ID_SERIAL`.
  It stops before any disk write unless exactly one disk matches.
- It also stops before any disk write when the Ubuntu archive does not answer (not yet tested in a VM), or when an encrypted mode finds no TPM 2.0 (not yet tested in a VM).
- Disk encryption has three modes: `tpm2+tang` (the default), `tpm2` and `none`.
  The encrypted modes use LUKS2, unlocked by clevis in the initramfs.
- The LUKS key is 48 random digits.
  The installer encrypts it to your offline RSA-4096 recovery key and writes the result to `/bootpart/agentbox/recovery.bin`.
- `hack/remaster-iso.sh` copies the pinned stock ISO and adds `autoinstall` to the installer's kernel command line.
  With that zero-touch ISO, the install needs no keyboard input.
  With the plain stock ISO, you add `autoinstall` at its GRUB menu.

More: [Encryption and Recovery](Encryption-and-Recovery.md) and [Installing on Real Hardware](Installing-on-Real-Hardware.md).

### Storage

| Partition | UEFI | BIOS |
|---|---|---|
| 1 | 1 GiB ESP at `/boot/efi` | 1 MiB `bios_grub` |
| 2 | 4 GiB ext4 at `/bootpart`, not encrypted | same |
| 3 | btrfs on the rest of the disk, inside LUKS2 in the encrypted modes | same |

- The btrfs subvolume `@gen-N` is the OS root (`/`, `/etc`, `/usr`) of generation N.
- These subvolumes stay the same across generations: `@home`, `@var_log`, `@var_lib_agentbox`, `@var_lib_agentbox_data`, `@var_lib_tailscale`, `@var_lib_ntfy`, `@srv` and `@snapshots`.
  Persistent data is outside the generations, so it survives a fallback.
- Each generation keeps its kernels and initrds in `/bootpart/agentbox/gens/gen-N/`, bind-mounted at `/boot`.
- *Built (milestone 2):* btrfs quotas. One parent quota group, `2/0`, caps every store that agents and apps can fill. Its limit leaves max(10%, 4 GiB) of the file system free, and it moves with the space the OS, agentbox's control state and the generations use. Those stay outside `2/0`, so they always keep the reserve. The content store (`cas`) has its own cap. Per-agent quota groups come with agent accounts (milestone 4).

### Generations

- `agentbox os plan` resolves a package change against a copy of the running generation's package state.
  It downloads every `.deb` and checks it against apt's signed index.
  It installs nothing, and it prints the plan's SHA-256.
- `agentbox os apply --approve <plan-sha256>` builds a new generation from exactly that plan:
  1. It snapshots the committed generation into a new subvolume, `@gen-M`.
  2. It installs the approved `.deb` files offline, in `systemd-nspawn` with a private user range and no network.
  3. It checks that every new initrd has the drivers and tools to unlock and mount the root.
  4. It sets GRUB to boot the new generation once, then reboots.
- After the reboot, `agentbox-health.timer` runs `agentbox os health` every 50 seconds.
  A healthy trial is committed.
  Anything else falls back to the last committed generation, with no console input.
- Fallback has several paths:
  - GRUB's fallback entry, for a trial that fails inside GRUB;
  - a one-shot boot entry, so the boot after a failed trial is the committed generation;
  - reboots from kernel panics and emergency shells;
  - a commit deadline, 900 s by default;
  - a 60 s watchdog.
- The health check is basic today. It checks five things:
  - systemd reports `running`;
  - `/boot` is the trial's own boot dir;
  - the booted kernel's modules exist;
  - `/` has at least 2 GiB free;
  - there is an IPv4 default route.
- Before those checks, `agentbox-health.service` runs `fwcheck --repair` (milestone 2). Health checks for agentbox services, DNS and Tailscale are designed.
- The box keeps the three newest generations at or below the committed one, plus any generation that is booted, committed or pending.
- Only one `os apply` runs at a time.
  Until `rootd.db` exists, the `os` commands keep their lock and trial records in `/var/lib/agentbox/os/`.
  Plans and their `.deb` files go in `/var/lib/agentbox/cas/debs/`.

On the box, as root. The binary is not on PATH:

```sh
sudo /var/lib/agentbox/current/bin/agentbox os plan --install <package>
sudo /var/lib/agentbox/current/bin/agentbox os apply --approve <plan-sha256>   # reboots, unless you add --no-reboot
sudo /var/lib/agentbox/current/bin/agentbox os status
```

Use `os plan` and `os apply` instead of `apt`.
Changes made to the running generation after a build's snapshot are lost when the new generation commits.
Installing, upgrading or removing a package with `apt` between `os plan` and `os apply` makes the apply refuse with `stale_base`.

More: [Generations and Updates](Generations-and-Updates.md).

### Release and firstboot

- `make release` builds one tarball with `agentbox` for linux/amd64 and linux/arm64, plus a minisign signature.
  Two builds of the same commit with the same Go version give the same tarball.
  At the time of writing, this was checked on one machine only.
- The seed pins the release URL, the tarball's SHA-256 and the minisign public key.
- At first boot, `agentbox-firstboot.service` downloads the release.
  It checks the pinned SHA-256 first, then the signature.
  It installs nothing unless both checks pass.
- It installs the release into `/var/lib/agentbox/releases/<ver>/` and points the `current` link at it.
- There is no supported way to update the agentbox release on an installed box.
  A new release means a reinstall.
  A release-update operation is out of scope for v1.

More: [Release Pipeline](Release-Pipeline.md).

### Units on the box today

| Unit | Comes from | Job |
|---|---|---|
| `agentbox-firstboot.service` | the seed | Installs the signed release once. Retries every 60 s until it succeeds. |
| `agentbox-boot-deadline.service` | the seed | Reboots an uncommitted generation after 900 s. |
| `agentbox-reconcile.service` | the release | Re-applies agentbox's control state to the booted generation: the quota groups, the git service's ownership of its repos, the agent accounts, ntfy's config, ACLs and unit drop-in, and a systemd-networkd drop-in for every network config that records the NAT64 prefixes routers announce. |
| `agentbox-accounts.service` | the release | Writes the agent accounts from rootd's `ids` table into `/etc`: users, groups, sub-id lines and the systemd drop-ins. |
| `agentbox-firewall.service` | the release | Loads the `inet agentbox` nftables table before the network comes up. Every other agentbox unit `Requires=` it. It needs nothing from reconcile, so a failed reconcile keeps the agents down but not the firewall. |
| `agentbox-health.service`, `agentbox-health.timer` | the release | Every 50 s: `agentbox fwcheck --repair`, then `agentbox os health`. |
| `agentbox-auditd.service` and its sockets | the release | The audit daemon. Socket-activated: one socket per producer (agentboxd, rootd, proxy, keys, git). |
| `agentbox-rootd.service` and its sockets | the release | The root daemon: agent accounts, task start and stop, attach sessions, the resolver sockets for the three brokers, the admin socket, and the seal socket auditd calls. It starts after auditd and stops before it. At a stop it finishes the requests in flight, for up to 60 s, so their audit records still reach auditd. |
| `agentboxd.service` and its socket | the release | The task gate: one socket per task, with no network. |
| `agentbox-proxy.service` and its socket | the release | The egress proxy, as `agentbox-proxy`: one socket per task. Its socket starts it at the first task. |
| `agentbox-keys.service` and its socket | the release | The LLM keys broker, as `agentbox-keys`: one socket per task. It starts at boot, and `agentbox secret set` restarts it. |
| `agentbox-git.service` and its socket | the release | The git service, as `agentbox-git`: the agents' local repos, one socket per task, and the GitHub writes an admin approved. Its socket starts it at the first task or `remote set`, and `agentbox secret set --name github-token` restarts it. |
| `ntfy.service` | the Ubuntu `ntfy` package | Notifications, as `_ntfy`, on a Unix socket only. `install.sh` installs the package; reconcile configures and enables it. It starts after rootd, once rootd has filled the firewall sets that ntfy's `fwcheck` compares. A `systemctl restart` of rootd, or a firewall repair, restarts it too. It has no systemd start limit, so many rootd restarts in a row can't leave it failed. |
| `agentbox-agent-stub.service` | the release | A stand-in for an agent unit, for the gates. Not enabled. |

### Designed parts of the OS layer

- **OS operations for agents** (milestone 7). Agents may request `os.pkg.install`, `os.pkg.remove` and similar operations. Each one needs a signature on the laptop.
- **A protected-package floor** (milestone 7). `os.pkg` operations can't touch protected packages, even when signed. These include the kernel, systemd, GRUB, shim, cryptsetup, clevis, nftables, podman, openssh-server and sudo.
- **Nightly `os.update`** (milestone 7). It runs unsigned only if the whole change stays inside a signed update policy. Today no update runs on its own: the seed masks apt's daily timers.
- **An `os.rollback` operation** (milestone 7). Today fallback is automatic, but no command boots or pins an older generation.

## The services

**Status:** Mostly designed. `agentbox-auditd` and the packaged ntfy are built, and so are parts of `agentbox-rootd` and `agentboxd` (milestones 2-4). The table says which parts. So are `agentbox-proxy`, `agentbox-keys` and `agentbox-git` (milestone 5). Approvald, the local-model units and tailscaled don't exist yet. [Units on the box today](#units-on-the-box-today) lists what runs today.

In the design, rootd, agentboxd, auditd, approvald and the three brokers are all subcommands of the one `agentbox` binary.
The local-model units run llama-server, and ntfy and tailscaled come from their own packages.
Each service runs as its own Linux user, with only the access it needs.

| Service | Runs as | Job | Status |
|---|---|---|---|
| `agentbox-rootd` | root | The only executor. Stores pending operations, starts tasks, creates accounts, builds OS generations and fills the firewall's address sets. | Built in part: the resolver, the brokers' firewall sets, `egress` allowlist edits and audit sealing (milestone 2); agent accounts, task start and stop, and attach sessions (milestone 4); the brokers' encrypted credentials, the agents' daily LLM shares and the pending operations for the git service's writes (milestone 5). Its generation code is built. The floor, policy and OS operations for agents are designed (milestones 6-7). |
| `agentboxd` | `agentbox` | The front door for agents: the task gate, Cedar policy, the agent bus, memory and decide. Has no network. | Task gate built (milestone 3): one socket per task, argument and caller checks, typed denials. Policy, the agent bus, memory and decide are designed (milestones 6-8). |
| `agentbox-auditd` | `agentbox-audit` | Writes the hash-chained audit log and the taint ledger. Has no network. | Built (milestones 2 and 3), including the per-field audit classes. |
| `agentbox-proxy` | `agentbox-proxy` | Tunnels task traffic to allowlisted hosts, and keeps each agent's read-only Go module cache. Holds no secrets. | Built (milestone 5) |
| `agentbox-keys` | `agentbox-keys` | Holds the LLM API keys and budgets. Checks every model request, then adds the key. | Built (milestone 5). The local model behind it is not packaged yet. |
| `agentbox-git` | `agentbox-git` | Hosts local git repos. Holds the GitHub token and runs the remote writes a human approved. | Built (milestone 5): local repos, the push hook, the remotes registry, `repo.push`, `gh.*` writes and `repo.merge`, taint and the canary. Approvals are made on the box until milestone 6. [Git and GitHub](Git-and-GitHub.md) |
| `agentbox-approvald` | `agentbox-approve` | Serves the phone approval page. Holds no keys. | Designed (milestone 6) |
| `agentbox-llm@task`, `agentbox-llm@decide` | `agentbox-llm`, `agentbox-llm-decide` | Local models (llama-server) for tasks and for decide. Have no network. | Designed (milestones 5 and 7) |
| ntfy, tailscaled | `_ntfy`, root | Phone notifications. Tailnet access to the approval page. | ntfy: built (milestone 2). tailscaled: designed. |

- rootd is the only agentbox service that runs as root.
  For OS builds, it starts short-lived helper units: `osbuild-fetch@` downloads packages, `osbuild-apply@` installs them in nspawn, and `osbuild-image@` builds the task image.
- Today the `agentbox os` commands do rootd's generation work directly, as root.
  They run apt and `systemd-nspawn` themselves.
  Their code lives in `internal/rootd/gens`.
- agentboxd parses untrusted input from agents, so it runs unprivileged and with no network.
  An attacker who takes it over can drive tasks that are not tainted.
  They still can't run any operation that needs a signature.
- Services talk to each other over Unix sockets, each with an explicit owner, group and mode.
  Every Unix-socket server checks the caller's uid with `SO_PEERCRED`.
  Between services, the only TCP listeners are loopback ports for the phone page, ntfy and apps.
  The firewall lets only listed (uid, port) pairs reach them.
  No server accepts file descriptors from a client.
- Humans reach rootd's admin socket over SSH.
  Members of the `agentbox-admin` group may run admin operations.
  The admin account is root-equivalent anyway: the installer adds it to `sudo`.

## Task containers

**Status:** Built (milestone 4), except where a bullet says otherwise. The proxy behind the egress forwarder, the keys broker behind the LLM forwarder and the git service behind the git forwarder are built (milestone 5).

### Accounts

- `agentbox agent add --name <name>` makes a Linux user `ag-<name>` with uid `70000+N`.
  In the design, each app is a user `app-<name>` with uid `71000+M` (milestone 7).
- rootd allocates N from its `ids` table and never reuses it, so a removed agent's uid and sub-id range never come back.
- Each agent gets its own 65536-wide sub-uid range, its own disk quota (a btrfs qgroup) and its own CPU, memory and IO limits.
- Its workspace, its podman storage and its session-home are subvolumes inside that quota.
- If btrfs marks the quota counts inconsistent, for example after a snapshot delete or a generation prune, rootd freezes every running agent and refuses new tasks, attaches and task writes with `BUSY`.
  It rescans the quotas, and thaws the agents only once the counts are consistent again. `agentbox quota check` runs this check at once.
- `agentbox agent remove` deletes the account and moves its data to an archive. It refuses while the workspace holds a nested subvolume.

### One container per task

- rootd starts one rootless podman container per task.
  The container is removed when the task ends.
- The container has no network, a read-only root filesystem, no capabilities and `no-new-privileges`.
- Its home directory is a fresh tmpfs.
  The workspace is the only writable mount that outlives the task.
- A seccomp profile blocks btrfs ioctls.
  So a task can't create a subvolume that escapes its quota or the workspace snapshots.
- The same profile allows only Unix, IPv4, IPv6 and routing netlink sockets, and blocks new namespaces.
  It starts from a pinned copy of podman's upstream default profile, not the one the distro ships.
- An admin starts a task with `agentbox task new --agent <name>`, with the prompt on stdin.
  The task records the admin's user name, so an admin with no entry in `/etc/passwd` can't start or undo a task.
- A top-level task has a 2-hour deadline by default.
  The design caps its output at 50 MB; today the result keeps the last 16 KiB.
  A child task never outlives its parent's deadline.

### Inside the container

- `agentbox taskrun` runs as PID 1.
  It copies generated CLI configs into the home directory, starts local forwarders, and runs the agent CLI with the prompt on stdin.
- Before the CLI starts, taskrun checks its own boundary from inside.
  The task must see no network device but `lo`, no default route, `ENETUNREACH` for a public IP, only `127.0.0.1` in `resolv.conf`, no other task's sockets and no abstract socket.
  A tunnel device that the kernel adds, switched off, to every network namespace doesn't count until it is switched on.
  Any failure stops the task with `TASK_ISOLATION_PROBE`, an audit record and an ntfy alert.
- Tasks run two agent CLIs: Claude Code and Codex.
  Their configs, flags and system policy files are built.
  The policy files sit in the image's read-only `/etc`, so a CLI started by hand in a task obeys them too.
  They turn off workspace hooks, MCP servers, plugins, web search, updates and telemetry.
  The CLIs are not in the task image yet; the gates install them on the host.
- opencode is not supported.
  Its current release has no setting that stops a plugin named in a workspace `opencode.json` from running.
- The forwarders listen on `127.0.0.1:8080` for egress, `:8081` for LLM APIs and `:8082` for git.
- The forwarders lead to the task's own Unix sockets for the proxy, keys and git.
  A fourth socket reaches the gate in agentboxd.
  rootd creates these sockets for this task only, and revokes them when the task ends.
- If a broker restarts, the forwarders retry for up to 5 s, then answer `503 BROKER_UNAVAILABLE`.
- The task has no DNS: its `resolv.conf` names only `127.0.0.1`, so a direct lookup fails in under 1 s.
- Go's settings follow the agent's allowlist. npm and pip skip their update checks, and npm skips its audit.
- `agentbox why`, run inside the task, explains a recent denial and what would unblock it.

### Nothing carries over to the next task

- Hooks, settings and MCP configs that a task writes outside the workspace vanish with its container.
- The agent CLI runs with project hooks and project MCP config turned off.
  Git hooks are off too.
- Instruction files in the repo, such as `CLAUDE.md` and `AGENTS.md`, can still steer a later task.
  Taint covers that case: any task that mounts a tainted workspace is tainted too.
- Tasks share no package caches but one: each agent's read-only [Go module cache](#the-go-module-cache), which only the proxy writes.
  Tools are baked into the task image.
  Today the default image is a small root file system with the host's `/usr` mounted read-only.
  The pinned image with Go, `image/task`, is built only in a test so far. The box builds it from milestone 7.

### Stopping a task

- `agentbox task stop` kills the task's whole cgroup, removes the container and revokes the task's sockets.
  The task's processes are gone within 20 s, and its container and sockets within 5 s.
- It also stops every child task.
- It never waits for the audit service, because it only removes capability.
- If processes survive the stop, or rootd can't read whether any did, rootd blocks new tasks for that agent and sends an alert.
  The block survives a rootd restart. `agentbox attach rescan --agent <name>` lifts it once the processes are gone.

### Undoing a task

- Before each task's container starts, rootd takes a read-only btrfs snapshot of the workspace.
  The snapshot counts against the agent's disk quota and carries the workspace's taint, including taint another task adds while the snapshot runs.
  If the workspace holds a nested subvolume, the task does not start (`NESTED_SUBVOLUME`).
  A snapshot whose audit records fail is deleted, so undo never restores it.
- rootd keeps the last 5 of these per agent and deletes older ones.
  It never deletes other snapshots, such as the one an undo takes.
- `agentbox task undo --task <id>` puts the workspace back as it was when that task started.
  It refuses while a task or a session of that agent runs.
  While it runs, no task or session of that agent starts, even after `agentbox attach rescan`.
  It first snapshots the current tree, so the undo can be undone by hand.
- The restored workspace is tainted if the snapshot was, even if the workspace was clean before the undo.

### Credentials in the workspace

- The proxy does not strip credentials that a task sends itself.
  So a token left in a workspace file works against any host the egress list allows.
- rootd scans the workspace for live credentials before an agent's first task and at each `agentbox egress allow`.
  The rules are a pinned subset of gitleaks' rules: GitHub, GitLab, AWS, Anthropic, OpenAI, npm, PyPI, Slack, Stripe, Hugging Face, DigitalOcean, Google API keys and private keys.
- The scan runs in a transient unit with no network but loopback, a throwaway uid that can read but not write the workspace, and nothing else in its file system.
- A hit blocks the agent's tasks. The refusal names each file, line and credential type, never the credential.
  Remove the file, or start the task with `agentbox task new --ack-secrets <n>`, where `<n>` is the number of hits the refusal reported.
- The scan stops at 1000 hits. Files after that are not read, so the list is not complete and `--ack-secrets` can't acknowledge it.
  Tasks stay blocked until the workspace holds fewer.
- `agentbox egress allow` is refused while a workspace holds a credential that works against the host. The refusal names each one.
  A grant reaches running tasks at once, so a running task could use that credential.
  Remove the credentials, or grant with `--ack-secrets <n>`, where `<n>` is the number the refusal reported.
  After such a grant, each credential blocks the agent's next task until it is removed or acknowledged again.
- A scan that fails refuses the grant, and leaves the agent's next task to scan again, so the failure blocks that task too.
- The scan is a detection aid. See the residuals in the [threat model](../../docs/THREAT-MODEL.md).

### Interactive sessions

- `agentbox attach --agent <name>` opens an interactive Claude Code, Codex or bash session.
  It runs in the agent's rootless podman with a task's hardening, but with loopback only instead of the brokers.
- The session uses a persistent `session-home`, which may hold subscription logins.
  `session-home` is never mounted into automated tasks.
- Hooks, MCP servers and git hooks don't run in a session, and a bash session reads no shell startup file.
  Claude's Bash tool still reads `~/.bashrc`, so the startup files are control files (below).
  The session can't change its own Claude settings.
- An attach is refused while control files changed since the last accepted state.
  The refusal lists them and prints a digest of that list. Review them, then attach again with `--ack-control-changes=<digest>`.
  If a control file changed after the refusal, the old digest no longer matches, and the attach is refused again with the new list.
- The control files are the workspace's, and these files in `session-home`:
  - the CLIs' instruction files: `~/.claude/CLAUDE.md`, rules, skills, agents and commands, Codex's skills and plugins in `~/.agents`, `~/.npmrc` and `~/.local/bin`;
  - what the shells and tools in a session read at startup: bash's startup files, `~/.inputrc`, vim's, nano's, less's, tmux's and screen's config, the Python user site, `~/bin`, `~/.ssh`, `~/.config/git/attributes` and `~/.config/go/env`.
- The workspace's control files include `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md` and `AGENTS.override.md` at any depth, every git dir, bare repos and the dir a `commondir` file names among them, and every Python venv, the workspace root included.
- What a control file leads to is a control file too: the target of a symlink at or under one, each symlink on the way, and each file a `CLAUDE.md` imports with `@path`.
  A git dir in `session-home` refuses the attach, whether a `.git` file, a `.git` symlink or a relative path leads there, since a session could change it unseen.
  So does a `.git` or `commondir` file over 1 MiB, or one whose path git and other tools could read differently, such as one with a space at either end.
  So does a control file's symlink or import that leads through `/proc` or `/dev`.
  Tasks and sessions run git with `safe.bareRepository=explicit`, so git finds no bare repo by itself.
- An attach and a task of the same agent never run at once.
- rootd relays the session output through a filter.
  The filter drops terminal escape sequences that could write to your clipboard or inject input.
- When the session ends, rootd scans the workspace for every login token the session held.
  rootd watches the login files during the session, so a token the CLI rotated away counts too, and the scan reads git objects and packfiles.
  Tasks stay blocked until the scan is clean, and a hit sends an alert.
  A login file the scan can't read, such as a symlink, refuses the attach.
  A session that leaves one so keeps tasks blocked until it is a regular file again and `agentbox attach rescan` runs.
- `agentbox attach rescan --agent <name>` scans again and lifts a clean block.
  After a rootd restart, the token versions rootd saw are gone, so it lifts the block only with `--ack-restart`, once you have checked the workspace by hand.
  Each rescan that changes a block is audited: it records the ack and the number of hits, never a file name.
  If the audit service is down, the block stays.
- A session has no network yet, so a real login can't reach its servers (issue #90).

### Apps

*Designed (milestone 7).*

- Agents can deploy small apps.
  Each app runs as a rootless pod with no network.
- Requests reach an app through a socket bridge on loopback.
- An app can be exposed on the tailnet only.
  Exposure to the LAN is out of scope for v1.
- App images build offline, from a content-addressed snapshot of the build context.

## Control plane and approvals

**Status:** The operation registry, the argument and caller checks and the denial codes are built (milestone 3). Policy, pending operations and approvals are designed (milestones 6 and 7). Today the only approval is for OS changes, by plan hash. See [Today's stand-in](#todays-stand-in).

### The operation registry

- Every action an agent can ask for is a typed operation in one registry.
  Examples: `file.write`, `repo.push`, `gh.pr.create`, `memory.write`, `os.pkg.install`.
- The registry declares each operation's schema, policy action, floor rule, bound inputs, rollback coverage and audit rules.
- The policy schema, the JSON schemas, the MCP tools and the docs are generated from it.
  agentboxd and rootd refuse to start if the Cedar schema, JSON schemas or MCP tools don't match the registry.
- Built today: the registry in `internal/ops`, the generated files in `gen/`, and rootd's startup check.
  A refusal is a typed denial with a stable code from one table. It never echoes the refused value.
- There is no generic shell, no host file read, no `/etc` write and no LAN exposure.

### Operation classes

| Class | Examples | Rule (the floor) |
|---|---|---|
| Read | `system.info`, `disk.usage`, `app.logs`, `memory.read` | Runs. Reads of untrusted content taint the reader first. |
| Safe | `app.restart` on the agent's own app, `workspace.snapshot`, `repo.create` | Runs, even for a tainted task. |
| Coordination | `bus.task.send`, `bus.message.send` | Checked for the caller only. Taint carries forward. |
| Live | `file.write`, `repo.push`, `repo.merge`, `gh.pr.create`, `net.allow_domain` | Needs a signature if the task is tainted. Many need one anyway: `repo.merge`, `net.allow_domain` and `gh.*` writes always need a laptop signature. |
| OS | `os.pkg.install`, `os.unit.disable`, `os.rollback`, `os.update` | Needs a laptop signature. No agent can request `os.update`, and it runs unsigned only inside the signed update policy. |
| Admin | `agent.add`, `policy.set`, `secret.set`, `taint.clear` | Humans only, through rootd's admin socket. `taint.clear` and `memory.review` also need a signature. |

### The request flow

1. A task calls an operation on its gate socket.
   agentboxd checks the arguments against the operation's schema.
   It takes the task and agent from the socket, never from the request.
   This step is built (milestone 3). The steps after it are designed, except auditd's part in step 6.
2. agentboxd evaluates policy for every agent in the task's delegation chain.
   The answer is Run, Ask or Deny.
3. rootd binds the operation to its exact inputs: commit IDs, content hashes, or package lists with `.deb` hashes.
   It applies the floor and checks the task's taint.
4. On Run, rootd executes.
   On Ask, rootd stores the operation as a pending op P, with a hash H over P and its bound inputs.
   A human reviews P and signs H.
   On Deny, nothing runs.
5. Before it executes, rootd checks again: the bound inputs still match, the task is still live, and its taint has not changed.
   It runs the stored P, never a resubmitted copy.
6. auditd records an INTENT before the effect and a RESULT after it.
   The effect waits until auditd confirms that the INTENT is on disk.

### Policy and the floor

- The floor is rootd's fixed set of rules.
  Policy can make an outcome stricter, never looser.
- Policy is written in Cedar.
  The strictest answer across the delegation chain wins: Deny, then Ask, then Run.
- A Cedar evaluation error counts as Deny.
- If the task is tainted, every operation except reads, Safe ops and coordination ops needs a human signature.

### Approvals

**On your laptop (any operation).**

- The approval key stays on your laptop.
  It is never on the box, and SSH agent forwarding stays off.
- The laptop CLI fetches P from rootd over SSH.
  It recomputes H and refuses if H differs.
- It prints P from a fixed template, with the bound fields first.
  Text that an agent wrote is quoted and escaped, so control characters and bidi tricks can't hide anything.
- It signs H with an SSH signature (SSHSIG) in the namespace `agentbox-approve-v1`.
  A hardware-backed `sk-ssh-ed25519@openssh.com` key is recommended, so each approval needs a touch.
- For `net.allow_domain`, `repo.merge` and OS operations, you type the critical value before the key signs.
  That is the host and port, or the first 8 hex digits of the commit ID or the package-set hash.
- The first approver is the admin SSH key from the seed.
  You can add a hardware key, then remove the first one.

**On your phone (four reversible operations only).**

- Phone approvals cover only four operations whose data changes can be reverted.
  A revert does not undo what happened before it, such as an app serving a file that a phone approval wrote.
  They are `memory.write`, `memory.forget`, `file.write`, and `workspace.restore` of an untainted snapshot.
- ntfy sends a link with fixed text: the operation name, the agent and the op ID.
- The link opens approvald's page on your tailnet, through `tailscale serve`.
  It is never exposed with `tailscale funnel`.
- Your passkey signs H.
  rootd checks the exact web origin, and it rejects a phone approval for any other operation.
- approvald holds no keys, and it can make exactly three calls to rootd.
- A new passkey can approve nothing until you confirm it with a laptop signature.

**Limits.**

- An ask expires 15 minutes after it is created.
- An approval is single use, and it must start running within 15 minutes.
- rootd allows at most 3 open asks per task, and 20 per agent in any 24 hours.
- The benchmark target is at most 5 asks per 100 tasks.
  Nothing has measured this yet, because the runtime is not built.

### decide

*Designed (milestone 7).*

- decide is a typed helper on a local model.
  It returns a choice, a score or a yes or no.
- It helps with risk escalation, event triage, injection screening and labels.
- It can only add friction: an ask, a warning or a quarantine.
  It never removes one.
- Its labels never enter P or H.
  Reviewers see them last, under a heading that marks them as untrusted.

### Today's stand-in

Today the only approval is for OS changes, and it has no signature.
`agentbox os plan` prints the plan's SHA-256.
`agentbox os apply --approve <plan-sha256>` builds exactly that plan.
It refuses with `stale_base` if the packages changed since the plan.
Root access is the approval.

## Network and secrets

**Status:** The firewall and rootd's resolver are built (milestone 2), and so are the proxy, the keys broker and the git service (milestone 5). The seed still masks the stock `nftables.service`: `agentbox-firewall.service` loads agentbox's own table instead.

### Firewall

- `agentbox-firewall.service` loads agentbox's nftables table in one transaction.
- It drops all traffic from agent and app uids, including their sub-uid ranges.
  Containers have no network anyway, so this is a second wall.
- Each broker may connect only to the addresses in its own set.
  Only rootd adds addresses to those sets.
- Loopback service ports 43000-45999 accept only listed pairs of uid and port.
- A check runs every 60 s.
  If the table changed, the check reloads it and restarts rootd, the brokers and each agent's systemd user manager.
  Running tasks are killed, and an alert goes out.
- If the check fails, no agent or app can start.
- Drops are silent: the table has no log statement.

Built today (milestone 2): `agentbox fw load` adds the table as one add-only transaction, so a reload keeps every element rootd added.
`fwcheck` runs from the health timer every 50 s, and from each agent-side unit's `ExecStartPre=`.
On a mismatch it prints `agentbox: ALERT: firewall altered`, sends an ntfy alert, and restarts the firewall unit, which restarts every unit that `Requires=` it.
A failed firewall unit counts as a mismatch too. After the restart, `fwcheck` starts rootd, auditd, agentboxd and ntfy, so the ones a failed load stopped come back.
An agent's user manager comes back with its next task or attach.
An input chain drops inbound traffic by default.
It accepts loopback, replies to the box's own connections, the `tailscale0` interface, Tailscale's direct UDP port 41641, IPv6 neighbor discovery and DHCP replies.
It accepts SSH only from the prefixes in `/etc/agentbox/ssh-from`, which the seed's `--ssh-from` writes.
Without that file, the defaults are the private LAN ranges, `100.64.0.0/10` (Tailscale) and link-local.
`fwcheck` covers the input chain and the SSH prefixes like the rest of the table.
An enabled `ufw` can only drop more: a packet must pass every input hook.
Rootful Docker is unsupported: it publishes ports through the forward hook, which this table does not filter.

### DNS and pinned dialing

- Brokers never use DNS.
  They ask rootd to resolve a name.
- rootd resolves allowlisted names through systemd-resolved, over a Unix socket.
- It rejects a name if any answer is in a private or special-purpose range, is one of the box's own addresses, or is not routed through the default gateway.
- It also rejects an answer in the box's own network, which some routers announce as off-link, so the default gateway routes it.
  An IPv6 network counts as at least its /64.
- For an IPv6 answer that wraps an IPv4 address (NAT64 or 6to4), the same checks also run on that IPv4 address.
- It also rejects a name that a resolve hook answered instead of DNS.
  Since systemd 259, any privileged local service can answer lookups that way.
- rootd adds the answers to the broker's address set, with a timeout, and returns them.
- The broker dials only those addresses.
  TLS still checks the original hostname.

Built today (milestone 2): the resolver, through systemd-resolved's Varlink socket, with every refusal rule above, NAT64 prefixes included.
rootd keeps its answers in `rootd.db`, refills the sets at start (before `READY=1`) and on a timer, and `agentbox egress list|refill|allow|remove` edits the allowlists.
Built in milestone 5: the refusals of the box's own addresses and of hook answers, and the dialer the brokers share (`internal/dial`).
It asks rootd, dials only rootd's addresses, in order, within one 10 s budget, and follows no redirect.
The proxy, the keys broker and the git service use it. For a push, the git service hands rootd's addresses to git with `http.curloptResolve`, so git looks nothing up either.

### The proxy

- Allowlists hold exact `host:port` entries, with no unapproved wildcards.
- For each connection, the proxy checks the allowlist, gets addresses from rootd and connects.
  It records the connection with auditd before any byte flows.
- It follows no redirects, and it does not intercept TLS.
- All traffic through the proxy taints the task.
  That includes npm, PyPI, crates.io and GitHub's web pages.
- LLM API traffic never goes through the proxy.
  It goes through the keys broker, and it does not taint.
- The proxy holds no secrets.

Built today (milestone 5): the proxy and its Go module cache.
Each task's socket takes one request per connection.
A CONNECT to an IP address, an unlisted name or an LLM vendor host is refused before rootd is asked.
rootd re-checks the agent's list and resolves the name.
A private, special-purpose or LAN answer refuses the whole name.
The proxy dials only rootd's addresses, within one 10 s budget, and auditd acknowledges the task's taint before the tunnel opens.
A plain HTTP request is refused.
Each task's proxy socket serves 64 connections at once.
Other task sockets serve 8, but npm keeps up to 15 open to one registry.

### The Go module cache

- The proxy keeps one store of Go module files for each agent whose allowlist has `proxy.golang.org:443`.
  It is `/var/lib/agentbox/data/cache/<agent>`, a btrfs subvolume with its own size limit, and tasks can't write it.
- Inside each task, a filter on `127.0.0.1:8083` is the first `GOPROXY` entry.
  It passes only exact `.info`, `.mod` and `.zip` requests.
  Lists, `@latest`, checksum lookups and private paths get its own `404`, so `go` asks `proxy.golang.org` through the tunnel.
- The filter taints the task through its gate socket before its first request, and checks each version live at `proxy.golang.org`.
  The proxy taints the task too, before the first cache byte.
- The proxy stores a file only if it matches Go's signed checksum database, and `go` checks it again.
- Nothing is shared between agents. `agentbox cache purge --agent <name>` empties one agent's store, and removing an agent deletes it.
  `agentbox goprivate set` keeps an agent's private module paths out of it.
- Fills stop at per-task, per-day and disk-reserve limits, which `agentbox budget set` changes. `go` then downloads through the tunnel.
- Each agentbox service that does not run as root refuses the btrfs call that creates a subvolume, so none can make one in the cache.

### The keys broker

- It holds the LLM API keys.
  A task sees only a local URL (`http://127.0.0.1:8081/anthropic`, and `.../openai/v1` for Codex) and a placeholder key: the task's canary, a fake credential (see [The git broker](#the-git-broker)).
- It allows only a few model endpoints: Anthropic's `POST /v1/messages` and `POST /v1/messages/count_tokens`, and OpenAI's `POST /v1/responses`, `POST /v1/chat/completions` and `GET /v1/models`.
  It answers Claude Code's `HEAD /api/hello` startup probe itself.
- It checks every request against a closed schema.
  It rejects fields that make the vendor fetch something or keep state, such as `mcp_servers`, `container`, image or PDF URLs, file IDs and `previous_response_id`.
  It forces OpenAI's `store` to `false`.
- It allows a fixed list of beta features.
  For any other beta value, or a field outside the schema, it answers `400` in the vendor's own wording, so Claude Code retries without it.
- Tasks set `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1` and `CLAUDE_CODE_AUTO_MODE_SERVER=0`.
  So Claude Code sends only the features the schema allows.
- Vendor-side web tools are blocked unless policy allows them.
  An allowed one taints the task before the request leaves.
  For now that policy is a file, `/var/lib/agentbox/control/keys/server-tools`, with one tool name per line (`web_search`, `web_fetch`).
- It strips the client's auth and adds the real key.
  It records the request with auditd, and waits for the record to be stored, before it forwards anything.
- Before it forwards a request, it reserves the worst-case cost against the agent's daily share and the task's trace budget.
  The daily cap is split among the agents, so one agent's spending never blocks another.
  Over either limit, it answers `429` with `x-should-retry: false`.
  A stream that ends before its final usage count, because the task or the vendor hung up, is billed the full reservation.
- It checks every reply for the key: as sent, base64-encoded or URL-encoded, even when the key is split across chunks.
  A reply with the key never reaches the task. Keys answers `502` instead, or cuts the stream, and raises an alert.
- It checks every request for the task's canary, in the body and the headers it forwards.
  A request with the canary still goes to the vendor, but the task is tainted and you get one alert for it.
- A vendor's `401` or `403` becomes keys' own `502`, with no vendor bytes.
- It caps each request: the header size and time, the body size, before and after `gzip`, and 16 open connections per task.
  A body must keep arriving at 256 KiB/s after its first 2 s.
  Its JSON may nest at most 64 levels and hold at most 262144 values.
  Keys reads and checks at most 6 bodies at once, 2 per agent, so one agent's slow requests never hold up another's.
- It also fronts the local model.
  It rebuilds the request from a short field list and names the fields it dropped.
  An instance that served a tainted request serves only tainted requests, until rootd restarts it.

#### Setting the keys

Run these as root on the box. The binary is not on `PATH`, so give its full path. Each command asks for the key without showing it, or reads it from standard input, so the key never lands in your shell history:

```sh
sudo /var/lib/agentbox/current/bin/agentbox secret set --name anthropic-api-key
sudo /var/lib/agentbox/current/bin/agentbox secret set --name openai-api-key
```

rootd encrypts the value with `systemd-creds` and restarts `agentbox-keys`.
Only that service can read the plaintext, from its own memory-only credentials directory.
With `tpm2` or `tpm2+tang`, the encryption key is in the TPM.
With `--encryption none`, it is a file on the same disk, so the encryption only hides the key from a casual look.

Tasks use API keys only.
`claude setup-token` and other subscription logins don't work in tasks, and Codex tasks use an OpenAI API key.
A subscription login stays in `session-home`, for interactive sessions only.

### The git broker

**Status:** Built (milestone 5). [Git and GitHub](Git-and-GitHub.md) covers setup and approvals.

- It hosts local bare repos, one set per agent, over git's smart HTTP on each task's own socket.
  A root-owned hook accepts pushes only to `agent/<name>/*` refs.
- It holds the GitHub token, scoped to the repos you register, as a systemd credential no task or other service can read.
  `agentbox secret set --name github-token` stores it encrypted, as for the LLM keys (see [Setting the keys](#setting-the-keys)).
- Agents write to GitHub only through registry operations: `repo.push`, `gh.pr.create`, `gh.pr.comment` and `gh.issue.comment`.
  Each one waits for a human. rootd stores it with the remote's URL and GitHub id and the commits it names, re-checks them at approval, and has the git service run it once.
- Each comment and pull request body ends with a hidden marker. After a restart, rootd finds an interrupted write on GitHub by that marker and never sends it twice.
  So does a write whose answer leaves it unclear whether GitHub stored it, such as a timeout or a `502`.
- By default, a push is capped at 512 MiB, and each agent at 4 GiB of pushes per day (`git.push_bytes_day` in the box's budgets).
- Each task socket has the keys broker's caps: 16 open connections, and a size and time limit on the request header.
  A request body must keep arriving at 256 KiB/s after its first 2 s.
  Each agent spools at most 2 large pushes at once, and the service runs under a memory and process limit.
- Taint follows commits.
  A tainted push taints the refs it updates and records its commits, a fetch that may deliver a tainted ref taints the fetcher, and a merge carries taint into the target branch.
- Each task carries a canary, a fake credential. A push or a GitHub write that holds it is refused, the task is tainted, and you get an alert.
- It never resolves a name. rootd resolves GitHub for it, and the firewall lets it reach only those addresses.
- Like the other services, it installs its own seccomp filter at start, so neither it nor git can make btrfs subvolumes.

### Where secrets live

| Secret | Where it lives | Status |
|---|---|---|
| LUKS disk key | Unlocked through clevis: the TPM, plus Tang in `tpm2+tang`. The 48-digit install key opens its own key slot. It is kept only in `recovery.bin`, encrypted to your offline recovery key. | Built |
| LLM API keys | `agentbox-keys` only, encrypted on disk with `systemd-creds` (see [Setting the keys](#setting-the-keys)) | Built |
| Subscription logins | `session-home`, for interactive sessions only | Built. A login can't reach its servers from an attach yet (issue #90). |
| GitHub token | `agentbox-git` only, scoped to registered repos, encrypted on disk with `systemd-creds` | Built |
| Approval keys | Your laptop (SSH key) and your phone (passkey). Never on the box. | Designed |

In the design, no credential of any kind exists inside a task.

### Known limits

- A proxy tunnel can't see HTTP methods.
  So an allowlisted host can receive writes, not only reads.
  Allowlist only hosts you trust for both.
- A CDN can front other sites behind an allowed hostname.
  Avoid CDN hostnames in allowlists.

## Taint

**Status:** Mostly designed (milestones 3-8). auditd's taint ledger is built (milestone 2): per-subject epochs, the write rules, and `taint.clear` only from rootd's admin path, after which the row stays with its epoch moved on.

Taint is how agentbox tracks untrusted content.
It decides when a task's actions need a human signature.

- **What can be tainted:** tasks, interactive sessions, workspaces, git refs, workspace snapshots and memory facts.
- **What taints:**
  - any traffic through the proxy;
  - reading app logs, GitHub issues or pull requests;
  - fetching a tainted git ref;
  - reading a tainted message, child result or memory fact;
  - any interactive session;
  - starting with no parent task and no human request.
- **How it spreads:** a tainted task taints its workspace, even if it writes nothing.
  Any task that mounts a tainted workspace becomes tainted, even one that is already running.
  Child tasks inherit taint.
- **What it costs:** a tainted task needs a human signature for every operation except reads, Safe ops and coordination ops.
- **Why a taint change voids an approval:** each approval binds the taint state it saw.
  If that taint changed, rootd does not run the approved copy.
  It evaluates the operation again, and a tainted task then needs a new signature.
- **How to clear it:** only a human can, with a signed `taint.clear`.
  The review shows the diff against the last clean snapshot.
  Control files come first, such as `.claude/`, `.mcp.json`, `CLAUDE.md`, `AGENTS.md` and `.git/`.
- A task's own taint can never be cleared, because the model's context still holds the injected text.
- auditd keeps taint in its own ledger.
  Taint only goes up, except for a clear that rootd delivers.

## The agent bus

**Status:** Designed (milestone 8).

- Agents hand work to each other over an internal bus.
  Its objects follow the A2A v1 shapes: Task, Message and AgentCard.
- It is not an external A2A endpoint.
  An external A2A binding is out of scope for v1.
- Humans start top-level tasks through rootd's admin socket.
- A parent task can send a task to a named agent (`to:`), or post it to a claim board (`skills:`).
  On the board, exactly one agent with the right skill claims it.
- Limits: at most 4 hops, no cycles, at most 5 children per task, and a 2-hour default deadline.
  Budgets apply per trace, so a fan-out is capped as a whole.
- For operations with side effects, rights intersect across the whole chain.
  A child can never do more than any of its ancestors.
- rootd records each task's origin and chain.
  agentboxd strips any `agentbox.dev/*` metadata that an agent supplies, so provenance can't be forged that way.
- Leases give agents mutual exclusion.
  In v1 they cover only `repo:<p>:main`.
  They are advisory: the real guard is rootd's compare-and-swap check when it executes.
- Canceling a task stops its container and cancels its children.
- Taint flows with the work.
  Children inherit it, and reading a tainted message or child result taints the reader first.

## Shared memory

**Status:** Designed (milestone 8).

| Layer | Store | Writer |
|---|---|---|
| Working | The agent CLI's own session, in the task's throwaway home | The agent |
| Episodic | Redacted per-agent views of the audit log, plus nightly summaries | agentboxd |
| Semantic | `memory.db`: SQLite with full-text search | agentboxd, through `memory.write` |
| Procedural | `control/procedural/`, owned by root | Humans only |

- Memory has three kinds of scope: `agent/<name>`, `project/<p>` and `procedural`.
- An agent's trusted writes to its own scope commit directly.
- Writes to a shared scope, and any tainted write, go into quarantine.
  No task can read a quarantined fact.
- A human releases a quarantined fact with a signed `memory.review`.
  Release never clears the fact's taint.
- Policy checks every read, per scope.
  Reading a tainted fact taints the reader first.
- Memory is never mounted into tasks.
  Agents reach it only through the `memory.read` operation.
- rootd exports procedural memory read-only, as an instructions file that each agent CLI loads.
- `memory.forget` hides a fact.
  `memory.purge` deletes it, as a signed admin operation.
- A task may make at most 20 memory writes.
  Embeddings are planned for v2.

## Audit

**Status:** Built (milestones 2 and 3), except shipping the log off the box. No producer other than rootd and the test producer writes to it yet.

- `agentbox-auditd` is the only writer of the audit log.
  It runs as its own user, with no network.
- Each producer has its own socket, and auditd identifies the producer by its uid.
- The log is a chain of JSONL segments.
  Each record holds a sequence number and the SHA-256 of the previous record.
  Order comes from the sequence, never from the clock.
- Every effect follows one order: INTENT, acknowledgement, effect, RESULT, acknowledgement.
  auditd acknowledges a record only after it is on disk.
- If auditd is down, no effect runs and no tainted data is delivered.
  The exceptions only remove capability: `task.stop`, and the stop of a session that outlived a rootd restart, which `agentbox attach rescan` runs before its scan.
- Each field has an audit class.
  `drop` fields, such as secrets, are never logged, not even as a hash.
  `hash` fields, such as file contents, are logged as a hash and a length.
  `keep` fields are logged as they are.
- auditd rejects a record that breaks the class rules, and then the effect never runs.
- rootd creates each segment append-only, and seals it immutable when auditd rotates to the next one.
- auditd keeps a 512 MiB disk reserve.
  If the disk fills, only admin operations still run.
- The design keeps audit records for 1 year, and it records no task transcripts by default.
- Shipping the log off the box is recommended, so tampering on the box can be detected.

Built today: auditd with one socket per producer, sequence-named segments, the hash chain, taint epochs, disk-full mode and rootd's sealing (`chattr +a`, then `+i`).
`agentbox audit verify` checks the chain.
Installer logs persist under `/var/log`, with no password hash.
The `os` commands and `fwcheck` print alerts that start with `agentbox: ALERT:`, and send each one to ntfy with fixed text.
The printed line keeps the details. When `os health` runs from its timer, it lands in the journal.
A condition that stands, such as an unhealthy committed generation, sends one ntfy alert, and the next only after it clears or the box reboots.
If ntfy can't take an alert, the command prints `agentbox: alert not sent` and puts the alert in rootd's alert queue.
rootd's own alerts go through that queue too. rootd sends its own alerts at once, and tries every queued alert again every 10 seconds until ntfy takes it.
The queue lives in `rootd.db`, so an alert survives a restart of ntfy or rootd. It holds at most 256 alerts.

## When things fail

| Failure | What happens | Status |
|---|---|---|
| A new generation fails to boot, or fails its health check | The box falls back to the committed generation, with no console input. | Built |
| Power cut during `os apply` | The committed generation boots, or the finished trial boots and then commits. | Built |
| Tang is down (`tpm2+tang`) | The disk can't unlock. The box reboots about every 8 minutes until Tang is back, or someone types the recovery key. | Built |
| agentboxd is down | Running tasks keep running. A task's result still arrives if agentboxd returns before the task's deadline. | Designed |
| rootd is down | Operations fail closed. On restart, rootd reconciles every open operation with auditd before it listens again. | Designed |
| auditd is down | No effect runs, and no tainted read is delivered. | Built for rootd and the test producer |
| The firewall check fails | No agent or app can start. | Built, with a stand-in agent unit |
| The disk is nearly full | New task dispatch pauses at 92% used. Audit and control state keep a reserve, so admin operations still run. | auditd's disk-full mode and the `2/0` reserve are built. Dispatch is designed. |

## Security model in brief

**Status:** Mostly designed.

- agentbox protects the host, its secrets, your data and LAN, and the integrity of approvals, audit and memory.
- Prompt injection is the most likely attack.
  Others are a compromised agent CLI or dependency, a thief, someone on your LAN or tailnet, and bugs in agentbox's own services.
- The threat model lists seven non-negotiables that tests must prove.
  Six have built parts today:
  - "Tasks have no network": task containers, the proxy, the keys broker and the git service are built.
  - "No credential exists inside a task": built for the LLM API keys and the GitHub token.
  - "Agents never mutate the running OS": the generation mechanism is built. Agents are not.
  - "Taint is sticky": auditd's taint ledger, the spread from a task to its workspace, and the taint the proxy, the keys broker and the git service set are built. The rest of what sets taint is not.
  - "Nothing persists between tasks": built for task containers. Each agent's read-only Go module cache is the one narrow exception.
  - "The seed and logs contain no plaintext secrets": built. The seed still holds the admin password hash, so keep it private.
- The threat model also lists accepted risks, many with a path for v2.
  Examples: shared-kernel exploits (v2: microVM tasks), and an admin account that is root-equivalent.

Read [Security Model](Security-Model.md) and the one-page threat model in the repo, [`docs/THREAT-MODEL.md`](../../docs/THREAT-MODEL.md).

## Code layout

| Path | What it holds | Status |
|---|---|---|
| `cmd/agentbox` | The CLI: `seed`, `recovery`, `os`, `reconcile`, `fw`, `fwcheck`, `auditd`, `audit`, `rootd`, `egress`, `sockets`, `agentboxd`, `gate`, `agent`, `accounts`, `task`, `taskrun`, `attach`, `why`, `goprivate` and `version` | Built |
| `internal/seed` | Seed validation and the autoinstall template | Built |
| `internal/recovery` | Recovery key generation and decryption | Built |
| `internal/rootd/gens` | A/B generations: plan, build, initrd checks, commit, fallback, retention | Built |
| `internal/rootd`, `internal/rootd/{resolve,quota,nl}` | The rootd skeleton: sockets, the resolver, quota groups, netlink (nftables sets and conntrack) | Built (milestone 2) |
| `internal/fw` | The nftables ruleset, `fw load` and `fwcheck` | Built (milestone 2) |
| `internal/audit` | auditd: segments, the hash chain, the taint database, sealing, `audit verify` | Built (milestone 2) |
| `internal/ntfy` | ntfy's config, ACLs, unit drop-in and fwcheck's ntfy check | Built (milestone 2) |
| `internal/ops`, `gen/` | The operation registry, the denial codes table, and the files generated from them: the Cedar schema, the JSON schemas and the MCP tool list | Built (milestone 3) |
| `internal/gate`, `internal/ids` | agentboxd's task gate and the `<kind>_<ULID>` ids | Built (milestone 3) |
| `internal/sockets` | The socket inventory, the generated tmpfiles.d and `.socket` units, and `agentbox sockets check` | Built (milestone 3) |
| `internal/rootd/accounts`, `internal/task`, `internal/seccomp`, `internal/rootd/attach`, `internal/controlpaths` | Agent accounts, the task container and its seccomp profile, interactive sessions, and the workspace control-file list | Built (milestone 4) |
| `internal/taskenv`, `internal/taskrun`, `internal/rootd/witness` | The task environment, the in-task forwarders and `agentbox why`, and the witness pipe rootd reads | Built (milestone 4) |
| `internal/proxy`, `internal/dial` | The egress proxy (CONNECT checks, taint and tunnels), and the pinned dialer the brokers share | Built (milestone 5) |
| `internal/keys`, `internal/broker`, `internal/budgets` | The keys broker (request schemas, the key, the reply scan, spend), the per-task socket server with admission caps that it runs on, and the agents' daily shares | Built (milestone 5) |
| `internal/proxy/gocache`, `internal/taskrun/gomodfilter` | The Go module cache and its in-task filter | Built (milestone 5) |
| `sysusers.d/`, `tmpfiles.d/` | The service users and the runtime directories | Built (milestones 2 and 3) |
| `install/`, `systemd/` | The release's `install.sh` and its systemd units | Built |
| `hack/` | The release builder, the ISO remaster script, the QEMU harness and the test gates | Built |
| `internal/{policy,bus,memory,decide,dispatch,approvald,webauthn,gitsvc,reconcile}`, the rest of `internal/rootd` | The rest of the agent runtime | Designed |

Today the code uses the Go standard library plus three modules: `golang.org/x/sys`, `golang.org/x/mod` (for the Go module cache) and the pure-Go SQLite driver `modernc.org/sqlite` (for auditd's taint database and `rootd.db`).
The design adds more later, such as cedar-go, the MCP Go SDK and a WebAuthn library.

## Read more

- [Generations and Updates](Generations-and-Updates.md), [Encryption and Recovery](Encryption-and-Recovery.md) and [Release Pipeline](Release-Pipeline.md) cover the built parts in depth.
- [Security Model](Security-Model.md) covers the threats, the trust boundaries and the accepted risks.
- [Roadmap](Roadmap.md) lists what each milestone adds.

Where each topic lives in [`ARCHITECTURE.md`](../design/ARCHITECTURE.md):

| Topic | Section |
|---|---|
| Principles | §0 |
| System context | §1 |
| Services and sockets | §2 |
| Install, storage and generations | §3 |
| Agent runtime: accounts, tasks, credentials | §4 |
| Control plane: registry, request flow, operations, approvals, decide | §5 |
| Network, secrets and budgets | §6 |
| Agent bus | §7 |
| Shared memory | §8 |
| Audit | §9 |
| Security model | §10 |
| Failure modes | §11 |
| Build order and gates | §15 |
