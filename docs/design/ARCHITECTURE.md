# agentbox: Architecture Design v5.3

**Status:** build-ready design. Implementation proof is the per-phase gates in §15.
**Date:** 2026-11-20.
**Changelog:** 2026-11-20, v5.3: adopted proposals A–D of `PROPOSALS-v5.3.md` (a read-only Go module cache, workspace-bound memory notes, structured denials, a visible ask budget with `ask.quote`, `ask.status` and `ask.batch`); rejected proposal E (the delivery lane); a new approval target (§15); §3.3 step 6 re-asserts `saved_entry` on a failed trial (§17 Round 6). v5.2 is kept as `ARCHITECTURE-v5.2.md`. Earlier on 2026-11-20: weeks 1–2 build corrections, still v5.2: §2 `osbuild-fetch@`; §3.1 zero-touch, password hashes, taken names, initrd checks, gen-1 masks, the signed-kernel step, firstboot's sha256 pin and download cap, the release layout; §3.2 `cas/`; §3.3 the as-built stand-ins, fstab, the initrd gate, the GRUB-safe replace, Settle, FixGrub, the watchdog via `force_drivers`, `rd.timeout=600`, the snapd policy, health; §10 new residuals and test-model limits; §12, §14, §15 results; Appendix A re-rendered.
**Base:** Ubuntu Server 26.04.1 LTS ("resolute"): Linux 7.0, systemd 259.9, Podman 5.7.0, nftables 1.1.6, GRUB 2.14, dracut 110 (the default initramfs generator).

**Reviews.** Rounds 1–4 ran Codex at `model_reasoning_effort="max"`. Round 5 was a multi-agent audit of v5.1 plus the week-1 code. Round 6 red-teamed and judged five agent-ergonomics proposals for v5.3.

| Version reviewed | Result | File |
|---|---|---|
| v2 | 32 findings | `codex-arch-review-max.md` |
| v3 | 17 fixed / 14 partial / 1 wrong, plus 17 new findings | `codex-arch-review-max-v3.md` |
| v4 | 11 fixed / 5 partial / 2 wrong on the round-2 items, plus 12 new findings (2 critical, 10 high) | `codex-arch-review-max-v4.md` |
| v5 | round-3 items: 3 fixed / 10 partial / 1 wrong, plus 11 remaining findings (1 critical, 10 high) | `codex-arch-review-max-v5.md` |
| v5.1 + week-1 code | 154 findings: 82 on the code, 72 on the architecture | `LEDGER.md` |
| v5.2 (agent ergonomics) | 5 proposals, each red-teamed and scored by three judges: 4 adopted (A–D), 1 rejected (E, the delivery lane) | `PROPOSALS-v5.3.md` |

v5.2 resolves every round-5 architecture finding in the text, and schedules each one in `PLAN.md` at the week that builds its component (see §17). One deliberate disagreement from earlier rounds stays recorded (Codex's disposable VM, §17 round 3). The other, keeping PCR 7 for `tpm2`, is reversed in v5.2: `tpm2` binds with no PCR policy (§3.1, §17). v5.3 adopts round 6's proposals A–D and rejects E (§17 Round 6).

✓ = verified against primary sources: the Launchpad archive API, upstream source, man pages and specs (2026-11-10, plus the round-5 fact checks B1–B11 on 2026-11-16).

## 0. Principles
1. **Models propose, code decides.** No model output grants a permission. Classifiers can only add friction.
2. **The running OS is never mutated by agents.** OS changes are downloaded as signature-verified packages, then installed offline into a cloned generation inside a user-namespaced, network-less nspawn. That generation is booted once and becomes the default only after a health check.
3. **No network for agents or apps.** Containers run `Network=none`. Egress goes only through per-task Unix sockets. Broker services (proxy, keys, git) may connect only to IPs that **rootd** resolved for allowlisted names (through systemd-resolved's Varlink API over a Unix socket ✓). Those IPs sit in nftables sets that only rootd writes.
4. **The executor owns the floor.** `agentbox-rootd` stores every pending operation. Each one is bound to its **immutable inputs**: commit IDs, content-addressed build snapshots, package closures with `.deb` hashes. rootd executes only what a human signed, and re-checks state at execution (compare-and-swap, taint, policy).
5. **No credentialed remote writes outside the registry.** Tasks hold no credentials. Every write that needs a credential (git push, PR, comment) is a registry op, executed by a broker on a one-shot rootd capability. **Limit:** plain egress to a human-allowlisted host can still carry writes (CONNECT can't see HTTP methods). Allowlist only hosts you trust for both reads and writes (§6.2).
6. **Tasks are disposable.** Each task gets its own container, its own ephemeral HOME and its own sockets. Nothing a task writes outside the (sticky-tainted) workspace survives the task.
   **Two narrow stores outlive a task without a per-item review, and both end at the next `taint.clear`.** (a) The read-only Go module cache (§6.2): tasks can't write it; it holds only `.mod` and `.zip` files that the Go checksum database binds to their version; a task can use it only after it is tainted, and the task's own filter checks every use live upstream; it is empty whenever the agent's workspace is clean. (b) Workspace-bound memory facts (§8): own-scope notes that automated tasks write while their workspace is tainted; readable only by tasks that hold the same tainted workspace epoch, which are already tainted; never written by attach sessions; quarantined at the next clear or signed restore. Both assume one workspace subject per agent (§4.1). The arguments are in §6.2 and §8.
7. **Taint is sticky and independent of the policy daemon.** Brokers and rootd report it to auditd. Only humans clear it, through an admin `taint.clear` that rootd executes (§9). **Exception:** agentboxd reports bus and memory taint, so that taint is only as sound as agentboxd (§5.2).
8. **Honest guarantees.** The doc states rollback coverage per op, treats deletion as logical, and spells out the exact disk-encryption threat model and the phone-approval limits.
   Denials are honest too. A denial holds only the caller's own grammar-checked request fields, constants from the signed release, and facts about the caller's own task and resources (§5.6). It is built after the decision and can't change it. rootd keeps its own record of the denials each task saw (§5.6 Witness). Every quote-shaped read (`ask.quote`, and an `ask.batch` refused at admission) is counted per task, per trace and per agent and can raise an alert, so the recon surface is bounded and visible, not merely logged (§5.4).

## 1. System context
```
 Humans: laptop `agentbox` CLI ─ SSH ─ rootd-admin.sock (P fetched from root; H recomputed and SSHSIG-signed on the laptop)
 Phone (reversible asks only): ntfy view link → tailscale serve :443 → 127.0.0.1:43100 (socket-activated; nft uid 0 only)
        → agentbox-approvald (static page, exact-origin WebAuthn) → passkey assertion over H → approve.sock → rootd verifies
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ agentboxd (agentbox; PrivateNetwork): task gate · Cedar (stricter-than-floor asks) · bus · memory · decide│
│ agentbox-rootd (root; AF_UNIX/NETLINK only): FLOOR · pending ops P bound to immutable inputs · nonce txn  │
│   · task registry + launcher · users/pods/Quadlets · generations · CAS · audit file creation/sealing     │
│   ├─ osbuild-fetch@  (root, network, apt download only: no maintainer scripts)                          │
│   ├─ osbuild-apply@  (nspawn --private-users=0x7F000000:65536, ownership=map, --private-network)        │
│   └─ osbuild-image@  (rootful podman build of agentbox's own pinned Containerfile only)                │
│ agentbox-auditd (agentbox-audit; PrivateNetwork): hash chain + taint ledger, ACK after fdatasync        │
│ rootd resolver: systemd-resolved Varlink (AF_UNIX) → validate public → nft dst sets (TTL); brokers ask over svc sockets │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
 per-task sockets /run/agentbox-<svc>/t/<task>/<svc>.sock  (dir 2750 svc:ag-<agent> made by rootd, sock 0660)
┌──────────────────────────┐  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌───────────────────────┐
│ task container (ag-*)    │─►│ proxy        │ │ keys         │ │ git          │ │ llm@task, llm@decide  │
│ Network=none · --rm      │  │ no secrets   │ │ LLM keys,    │ │ local repos, │ │ (llama-server,        │
│ HOME = tmpfs (ephemeral) │  │ dst ∈ rootd  │ │ budgets      │ │ GitHub token,│ │ PrivateNetwork) via   │
│ fwd 8080/8081/8082       │  │ set only     │ │              │ │ gh.* ops     │ │ socket-proxyd unix    │
└──────────────────────────┘  └──────────────┘ └──────────────┘ └──────────────┘ └───────────────────────┘
 apps: rootless pods (app + shim), Network=none; ingress 127.0.0.1:45000+M (socket-activated) → socket-proxyd
       (agentbox-ingress) → /run/agentbox-apps/<m>/in/in.sock (bound by shim in pod) → app 127.0.0.1:<port> in pod
 Disk: GPT ESP │ ext4 /bootpart {grub/, agentbox/{gens/<gen>/ (= that generation's /boot), recovery.bin, committed}}
       │ LUKS2 → btrfs {@gen-N, @home, @var_log, @var_lib_agentbox, @var_lib_agentbox_data, @var_lib_tailscale,
       │                @var_lib_ntfy, @srv, @snapshots}
```

## 2. Services and sockets
All agentbox services are subcommands of one Go 1.26 binary (✓ `golang-1.26` 1.26.8). Every unit sets `Requires=` and `After=agentbox-reconcile.service agentbox-firewall.service`.

| Service | uid | Holds | Isolation | Notes |
|---|---|---|---|---|
| `agentboxd` | `agentbox` | state.db, memory.db | `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX` | parses agent JSON-RPC |
| `agentbox-rootd` | root | rootd.db (pending, nonces, approvers, task registry, ids, remotes), CAS | `RestrictAddressFamilies=AF_UNIX AF_NETLINK`, `InaccessiblePaths=/home /root` (`ProtectHome=yes` less `/run/user`, for the pause check, §4.2), `ProtectKernelModules=yes` | typed executor; spawns the `osbuild-*@` transient units; **resolves allowlisted names** via systemd-resolved Varlink (`ResolveHostname` ✓) and writes the broker destination sets; `Type=notify`, sends READY=1 only after the nft sets match rootd.db (§6.1) |
| `osbuild-fetch@` | root (transient) | none | IP allowed; runs only `apt-get --print-uris` and `apt-get --download-only` with an explicit `Dir::State::status`, `Dir::Etc` and `Dir::Cache` | no maintainer scripts run. Every apt call gets `-c plan.conf`, which `#clear`s apt's update hooks (`APT::Update::*`) and JSON hooks (`AptCli::Hooks`), so no hook of the running generation runs. **Not built yet:** in weeks 1–2, `agentbox os plan` runs these apt calls as root on the host. |
| `osbuild-apply@` | container root mapped to an unprivileged range | none | `systemd-nspawn --private-users=0x7F000000:65536 --private-users-ownership=map ✓ --private-network --bind=<gen boot>:/boot:rootidmap --bind-ro=<debs>:/var/cache/apt/archives` | installs approved `.deb`s offline. The fixed id range lies outside nspawn's automatic pool and every sub-id block (§4.1). rootd runs one `os.apply` at a time, so the fixed range can't collide. |
| `osbuild-image@` | root (transient) | none | IP allowed | builds only agentbox's own pinned task-image Containerfile |
| `agentbox-depcheck@` | transient `DynamicUser` | none | `PrivateNetwork=yes`; `AmbientCapabilities=CAP_DAC_READ_SEARCH` and no other capability; `NoNewPrivileges=yes`; `RootDirectory=` an empty root-owned dir with `BindReadOnlyPaths=` for the binary, the two snapshots and `data/cache/<agent>`; `MemoryMax=2G`; `RuntimeMaxSec=300` | dependency report for `taint review` and `agent.attach` (§7): one JSON report on stdout, at most 16 MiB, checked by rootd against a strict schema; started by rootd like `osbuild-*@` |
| `agentbox-auditd` | `agentbox-audit` | audit chain, taint.db | `PrivateNetwork=yes`, AF_UNIX | ACKs only after `fdatasync` plus SQLite `synchronous=FULL` |
| `agentbox-approvald` | `agentbox-approve` | **no keys** | AF_UNIX; inherited TCP fd from its socket unit | static review page plus relay; three calls on `approve.sock` (§5.4) |
| `agentbox-proxy` | `agentbox-proxy` | **no secrets**; per-agent Go module caches (`data/cache/<agent>`, §6.2) | AF_UNIX/INET/INET6; nft: destinations in `proxy_dst` only; `InaccessiblePaths=/run/systemd/resolve /run/dbus/system_bus_socket` (§6.1); `ReadWritePaths=/var/lib/agentbox/data/cache` | CONNECT egress for tasks; read-only Go module cache (§6.2) |
| `agentbox-keys` | `agentbox-keys` | LLM keys, spend ledger | as proxy; nft: `keys_dst` only | LLM broker |
| `agentbox-git` | `agentbox-git` | local bare repos, GitHub token | as proxy; nft: `git_dst` only | smart-HTTP plus `gh.*` ops |
| `agentbox-llm@task` | `agentbox-llm` (`render`, `video`) | models (read-only) | `PrivateNetwork=yes`; reached via `agentbox-llm-proxy@task` (`systemd-socket-proxyd`, `JoinsNamespaceOf=`) ✓ | task completions, through keys only; restarted by rootd on `llm.recycle` (§6.3) |
| `agentbox-llm@decide` | `agentbox-llm-decide` (`render`, `video`) | models (read-only) | as `@task`, via `agentbox-llm-proxy@decide` | decide only (§5.5); may load a smaller model |
| `agentbox-ingress@M` | `agentbox-ingress` | none | `systemd-socket-proxyd` from socket-activated TCP to the app's Unix socket ✓ | one per app |
| ntfy (`ntfy` 2.11.0 ✓) | `_ntfy` (packaged, sysusers ✓) | topic ACLs (`auth-file`) | no TCP listener (`listen-http: "-"`); `listen-unix` ✓; phone TCP via a socket-proxyd unit; nft: `ntfy_dst` and `127.0.0.53:53` only | packaged unit plus agentbox drop-in (below) |
| tailscaled | root | node key | tailnet | `serve` only; **never `funnel`** |

- **Common hardening:** `ProtectSystem=strict`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `MemoryDenyWriteExecute=yes`, `SystemCallFilter=@system-service`, and explicit `ReadWritePaths=` on every unprivileged service.
- **No btrfs ioctls in services.** Every non-root agentbox service (agentboxd, auditd, approvald, proxy, keys, git) installs a seccomp filter at start. An `ioctl` whose type byte is `0x94` returns `EOPNOTSUPP` (the §4.2 rule), and a non-native arch kills the process. The service installs it with `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC)` under `NoNewPrivileges=yes`; if the install fails, the service exits. systemd's `SystemCallFilter=` can't match ioctl arguments, so the binary installs the filter itself. No service can then create a subvolume outside `2/0` in `data/cache/`, `git/`, `state/` or `memory/`.
- **llama-server flags (both instances):** `--no-slots --no-webui`. Never `--slot-save-path`, `--props`, `--lora` or `--metrics`. Upstream enables `/slots` and the web UI by default ✓.
- **ntfy (packaged).** Ubuntu's package runs ntfy as `User=_ntfy`, `Group=_ntfy` ✓ (`debian/ntfy.sysusers`: `u _ntfy -`) and ships the unit `--no-enable` ✓. agentbox creates no `ntfy` user. Reconcile writes these files, root-owned, and then enables `ntfy.service`:
  - `/etc/ntfy/server.yml`:
    ```yaml
    base-url: "https://<box>.<tailnet>.ts.net:8443"   # the tailscale serve URL that fronts 127.0.0.1:43200
    listen-http: "-"
    listen-unix: /run/ntfy/ntfy.sock
    listen-unix-mode: 0660
    cache-file: /var/lib/ntfy/cache.db
    auth-file: /var/lib/ntfy/user.db
    auth-default-access: deny-all
    upstream-base-url: "https://ntfy.sh"
    ```
  - `listen-http: "-"` is required. The upstream default is `:80` on every interface ✓. Nothing filters input, so LAN hosts would reach ntfy directly, and `_ntfy` can't bind `:80` anyway.
  - `auth-default-access` does nothing without `auth-file` ✓. The `agentbox-notify` identity gets write access to its own topics only.
  - `upstream-base-url` needs `base-url` ✓, or ntfy refuses to start. ntfy.sh receives only the SHA-256 of `<base-url>/<topic>` and the message ID ✓, never the text.
  - tmpfiles: `d /run/ntfy 2750 _ntfy agentbox-notify -` and `d /var/lib/ntfy 0750 _ntfy _ntfy -`. ntfy only chmods its socket and never chowns it ✓, so the setgid dir supplies the group.
  - Drop-in `/etc/systemd/system/ntfy.service.d/50-agentbox.conf`: `[Unit] Requires=agentbox-firewall.service`, `After=agentbox-firewall.service`; `[Service] ExecStartPre=+/var/lib/agentbox/current/bin/agentbox fwcheck`. The packaged unit orders only `After=network.target` ✓.
  - **install.sh order:** `apt-get install ntfy` → `getent passwd _ntfy` must succeed → write the files above → `systemd-tmpfiles --create` → `nft -c -f /etc/nftables.d/agentbox.nft` must exit 0 → `systemctl enable ntfy.service`. Any failure stops the install.

### 2.1 Socket inventory (complete)
- **Fixed sockets** are systemd `.socket` units with explicit `SocketUser=`, `SocketGroup=` and `SocketMode=`. The systemd default is 0666 ✓ (Codex citation), so every unit sets these explicitly.
- **Runtime dirs** come from `/usr/lib/tmpfiles.d/agentbox.conf`, never from `RuntimeDirectory=`. systemd deletes `RuntimeDirectory=` dirs when the unit stops, which would break running tasks' bind mounts.
  - `d /run/agentbox-rootd 0711 root root -`
  - `d /run/agentbox-rootd-approve 0750 root agentbox-approve -`
  - `d /run/agentbox-audit 0711 agentbox-audit agentbox-audit -`
  - `d /run/agentbox-<svc> 0711 root root -` and `d /run/agentbox-<svc>/t 0711 root root -` for gate, proxy, keys and git
  - `d /run/agentbox-witness 0711 root root -` and `d /run/agentbox-witness/t 0711 root root -` for the task witness FIFOs (§5.6)
  - 0711 allows traversal but not listing. Access control lives on each socket's owner, group and mode, plus `SO_PEERCRED`.
- **Per-task sockets.** In `task.start`, before the container launches, rootd (as root) creates `/run/agentbox-<svc>/t/<task>`. It uses `mkdirat`, then `fchownat` with `AT_SYMLINK_NOFOLLOW` to `<svc>:ag-<agent>`, then sets mode **2750 (setgid)**. The service binds `<svc>.sock` inside with umask 0117. Setgid inheritance makes the socket `<svc>:ag-<agent>` 0660. The service never calls chown. This is the same pattern as the app dirs below.
- **Restarts keep the dir.** A restarted service gets the live tasks from rootd (`task.list_live`: `task_registry` rows with `ended_at IS NULL`). It unlinks only its own stale socket and binds a new one in the same dir. The dir inode doesn't change, so the container's bind mount (Appendix C) sees the new socket. rootd removes the dir only after the task cgroup is empty. This is how a task survives an agentboxd restart (§4.2, §11).
- **Peer checks.** Every server checks `SO_PEERCRED` against the expected uid set. `agentbox-approve` is never a member of `agentbox-admin`; rootd refuses to start if it is.
- **No descriptor passing.** Servers refuse `SCM_RIGHTS` ancillary data, `rootd-admin.sock` included. `agent.attach` relays bytes through rootd's output filter (§4.2).
- **Revocation** when a task ends (`task.stop`, §4.2): rootd sends `revoke{task}` on `svc-<svc>.sock`. The service unlinks the socket, closes the listener, then closes every accepted connection tagged with that task id. It drops the task's registration and rejects any request whose task id is no longer registered, so an orphaned connection can't be reused.

| Socket | Owner:group, mode | Allowed peers |
|---|---|---|
| `/run/agentbox/admin.sock` (agentboxd) | root:agentbox-admin 0660; dir 0750 | humans in `agentbox-admin` |
| `/run/agentbox-rootd/rootd.sock` | agentbox:agentbox 0600; dir root:root 0711 | uid `agentbox` |
| `/run/agentbox-rootd/rootd-admin.sock` | root:agentbox-admin 0660 | `agentbox-admin` members |
| `/run/agentbox-rootd-approve/approve.sock` (approvald → rootd) | root:agentbox-approve 0660; dir root:agentbox-approve 0750 | uid `agentbox-approve` only; three calls only (§5.4) |
| `/run/agentbox-rootd/svc-<svc>.sock` (task registration and revocation, rootd → service; the proxy also takes `cache.purge{agent}`) | `<svc>`:root 0600 | uid 0 only |
| `/run/agentbox-audit/<producer>.sock` | agentbox-audit:`<producer>` 0660; dir agentbox-audit 0711 | that producer's uid |
| `/run/agentbox-rootd/resolve-<svc>.sock` (resolution requests; keys also sends `llm.recycle`; the proxy also sends `cache.alert{agent, reason}`) | root:`<svc>` 0660 | proxy, keys, git (rootd fills `ntfy_dst` itself, §6.1) |
| `/run/agentbox-<svc>/t/<task>/<svc>.sock` (gate, proxy, keys, git) | `<svc>`:ag-`<agent>` 0660; dir `<svc>`:ag-`<agent>` **2750 (setgid)**, created by rootd | that agent's uid (and only inside that task's mount namespace) |
| `/run/agentbox-witness/t/<task>/witness` (a FIFO, not a socket) | dir root:ag-`<agent>` 0750, FIFO root:ag-`<agent>` 0620, created by rootd | written by that agent's uid inside that task only; read by rootd only (§5.6) |
| `/run/agentbox-llm/llama.sock` (task instance) | agentbox-llm:agentbox-keys 0660 | agentbox-keys |
| `/run/agentbox-llm-decide/llama.sock` (decide instance) | agentbox-llm-decide:agentbox 0660 | agentbox |
| `/run/agentbox-apps/<m>/in/in.sock` (bound by the pod shim) | dir app-`<m>`:agentbox-ingress **2750 (setgid)**, created by rootd; socket 0660 | agentbox-ingress |
| `/run/agentbox-apps/<m>/egress/egress.sock` (created by proxy) | dir agentbox-proxy:app-`<m>` **2750 (setgid)**, created by rootd; socket 0660 | app-`<m>` |
| `/run/ntfy/ntfy.sock` | dir `_ntfy:agentbox-notify` **2750 (setgid)**, created by tmpfiles; socket 0660 (`listen-unix-mode`), group inherited from the dir | agentbox, rootd, ntfy-tcp proxy |
| TCP `127.0.0.1:43100` (approvald), `:43200` (ntfy), `:45000+M` (apps) | socket-activated by PID 1 at boot | nft `(uid . port)` tuples (§6.1) |

taskrun's Go module filter (§6.2) listens on `127.0.0.1:8083` inside the container only. It uses the task's existing gate socket (`task.taint_self`) and proxy socket. Every proxy resolution request names a live task. No new socket.

## 3. Install, storage, generations
### 3.1 Install (Appendix A)
- **Media and seed.** Stock Ubuntu Server ISO plus a NoCloud seed from `agentbox seed`.
  - **Zero-touch.** `hack/remaster-iso.sh` adds `autoinstall ds=nocloud` before ` ---` on every casper linux line of the pinned ISO's `grub.cfg`. It changes only that file and its `md5sum.txt` line, and refuses an ISO that doesn't match `hack/SHA256SUMS`. The stock 30 s GRUB timeout stays as an abort window. With the stock ISO instead, press `e` at its GRUB menu and add `autoinstall` before `---`; otherwise subiquity waits for a typed "yes". Never put USB first in the boot order: with both sticks in, every boot reinstalls.
  - **Network.** The install needs wired network access to the Ubuntu mirror: `archive.ubuntu.com` on amd64, `ports.ubuntu.com` on arm64. Ten seed packages in the encrypted modes (five in `none`) are not on the ISO: minisign, podman, crun, systemd-container and systemd-zram-generator, plus clevis, clevis-luks, clevis-tpm2, clevis-dracut and tpm2-tools and their dependencies ✓ (B10). The seed sets `apt: {fallback: abort}`, and `early-commands` probes the mirror for the running architecture, so an offline box stops before any disk write.
  - **No plaintext secrets.** The seed holds:
    - the admin SSH key
    - the admin's password hash: yescrypt (`mkpasswd -m yescrypt`), or sha512-crypt with `rounds=100000` or more. `openssl passwd -6` (5000 rounds) is refused. It is for the console and `sudo` only; SSH password auth is off. **Treat the seed as private.** `agentbox seed` writes `user-data` as 0600.
    - the minisign release key
    - the RSA-4096 recovery public key
    - the optional Tang URL and its **thumbprint (`thp`)** ✓
  - **Tang URL.** It MUST be `http://<private IPv4 literal>[:port][/path]`. The 26.04 dracut initrd has no DNS resolver and no CA bundle: `clevis-pin-tang` pulls in only `network`, and dracut's `systemd-resolved` module is opt-in ✓. A hostname or https URL binds in the installer but never unlocks at boot, and with SSS `t=2` the disk stays locked. `agentbox seed` rejects hostnames, https and public addresses. Give the Tang device a DHCP reservation. Any later tool that rewrites the clevis binding (`os.apply`, re-bind) MUST apply the same check.
- **Admin user.** Defaults to `boxadmin`; set it with `--admin`. `agentbox seed` refuses the name, before anything is written, unless it matches `^[a-z_][a-z0-9_-]{0,31}$` and is none of:
  - a name in subiquity's `reserved-usernames` ✓ (B6; subiquity aborts with "Username is reserved by the system"; e.g. `root`, `admin`, `operator`). The 110-name list is embedded in `internal/seed/reserved.go`, pinned to subiquity 26.04.1.
  - an account already in the 26.04.1 server image (e.g. `lxd`, `tss`, `clock`, `rdma`, `usbmux`; read from `etc/passwd` and `etc/group` in the ubuntu-server squashfs layer of both pinned ISOs), or one of agentbox's accounts and namespaces (§12): `agentbox`, `ntfy`, and the prefixes `agentbox-`, `ag-`, `app-`, `systemd-`, `_`.
  - Re-sync both lists whenever the pinned ISO or subiquity changes. The gate checks that `agentbox seed` refuses every user and group on the installed box.
- **Disk.** Matched by exact udev `ID_SERIAL` (`serial:`) ✓ (B1). Get it on the target with `udevadm info --query=property --property=ID_SERIAL --value /dev/<disk>`. Do not use `lsblk SERIAL`: it prints the short form (`ID_SERIAL_SHORT`), which never matches SATA, NVMe or USB disks.
  - subiquity fails when nothing matches, but silently takes the first of several matches. curtin storage v1 re-resolves `serial` by `/dev/disk/by-id` substring.
  - So `early-commands[0]` is a disk guard. It logs every disk's `ID_SERIAL` to the journal (`journalctl -b | grep 'agentbox: disk'`). It exits 1 unless exactly one whole disk has that `ID_SERIAL` and no other by-id name contains it.
  - A guard failure, or subiquity's "matched no disk", stops the install before storage runs. Nothing is wiped.
- **TPM precheck.** In encrypted modes, an early command runs `test -c /dev/tpmrm0`. A box without an enabled TPM2 stops before any disk write, instead of failing at `clevis luks bind` after the disk was LUKS-formatted.
- **LUKS key.** `early-commands` writes 48 random decimal digits (no newline, umask 077) to tmpfs. That is typeable at the unlock prompt, and the same format as subiquity's recovery keys ✓ (B5).
  - curtin uses the file as `keyfile:` with `options: [luks, x-initrd.attach, timeout=300s]`. It writes crypttab `croot UUID=… none luks,x-initrd.attach,timeout=300s` ✓ (B4). Field 3 stays `none` so clevis can answer the prompt; never add `headless`, `keyscript` or `noauto`.
  - `x-initrd.attach` makes dracut's hostonly crypttab filter keep `croot` even when it can't probe the disk (the §3.3 nspawn can't) ✓. `timeout=300s` ends a stuck unlock prompt so `rd.emergency=reboot` can fire (§3.3).
  - In `late-commands`, inside the gen-1 chroot:
    1. `clevis-dracut` comes from `packages:`. 26.04 Server uses dracut 110; initramfs-tools is not in the target ✓ (B9).
    2. `clevis luks bind -k <file>` per mode, never with `-y`, so the Tang advertisement is checked against `thp`.
    3. Write `/etc/dracut.conf.d/90-agentbox.conf` (Appendix A). Every later generation inherits it. Then `dracut -f --regenerate-all`, and check every kernel's initrd: the `croot` crypttab line, `systemd-cryptsetup`, `clevis-luks-askpass`, each pin's `clevis-decrypt-*` binary (`sss`, `tpm2`, `tang`), `btrfs.ko`, the recorded drivers and the watchdog driver (unless built in). A failure stops the install, not the first boot.
    4. Encrypt the keyfile to the recovery public key → `/bootpart/agentbox/recovery.bin`.
    5. Shred the keyfile.
    6. Remove the seed copy and the generated curtin configs from the live `/var/log/installer`, then mount `@var_log` at `/target/var/log` as the last late-command. Subiquity rsyncs the live directory into `/target/var/log/installer` only after late-commands ✓ (B7). `/target` is the btrfs top level, which firstboot deletes, so without the mount the logs are lost.

| Mode | Unattended | Protects | Doesn't protect |
|---|---|---|---|
| `tpm2+tang` (**recommended**) | yes, on your LAN | disk removal; **whole-machine theft away from home**. Clevis SSS `t=2` of tpm2 `{}` and Tang (`thp`-pinned). Initramfs networking: dracut systemd-networkd with `ip=dhcp rd.neednet=1`. The Tang URL must be http:// to a private IPv4 address. | an attacker who stays on your LAN with physical access |
| `tpm2` | yes | **disk removed or disposed of without its TPM/board** (TPM-bound, no PCR policy: clevis `tpm2 '{}'`) | whole-machine theft: the TPM unseals for any boot, and a modified initrd on unencrypted `/bootpart` can capture the key |
| `none` | yes | nothing | everything (prints a warning) |

- **No PCR policy (decided 2026-11-16).** PCR 7 adds no protection against these threats: booting any Microsoft- or Canonical-signed medium reproduces it, and `/bootpart`'s initrd is not measured. Disk removal is covered by TPM binding alone; whole-machine theft is covered only by Tang. PCR 7 also breaks unattended unlock after dbx, SBAT and Secure Boot updates on the shared ESP, so every generation fails at once. And clevis 20 defaults `pcr_bank` to sha1. **To revert:** bind with `{"pcr_bank":"sha256","pcr_ids":"7"}`. The v2 path stays UKI with a signed PCR 11 policy.
- **Recovery.** Copy `recovery.bin` off the box after first boot: `scp boxadmin@box:/bootpart/agentbox/recovery.bin .`. On your laptop, run `agentbox recovery decrypt --key recovery.key --in recovery.bin --out luks.key`. Type its 48 digits at the prompt, or run `cryptsetup open --key-file luks.key /dev/<root partition> croot` from rescue media.
- **Layout.** Curtin can't make btrfs subvolumes ✓ but honors mount options ✓. `late-commands`:
  0. Delete the subvolumes nested in the top level and recreate them as 0700 directories. systemd-container's tmpfiles `Q` lines create `var/lib/machines` and `var/lib/portables` there, because curtin's chroot root is the top level. Snapshots skip nested subvolumes, and firstboot's `rm --one-file-system` can't cross them.
  1. Snapshot the top level into `@gen-1` and create the persistent subvolumes, including `@var_lib_agentbox_data` (mounted at `/var/lib/agentbox/data`, §3.2).
  2. Move `/home`, `/var/log` and `/srv`.
  3. Mount ext4 at `/bootpart` and move gen-1's kernels into `/bootpart/agentbox/gens/gen-1/`.
  4. Write gen-1's fstab binds (`gens/gen-1`→`/boot`, `/bootpart/grub`→`/boot/grub`, ESP→`/boot/efi`).
  5. Write gen-1's boot policy: the GRUB defaults and cmdline, zram, the emergency/rescue reboot drop-ins, the watchdog config, the commit-deadline unit (§3.3), and the masks for `apt-daily.timer`, `apt-daily-upgrade.timer`, `nftables.service`, snapd (§3.3 Updates), `secureboot-db.service`, `grub2-common.service` and `grub-initrd-fallback.service` (§3.3 step 8). Purge `kdump-tools` (§3.3).
     - **Signed kernels only.** curtin purges the ISO's kernel image, but `linux-main-modules-zfs-K` still needs one, so apt pulls in `linux-image-unsigned-K`. shim refuses it under Secure Boot, and a trial of that kernel never boots. So late-commands install the signed `linux-image-K` for each unsigned one (the two Conflict). The gate checks that `is-not-revoked` accepts every installed kernel.
  6. Install `09_agentbox`. It lists generations oldest first, skips names outside `gen-<digits>` and kernel names outside `[0-9A-Za-z.+~_-]`, and maps `saved_entry` to GRUB's numeric `fallback` for one-shot trials.
  7. Mount gen-1 exactly as the booted system sees it. `/bootpart` is made `private` and the `dev proc sys run` rbinds `rslave` before use, so the final `umount -R /mnt/new` never propagates into the live installer or `/target`.
  8. Write `agentbox-gen-1-<kver>` to `/bootpart/agentbox/committed`. Run `update-grub`, check that `grub.cfg` has `--id 'agentbox-gen-1-<kver>'` (an unknown id silently boots entry 0), then `grub-editenv … saved_entry=agentbox-gen-1-<kver>`.
- **Swap.** No swapfile: `storage: {swap: {size: 0}}` ✓ (B3). `systemd-zram-generator` ✓ with `[zram0]`.
- **Firstboot, in order:**
  1. Clean the top level.
  2. Check the release's SHA-256 against the seed's pin, then verify it with minisign. The pin comes first: minisign alone accepts any older signed release.
  3. Install it with `install.sh --from-firstboot` to `/var/lib/agentbox/releases/<ver>/{bin/agentbox,systemd/}`. The release is staged, synced, then renamed into place, and `current` and `previous` switch by rename. Unit files are copied to `/etc/systemd/system`, because PID 1 loads units before `@var_lib_agentbox` is mounted. Every shipped unit with an `[Install]` section is enabled.
  4. Run `agentbox-reconcile`.
  5. Mark gen-1 last-good.
  6. Write `.firstboot-done`.
  - It runs from `RuntimeDirectory=agentbox-firstboot` (root-only, fresh on every start, removed when the unit stops) with `PrivateMounts=yes`, so the `subvolid=5` mount never leaks.
  - curl uses timeouts, 5 retries, `--proto-redir =https` and `--max-filesize 64M`: both files land in tmpfs `/run`, and `make release` refuses a bigger tarball. The unit has `TimeoutStartSec=45min`.
  - Every step is idempotent, so `install.sh --from-firstboot` MUST be safe to re-run.
  - On failure the unit retries every 60 s with no start limit (`Restart=on-failure`, `RestartSec=60`, `StartLimitIntervalSec=0`). A reboot retries too: the unit stays enabled until `.firstboot-done` exists.
  - The health check ships in the release, so it can't see this unit. Until `.firstboot-done` exists, a failing firstboot shows only in `systemctl status agentbox-firstboot` (`activating (auto-restart)`), `journalctl -u agentbox-firstboot` and the console.
  - **Built in weeks 1–2:** `make release`, `install.sh`, `agentbox-reconcile.service` and `agentbox os mark-last-good`.
    - The tarball is reproducible (sorted entries, fixed mtime, root:root), so anyone can recompute a seed's pin. One tarball carries linux/arm64 and linux/amd64; `install.sh` picks by `dpkg --print-architecture`. Versions match `[0-9A-Za-z][0-9A-Za-z._~-]{0,63}`.
    - `agentbox-reconcile.service` is `Type=oneshot` with `RemainAfterExit=yes` and no ordering beyond the defaults. It is never ordered `After=multi-user.target` or `agentbox-firstboot`, which would deadlock firstboot's nested start. `systemd-analyze verify` can't catch that hazard.

### 3.2 Persistence domains
| Domain | Location | Changes with the generation? |
|---|---|---|
| OS (`/`, `/etc`, `/usr`) | `@gen-N` | yes |
| `/boot` | `/bootpart/agentbox/gens/gen-N/`, bind-mounted | yes (Build rewrites each clone's fstab bind, §3.3) |
| GRUB files and ESP | `/bootpart/grub`, ESP | shared; updated only post-commit (§3.3) |
| Humans, logs, Tailscale, ntfy, app data | `@home`, `@var_log`, `@var_lib_tailscale`, `@var_lib_ntfy`, `@srv` | no |
| agentbox control state (releases, control, rootd.db, audit/ with taint.db) plus the nested fillable subvolumes `state/`, `memory/`, `cas/`, `git/` (each under qgroup `2/0`) | `@var_lib_agentbox` | no |
| agentbox fillable stores: workspaces, agent storage and session homes, Go module caches, images (`/var/lib/agentbox/data`) | `@var_lib_agentbox_data` | no |

- **Why two agentbox subvolumes.** Workspaces, agent storage, session homes and images live in `@var_lib_agentbox_data`. The other fillable stores (`state/` with state.db, `memory/`, `cas/`, `git/`) are nested subvolumes in `@var_lib_agentbox`. All of them sit under `2/0`, so a qgroup can cap them without starving the control state (§4.1). The seed creates both top-level subvolumes; the qgroup limits land in week 3.
- **`agentbox-reconcile`** runs before every agentbox unit. It rebuilds the OS-domain artifacts that agentbox manages from the persistent control store, including agent and app accounts, sub-id ranges, linger and `user@` drop-ins. So `agent.add/remove` take no OS lock: they write the control store, and reconcile re-applies them in whichever generation boots.
- **Other OS-domain changes are not carried.** Human `/etc` edits or manual `apt` runs on the running generation after the Build snapshot are lost at commit. While the OS lock is held, the login banner and `agentbox status` warn about this. A manual `apt` run before Build changes the dpkg status, so the `os.apply` gets `stale_base` (§3.3).
- **Service state across generations.** `@var_lib_ntfy` and `@var_lib_tailscale` persist, but the binaries that read them change with the generation. ntfy refuses a database whose schema is newer than its own ✓ (both `cache.db` and the ACL `user.db`). So a failed gen-M must not leave migrated state behind; §3.3 steps 5 and 6 snapshot and restore it.
- **Binaries.** Releases sit in `releases/<ver>/{bin/agentbox,systemd/}` with `current` and `previous` links. v5.3 has no release-update op: firstboot installs the only release. Any future release-update op must be A/B like `os.apply`: a health window, and on failure flip `current` back to `previous` and restore the pre-migration database copy.
- **Database.** Migrations are forward-only, with a pre-migration copy.
- **CAS.** `cas/` is its own nested subvolume inside `@var_lib_agentbox` (`agentbox os plan` creates it with `btrfs subvolume create`, and refuses while `cas/` is a plain directory), with a qgroup exclusive limit `budgets.toml: cas.max_bytes` (default 10% of the pool), assigned to the parent qgroup `2/0` (§4.1). Only rootd writes there. A full CAS fails new bindings (§5.2). It can't use the space that `audit/`, `taint.db` and `rootd.db` need.

### 3.3 A/B generations
`os.apply` covers package install and remove, updates, and system-unit enable/disable.

**As built in weeks 1–2.** `internal/rootd/gens` and `agentbox os plan|apply|health|mark-last-good|status` run the phases below, with these stand-ins until rootd lands:
- The approval is the plan's SHA-256. The plan is stored at `cas/debs/<sha256 of plan.json>/`, `--approve` must equal that hash, and nothing is re-resolved.
- `/var/lib/agentbox/os/pending.json` (with the build's boot id) plus a flock stand in for `os_lock`. `failed/gen-M.json` records each failed trial.
- `os plan` runs apt as root on the host, not in `osbuild-fetch@` (§2). There is no protected floor, binding admission or service-state snapshot yet.
- Every os command runs in a private mount namespace and binds `/bootpart` over itself non-recursively. `/bootpart` is a shared mount, so the booted `/boot/grub` and `/boot/efi` binds also appear inside `gens/<booted>/`; a recursive copy or delete there could reach the ESP.
- The nspawn runs with `SYSTEMD_NSPAWN_LOCK=0`: its image lock files would land on the btrfs top level, which must hold only `@*`. The os commands are serialized by the lock anyway.

Its phases:
1. **Plan (before approval).** `osbuild-fetch@` computes the exact transaction for the target (`apt-get -s` against a clone of the current generation's dpkg state).
   - It sizes the closure with `apt-get --print-uris` and an empty archive dir. This prints each `.deb`'s URI, size and hash from the signed index without fetching ✓. rootd applies binding admission (§5.2) to the summed size. Only then does `osbuild-fetch@` download with `--download-only` into `cas/debs/<plan-id>/`. apt verifies Release signatures.
   - rootd records the closure: every package, version and action from `apt-get -s` (`Inst`, `Remv`, `Purg`), plus each `.deb`'s SHA-256. It also records the base: `baseGen` (the running generation), `baseDpkg` (SHA-256 of that generation's `/var/lib/dpkg/status`) and the end state (the installed `package:arch=version` set after the transaction).
   - **Protected packages.** `registry.protectedPackages` is compiled into the release and covered by `floorVersion`: `linux-image-*`, `linux-modules-*`, `systemd*`, `udev`, `dracut*`, `grub*`, `shim*`, `cryptsetup*`, `clevis*`, `tpm2-tools`, `nftables`, `podman`, `crun`, `openssh-server`, `sudo`, `tailscale`, `minisign`, `kdump-tools`, `agentbox*`. Changing it needs a new agentbox release.
   - **Floor for every closure**, signed or not, checked per entry by package, action and origin. Origin is the suite plus the key that signed its `Release` file, not the label string, which any repo can set. For a protected package the floor rejects: `Remv` and `Purg` (except old kernels under (c) below); a downgrade (`dpkg --compare-versions`); and any origin outside the signed Ubuntu pockets `resolute`, `resolute-updates` and `resolute-security`. It also rejects a downgrade or removal of any `Essential: yes` package.
   - **`os.pkg.*` and `workbench.add_package`:** a protected package anywhere in the closure (install, remove, upgrade or downgrade) is rejected, even when signed.
   - **`os.update`:** protected packages may change only inside the signed update delta (see **Updates** below).
   - **H includes the closure, the hashes and the base.**
2. **Approve.** The human sees and signs the exact closure. The one exception is a nightly `os.update` closure that sits wholly inside the signed delta: the standing policy stands in for the per-closure signature.
3. **Build.**
   - **OS lock.** rootd takes its `os_lock` (a row in rootd.db, not a bus lease) and holds it across the reboot, until commit or fallback. Any `os.apply`, other `os.*` op or maintenance run that finds it held fails with `busy`; maint retries the next night.
   - **Base check.** The running generation must be `baseGen`, and its dpkg status must hash to `baseDpkg`. Otherwise rootd refuses with `stale_base` and never runs a re-resolved transaction. Under the standing `update` policy, maint re-plans on its own. Any other op becomes a new pending P that needs a new signature.
   - **Clone.** Take CUR from `rootflags=subvol=@gen-N` in `/proc/cmdline`. Snapshot `@CUR` → `@gen-M` and re-check `baseDpkg` on the clone. Copy the boot dir with `cp -a --one-file-system /bootpart/agentbox/gens/CUR/. /bootpart/agentbox/gens/gen-M/`. Copy from the per-generation dir, never from `/boot`: `/boot` has the `/boot/grub` and `/boot/efi` binds nested inside it.
   - **fstab.** Rewrite the `/boot` bind in `@gen-M/etc/fstab`: the one line whose mountpoint is `/boot` gets the source `/bootpart/agentbox/gens/gen-M`. The build fails unless exactly one line matched. rootd does this in Go (`internal/rootd/gens`), with a unit test on fixture fstabs. The bind gets no `nofail`. A wrong bind still boots: systemd creates a missing bind source, and a bind to another generation mounts. Health's `/boot` check and the commit deadline catch it.
   - **Apply.** Run `osbuild-apply@`: an nspawn with a fixed user-namespace range and id-mapped ownership, a private network, only the generation's `/boot` bound, and the approved `.deb`s bound read-only. It installs **only those files**:
     1. Recheck the bound `.deb` hashes.
     2. `apt-get -s install` with the exact `pkg=version` and `pkg-` list. Its action set must equal the bound closure.
     3. `apt-get install --no-download -o APT::Get::AutomaticRemove=false` with the same list. Never `--allow-downgrades` or `--allow-remove-essential`.
     4. The installed `package:arch=version` set from `dpkg-query -W` must equal the bound end state, or the build is discarded.
   - **Scaffolding.** Before apt runs, the build writes `/usr/sbin/policy-rc.d` (exit 101) to block service starts, and diverts `grub-install` and `update-grub` to no-op stubs with `dpkg-divert --local --rename --divert <path>.agentbox`. A trap removes all of it on every exit path. After the nspawn exits, the host fails the build unless all three hold in `@gen-M`: `dpkg-divert --root=<gen-M> --list` names neither file; `dpkg --root=<gen-M> --verify grub2-common` is clean (it ships both real files ✓); `/usr/sbin/policy-rc.d` is absent. A leftover diversion would make the next `update-grub` a no-op.
   - Kernel, systemd, cryptsetup and clevis updates rebuild the initrd in here, and dracut can't see any block device. `90-agentbox.conf` (from gen-1) forces the root dracut modules, the root disk's recorded storage drivers (`add_drivers`, loadable modules only: built-in drivers have no `initstate`) and the watchdog driver (`force_drivers`), and `x-initrd.attach` keeps `croot` (§3.1).
   - The build refuses any file name in `gens/gen-M/` outside `[0-9A-Za-z.+~_-]`.
   - Nothing touches the ESP or `/bootpart/grub`.
4. **Initrd gate (host, read-only).** For each `K` with a `vmlinuz-K` in `gens/gen-M/`, rootd runs `lsinitrd` on `initrd.img-K`:
   - `-f etc/crypttab` has a `croot ` line.
   - The file list has `clevis-luks-askpass`, `/systemd-cryptsetup`, `btrfs.ko` and each pin's `clevis-decrypt-*` binary: `tpm2`, plus `sss` and `tang` in `tpm2+tang` mode. `none` mode checks only `btrfs.ko`.
   - Every mode also checks each recorded `add_drivers` and `force_drivers` module, unless it is built into K (`modules.builtin`). A recorded driver that K lacks fails the gate, as does an unreadable `90-agentbox.conf` or `modules.builtin`. There is no `modules.alias` lookup, so a renamed driver fails too.
   - The gate doesn't check K's Secure Boot signature. §3.1's signed-kernel step keeps every installed kernel signed.
   - A missing `initrd.img-K` or any failed check discards gen-M and alerts. There is no `update-grub` and no reboot.
5. **Boot once.**
   - On the host, run `update-grub` (`09_agentbox` lists `agentbox-gen-M-K`, where K is gen-M's newest kernel). Here and below, rootd's `update-grub` is `grub-mkconfig` into `grub.cfg.agentbox-new`, `grub-script-check`, then the GRUB-safe replace (step 8): GRUB 2.14's own `update-grub` writes `grub.cfg` in place, so a cut could leave it empty. Abort unless `grep -qF -- "--id 'agentbox-gen-M-K'" /bootpart/grub/grub.cfg` finds the entry.
   - If the closure contains `ntfy` or `tailscale`, take `btrfs subvolume snapshot -r` of `@var_lib_ntfy` / `@var_lib_tailscale` into `@snapshots/<svc>-pre-gen-M`, just before the reboot. Other closures take no snapshot.
   - Set `next_entry=agentbox-gen-M-K` with a GRUB-safe grubenv write (step 8). If that write fails, read grubenv again: if `next_entry` names the trial, or grubenv can't be read, gen-M stays pending (the state a cut there leaves), and apply reports the error without rebooting.
   - Reboot now for approved ops, or at 04:00 for updates.
6. **Commit or fall back.**
   - **Commit only if gen-M really booted:** health OK within 15 minutes, `grep -qw rootflags=subvol=@gen-M /proc/cmdline`, and `uname -r` = K. Then, in order:
     1. Set `saved_entry=agentbox-gen-M-K` (GRUB-safe, step 8); `grub-editenv list` must then show it.
     2. Write the same id to `/bootpart/agentbox/committed` (temp file, fsync, rename) and run `update-grub`, so the empty-env fallback names gen-M.
     3. If the closure contained boot-chain packages, run the post-commit boot-chain step on the host (below).
     4. Delete the `pre-gen-M` service snapshots.
   - If any other generation booted, mark gen-M failed and alert. A failed trial re-asserts grubenv on the committed generation first: clear `next_entry` if it names gen-M, and set `saved_entry` back to the committed entry if it names gen-M (both GRUB-safe, step 8). Only then write `failed/gen-M.json` and drop the pending state, so a cut in between reruns this step. Why: GRUB reads `/bootpart` without replaying the ext4 journal, so a cut inside a grubenv replace can split it. GRUB then boots the old file while Linux, after journal replay, still sees the trial armed (`next_entry`) or made the default (`saved_entry`). A `saved_entry` left on a trial that can't boot would send every later boot to it, so the box would never settle on the committed generation. Re-asserting `saved_entry` means a split grubenv can't strand the box. The code does this since the power-cut fix (`Settle` in `internal/rootd/gens`), and the power-cut gate boots every split.
   - gen-M's number is never reused, and its leftovers are pruned at the next build start.
   - **Post-commit boot-chain step** (the documented non-A/B residual). With no PCR policy, shim and GRUB updates need no TPM reseal.
     1. Run `/usr/lib/shim/is-not-revoked` on every `/bootpart/agentbox/gens/*/vmlinuz-*`. shim-signed's postinst ran in the nspawn without efivars and checked only gen-M's `/boot`, so its shim choice is not trusted. With §3.1's signed-kernel step, every installed kernel passes today.
     2. If all retained kernels pass, select `shim<arch>.efi.signed.latest`; otherwise `.previous`, or retire that generation and audit it.
     3. Only then run the real `grub-install` and `update-grub`. Never write an ESP shim that revokes a retained rollback target.
   - **Fallback paths.** All are unattended (see **Unattended fallback** below).
     - A trial that fails inside GRUB falls back in the same boot, through 09_agentbox's numeric `fallback`.
     - After handoff to the kernel, `next_entry` is already consumed, so the next boot is the committed generation. That covers panics, initrd failures (LUKS prompt timeout, then dracut `rd.retry`, then `rd.emergency=reboot`), real-root emergency shells, a missed commit deadline, a failed health check and power loss.
   - **Service state on fallback.** When gen-N boots and gen-M is uncommitted, `agentbox-reconcile` (ordered `Before=ntfy.service tailscaled.service`) restores each `@snapshots/<svc>-pre-gen-M`. It moves the live subvolume to `@snapshots/<svc>-failed-gen-M`, puts a writable snapshot of the pre-gen-M copy in its place, and mounts it. Changes made during the failed boot are lost by design. A later `os.rollback{gen}` past a schema change doesn't restore service state; it shows up as a failed ntfy or tailscaled in health.
7. **Retention.** Keep current, previous and one more generation.
   - Never delete the generation named in `/proc/cmdline`, by `saved_entry` or by `/bootpart/agentbox/committed`.
   - Refuse and alert if the fstab of any kept generation still references `gens/gen-K`.
   - Delete `@gen-K` and `gens/gen-K` together, then run `update-grub`, so `grub.cfg` never lists a missing generation. If a prune or discard is cut in between, health's FixGrub runs `update-grub` once `grub.cfg` lists a kernel or initrd that is gone.
   - Then wait until Linux has dropped each deleted subvolume and removed its qgroup, and call rootd's `quota.check`. The drop's last step can mark qgroups inconsistent (§4.1). If rootd can't be reached, alert.
8. **grubenv writes.** agentbox never calls `grub-reboot` or `grub-set-default`. Both truncate `grubenv` in place (`grub-editenv` opens it with `"wb"`) ✓, so a power cut can leave it empty. GRUB then has no `default` and boots entry 0 ✓ (B8).
   - **GRUB-safe replace.** rootd writes `grubenv.new` (a copy, then `grub-editenv grubenv.new set next_entry=<id>` or `saved_entry=<id>`) and fsyncs it. It then checkpoints the ext4 journal (`EXT4_IOC_CHECKPOINT`, Linux 5.13), hard-links the old file to `grubenv.agentbox-old`, renames, fsyncs the directory, checkpoints again and removes the link. `grub.cfg` gets the same replace.
   - Why: GRUB reads ext4 without replaying the journal, so it sees each metadata block as it last reached its home location. fsync plus rename is atomic for Linux only. In the power-cut gate it once left GRUB a 0-byte `grub.cfg`, and the box stopped at `grub>`. The first checkpoint puts the new inode home before any directory entry names it. The link keeps the old inode and its blocks allocated until the rename is home. `hack/powercut.sh grub` checks this write by write.
   - Ubuntu's `grub2-common.service` and `grub-initrd-fallback.service` run `grub-editenv` at every boot, which rewrites grubenv in place, only to clear 10_linux's `recordfail` and `initrdfail`. 09_agentbox entries set neither, so gen-1 masks both units. GRUB's own boot-time `save_env` still rewrites the 1024-byte block in place; that is upstream behavior.
   - **Fallback.** `09_agentbox` reads `/bootpart/agentbox/committed` at `update-grub` time and emits `set default=<committed id>` when `saved_entry` is empty and this is not a one-shot boot. An empty or lost grubenv then boots the committed generation, not entry 0.
   - Generations are listed oldest first, so entry 0 is never the newest trial. This is the second safety net, and it is already in the template.

- **Unattended fallback.** Every generation carries all four. Nothing waits for console input.
  1. **LUKS prompt.** crypttab has `timeout=300s` (§3.1). If clevis can't unlock, systemd-cryptsetup gives up after 300 s and removes its ask-password file. dracut-initqueue then counts down `rd.retry` (default 180 s) ✓, and `rd.emergency=reboot` reboots. Worst case is about 8 minutes: the VM gate measures about 490 s from kernel start to the reboot. `rd.timeout=600` on the cmdline is the backstop for an initrd that can't find or mount root, which would otherwise wait forever. Keep the crypttab timeout plus `rd.retry` under 600 s, or `rd.timeout` fires first. A Tang outage hits every generation the same way, so the box reboots in a loop until unlock works again. This is accepted.
  2. **Real-root emergency and rescue.** `/etc/systemd/system/{emergency,rescue}.service.d/90-agentbox.conf` sets `FailureAction=reboot-force`, `SuccessAction=reboot-force` and `RuntimeMaxSec=120`. Ubuntu's root account is locked, so without this sulogin waits for Enter forever.
  3. **Commit deadline.** `agentbox-boot-deadline.service` (`DefaultDependencies=no`, `WantedBy=sysinit.target`) sleeps 900 s, then runs `systemctl reboot --force` unless the booted entry is committed: grubenv `saved_entry` equals `agentbox-<gen>-$(uname -r)`, with `<gen>` from `findmnt -no FSROOT /` with the leading `/@` stripped (`g=$(findmnt -no FSROOT /); g=${g#/@}`). The check is plain shell, so it works on gen-1 before firstboot installs the agentbox binary. It starts early in sysinit, so a unit that blocks boot can't stop it. It also accepts the entry named in `/bootpart/agentbox/committed`: an emptied grubenv boots the committed entry, and a `saved_entry` check alone would reboot it every 900 s.
  4. **Watchdog.** `/etc/systemd/system.conf.d/50-agentbox.conf` sets `RuntimeWatchdogSec=60s`. That needs a loaded watchdog driver. Ubuntu blacklists every watchdog module, softdog included (`/usr/lib/modprobe.d/blacklist_linux_*.conf`), and `systemd-modules-load` honors the blacklist, so `modules-load.d` can't load one. Instead the install detects the box's driver (the first device modalias that `modprobe -R` resolves to a `drivers/watchdog` module, else `softdog`) and writes it to `90-agentbox.conf` as `force_drivers`. dracut puts it in every initrd and loads it with plain modprobe, and every later generation inherits the config. The VM attaches `-device i6300esb` on amd64 only, so arm64 `virt` boots softdog. x86 detection (`iTCO_wdt`, Super I/O chips) is unit-tested only.
- **Updates.** Stock `unattended-upgrades` is disabled: gen-1 masks `apt-daily.timer` and `apt-daily-upgrade.timer` (gate-checked). The masks live in `/etc`, so every later generation keeps them. fwupd only refreshes metadata; firmware and dbx updates run only as an explicit op.
  - **snapd and friends (decided 2026-11-17).** gen-1 masks `snapd.socket`, `snapd.service`, `snapd.seeded.service`, `snapd.snap-repair.timer`, `lxd-installer.socket` and `secureboot-db.service`, and purges nothing. snapd and snap-repair change the box in place, and `lxd-installer` installs the lxd snap on first use. `secureboot-db` runs `sbkeysync` on db and dbx at every boot. Purging snapd also purges `ubuntu-server-minimal`, which leaves sudo, systemd and cloud-init to `apt autoremove`. fwupd stays stock: its timer only refreshes metadata, and firmware updates need `auth_admin`.
  - Not covered by any policy yet: `ua-timer`, `motd-news`, `apport-autoreport` and `update-notifier-download`. They contact the network but change no packages.
  - `os.update` is a separate op from `os.pkg.*`. `agentbox-maint.timer` plans it nightly; a human can also run it from the CLI. No agent can request it.
  - It runs without a per-closure signature only if the whole closure is inside the delta recorded by the signed `update.policy.set`. The delta allows:
    - (a) upgrades of already-installed packages, protected ones included, from `resolute`, `resolute-updates` and `resolute-security`, signed by the Ubuntu archive key;
    - (b) new packages only when they are `linux-*-<abi>` packages of the installed kernel flavor, or new `Depends` of a package upgraded under (a), from the same origins;
    - (c) removals only of `linux-*-<abi>` packages of kernels older than the two newest.
  - A nightly closure that removes or purges anything else becomes a pending P that needs a CLI signature.
  - rootd stores the digest of the signed policy. H includes `updatePolicyDigest`, and the execution re-check compares it. Every closure is audited.
- **Cmdline:** `panic=10 rd.emergency=reboot rd.shell=0 rd.timeout=600`, plus `ip=dhcp` / `rd.neednet=1` in `tpm2+tang` mode. In encrypted modes `09_agentbox` also adds `rd.luks.uuid=<LUKS UUID>`, read from the `croot` line of `/etc/crypttab`, so unlock never depends on a cmdline baked into the initrd (`hostonly_cmdline="no"`).
- **No kdump.** The seed sets `kernel-crash-dumps: {enabled: false}` ✓, and `late-commands` purges `kdump-tools`: its `grub.d` snippet adds `crashkernel=` even when disabled, and its crash initrd can't unlock the LUKS root. So there is no `crashkernel=` reservation and no `panic_on_oops=1`. A panic goes straight to `panic=10` and the fallback. Diagnostics come from pstore and the journal. `kdump-tools` is protected, so `os.apply` can't bring it back.
- **Health:** agentbox units, the firewall check (§6.1), default route and DNS, Tailscale and its serve config (§5.4), free space (pool free space at or above `budgets.toml: disk.reserve_bytes`, default 2 GiB; alert at 85% used; agentboxd pauses new task dispatch at 92%), and `/boot` bound to the running generation's own dir (`findmnt -n -o FSROOT /boot` = `/agentbox/gens/gen-M`).
  - An uncommitted generation falls back; a committed one only alerts.
  - The health unit runs from `agentbox-health.timer` every minute and has no `Requires=` on the units it checks, so a failed agentbox unit can't stop the check from running. It exits 0 while a trial is not yet healthy, because a failed health unit would block its own commit.
  - **Weeks 1–2 skeleton:** `is-system-running` is `running`; `/boot` is the generation's own dir; `/lib/modules/$(uname -r)` exists; at least 2 GiB free; an IPv4 default route. On the committed generation it also runs FixGrub (step 7).

## 4. Agent runtime
### 4.1 Accounts
`agent.add` is an admin op, executed by rootd. rootd's `ids` table (App. E) is the only allocator. Its rows are never deleted, so N only grows and ids are never reused.
- **Allocation:** `N = COALESCE(MAX(n),0)+1` for the kind, with N ≤ 999. rootd commits the row first, then writes `/etc/subuid` and `/etc/subgid`; reconcile repairs a crash in between. `app.deploy` allocates an app's M the same way on first deploy, and `app.remove` retires it.
- **User:** `ag-<name>`, uid/gid `70000+N`, `nologin`. Apps are `app-<M>`, uid/gid `71000+M`. App names are per owner: rootd's `ids` row has name `<agent>/<app>`, and a Tailscale Service is `svc:<agent>-<app>`. Agents name apps by `<app>` only, resolved inside the executor's namespace. M, app uids and ports never appear in agent-visible output (§5.6). Both are above `UID_MAX` and outside systemd's DynamicUser range 61184–65519 ✓. The account home is a root-owned, empty dir.
- **Sub-ids:** rootd writes them with `usermod --add-subuids/--add-subgids`, because `useradd` assigns none above `UID_MAX` ✓. They are derived from N or M, never read from agentboxd. Each block is 65536 wide and 65536-aligned, inside systemd's unused range 0x70000000–0x7FFDFFFF ✓, and outside nspawn's automatic pool (524288–1879048191) ✓:
  - agent N: `0x70000000 + N·0x10000`
  - app M: `0x74000000 + M·0x10000`, written when rootd creates `app-<m>`, before its first build
  - `--userns=keep-id` maps container ids 0–65535 to the block and the agent uid to itself ✓.
  - reconcile rewrites both files from `ids WHERE state='active'`. It refuses to start if any other entry overlaps either base.
  - **Every block lies inside the static nft confined set** (§6.1), so adding an agent or app never edits the firewall.
- **Linger plus a `user@<uid>` drop-in** (Appendix C):
  - root-owned `XDG_CONFIG_HOME` and `XDG_DATA_HOME`, with `storage.conf` pointing graphroot at `data/agents/<name>/storage`
  - `CONTAINERS_STORAGE_CONF` set to that `storage.conf`, and `CONTAINERS_STORAGE_CONF_OVERRIDE` unset: podman reads that one file and no `storage.conf.d` drop-in
  - `Requires=` and `After=` on `agentbox-firewall.service`, `agentbox-reconcile.service` and `agentbox-rootd.service`
  - `ExecStartPre=+agentbox fwcheck`
- **Podman 6 checklist.** Recheck these when the base moves past Podman 5.7:
  - Podman 6 reads `storage.conf.d` drop-ins from `/usr/share` and `/etc`, the per-UID `storage.rootless.conf.d/<uid>/` ones too. `CONTAINERS_STORAGE_CONF` keeps them out; `CONTAINERS_STORAGE_CONF_OVERRIDE` would still apply, so the drop-in unsets it.
  - Podman 6.0.0 fixes a reused pause-process PID. The pause check in §4.2 stays.
- **Subvolumes:** `data/workspaces/<name>`, `data/agents/<name>/storage`, `data/agents/<name>/session-home` (interactive only) and workspace snapshots. rootd creates all of them and assigns each to one qgroup `1/N` with an exclusive limit, before it holds data. The slice drop-in sets CPU, memory, IO and task limits. Also `data/cache/<name>` (owner `agentbox-proxy`, mode 0700; §6.2), made at `agent.add`. It is assigned to `1/N` and also gets its own exclusive limit, `cache.agent_max_bytes`; `budget.set` re-applies it. `data/cache` itself is root-owned, mode 0711.
- **Disk reserve.** Every store that agents or apps can fill sits under one parent qgroup `2/0`: each agent's `1/N`, plus the subvolumes `git/`, `cas/`, `data/images/`, `memory/`, `state/` and `@srv`.
  - Week 3 creates it: `btrfs quota enable` (full mode, no `-s`), `btrfs qgroup create 2/0 /`, `btrfs qgroup assign <child> 2/0 /`, `btrfs qgroup limit <limit> 2/0 /`.
  - The control state in `@var_lib_agentbox` (releases, control, `rootd.db`, `audit/` with `taint.db`) and the OS generations stay outside `2/0`, so they always keep the reserve.
  - The reserve is max(10%, 4 GiB) of the file system. `2/0`'s limit is what it references now plus the free space above the reserve, less 64 MiB of slack. So usage outside `2/0` (generations, logs, control state) comes out of `2/0`'s share, not out of the reserve. Reconcile sets the limit at boot, and rootd moves it on each consistent qgroup check (its 5-minute timer and `agentbox quota check`): when it is above that bound, or more than 128 MiB below the target. Once usage outside `2/0` has eaten the reserve, the limit is 1 byte and every write into `2/0` fails (#209).
  - Simple-quota auto-inherit is not used as a control. An unprivileged caller can pass `BTRFS_SUBVOL_QGROUP_INHERIT` with an empty list, and the kernel then skips auto-inherit ✓. Agents instead can't create subvolumes at all (§4.2, no btrfs ioctls).
  - Full mode, not simple quotas, because only full mode counts shared extents. The cost: when a dropped subvolume's shared subtree reaches `qgroup_drop_subtree_thres` (default 3), Linux 7.0 skips its accounting and marks qgroups inconsistent, and `2/0` then limits nothing. Simple quotas never get there. A snapshot into `1/N` marks qgroups inconsistent too, when `1/N` shares extents with a subvolume outside it. So rootd reads `/sys/fs/btrfs/<fsid>/qgroups/inconsistent` at start, on its 5-minute timer, after each snapshot it makes, and after each subvolume delete it makes, once `btrfs subvolume sync` returns (`agentbox quota check` runs it at once). A flag set after a task-start snapshot refuses that task with `BUSY` before it launches (#205). Generation deletes count too: on a stock box, Linux marks qgroups inconsistent when it removes a pruned generation's qgroup, which still counts bytes, seconds after `btrfs subvolume delete` and possibly after `btrfs subvolume sync` returns. So after a prune or a discarded build, `agentbox os` waits until each deleted generation's `qgroups/0_<id>` is gone, then calls `quota.check` (§3.3 step 7, #209). On `1` it fences the `2/0` writers: it freezes every agent's user slice (user manager, tasks, attach) and refuses `task.new`, `task.start`, `task.undo`, `agent.attach` and every non-read task op with `BUSY`. It sends one ALERT to auditd and ntfy, runs `btrfs quota rescan -w` (`-W` only waits for a running one), and thaws only once the rescan succeeds and the flag reads `0`. A failed rescan keeps the fence until the next check (#79).
- **No nested subvolumes.** Snapshots are not recursive, so a nested subvolume would be missing from snapshots and review diffs. Before `workspace.snapshot`, `workspace.restore`, `taint.clear` and removal, rootd runs `btrfs subvolume list -o` on each agent subvolume. If anything is nested, it refuses with `NESTED_SUBVOLUME` and taints the workspace. It never deletes recursively. rootd's hourly sweep also runs `btrfs subvolume list -o` on each `data/cache/<name>` and alerts on any hit. The service filter (§2) should make that impossible.
- **Removal:** stop tasks → `loginctl terminate-user` → stop `user@` → kill the uid → revoke sockets → delete the user → `cache.purge{agent}`, then delete `data/cache/<name>` by name from the root-owned `data/cache` dirfd (public module files only; not archived) → archive the subvolumes → retire the id (`ids.state='retired'`; the row and its sub-id range stay reserved, because archived storage still owns files in that range).

### 4.2 Tasks
- **Provenance belongs to rootd.** agentboxd calls rootd `task.start{agent, origin}` and never supplies a chain or trace. rootd writes the result to `task_registry` (App. E):
  - `origin: parent:<task>`. The parent must be a live registry task, and rootd's `delegations` row for the child (written at `bus.task.send`, or at a `skills:` claim, §7) must name this agent as executor. rootd sets chain := parent.chain ++ [agent:<agent>] and trace := parent.trace. In the same call it registers taint(child) := effective taint of the parent (§5.2) with auditd, and waits for the ACK. A missing parent row fails `task.start`.
  - `origin: admin:<request>`. This must be an unused request that a human made on `rootd-admin.sock` with `agentbox task new`. rootd records the request id, the human and the agent, then passes the request to agentboxd. rootd sets chain := [human:<name>, agent:<agent>] and mints a new trace.
  - Any other start (onfailure triage, or any task with no parent and no human request) gets `origin: daemon`. rootd registers it tainted, so every non-read, non-Safe op it submits needs a signature.
  - **Ask budget** (rootd, per task; §5.4). Each ask, single or `ask.batch`, uses 1 of the task's budget when its row is created.

    | Task origin | Budget | Set by |
    |---|---|---|
    | admin (`agentbox task new`) | `--asks N`, 0 to 10; default `ask.per_task` = 3 | the human, on `rootd-admin.sock` |
    | daemon | `ask.per_daemon_task` = 1, inside the box-wide `ask.daemon_per_day` = 5 | rootd |
    | parent, `to:` routing | the `asks: k` grant in `bus.task.send` (default 0), moved from the parent's budget in the same transaction and never returned | the parent |
    | parent, `skills:` claim | 0 | fixed |

    `budget.set` can raise a live task's budget, up to 10. `task_registry` keeps `asks_budget`, `asks_used`, `asks_granted`, `asks_created`, `quote_items` and `quote_deny`; `trace_quota` keeps the per-trace sums (App. E). `agentbox task show <id>` shows the task's asks with their final states and their fine reasons (`always`, `tainted`, `tainted_commits`, `remote_not_private`, `no_push_policy`, `spend`, `review`), the task and trace quote counters, cap denials, and the witness lines (§5.6). It reads rootd and audit, never agentboxd. Agents see only the coarse reasons (§5.6).
  - rootd doesn't verify the prompt (§5.2 compromise bound).
- **Dispatch.** agentboxd picks agent, task, prompt and origin, then calls rootd `task.start`. rootd:
  1. Registers `task↔agent↔uid↔trace` with gate, proxy, keys, git and auditd over their `svc-*` sockets, and records the rw workspace mount in auditd's `writers` table (§5.2).
  2. Creates each per-task socket dir (§2.1) and has each service bind its socket there. rootd also creates `/run/agentbox-witness/t/<task>/` holding a FIFO named `witness`. It keeps the read end open and buffers at most 64 KiB (§5.6). After a restart it reopens the FIFOs of `task.list_live`.
  3. Launches the container (Appendix C):
     - **Pause check, before every launch and attach.** Rootless podman keeps the agent's user namespace in a pause process named by `/run/user/<uid>/libpod/tmp/pause.pid`. rootd opens that file through no-follow dirfds. The PID must be alive, owned by the agent uid, in the agent's user namespace (uid 0 is the agent, 1–65536 its sub-id block), and in its user manager outside every task unit. Otherwise rootd removes the file and sends PAUSE_PID_STALE to auditd. Without a live pause process, rootd runs one podman call through the user manager first, so the new pause process lands there. A pause process made by a task's podman would sit in the task unit, and the task's stop would kill it. Podman 5.7 joins whatever process has a reused PID, and every podman call then fails with `cannot set user namespace` (`task.start` reason `podman_userns`).
     - `systemd-run --user -M ag-<name>@ --unit=agentbox-task-<id> --collect -p Delegate=yes -p KillMode=mixed -p TimeoutStopSec=15 -p RuntimeMaxSec=<deadline − now> -p 'ExecStopPost=-/usr/bin/podman rm -f -i -t 0 task-<id>' podman run --cgroups=split --rm --name task-<id>`
     - **Why `--cgroups=split`:** without it, rootless podman parents the container payload to `user.slice/libpod-<id>.scope`, outside the unit ✓. Unit stop, `RuntimeMaxSec` and `cgroup.kill` then reach only the podman CLI. conmon already stays in the unit, because systemd sets `INVOCATION_ID` ✓. With split plus `Delegate=yes`, conmon and the payload both sit in sub-cgroups of the unit, the same as Quadlet ✓.
     - `--network=none`, `--userns=keep-id`, `no-new-privileges`, `--cap-drop=all`, `--read-only`, `--security-opt=seccomp=/var/lib/agentbox/control/seccomp-task.json` (no btrfs ioctls, below)
     - `--tmpfs /tmp`, **`--mount type=tmpfs,destination=/home/agent,tmpfs-size=4g,tmpfs-mode=0700,U=true`** (ephemeral HOME, owned by the agent uid ✓), `--pids-limit`, `--log-driver=none`
     - mounts: the workspace, the four socket dirs, read-only `/opt/agentbox/exports`, the read-only binary
  4. **Uses the user bus only for this launch.** For `-M ag-<name>@`, sd-bus runs `systemd-run -M .host … -pPAMName=login systemd-stdio-bridge` ✓, so each call opens one PAM `login` session for the agent uid. rootd makes exactly one such call per task, never one per status or stop.
     - **Status:** rootd watches the unit's `cgroup.events` under `user@<uid>.service/app.slice/` with inotify. `populated 0` means the task exited. The task result comes from `taskrun`, not from the unit.
     - **Stop:** rootd writes `1` to that unit's `cgroup.kill` (below).
     - PAM `login` skips `pam_motd` for agent users (Appendix C), so a launch never runs `/etc/update-motd.d/*`.
- **Inside the container.** `agentbox taskrun` (PID 1):
  1. Copies the generated CLI configs (settings, MCP config, instructions import) from the read-only exports into the tmpfs HOME.
  2. Starts the forwarders on `127.0.0.1:8080` (egress, a CONNECT relay), `:8081` (LLM) and `:8082` (git); the last two are reverse proxies. When rootd set the cache `GOPROXY`, taskrun also starts the Go module filter on `:8083` (§6.2). Each forwarder reads the broker's response head: a response with an `Agentbox-Denial` header goes to `$HOME/.agentbox/denials.jsonl` (a 64-entry ring) and to the witness (§5.6). If a broker socket is missing or refuses, the forwarder retries for 5 s, then answers 503 `BROKER_UNAVAILABLE` in that channel's format.
  3. Fetches the task and probes its own boundary before the CLI starts: only `lo` in `/sys/class/net`; no default route (IPv4 or IPv6); a UDP connect to a public IPv4 and IPv6 address gives `ENETUNREACH`; `resolv.conf` names only `127.0.0.1`; no `/run/agentbox-*` dir (the host's per-task socket dirs) and no mount from another task's socket dir; no abstract socket bound in the task's network namespace (abstract names are per netns, so one there means another netns's sockets, a broker's included, are reachable). Any failure stops the task with `TASK_ISOLATION_PROBE`: taskrun posts the failed check in its result, agentboxd passes it to rootd with `task.stop`, and rootd writes an `ALERT` to auditd and sends an ntfy alert. The probe takes a few ms.
  4. Runs the CLI with **the prompt on stdin**:
     - `claude -p --output-format json --dangerously-skip-permissions --setting-sources user --strict-mcp-config --settings /opt/agentbox/exports/claude-settings.json --mcp-config /opt/agentbox/exports/mcp.json` ✓. `claude-settings.json` sets `"disableAllHooks": true`, as `claude-settings-attach.json` already does. This ignores project settings and `.mcp.json`; `disableAllHooks` stops project, local and skill hooks.
       - **No `--bare`** (#120). Bare mode skips `CLAUDE.md` discovery, so `INSTRUCTIONS.md` would stop reaching the model without an error. It also limits the tools to Bash, Read and Edit, and `--tools` can't widen that (checked on 2.1.330). Discovery stays on. `hack/cli-gate.sh` puts a canary line in `INSTRUCTIONS.md` and checks that it reaches the recorded model request and that the tool list is the pinned set. A unit test ties every gate's Claude Code pin to it, so each version bump runs that gate. This catches a release that makes bare the `-p` default.
     - `codex exec --json --dangerously-bypass-approvals-and-sandbox -C /workspace/<p> -` ✓
     - No opencode (#77). opencode 1.19.6 has no managed policy for plugins or MCP servers (its policies take only `provider.use`). A workspace `opencode.json` plugin still runs with `OPENCODE_DISABLE_PROJECT_CONFIG=1`, and every writable config dir gets a background `npm install`. agentboxd refuses `--cli opencode`.
     - **System policy files** (#77), root-owned in the image's read-only `/etc`. User, project, flag and `-c` config can't override them, so a CLI run by hand in a task obeys them too:
       - `/etc/claude-code/managed-settings.json`: `allowManagedHooksOnly`, `allowManagedMcpServersOnly` with an empty `allowedMcpServers`, `allowManagedPermissionRulesOnly`, `disableAllHooks`, an empty `strictKnownMarketplaces`, and `WebSearch` denied (it runs on the provider's side, outside the proxy). No `managed-mcp.json`: with one, Claude exits on `--strict-mcp-config` and `--mcp-config`. The empty managed allowlist blocks every server instead, `.mcp.json`'s and a subagent's `mcpServers` included. The flags stay.
       - `/etc/codex/requirements.toml`: `allowed_web_search_modes = []` (only `disabled`), `allow_managed_hooks_only` and `[features] hooks = false`, so no hook runs even with `--dangerously-bypass-hook-trust`. Also `plugins = false` (the curated plugin sync fetches github.com and chatgpt.com), no update check and no feedback. The generated Codex config sets the same, plus `web_search = "disabled"`.
       - Attach sessions run the same image. rootd binds the attach settings over the managed file, and they carry the same keys. attach refuses `--dangerously-bypass-hook-trust` and `--trust` in the admin's extra arguments.
     - **Quiet CLIs** (#121). rootd sets `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, `DISABLE_UPDATES=1` and `CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL=1` (the first doesn't cover the marketplace). The Codex config turns off the update check, analytics, feedback and OpenTelemetry export. Claude gets `ANTHROPIC_BASE_URL=http://127.0.0.1:8081/anthropic`, and Codex a `model_providers.agentbox` at `…/openai/v1` (§4.3). A no-op task of each CLI opens no CONNECT, and the keys broker sees only model API requests.
  5. Posts the result, idempotently keyed by task id. Every gate call, including the fetch and the result post, retries on `ECONNREFUSED` or `ENOENT` with capped backoff (1 s to 30 s) until 60 s before `RuntimeMaxSec`. Then taskrun exits non-zero. The result carries `denials`: the last 20 log entries. taskrun then writes `END <sha256 of the posted result>` to the witness.
  - Limits: `RuntimeMaxSec` = deadline − now (2 h for a top-level task, less for a child, §7); 50 MB output cap. On timeout, systemd sends SIGTERM to the podman CLI, waits `TimeoutStopSec`, then SIGKILLs everything left in the unit cgroup, payload included.
- **No DNS, fast failure.** Tasks run with `--dns=none`. The image's `/etc/resolv.conf` is `nameserver 127.0.0.1` with `options timeout:1 attempts:1`, and nothing listens on port 53, so a direct lookup fails in under 1 s. A task's own `connect()` gets `ENETUNREACH` at once (`Network=none`). taskrun exports `HTTPS_PROXY` and `https_proxy` = `http://127.0.0.1:8080`, and `NO_PROXY` and `no_proxy` = `127.0.0.1,localhost,::1`. `HTTP_PROXY` and `ALL_PROXY` are never set.
- **In-task CLI.** `agentbox why [<CODE> | --errno <E>]` prints the task's recent denials or fixed guidance, with no gate call. `agentbox ask wait <id> [--max 600s]` loops `ask.status{id, waitMs: 25000}`. Exit codes: 0 executed, 75 still open, 77 any other final state. Every gate reply passes the §5.6 in-task check before any tool or model sees it.
- **Stop.** rootd op `task.stop{task, reason}`, where reason is one of `completed`, `failed`, `canceled`, `timeout`, `deadline`, `parent_stopped`.
  - **What it is.** An internal op, like `task.start`. It is not in the registry and not Cedar-gated. It only removes capability, so the worst a caller can do is end a task early.
  - **Who calls it:** agentboxd, on `bus.task.cancel` and every terminal transition; humans, via `rootd-admin.sock` (`agentbox task stop`); rootd itself, on unit exit, `RuntimeMaxSec` expiry or deadline.
  - **Steps,** in order, each idempotent:
    1. Write `1` to `<unit cgroup>/cgroup.kill`. It is recursive, so it reaches the payload sub-cgroup. A missing cgroup (unit already collected) counts as done.
    2. Poll `cgroup.events` until `populated 0`, with a 10 s deadline. On timeout, fail closed: block the agent from further dispatch and alert. rootd records each such task in `task_leftover`, and `agentbox attach rescan` lifts the block only once every recorded task's cgroup is empty or gone. Once the cgroup is empty, drain the witness, run the §5.6 witness check, and send WITNESS and any GATE_MISMATCH to auditd without waiting for the ACK.
    3. Run `podman rm -f -i task-<id>` as the agent user. It backs up the unit's `ExecStopPost`.
    4. Revoke the task's sockets (§2.1) and remove the witness dir.
    5. `UPDATE task_registry SET ended_at=:now_ms, end_reason=:reason WHERE task=:t AND ended_at IS NULL`, and expire the task's `delegations` rows. The step 2 block goes in the same transaction. If it fails, the row stays live and `task.stop` returns `ok:false`.
    6. If reason ≠ `completed`: `UPDATE pending SET state='denied' WHERE task=:t AND state IN ('pending','approved')`.
    7. Recurse over `SELECT task FROM task_registry WHERE parent=:t AND ended_at IS NULL` with reason `parent_stopped`.
  - **auditd.** These steps never wait for an auditd ACK (§9).
  - **Start check.** `task.start` refuses a task whose parent has `ended_at` set, or whose deadline has passed.
  - **During a launch.** `task.start` holds the task's stop lock from its registry insert to the end of the launch. A `task.stop` that arrives then waits, and then kills what the launch started.
  - **agentboxd, after rootd returns:** `DELETE FROM leases WHERE holder_task=:t`, then cancel the children's bus rows (§7).
  - Container, HOME and sockets are then gone, so **hooks, settings or MCP configs a task writes outside the workspace cannot reach the next task** (workspace control files: below), and no process of the old task can still write to the workspace.
- **One cache: Go modules, read-only to tasks** (§6.2). rootd sets the Go env at `task.start` from the agent's allowlist (App. C). With `proxy.golang.org:443` on it: `GOPROXY=http://127.0.0.1:8083,https://proxy.golang.org,direct` and `GOSUMDB=sum.golang.org`. Without it: `GOPROXY=off`, so go fails at once with its own error and opens no CONNECT. `GOTOOLCHAIN=local` is always set, so go stays on the image Go unless the agent sets `GOTOOLCHAIN=auto` itself (that download then taints like any fetch). `GOPRIVATE` comes from the admin's `go.private` patterns, if set. taskrun unsets `GOFLAGS`, `GONOSUMDB`, `GONOPROXY` and `GOINSECURE` before the CLI starts, so only the admin scopes private paths. It doesn't set `GOFLAGS=-mod=readonly`: an explicit `-mod` makes go ignore `vendor/` ✓, and build commands already never resolve an unpinned version ✓. `GOMODCACHE` and `GOCACHE` stay in the tmpfs HOME. No other cache is shared between tasks in v1: not npm, pip, cargo or mise, and no build cache. Tools are baked into the image.
- **Quiet package managers.** taskrun sets `npm_config_audit=false`, `npm_config_fund=false`, `npm_config_update_notifier=false`, `NO_UPDATE_NOTIFIER=1` and `PIP_DISABLE_PIP_VERSION_CHECK=1`. With a fresh HOME these checks would run, and taint the task, in every task.
- These variables are defaults, not controls. An override either reaches the network through CONNECT and taints, or trusts cache bytes inside a task that the filter and the proxy have already tainted. Nothing outlives the task: `go env -w` writes to the tmpfs HOME, and rootd sets the env again at each launch.
- Attach sessions don't use the Go module cache. session-home keeps its own `GOMODCACHE`, and a persistent HOME could turn checksum checks off for later sessions.
- **No btrfs ioctls.** `/workspace` is a writable btrfs bind mount, and podman's default seccomp profile allows every `ioctl` ✓. Subvolume creation needs only write access to the parent dir. So a task could make a subvolume outside `1/N`, or one that snapshots skip. Tasks, attach sessions and app pods all run with `seccomp-task.json`, which agentbox generates at build time from containers/common `pkg/seccomp/seccomp.json`:
  - Remove `ioctl` from the unconditional allow list. libseccomp drops a conditional rule when an unconditional rule exists for the same syscall ✓, so just appending a deny rule would do nothing.
  - Allow `ioctl` when any bit of the type byte (cmd bits 8–15) differs from `0x94` (`BTRFS_IOCTL_MAGIC`): eight `SCMP_CMP_MASKED_EQ` rules on arg 1, one per bit.
  - Return `EOPNOTSUPP` (95) when the type byte is `0x94`: one `MASKED_EQ` rule with mask `0xff00` and value `0x9400`. This covers all subvolume, snapshot and setflags ioctls.
  - The masks cover only bits 8–15, so setting the high 32 bits (which the kernel truncates) can't move a call to another rule.
  - `FICLONE` is in the `0x94` family too. `EOPNOTSUPP` is what it returns on ext4, so `cp --reflink=auto` falls back to a plain copy.
  - `copy_file_range` gets `ENOSYS`. Within one btrfs it is a reflink too, and the task's bind mounts (the agentbox binary, the host `/usr` dirs) sit on the same file system, outside `1/N`. A workspace file sharing their extents makes the next snapshot into `1/N` mark qgroups inconsistent (§4.1, #205). `cp`, Go and Python copy the bytes instead.
  - A unit test checks that there is no unconditional `ioctl` rule, and that every 16-bit cmd, with and without high bits set, matches exactly one rule.
- **Only the sockets and processes tasks need.** The same profile starts from a pinned upstream copy (container-libs commit `dadba8b` or later, checked by sha256), never the distro's file:
  - `socket` is allowed only for `AF_UNIX`, `AF_INET`, `AF_INET6`, and `AF_NETLINK` with `NETLINK_ROUTE`; `socketpair` only for `AF_UNIX`. Every rule compares the low 32 bits (`MASKED_EQ` with `0xffffffff`), so high bits can't move a call off its rule. Any other family, `AF_ALG` and `AF_VSOCK` included, gets the default `ENOSYS`.
  - `clone` is allowed only with every `CLONE_NEW*` bit clear, and `unshare` the same (with `CLONE_NEWTIME`); a `CLONE_NEW*` bit gets `EPERM`. `setns` gets `EPERM`. `clone3` gets `ENOSYS`, so glibc and Go fall back to `clone`.
- **Workspace control files can't steer later tasks.**
  - Git runs with command-line-precedence config from the environment (`GIT_CONFIG_COUNT`/`KEY`/`VALUE`): `core.hooksPath=/opt/agentbox/exports/nohooks`, `core.fsmonitor=false`. Repo-local `.git/config` can't re-enable hooks.
  - Claude ignores project settings and MCP config (flags above), and Codex runs with a generated `CODEX_HOME` in the tmpfs HOME. The system policy files (above) hold even without the flags.
  - Instruction files in the repo (`CLAUDE.md`, `AGENTS.md`) can still be read, but they are covered by **live workspace taint** (§5.2): any task or session that mounts a tainted workspace is tainted, including one that is already running.
  - Workspace skills under `.claude/` and Codex's `.agents/skills` still load inside the next task, but their hooks do not run (`disableAllHooks`, and Codex's hooks off, above). The skill text is covered the same way as instruction files: both dirs are control paths, and the workspace taint makes the next task tainted.
  - `agentbox taint review` lists changed control paths first, and clearing them needs an explicit acknowledgement. The clear is bound to the reviewed snapshot (§7). The control paths (`internal/controlpaths`), at any depth:
    - CLI config and instructions: `.claude/`, `.codex/`, `.agents/`, `.opencode/`, `.mcp.json`, `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `AGENTS.override.md`, `opencode.json`, `opencode.jsonc`.
    - Files a trusted host component runs or loads (#123): `.git` (a dir, a gitdir file or a symlink) and the git dir it leads to, `.envrc`, `.devcontainer/`, `.vscode/`, `.idea/`, `.zed/`. A git dir's objects, logs and refs are not, but a git dir planted inside them is one, with its own config (#199, #207). So is a bare repo whose objects and refs are in the dir its `commondir` names. A `.git` or `commondir` file is read as git reads it, up to git's 1 MiB limit for a `.git` file. One that can't be read in full, or whose path git and other readers could take differently (a space at either end, a NUL, a second line), refuses the attach (#206).
    - A venv, found by its `pyvenv.cfg` whatever its name: that file, its `bin/` and every `.pth` file in it (python runs their import lines at startup).
    - What a control path leads to (#202, #210): the target of a symlink at or under one and each symlink on the way, and each file a control-path instruction file imports with `@path`, followed again from there. Paths resolve as the session's kernel resolves them, and an import also as Node's `path.resolve` would, from the file's dir, the dir of each link that leads to it and the session's working dir. A gitdir or commondir path resolves as git's does (#201). One that leads into session-home, `/proc` or `/dev` refuses the attach: what is there is not known, or changes per process.
- **Interactive sessions.** `agent.attach` (admin) mounts `session-home`, persistent and possibly holding subscription logins. It is **never mounted into automated tasks**. The workspace is agent-writable, so attach gets the same control-file lockdown as tasks:
  - Claude starts as `claude --setting-sources user --strict-mcp-config --settings /opt/agentbox/exports/claude-settings-attach.json`. That file sets `"disableAllHooks": true`, which takes precedence over project and local settings ✓. Project hooks and `.mcp.json` servers don't run, even if session-home's `~/.claude.json` already trusts the workspace.
  - rootd bind-mounts the generated user settings read-only over session-home's `~/.claude/settings.json`, so a session can't persist hooks into session-home.
  - The attach env carries the same `GIT_CONFIG_*` as tasks. This also covers git run by the human in the attach shell.
  - Codex runs with a rootd-generated `CODEX_HOME` config with no `[projects]` `trust_level` entries. Only `auth.json` comes from session-home. The `CODEX_HOME` dir itself is in session-home, so what Codex writes counts against the agent's quota and not the control-state reserve (#210); rootd removes it before and after each session.
  - rootd refuses `agent.attach` while the workspace has changed control paths since the last reviewed snapshot. The refusal lists them with a digest of the list and each path's state, and the admin passes `--ack-control-changes=<digest>` after viewing it (#210): a change made after the refusal makes a new digest, so the ack never accepts more than was shown. This gate also covers `.git/config` keys the env doesn't override (`core.pager`, filters, aliases).
  - The agent picks those names, so rootd quotes each one with Go's `strconv.QuoteToASCII` in the refusal and in `attach status`. A name can't send terminal controls or pass for two entries. In walk and scan errors rootd escapes each terminal control. The CLI escapes any other non-printable rune in an error or reply it prints. One walk records at most 50,000 control paths or 32 MiB; past that the attach is refused. rootd keeps at most 8 MiB of an agent's session-home token versions; past that every token scan counts as failed, and the block stays.
  - Session-home's control paths share that baseline (#153, #200): the CLIs' user instruction files, skills and plugins, and what the shells and tools in a session read at startup and can run code from: bash's startup files (Claude's Bash tool sources `~/.bashrc`, Codex runs a login shell), readline's, vim's, nano's, less's, tmux's and screen's config, the python user site, node's home module dirs, `~/bin`, `~/.ssh`, `~/.config/git/attributes` and `~/.config/go/env`.
  - rootd also refuses `agent.attach` while the dependency report (§7) for the same snapshot pair has high-risk items. The admin can pass `--ack-dependency-changes` after viewing them. Routine dependency changes never block attach. `--ack-control-changes` doesn't pass this gate, and `--ack-dependency-changes` doesn't pass the control-path gate.
  - Instruction files can still steer the CLI into reading the token. After attach ends, and before the next task may start, rootd scans the workspace diff since attach start, and the bodies of facts the session wrote to `agent/<self>` during the attach (agentboxd returns them over a read-only call), for the session-home OAuth access and refresh token strings. A hit blocks tasks on that workspace and alerts via ntfy.
  - Session output is tainted, like any other source, so an attach also taints `workspace:<agent>` (§5.2).
  - A `memory.write` or `memory.forget` from an `agent.attach` session is never workspace-bound. It follows the v5.2 quarantine path (§8), because session-home holds subscription credentials.
  - **Output filter.** rootd owns the session PTY and relays its output to the CLI as bytes through a filter. The filter drops OSC strings (including OSC 52 clipboard writes), DCS, APC, PM and SOS strings, 8-bit C1 controls, and CSI report requests (`c`, `n`, `t`) whose replies would be injected as input. Other CSI passes, so TUIs still work.
- **Image.** Built by `osbuild-image@` from a pinned `ubuntu:26.04` digest. It is saved as a digest tarball and loaded per agent user with `podman load`. AppArmor userns profiles for podman, crun and rootlesskit ✓. There is no apt inside. `workbench.add_package` is an `os`-class op: closure plus hashes, then an image rebuild.

### 4.3 Credentials
| Credential | Where | Used by |
|---|---|---|
| LLM API keys (brokered, default) | `agentbox-keys` only. Tasks get `ANTHROPIC_BASE_URL=http://127.0.0.1:8081/anthropic` with a placeholder key, and Codex gets `model_providers.agentbox.base_url=…/openai/v1`. | all tasks |
| Subscription OAuth | `session-home` only | interactive sessions only (`taskrun` refuses it). Workspace hooks, MCP servers and git hooks never run in attach (§4.2). A session can't persist this token into memory as a readable fact: session `memory.write` is quarantined (§8), so no later task reads it, and a human sees it at review. |
| GitHub token | `agentbox-git` only: a fine-grained token (or a GitHub App installation) scoped to exactly the repos in `remotes` | `gh.*` registry ops and git transport. **No PAT or GitHub credential in any task.** `github-mcp-server` is not bundled. |

## 5. Control plane
### 5.1 Operation registry
`internal/ops/registry.go` declares each op once: name, JSON schema, Cedar action and group, resource builder, floor class, **immutable-input binder** (which IDs and hashes go into H), signature requirement, rollback coverage, the **`reversible` flag** (the only input to phone eligibility, §5.4), the **`taintsOutput` flag** for reads (§5.3), the **`workspaceBindable` flag** (§8), and a **per-field audit class** for args and outputs (`keep`, `hash` or `drop`; §9).
- **Generated from it:** the Cedar actions (with parent groups, passed to every `Authorize`), JSON schemas, MCP tools, the per-op audit schema and the docs table.
- **Denial codes.** The registry declares the codes table (§5.6). Each code has: `next` per `what`, enforcers, HTTP status, a message template, agent-visible slots with grammars, and a static remedy. Generated from it: the Go constants (`ops.Code` is the only type `ops.Deny` accepts), `gen/denial.v1.json`, the `agentbox why` text, the docs table and the DENY audit schema. The in-task binary compiles the same tables. CI diffs `gen/codes.golden`: codes are append-only and never renamed.
- Each op declares the codes it can return, its `matchKey` fields (§5.4), its resolution kind (owner-scoped or shared, §5.2), whether it reaches rootd, and for each output whether agentbox or the remote generated it (`ask.status` returns only agentbox-generated outputs, §5.3). Each generated MCP tool description starts with one ask-cost line: `Never asks a human.`, `Asks (1 of your task's ask budget) when this task is tainted or policy requires; CLI or phone.`, or `Always asks (1 of your task's ask budget); laptop CLI only.` `repo.push` reads: `Asks unless a standing push policy covers this private remote and the task is clean; CLI only. Send it with its PR as one ask.batch.`
- **Ids.** Bus task, message, fact, pending, snapshot and denial ids are `<kind>_<ULID>`, from `crypto/rand`.
- **Startup check.** agentboxd and rootd verify that the registry and the generated Cedar schema, JSON schemas and MCP tools match one to one, plus golden tests, and refuse to start on mismatch. Codes match one to one across the table, the constants and the schema. Each `NEEDS_SIGNATURE` channel equals the op's `reversible` flag. An op that returns an undeclared code fails the golden test.
  - The golden set includes 2-agent and 3-agent chains. The child gets Run for own-app `app.logs` and `app.restart`, own `memory.read` and own `bus.inbox.read`. A tainted `file.write` by the child gets Ask. An ancestor-only resource gets Deny. A tainted own-scope `memory.write` by a child task with W tainted gets Run (bound); the same write by an attach session gets quarantine (0 bound rows). With `tainted=true`, every op's floor and Cedar outcome is the same for `workspaceBound` true and false, except own-scope `memory.write` and `memory.forget` by a task executor.
- **Reversible check.** An op with `reversible=true` must have rollback coverage `logical`, `workspace` or `CAS-revert`. Coverage `none`, `none (external)` or `n/a` with `reversible=true` fails the check, and rootd refuses to start. A golden test pins the phone-eligible set to exactly {`memory.write`, `memory.forget`, `workspace.restore`, `file.write`}.
- **Workspace-bindable check.** An op may set `workspaceBindable` only if its rollback coverage is `logical`, it has no remote effect, agentboxd executes it, its target is read only by the executor's own tasks and humans, its effect can be bound to W's epoch, and the writer is an automated task executor (a `task:<id>` holder, never a `session:<id>`). A golden test pins the set to exactly {`memory.write`, `memory.forget`} on `agent/<executor>`. agentboxd and rootd refuse to start on a mismatch.
- **Batch and quote fields.** Each op declares its batch role (`push+pr`, `push+reply`, or none) and whether it is quotable.
- **Batch check.** A golden test pins the shapes to exactly `push+pr` = {`repo.push`, `gh.pr.create`} and `push+reply` = {`repo.push`, 1 to 3 `gh.pr.comment`, private remote only}, the text caps (16 KiB of agent text per member, 64 KiB per batch), and that every member op has `reversible=false`, no CAS-writing binder and no phone path. rootd refuses to start on a mismatch.
- **Quote check.** The quotable set is every Safe, live and os op an agent may submit, plus `memory.write` and `memory.forget`. The always-exact set (ops whose cost a quote can compute from its own inputs) is pinned too.
- **Build check.** CI runs Cedar strict validation of the hand-written policies (App. D) against the generated schema. A policy that names a missing action fails the build.
- **Prose names are not checked by code.** Every op the text names must be a registry op listed in §5.3, including the Read and Coordination ops.
- **External effects.** Every remote write is in the registry: `repo.push`, `gh.pr.create`, `gh.issue.comment`, `gh.pr.comment`. There is no path around it, because tasks hold no write credentials.

### 5.2 Request flow
```
task gate → agentboxd: validate; task identity = rootd-registered socket; chain = rootd's registry chain (§4.2)
  Cedar: read/safe/side-effect ops → strictest across the whole chain, ownership = executor; coordination ops (incl. inbox) → actor only (§7)
  → rootd {op, args, task, cedarOutcome, escalate}
rootd: binding admission (below) → bind immutable inputs (commit OIDs, CAS digest, closure + .deb hashes + base gen, dpkg-status
       hash and end state, content hash, remote_url + gh_node_id) → floor check (own task registry: agent, chain, origin;
       effective taint from auditd) → Run | pending P with H = SHA-256(JCS{name, args (canonical; `hash`-class fields as
       {sha256, len}), bound inputs, agent, task, chain, trace, taintEpochs, floorVersion, policyDigest, updatePolicyDigest,
       quotes, batch, nonce, expiresAt})
approval (SSHSIG or WebAuthn over H) → BEGIN IMMEDIATE; INSERT used_nonces(nonce); UPDATE pending SET state='approved', signer=?,
       approved_at=:now_ms WHERE id=? AND h=? AND state='pending' AND expires_at > :now_ms RETURNING id; exactly one row → COMMIT,
       otherwise ROLLBACK and reply approval_stale. Only a returned row authorizes execution.
execute: BEGIN IMMEDIATE; UPDATE pending SET state='executing' WHERE id=? AND state='approved' AND approved_at > :now_ms - 900000
       AND the signer is still unrevoked RETURNING id; COMMIT (no row → 'expired' or 'refused' with a reason)
       → re-check (CAS compare: target ref == bound OID, CAS digest present, debs hash-match, running gen and dpkg-status hash
       equal the bound base; remote node_id and visibility; task live: ended_at IS NULL or end_reason='completed'; taint,
       policy digest, floor version; any failure → 'refused' with a §5.6 code in `pending.reason`)
       → INTENT to auditd (ACK only if every epoch in taintEpochs still equals the evaluated one; ACK after fdatasync)
       → effect (idempotent, or reconcilable by op id; §5.3) → RESULT (ACK) → 'executed' (effect error → 'failed')
recovery: before rootd listens on any socket (§2.1), it reconciles every 'approved' or 'executing' row with auditd by op id:
       RESULT → 'executed' or 'failed'; 'executing' without INTENT → 'refused' (nothing ran); 'approved' past the 15 min
       window → 'expired'; INTENT without RESULT → inspect state (gh.*: find the op marker, §5.3), never re-run;
       state not found → 'indeterminate' (only a human `op.resolve` moves it on; for gh.* rootd also offers a new pending P)
```
`quotes` = {taskItems, taskDeny, traceItems, traceDeny}: this task's and this trace's quote counters at bind time. Every P carries it. `batch` = {id, idx, n} for a batch member; absent otherwise. The renderer's tripwire line shows the trace totals: `quotes by this trace: <N> items, <D> deny`.

**Denials and result codes.** Every outcome other than Run returns a §5.6 denial. agentboxd builds gate and Cedar denials. rootd builds floor, ask and execution denials, and agentboxd relays them unchanged. agentboxd sends every Safe, live and os request to rootd, Cedar Deny included; rootd records each denial id in `task_denials` and makes no P for a Deny. A refusal after approval reaches the task through `ask.status`. Every submit reply carries `{cost, reason}` in the enums of `ask.quote` (below), so a quote never shows more than a submit. An approved P whose INTENT is NACKed for a moved epoch becomes `refused` with `STALE{taint_moved}`; if rootd re-pends it, the code carries the new pending id, and the re-pend uses no ask budget.

**Resolution.** Owner-scoped kinds are looked up only in the caller's namespace: apps, remotes and snapshots by executor; pending rows by task; facts inside the scopes the executor may read; inbox messages by owner; leases by resource and holder task. Missing and not-owned are one miss. Shared kinds (bus task ids) are ULIDs; a miss becomes a synthetic Task with no executor, skill or originator, and goes through the same Cedar pass. Both end in `NOT_FOUND_OR_NOT_OWNED`, sent at receipt + 200 ms. `NEEDS_SIGNATURE`, every `ask.quote` reply and every `ask.batch` reply are sent at receipt + 2 s. A reply later than its floor is still sent, and is counted in a PAD_OVERRUN record. Submits, quotes and batch admission use this one resolver.

**Exact execution.** rootd executes the stored canonical object P, never a resubmitted one.

**Time.** `expiresAt` in H is an integer: Unix milliseconds UTC, the same value as `pending.expires_at`. rootd checks `P.expiresAt > now` in Go before the approval UPDATE and again at execute; the SQL predicate is a second check. `:now_ms` is always bound from Go (App. E).

**Taint fence.**
- **Subjects:** `task:<id>`, `session:<id>`, `workspace:<agent>#<N>` (keyed by the agent's N too: a name can come back after removal, N never does), `ref:<repo>:<ref>`, `snap:<id>`, `fact:<id>`.
- **Writers.** At `task.start` and `agent.attach`, rootd registers each rw workspace mount with auditd (`writers`, App. E) before the container starts. Stop deletes the row. In the same `synchronous=FULL` transaction that taints any holder, auditd also taints every workspace that holder writes, and bumps both epochs. A tainted task or session taints a workspace as soon as it mounts it. Attach sessions are tainted from start. This happens at the proxy, keys, git or READ-INTENT (§9), before any byte flows, so no file watch is needed.
- **Effective taint** of a task is the OR of its own taint, its workspace's, every chain ancestor's, and every tainted ref it fetched (`task_subjects`, App. E). rootd evaluates it at `task.start`, at the floor check and again at execution.
- **H binds `taintEpochs`,** a JCS map `{subject: epoch}` over every subject in the effective set. auditd ACKs INTENT only if every listed epoch is unchanged. A missing row is clean at epoch 0. If any epoch moved, auditd refuses the INTENT and rootd re-evaluates; a tainted result becomes Ask.
- **Epochs move on clean → tainted, on clear, and on a signed `workspace.restore` (§5.3):** `INSERT INTO taint(subject, tainted, epoch, source, since) VALUES(?, 1, 1, ?, ?) ON CONFLICT(subject) DO UPDATE SET tainted=1, epoch=epoch+(tainted=0), source=CASE tainted WHEN 0 THEN excluded.source ELSE source END, since=CASE tainted WHEN 0 THEN excluded.since ELSE since END`. Re-tainting a subject that is already tainted (for example, every untrusted CONNECT) never moves its epoch, so it never NACKs pending approvals. `taint.clear` sets `tainted=0`, increments the epoch and records `cleared_by`. A signed `workspace.restore` sets the workspace to max(current, snapshot) and adds 1 to its epoch. auditd applies that move only when it arrives on rootd's socket as the INTENT of a signed restore, the same rule as a clear (§9). Taint rows are never deleted, so a subject's epochs never repeat, and an ended binding never matches again.
- **Result:** a clean task that shares a workspace with a tainted writer becomes tainted at once, and an approval it got while clean is NACKed at execution. No per-task workspace clones, locks or leases are needed.
- **Cost.** A tainted task taints its workspace even if it writes nothing. Until a human runs `taint.clear` on it, every task on that workspace needs signatures.

**Binding admission.** Binding writes to CAS before any human sees the op, so rootd bounds it with limits from `budgets.toml`. A rejection returns `ADMISSION_REJECTED{what, limit}`. A box-wide limit (the box's 3 CAS-binding asks, the disk reserve) returns `BUSY` with no sub-reason. Both are audited.
- An `os`-class closure over `os.plan_max_bytes` (default 2 GiB) is rejected before any download. The size comes from `--print-uris` (§3.3).
- The `app.deploy` context walk aborts once it passes `deploy.ctx_max_bytes` (default 512 MiB).
- Each agent may hold at most 1 pending P that binds CAS inputs. The box holds at most 3.
- No new binding while pool free space is below `disk.reserve_bytes` (default 2 GiB).

**Quotes (`ask.quote{ops}`).** A read op for 1 to 8 quotable ops (§5.1), own task only. rootd runs the submit's own floor function, and agentboxd its Cedar pass, with fewer inputs: no decide call, no name resolution, no GitHub call, no `osbuild-fetch`, no read of any workspace, `git/`, `cas/` or `/srv` file, no binder write, and no taint outside the caller's effective set. A skipped check that can raise the class counts at its worst case, with reason `unchecked`. A skipped check that can only refuse counts as passed. Either way the item is `exact: false`. Args may be partial.
- Per item: `cost` ∈ {`run`, `ask_phone`, `ask_cli`, `quarantine`, `deny`, `none`}; `reason`: one of {`tainted`, `signed`, `unchecked`} for asks, {`tainted`, `shared_scope`} for quarantine, the submit's own §5.6 code for deny, `already_allowed` for none; `exact`; and `shape`, the batch shape the item could join, or none. A `memory.write` that would bind quotes as `run`.
- With 2 or more items: `batch = {ok, shape, asks}`, or the `ADMISSION_REJECTED` what that `ask.batch` would return.
- The reply also carries `asks` and `taint` (§5.4).
- Every item counts against this task's quote counter (`ask.quote_items_task`, 32) and its trace's (`ask.quote_items_trace`, 64) in one transaction; deny items also count as `quote_deny`. Over either cap gives `CAP_REACHED{quote_items_task|quote_items_trace}`, and nothing is returned.
- rootd writes one QUOTE record and replies after its ACK, at receipt + 2 s. A quote writes no pending row, nonce, CAS object or taint record, and sends no ntfy. One quote per task is in flight at a time. With auditd down: `AUDIT_UNAVAILABLE`.

**Batches (`ask.batch{shape, ops}`).** One signature for one delivery. Class live, Cedar group SideEffect, `reversible=false`, CLI only.

| Shape | Members | Rules |
|---|---|---|
| `push+pr` | 1 `repo.push`, then 1 `gh.pr.create` | One registered remote of the agent, any visibility. The PR's `head` is the pushed ref, and its bound head OID is the pushed OID. |
| `push+reply` | 1 `repo.push`, then 1 to 3 `gh.pr.comment` | One registered remote with visibility `private`. Every reply names the same PR number. |

- No other op is ever a member. `gh.issue.comment`, `net.allow_domain`, `app.*`, `file.write`, os, admin, `memory.*`, `workspace.*` and `repo.merge` stay singles.
- Each member's agent-controlled text is at most 16 KiB, and the batch's at most 64 KiB.
- **The `push+reply` PR number.** The agent supplies it as the PR number argument of each `gh.pr.comment` member. It takes it from its prompt or from `gh.pr.read` output. `gh.pr.read` taints the caller before any output (§5.3), and a task that answers review comments reads them with it anyway. `ask.status` never returns the number (§5.3). At admission each member binds it into its own H as one of its canonical args, next to the remote's `remote_url` and `gh_node_id`, which rootd binds from the `remotes` row as in v5.2. Replies that name different numbers get `ADMISSION_REJECTED{batch_shape}`. The number the human types at signing only confirms the bound value (§5.4 step 7): it never enters P or H, and any other number signs nothing. A number that names no PR on the remote fails at execution with `REMOTE_REJECTED{not_found}`.
- **Admission.** agentboxd runs Cedar for each member as its own action, per chain member. rootd checks the shape, the remote, the head rule, the visibility rule and the text caps, then runs binding admission, the binders and the floor per member. Batchable ops have no CAS-writing binder, so admission writes nothing. Any refusal refuses the whole batch with `{idx, code}` (codes from §5.6; missing and other-principal resources give `NOT_FOUND_OR_NOT_OWNED`, byte-identical) and writes no pending row. Before it replies, rootd charges one quote item per attempted member and one `quote_deny` against the task and trace counters, under the same caps, with a QUOTE record marked `batchAdmissionDeny`. A batch whose member matches an open single gets `ADMISSION_REJECTED{batch_member_open}`. Every `ask.batch` reply leaves at receipt + 2 s.
- **Rows.** On success rootd inserts one P per member, each bound as if submitted alone and carrying `batch{id, idx, n}` in its H, plus one batch P of op `ask.batch` with H = SHA-256(JCS{name, shape, remote, members: [{idx, name, h}], agent, task, chain, trace, quotes, nonce, expiresAt}). The batch uses 1 ask of the task budget and `n` reviewed ops of the agent's 24 h count. The reply is one `NEEDS_SIGNATURE` with the batch id.
- **Approval.** The CLI signs hex H with `ssh-keygen -Y sign -n agentbox-approve-batch-v1`. Batch rows verify only under that namespace, and singles only under `agentbox-approve-v1`. In one `BEGIN IMMEDIATE`, rootd inserts all n+1 nonces and moves all n+1 rows to `approved`, with checked row counts; anything else rolls back and replies `approval_stale`. A member can't be approved alone. WebAuthn is refused (`reversible=false`).
- **Execution.** Ordered, not atomic. Each member runs its own claim, re-check, INTENT (which also carries the batch H), effect and RESULT. The push's RESULT comes before the next member's INTENT. A member that is refused or fails stops the batch: later members become `refused` with `BATCH_ABORTED`, earlier effects stay, and the batch row takes that member's state. After a rootd restart, a member with no INTENT becomes `refused` with `BATCH_ABORTED`; nothing re-runs.
- **Deny.** `pending.deny{id, strike?}` on a batch denies every member. Struck members get reason `ASK_DENIED`, final for their match key in this task (§5.4). The others get `batch_denied` and may be asked again. The CLI requires `--strike <idx>,…` or `--all`.

**CAS cleanup.** When P becomes denied, expired or executed, rootd deletes `cas/debs/<plan-id>/`. It also deletes every `cas/ctx/<sha>` that no pending P, deployed image or kept previous image references. A sweep at startup and every hour removes orphans.

**Plaintext lifetime.** `pending.op` holds plaintext only until the row reaches a final state. rootd then replaces `hash`-class fields with {sha256, len} and removes `drop`-class fields. H stays verifiable, because H already covers the hashes. Recovery reads open `pending` rows in rootd.db, never the audit file.

**Compromise bound.** agentboxd writes every task's prompt, inbox and memory reads. It names the task on every op, and it reports bus and memory taint. A compromised agentboxd can therefore drive any clean task, and it can attribute ops to any live clean task. That gives it every op the floor runs unsigned for an untainted task:
- `app.start/stop/restart`, `workspace.snapshot`, `repo.create`, `file.write` to an own app, an `app.deploy` that changes no signed field, and own-scope `memory.write` / `memory.forget`;
- `repo.push` of an existing local OID to `agent/<name>/*` of a private remote under a standing push policy.

It also controls bus content, bus and memory taint inheritance (§7), memory writes and quarantine (§8), leases and prompts, and it can skip READ-INTENT for bus and memory reads. It can also skip `task.taint_self` (§6.2); for Go cache files the proxy's own taint record then still applies. It also computes `workspaceBound` and the §8 read predicate; this adds nothing it doesn't already control. It can alter `ask.status` replies and denials within the §5.6 grammar (codes, ids, hex and decimals; the in-task check drops anything else). It can drop a request or return a wrong denial. The §5.6 witness records what the task saw, and rootd flags floor denials it never issued and Safe, live or os denials it never saw.

It can't run any op that needs a signature: those stay bound to H, and rootd keeps the stored object, the re-checks and the nonces. That excludes `os`, admin, `net.allow_domain`, `repo.merge`, `gh.*` writes and any deploy that changes CAS, Containerfile, ports, egress or exposure. It can't forge a signature or a chain, drop inherited child taint, start a clean task without a live parent or a human request (§4.2), or remove taint that the proxy, keys or git brokers recorded. Budget caps live in `agentbox-keys`. v2 path: §10 residuals.

### 5.3 Ops
The table below is generated from the registry. Defaults equal the floor; Cedar can only make them stricter.

| Op | Class | Floor | Bound inputs | Rollback coverage |
|---|---|---|---|---|
| `app.status`, `system.info`, `disk.usage`, `os.generations`, `pkg.search`, `bus.agents.list` | read | allowed | n/a | n/a |
| `app.logs` (own apps, redacted), `gh.issue.read`, `gh.pr.read` | read (output tainted) | allowed; the caller's taint is committed to auditd before any output is returned | n/a | n/a |
| `memory.read` (Cedar per scope, §8), `bus.inbox.read` (own inbox), `bus.task.get{taskId}` (executor or originator) | read | allowed; tainted facts, messages and child results taint the reader first (§9); a clean reader skips rows that need a READ-INTENT unless it passes `raise: true`; the reply never says whether rows were skipped; workspace-bound facts follow §8 | n/a | n/a |
| `ask.quote{ops}` | read | allowed; own task only; output generated by agentbox, so untainted; counted and capped per task and per trace; reply at receipt + 2 s (§5.2) | n/a | n/a |
| `ask.status{id?, waitMs?}` | read | allowed; own task only. Returns `asks`, `taint` and the task's open ask ids; with `id`, also that row's `{id, op, state, code, channel, expiresAt, result, members}`. `result` holds only agentbox-generated outputs (OIDs, digests, gen id, remote id), never GitHub-assigned numbers or URLs. `waitMs` (at most 25000) returns early when the row leaves `pending`, `approved` or `executing`. 1 call per second and one open wait per task; not audited; not a quote. Untainted while agentboxd is honest (§5.2 bound). | n/a | n/a |
| `bus.task.send{to/skills, message, deadline}` (resource Agent) | coordination | §7 limits; rootd writes the `delegations` row | n/a | none |
| `bus.task.claim/update/cancel`, `bus.lease.acquire/heartbeat/release`, `bus.message.send{to, taskId?, parts}`, `bus.inbox.ack{messageId}` | coordination | actor only (§7) | n/a | none |
| `app.start`, `app.stop`, `app.restart` | Safe | own registered app (exact ID) | app ID | none |
| `app.deploy` / `app.remove` / **`app.rollback{app, imageDigest}`** | live | Context copied by rootd (openat2-safe walk) into a **read-only CAS snapshot** `cas/ctx/<sha>` before hashing, size-capped (§5.2). Signature required for any change to Containerfile, CAS, base digest, ports, egress or exposure. Build is offline (`--network=none`, rootless as `app-<m>`), only from CAS; base images pre-pulled by digest from an allowlist. Exposure is a tailnet HTTPS port other than 443, or a Tailscale Service; port 443 of the box name is rejected (§5.4). | CAS digest, base digest, manifest hash | previous image kept; `@srv` data not rolled back |
| `file.write{path, content}` | live | openat2 RESOLVE flags from the `/srv/<own-app>/` dirfd; temp + fsync + `renameat2`; reject hardlinks and NUL/LF; **signature if tainted** | content hash | CAS-revert (previous content kept in CAS; a revert is another `file.write`) |
| `os.pkg.install/remove`, `os.unit.enable/disable`, `os.rollback{gen}`, `workbench.add_package` | os | signature, CLI only (§5.4); closure check rejects any `protectedPackages` entry (§3.3); `os.unit.disable`/mask of any `protectedUnits` entry is rejected outright, even when signed; OS lock (§3.3) | closure + `.deb` hashes + base gen, dpkg-status hash and end state; the unit name; or the gen ID | full OS (previous generation kept) |
| `os.update` | os | timer or human CLI only, never an agent; runs unsigned only if the closure is inside the signed `update.policy` delta (§3.3), else signature, CLI only; OS lock | closure + `.deb` hashes, base, `updatePolicyDigest` | full OS (previous generation kept) |
| `workspace.snapshot` / `workspace.restore{id}` | Safe / live | allowed / signature; same agent and same workspace only; **CLI only if the snapshot is tainted**; restore re-taints the workspace | snapshot ID, snapshot taint, tree digest, diff digest vs current | workspace |
| `net.allow_domain{host, port, reason, agent?}` | live | signature, CLI only; the human types host:port (§5.4). `agent` is set only by a human (`agentbox egress allow --agent <a> <host>:<port>`) and names whose list changes; for an agent principal it is the executor. The binder refuses the release's LLM vendor hosts (`FLOOR_NEVER{vendor_host}`). It refuses an agent-submitted request for a host in the registry constant `deputyHosts` (`HUMAN_ONLY{deputy_host}`); a human-started one shows the DEPUTY HOST line (§5.4). If host:port is already on the caller's lists, it returns `none` (`already_allowed`) and creates no P. Never an `ask.batch` member. | host:port, agent | none (persistent, audited) |
| `repo.create` | Safe | allowed | n/a | none |
| `repo.merge{p, srcOid, dstOid}` | live | signature, CLI only; compare-and-swap at execution (the `repo:<p>:main` lease is advisory, §7); propagates ref taint (§6.3) | source and target OIDs | revert commit |
| `repo.push{remote, ref, oid}` | live | `remote` is a registered remote ID (App. E `remotes`) whose `owner` is the requesting agent. `oid` is in that remote's own bare repo: `git -C <bare repo> for-each-ref --contains <oid>` lists at least one ref, and the push runs from that repo. `agent/<name>/*` refs only. Signature unless a human-signed standing push policy (`push.policy.set`) covers the remote and its visibility is `private`; and always if the effective taint is set, or if `oid` reaches a commit that `pre-receive` recorded as tainted and that is not already reachable from a human-merged `main`. GitHub rulesets also enforce the namespace. | OID, `remote_url`, `gh_node_id` | none |
| `gh.pr.create{remote, head, base, title, body}`, `gh.pr.comment`, `gh.issue.comment` | live | `remote` is a registered remote ID owned by the requesting agent; `head` must pass the same `for-each-ref --contains` check; signature, CLI only (§5.4) | head OID, body hash (op marker included), `gh_node_id` | none (external) |
| `ask.batch{shape, ops}` | live | §5.2 Batches; signature, CLI only | each member's bound inputs; the member H list | per member |
| `memory.write` | agentboxd | Own scope `agent/<self>`, untainted: trusted write (§8). Own scope while W is tainted, by an automated task executor, under the per-epoch cap and the staleness bound: Run as a workspace-bound write (`active`, `taint=1`, bound to W's epoch, §8). Attach sessions, shared scopes, a tainted own-scope write while W is clean, over the cap, or stale: Cedar Ask carried out as quarantine, released by `memory review` (§8). | body hash | logical |
| `memory.forget{factId}` | agentboxd | Run on own `agent/<self>` when untainted, or when the fact is bound to W's current epoch and the caller is a task executor (the row is kept as `forgotten` and listed in `taint review`, §7, §8); otherwise Ask; Cedar Ask on shared scopes; never `procedural`. `factId` resolves only to facts the caller could read now (§5.2). | fact ID | logical |
| `memory.review{factId, decision, bodyHash}`, `memory.purge{factId}` | admin | humans via `rootd-admin.sock`; signature, CLI only; agentboxd applies it after rootd verifies H | fact ID, body hash | none (purge is final) |
| `taint.clear{subject, contentId}` | admin | signature, CLI only; refuses `task:*` subjects; refuses while any task or session that mounts the workspace is running; compare-and-swap at execution (§7); for `workspace:` subjects, rootd purges the agent's Go module cache before the INTENT, and refuses with `CACHE_PURGE_FAILED` if a running proxy doesn't confirm (§7) | contentId (read-only snapshot ID for `workspace:`, OID for `ref:`, body hash for `fact:`) plus the subject's taint epoch, and, for `workspace:`, the dependency report's SHA-256 and its high-risk count (§7) | none |
| admin: `agent.add/remove/attach`, `agent.skills.set`, `approver.add`, `approver.remove{name}`, `passkey.register/confirm/revoke`, `policy.set`, `secret.set`, `budget.set`, `procedural.set`, `update.policy.set`, `push.policy.set`, `remote.set`, `op.resolve`, `cache.purge{agent}`, `go.private.set{agent, patterns}`, `pending.deny{id, strike?}` | admin | humans via `rootd-admin.sock` | n/a | n/a |

- **Taint rule:** every non-read, non-Safe op whose effective taint (§5.2) is set requires a signature. Coordination ops are exempt; they carry the taint forward instead (§7). For `memory.write`, the signature is the `memory review` release of the quarantined row (§8), not a live prompt. Workspace-bound ops are exempt (§5.1): own-scope `memory.write` and `memory.forget` by an automated task executor while W is tainted. Their effect is bound to W's epoch and ends at the next epoch move unless a human releases it (§8). An attach session never gets this exemption. It depends only on where the op writes; reads taint exactly as §6.2. rootd never reads the flag, and no rootd op is bindable.
- **Read taint rule.** A read op is untainted only if agentbox generates every byte of its output. Each read op has a `taintsOutput` registry flag, and the table renders "(output tainted)" from it. For these ops rootd writes INTENT, which taints the calling task, and returns the output only after the ACK, the same order as the proxy (§6.2). Bus and memory reads follow §9.
- **Op outputs.** A side-effect op returns only fields agentbox generates (OIDs, digests, the gen id, the remote id) plus fields the remote generates (PR and comment numbers and URLs). rootd stores both in `pending.result` when P becomes `executed` or `failed`. `ask.status` returns only the agentbox-generated fields, so it stays an untainted read; humans see the rest in `agentbox task show`. A denial is not a read: its only non-constant bytes are the caller's own grammar-checked fields, returned to the same task, so it taints nothing.
- **Snapshots carry taint.** rootd records each workspace snapshot in `workspace_snapshots` (App. E), and auditd records its taint as subject `snap:<id>`, copied from the workspace at creation. The snapshot's INTENT is ACKed only if the workspace epoch is unchanged. After the btrfs call returns, rootd raises `snap:<id>` to the workspace taint read at that moment, in the RESULT. That is an upper bound: taint only rises while a holder is live, `taint.clear` refuses while one runs, and rootd runs `workspace.snapshot`, `workspace.restore` and `taint.clear` one at a time per workspace. The snapshot is a read-only btrfs subvolume. Kinds: `agent`, `pre-restore` and `clean-baseline`; only rootd creates the last two.
  - `workspace.restore` first takes a `pre-restore` snapshot, which inherits the current taint.
  - In its INTENT, before the swap, rootd sets taint(`workspace:<w>`) = max(current, taint(`snap:<id>`)) as a new epoch.
  - P shows the snapshot kind, its taint, the creating task, and a file-level diff against the current tree (changed control paths first, deletions included).
  - A signed `workspace.restore` sets W to a new epoch (§5.2). Every memory fact bound to an earlier epoch then fails the §8 read predicate, and agentboxd quarantines it as a step of the restore, even though `memory.db` is not inside the restored subvolume.
- **Protected units.** `registry.protectedUnits`: `agentbox-*`, `nftables.service`, `ssh.service`, `ssh.socket`, `tailscaled.service`, `systemd-journald.service`, `systemd-resolved.service`. The floor rejects `os.unit.disable` or mask of any of them, even when signed. Changing the list, or `protectedPackages`, requires a new agentbox release.
- **Remote re-check:** at execution, `agentbox-git` reads the repo through GitHub REST (`GET /repos/{owner}/{repo}`). If `node_id` or `visibility` differs from the bound row, the op is refused.
- **`gh.*` writes are at-most-once.** GitHub has no idempotency key for these endpoints. So rootd makes each effect findable:
  1. At bind time, rootd rejects any body that already contains `agentbox-op:`. Then it appends `\n<!-- agentbox-op:<op-id> -->` to the body, before JCS canonicalization.
  2. On INTENT without RESULT, the git service lists candidates: comments via `GET /repos/{o}/{r}/issues/{n}/comments?since=<INTENT time − 60 s>&per_page=100`, all pages; PRs via `GET /repos/{o}/{r}/pulls?head=<owner>:<ref>&base=<base>&state=all`.
  3. A candidate matches only if `user.login` is the git service token's login and the body ends with the marker.
  4. Match → RESULT with the URL. No match → list again after 30 s, because listings can lag.
  5. Still no match → `indeterminate`, plus a new pending P with a fresh nonce and the same marker. It is never re-run automatically.
  - `repo.push` needs no marker: reconcile compares the remote ref with the bound OID.
- **Admin trust.** Admin ops are authorized by `SO_PEERCRED` membership in `agentbox-admin`. The admin user (default `boxadmin`, `--admin`) is root-equivalent anyway, because subiquity puts it in `sudo` ✓. Signatures protect against confined principals (agents, apps, agentboxd, approvald) and against drift between review and execution. They don't protect against a compromised admin account (§10). `taint.clear`, `memory.review`, `memory.purge` and `passkey.confirm` also need an approver signature over their bound inputs.
- **Revocation.** `approver.remove` sets the approver's `revoked_at`; `passkey.revoke` sets `revoked_at` on that one credential. rootd refuses to remove the last approver with an unrevoked SSH key. In the same immediate transaction, every P in state `approved` whose `signer` is the revoked key or credential moves to `denied`. Revoked keys never verify again, and the execution claim (§5.2) also checks the signer.
- **Admin ops without an approver signature.** `cache.purge`: rootd sends it to the proxy on `svc-proxy.sock`. The proxy cancels the agent's in-flight fills, then deletes its rows, blobs and checksum state. It needs no approver signature, because it only deletes cached public files. `go.private.set` writes `control/egress/<agent>.goprivate`: comma-separated `path.Match` globs of module path prefixes, ASCII, at most 1 KiB. Both are keep-class in audit. Agents get no cache op. `pending.deny` needs no approver signature, because it only removes capability, like `task.stop`. It sets `state='denied'` and `reason='ASK_DENIED'`, and is audited. For a batch, see §5.2 Batches. CLI: `agentbox pending deny <id> [--strike <idx>,… | --all]`.
- **Internal calls** (not registry ops, not Cedar-gated): `task.start` and `task.stop` (§4.2), and `task.taint_self{source}` on the gate socket (§6.2). `task.taint_self` can only add taint to the calling task, so the worst misuse is a task tainting itself.
- **Batch shapes.** `push+pr` and `push+reply` only (§5.2). Never mixed with any other op.
- **Never available:** a generic shell, host file reads, `/etc` writes, or a LAN-exposure op.

### 5.4 Approvals
- **CLI (any class).** The approval key lives on the human's laptop, never on the box. SSH agent forwarding to the box stays off. `agentbox approve <id>` runs on the laptop:
  1. `ssh box agentbox pending get <id>` returns P's canonical JSON, fetched **from rootd** over `rootd-admin.sock`.
  2. The laptop renders P (below) and recomputes H. It signs the lowercase hex of H (no newline) with `ssh-keygen -Y sign -n agentbox-approve-v1` (SSHSIG, OpenSSH `PROTOCOL.sshsig` ✓). The namespace gives domain separation. `sk-ssh-ed25519@openssh.com` keys are recommended, so each approval needs a physical touch.
  3. `ssh box agentbox pending approve <id> <sshsig>` submits the signature. rootd verifies it against an unrevoked approver `ssh_pub`, with namespace `agentbox-approve-v1` and message == hex H, then records `signer`.
  - **Approver #1** is the seed's admin `ssh-ed25519` public key (App. A), so the seed still holds no private key. To move to a hardware key, `approver.add` an `sk-` key, then `approver.remove` the bootstrap one.
- **CLI rendering.** P holds agent-controlled strings (`reason`, `title`, `body`, `content`, commit messages). JCS leaves C1 controls and bidi characters raw (RFC 8785 §3.2.2.2) ✓, so the CLI never prints P's JSON or decoded strings directly.
  1. The CLI re-canonicalizes P and refuses unless `SHA-256(JCS(P)) == H`.
  2. It prints a fixed per-op template from the registry. Bound and structural fields (op, host, port, OIDs, digests, sizes, gen IDs, expiry) come first, one labeled line each, each checked against its per-field grammar. Hosts must be ASCII IDNA A-labels. For `net.allow_domain` of a host in the registry constant `deputyHosts` (`proxy.golang.org:443`, `sum.golang.org:443`), the template adds a fixed line before the typed host:port: `DEPUTY HOST: it fetches from any origin a request names, so data can leave through it, even from a tainted task.`
  3. Agent-controlled strings follow under an `untrusted text` header. Each is quoted and prefixed with its byte length and code-point count. One escaper prints them through an allowlist: Unicode categories L, M, N, P, S and U+0020 pass. Everything else (all Cc, Cf, Zl, Zp, Co, Cn, Cs and other Zs) is shown as `\u{XXXX}`, and the field is flagged. A footer repeats the critical bound fields.
  4. For `net.allow_domain`, `repo.merge` and the `os` class, the human types the critical value before the key signs: the host:port, or the first 8 hex digits of the source OID or closure hash.
  5. Long content (`file.write`, PR bodies, `taint review`) is shown as a diff computed in Go from CAS or snapshots, through the same escaper and a built-in pager. The CLI never runs `git`, `less -R` or any external pager on agent data. For `taint review`, the CLI also renders the dependency report (§7). It checks the report's SHA-256 against the bound one, shows high-risk items first, and requires the human to type their count before the key signs.
  6. approvald's page uses the same escaper and inserts text only with `textContent`.
  7. For `ask.batch`: a header with the shape, the remote and its visibility (a non-private remote is flagged `DELIVERS TO A <visibility> REMOTE`), one summary line that lists the member ops in order, the tripwire line from the bound counters, and the words "ordered, not atomic". Then one page per member, each with that member's own template, untrusted text and footer. The human types the member count, and for `push+reply` the PR number that every reply member binds, before the key signs. As in step 4, a typed value only confirms what P already holds: it never enters P or H, and the agent's bound number stays the one that runs. Any other answer signs nothing. Golden tests add: a member string holding a fake `[2/2] net.allow_domain evil.example:443` line, ESC/CSI or U+202E leaves the header, the summary, the bound-field lines, the footers and both prompts byte-identical.
  - **Golden tests:** every string field of every registry op is fed ESC/CSI, U+009B, U+202E, U+2066–U+2069, U+200B, U+2028, U+FEFF and U+E0001. The output must contain only printable characters plus LF, and the bound-field lines and footer must be byte-identical to the clean case.
- **Phone (reversible ops only).** These are registry ops flagged `reversible`: `memory.write` and `memory.forget` (both logical; `memory.write` is approved through `memory review` of the quarantined row, never as a live prompt, §8), `workspace.restore` of an untainted snapshot (rootd snapshots the current workspace first; the page shows the snapshot's taint), and `file.write` (the previous content is kept in CAS, so a revert is another `file.write`).
  - **CLI only:** everything else, including `app.deploy`, `app.remove`, `app.rollback`, `os`, `admin`, `net.allow_domain`, `repo.merge`, `repo.push`, and all `gh.*` writes.
  - **Enforcement:** rootd rejects a WebAuthn approval for any pending P whose registry op has `reversible=false`, whatever approvald sends and whatever the approver's `phone_allowed` says.
  - **Phone flow:**
    1. ntfy sends a view link. Its title and body are a fixed template that rootd builds from P only: op name, agent and op ID.
    2. approvald serves a static, root-owned page with inline script and style. It gets P's JSON from rootd with `pending.get`, inserts P's strings only through `textContent` (no `innerHTML`, no markdown, no auto-linking), replaces each `hash`-class field with {sha256, len}, and computes `H = SHA-256(JCS(json))` in WebCrypto from the exact bytes it rendered. That H is the challenge. Response headers: `Content-Security-Policy: default-src 'none'; script-src 'sha256-<page.js>'; style-src 'sha256-<page.css>'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; require-trusted-types-for 'script'`, `Cross-Origin-Opener-Policy: same-origin`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
    3. The passkey signs with `UV=1`.
    4. approvald relays the assertion with `pending.approve_webauthn`. rootd verifies with `go-webauthn` (BSD-3 ✓). Checks: the **exact Origin** `https://<box>.<tailnet>.ts.net`, `crossOrigin=false`, no `topOrigin`, the RP ID, a **confirmed** unrevoked credential, `UV`, and challenge == H.
  - **approve.sock calls.** approvald can make exactly three calls. rootd refuses and audits any other method. No `SCM_RIGHTS`.
    - `pending.get{id}` returns P only if the op is flagged `reversible` and its state is `pending`. Otherwise it returns not-found.
    - `pending.approve_webauthn{id, assertion}` runs the checks in step 4.
    - `passkey.finish{regId, response}` is accepted only inside an open registration window (below).
  - **Origin isolation (rootd invariant).** The WebAuthn RP ID ignores scheme and port, so any page on `<box>.<tailnet>.ts.net` can ask for an approval assertion. Only the exact-Origin check separates them, and it includes the port.
    1. `https://<box>.<tailnet>.ts.net:443` has exactly one handler: `/` → `http://127.0.0.1:43100` (approvald). No other path, `--set-path` mount or proxy is allowed on that host and port ✓.
    2. rootd is the only writer of the Tailscale serve config. ntfy is served on `--https=8443`. App M is served on `--https=<10000+M>` or as a Tailscale Service (`--service=svc:<agent>-<app>`). Assertions made on those origins fail the exact-Origin check.
    3. The `app.deploy` binder rejects any exposure that targets port 443 of the box name (§5.3).
    4. rootd reads `tailscale serve status --json` at startup, before each phone verification, and in the health check (§3.3). On any other handler for `:443`, it refuses all phone approvals (CLI still works) and alerts.
  - **Residual:** a compromised approvald can show misleading text, but only for reversible ops. "Reversible" covers the data only. A revert does not undo effects that happen before it, such as content from a phone-approved `file.write` that the app serves in the meantime. Approving a memory fact releases it from quarantine but never clears its taint (§8).
- **Passkey registration.**
  1. `agentbox passkey register` on `rootd-admin.sock` opens a registration window. It has a single-use `regId` and a 120 s TTL. Only one window can be open at a time.
  2. Before the window opens, rootd restarts `agentbox-approvald.service` from the root-owned, minisign-verified binary. The unit has no state directory and no writable path except its private tmpfs, so a compromise can't survive the restart without root.
  3. rootd accepts one `passkey.finish` for that `regId`. It requires `UV=1`, the exact Origin, the RP ID and the challenge rootd issued. Attestation is requested as `direct` and stored if present. It is never required, because synced passkeys send `none` ✓. Any further response for that `regId` marks the window contested, and `passkey confirm` then fails.
  4. The new credential stays in state `probation` and can approve nothing. The CLI shows its AAGUID, the authenticator name when known, and the registration time. `agentbox passkey confirm <regId>` SSHSIG-signs `passkey.confirm{regId, credIdHash, coseKeyHash, createdAt}` on the laptop. A credential not confirmed within 15 min is discarded.
  5. Every phone approval audits the credential ID. `agentbox passkey list` shows each credential's last use. `passkey.revoke` removes a credential.
- **Expiry and fatigue.** An ask expires 15 min after creation (`expires_at`). An approval is single-use and must start executing within 15 min (`approved_at`). Benchmark gate: §15 weeks 15–16 (asks on the baseline task mix).
- **Ask budget and caps (rootd).** Every check runs in the `BEGIN IMMEDIATE` that inserts the row. An ask over a cap is denied with no ntfy push and is audited. Recovery re-offers and the re-pend after `STALE{taint_moved}` skip every cap and use no budget.
  1. **Task budget** (§4.2): each ask, a single P or one `ask.batch`, uses 1 when its row is created. Spent: `ASK_CAP{task_budget}`.
  2. **Open asks:** at most 3 open asks and 1 open batch per task: `ASK_CAP{task_open}` (it lists the task's own open ids), `ADMISSION_REJECTED{batch_open}`.
  3. **Per agent, rolling 24 h:** at most `ask.agent_24h` (20) asks created and `ask.agent_ops_24h` (40) ops reviewed (a single is 1; a batch is its member count): `ASK_CAP{agent_24h|agent_ops_24h}`, with `resetsAt` rounded up to 15 min.
  4. **Box-wide:** at most `ask.daemon_per_day` (5) asks from `origin: daemon` tasks per rolling 24 h. Over it, the task sees `BUSY`.
  5. **One match key.** `matchKey` = SHA-256(JCS{op, structural args, bound inputs}). Structural args are the op's args minus its free-text fields (`reason`, `title`, `body`, `content`, commit messages). Bound inputs keep body and content hashes, each taken over the agent's own text before rootd appends the `gh.*` op marker, so a new comment or PR body is a new question and a resubmission of the same body is not. Against rows of the same task:
     - an open row (single or batch member) with the same key is returned instead of a new ask (H differs only by nonce and expiry);
     - a row a human denied (`pending.deny`, reason `ASK_DENIED`) makes the key final for this task: `ASK_DENIED` with that row's id, reworded or not;
     - an executed `repo.push` or `gh.*` write returns its stored result (the `ask.status` row view) and makes no new ask; an executed `net.allow_domain` returns its result while the entry is still listed;
     - a failed row returns its stored code, and allows a new ask only if that code's `next` is `retry`;
     - an expired, refused, revoked or `batch_denied` row allows a new ask, counted against the caps.

     A new question whose op and target match a human-denied row in the same task (a new PR body for the same head and base, a new reply on the same PR) is flagged in the renderer header: `a related <op> to <target> was denied earlier in this task`.
  6. **Task end.** Open asks of a task that ends `completed` stay until `expires_at`, matching §4.2 step 6 and the §5.2 execute re-check. Any other end reason denies them (§4.2 step 6).
- **Budget view.** `ask.quote` and `ask.status` return `asks = {max, used, granted, open, openBatch, left}`, with `left = min(max − used − granted, 3 − open)`, and `taint = {tainted, workspaceBound}`. No field reflects another task's state or any agent-wide state: the per-agent and box caps surface only at submit, as audited denials. No reply holds an arg byte, an upstream byte, a policy id, a decide score or a taint source.
- **Isolation.** Denials, remedies, quotes, witness lines and task-reported denials never enter P, H, ntfy text or the approval renderer. The one exception is the bound quote counters in P and the tripwire line (§5.2).

### 5.5 decide
- **Types:** `Choice` (≤255), `Score`, `Bool` (Jev `Noul`).
- **Backends:** the local `agentbox-llm@decide` instance via its own socket (JSON schema plus token probabilities), then Jev (opt-in, via the proxy `svc` socket), then rules (fail closed). decide never shares an instance with task traffic.
- **Uses:** risk escalation, event triage, injection screening, approval labels, memory labels. Never a grader.
- **Friction only.** decide reads attacker-controlled text, so its instance may be compromised. A decide result can add an ask, a warning or a quarantine. It never removes or downgrades one (§0.1). Output that fails to parse or falls outside the schema becomes Ask.
- **Labels are untrusted.**
  1. A label is never part of P or H. It never changes an op's class, approval channel or expiry.
  2. ntfy title and body are fixed templates (§5.4). They hold no label and no free-form args.
  3. `agentbox approve` and the approvald page render P first and in full. A label may follow, as plain text of at most 120 chars, under the fixed heading "Untrusted model summary (may be attacker-influenced)".
  4. `memory review` shows each record's body, scope, provenance and taint before any label. Labels never sort, group, filter or pre-select items. Each accept is a separate action; there is no bulk accept.
  5. A decide escalation reaches an agent only as reason `signed` (§5.6). It is byte-identical to a floor-default ask, a custom-policy ask, a spend ask and a missing Run permit, and it leaves at the same 2 s floor, so decide latency doesn't show. decide is never called by `ask.quote` or at `ask.batch` admission, so neither is a classifier oracle; a quoted `run` can still become an ask at submit. Scores and labels never reach any task-visible byte.

### 5.6 Denials
Every refusal, ask, cap and broker failure that a task can hit returns one denial. A denial explains. It never authorizes. Code decides first; the denial is built afterwards from the registry and can't change the decision. No enforcement point reads a denial. A remedy op goes through §5.2 like any other op.

**Shape.** JSON per `gen/denial.v1.json` (`additionalProperties: false`), printable ASCII (0x20–0x7E) only, at most 1 KiB. `ops.Deny(code, what, slots)` is the only constructor. It drops a slot that fails its grammar and keeps the code. Fields:
- `v` (1); `id` (`dn_<ULID>`, or the pending id for an ask); `code`; `by` (gate, cedar, floor, proxy, keys, git, forwarder); `rule` (a static name); `op`.
- `next`: `fix` (change the request); `wait` (a human is deciding: run `agentbox ask wait <id>`); `ask` (you may submit the remedy op; a human signs it); `retry` (after `afterMs`); `human` (only a human can unblock: report the code and id, and go on without it); `stop` (never retry).
- `subject`: the caller's own structural fields that pass their grammar: host (A-label), port, ref, OID, remote, app or snapshot id, JSON pointer, package, unit or model name.
- `what`: from the code's closed list. `reason` and `taint` (asks only). `limit`; `resetsAt` (own scope only, rounded up to 15 min); `asksLeft` (equal to `asks.left`, §5.4).
- `msg`: one fixed sentence from the registry template, at most 200 bytes.
- `remedy`, at most 3 of: `op{op, args, approval}`, `fix{field, expect}`, `wait{pending, approval, expiresAt, notified, human}`, `poll{op: ask.status, afterMs}`, `retry{afterMs}`, `human{admin}`, `none`.

**Leak rules.**
1. Echo only the caller's own grammar-checked fields. Never echo free text (`reason`, `title`, `body`, `content`, commit messages), request bodies, upstream text, IP addresses, or hash- and drop-class values (§9).
2. Name only the requested item. Never list allowlist entries, models, policies or remotes. Never name other agents' tasks, apps, leases, budgets or asks.
3. Missing and not-owned give `NOT_FOUND_OR_NOT_OWNED` through one lookup or one Cedar path (§5.2), sent at receipt + 200 ms.
4. Taint shows only as `taint = {tainted, workspaceBound}` (§8).
5. Cedar `rule` is `cedar.hop-limit`, `cedar.memory-procedural-never`, `cedar.chain` (an ancestor's block; no ancestor named) or `cedar.custom` (any other forbid, including every human-written policy). An ask's `reason` is `tainted` when the effective taint is set, and `signed` otherwise: the floor default, a custom policy, a missing push policy, spend (`budget-ask`), risk and decide all look the same. Every `NEEDS_SIGNATURE` leaves at receipt + 2 s.
6. Box-wide limits give one `BUSY` with no sub-reason: the OS lock, the box's 3 CAS-binding asks, the disk reserve and the box-wide daemon-ask pool. `LEASE_HELD` always says `afterMs` 30000 and never names the holder. `KEYS_BUDGET` covers only the caller's own day share or trace (§6.3).
7. Remedies are static per (code, what, op). A remedy op is listed only if its binder admits those args. agentbox never re-runs policy to find one.
8. A denial never sends ntfy, never waits for an auditd ACK, and never enters P, H, ntfy text or the approval renderer.

**Codes** (append-only; v1 has 36):

| Code | next | By | Notes |
|---|---|---|---|
| `INVALID_ARGS` | fix | gate, floor | `field` (JSON pointer) and `expect`; never the value; also a body that contains `agentbox-op:` |
| `UNKNOWN_OP` | stop | gate | also any op no agent may call |
| `TASK_ENDED` | stop | any | |
| `NOT_FOUND_OR_NOT_OWNED` | stop | gate, cedar, floor, git | one path (§5.2); at receipt + 200 ms |
| `DENIED_POLICY` | stop | cedar | `rule` per leak rule 5 |
| `POLICY_ERROR` | human | cedar | evaluation error; fails closed |
| `MEMORY_QUARANTINED` | human | gate | the write was stored in quarantine; MCP `isError: false`; `agentbox memory review` |
| `CAP_REACHED` | per what | gate, floor, git | `memory_writes_task`, `memory_rows`, `memory_bytes`, `bus_messages`, `artifacts`, `push_bytes_day` (human; `limit`, `resetsAt`); `quote_items_task`, `quote_items_trace` (stop) |
| `BUS_REFUSED` | stop | gate | `hop`, `children`, `cycle`, `deadline`, `parent_ended`, `not_cancelable` |
| `LEASE_HELD` | retry | gate | `afterMs` 30000 |
| `NEEDS_SIGNATURE` | wait | floor | see Asks; at receipt + 2 s |
| `ASK_DENIED` | stop | floor | a human denied this match key in this task; carries the denied row's id |
| `ASK_EXPIRED` | ask | floor | a new ask counts against the budget |
| `ASK_CAP` | per what | floor | `task_open` (wait; lists the task's own open ids); `task_budget` (human); `agent_24h`, `agent_ops_24h` (human; `resetsAt`) |
| `STALE` | per what | floor | `ref_moved`, `cas_changed`, `stale_base` (fix); `policy_changed`, `signer_revoked`, `approval_expired` (ask); `taint_moved` (wait; carries the new pending id; uses no budget); `remote_changed` (human) |
| `BUSY` | retry | floor | OS lock, box CAS-binding cap, disk reserve, box daemon-ask pool; `afterMs` 60000 |
| `ADMISSION_REJECTED` | per what | floor | `closure_too_large`, `context_too_large` (fix; `limit`); `own_cas_pending` (wait); `batch_shape`, `batch_remote_not_private`, `batch_text_cap`, `batch_member_open` (fix); `batch_open` (wait) |
| `FLOOR_NEVER` | stop | floor | `protected_package`, `protected_unit`, `exposure_443`, `vendor_host`, `never_available` |
| `HUMAN_ONLY` | human | floor | `deputy_host`; remedy `human{agentbox egress allow}` |
| `REF_OUTSIDE_NAMESPACE` | fix | floor, git | expect `refs/heads/agent/<name>/*` |
| `OID_NOT_IN_REMOTE_REPO` | fix | floor | push the commit through `:8082` first |
| `REMOTE_REJECTED` | per what | floor | `pr_exists`, `no_commits` (fix); `ruleset` (stop); `not_found`, `other` (human); `rate_limited`, `unreachable` (retry); no GitHub text or status |
| `EFFECT_FAILED` | human | floor | no effect output |
| `INDETERMINATE` | human | floor | a human runs `op.resolve` |
| `BATCH_ABORTED` | ask | floor | an earlier member of the batch failed or was refused; this member never ran |
| `NESTED_SUBVOLUME` | human | floor | name kept from §4.1 |
| `AUDIT_UNAVAILABLE` | retry | floor, brokers | auditd down or in disk-full mode |
| `EGRESS_NOT_ALLOWLISTED` | ask; human for `deputy_host` | proxy | remedy `net.allow_domain{host, port}`, CLI; for a deputy host, `human{agentbox egress allow}` |
| `EGRESS_WRONG_ROUTE` | fix | proxy | `llm_vendor` (use `:8081`), `plain_http` |
| `EGRESS_NAME_REJECTED` | stop | proxy | `non_public` only; no IP, no check name |
| `EGRESS_RESOLVE_FAILED` | per what | proxy | `no_such_name` (fix), `unavailable` (retry) |
| `EGRESS_DIAL_FAILED` | retry | proxy | `timeout`, `refused`, `blocked` |
| `KEYS_REQUEST_REJECTED` | per what | keys | `max_tokens`, `server_tool`, `dropped_field` (fix; `limit`); `endpoint`, `field`, `block_type`, `tool_type`, `url_field`, `source_type`, `beta_header`, `model` (human); `field` pointer |
| `KEYS_BUDGET` | human | keys | `agent` (own day share; `resetsAt`), `trace`; remedy `human{budget.set}` |
| `KEYS_UPSTREAM` | per what | keys | `unreachable`, `timeout` (retry); `auth` (human, `secret.set`) |
| `BROKER_UNAVAILABLE` | retry | forwarder, `agentbox mcp` | `gate`, `egress`, `llm`, `git`; also a gate reply that fails the in-task check |

Human CLI replies (`approval_stale`, `CACHE_PURGE_FAILED`) are not agent codes; no task sees them.

**Asks.** `NEEDS_SIGNATURE` (next `wait`) carries: `reason` (`tainted` or `signed`); `taint`; the pending id (the batch id for a batch); `channel` (`cli` or `cli_or_phone`, from `reversible`); `expiresAt` (= `pending.expires_at`); `notified` (false only if the ntfy push failed); `asksLeft`; the fixed human command `agentbox approve <id>`; and the remedies `wait` and `poll{ask.status, afterMs 30000}`. `msg`: `<op> waits for a human (<channel>) until <time>. It stays open if your task ends normally. Run: agentbox ask wait <id>.` Re-submission follows the §5.4 match key.

**Surfaces.**

| Caller | The denial arrives as |
|---|---|
| MCP (`agentbox mcp`) | `isError: true` plus one text block: `msg`, a newline, then `agentbox-denial/v1 <JSON>`; no `structuredContent` on errors. `MEMORY_QUARANTINED` uses `isError: false`, because the write was stored. |
| gate JSON-RPC | error -32010; message = code; data = the denial |
| proxy CONNECT | 400, 403, 502, 503 or 504; reason phrase `agentbox <CODE> (run: agentbox why)`, ASCII, at most 64 bytes; header `Agentbox-Denial: v1 code=<c> next=<n> id=<id>`; JSON body `{error, agentbox}`; `Connection: close` |
| keys | the v5.2 statuses in the vendor's own error envelope; the message starts `agentbox <CODE>:`; plus the `agentbox` member and the header; `x-should-retry: false` unless next is `retry`; `retry-after` if the reset is under 1 h |
| git | `text/plain; charset=utf-8` (404 for `NOT_FOUND_OR_NOT_OWNED`, else 403 or 503), two lines: `msg`, then the JSON; git prints them as `remote:` lines; `pre-receive` prints the same |
| task result | `result.denials`: up to 20 entries. agentboxd keeps {id, code, what, op, subject}, re-renders `msg` and `remedy` from the registry, labels them task-reported, and gives them the result's taint (§7) |
| errno only | seccomp `EOPNOTSUPP`, `EDQUOT`, `EROFS`, `ENETUNREACH`, failed lookups, pids `EAGAIN`: `agentbox why --errno <E>` prints fixed guidance |

**Integrity.**
- Floor codes come only from rootd. Each has a rootd-minted id, kept in `task_denials` or `pending` until the task ends.
- The in-task `agentbox` binary (rootd-mounted, read-only, same release) checks every gate reply against the schemas compiled into it. It replaces `subject` with the request it sent, re-renders `msg` and `remedy` from its own registry, and drops any `ask.status` result field that is not an agentbox-generated output. A reply that fails becomes `BROKER_UNAVAILABLE{gate}`, plus a `malformed` witness line.
- So agentboxd can choose a code, an id or a number, never text.

**Witness.**
- The forwarders and `agentbox mcp` write `<id> <op> <code> <by>` for each denial to the task's witness FIFO. taskrun ends with `END <sha256 of the posted result>`.
- The agent uid can write the FIFO but not read it. agentboxd's uid can't open it. rootd parses each line with one anchored pattern and keeps the first 64 KiB of lines. It counts every later line in `dropped`, and still keeps the last `END` line.
- At `task.stop`, rootd checks each Safe, live or os line it kept: the id must be in `task_denials` or `pending` for that task, with the same code. A miss gives `GATE_MISMATCH{forged|unseen}`. A witness with `dropped` > 0 also gives `GATE_MISMATCH{flooded}`. The kept lines are still checked, so an overflow never hides a mismatch among them. If the task is clean at stop and has any mismatch kind, rootd sends one ntfy alert with fixed text: `agentbox: gate mismatch, task <id>`. A tainted task gets the record only.
- Only a rootd restart marks a witness `incomplete`, and only that case raises no alert: the gap is rootd's own, because lines written while it was down are lost. Its WITNESS and GATE_MISMATCH records and its `agentbox task show` lines stay. A flood is the task's doing, so it never suppresses the alert.
- **Scope.** The witness proves what a task saw only while the task itself doesn't collude. Task code runs as the agent uid, so it can forge, flood or withhold its own lines, or call the gate socket directly. A flood still raises `flooded`; a withheld line raises nothing. A compromised agentboxd that also writes the task's prompt can make the task collude, which the v5.2 bound already allows (it can drive any clean task, §5.2). v2: `agentbox-gate` binds the prompt hash of human-started tasks (§10).
- `agentbox task show <id>` reads rootd and audit, never agentboxd. It shows the task's asks with their final states and fine reasons (§4.2), its quote counters, the witness lines and any mismatch, and prints `result_altered` if the stored result doesn't hash to `END`.

**In-task fallback.** The forwarders and `agentbox mcp` log to `$HOME/.agentbox/denials.jsonl` (a 64-entry ring in the tmpfs HOME). `agentbox why` prints the newest 10. Task code can write this log, so it is help text, not evidence. `agentbox why` is not an MCP tool, so the §5.1 bijection is unchanged.

## 6. Network, secrets, budgets
### 6.1 nftables (Appendix B)
- **Confined uids:** agents (70001–70999), apps (71001–71999) and the whole sub-id span 0x70000000–0x77FFFFFF (§4.1). They are dropped entirely: containers have no route anyway. **The confined set is static.** rootd never inserts into it, and fwcheck compares it to a constant.
- **Broker uids** (`agentbox-proxy`, `agentbox-keys`, `agentbox-git`):
  - may connect only to `proxy_dst`, `keys_dst` and `git_dst`. These are IPv4 and IPv6 sets with per-element timeouts, filled **only by rootd** for allowlisted `host:port` entries.
  - They do no DNS of their own, and can't: `127.0.0.53` is not in their sets, and their units set `InaccessiblePaths=/run/systemd/resolve /run/dbus/system_bus_socket`. resolved's Varlink socket (mode 0666) and its D-Bus `ResolveHostname` are AF_UNIX, which nft never sees; without this a compromised broker could leak data in query names. Each broker dials only rootd's answers (pinned dialing, §6.3).
  - nft drops the box's own addresses and the special-purpose ranges in `private4`/`private6` for them and for ntfy, except approved `allow_private` tuples. rootd's route check also refuses on-link and tailnet-routed addresses, which look public by prefix (Appendix B).
- **DNS.** No agentbox uid needs IP DNS: rootd resolves over AF_UNIX Varlink. The one exception is ntfy. It may query `127.0.0.53:53` and connect to `ntfy_dst` (`ntfy.sh:443`) for the iOS push upstream. It binds no TCP port and has no other loopback access (§2).
  - **`ntfy_dst` refresh.** A rootd-internal timer runs at rootd start and then every 5 min. It resolves `ntfy.sh` through resolved Varlink, applies the Appendix B checks, and re-adds each answer with the 10-min element timeout. fwcheck checks that the set is a subset of the answers rootd added in the last 10 min.
  - **Limit.** A compromised ntfy can still post to any ntfy.sh topic, and can leak data in DNS query names. ntfy holds only notification text. Pinning ntfy.sh in a bind-mounted `/etc/hosts` would close the DNS path; it is not in v1.
  - `fwcheck` also asserts that `systemctl show -p User --value ntfy.service` is `_ntfy`, the uid the ruleset names. A mismatch is a hard failure, so a packaging change fails closed instead of leaving ntfy unconfined.
- **Service ports.** Reserved loopback ports 43000–45999 (IPv4 and IPv6) accept only listed `(uid . port)` tuples. Other new connections get a TCP reset.
  - `/etc/sysctl.d/60-agentbox.conf` sets `net.ipv4.ip_local_reserved_ports = 43000-45999` (covers IPv6 too). The kernel then never picks an ephemeral client port in the range, so replies to loopback clients never land on it.
  - `fwcheck` asserts that `/proc/sys/net/ipv4/ip_local_reserved_ports` contains `43000-45999`.
- **Stateful.** After the confined drop, established packets in the original direction are accepted. Port and destination rules judge only new connections. Reply-direction packets get no such accept, so a broker still can't answer an inbound connection (brokers have no listeners).
- **Inbound.** The `input` chain drops by default. It accepts loopback, established and related traffic, `tailscale0`, Tailscale's direct UDP 41641, IPv6 neighbor discovery, DHCP replies, and SSH from `ssh_from4`/`ssh_from6`. Those two sets hold `/etc/agentbox/ssh-from`, which the seed's `--ssh-from` writes; with no file, the private LAN ranges, `100.64.0.0/10` and `fe80::/10`. fwcheck compares them to the file like the static sets. A `ufw` that is enabled later can only drop more: a packet must pass every input hook. Rootful Docker is unsupported: its published ports go through the forward hook, which agentbox does not filter.
- **Firewall load.** `agentbox-firewall.service` runs `agentbox fw load`, one `nft -f` transaction (Appendix B). It adds the table, sets and chains if missing, flushes only the `output` and `input` chains, then writes the rules. There is no `destroy`, so a reload keeps every set's elements.
- **rootd fills the sets.** rootd writes each element's row to rootd.db before it adds the element. On start it makes the sets match rootd.db (`port_allow` and the unexpired resolution answers, with their remaining timeout). Only then does it send READY=1. User managers, brokers and ntfy order after it.
- **Firewall verification.** `agentbox-firewall.service` and `fwcheck` hash the **normalized stateless JSON** (`nft -j -s list table inet agentbox`, set elements excluded). fwcheck then compares each set's elements to the expected state, read read-only from rootd.db. Static sets must match exactly. Dynamic `*_dst` sets must be subsets of rootd's recorded answers, so an empty set passes.
- **Runtime check.** `agentbox-health.timer` runs `fwcheck` every 60 s. On a mismatch it alerts and runs `systemctl restart agentbox-firewall.service`. `Requires=` then restarts rootd, the brokers and the agent user managers, so a flushed or edited table is restored within about 60 s.
- **Stock `nftables.service` is masked** at install (§3.1). Its config starts with `flush ruleset`, and its `ExecStop` runs `nft flush ruleset` ✓.
- No ruleset change for denials. nft never logs to agents, and a drop stays silent. Structured refusals come from the brokers (§5.6). A broker dial that nft drops ends in `EPERM` or in the 10 s dial budget, which becomes `EGRESS_DIAL_FAILED` or `KEYS_UPSTREAM`.

### 6.2 Proxy (no secrets)
- **Allowlists.** Exact `host:port` entries in `control/egress/{common,<agent>,app-<m>,service}.list`, IDNA-canonicalized, with no unapproved wildcards.
- **Per CONNECT,** the proxy:
  1. Canonicalizes and checks the allowlist. A miss returns 403 `EGRESS_NOT_ALLOWLISTED` with the remedy `net.allow_domain{host, port}`, before any rootd call; for a deputy host the denial has `what: deputy_host`, `next: human` and the remedy `human{agentbox egress allow}`. It names no other entry. A host on the release's LLM vendor list returns 400 `EGRESS_WRONG_ROUTE{llm_vendor}`, with no allowlist remedy. An origin-form `GET /_cache/go/...` on a task's own proxy socket is handled by the Go module cache (below). Any other non-CONNECT request returns 400 `EGRESS_WRONG_ROUTE{plain_http}`.
  2. Asks rootd over `resolve-proxy.sock`. rootd re-checks the allowlist, resolves through systemd-resolved Varlink, rejects the name if any address fails the Appendix B checks (special-purpose range, private-wrapping NAT64, or not routed via the default gateway), adds the addresses to `proxy_dst` with a TTL, and returns them. A rootd refusal carries one reason: `not_allowlisted`, `non_public`, `no_such_name` or `unavailable`. The proxy maps it to `EGRESS_NOT_ALLOWLISTED`, `EGRESS_NAME_REJECTED{non_public}` (every Appendix B cause, with no address and no check name) or `EGRESS_RESOLVE_FAILED`. Addresses and the failed check go only to the DENY detail (§9).
  3. Connects to the returned IPs in order, within one 10 s budget split across them. On failure it returns 504 `EGRESS_DIAL_FAILED{timeout}`, or 502 with `refused` or `blocked`.
  4. Writes INTENT, which applies taint for untrusted classes **before any byte flows**, waits for the ACK, and only then tunnels.
  Refusals use the §5.6 CONNECT format. A refused CONNECT writes no INTENT and taints nothing, as before. Go cache misses and grammar refusals under `/_cache/` are bare 404, 405 or 503 with no denial header, because go needs a bare 404 to fall back.
- **No redirects, no TLS interception.** CDN fronting is a documented residual; avoid CDN hostnames.
- **Taint classes:** `api` (LLM vendors) doesn't taint, and it is valid only in `agentbox-keys`' `service.list`. LLM vendor hosts never appear in any proxy CONNECT list, because a task could reach them with its own key and bypass request validation (§6.3). Everything else taints, **including npm, PyPI, crates.io and GitHub web**. The Go module cache (below) records exactly the taint a CONNECT to `proxy.golang.org:443` would, twice: once from taskrun's filter through the gate, once from the proxy. Both records come before any module byte, so the cache never makes a caller cleaner than that CONNECT. There is no lower taint tier for registries or docs: what a tainted task may do without a human depends on where it writes, never on what it read (§5.3, §8).
- **What it can't see.** CONNECT can't see HTTP methods. Allowlisted hosts are therefore trusted by the human for both reads and writes, so only add read or API endpoints you accept. That is a documented residual. `proxy.golang.org` and `sum.golang.org` are deputy hosts (registry constant `deputyHosts`). They fetch any origin a module path names, so for them write-capable includes sending data to arbitrary origins. They are never in `common.list` (rootd refuses to load a `common.list` that names one), only a human can add them (§5.3), and `net.allow_domain` shows a fixed deputy line for them (§5.4). The Go cache can't contain this channel, because `@v/list`, `@latest` and checksum lookups never reach it.

**Go module cache (read-only to tasks).**
- **Why a filter.** go tries `GOPROXY` entries in order and moves on only on 404 or 410 ✓ (`modfetch/proxy.go`, TryProxies). It checks every `.mod` and `.zip` against go.sum, or against the signed checksum database when go.sum has no line ✓ (`modfetch/fetch.go`, checkModSum). But it sends every request, including the unsigned `@v/list`, `@latest` and `.info`, to the first entry first. So the first entry is a filter inside the task, and the proxy never sees an unsigned Go request.
- **Task-side filter** (taskrun, `127.0.0.1:8083`, inside the container). taskrun starts it only when rootd set the cache `GOPROXY`. It is part of the read-only agentbox binary and keeps no state beyond the task.
  1. *Grammar.* Only `GET /<module>/@v/<version>.{info,mod,zip}`, with no query string, no `%` in the raw path and no body. It unescapes with `module.UnescapePath` and `module.UnescapeVersion`, and requires `module.Check(path, version)`, `module.CanonicalVersion(version) == version` (this keeps `+incompatible` ✓), and no match in the agent's `go.private` patterns. Everything else (`@v/list`, `@latest`, `/sumdb/...`, branches, partial versions, commit hashes) gets the filter's own 404 and is never forwarded. go then asks proxy.golang.org over CONNECT, with TLS end to end.
  2. *Taint.* Before its first request to the proxy, the filter calls `task.taint_self{source: cache:go}` on the task's gate socket and waits for the reply. agentboxd sends auditd the same taint record the proxy applies to `proxy.golang.org:443`, and replies after the ACK. If the call fails, the filter answers 404 to everything for the rest of the task, and go uses CONNECT as in v5.2.
  3. *Live check.* Once per version per task, the filter fetches `https://proxy.golang.org/<module>/@v/<version>.info` through a CONNECT on the task's proxy socket: TLS with SNI `proxy.golang.org` and the image's roots, no redirects, a 64 KiB cap, a 10 s timeout, and one reused HTTP/2 connection (HTTP/1.1 keep-alive if HTTP/2 over the tunnel fails). Only a 200 whose JSON `Version` equals the request makes the version available. Anything else makes every file of that version 404. A failure is retried after 60 s and is never cached longer.
  4. *Serve.* `.info`: the upstream body from step 3; never from the cache. `.mod` and `.zip`: only for an available version, by `GET /_cache/go/<module>/@v/<version>.<ext>` on the proxy socket. A 200 body streams through unchanged; any other status becomes 404, and go falls back. No cache byte reaches go before step 3 returned 200 for that version.
- **Proxy cache request** (a task's own proxy socket only; attach and app egress sockets answer 404 for `/_cache/`), in order:
  1. *Grammar.* Only origin-form `GET /_cache/go/<module>/@v/<version>.{mod,zip}`, with the filter's checks, for a path that matches none of the agent's patterns in `control/egress/<agent>.goprivate`. Anything else under `/_cache/`, `.info` included, gets 404, or 405 for another method: no lookup, no upstream request and no taint. A request path never becomes a file name.
  2. *Allowlist.* `proxy.golang.org:443` must be on the calling agent's allowlist, checked as in CONNECT step 1. Otherwise: 404, no taint, no lookup.
  3. *Taint first.* The proxy writes the INTENT a CONNECT to `proxy.golang.org:443` would write for this task (same class, source `cache:go`) and waits for the ACK before any lookup and any response byte. It writes one record per task; concurrent first requests share it. While auditd is down, every cache request gets 503 with no body.
  4. *Hit.* The proxy opens `blobs/<sha256>` with `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` from the agent's store dirfd, checks the SHA-256 against the row before the first byte, then streams the blob. On a mismatch it deletes the row and the blob, counts `blob_corrupt`, and continues as a miss.
  5. *Miss.* The proxy fills (below), then streams the stored blob. On any failure it returns 404; go then falls back to CONNECT and checks the same hashes itself.

  Steps 1 and 2 read only the request and the policy. Everything that depends on cache state (hit, miss, caps, errors, timing) comes after step 3.
- **Fill** (only the proxy writes). Preconditions, all required: step 2 passed; this task's fills are under `cache.task_fill_max_bytes` (2 GiB) and `cache.task_fill_max_files` (20000); the agent's fills today are under `cache.agent_fill_day_bytes` (4 GiB); one of the agent's 8 fill slots frees within 30 s (otherwise 404); pool free space is above `disk.reserve_bytes`.
  1. Resolve `proxy.golang.org:443` through rootd on `resolve-proxy.sock`, naming the task. rootd re-checks that agent's allowlist and adds the answers to `proxy_dst`. The proxy dials only those addresses (§6.3), uses TLS with SNI `proxy.golang.org`, sends GET only, follows no redirects, and sends no credentials or cookies. The URL is built from the validated path and version.
  2. Stream into `tmp/<random>` (`O_EXCL`, 0600). Stop at the x/mod limits ✓: 500 MiB per `.zip`, 16 MiB per `.mod`.
  3. Check against the signed log. `sumdb.Client.Lookup(path, version)` reads `https://proxy.golang.org/sumdb/sum.golang.org/` (same host, same allowlist entry, same pinned dialing), with this agent's own tree state and tiles under `sumdb/`, and the key the go command pins ✓ (`modfetch/key.go`: `sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8`). A `.zip` must pass `zip.CheckZip` ✓, and `dirhash.HashZip(file, Hash1)` must equal the version's h1 line. A `.mod` must hash, with `dirhash.Hash1` over the bytes as the file `go.mod` (the go command's goModSum ✓), to the `/go.mod` h1 line.
  4. Store. fsync the file, chmod it 0444, and `renameat2(RENAME_NOREPLACE)` it to `blobs/<sha256>`; EEXIST means the same bytes are already there, so drop the temp file. fsync `blobs/`. Send the fill's audit record and wait for its ACK. Then insert the index row, but only while the filling task is still registered; revocation cancels the task's fills. A crash before the row leaves at most an orphan blob, which the start sweep removes. The temp file sits in the proxy's own 0700 store, so no other writer can change it between the hash and the rename.

  Failures delete the temp file, audit, and return 404. A version the log doesn't hold gets a plain 404, not an alert.
- **Alerts** fire only for events no task can cause: `sum_mismatch` (upstream bytes differ from the record `sum.golang.org` signed for that version), `sumdb_security` (the checksum log is inconsistent; that agent's fills stop until `cache.purge`), and `blob_corrupt` (a stored blob no longer matches its row). The proxy sends `cache.alert{agent, reason}` on `resolve-proxy.sock`, as keys sends `llm.recycle`. rootd sends at most one ntfy alert per agent per 24 h, from a fixed template with the agent name and a count per reason. Details stay in audit.
- **Availability and withdrawal.** The consuming task checks availability live on every use (filter step 3), so from the moment upstream withdraws a version no task gets it from the cache. The proxy makes no request without a live task: there is no re-check job, no freshness window and no withdrawal alert. A withdrawn version's rows idle out. Retractions are read upstream, through `@v/list` and `@latest`. A stored h1 is never re-read: the log is append-only.
- **One store per agent.** Nothing is shared across agents: no files, rows, checksum state, tiles, fill slots, fill coalescing or HTTP connection pool, and no shared page cache (blobs are separate files). Agent B's miss is a real upstream fetch even when agent A holds the file. Within an agent, hit, miss and timing come back only after the caller's taint records, so only tainted tasks see them, and only until the next clear.
- **Store, caps, eviction, purge.** `data/cache/<agent>` (§4.1) holds `index.db`, `blobs/`, `sumdb/` and `tmp/` (App. E). Before a fill would pass 90% of `cache.agent_max_bytes` (8 GiB), the proxy deletes least-recently-used rows until usage is under 80%, then each blob that no row names. Nightly it drops rows idle for more than `cache.max_idle_days` (30); this is local work, with no network. At start it deletes `tmp/`, blobs with no row and rows with no blob. Eviction only turns a hit into a miss; an open stream keeps its file. `cache.purge{agent}` cancels that agent's in-flight fills, waits for them to stop, deletes the rows, blobs, `tmp/` and checksum state, and replies. `taint.clear{workspace:<agent>}` purges first (§7). **Invariant: an agent's store is empty whenever its workspace is clean.** Every fill comes after its task's taint record, which also taints the workspace (writers, §5.2); only `taint.clear` makes the workspace clean, and it purges first; no task runs during a clear.
- **Audit.** One record per filled file {agent, task, key, sha256, h1, bytes, result}, ACKed before the index row is written. One record per mismatch, checksum-log error, corrupt blob and purge. Hits are not logged one by one.
- **A compromised proxy** can omit its own taint records (the filter's gate record still taints the task, unless agentboxd is also compromised), deny or slow Go fetches, see which public module versions each agent fetches (CONNECT showed it only the host), fill each store up to its limit, and serve forged `.mod` or `.zip` bytes to a task that turned go's checks off or skipped the filter. It can't answer `@v/list`, `@latest`, `.info` or checksum requests (the filter never forwards them), serve a withdrawn version to a task (the task checks over TLS itself), make go accept a file that the signed log or go.sum doesn't hold in the default env, create nested subvolumes (§2), reach a host rootd didn't resolve, or clear taint.
- **Private paths.** The admin op `go.private.set{agent, patterns}` writes `control/egress/<agent>.goprivate`. rootd passes the patterns as `GOPRIVATE` at launch. go then fetches those paths directly and skips the checksum database ✓ (`GONOPROXY` and `GONOSUMDB` default to `GOPRIVATE`, `cfg/cfg.go`). The filter and the proxy refuse those paths, so no fill or lookup names them.
- **Other ecosystems** join only if all of these hold: (a) the client falls back to the network on a miss, so the cache serves no metadata; (b) it checks every served file against a hash it already holds, or against a signed log; (c) a task-side filter keeps every unsigned request on end-to-end TLS and checks availability live; (d) two taint records before any byte, the CONNECT class, one store per agent, and purge on clear; (e) the dependency report (§7) covers its installed trees. npm, PyPI and crates fail (a) today: npm and cargo take one registry, and pip's extra indexes merge instead of falling back. A later npm cache must also store only SHA-512 tarballs pinned verbatim in a root-owned copy of the lockfile, build URLs from the validated name and version (never from lockfile URLs), serve tarballs from a read-only per-task view, and send all metadata over CONNECT.
- **Why §0.6 holds.** No write path: tasks have no mount of the store, only a GET grammar checked twice, and only the proxy writes. Fixed content: only public `.mod` and `.zip` bytes that match the signed record, which no task authors. Presence only, seen only by the tainted, gone at the clear: a task chooses only which public versions are stored, only tainted tasks of the same agent can observe it, and the store is empty whenever the workspace is clean. No lasting off-switch: go re-checks every file, `go env -w` writes to the tmpfs HOME, and rootd sets the env again at each launch. Takedowns take effect at once: the task's own filter checks every use live upstream.

### 6.3 Brokers
- **Pinned dialing (keys and git; the proxy does the same in §6.2 step 3).** A broker never calls the system resolver.
  1. For each upstream request, it asks rootd over `resolve-<svc>.sock` for `host:port`. rootd re-checks the fixed allowlist, resolves, adds the answers to `<svc>_dst` with a TTL, and returns them.
  2. Go clients use an `http.Transport` whose `DialContext` ignores the hostname and dials only the returned addresses, in order.
  3. TLS SNI, certificate checks and the `Host` header keep the original hostname.
  4. If `repo.push` uses the git CLI, it runs over https only, as `git -c http.curloptResolve=<host>:443:<a1>[,<a2>…] -c http.followRedirects=false push …`, so libcurl does no lookup ✓.
  5. A lookup attempt is a bug. It shows up in the broker uid's `counter drop` (App. B).
  6. The proxy's cache fills use the same pinned dialing, with `CheckRedirect` returning an error and no cookie jar. The proxy makes no upstream request without a live task.
- **`agentbox-keys`:**
  - Fixed upstreams only, resolved via rootd.
  - **Endpoint allowlist:** Anthropic `POST /v1/messages` and `POST /v1/messages/count_tokens`; OpenAI `POST /v1/responses`, `POST /v1/chat/completions` and `GET /v1/models`. Anything else gets 403 `KEYS_REQUEST_REJECTED{endpoint}`.
  - **Request validation (no vendor-side fetches):** each endpoint has a versioned schema. A failed check gets 403 `KEYS_REQUEST_REJECTED{what}` with the JSON pointer. It echoes a rejected name only for closed vocabularies (model, block type, beta name), and gives the numeric cap for `max_tokens`. No other request byte.
    - Model allowlist and `max_tokens` cap. The budget is computed server-side from the validated request.
    - Top-level fields: closed allowlist per endpoint. `mcp_servers`, `container`, `previous_response_id`, `conversation`, `background` and `prompt` are always rejected. `store` is forced to `false`.
    - Content block types: closed allowlist. Anthropic: `text`, `image`, `document`, `tool_use`, `tool_result`, `thinking`, `redacted_thinking`. A `source.type` must be `base64` or `text`.
    - Tool types: client tools only (Anthropic: no `type` or `custom`; OpenAI: `function` or `custom`). A server tool is allowed only if the policy names it, and it taints (below).
    - URL-bearing keys are rejected at any depth (`url`, `image_url`, `file_url`, `file_id`). The only exception is an `image_url` whose value starts with `data:`. OpenAI `input_file` is allowed only with `file_data`.
    - The client `anthropic-beta` and `openai-beta` headers are filtered to a fixed allowlist of beta names.
  - It strips client auth and injects the key.
  - **Budget reservation:** before forwarding, it atomically reserves `max_tokens × price` (plus an input estimate) against the agent's day share and the trace budget. Above either, it rejects with 429 `KEYS_BUDGET{agent|trace}` and `x-should-retry: false`; it sets `retry-after` only for `agent`, and only when the reset is under 1 h. The box day cap is split into per-agent day shares: equal by default and recomputed at `agent.add` and `agent.remove`, unless `budget.set` gave explicit shares (it refuses shares that sum above the box cap). So keys never refuses one agent because of another agent's spend or reservations. keys still checks the box total as a backstop; a backstop hit gives `KEYS_BUDGET` with no `what`, plus an alert.. The trace is the one rootd registered for the calling per-task socket (§4.2); a request on a socket with no registration is rejected. Spend is reconciled from `usage`.
  - **Vendor server-side web tools** taint the task and are blocked unless the policy allows them.
  - **Local LLM** (`agentbox-llm@task`):
    - **Endpoint allowlist:** `POST /v1/chat/completions` only. Anything else gets 403 `KEYS_REQUEST_REJECTED{endpoint}`, including `/slots*`, `/props`, `/lora-adapters`, `/tokenize` and `/apply-template`.
    - **Field allowlist:** keys rebuilds the body from `messages`, `max_tokens` (≤ cap), `temperature`, `top_p`, `stop`, and `tools` (type `function` only) with `tool_choice`. Everything else is dropped, including `grammar`, `json_schema`, `response_format`, samplers, `lora`, `n_probs`, `id_slot` and `cache_prompt`. When fields are dropped, the 200 carries `Agentbox-Denial` with `KEYS_REQUEST_REJECTED{dropped_field}` and the dropped names.
    - **Instance taint.** The instance is dirty once it has served a tainted request since it last started. A dirty instance serves only tainted requests. An untainted request waits: keys drains the queue and sends `llm.recycle` to rootd, which restarts the instance (one model load; at most once a minute). Queued untainted requests go first after the restart.
    - A fair queue across agents.
  - INTENT is ACKed before forwarding.
  - **Upstream responses.** keys strips every upstream `Agentbox-*` header, and the top-level `agentbox` member of any non-2xx JSON body. An upstream 401 or 403 becomes 502 `KEYS_UPSTREAM{auth}`, with no upstream bytes. Other upstream errors pass through unchanged, so CLIs still see context-length errors. Pinned dials share one 10 s budget; on timeout: 504 `KEYS_UPSTREAM{timeout}` with `x-should-retry: true`.
- **`agentbox-git`:**
  - Local bare repos: `git http-backend`, `REMOTE_USER`, a root-owned `pre-receive` hook that allows `agent/<name>/*` only. For any other ref it prints the two §5.6 lines (`REF_OUTSIDE_NAMESPACE`), which git shows as `remote:` lines. It enforces the daily byte cap from the size of `$GIT_QUARANTINE_PATH` (`CAP_REACHED{push_bytes_day}`, `resetsAt`), so a rejected pack is never stored. `receive.maxInputSize` keeps git's own message..
  - **Push size.** Bare repos set `receive.maxInputSize` (default 512 MiB per push) ✓. agentbox-git also caps each agent's pushed bytes per day (default 4 GiB, `control/budgets.toml`). `git/` sits under qgroup `2/0` (§4.1).
  - Smart-HTTP refusals are `text/plain` bodies in the §5.6 format. A repo agentbox-git doesn't serve to the caller and a missing repo are one lookup miss: both get 404 `NOT_FOUND_OR_NOT_OWNED`, sent at receipt + 200 ms.
  - **Remote writes only through registry ops:** `repo.push` (OID-bound), `gh.pr.create`, `gh.*.comment`. Each runs on a one-shot rootd capability, using the git service's token and GitHub REST. The token is scoped to exactly the repos in `remotes`. `agentbox-git` refuses any destination that is not a `remotes` row. GitHub rulesets also restrict refs to `agent/*`. A GitHub refusal at execution becomes `REMOTE_REJECTED{what}`. GitHub's text and status never reach a task; they go only to the DENY detail.
  - **Pushed workflows.** A pushed branch carries its own workflow files, and GitHub runs `on: push` workflows from them. A repo under a standing push policy must keep its Actions secrets in environments whose deployment-branch rule excludes `agent/**`, or have Actions disabled.
  - **Ref and commit taint:** pushes whose effective taint (§5.2) is set taint the refs they update, and `pre-receive` records the commits they bring in as tainted. Fetch or clone of a tainted ref applies read taint to the fetcher before the first pack byte (§9).
  - **Merge taint:** `repo.merge` sets taint(dst ref) |= taint(src ref at srcOid). A merge signature doesn't clear taint. Only `taint.clear{ref:<p>:<ref>}` clears a ref. Like the workspace clear, it shows the diff since the last clean OID, with control paths (§4.2) first.
  - **Reads:** `gh.issue.read` and `gh.pr.read` apply read taint before returning data (§9).

## 7. Agent-to-agent: the internal A2A-shaped bus
- **Data model.** A2A v1 objects (Task `id`, `contextId`, `status`, `artifacts`, `history`, `metadata` ✓; Message; AgentCard) with camelCase and `TASK_STATE_*` ✓. Not a conforming external binding.
- **Provenance** is generated server-side in `metadata["agentbox.dev/provenance/v1"]`, on the Task only. agentboxd builds it from `tasks.chain` and `taint.db`.
  - **Reserved prefix.** The `agentbox.dev/` metadata prefix belongs to agentboxd. On every bus write (`bus.task.send`, `bus.task.update`, message send, artifact append), agentboxd strips every client-supplied `agentbox.dev/*` key from Task, Message, Artifact and Part metadata. Each strip is an audit event.
  - **Provenance is never read back from A2A metadata.** Authorization, taint checks, and all CLI and UI provenance displays read only `tasks.chain`, rootd `task_registry.chain` and `taint.db`.
- **Authorization model:**
  - **Side-effect ops** (anything reaching rootd): rights are intersected across the whole chain. A child can never exceed any ancestor.
    - Ownership is checked against the task's **executor** (`context.executor`, from rootd's task registry). Resources the executor owns are not blocked by ancestors. Taint, risk and budget still intersect (App. D).
  - **Coordination ops** (`bus.task.send/claim/update/cancel`, `bus.lease.*`, `bus.message.send`, `bus.inbox.ack`) and the bus reads `bus.task.get` and `bus.inbox.read`: authorized for the **actor only**, against immutable **delegation capabilities**:
    - `{taskId, parent, executor, allowedTransitions, expiresAt, version}`, recorded by **rootd** in its `delegations` table. For `to:` routing, rootd records it at `bus.task.send`. For `skills:` routing, it records it at a successful `bus.task.claim`. Once recorded, a capability is immutable. agentboxd keeps a read copy.
    - rootd uses its row as provenance for `task.start` (§4.2). Only agentboxd enforces the transitions themselves, so that part is lost if agentboxd is compromised (§5.2). rootd still bounds side-effect ops by its own chain and taint.
    - Ancestors are not evaluated, so delegated chains work.
    - Cancel rights belong to the originator, whether an Agent or a Human: `Task.originatorAgent?` / `Task.originatorHuman?`.
    - `bus.task.get` is allowed for the task's executor and originator.
  - **Messages.** `bus.message.send` needs a live task that links sender and recipient (as executor or originator); humans can always send. The message row stores the sender's taint at send time. `bus.inbox.ack` is owner-only and sets `messages.acked_at`.
- **Transitions are atomic SQL** (`UPDATE … WHERE id=? AND state=? AND executor=?`):
  - submitted→working→{completed, failed, input_required}
  - input_required→working
  - {submitted, working, input_required}→canceled: `UPDATE tasks SET state='canceled' WHERE id=? AND state IN ('submitted','working','input_required')`. Zero rows changed returns `TaskNotCancelableError`, as A2A requires for terminal states ✓.
  - **Cancel cascade.** After the row changes, agentboxd calls rootd `task.stop{canceled}` (§4.2) and retries until rootd confirms. It then cancels `SELECT id FROM tasks WHERE parent_id=:t AND state IN ('submitted','working','input_required')`, as the system actor with reason `parent_stopped`.
  - **Other terminal transitions.** `completed` and `failed` also call `task.stop` with that reason.
- **Leases** are advisory. They give agents mutual exclusion, not safety. The guard is rootd's compare-and-swap at execution (§5.2). agentboxd keeps leases in `state.db` (App. E). Times are Unix ms.
  - Acquire: `INSERT INTO leases VALUES(:r,:t,1,:now+:ttl,:max) ON CONFLICT(resource) DO UPDATE SET holder_task=excluded.holder_task, epoch=leases.epoch+1, expires_at=excluded.expires_at, max_until=excluded.max_until WHERE leases.expires_at<=:now`. `changes()=1` means acquired. This is how an expired lease is reclaimed.
  - Heartbeat: `UPDATE leases SET expires_at=min(:now+:ttl, max_until) WHERE resource=:r AND holder_task=:t AND epoch=:e AND expires_at>:now`. `:max` and `max_until` are at most the task deadline.
  - Release: `DELETE FROM leases WHERE resource=:r AND holder_task=:t AND epoch=:e`.
  - Task end deletes that task's leases (§4.2). If that delete is missed, expiry reclaims the lease.
  - Only the holder may heartbeat or release (App. D).
  - **Leases cover:** `repo:<p>:main` only. Add `gpu:exclusive` back when the keys local-LLM queue needs it.
- **Restart reconcile.** On startup agentboxd compares `tasks` with rootd's task registry. A task in `submitted` or `working` whose registry row has `ended_at` set and no result becomes `failed` (reason `agentboxd_restart`). Leases held by that task are deleted now, not at `expires_at`.
- **Limits:** hop ≤ 4, no cycles, deadline default 2 h, at most 5 children, per-trace budgets. A parent can grant asks to a `to:` child with `asks: k` in `bus.task.send` (default 0). The grant leaves the parent's budget at send and is never returned. A `skills:` child gets 0. Quote counters roll up per trace, so a grant or a fan-out can't multiply silent recon; a trace's counters and `asks_created` drive the recon alerts (§9).
  - **Child deadline** = `min(parent.deadline, now + 2h)`. The child's delegation `expires_at` equals that deadline, and its unit's `RuntimeMaxSec` is `deadline − now`.
  - Per-trace budgets come from `budgets.toml` and are enforced by `agentbox-keys` against the rootd-registered trace (§6.3). This caps a delegation fan-out as a whole.
- Bus task ids are ULIDs (§5.1); rootd's `task.start` refuses any other grammar. Refusals are §5.6 denials: `BUS_REFUSED{hop|children|cycle|deadline|parent_ended|not_cancelable}`; the `not_cancelable` case keeps the A2A name `TaskNotCancelableError`. Cedar `hop-limit` shows as `BUS_REFUSED{hop}` with rule `cedar.hop-limit`. A task id the actor has no right to and a missing one run the same Cedar pass (a miss is a synthetic Task with no executor, skill or originator); both give `NOT_FOUND_OR_NOT_OWNED` at receipt + 200 ms. Originator get and cancel, linked-peer messages and `skills:` claims are unchanged. `LEASE_HELD` gives `afterMs` 30000 and never names the holder. A child's `NEEDS_SIGNATURE` shows only its own `taint` shape, never an ancestor's task or agent.
- **Taint:** inherited by children, messages and memory writes.
  - A message's taint is fixed from the sender's taint at `bus.task.send`/`update`. A task's `result_taint` is raised to the executor's taint at every `bus.task.update`.
  - Delivering a message, or a child's `status`/`artifacts`, applies read taint to the reader first (§9).
  - Workspace taint is live and sticky (§5.2). Children share the parent's `workspace:<agent>` subject when they run as the same agent.
  - Message text is still rendered as quoted data, but only as defense in depth.
- **Clearing taint** (`agentbox taint review <subject>`, then `agentbox approve <id>`):
  1. rootd takes a read-only snapshot S of the workspace and runs `agentbox-depcheck@` on S against the newest `clean-baseline` (the dependency report, below). It pends `taint.clear{subject, contentId=S}`; H includes the current taint epoch, the report's SHA-256 and its high-risk count. The CLI renders, in this order: the changed control paths (§4.2), deletions included; the dependency report, high-risk items first, and if there are any, the human types their count; the current epoch's workspace-bound memory facts, active and forgotten, by {sha256, len, title-sha256}, for information only (not bound in H); then the rest of the diff of S against the newest `clean-baseline` snapshot of that workspace (or the empty tree). Agent snapshots are never used as the review base.
  2. At execution rootd refuses if any task or session that mounts the workspace is running. It doesn't stop them; the human does. rootd blocks new task starts on the workspace until the clear finishes.
  3. rootd replaces the workspace with a rw snapshot of S, so the cleared content is exactly the reviewed content. The replaced subvolume is kept as a tainted snapshot. For `workspace:` subjects, after the swap and before the INTENT, rootd sends `cache.purge{agent}` to the proxy on `svc-proxy.sock` and waits up to 30 s. If the `agentbox-proxy` unit is inactive, rootd deletes `data/cache/<agent>` by name and re-creates it empty, with its limit. If the proxy is active but doesn't reply, the clear is refused with `CACHE_PURGE_FAILED`, and the workspace stays tainted. A crash after the purge and before the INTENT leaves an empty cache and a tainted workspace, which is safe.
  4. INTENT to auditd clears `workspace:<w>` only if its epoch still equals the signed one. auditd records `snap:S` as untainted, and rootd records S as kind `clean-baseline`. Only rootd creates a `clean-baseline`: the first when it creates the workspace, then one each time a clear succeeds. Once the clear applies, the epoch's workspace-bound facts fail the §8 read predicate, and agentboxd quarantines them before its next memory op for that agent and in its nightly sweep. The clear doesn't offer their release; a human releases any later, one at a time, with `memory review` (§8).
  - Ref clears bind the OID and fail if the ref moved. Fact clears bind the body hash. `task:*` subjects can't be cleared: the model context still holds the injected text.
  **Dependency report.** Lockfiles are not control paths; this report covers dependency trees instead.
  - **depcheck.** rootd runs `agentbox depcheck` as a transient unit, the way it runs `osbuild-*@` (§2): `DynamicUser=yes`, `AmbientCapabilities=CAP_DAC_READ_SEARCH` and no other capability, `NoNewPrivileges=yes`, `PrivateNetwork=yes`, `RootDirectory=` an empty root-owned dir with `BindReadOnlyPaths=` for the binary, the two snapshots and `data/cache/<agent>`, `MemoryMax=2G`, `RuntimeMaxSec=300`. It writes one JSON report to stdout, at most 16 MiB, and rootd checks it against a strict schema. Any failure (exit code, timeout, schema) makes every changed dependency file high-risk, and the report says why.
  - **Pairs.** For `taint review`: S against the newest `clean-baseline`, the same pair as the diff. For `agent.attach`: a read-only snapshot of the workspace against the last reviewed snapshot, the same pair as the control-path check.
  - **Pins** come from `go.mod`, `go.sum`, `go.work`, `package-lock.json` or `npm-shrinkwrap.json` (lockfile v1–v3), `Cargo.lock`, `uv.lock` and `requirements*.txt`, at any depth outside the dependency trees. Each file is capped at 16 MiB.
  - **Dependency trees** are `vendor/`, `node_modules/` and every venv (a dir holding `pyvenv.cfg`, whatever its name, the workspace root included), at any depth. Each changed file maps to its owning package: Go by the longest module path in S's `vendor/modules.txt`; npm by the longest package path in the lockfile (`packages` keys in v2–v3, nested `dependencies` in v1); Python by the dist-info `RECORD` that lists it. A file with no owner is its own item. No changed file is ever shown as a bare path.
  - **Go vendored check.** A changed vendored file counts as verified only if its module's go.sum h1 is unchanged from the base snapshot, and the file is byte-identical to the same path in a cached zip whose `dirhash.HashZip` equals that h1. `index.db` is only a hint: depcheck re-hashes every zip it relies on.
  - **High-risk items**, in this order, each with its content diff through the §5.4 escaper and pager:
    1. Drift: changed files in a package whose pin didn't change, unless verified.
    2. Pin anomalies: a downgrade, the same version with a new hash, a pin with no hash, a lockfile that fails to parse or is over 16 MiB, or a depcheck failure.
    3. New packages with installed code. Packages the main module imports come first (Go: the import lines of the main module's own `.go` files, parsed with `go/parser`, imports only; npm: `package.json`; Python: the `uv.lock` root).
    4. Changed pins with installed code.
  - **Routine changes** are summarized: pin changes with no installed code (a later fetch of them taints), verified Go vendored files, removals and reorders. Direct changes are listed one per line; the rest are counted; the pager has the full list.
  - **At the clear.** The existing acknowledgement covers control paths and routine changes. If there are high-risk items, the human also types their count before the key signs. `taint.clear` binds the report's SHA-256 and the high-risk count into H. The full file diff still follows the report. To avoid trusting high-risk code, have a task delete those trees and review again; the next task reinstalls them, and that fetch taints like any other.
  - **At attach.** rootd refuses `agent.attach` while the report for that pair has high-risk items, until the admin passes `--ack-dependency-changes` after viewing them. Routine churn never blocks attach (for example go.sum lines filled for required versions, or pin upgrades with no installed code). `--ack-control-changes` doesn't pass this gate, and `--ack-dependency-changes` doesn't pass the control-path gate.
  - All text goes through the §5.4 escaper. The report changes no taint rule.
- **Routing:** `to:` and `skills:` (a claim board) from a parent task, `agentbox task new` from humans, and onfailure triage. An onfailure task has no parent and no human request, so rootd starts it tainted (§4.2). Triage that sees journal or app log text is tainted anyway. For agentbox-owned units, the triage agent gets only an agentbox-generated struct {unit, result, exit_code, signal, timestamps}, with no journal text.
  - A `skills:` task is created with `executor` NULL and `skill` set. It has no capability until it is claimed.
  - The claim is one atomic transaction: `UPDATE tasks SET executor=:me, state='working' WHERE id=:id AND state='submitted' AND executor IS NULL AND skill IN (:claimerSkills)`. If exactly one row changed, rootd inserts the delegation row (version 1) before agentboxd commits. Otherwise the claim fails and nothing is recorded.
  - rootd's `delegations` primary key is the tie-breaker: a second insert for the same task fails. After a crash, agentboxd takes the executor from rootd's row.
  - `:claimerSkills` come only from the admin-set skills that rootd holds (`agent.add`, `agent.skills.set`). rootd re-checks them before it inserts the row. An AgentCard the agent writes itself is never used.

## 8. Shared memory
| Layer | Store | Writer |
|---|---|---|
| Working | the CLI's own session (ephemeral HOME) | agent |
| Episodic | redacted per-agent audit views from auditd's query call, plus nightly summaries, each in scope `agent/<subject>` (taint = max of sources; facts referenced by id, never by body) | agentboxd |
| Semantic | `memory.db` (`modernc.org/sqlite` ✓, FTS5, `secure_delete=ON`, directory `chattr +C`) | agentboxd via `memory.write` |
| Procedural | `control/procedural/` (root-owned) | **humans only** |
| Tasks | bus tables | agentboxd |

- **Scopes:** `agent/<name>`, `project/<p>` and `procedural`. The Cedar `MemoryScope.kind` is the first part. An `agent` scope has `owner` = that agent.
- **Write:**
  - A fact's taint is the max of its sources' taint.
  - Trusted writes to `agent/<self>` commit directly only if auditd ACKs INTENT{writer, epoch} with the taint epoch agentboxd evaluated still unchanged. Otherwise the write is quarantined.
  - **Workspace-bound writes.** A tainted own-scope write commits `active` and bound only if: the writer is an automated task (`writers.holder` is `task:<id>`); W is tainted at epoch e; fewer than `memory.bound_max_per_epoch` (50) active plus forgotten facts are bound to (W, e); and `now − taint.since(W)` is at most `memory.bound_stale_ms` (7 days). agentboxd sends INTENT{writer, taintEpochs {W: e}, title and body hashes}. auditd ACKs only if W is still tainted at e and `writers` maps the task to W. On ACK the fact commits with `taint=1`, `ws_subject=W` and `ws_epoch=e`, is indexed only in `memory_fts_ws`, and the reply is `{id, state: active, bound: true}`.
  - Every other tainted write is quarantined: attach sessions, shared scopes, a tainted own-scope write while W is clean (ancestor-only taint), over the cap, past the staleness bound, or with no ACK. Shared-scope writes are quarantined even when clean. Cross-agent summaries are shared-scope writes, so they are quarantined too. decide labels are shown only as untrusted hints (§5.5).
  - Cedar returns Ask for these writes (`tainted-ask`, `risk-ask`, `budget-ask`, or no own-scope permit). agentboxd never turns this Ask into a live prompt. It stores a quarantined row and returns `MEMORY_QUARANTINED` (§5.6). The row is not indexed, and no task can read it.
  - A human releases a quarantined row with `agentbox memory review`, the CLI front end for `memory.review` (signed over fact ID and body hash; `memory.write` is `reversible`, so a phone approval works too, §5.4). At release, Cedar runs again with the writing agent as principal and `approved=true`, so `memory-procedural-never` still denies procedural writes. Release sets `ws_*` to NULL, keeps `taint=1`, and indexes the fact in `memory_fts`.
  - Quarantined writes are reviews, not asks.
  - Rate limit: 20 per task. Per-agent caps on memory rows and body bytes, bus messages and artifacts (`control/budgets.toml`). Over a cap, the write fails with `CAP_REACHED{what, limit}` (§5.6).
- **Taint and review are separate fields.** `taint` is immutable. `state` is `quarantined`, `active` or `forgotten`. Approval only releases the fact from quarantine; it never changes `taint`. Only `taint.clear{fact:<id>}` (admin, CLI) marks a fact clean.
- **Index:** `memory_fts` holds active facts without a binding, and released facts. `memory_fts_ws` holds active workspace-bound facts only. Quarantined facts are visible only through `memory review`.
- **Read:** checked by Cedar per scope, returned as JSON with provenance. Every read joins `facts` with `f.state='active' AND (f.expires_at IS NULL OR f.expires_at > :now_ms) AND (f.ws_epoch IS NULL OR (f.ws_subject = :ws AND :ws_tainted = 1 AND f.ws_epoch = :ws_epoch))`, where `:ws`, `:ws_tainted` and `:ws_epoch` come from auditd's `taint.get` for the reader (§9). Unbound facts are ranked by FTS5 bm25 in `memory_fts`. Bound facts are matched in `memory_fts_ws`, own scope only, newest first, and never bm25-ranked. Episodic summaries and tainted unbound facts apply read taint to the reader before delivery (§9). A clean reader skips them unless it passes `raise: true`, and the reply never says whether rows were skipped. Bound facts need no READ-INTENT, because their only readers already hold the tainted W. This filter protects only against facts known to be tainted: it doesn't cover a fact that a compromised broker laundered to `taint=0` by omitting a READ-INTENT (a v5.2 residual, §10). Results are rendered as a quoted `untrusted-memory` block as defense in depth. Memory is never mounted into tasks.
- **End of binding.** Any epoch move of W (`taint.clear`, or a signed `workspace.restore`) makes that epoch's bound facts fail the read predicate at once. agentboxd then sets them `quarantined` and deletes their `memory_fts_ws` rows, before its next memory op for that agent and in the nightly sweep. Epochs never repeat, so a binding never matches again. The clear doesn't offer their release; a human releases any later, one at a time, with `memory review`.
- **Visibility.** `agentbox status` and the health view show, for each tainted workspace, the bound-fact count and the epoch age. Every `memory.digest_interval_ms` (6 h), if there are new bound facts, agentboxd sends one ntfy digest per agent from a fixed template: the count, and for each fact the first 8 hex digits of its body SHA-256 and its length. No body, title or label. It is a notification, never an ask. `agentbox memory review --bound` lists the current epoch's bound facts any time, through the `memory review` renderer; releasing one is a separate signed `memory.review`.
- **Exports:** procedural only, written by rootd to the read-only `/opt/agentbox/exports/INSTRUCTIONS.md`. Claude gets `@/opt/agentbox/exports/INSTRUCTIONS.md` in its generated `CLAUDE.md`; Codex gets a generated `AGENTS.md`. Semantic facts are never exported.
  Both generated files also carry eight fixed lines from the release. They are constants, not memory, so semantic facts are still never exported:
  1. `Blocked actions return agentbox-denial/v1 <JSON> (an MCP tool error, an HTTP error body, or a git remote: line). Act on its next field.`
  2. `next: fix = change the request; wait = a human is deciding, run agentbox ask wait <id>; ask = you may submit the remedy op; retry = after afterMs; human or stop = don't retry, report it.`
  3. `A call that fails with no detail (bare 403, CONNECT tunnel failed, timeout, name resolution failure): run agentbox why.`
  4. `Before acting, quote your whole plan once with ask.quote. Send a push and its PR (or, on a private remote, a push and its replies to one PR) as one ask.batch.`
  5. `Your task has a small ask budget; ask.status shows it. Don't submit an op again while it is open. If an ask is denied or the budget is spent, stop at the local branch and report.`
  6. `Open asks stay open if your task ends normally, until they expire. They die if your task fails or is canceled.`
  7. `Go modules come from a read-only cache. If go reports GOPROXY=off, this agent has no module access: report it; only a human can enable it.`
  8. `List every blocked action in your final result as op, code and id.`
- **Deletion:**
  - `memory.forget{factId}` is logical. It resolves only facts the caller could read now (§5.2). Own scope Run, shared scopes Ask, procedural never. For an unbound fact it sets `forgotten` and deletes the `memory_fts` row in one transaction. For a fact bound to W's current epoch, forgotten by a task executor, it sets `forgotten`, deletes the `memory_fts_ws` row and keeps `ws_*` until the epoch ends; `taint review` and `memory review --bound` list it by {sha256, len, title-sha256}. The nightly sweep deletes the FTS rows of expired facts.
  - `memory.purge{factId}` is an admin op (humans via `rootd-admin.sock`, CLI only, signed). rootd forwards it to agentboxd. It deletes the rows, runs FTS `optimize`, checkpoints WAL and VACUUMs. This is best-effort, not forensic; the disk is LUKS-encrypted. Audit records hold only hashes of the title and body (§9), so purge needs no audit rewrite.
- **Episodic layer.** Summaries reference bound facts by id only, never by body. auditd's query call never returns the records listed in §9 Access.
- **Embeddings:** v2 (llama `--embedding` plus Go brute-force search).

## 9. Audit
- **Writer:** `agentbox-auditd`, with one socket per producer and SO_PEERCRED attribution.
- **Format:** hash-chained JSONL segments `audit/seg-NNNNNN.jsonl`, named by sequence number, never by date. Each record has `seq`, `prev` (SHA-256 of the previous record's line), `ts_wall` (CLOCK_REALTIME), `ts_boot` (CLOCK_BOOTTIME) and `boot_id`. Order comes from `seq` and `prev`, never from time.
- **Durability.** auditd ACKs only after `fdatasync`, and after `taint.db` commits with `synchronous=FULL`. Every effect is: INTENT → ACK → effect → RESULT → ACK.
  - **The one exception is `task.stop`** (§4.2). It only removes capability, so it never waits for an ACK. rootd keeps its records in rootd.db and sends them when auditd is back, reconciled by op ID.
- **Read taint.** Taint moves on read, not only through the proxy. A service that delivers bytes from a tainted source first sends READ-INTENT{reader, source} to auditd. auditd sets taint(reader) |= taint(source) in `taint.db`, bumps the reader's epoch (and its workspace's, §5.2), and ACKs after the commit. Bytes go out only after the ACK. An op evaluated before the raise then fails its epoch check. If the reader is already tainted, or the source is not tainted, no call is made. If auditd is down, these reads fail closed. Producers:
  - the proxy tunnel and the Go module cache (§6.2): one record per task at its first valid cache request, ACKed before any lookup
  - taskrun's Go module filter, through the gate (`task.taint_self`, §6.2), before its first request to the proxy
  - `agentbox-git`, for fetch or clone of a tainted ref (§6.3)
  - the `app.logs`, `gh.issue.read` and `gh.pr.read` handlers
  - agentboxd, for bus messages (`messages.taint`) and child `status`/`artifacts` (`tasks.result_taint`), delivered to any reader: parent, originator or claimant
  - agentboxd, for `memory.read` of episodic summaries and of any fact whose `taint` is set. Approval through `memory review` doesn't clear a fact's taint (§8).
  Workspace-bound facts need no READ-INTENT: their only readers already hold the tainted workspace (§8).
- **Quoting is not a control.** Rendering messages and memory as quoted data is defense in depth only (§0.1).
- **Taint write rules.** Taint only moves up, except through one path.
  - Any producer may set taint on any subject. Over-tainting fails safe: it only adds signature asks.
  - A set record names the subject and source only. auditd sets `tainted=1` itself and moves the epoch per §5.2. A producer never supplies `tainted` or `epoch`.
  - auditd rejects, and logs as a violation, any record that has `tainted=0` or an `epoch` field, on every socket except rootd's.
  - auditd applies a clear only when it arrives on rootd's socket as the RESULT of an admin `taint.clear` op whose INTENT is already in the chain. The clear sets `tainted=0`, `cleared_by` and `cleared_at`, and adds 1 to `epoch`.
- **Reconciliation.** On restart, rootd, brokers and auditd reconcile by op ID. rootd finishes its pass before it listens on any socket (§5.2).
- **Files and sealing.** auditd is the only writer. rootd only creates and seals segments, because setting `+a` and `+i` needs `CAP_LINUX_IMMUTABLE`.
  - rootd creates each segment owned by `agentbox-audit`, mode 0640, `chattr +a`. auditd opens it `O_APPEND`.
  - auditd rotates at 64 MiB, after 24 h of CLOCK_BOOTTIME, or at its first start in a new boot. A wall-clock step never rotates or seals a segment.
  - To rotate, auditd stops ACKing, appends `close{seq, last_hash}`, runs `fdatasync` and closes its fd. It then calls rootd `audit.seal{seg, last_hash}`. rootd verifies the chain through `close`, sets `+i`, and creates the next segment with `+a`. auditd's first record there is `open{prev = hash(close)}`. Then ACKs resume.
  - `audit.seal` is idempotent. After a crash, auditd finds `close` as the last record and calls it again. rootd finishes whichever step is missing.
  - **Torn tail.** On start, if the open segment doesn't end in `\n`, auditd appends `\n`, then `torn{offset, len, sha256, prev = hash of the last complete record}`. Nothing is truncated, so `+a` is never removed. The torn bytes were never ACKed, so no effect depended on them. `audit verify` skips exactly the declared byte range and reports it.
  - **Failed `fdatasync`.** The record is not ACKed. Linux reports a writeback error once and can mark the pages clean, so a later `fdatasync` succeeds without them. Before the next record or seal, auditd drops the segment's cached pages and reads it again from the disk. Bytes that did not reach the disk are declared torn, and the chain goes on from the last record that did.
  - **Clock steps.** auditd compares the wall-clock and CLOCK_BOOTTIME deltas between records. If they differ by more than 1 s, it logs `clock_step{delta}`. A `clock_step` never comes before a segment's `open`, or between torn bytes and their `torn` record.
- **Disk-full mode.** At start, auditd keeps `audit/.reserve` (512 MiB, `fallocate`).
  - On `ENOSPC`, or when free space falls below the reserve, it deletes the reserve, raises a critical alert and enters disk-full mode.
  - In that mode it ACKs only INTENTs for admin ops from `rootd-admin.sock`, such as `taint.clear` and `agent.remove`. Every other INTENT is refused, so those effects fail closed.
  - The ACK rule doesn't change: `fdatasync` plus the `taint.db` commit.
  - When free space is back above the reserve plus 1 GiB, auditd recreates the reserve and leaves the mode.
- **Audit classes.** Each registry field has a class (§5.1). `drop`: removed entirely, with no hash, because hashes of low-entropy secrets can be brute-forced. `hash`: replaced by {sha256, len}. `keep`: logged verbatim. Defaults:
  - `drop`: the `secret.set` value and any other credential field.
  - `hash`: `file.write.content`, `memory.write` title and body, `gh.*` title and body, and read outputs (`app.logs`, `gh.*.read`).
  - `keep`: everything else.
- **Records.** INTENT = {opId, name, H, args (classes applied), bound, agent, task, chain, taintEpochs, ts}. RESULT = {opId, status, errorCode (a §5.6 code), outputs (classes applied)}. A batch member's INTENT and RESULT also carry `batch{id, idx, n}` and the batch H. No producer logs raw P.
  - **DENY** = {id, code, what, by, task, agent, op, subject (classes applied), detail, count, first, last}. `detail` is for humans only: Cedar policy ids and diagnostics, the Appendix B check, addresses, the upstream status. Producers: agentboxd, rootd (asks included), proxy, keys, git. They send best-effort and never wait for the ACK. Each sends one record per (task, code, what, subject) per 60 s, and repeats in that window reuse the id; at most 500 per task. Past that, a producer sends no more DENY records for the task, and when the task ends it sends one **DENY_FLOOD**{task, by, count}, where count is the number it skipped. auditd checks DENY records against the generated schema and drops them in disk-full mode.
  - **DENY_FLOOD** is an audit record type, like WITNESS and GATE_MISMATCH. It is not a §5.6 code: it carries no code, it is not in the 36-code table, and no reply to a task ever holds it, so it never reaches the in-task check. As for DENY, auditd checks it against its own generated schema, drops it in disk-full mode, and never returns it through the query call (Access, below).
  - **WITNESS**{task, lines, dropped, incomplete, endDigest}, **GATE_MISMATCH**{task, kinds, count}, **PAD_OVERRUN**{op, code, ms} and **PAUSE_PID_STALE**{agent, reason} (§4.2): from rootd, best-effort.
  - **QUOTE** = {task, trace, agent, items: [{name, args (classes applied), cost, reason, exact, batchAdmissionDeny?}], taskCounters, traceCounters, ts}: from rootd, ACKed before the quote replies. `ask.status` writes no record.
  - **ALERT** records from rootd: `quote_recon{task|trace}` when a task, or a trace's root task, ends with `asks_created = 0` and with `quote_items` ≥ `ask.recon_items` (24) or `quote_deny` ≥ `ask.recon_deny` (4); `quote_enum{trace}` when a trace's `quote_deny` reaches `ask.enum_deny_trace` (16); `quote_recon{agent}` when an agent's quote items over a rolling 24 h reach `ask.agent_recon_items_24h` (128), or its deny items `ask.agent_recon_deny_24h` (32). They reach the human through the health and ntfy path, at most one per (agent, reason) per hour, as fixed text. They are alerts only: no cap follows from them.
  - **Cache records** from the proxy: one per filled file {agent, task, key, sha256, h1, bytes, result}, ACKed before the index row is written, and one per mismatch, checksum-log error, corrupt blob or purge. Hits are not logged one by one. Module paths are keep-class (they pass `module.CheckPath` and are under 1 KiB), and so are `go.private` patterns.
- **Enforcement at the sink.** auditd checks each record against the per-op audit schema generated from the registry. It NACKs a record that has a `drop` field, a `hash` field not in {sha256, len} form, or a `keep` string over 1 KiB. A NACKed INTENT means the effect never runs.
- **Access.** agentboxd never reads audit files. It gets episodic views through a read-only query call on its own producer socket, which returns schema-filtered records. `/var/lib/agentbox/audit` is `agentbox-audit:agentbox-audit` 0750, files 0640. agentboxd's query call also answers `taint.get{task}`: the task's effective subjects with {tainted, epoch}, W from `writers`, and the holder kind (`task` or `session`). It is agentboxd's only source for Cedar's `tainted` and `workspaceBound`, the §8 read predicate, the `taint` view in `ask.status`, and the bound-write guard. It can't write taint. On failure agentboxd uses `tainted=true` and `workspaceBound=false`, and returns no bound fact. The query call never returns DENY, WITNESS, GATE_MISMATCH, PAD_OVERRUN, PAUSE_PID_STALE, QUOTE, ALERT or cache records, so neither their detail nor their existence reaches an agent, episodic views included. A human reads them with `agentbox audit denial <id>` and `agentbox task show <id>`, which run on the box and read segments and `rootd-admin.sock`, never agentboxd.
- **Logging limits.** No transcripts by default (`--log-driver=none`). No service logs a `drop` or `hash` field to journald. journald is capped at 2 GB. Audit is kept 1 year.
- **Off-box shipping** is recommended: `audit ship` via rsync over Tailscale, or OTLP with pinned GenAI semantic conventions. `audit verify` checks the chain.

## 10. Security model
| Threat | Control |
|---|---|
| Injection leading to exfiltration | `Network=none`; per-task sockets; nft drops confined uids including all sub-id blocks; brokers can reach only rootd-resolved allowlisted IPs; taint → signature; no secrets or write credentials in tasks; keys rejects vendor-side URL fetches (§6.3) |
| Exfiltration over allowed channels | Exact host:port allowlists (human-trusted); remote writes are registry ops only, to registered remotes; INTENT audit; deputy hosts (`proxy.golang.org`, `sum.golang.org`) are never in `common.list`, only a human can add them, the approval shows a fixed DEPUTY HOST line (§5.3, §5.4), and agents without them get `GOPROXY=off` (§4.2). Residual: CDN fronting, write-capable allowlisted hosts, and deputy hosts when allowlisted. |
| Persistence across tasks (hooks, MCP config, credentials) | Ephemeral HOME per task; session-home never mounted into tasks; attach runs with hooks and workspace MCP off; the one shared cache (Go modules) is read-only to tasks, holds only checksum-database-bound `.mod` and `.zip` files, answers only after the caller is tainted, serves a file only after the task's own filter sees it live upstream, and is purged by `taint.clear` (§6.2); workspace-bound memory facts are readable only by tasks that hold the same tainted workspace epoch, can't be written by attach sessions, and end at the next clear or signed restore (§8) |
| Host persistence through agent config | Root-owned account and XDG dirs; agent-writable paths are never read by host tooling |
| Quota bypass and disk exhaustion | No btrfs ioctls in tasks (seccomp); `1/N` under a capped `2/0`; CAS cap and binding admission; auditd disk-full mode (§4.1, §4.2, §5.2, §9); Go module caches in each agent's `1/N`, with a kernel limit per store and per-task and daily fill caps; no btrfs ioctls in non-root services (§2, §6.2) |
| agentboxd compromise | Signed ops stay bound to H, with the stored object, re-checks and nonces in rootd; rootd derives chain, trace and child taint; auditd rejects a taint clear from any socket but rootd's. Residual: unsigned floor ops for clean tasks; bus and memory integrity, workspace-bound facts included; `ask.status` and denial contents within the §5.6 grammar (§5.2) |
| approvald compromise | No keys; only three calls on `approve.sock`; restarted from the verified binary before passkey registration; new passkeys need a CLI SSHSIG confirm; exact-origin WebAuthn; high-impact classes are CLI-only |
| Same-origin script on the approval page | approvald is the only handler on `:443`; apps and ntfy on other ports or Services; rootd checks the serve config; textContent-only page with a hash CSP (§5.4) |
| Approval display spoofing (terminal controls or bidi in agent strings) | Registry-templated CLI renderer: H re-check, bound fields first, allowlist escaper, footer, typed confirmation of critical values; attach output filter (§5.4, §4.2) |
| agentbox-llm compromise (a crafted prompt hits a llama-server tokenizer, template or grammar bug) | No network, no secrets, read-only models; task and decide on separate instances and uids; keys endpoint and field allowlist; a dirty instance serves only tainted requests until rootd restarts it; decide is friction only (§5.5, §6.3) |
| Proxy, keys or git compromise | No reach beyond rootd-resolved allowlisted IPs (kernel-enforced). nft also drops the box's own addresses and special-purpose ranges; rootd's route check refuses on-link and tailnet-routed addresses. Secrets split by service. It can't clear taint (§9). Residual: it can omit taint for content it delivers. A compromised proxy can also withhold or slow Go module files, see which public module versions each agent fetches, and fill its cache store up to its kernel limit. It can't answer unsigned Go requests or serve withdrawn versions: taskrun's filter never forwards the first, and checks the second live over TLS. Through the filter, cache files reach a task untainted only if agentboxd is also compromised (§6.2). |
| auditd compromise | No network, AF_UNIX peers only; off-box chain shipping and `audit verify` detect rewritten history. Residual: it can forge ACKs and report subjects clean until detected. |
| Offline OS build compromise | Unprivileged userns nspawn with a private network; only verified `.deb`s; no ESP or GRUB access. This bounds build-time effects only. The generation that boots runs as real root with the TPM and Tang reachable, so its trust rests on the Supply chain row. Boot failures fall to Bad OS change. |
| Approval drift (contents changing after review) | Bound OIDs, CAS digests, `.deb` hashes and the dpkg base; compare-and-swap and re-checks at execution |
| Race, replay or substitution | Nonce plus state change in one immediate transaction with a checked row count; rootd executes the stored P |
| Socket misuse | Full inventory with explicit modes, peer checks, no fd passing |
| Firewall missing or drifting | `Network=none` doesn't depend on it; normalized-hash and set verification gates user managers; `fwcheck` every 60 s reloads the table, restarts dependents and alerts; stock `nftables.service` masked (§6.1) |
| TOCTOU | openat2, CAS copies, `renameat2`; taint epochs bound in H |
| Deputy, poisoning, laundering | Chain intersection for effects; quarantine; procedural is human-only; live sticky workspace, snapshot, ref, commit and registry taint; read taint on bus, memory, logs, git and gh (§9); bound `taint.clear`; the Go cache answers only after two taint records; dependency code that would run untainted after a clear (`vendor/`, `node_modules/`, `.venv/`) is high-risk in `taint review`, shown with content diffs, and needs a typed count bound into H (§7); workspace-bound facts are own-scope, readable only while the reader holds W at the bound epoch, indexed apart from other facts, quarantined at any epoch move including a signed restore, listed by hash even when forgotten, and capped per epoch with a staleness bound; a clean reader gets tainted memory only with `raise: true`, and that filter doesn't cover a fact a compromised broker laundered to `taint=0` (the residual below) |
| Bad OS change | A/B generations, one-time boot, booted-generation check before commit, initrd gate, watchdog, emergency reboot, commit deadline, commit on health |
| Disk theft | Per-mode threat table (§3.1) |
| Supply chain | minisign; pinned digests; mise pins with `minimum_release_age = "3d"`; signed apt metadata plus bound `.deb` hashes; offline app builds; Go module files checked against sum.golang.org before storage and again by the go command; withdrawn versions never served from the cache; Go pinned in the image through mise |
| Attach session exfiltrates a subscription credential through memory | Attach sessions never get the workspace-bound exemption, so their tainted own-scope writes are quarantined and shown to a human; the post-attach token scan also covers the facts the session wrote (§4.2, §8) |
| Denials as a leak, oracle, steering or suppression channel (secrets, allowlists, policy shape, other agents' resources and spend, taint sources, LAN facts, the approval path) | One constructor and a closed ASCII schema, checked again in the rootd-mounted in-task binary. Only the caller's grammar-checked fields, release constants and own-subject facts. Owner-scoped lookups, per-owner app names, ULID shared ids and one Cedar path for `NOT_FOUND_OR_NOT_OWNED`, with 200 ms and 2 s reply floors. One taint shape, `{tainted, workspaceBound}`. One reason, `signed`, for every non-taint ask. One `BUSY`. Per-agent day shares. Static remedies. Never in P, H or ntfy. DENY records hidden from the query call. Floor codes only from rootd; a rootd-read witness flags forged and unseen denials (§5.6) |
| Ask quotes and status as a policy, allowlist or cross-task oracle | A quote is the submit's floor function with fewer inputs, each missing input at its worst case; no decide, network, file or repo reads; closed enums; no agent-wide value; `already_allowed` reveals no more than a CONNECT probe; counted per task (32), per trace (64) and per agent, bound into every P in the trace, and alerted on recon and enumeration; replies at receipt + 2 s (§5.2, §5.4) |
| Hidden, swapped or rider members in a batch | Two shapes only (`push+pr`, `push+reply`); one remote; replies only on a private remote, to one PR whose number the human types; issue comments and egress never batch; 16 KiB of agent text per member and 64 KiB per batch; the member H list is in the batch H; one page per member, a typed member count, a separate SSHSIG namespace; members can't be approved alone; every nonce burned in one transaction (§5.2, §5.4) |

**Residuals** (each with a v2 path):
- Shared-kernel exploits. v2: Firecracker tasks.
- Whole-machine theft in `tpm2` mode. v2: UKI with a signed PCR 11 policy.
- Boot-chain package updates, which are post-commit rather than A/B.
- A signed but malicious package in an approved closure runs as root at the trial boot. It can read the LUKS key and rewrite `/bootpart` and the ESP. A/B fallback covers crashes, not hostile code. v2: UKI + PCR 11 measured trial boot.
- CDN fronting, write-capable allowlisted hosts, and deputy hosts when allowlisted: an agent with `proxy.golang.org` or `sum.golang.org` can send data out in module paths, tainted or not. v2: a GET-only package broker that still taints and takes registry and GitHub hosts off CONNECT lists; a private module proxy as the Go cache upstream.
- Root tampering with on-box audit (ship it off-box).
- Misleading phone page for low-risk ops.
- Model labels can bias a reviewer. Bounded by §5.5: P's deterministic rendering always comes first.
- An approvald compromised in memory during the 120 s passkey registration window can swap in its own credential. If the human confirms it, it can approve reversible ops until `passkey.revoke`. v2: an attested-only mode for hardware keys.
- The `admin` uid is root-equivalent (subiquity adds it to `sudo`), and admin ops need only `SO_PEERCRED` membership. CLI signatures don't protect against a compromised admin account. v2: no `sudo` for admin; admin ops become signed pending P.
- A compromised agentboxd acts as any untainted agent for unsigned floor ops, and can skip READ-INTENT on bus and memory reads. It can write workspace-bound facts for any live tainted task (it already controls memory writes). It can alter `ask.status` replies and denials within the §5.6 grammar (codes, ids, hex, decimals). It can drop requests or send wrong Cedar denials; the witness records them, but rootd can't re-check Cedar (§5.2). v2: an `agentbox-gate` service (own uid) serves the per-task gate sockets and relays raw requests to rootd. rootd then answers `ask.status` directly, re-evaluates Cedar denials, issues per-task gate MAC keys, binds the prompt hash of human-started tasks, and applies bus and memory READ-INTENT itself.
- A compromised proxy, keys or git can omit taint for content it delivers. v2: a second taint check at the task gate on response classes. For Go cache files, taskrun's filter already records that second taint (§6.2).
- Go module cache: tainted tasks of an agent can see which public versions its store holds, until the next clear. A task that turns go's checks off (`GOSUMDB=off`, `GONOSUMDB`) trusts a compromised proxy's `.mod` and `.zip` bytes. This is accepted as bounded. It needs a compromised proxy plus task code that turns the checks off, which taskrun never does. Through the filter, the gate record taints the task before the first forged byte; skipping the filter takes hand-built requests, so the task already runs injected code. Either way the forged code gets nothing that code lacks: every non-read, non-Safe op still needs a signature. The override lasts one task. v2: a clean path for lockfile-pinned files once workspace taint is narrower.
- Dependency review: npm and Python installed code can't be checked against an upstream hash, so every changed `node_modules/` or `.venv/` package is high-risk at a clear, and so is vendored code of a changed Go pin. v2: offline checks of stored checksum-database proofs for Go.
- Workspace-bound facts: inside one tainted epoch, an injected bound note can steer the same agent's later tasks, which are all tainted already. Bounded by the per-epoch cap, the staleness bound, the digest and `memory review --bound`; one stricter Cedar forbid restores per-fact review.
- Denials: run, ask and refuse stay observable as in v5.2, and codes add only the coarse reason. `BUSY` still shows one box-wide bit (the OS lock, the box's 3 CAS-binding slots, the daemon-ask pool). Task code can forge its own in-task log.
- Ask budget: one batch signature can cover up to 4 effects, so a human may review up to 40 ops per agent per 24 h (v5.2: 20). Within the quote caps, a small low-volume probe raises no alert. Several tasks together, or one task with the maximum budget of 10 sending 4-member batches, can use up a shared per-agent cap and deny a sibling's asks (availability only, and noisy: every ask is an ntfy push).
- A compromised auditd can forge ACKs and mask taint until off-box verification catches it. v2: rootd keeps its own append-only taint record and refuses on regression.
- The post-attach token scan finds a token as written, not encoded. It inflates git packs and reads a delta's inserted bytes, but doesn't rebuild a delta from its base, so a token spliced from base copies is missed. Bounded by the review diff (§7).
- A file that a workspace git config pulls in with `include.path` or `includeIf` is not a control path. Once the include line is acked, the included file can change with no new ack (#193).
- Root can always remove confinement. After a root-level flush, brokers are unconfined for up to 60 s, until the next `fwcheck` (§6.1).
- One duplicate `gh.*` comment or PR, if a human re-approves an indeterminate op whose first POST landed late.
- Jev egress when enabled.
- Approximate metering for subscription sessions.
- Until `osbuild-fetch@` lands (weeks 11–12), `agentbox os plan` runs apt as root on the host. It clears apt's update hooks (§2), but it still prints `apt-get update` and `--download-only` output raw to the admin's terminal, and a closure-mismatch error embeds raw `apt-get -s` output. The approval listing itself quotes every origin.
- The stock `10_linux` "Ubuntu" entries stay in `grub.cfg`. Nothing selects them unattended, but one booted by hand runs the btrfs top level without `rootflags`, and leaves `recordfail` set, so GRUB then shows its menu for 5 s on every boot.
- `ua-timer`, `motd-news`, `apport-autoreport` and `update-notifier-download` stay enabled and contact the network (§3.3 Updates).

**Test-model limits** (what the gates can't show; not product residuals):
- QEMU 11.1's NVMe controller ignores FUA. In an NVMe power-cut log, FUA writes are never flush marks, so the replay at the last flush can be the disk just before the final journal commit. Use `DISKBUS=virtio` for exact durability points.
- blklogwrites once left a 15.7 MiB hole in a 9.9 GB virtio install log; the root cause is unknown. `replay-log`, `check` and `boot` fail loudly at a hole.
- Power-cut replay needs a plain btrfs partition, so encrypted disks are not replayed. `vm.sh cut` (a QMP reset) models only a disk with no volatile write cache. Power-cut suites run in `tpm2` mode only.
- The milestone 4 (weeks 5–6) gates use stand-in brokers: restart, outage and retry checks run against stubs that bind the same per-task sockets. A skill's frontmatter hook needs a model reply to fire, so the tasks gate checks only `disableAllHooks`.
- The VM's network is `hack/vmnet`: libslirp with the host loopback cut off. The guest reaches the Mac's `127.0.0.1` only on Tang's and release-serve's ports, forwarded as `10.0.2.2`; `gate.sh` checks that a loopback listener with no forward sees nothing. The guest still reaches the Mac's LAN.
- The arm64 VM tests softdog only; the i6300esb path runs on amd64. x86 watchdog detection is unit-tested only.
- HVF guests stop while the Mac sleeps, and their clocks fall behind. Long gates need AC power and an open lid. `vm.sh` no longer counts sleep against the install timeout.

## 11. Failure modes
| Failure | Behavior |
|---|---|
| agentboxd down | Running tasks continue. Gate calls fail closed and retry (§4.2). A result is delivered if agentboxd returns before the task's `RuntimeMaxSec`, because sockets are re-bound from rootd `task.list_live` (§2.1). Otherwise the task is marked failed on restart (§7). rootd still runs `task.stop` on unit exit, timeout or deadline, and humans can stop a task via `rootd-admin.sock`. |
| rootd down | Ops fail closed. Recovery reconciles by op ID before rootd listens again. Witness lines written during the outage are lost; those witnesses are marked incomplete and raise no alert. |
| auditd down | No effect executes and no tainted read is delivered; INTENT and READ-INTENT are never ACKed. `task.stop` still runs (§9). No workspace-bound fact is returned, and memory writes are quarantined. Ops, quotes and brokers answer `AUDIT_UNAVAILABLE`; `ask.status` still answers, with `taint.tainted` = true. Every proxy cache request gets 503, like CONNECT. |
| Audit disk below reserve | auditd enters disk-full mode: only admin ops execute; alert (§9). |
| Torn audit tail (crash mid-append) | auditd appends a `torn` record and restarts without human action. |
| Wall-clock step (NTP) | Audit continues. Segments roll by size and CLOCK_BOOTTIME only; a `clock_step` record is logged. |
| systemd-resolved down | Brokers can't resolve new destinations. Existing set entries expire, then everything fails closed. |
| proxy, keys or git down | That capability is lost; alert. The task's forwarder retries for 5 s, then answers 503 `BROKER_UNAVAILABLE`, so clients don't hang. |
| Firewall check fails | No agent or app user managers start. |
| Table flushed or edited at runtime | The next `fwcheck` (at most 60 s later) fails. The firewall is reloaded, and rootd, the brokers and the user managers restart; running tasks are killed. Alert. |
| Agent quota full (`1/N`) | That agent's writes fail with `EDQUOT`; alert. Agents can't create subvolumes outside `1/N`. `cache.purge{agent}` frees the cache share. |
| Shared stores full (`2/0` limit) | Agent and app writes fail; new dispatch is already paused at 92%. Audit, `taint.db` and `rootd.db` keep the reserve, so admin ops still execute; alert. |
| CAS quota full, or pool below reserve | New bindings are refused (`ADMISSION_REJECTED` or `BUSY`, §5.2); alert. Audit and the DBs are unaffected. |
| Power loss | GRUB-safe grubenv and `grub.cfg` replace (§3.3 step 8) with a committed-generation fallback; rootd.db, state.db and taint.db in WAL with `synchronous=FULL`; fsynced audit. |
| Stuck task | `RuntimeMaxSec` or deadline reached → rootd `task.stop{timeout\|deadline}` (§4.2), which reaches the payload via `--cgroups=split`. Not empty within 10 s → agent blocked from dispatch; alert. |
| Bad OS change | Automatic, unattended fallback (§3.3). |
| TPM unseal fails (TPM cleared, board swap) | `tpm2` and `tpm2+tang` both stop at the LUKS prompt (SSS `t=2` needs the TPM share), then reboot after about 8 min. Unlock with the key from `agentbox recovery decrypt`, then `clevis luks regen`. |
| Firstboot fails (network, release host) | Retries every 60 s from a clean start, with no limit, and again on every reboot. The health check isn't installed yet, so the failure shows only in `systemctl status agentbox-firstboot`, the journal and the console (§3.1). |
| Go module cache full, corrupt, or upstream down | Misses and failed live checks get 404, and go uses the CONNECT path as in v5.2. A corrupt blob is deleted on read. A checksum mismatch or checksum-log error alerts (at most once per agent per day) and stops that agent's fills until `cache.purge`. With agentboxd down, the filter serves nothing and go uses CONNECT. |
| Proxy stopped or hung during `taint.clear` | Stopped: rootd re-creates the agent's empty store itself and the clear goes on. Hung: the clear is refused (`CACHE_PURGE_FAILED`) and the workspace stays tainted; retry when the proxy answers. |
| depcheck fails or times out | Every changed dependency file is high-risk, and the report says why. |
| A tool ignores the proxy | Its lookup fails in under 1 s, or `connect()` gets `ENETUNREACH`; `agentbox why --errno` explains. |
| A batch member is refused or fails | Later members become `refused` with `BATCH_ABORTED`; earlier effects stay (for example a pushed branch with no PR); the batch row takes that member's state. The agent may re-ask the rest. |
| An alert can't be delivered (ntfy down) | It is queued like other alerts and retried. |

## 12. Layout
```
/bootpart/{grub/,agentbox/{gens/<gen>/,recovery.bin,committed}}      /boot = bind gens/<current>; /boot/grub = bind /bootpart/grub
/var/lib/agentbox/releases/<ver>/{bin/{agentbox,cedar},systemd/}       current, previous
/var/lib/agentbox/control/{policy,egress/{*.list,<agent>.goprivate},approvers,passkeys,budgets.toml,prices.toml,procedural,xdg/<agent>,apps,exports/<agent>,update-policy,seccomp-task.json}
/var/lib/agentbox/{rootd.db,audit/{seg-*.jsonl,taint.db,.reserve},state/state.db,memory/,cas/{ctx,debs},git/}
/var/lib/agentbox/data/{images/,agents/<name>/{account,storage,session-home},workspaces/<name>,cache/<name>/{index.db,blobs/,sumdb/,tmp/}}     (@var_lib_agentbox_data)
/run/agentbox*/ … (full inventory in §2.1; dirs from /usr/lib/tmpfiles.d/agentbox.conf)
/etc/grub.d/09_agentbox   /etc/nftables.d/agentbox.nft   /etc/sysctl.d/60-agentbox.conf   /etc/dracut.conf.d/90-agentbox.conf
```
- **Under qgroup `2/0`** (§4.1): every agent's `1/N` (in `data/`, including `data/cache/<name>`, which also has its own limit), and the subvolumes `data/images/`, `state/`, `memory/`, `cas/`, `git/` and `@srv`. Everything else in `/var/lib/agentbox` keeps the reserve.
- **Users:**
  - services: `agentbox`, `agentbox-audit`, `agentbox-approve`, `agentbox-proxy`, `agentbox-keys`, `agentbox-git`, `agentbox-llm`, `agentbox-llm-decide`, `agentbox-ingress`
  - packaged: `_ntfy` (ntfy's sysusers entry); agentbox never creates an `ntfy` user
  - per agent and app: `ag-<name>` (70000+N) and `app-<M>` (71000+M); ids never reused; sub-ids per §4.1
  - the human admin (default `boxadmin`, §3.1)
- **Groups:** `agentbox-admin`, `agentbox-approve`, `agentbox-notify`.

## 13. Tooling
- **Host (✓ archive):** `btrfs-progs`, `cryptsetup`, `clevis` (with `-luks`, `-tpm2` and `-dracut`), `tpm2-tools`, `tang` (on the Tang device), `podman 5.7.0`, `crun`, `systemd-container 259.9`, `nftables`, `minisign`, `sqlite3`, `git`, `jq`, `llama.cpp 8681` (with the vulkan/hip ggml backends), `ntfy`, `systemd-zram-generator`, `ufw`, `curl`, `openssl`. All seed packages are published for resolute on arm64 and amd64 ✓ (B10).
- **Host (vendor repo):** Tailscale.
- **Task image:**
  - **apt:** `git ripgrep fd-find fzf jq tmux build-essential python3 python3-venv nodejs sqlite3 ocrmypdf tesseract-ocr ffmpeg whisper.cpp`
  - **mise, pinned, 3-day cooldown:** `claude codex uv ast-grep go`. `gh` is omitted: GitHub goes through the `gh.*` ops. The image Go is the only Go a task runs by default (`GOTOOLCHAIN=local`, §4.2). mise keeps it current; apt `golang-1.26` would trip `GOTOOLCHAIN=local` on more repos.
  - **Playwright, pinned:** Chromium.
  - **MCP servers:** `agentbox mcp` (registry tools, including `gh.*`, the bus, `ask.quote`, `ask.status` and `ask.batch`), `playwright-mcp --headless --isolated`, filesystem, git, time, fetch (tainting), `ast-grep-mcp`.
  - **Generated tool descriptions.** Each starts with the op's ask-cost line (§5.1). The `ask.*` descriptions tell the agent to: quote its whole plan once before acting; send a push and its PR (or, on a private remote, a push and its replies to one PR) as one `ask.batch`; wait with `ask.status` or `agentbox ask wait <id>`, or end the task normally; and stop at the local branch when an ask is denied or the budget is spent. They also say that quote reasons are coarse (`signed` covers every signed cause), that reply batches need a private remote, that the PR number for a reply batch comes from the prompt or `gh.pr.read` (a tainting read), never from `ask.status`, and that no agent-wide cap is reported. A CLI that can't hold a 25 s tool call is told to use `agentbox ask wait` from the shell (D-G10).
  - **In-task CLI** (part of the read-only agentbox binary; not MCP tools): `agentbox why` and `agentbox ask wait` (§4.2).
  - **Also:** `markitdown`; `jevgrep` (off until enabled).
- **Not bundled (license):** serena (GPL), basic-memory (AGPL), Phoenix (ELv2), claude-squad (AGPL). Omarchy patterns keep their MIT notice.

## 14. Code
```
agentbox/ (Apache-2.0, Go 1.26)
  cmd/agentbox/
  internal/{ops(registry,binders,codegen),gate,policy,bus,memory,decide,dispatch,depcheck,
            rootd/{floor,pending,asks,witness,cas,tasks,gens,osbuild,users,ids,openat,apps,seal},audit,approvald,webauthn,proxy/gocache,keys,gitsvc,taskrun/gomodfilter,reconcile,seed,recovery}/
  gen/  policy/{default,golden}/  install/  image/  systemd/  nft/  seccomp/  bench/  fuzz/  Makefile  .github/workflows/ci.yml
  hack/{vm.sh,gate.sh,apply-gate.sh,remaster-iso.sh,powercut.sh,powercut/,release/,release-serve/,verify-seed.py,tang/,SHA256SUMS}
```
- **Built in weeks 1–2:** `cmd/agentbox` (`seed`, `recovery`, `os`), `internal/{seed,recovery,rootd/gens}`, `install/install.sh`, `systemd/` (reconcile, plus the health service and timer), `hack/release` (`make release`), `hack/release-serve` and the `hack/` harness. Standard library only.
- **Go dependencies:** `cedar-go` v1.9.1 ✓, `modernc.org/sqlite`, `modelcontextprotocol/go-sdk` ✓, `go-webauthn/webauthn` ✓, `godbus/dbus/v5`, `golang.org/x/sys/unix`, `golang.org/x/crypto`, `bubbletea`; from v5.3, `golang.org/x/mod` (module, semver, modfile, zip, sumdb, sumdb/dirhash; BSD-3) for the Go cache, the filter and depcheck, and `github.com/BurntSushi/toml` (MIT) for `Cargo.lock` and `uv.lock` in depcheck. The service seccomp filter uses `x/sys/unix`. Week 1 (seed and recovery) uses only the standard library.
- **Policy validation:** static, with the Rust `cedar` CLI; plus per-request schema validation and Deny on any evaluation error in agentboxd (App. D).

## 15. Build order and gates (about 20 weeks with 2 engineers; about 34 weeks with 1)
**Weeks 1–2 results (2026-11-20).** Every weeks 1–2 gate item passed on QEMU, except the old PC, which needs its owner. PLAN "Where we are" lists each item with its suite. The runs used `main` at `e2e53af` and `61acfc7`, after the review fixes. Evidence is in the maintainer's local evidence store, not in the repo.
- **arm64 UEFI on NVMe, Secure Boot on** (resolute's pinned AAVMF, shim, GRUB): unattended install and first boot in `none`, `tpm2` and `tpm2+tang`. With Tang down the box reboots about 490 s after the LUKS prompt, a typed recovery key unlocks, and clevis unlocks once Tang is back. Two disks with one `ID_SERIAL` abort before storage (`gates-none` r1 `e2e53af`; `gates-tpm2`, `gates-tpm2-tang-down-typed-recovery` r2 `61acfc7`; `dup-serial-abort` r1 `e2e53af`).
- **amd64 BIOS** (q35, SeaBIOS, SATA, swtpm, TCG): `none` and `tpm2` (`bios-amd64-none` r3 `61acfc7`, `bios-amd64-tpm2` r1 `e2e53af`).
- **`os.apply`:** two cycles, then a third that prunes gen-1; a kernel and systemd upgrade in both TPM modes; five breaks in all three modes; and six QMP power-cut points in `tpm2`. Each fell back with no console input (`os-apply-cycles-*`, `os-apply-breaks-tpm2`, `os-apply-powercuts-tpm2` r1 `e2e53af`; `os-apply-breaks-none`, `os-apply-breaks-tpm2-tang` r2 `61acfc7`).
- **Power-cut fidelity:** `btrfs check --readonly` is clean at all 1010 flushes of a logged boot, and the replayed disks boot and settle on the committed entry. `powercut.sh grub` (in `os-apply-powercuts-tpm2`) finds a bootable GRUB entry after every write to `/bootpart` in one logged apply (`powercut-fidelity` r2 `61acfc7`).
- **Also:** Secure Boot off with `-kernel`, the zero-touch ISO, and uutils on the target (`secureboot-off-direct-kernel-none`, `zero-touch-iso`, `uutils-target` r1 `e2e53af`).

Not run: the old PC (and with it amd64 UEFI), GitHub KVM CI (needs a push), QMP power cuts in `none` and `tpm2+tang`, replay of encrypted disks, `tpm2+tang` on BIOS, and `os.apply` on BIOS after the fixes (one pre-merge run at `e17a778`). Everything below week 2's gate is still open until that gate passes.

v5.3 adds about 39 engineer-days (proposals A–D, `PROPOSALS-v5.3.md` section 10.3), so the 16-week plan becomes about 20 weeks with 2 engineers. Row labels name phases, not calendar weeks. Gate ids (A-G1, B-G1, C-G1, D-G1, X-G1, …) are defined in `PROPOSALS-v5.3.md` sections 3.5, 4.5, 5.5, 6.5 and 8.3.

| Weeks | Build | Gate |
|---|---|---|
| 1–2 | Seed generator (no plaintext secrets; reserved-name check; ID_SERIAL disk guard; TPM precheck; arch-aware mirror probe); autoinstall (tmpfs 48-digit keyfile, clevis in late-commands for `tpm2 {}` and `tpm2+tang` with `thp` + dracut networking, initrd checks); recovery.bin; generations and `/bootpart`; `os.apply` (fetch → closure H → userns nspawn apply with the fstab rewrite and scaffolding removal → initrd gate → one-time boot → booted-generation check → commit); firstboot plus the release pipeline (tarball + minisig, `install.sh`, reconcile unit, `os mark-last-good`); watchdog, emergency reboot, commit deadline; zram; reconciler | QEMU arm64 UEFI on NVMe (swtpm, Tang container): unattended first boot in both TPM modes. Tang down → `tpm2+tang` won't unlock; the box reboots about every 8 min and unlocks once Tang is back. A typed recovery key unlocks. Late-commands exit 0 in every mode, and `mountpoint -q /dev/pts` and `mountpoint -q /sys/fs/cgroup` still succeed in the live installer afterwards. Two disks with the same `ID_SERIAL` abort before storage. Installer logs persist (`/var/log/installer/installer-journal.txt` exists) with no `$6$` anywhere under `/var/log/installer`. Seed rejects hostname, https and public-IP Tang URLs (unit test). No `crashkernel=` in `/proc/cmdline`. Two consecutive `os.apply` runs (gen-1 → gen-2 → gen-3) each boot the new generation, checked via `/proc/cmdline`; neither leaves a grub diversion or `policy-rc.d`. A gen-2 whose closure upgrades `linux-image-*` and `systemd` passes the initrd gate and commits in both TPM modes. Three apply + reboot + commit cycles in a row (one a kernel upgrade) prune gen-1; then current cold-boots and a forced fallback to previous boots, both with `/boot` = their own `gens/gen-N` and `/lib/modules/$(uname -r)` present. With no console input, breaks inside GRUB, in the initrd (clevis removed) and in fstab, a unit that blocks boot forever, and QMP power cuts during apply all fall back to gen-1. BIOS: an amd64 VM in GitHub KVM CI, or the old PC. **Old PC in week 2.** |
| 3 | Firewall (add-only load, normalized hash, set checks, `fwcheck` every 60 s, reserved ports, conntrack, special-purpose sets, static confined set); qgroups (`2/0`, CAS cap); auditd (durable ACK with per-subject taint epochs and workspace writers, taint write rules, sequence-named segments, disk-full mode); rootd resolver (resolved Varlink → nft sets) and `Type=notify` refill; rootd skeleton plus sealing; packaged ntfy config. v5.3: auditd never deletes taint rows; `taint.get` returns the holder kind (B) | Firewall altered → agents won't start. auditd down → no effect. A broker can't reach any IP that rootd didn't resolve. A taint clear sent on proxy.sock or agentboxd.sock is rejected and the subject stays tainted. Disk filled → auditd still ACKs `taint.clear` and `agent.remove`. A torn tail, a backward clock step across midnight and a crash mid-seal don't stop ACKs, and `audit verify` passes. Firewall reload and reboot keep the sets, and user managers start cleanly. `nft flush ruleset` → table restored within 60 s, with an alert. ntfy running as any uid other than `_ntfy` → agents won't start. 200 root loopback connections to `127.0.0.1:43100` all succeed. A keys flow survives element expiry and is cut when its entry is removed. v5.3: A taint row survives `taint.clear` with its epoch incremented; `taint.get` names `task` or `session` for each writer. |
| 4 | Op registry + binders + codegen + bijection (all bus and memory ops, `reversible`, `taintsOutput`, audit classes); gate; socket inventory as code (tmpfiles); fuzzers (JSON-RPC, WebAuthn, pkt-line, HTTP, nft JSON). v5.3: denial codes table and codegen, `ops.Deny`, `gen/denial.v1.json`, the in-task check, ULID ids, the DENY sink check (C); batch and quote registry fields, the three schemas, Cedar actions, golden lists (D); the `memory.write` title as hash class (B) | Mismatch → refuse to start. Socket modes match the inventory. A record with a `drop` field or an unhashed `hash` field → NACK, and no effect. 24 h fuzzing clean. v5.3: C-G1, D-G1, D-G2. |
| 5–6 | Accounts (`ids` table, uids `70000+N`, sub-id blocks, qgroups `1/N` under `2/0`, nested-subvolume refusal); task launcher (rootd provenance and per-task dirs, ephemeral HOME, `--rm`, `--cgroups=split`, seccomp without btrfs ioctls, stdin, limits, `task.stop`, gate retries); session-home attach (control-file lockdown, output filter, token scan). v5.3: Go task env, quiet npm and pip, `go.private.set`, Go in the image (A); HTTP-aware forwarders, `agentbox why`, the proxy env, `--dns=none`, the fixed lines, the witness FIFO (C) | A task writes Claude/Codex hooks and MCP config, and the next task is unaffected. A task tainted mid-run makes every concurrent task on its workspace tainted, and the next task starts tainted. A task plants a `.claude/settings.json` SessionStart hook, a `.mcp.json` server and `.git/hooks/pre-commit`: attach is refused until `--ack-control-changes`, then attach plus `git commit` runs none of them, and session-home settings stay unchanged; a planted token copy is caught by the post-attach scan. Escape attempts via user units or containers.conf fail. A task that traps SIGTERM and forks `sleep infinity` leaves no process in its unit cgroup and no `libpod-*.scope` under `user@<uid>.service` within 20 s of timeout or `cgroup.kill`. Cancel a running task: within 5 s its unit is gone and its sockets refuse, also with auditd stopped. Restarting each broker mid-task doesn't break the running task. Inside a task, a python3 `ctypes` `ioctl(BTRFS_IOC_SUBVOL_CREATE)` on `/workspace` fails with `EOPNOTSUPP`, also with `0xdead00000000` OR'd into cmd; `cp --reflink=auto` still works. An agent at its limit gets `EDQUOT` while auditd still writes. A nested subvolume made on the host makes `workspace.snapshot` refuse with `NESTED_SUBVOLUME`. Removing the highest agent and adding a new one gives a higher N and an unused sub-id range. 20 consecutive launches each add under 300 ms of bridge overhead, open exactly one `login` session, and run no `update-motd.d`. v5.3: A-G1, A-G2, C-G2. |
| 7–8 | Proxy; keys (request validation, reservations against the registered trace, server-tool taint, local-LLM endpoint and field allowlist, dirty-instance recycle); git (local hooks, `remotes`, `repo.push`, `gh.*` ops with op markers, ref, commit and merge taint, push size caps); pinned dialing. v5.3: the proxy's Go module cache, the taskrun filter, `data/cache/<agent>`, the service btrfs filter (A); proxy, keys and git denial formats, dial budgets, per-agent day shares, the git 404 floor (C) | Rebinding, raw IP, UDP, IPv6, LAN, metadata and redirect attempts fail. An allowlisted name is refused when it answers with the box's own address (including its SLAAC IPv6), a LAN host's global IPv6, `192.168.x`, NAT64-wrapped `192.168.x`, `240.0.0.1`, or an `/etc/hosts` entry. No credential anywhere in a task. Remote writes happen only via registry ops. A push or PR to an unregistered remote, to another agent's remote, or of project A's OID to project B's remote → refused. Each of these gets 403 from keys: a URL image, a URL PDF, `mcp_servers`, an OpenAI http `image_url`, an `input_image` URL, `input_file` with `file_url`, and an unknown block type. A recorded Claude Code session and a recorded Codex session replay with 0 rejections. `/slots`, `/props` and extension fields never reach llama-server. After a tainted request, an untainted request is answered only by a restarted instance. A clean agent that fetches a tainted ref is tainted before the first pack byte. A clean agent that pushes an OID from a tainted pusher needs a signature. Merging a tainted branch taints main. Kill rootd between a comment POST and RESULT → reconcile finds the marker and writes RESULT, with no second comment. A `secret.set` value is absent from audit and journald. `repo.push`, `gh.pr.create` and a keys `POST /v1/messages` succeed, and the keys and git `counter drop` counters stay at 0 during the run. v5.3: A-G3–A-G14, C-G3, C-G4. |
| 9–10 | Cedar (generated actions, executor-scoped ownership, Deny on evaluation errors, strict policy validation in CI, golden tests, coordination capabilities); rootd floor, binders, pending state machine, ask caps, nonce txn, execution re-checks with `taintEpochs`, `task.start` provenance, push policy, approver revocation; CLI SSHSIG signing on the laptop and the approval renderer (§5.4); approvald + WebAuthn exact-origin + serve-config check + passkey registration. v5.3: DEPUTY HOST line, `HUMAN_ONLY`, `agentbox egress allow` (A); `workspaceBindable`, `workspaceBound`, the two policies (B); Cedar and floor mapping, owner-scoped resolution, reply floors, `pending.deny`, the witness check, `agentbox task show` (C); the ask budget, `ask.quote`, `ask.status`, `ask.batch`, the match key, the strike list, recon alerts, the daemon pool (D) | App. D policies pass strict validation against the generated schema. Race, replay and argument swap fail. A branch moved after approval → merge refused. A phone attempt at a CLI-only class → refused. A phone approval of `gh.pr.comment` or `gh.issue.comment` → refused. A signature with the wrong namespace → refused. Revoking a key → its approved, unexecuted ops become `denied`. An expired or already-approved P → `approval_stale`. A signer removed after approval → refused. A 4th open ask in one task → denied. Tainted T1 and clean T2 of one agent run at once and T1 writes a file: T2's `repo.push` then needs a signature, and an approval T2 got before T1's first taint is NACKed at execution. Repeated untrusted CONNECTs by a tainted task NACK none of its pending approvals. A Cedar context missing `tainted`, or a missing entity → Deny. Control and bidi payloads in any string field leave the bound-field lines byte-identical. approvald calling any method outside its three → refused. An unconfirmed or contested passkey can't approve. A handler mounted at `/x` on `:443` → phone approvals refused. A P containing `<img onerror>` renders as text and runs no script. A client posing as agentboxd calls `task.start` with a forged chain and no parent, then `repo.push` → pending, not Run. v5.3: A-G15, B-G1, B-G2, C-G5–C-G7, D-G3–D-G10, X-G1, X-G2. |
| 11–12 | Apps (pods, CAS builds, ingress bridge, exposure off `:443`), `file.write`, `os.*` ops (`os.update` delta, per-action protected floor, protected units, binding admission, CAS cleanup, OS lock and base binding, atomic grubenv writes in rootd (the 09_agentbox committed fallback landed in week 1 day 4, `be318d0`), service-state snapshots, shim revocation check), workspace ops (snapshot taint), onfailure + decide (separate instance, labels untrusted). v5.3: snapshot taint at RESULT, restore moves the epoch, per-workspace serialization (B); per-owner app names (C) | A context changed after approval doesn't build. Symlink and hardlink races fail. Protected-package golden tests: a kernel upgrade from `resolute-security` passes; an `nftables` removal pulled in by a dependency, a downgrade, and a third-party repo offering a higher `systemd` are all rejected. A nightly closure with a kernel or openssh upgrade commits. A closure outside the update delta waits for a CLI signature. Disabling nftables is rejected even when signed. An oversized closure or a second pending plan from one agent is refused before any download. A tainted agent that requests repeated large installs, or pushes multi-GB packs, can't stop auditd ACKs; `taint.clear` still executes. A dpkg base changed after approval → `stale_base`, nothing installed. A second `os.apply` during boot-once → `busy`. Truncating `grubenv` to 0 bytes boots the committed generation with no console input. A pruned generation no longer appears in `grub.cfg`. A gen-2 that migrates ntfy's schema, then fails health, falls back with ntfy state restored. v5.3: B-G3. |
| 13–14 | Bus (capabilities, `skills:` claims, atomic transitions, advisory leases, sticky and read taint, reserved `agentbox.dev/` metadata, restart reconcile, cancel cascade, bound `taint.clear`) + memory (lifecycle, quarantine release, read taint). v5.3: depcheck and the dependency report, the purge in `taint.clear`, the attach dependency gate (A); workspace-bound memory, decoupled release, cap, staleness bound, digest, attach exclusion and scan (B); bus and memory codes, bus ULIDs (C); ask grants and the trace rollup (D) | A delegated chain completes. Deputy amplification is denied. A poisoned fact never reaches instructions. A quarantined, forgotten or expired fact never comes back from `memory.read`; another agent's episodic view is denied. Reading an approved but tainted fact taints the reader. A clean parent that reads a tainted child's result is tainted before any byte arrives, and its `repo.push` then needs a signature. With auditd down, bus and memory reads of tainted data fail. A tainted write to `agent/<self>` from an attach session, or to a shared scope, gives 1 quarantine row, 0 asks and 0 committed rows (a task executor's own-scope write binds instead, B-G4). A file written after `taint review` is not cleared. A tainted task snapshots, deletes its injected files, then `taint.clear` runs; restoring that snapshot re-taints the workspace, a phone approval is refused, and the review diff base is the `clean-baseline`. Two agents race to claim one `skills:` task: exactly one wins, and an agent without the skill is denied. A forged `agentbox.dev/provenance/v1` key in Artifact or Part metadata is stripped, never shown, and changes no gate outcome. Cancel a running T42 that has a pending `repo.merge` and one child: within 5 s the merge approval is refused, the child is canceled and its lease is released; cancel on a completed task returns `TaskNotCancelableError`. A killed task's lease is reclaimed after its TTL. Restarting agentboxd mid-task still delivers the result; a task that ended during the outage is marked failed, and its leases are freed. After `memory.purge`, a grep of `audit/` and the shipped copy finds no fact body. v5.3: A-G16–A-G18, B-G4–B-G12, C-G7 (rerun), C-G8, D-G11, X-G3–X-G5. |
| 15–16 | Benchmark (30 tasks with deterministic graders, 20 injection, 10 poisoning, 10 deputy, 10 OS rollback, 10 approval-drift, including injected decide labels that understate the op); external threat-model review; signed release. v5.3: the benchmark on the baseline mix; behavior metrics | ≥90% of stock-Ubuntu task success. 0 exfiltrations. 0 floor bypasses. **At most 1 ask per delivered change, plus 1 per new egress host.** One PR is one change: its push and PR go out as one `ask.batch`, one signature. So is one push plus its replies to one PR (`push+reply`, private remote). An issue comment, a deploy, a rollback, a tainted config `file.write` and an os-class op (`workbench.add_package`) are one change and one ask each. Each new host is one `net.allow_domain` ask. A read-only task makes 0 asks unless it adds a host. The 30 graded tasks follow the baseline mix of `PROPOSALS-v5.3.md` section 2.7 (27 of 30 deliver something), on private remotes. With any one v5.3 feature off (Go cache, bound notes, denials), asks are not lower than with it on. Reported, not gated: asks per 100 tasks (model 108.7; v5.2 model 182.7) and ops reviewed per 100. An injected label never changes P, H, the class or the channel, and never appears in ntfy text. v5.3: A-G19, B-G13, C-G9, D-G12. |

## 16. Out of scope for v1 (decided)
- microVM tasks; UKI/PCR 11 sealing
- external A2A binding; multi-node
- shared caches between tasks, except the read-only Go module cache (§6.2); npm, PyPI and crates caches until their clients meet the §6.2 join rule; shared build caches; a private module proxy as the Go cache upstream
- batch shapes beyond `push+pr` and `push+reply`; reply batches on an internal or public remote; an egress (`net.allow_domain`) batch; agent-wide values in `ask.quote` or `ask.status`; a quote reason that tells a custom policy, push-policy coverage, spend or decide apart from the floor default; closing the write-capable allowlisted-host residual (v2: the GET-only package broker)
- embeddings; default OTel export
- GUI computer use
- LAN app exposure; agent `/etc` writes
- PIN-based TPM unlock; GitHub writes other than the listed `gh.*` ops
- a release-update op (§3.2)

## 17. Review resolution
- **Round 1 (v2):** all 32 findings addressed in v3.
- **Round 2 (v3):** items addressed in v4. Codex's round-3 check confirmed 11 of them fixed. Its PARTIAL and WRONG verdicts are resolved below.
- **Round 3 (v4 → v5):**

| Finding (round-3 severity) | v5 resolution |
|---|---|
| Approvals don't bind immutable effects (critical) | Registry binders put OIDs, CAS digests, the closure and `.deb` hashes in H; compare-and-swap and full re-checks at execution (§5.2, §3.3) |
| External writes bypass rootd (critical) | No write credentials in tasks; `repo.push` and `gh.*` registry ops on one-shot capabilities; `github-mcp-server` and PAT removed (§4.3, §6.3) |
| Shared HOME defeats task isolation (#11 WRONG, high) | Ephemeral tmpfs HOME per task; separate session-home never mounted into tasks; no shared caches (§4.2) |
| nspawn can modify the host (#15 / B12, high) | Unprivileged fetch, then userns + id-mapped nspawn with a private network and only the generation's `/boot`; GRUB/ESP updated post-commit on the host (§3.3). **Codex's "disposable VM" was not adopted:** a user-namespaced nspawn with no network, no ESP and only signature-verified packages is the stated bound for the build process, not for the code the trial boot runs (§10 Offline OS build compromise). |
| Encryption modes not build-ready (high) | Tang `thp` pinned ✓; initramfs networking specified; `tpm2-pin` removed, and the attended `passphrase` mode is dropped too (it has no headless-safe way to deliver the secret). `tpm2` is kept as "disk-removal protection only", since it is strictly better than `none` and labeled exactly. `tpm2+tang` is recommended. **Reversed in round 5:** the round-3 note kept PCR 7 for `tpm2`. v5.2 binds the TPM share with no PCR policy, because PCR 7 is reproduced by any Microsoft- or Canonical-signed medium, adds nothing against the documented threats, breaks unattended unlock after dbx, SBAT and Secure Boot updates, and clevis 20 defaults to the sha1 bank (§3.1). To revert: `{"pcr_bank":"sha256","pcr_ids":"7"}`. |
| No app ingress bridge (#3, high) | `systemd-socket-proxyd` (socket-activated TCP) → app `in.sock` bound by the pod shim → app loopback, with ownership and teardown specified (§1, §2.1) |
| Firewall hash unstable; DNS blocked (high) | `nft -j -s` normalized hash plus per-set checks; rootd resolves through resolved Varlink; no agentbox uid except ntfy uses IP DNS (§6.1) |
| nft not independent (high) | Sub-id blocks confined by a static set (rootd never inserts into it; fwcheck compares it to a constant); broker destinations restricted to rootd-filled TTL sets (dnsfill removed in v5.1) (§6.1) |
| Socket ACLs incomplete (#28 WRONG, high) | Complete inventory with modes, peers, no fd passing, atomic revocation (§2.1) |
| WebAuthn display trust (high) | Exact Origin, crossOrigin and topOrigin checks; phone limited to low-risk classes, everything high-impact CLI-only (§5.4) |
| INTENT durability (high) | ACK after `fdatasync` plus taint commit with `synchronous=FULL`; reconcile by op ID (§9) |
| Cedar breaks delegated chains (high) | Coordination ops (incl. `bus.inbox.read`) authorized for the actor via delegation capabilities; originator as Agent or Human; atomic SQL transitions; ownership checks use `context.executor`, so ancestors never deny the executor's own resources; 2- and 3-agent golden tests (§5.1, §7, App. D) |
| #5 `app.rollback` and GitHub effects outside registry | Both are registry ops now (§5.3) |
| B16 build-context race | Read-only CAS snapshot before hashing; build only from CAS (§5.3) |

- **Round 4 (v5 → v5.1):**

| Finding (round-4 severity) | v5.1 resolution |
|---|---|
| H omits args (critical) | H covers name, canonical args, bound inputs and the taint epochs; rootd executes the stored object (§5.2) |
| dnsfill controls its own confinement (high) | dnsfill removed. rootd resolves through systemd-resolved Varlink over AF_UNIX ✓ and is the only writer of the nft sets (§6.1, App. B). |
| Cross-task control files; tmpfs HOME owner (high) | tmpfs `U=true` ✓; Claude `--setting-sources user --strict-mcp-config` ✓; git hooks and fsmonitor disabled by env config; sticky taint plus control-file review (§4.2) |
| nspawn can't write generation `/boot` (high) | `:rootidmap` on the boot bind (§2, §3.3). Round 5: the rebuilt initrd can't probe disks, so `x-initrd.attach`, `90-agentbox.conf` and `rd.luks.uuid` force unlock, and the §3.3 initrd gate checks every gen-M initrd before any reboot. Gated by a kernel + systemd upgrade test in both TPM modes (§15). |
| Passphrase recovery undefined (high) | `passphrase` mode removed; modes are `tpm2+tang`, `tpm2` and `none` |
| App sockets can't be created (#3 WRONG, high) | Separate setgid `in/` and `egress/` dirs, owned by the creating service (§2.1) |
| "Registry-only writes" overclaimed (high) | Narrowed to *credentialed* writes; generic egress to allowlisted hosts is a stated limit (§0.5, §6.2) |
| Phone scope too broad (high) | Phone allowed only for registry ops flagged `reversible` (§5.4) |
| Taint TOCTOU (high) | Taint applied at the proxy's INTENT, before any data flows; op INTENT is ACKed only if the taint epochs are unchanged (§5.2, §6.2) |
| Delegation mirror absent (high) | Corrected in round 5: the rootd `delegations` row is the provenance source for `task.start` (parent, executor, trace); rootd derives chain, trace and child taint itself (§4.2). Coordination transitions are enforced only inside agentboxd and are lost if agentboxd is compromised (§5.2, §7). |
| Keys broker endpoint scope (high) | Method/path allowlist, schema validation, server-side budget (§6.3) |

- **Round 5 (multi-agent audit, v5.1 → v5.2).** 154 findings: 82 on the week-1 code (C-*), 72 on the architecture (A-*). The code findings were fixed by the week-1 patch or its follow-up, resolved by a spec edit, or deferred to a week; `LEDGER.md` gives each one exactly one end state. Every architecture finding is resolved in the text below and scheduled in `PLAN.md` at the week that builds its component. Where two findings proposed different fixes for the same gap, the merge is noted.

| Finding (round-5 severity) | v5.2 resolution | Week |
|---|---|---|
| A-arch-control-plane-00: undefined taint subject; concurrent tasks share a workspace (high) | Effective taint = task OR workspace OR chain OR fetched refs; auditd taints every workspace a tainted holder mounts, in the same transaction; H binds `taintEpochs` (§5.2, §5.3). **Merged with bus-memory-audit-02 and runtime-network-11.** The per-workspace lease that serializes tasks was not adopted: a self-delegating parent that waits on its child would deadlock, and live workspace taint closes the same hole. Deferred to v2: per-commit taint provenance in agentbox-git. | 9–10 |
| A-arch-control-plane-01: stated agentboxd compromise bound false (high) | Bound restated with the exact unsigned ops a compromised agentboxd keeps; leases removed from rootd's re-check list; v2 `agentbox-gate` path (§0.4, §5.2, §10). **Merged with bus-memory-audit-04**, which also moves chain and trace derivation into rootd. | 9–10 |
| A-arch-control-plane-02: snapshot/restore launders taint (high) | Snapshots carry taint (`snap:<id>`) and epoch; restore re-taints the workspace; tainted restore is CLI-only; same agent and workspace only; review base is a rootd-only `clean-baseline` (§5.3, §5.4, §7, App. E) | 13–14 |
| A-arch-control-plane-03: admin ops unsigned; key location undefined (high) | Approval key stays on the laptop; SSHSIG with namespace `agentbox-approve-v1`; approver #1 from the seed key; `approver.remove`/`passkey.revoke` with cleanup of approved P; admin root-equivalence stated as a residual (§5.3, §5.4, §10) | 9–10 |
| A-arch-control-plane-04: approval rendering lets controls and bidi through (high) | H re-check, registry templates with bound fields first, allowlist escaper, typed confirmation, Go-side diffs; attach relayed through a rootd output filter with no fd passing (§2.1, §4.2, §5.4) | 9–10 (filter: 5–6) |
| A-arch-control-plane-05: Cedar denies delegated children their own resources (high) | Ownership predicates use `context.executor`; inbox is a coordination op; 2- and 3-agent golden tests (§5.1, §7, App. D) | 9–10 |
| A-arch-control-plane-06: protected-package floor vs nightly updates (high) | `protectedPackages` list; `os.update` as its own op with a signed delta; protected units (§3.3, §5.3, App. D). **Merged with boot-storage-12's per-action floor.** | 11–12 |
| A-arch-control-plane-07: approvald socket missing; passkey registration hijackable (medium) | `approve.sock` with three calls; rootd refuses to start if `agentbox-approve` is an admin; CLI-opened 120 s window after an approvald restart; CLI SSHSIG confirm; window-swap residual (§2.1, §5.4, §10) | 9–10 |
| A-arch-control-plane-08: approval origin shared with apps; P rendered as HTML (medium) | approvald is the only handler on `<box>:443`; ntfy and apps on other ports or Services; app.deploy rejects `:443`; serve-config check; textContent-only page with a hash CSP (§5.4) | 9–10 |
| A-arch-control-plane-09: phone approval of GitHub comments (medium) | `gh.*` writes CLI only; `reversible` flag checked against rollback coverage at startup; rootd enforces it (§5.1, §5.3, §5.4) | 9–10 |
| A-arch-control-plane-10: untainted reads of `app.logs` and approved memory (medium) | `taintsOutput` flag applied at INTENT; fact taint immutable and separate from review state; only `taint.clear` cleans a fact; "reversible" limited to data (§5.3, §5.4, §8, App. F) | 13–14 |
| A-arch-control-plane-11: push and PR targets unbound (medium) | `remotes` registry (`remote.set`); OID must be in that remote's bare repo; `remote_url` and `gh_node_id` in H; REST re-check; token scoped to registered repos (§5.3, §6.3, App. E) | 7–8 |
| A-arch-control-plane-12: cedar-go skips erroring policies (medium) | Deny on any evaluation error; schema validation of request and entities; typed context; explicit policy IDs (App. D, §14) | 9–10 |
| A-arch-control-plane-13: pending transaction and state machine gaps (medium) | Checked `RETURNING` row counts; `executing`, `refused`, `failed`, `indeterminate` states; expiry and signer re-checked at execution; integer time; ask caps (§5.2, §5.4, App. E) | 9–10 |
| A-arch-control-plane-14: binding fills `@var_lib_agentbox` (medium) | `--print-uris` sizing; binding admission caps; CAS subvolume quota; CAS cleanup (§3.2, §3.3, §5.2, §11) | 11–12 |
| A-arch-control-plane-15: decide labels shape approvals (medium) | Labels advisory, add-only, never in P, H or ntfy; P rendered first; no sort or bulk accept in `memory review` (§5.5, §8, §10) | 11–12 |
| A-arch-control-plane-16: tainted own-scope `memory.write` Ask vs quarantine (low) | Cedar unchanged; agentboxd carries out an Ask on `memory.write` as quarantine; release by `memory review`, re-checked with `approved=true`; not counted as an ask (§5.3, §8) | 13–14 |
| A-arch-bus-memory-audit-00: reads launder taint (high) | READ-INTENT ACKed before any byte, fail closed when auditd is down; taint columns on messages, task results and facts; commit taint for `repo.push`; epoch fence on trusted `memory.write`; agentboxd-mediated reads stated as a residual (§5.3, §6.3, §8, §9, §10). **Changed on merge with control-plane-10:** an approved fact keeps its taint, so reading it still taints the reader. | 13–14 (git: 7–8) |
| A-arch-bus-memory-audit-01: taint sources misclassified (high) | `app.logs` taints; read taint rule; journal-reading triage taints; agentbox-unit triage gets a generated struct only; merge propagates ref taint; fact taint = max of sources (§5.3, §6.3, §7, §8, App. F) | 7–8 (merge), 13–14 |
| A-arch-bus-memory-audit-02: workspace taint only at task start; single-epoch fence; re-taint storms (high) | `writers` table; per-subject `taintEpochs`; epochs move only on clean → tainted and on clear (§5.2, App. E). Merged with control-plane-00. | 3 (auditd), 9–10 |
| A-arch-bus-memory-audit-03: `taint.clear` unbound (high) | `taint.clear{subject, contentId}` signed, CLI only, CAS on epoch; refuses live writers and `task:*`; cleared content = reviewed snapshot; snapshot taint on restore (§5.3, §7, App. E) | 13–14 |
| A-arch-bus-memory-audit-04: rootd takes provenance from agentboxd (high) | rootd derives chain, trace and child taint from a live parent or a human request; other starts are tainted; push policy; delegation row corrected (§4.2, §5.2, §5.3, §7, §17 round 4) | 9–10 |
| A-arch-bus-memory-audit-05: no taint write-authorization rules (high) | Producers may only raise taint; auditd computes `tainted` and epochs; clears only from rootd as a `taint.clear` RESULT; auditd and broker compromise rows (§0.7, §9, §10) | 3 |
| A-arch-bus-memory-audit-06: cancel and task end leave everything running (high) | `task.stop` with ordered teardown, pending denial and child recursion; cancel only from non-terminal states; cascade; child deadline ≤ parent's (§4.2, §7, §9, §11, App. C, App. E) | 5–6, 13–14 |
| A-arch-bus-memory-audit-07: one unquota'd volume holds audit and fillable stores (high) | `@var_lib_agentbox_data` subvolume (already in the seed); parent qgroup `2/0` with a reserve; plan size cap; push and row caps; auditd disk-full mode (§3.2, §4.1, §6.3, §8, §9, §11). **Seed decision recorded:** the seed's separate data subvolume is enough for the week-2 old-PC install; no reinstall needed for week 3. | 3 |
| A-arch-bus-memory-audit-08: leases never reclaimed; no fencing (high) | Leases advisory, reclaim on expiry, epoch fencing token, holder-only heartbeat and release; only `repo:<p>:main` kept; removed from rootd's re-check (§0.4, §5.2, §7, App. D, App. E) | 13–14 |
| A-arch-bus-memory-audit-09: secrets and bodies in immutable audit (medium) | Per-field audit classes; sink-side schema check; plaintext lifetime of `pending.op`; agentboxd reads audit only through a query call (§5.1, §5.2, §8, §9) | 4 |
| A-arch-bus-memory-audit-10: TEXT timestamps compared as strings (medium) | Every instant INTEGER Unix ms; STRICT tables; bound `:now_ms`; expiry also checked in Go (§5.2, App. E) | 9–10 |
| A-arch-bus-memory-audit-11: audit lifecycle breaks on clock steps, two writers, torn tails (medium) | Sequence-named segments; auditd sole writer with close/seal/open handshake; idempotent seal; appended `torn` record (§9, §11) | 3 |
| A-arch-bus-memory-audit-12: no rootd-owned id allocation (medium) | rootd `ids` table, rows never deleted; disjoint agent and app sub-id blocks; static confined set. **Merged with runtime-network-13**, whose uid and sub-id numbers were adopted (§4.1, §6.1, App. B, App. E) | 5–6 |
| A-arch-bus-memory-audit-13: memory lifecycle undefined (medium) | FTS holds active facts only; mandatory state and expiry join; `memory.forget` op; `memory.purge` admin; episodic views owner-scoped (§5.3, §8, App. D, App. E) | 13–14 |
| A-arch-bus-memory-audit-14: registry names don't match the spec (medium) | §5.3 lists every bus and memory op; `task.delegate` → `bus.task.send`; `memory.propose` → `memory.write`; strict validation in CI (§5.1, §5.3, §7, App. D) | 4 |
| A-arch-bus-memory-audit-15: claim board unrepresentable (medium) | Nullable `executor` plus `skill`; delegation recorded at claim time; admin-held skills (§7, App. D, App. E) | 13–14 |
| A-arch-bus-memory-audit-16: GitHub comments can't be idempotent (medium) | Op marker bound in H; reconcile by author plus marker; `indeterminate` and re-approval, never re-run (§5.2, §5.3, §10) | 7–8 |
| A-arch-bus-memory-audit-17: no mechanism behind "results delivered on restart" (medium) | Socket dirs survive restarts; re-bind from `task.list_live`; taskrun retries; restart reconcile (§2.1, §4.2, §7, §11) | 5–6, 13–14 |
| A-arch-bus-memory-audit-18: pending can't park reconcile outcomes (low) | `executing` before INTENT; `indeterminate` plus `op.resolve`; reconcile before listening; `synchronous=FULL` on all three DBs (§5.2, §9, §11, App. E) | 9–10 |
| A-arch-bus-memory-audit-19: provenance forgeable in nested metadata (low) | Reserved `agentbox.dev/` prefix stripped on every write; provenance read only from server columns (§7) | 13–14 |
| A-arch-bus-memory-audit-20: per-trace budgets have no enforcer (low) | rootd registers the trace per task; keys enforces it (§4.2, §6.3, §7, App. E) | 7–8 |
| A-arch-runtime-network-00: keys forwards vendor-side URL fetches (critical) | Closed top-level fields, block types and tool types; URL-bearing keys rejected at any depth; MCP connector rejected; beta headers filtered; vendor hosts never on CONNECT lists (§6.2, §6.3) | 7–8 |
| A-arch-runtime-network-01: attach runs workspace hooks (high) | `disableAllHooks`, user-only settings, read-only user settings, task git env, generated `CODEX_HOME`, control-change refusal, post-attach token scan (§4.2, §4.3) | 5–6 |
| A-arch-runtime-network-02: tasks create btrfs subvolumes (high) | seccomp profile partitioned on the btrfs ioctl type byte; full-mode quotas under `2/0`; nested-subvolume refusal (§4.1, §4.2, §11, App. C) | 5–6 |
| A-arch-runtime-network-03: timeout and `cgroup.kill` miss the container (high) | `--cgroups=split`, `Delegate=yes`, `KillMode=mixed`, `ExecStopPost`; ordered teardown with an empty-cgroup check (§4.2, §11, App. C) | 5–6 |
| A-arch-runtime-network-04: firewall reload wipes sets; races; unwatched flush (high) | Add-only `nft -f` load; rootd `Type=notify` refill from rootd.db; ordering after rootd; `fwcheck` every 60 s; `nftables.service` masked. Not adopted: an NFNLGRP_NFTABLES watcher (the 60 s check covers it with less code; residual in §10). (§6.1, App. A–C) | 3 |
| A-arch-runtime-network-05: Ubuntu's ntfy runs as `_ntfy` (high) | Packaged identity used everywhere; setgid socket dir; fwcheck asserts the unit's user (§2, §2.1, §6.1, §12, App. B) | 3 |
| A-arch-runtime-network-06: output chain has no conntrack (high) | Established original-direction accept; port rules on `ct state new`; TCP reset; reserved local ports; conntrack flush on revocation (§6.1, App. B) | 3 |
| A-arch-runtime-network-07: socket inventory can't be built (high) | tmpfiles 0711 parents, no `RuntimeDirectory=`; rootd-created setgid per-task dirs; services re-bind in place (§2.1) | 4, 5–6 |
| A-arch-runtime-network-08: "private ranges dropped" not in the ruleset (medium) | `private4`/`private6` sets, `fib daddr type local` drop, `allow_private` sets; DNS-only resolution flags; route check (§6.1, §6.2, App. B) | 3, 7–8 |
| A-arch-runtime-network-09: workspace skills load in the next task (medium) | `claude-settings.json` sets `disableAllHooks`, so skill frontmatter hooks don't run; skill text is a control path covered by workspace taint (§4.2, App. C) | 5–6 |
| A-arch-runtime-network-10: ntfy LAN-exposed, outside the firewall gate (medium) | `listen-http: "-"`, `auth-file`, firewall drop-in with `fwcheck`; no loopback accept; rootd refreshes `ntfy_dst` every 5 min; DNS and ntfy.sh limit stated (§2, §6.1, App. B) | 3 |
| A-arch-runtime-network-11: sticky taint checked only at task start (medium) | Shared workspace subject in every task's taint set (§5.2, §7). Merged with control-plane-00. | 9–10 |
| A-arch-runtime-network-12: one llama-server crosses agent, taint and decide boundaries (medium) | Separate `agentbox-llm@decide` instance and uid; keys endpoint and field allowlist; dirty-instance recycle; decide friction-only (§2, §2.1, §5.5, §6.3, §10) | 7–8, 11–12 |
| A-arch-runtime-network-13: confined set clashes with sub-uid inserts (medium) | uids `70000+N` / `71000+M` outside DynamicUser; sub-id blocks at `0x70000000`/`0x74000000`; static confined set; fixed nspawn range `0x7F000000` (§1, §2, §4.1, §6.1, App. B, App. C) | 5–6 |
| A-arch-runtime-network-14: git/libcurl does its own DNS (low) | Pinned dialing: rootd answers feed a custom `DialContext` and git `http.curloptResolve` (§6.1, §6.3) | 7–8 |
| A-arch-runtime-network-15: each `-M` call opens a PAM login session (low) | One user-bus call per task; status and stop through cgroupfs; `pam_motd` skipped for `ag-*` (§4.2, App. C) | 5–6 |
| A-arch-boot-storage-00: `admin` is reserved (critical) | Default `boxadmin`; reserved and system-name check (§3.1, App. A) | 1 (code fixed) |
| A-arch-boot-storage-01: `umount -R` hits the live installer (critical) | `rslave` rbinds and a `private` `/bootpart` (§3.1, App. A) | 1 (code fixed) |
| A-arch-boot-storage-02: clones keep gen-1's `/boot` bind (critical) | Build copies from `gens/CUR` and rewrites exactly one fstab line; `/boot` binding in health; retention guard (§3.2, §3.3) | 1–2 (day 4) |
| A-arch-boot-storage-03: short disk serial documented (high) | Exact udev `ID_SERIAL`; disk guard as `early-commands[0]` (§3.1, App. A) | 1 (code fixed) |
| A-arch-boot-storage-04: nspawn-built initrd drops crypttab (high) | `x-initrd.attach`, `90-agentbox.conf`, `rd.luks.uuid`, host-side initrd gate (§3.1, §3.3) | 1–2 (day 4) |
| A-arch-boot-storage-05: fallback gaps hang the box (high) | crypttab `timeout=300s`; emergency/rescue drop-ins; commit deadline unit; watchdog driver (§3.3) | 1–2 (day 5) |
| A-arch-boot-storage-06: commit doesn't check the booted generation; scaffolding persists (high) | Booted-generation check; scaffolding removed by trap and checked on the host; `grub.cfg` id check; retention guard (§3.3) | 1–2 (day 4) |
| A-arch-boot-storage-07: PCR 7 breaks unattended unlock; shim step can revoke rollback targets (high) | No PCR policy (decision above); `is-not-revoked` check before the post-commit shim (§3.1, §3.3, §11) | 1 (code fixed), 11–12 (shim) |
| A-arch-boot-storage-08: empty grubenv boots entry 0 (medium) | Atomic grubenv replace; `committed` file fallback in `09_agentbox`; oldest-first listing (already in the template) (§3.1, §3.3) | 1–2 (day 4: `09_agentbox` fallback), 11–12 (rootd atomic writes) |
| A-arch-boot-storage-09: closure bound without its base; no OS lock (medium) | `baseGen`, `baseDpkg` and end state in H; `stale_base`; rootd `os_lock` (a rootd.db row, not a bus lease) (§3.2, §3.3, §5.2, App. E) | 11–12 |
| A-arch-boot-storage-10: service state migrates forward on a failed gen-M (medium) | Pre-boot snapshots of `@var_lib_ntfy` and `@var_lib_tailscale`, restored by reconcile on fallback; release-update op must be A/B (§3.2, §3.3) | 11–12 |
| A-arch-boot-storage-11: Tang hostname can't resolve in the initrd (medium) | `http://` private IPv4 literal enforced by the seed. Not adopted: `systemd-resolved` in the initrd (more wiring, adds DNS spoofing exposure) (§3.1) | 1 (code fixed) |
| A-arch-boot-storage-12: floor blocks security upgrades (medium) | Per-action, per-origin floor for every closure (§3.3) | 11–12 |
| A-arch-boot-storage-13: non-A/B updaters enabled (medium) | apt timers masked (in the template); fwupd metadata only; snapd policy decided in week 2 (§3.3) | 1 (code fixed), 2 |
| A-arch-boot-storage-14: firstboot runs once (medium) | Retry every 60 s, idempotent steps, visibility stated (§3.1, §11, App. A) | 1 (code fixed) |
| A-arch-boot-storage-15: nspawn bound overstated; build-controlled file names (medium) | §10 row narrowed; trial-boot residual; name filters in `09_agentbox` (in the template) and at Build (§3.3, §10) | 1–2 (day 4) |
| A-arch-boot-storage-16: kdump can't save a dump (low) | `kernel-crash-dumps: {enabled: false}` (in the template); purge `kdump-tools`; protected package (§3.3) | 1–2 (day 5) |
| A-arch-boot-storage-17: scrub runs before the logs exist (low) | Scrub the live `/var/log/installer`, then mount `@var_log` on `/target/var/log` last (§3.1, App. A) | 1 (code fixed) |

- **Round 6 (v5.2 → v5.3, agent ergonomics; owner decision 2026-11-20).** Five designs, each red-teamed and scored by three judges, then merged in `PROPOSALS-v5.3.md`: four ergonomics designs (A–D) and a delivery lane (E). The goal was a box agents can work in, with no §10 control weakened. The owner adopted A–D and rejected E. v5.3 changes:
  1. **A. Read-only Go module cache** in `agentbox-proxy`, one store per agent, filled only from files the Go checksum database signed, used only after two taint records, and purged by every `taint.clear` (§0.6, §2, §4.1, §4.2, §6.2, §7 Dependency report).
  2. **B. Workspace-bound memory notes:** the tainted-read tier as its red team narrowed it. Reads taint exactly as before. Only own-scope `memory.write` and `memory.forget` by automated tasks run without a human, bound to the tainted workspace epoch, and they end at the next clear or signed restore (§0.6, §5.1, §5.2, §5.3, §8).
  3. **C. Structured denials:** one constructor, 36 codes, native surfaces, `agentbox why`, asks that survive a normal task end, and a rootd witness (§0.8, §5.6).
  4. **D. Visible ask budget:** a per-task budget, `ask.quote`, `ask.status`, and `ask.batch` with two shapes, `push+pr` and `push+reply` (§4.2, §5.2, §5.3, §5.4).
  5. **Approval target** (§15 weeks 15–16, §5.4): "at most 5 asks per 100 tasks" becomes "at most 1 ask per delivered change (push and PR batched into one signature), plus one per new egress host". The floor alone gives 91 asks per 100 delivery tasks with no taint at all, so the old target failed by design. PLAN rows 15–16 cite the same target.
  6. **§3.3 step 6:** a failed trial re-asserts `saved_entry` to the committed generation. It replaces the earlier "never set `saved_entry`", which let a split grubenv keep a failed trial as the default and strand the box. The code does this since the power-cut fix.
  7. **Rejected (owner, 2026-11-20): E, the delivery lane.** It cuts asks only from about 109 to about 91 per 100 tasks with 3 agents, it needs a GitHub Enterprise Cloud org and a CI-less mirror repo, and 12 red-team attacks were still open. It stays in `PROPOSALS-v5.3.md` section 7 as a record; none of it is in this file.

| Proposal | Red-team attacks | Closed in the design | Stated, not closed | Weeks |
|---|---|---|---|---|
| A. Read-only Go module cache | 13 | 11, plus the deputy-host exposure regression | the deputy channel itself (pre-existing); checks turned off with a compromised proxy (new; accepted as bounded) | 5–6, 7–8, 9–10, 13–14 |
| B. Workspace-bound memory notes | 11 | 7 | 4, all pre-existing: two write-capable-host paths, the deputy GET path, broker taint omission | 3, 4, 9–10, 11–12, 13–14 |
| C. Structured denials | 4 | 3, plus the `KEYS_BUDGET` cross-agent bit | `BUSY`'s one box-wide bit (pre-existing) | 4 to 15–16 |
| D. Ask budget, quotes, batches | 9 | 7 | 2, both pre-existing: write-capable hosts; the shared per-agent cap | 4, 9–10, 13–14, 15–16 |

**The bar for "closed".** An attack on a mechanism v5.3 adds is closed, or accepted as a bounded residual that §10 states with its argument. A v5.2 residual may stay open only if v5.3 doesn't widen it. These are the nine attacks stated but not closed. Attack numbers are rows of the threat tables in `PROPOSALS-v5.3.md` (sections 3.4, 4.4, 5.4 and 6.4).

| Attack | Kind | v5.2 basis | Why v5.3 doesn't widen it, or why it is bounded |
|---|---|---|---|
| A-1, B-3: data out through `proxy.golang.org` module paths | v5.2 | §10 "Exfiltration over allowed channels", residual "write-capable allowlisted hosts" (a deputy host is one; §0.5 limit) | The cache adds no destination. A fill or a live check sends `proxy.golang.org` only a checked path and canonical version that the task could send over CONNECT, and lists, `@latest` and checksum lookups still use CONNECT. Exposure narrows: deputy hosts are human-only, never in `common.list` and flagged at approval, and agents without them get `GOPROXY=off`. |
| B-2, D-1: data out through a write-capable allowlisted host | v5.2 | the same row and residual | No design adds an egress destination or an allowlist path. A bound note moves no byte off the box. `net.allow_domain` never batches, so each new host keeps its own signature with the typed host:port. |
| B-10: a bound note carries a token to a later task, which sends it to such a host | v5.2 | the same row, plus §0.6: the sticky-tainted workspace already outlives tasks | The note's only readers hold the same tainted epoch, and could read the same token from a file in that workspace. The way out is still a write-capable host, and v5.3 adds none. |
| B-9: a compromised proxy omits READ-INTENT, so a clean task commits a trusted fact | v5.2 | §10 "Proxy, keys or git compromise", residual "it can omit taint for content it delivers" | B's exemption covers only writes by tainted tasks. A laundered task is clean, so its write takes the v5.2 trusted path unchanged. For Go cache files A narrows the residual: the filter records a second taint. |
| C-2, its `BUSY` part: one box-wide bit between colluding agents | v5.2 | no §10 row. Each box-wide limit already returned a typed error: the box's 3 CAS-binding asks and the disk reserve (§5.2 Binding admission), the OS lock (§3.3) and the keys day budget (§6.3) | `BUSY` merges them into one bit with no sub-reason, and per-agent day shares remove the keys bit. Its one new cause, the daemon-ask pool, takes human-visible asks to fill, like the CAS-binding cap. §10 now states it. |
| D-3: one task uses up the shared per-agent cap and starves a sibling | v5.2 | no §10 row. §5.4 Ask caps: 20 asks per agent per 24 h, shared by its tasks | In v5.2 one task could make all 20 asks. Now one task makes at most its budget (default 3, at most 10). Only a task with the maximum budget, sending ten 4-member batches, can reach the new 40-ops cap alone. Availability only, and every ask is an ntfy push. §10 now states it. |
| A-11: an agent turns go's checks off, and a compromised proxy feeds it forged `.mod` or `.zip` files | new | none: the Go cache is new | Accepted as bounded (§10). It needs a compromised proxy plus task code that sets `GOSUMDB=off` or `GONOSUMDB`, which taskrun never does. Through the filter, the gate record taints the task before the first forged byte. Skipping the filter takes hand-built `/_cache/` requests, so the task already runs injected code, which is tainted unless a broker omitted that taint (row B-9). The forged code gains nothing that code lacks: every non-read, non-Safe op still needs a signature, and the only unsigned ways out are the hosts in the first two rows. The override lasts one task, and forged code left in the workspace is a dependency change at the next clear (§7). |

The merge also fixed four cross-design interactions (deputy-host erosion, conflicting deny rules, conflicting reason enums, alert feedback through the query call) and four v5.2 text faults: the §5.2/§5.3 restore-epoch contradiction, the snapshot-taint race, the §5.4/§4.2 open-ask contradiction, and the missing `HTTPS_PROXY` in App. C. The model gives 108.7 asks per 100 tasks on the baseline mix (v5.2: 182.7), now in one sitting per delivery; the floor of 91 doesn't move (`PROPOSALS-v5.3.md` section 2).

---
## Appendix A: seed core (`agentbox seed`, `tpm2+tang`, UEFI)
Rendered on 2026-11-20 from `internal/seed/user-data.tmpl` on `main` (`61acfc7`) with placeholder values. The template is the source of truth; it validates against the 26.04.1 `autoinstall-schema.json`, and every script passes `dash -n` (`hack/verify-seed.py`, `TestRenderedSeedsVerify`). Two long values are shown as placeholders, `<DISK_GUARD>` and `<RECOVERY_RSA4096_PEM_LINES>`: run `agentbox seed` for the exact text.

Verified ✓ by the round-5 fact checks: top-level `serial:` matches exact `ID_SERIAL` (B1); `size: -1` on the last partition, which subiquity fills to the disk end minus 1 MiB, GPT-backup safe (B2); `swap: {size: 0}`, load-bearing on btrfs with kernel 7.0 (B3); curtin writes crypttab field 3 `none` from `keyfile:` and never copies the key into the target (B4); the 48-digit key works with `clevis luks bind -k` (B5); the reserved-name list (B6); early-command files in `/run` survive to late-commands, and logs are copied after late-commands (B7); `09_agentbox` paths under the bind-mounted `/boot` (B8); dracut is the generator and clevis-dracut unlocks with field 3 `none` (B9); all seed packages are published for resolute/arm64 (B10); `allow-pw`, `swap`, `grub_device` and `keyfile` placement are schema-valid (B11).

```yaml
#cloud-config
# Generated by `agentbox seed` (ARCHITECTURE.md Appendix A). Public keys plus the admin password hash: keep it private.
# encryption=tpm2+tang boot=uefi
autoinstall:
  version: 1
  apt: {fallback: abort}
  kernel-crash-dumps: {enabled: false}
  identity:
    hostname: "agentbox"
    username: "boxadmin"
    password: "<yescrypt or sha512-crypt hash>"
  ssh:
    install-server: true
    allow-pw: false
    authorized-keys:
      - "<admin ssh-ed25519 public key>"
  early-commands:
    - "<DISK_GUARD>"   # exit 1 unless exactly one disk has ID_SERIAL=<DISK_SERIAL> and no other /dev/disk/by-id name contains it; logs every disk's ID_SERIAL
    - "M=http://archive.ubuntu.com/ubuntu; [ \"$(dpkg --print-architecture)\" = amd64 ] || M=http://ports.ubuntu.com/ubuntu-ports; curl -fsS --connect-timeout 10 --retry 10 --retry-delay 3 --retry-all-errors -o /dev/null \"$M/dists/resolute/InRelease\""
    - "test -c /dev/tpmrm0 || { echo \"agentbox: no TPM2 (/dev/tpmrm0): enable it in firmware or use --encryption=none\" >&2; exit 1; }"
    - "umask 077 && tr -dc 0-9 </dev/urandom | head -c 48 > /run/agentbox-luks.key && [ \"$(wc -c < /run/agentbox-luks.key)\" -eq 48 ]"
    - "printf '%s\\n' '-----BEGIN PUBLIC KEY-----' '<RECOVERY_RSA4096_PEM_LINES>' '-----END PUBLIC KEY-----' > /run/agentbox-recovery.pub"
  storage:
    swap: {size: 0}
    config:
      - {type: disk, id: d0, serial: "<DISK_SERIAL: udev ID_SERIAL>", ptable: gpt, wipe: superblock-recursive, preserve: false}
      - {type: partition, id: esp, device: d0, number: 1, size: 1G, flag: boot, grub_device: true}
      - {type: partition, id: pboot, device: d0, number: 2, size: 4G}
      - {type: partition, id: proot, device: d0, number: 3, size: -1}
      - {type: dm_crypt, id: croot, volume: proot, keyfile: /run/agentbox-luks.key, options: [luks, x-initrd.attach, timeout=300s]}
      - {type: format, id: fesp, volume: esp, fstype: fat32}
      - {type: format, id: fboot, volume: pboot, fstype: ext4}
      - {type: format, id: froot, volume: croot, fstype: btrfs}
      - {type: mount, id: mroot, device: froot, path: /, options: "compress=zstd:1,noatime"}
      - {type: mount, id: mboot, device: fboot, path: /boot}
      - {type: mount, id: mesp, device: fesp, path: /boot/efi}
  packages: [btrfs-progs, minisign, nftables, podman, crun, systemd-container, systemd-zram-generator, curl, openssl, cryptsetup, clevis, clevis-luks, clevis-tpm2, clevis-dracut, tpm2-tools]
  late-commands:
    - |
      set -eux
      DEV="$(findmnt -n -v -o SOURCE /target)"; UUID="$(blkid -s UUID -o value "$DEV")"
      LUKSDEV="$(cryptsetup status "$(basename "$DEV")" | awk '/device:/{print $2}')"
      [ -b "$LUKSDEV" ]
      # 1. generation + persistent subvolumes. tmpfiles 'Q' lines (systemd-container) ran in curtin's chroot, whose / is
      #    the btrfs top level, so var/lib/{machines,portables} are nested subvolumes: snapshots skip them and firstboot's rm can't cross them
      for sv in $(btrfs subvolume list -o /target | awk '{print $NF}'); do btrfs subvolume delete "/target/$sv"; mkdir -m 0700 "/target/$sv"; done
      btrfs subvolume snapshot /target /target/@gen-1
      for sv in @home @var_log @var_lib_agentbox @var_lib_agentbox_data @var_lib_tailscale @var_lib_ntfy @srv @snapshots; do btrfs subvolume create "/target/$sv"; done
      for p in "home @home" "var/log @var_log" "srv @srv"; do set -- $p
        cp -a --reflink=always "/target/@gen-1/$1/." "/target/$2/"; find "/target/@gen-1/$1" -mindepth 1 -delete; done
      # agent-fillable data (workspaces, agent homes and storage, images) gets its own subvolume so a qgroup can cap it
      # without starving control state (rootd.db, audit, taint.db) that stays in @var_lib_agentbox
      mkdir -m 0755 /target/@var_lib_agentbox/data
      G=/target/@gen-1
      mkdir -p $G/var/lib/agentbox $G/var/lib/tailscale $G/var/lib/ntfy $G/.snapshots $G/bootpart $G/etc/default/grub.d
      # 2. per-generation /boot on the ext4 partition
      mkdir -p /target/boot/agentbox/gens/gen-1/grub /target/boot/agentbox/gens/gen-1/efi
      find /target/boot -maxdepth 1 \( -name 'vmlinuz*' -o -name 'initrd.img*' -o -name 'config-*' -o -name 'System.map-*' \) \
        -exec mv -t /target/boot/agentbox/gens/gen-1/ {} +
      awk '$2=="/boot" {$2="/bootpart"} {print}' $G/etc/fstab > /tmp/fstab
      for m in "@home /home" "@var_log /var/log" "@var_lib_agentbox /var/lib/agentbox" "@var_lib_agentbox_data /var/lib/agentbox/data" \
               "@var_lib_tailscale /var/lib/tailscale" "@var_lib_ntfy /var/lib/ntfy" "@srv /srv" "@snapshots /.snapshots"; do set -- $m
        echo "UUID=$UUID $2 btrfs compress=zstd:1,noatime,subvol=$1 0 0" >> /tmp/fstab; done
      printf '%s\n' '/bootpart/agentbox/gens/gen-1 /boot none bind,x-systemd.requires-mounts-for=/bootpart 0 0' \
                    '/bootpart/grub /boot/grub none bind,x-systemd.requires-mounts-for=/boot 0 0' >> /tmp/fstab
      cp /tmp/fstab $G/etc/fstab
      printf '%s\n' 'GRUB_DEFAULT=saved' 'GRUB_TIMEOUT=3' 'GRUB_RECORDFAIL_TIMEOUT=5' \
        'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT panic=10 rd.emergency=reboot rd.shell=0 rd.timeout=600 ip=dhcp rd.neednet=1"' > $G/etc/default/grub.d/90-agentbox.cfg
      printf '%s\n' '[zram0]' 'zram-size = min(ram / 2, 8192)' > $G/etc/systemd/zram-generator.conf
      # Ubuntu's root is locked, so sulogin waits forever: reboot after 120 s instead (§3.3 fallback)
      for u in emergency rescue; do mkdir -p $G/etc/systemd/system/$u.service.d
        printf '%s\n' '[Unit]' 'FailureAction=reboot-force' 'SuccessAction=reboot-force' '[Service]' 'RuntimeMaxSec=120' \
          > $G/etc/systemd/system/$u.service.d/90-agentbox.conf; done
      # a hung PID 1 or kernel resets the box (§3.3 fallback); dracut loads the driver (force_drivers below)
      mkdir -p $G/etc/systemd/system.conf.d
      printf '%s\n' '[Manager]' 'RuntimeWatchdogSec=60s' > $G/etc/systemd/system.conf.d/50-agentbox.conf
      cat > $G/etc/grub.d/09_agentbox <<'G9'
      #!/bin/sh
      set -e
      BP=/bootpart
      BOOTUUID=$(grub-probe --target=fs_uuid $BP); ROOTUUID=$(grub-probe --target=fs_uuid /)
      LUKS= # rd.luks.uuid: unlock never depends on a cmdline baked into the initrd (hostonly_cmdline="no")
      if [ -f /etc/crypttab ]; then LUKS=$(awk '$1=="croot" && sub(/^UUID=/,"",$2) {print $2}' /etc/crypttab); fi
      case $LUKS in *[!0-9a-f-]*) echo "09_agentbox: bad croot UUID in /etc/crypttab" >&2; exit 1 ;; esac
      ARGS="root=UUID=$ROOTUUID ro ${GRUB_CMDLINE_LINUX} ${GRUB_CMDLINE_LINUX_DEFAULT}${LUKS:+ rd.luks.uuid=$LUKS}"
      i=0 # top-level menu index: 00_header and 05_debian_theme emit no entries
      for d in $(printf '%s\n' $BP/agentbox/gens/gen-*/ | sort -V); do g=$(basename "$d") # oldest first: an unknown saved_entry boots entry 0, never the newest trial
        case ${g#gen-} in ''|*[!0-9]*) continue ;; esac
        for k in $(ls "$d" | sed -n 's/^vmlinuz-//p' | sort -rV); do
          case $k in *[!0-9A-Za-z.+~_-]*) continue ;; esac # file names come from packages: keep them from breaking grub.cfg quoting
          [ -f "$d/initrd.img-$k" ] || continue
          printf "menuentry 'agentbox %s %s' --id 'agentbox-%s-%s' {\n insmod part_gpt\n insmod ext2\n insmod gzio\n search --no-floppy --fs-uuid --set=root %s\n linux /agentbox/gens/%s/vmlinuz-%s %s rootflags=subvol=@%s\n initrd /agentbox/gens/%s/initrd.img-%s\n}\n" \
            "$g" "$k" "$g" "$k" "$BOOTUUID" "$g" "$k" "$ARGS" "$g" "$g" "$k"
          # GRUB 'fallback' takes numeric indexes only: a one-shot trial that fails inside GRUB boots the committed entry
          printf 'if [ -n "${boot_once}" ]; then if [ "${saved_entry}" = "agentbox-%s-%s" ]; then set fallback=%s; fi; fi\n' "$g" "$k" "$i"
          i=$((i+1))
        done
      done
      # an empty or lost grubenv has no saved_entry: boot the committed generation, not entry 0 (§3.3 step 8)
      if [ -f $BP/agentbox/committed ]; then C=$(cat $BP/agentbox/committed)
        case $C in agentbox-gen-[0-9]*) ;; *) echo "09_agentbox: $BP/agentbox/committed holds no entry id" >&2; exit 1 ;; esac
        case $C in *[!0-9A-Za-z.+~_-]*) echo "09_agentbox: bad id in $BP/agentbox/committed" >&2; exit 1 ;; esac
        printf 'if [ -z "${boot_once}" ]; then if [ -z "${saved_entry}" ]; then set default="%s"; fi; fi\n' "$C"
      fi
      G9
      chmod 0755 $G/etc/grub.d/09_agentbox
      # 3. mount gen-1 exactly as the booted system will see it; nothing may propagate back to /target or the live installer
      mkdir -p /mnt/new && mount -o subvol=@gen-1 "$DEV" /mnt/new
      mount --bind /target/boot /mnt/new/bootpart
      mount --make-private /mnt/new/bootpart
      mount --bind /mnt/new/bootpart/agentbox/gens/gen-1 /mnt/new/boot
      mount --bind /mnt/new/bootpart/grub /mnt/new/boot/grub
      mount --bind /target/boot/efi /mnt/new/boot/efi
      for d in dev proc sys run; do mount --rbind "/$d" "/mnt/new/$d"; mount --make-rslave "/mnt/new/$d"; done
      KV="$(ls /mnt/new/boot | sed -n 's/^vmlinuz-//p' | sort -rV | head -n 1)"
      [ -n "$KV" ]
      [ -f "/mnt/new/boot/initrd.img-$KV" ]
      chroot /mnt/new systemctl mask apt-daily.timer apt-daily-upgrade.timer # no in-place updates outside A/B (§3.3)
      # agentbox-firewall loads its own ruleset; snapd and lxd-installer change snaps in place, outside A/B; secureboot-db
      # rewrites db/dbx at boot, and dbx updates run only as an explicit op. Masked, not purged: snapd's purge takes the
      # ubuntu-server-minimal metapackage with it and leaves sudo, systemd and cloud-init to apt autoremove
      chroot /mnt/new systemctl mask nftables.service snapd.socket snapd.service snapd.seeded.service snapd.snap-repair.timer \
        lxd-installer.socket secureboot-db.service
      # grub2-common and grub-initrd-fallback run grub-editenv at every boot, which truncates and rewrites grubenv in
      # place (§3.3 step 8), only to clear 10_linux's recordfail and initrdfail; 09_agentbox entries set neither
      chroot /mnt/new systemctl mask grub2-common.service grub-initrd-fallback.service
      # kdump's grub.d snippet adds crashkernel= even when disabled, and its crash kernel can't unlock the LUKS root
      chroot /mnt/new env DEBIAN_FRONTEND=noninteractive apt-get purge -y kdump-tools
      test ! -e /mnt/new/etc/default/grub.d/kdump-tools.cfg
      # curtin purges the ISO's kernel image, but linux-main-modules-zfs-K still needs one, so apt pulls in
      # linux-image-unsigned-K, which shim refuses under Secure Boot: install the signed build (it Conflicts with the unsigned)
      U=$(chroot /mnt/new dpkg-query -W -f '${db:Status-Abbrev}${Package}\n' 'linux-image-unsigned-*' 2>/dev/null | sed -n 's/^ii *linux-image-unsigned-/linux-image-/p')
      [ -z "$U" ] || chroot /mnt/new env DEBIAN_FRONTEND=noninteractive apt-get install -y $U
      # dracut hostonly would bake the installer's top-level root flags (subvolid=5) into the initramfs cmdline; GRUB owns them.
      # os.apply's nspawn rebuild sees no disks, so force the unlock modules and the root disk's driver chain (the loadable
      # modules behind udevadm info -a's DRIVERS==, recorded here from the real hardware; built-in drivers have no initstate).
      # Ubuntu blacklists every watchdog module and systemd-modules-load honors that, so dracut loads the box's watchdog
      # driver (else softdog) with modprobe
      DRV=; p=$(readlink -f "/sys/class/block/$(basename "$(readlink -f "$LUKSDEV")")")
      while [ "${p#/sys/devices/}" != "$p" ]; do [ -e "$p/driver/module/initstate" ] && DRV="$DRV $(basename "$(readlink -f "$p/driver/module")")"; p=${p%/*}; done
      WD=$(sort -u /sys/bus/*/devices/*/modalias | xargs -n 1 modprobe -R 2>/dev/null | xargs -r modinfo -F filename 2>/dev/null |
        sed -n 's|.*/drivers/watchdog/\([^/.]*\)\.ko.*|\1|p' | head -n 1)
      printf '%s\n' 'hostonly="yes"' 'hostonly_cmdline="no"' 'add_dracutmodules+=" btrfs systemd-cryptsetup clevis clevis-pin-sss clevis-pin-tpm2 clevis-pin-tang "' \
        "add_drivers+=\"$DRV \"" "force_drivers+=\" ${WD:=softdog} \"" > /mnt/new/etc/dracut.conf.d/90-agentbox.conf
      # 4. bind LUKS to clevis and rebuild the target initramfs BEFORE the first reboot (clevis-dracut came from packages:)
      chroot /mnt/new clevis luks bind -k /run/agentbox-luks.key -d "$LUKSDEV" sss '{"pins":{"tang":[{"thp":"<TANG_THP>","url":"<TANG_URL>"}],"tpm2":{}},"t":2}'
      chroot /mnt/new dracut -f --regenerate-all
      # fail the install here, not as a silent reboot loop at first boot (rd.shell=0 rd.emergency=reboot): every kernel's initrd
      for k in $(ls /mnt/new/boot | sed -n 's/^vmlinuz-//p'); do chroot /mnt/new lsinitrd "/boot/initrd.img-$k" > /tmp/initrd.lst
        chroot /mnt/new lsinitrd -f etc/crypttab "/boot/initrd.img-$k" | grep -q '^croot '
        for f in btrfs.ko systemd-cryptsetup clevis-luks-askpass clevis-decrypt-sss clevis-decrypt-tpm2 clevis-decrypt-tang; do grep -qE "/$f(\.[a-z]+)?\$" /tmp/initrd.lst; done
        for m in $DRV $WD; do f=$(chroot /mnt/new modinfo -k "$k" -F filename "$m"); [ "$f" = "(builtin)" ] || grep -qF "/${f##*/}" /tmp/initrd.lst; done
      done
      openssl pkeyutl -encrypt -pubin -inkey /run/agentbox-recovery.pub -pkeyopt rsa_padding_mode:oaep \
        -pkeyopt rsa_oaep_md:sha256 -in /run/agentbox-luks.key -out /mnt/new/bootpart/agentbox/recovery.bin
      shred -u /run/agentbox-luks.key
      printf '%s\n' "agentbox-gen-1-$KV" > /mnt/new/bootpart/agentbox/committed # read by 09_agentbox (§3.3 step 8)
      chroot /mnt/new update-grub
      grep -qF -- "--id 'agentbox-gen-1-$KV'" /mnt/new/boot/grub/grub.cfg # an unknown saved_entry silently boots entry 0
      chroot /mnt/new grub-editenv /boot/grub/grubenv set saved_entry="agentbox-gen-1-$KV"
      # 5. firstboot: cleanup -> verify (sha256 pin, then minisign) -> install -> reconcile -> last-good -> done
      install -m 0755 /dev/stdin /mnt/new/usr/local/sbin/agentbox-firstboot <<'FB'
      #!/bin/sh
      set -eu
      . /etc/agentbox-firstboot.env
      umask 077
      D=/run/agentbox-firstboot # RuntimeDirectory: root-only, created fresh on every start, removed when the unit stops
      [ -d "$D" ] && [ -z "$(ls -A "$D")" ]
      mkdir "$D/top"; mount -o subvolid=5 "$(findmnt -n -v -o SOURCE /)" "$D/top" # PrivateMounts=yes: gone when the unit exits
      for e in "$D/top"/* "$D/top"/.[!.]*; do [ -e "$e" ] || continue
        case "${e##*/}" in @*) continue ;; esac; rm -rf --one-file-system "$e"; done
      umount "$D/top"
      C="curl -fsSL --proto-redir =https --connect-timeout 20 --max-time 900 --retry 5 --retry-all-errors --max-filesize 64M" # $D is tmpfs: bound what a bad release host can stream
      $C -o "$D/ab.tgz" "$AGENTBOX_RELEASE_URL"; $C -o "$D/ab.tgz.minisig" "$AGENTBOX_RELEASE_URL.minisig"
      h=$(sha256sum "$D/ab.tgz"); h=${h%% *} # the pin comes first: minisign alone accepts any older signed release
      [ "$h" = "$AGENTBOX_RELEASE_SHA256" ] || { echo "agentbox-firstboot: release sha256 $h does not match the seed's $AGENTBOX_RELEASE_SHA256; nothing installed" >&2; exit 1; }
      minisign -Vm "$D/ab.tgz" -P "$AGENTBOX_MINISIGN_PUBKEY" || { echo "agentbox-firstboot: release signature does not verify with the seed's minisign key; nothing installed" >&2; exit 1; }
      mkdir "$D/x" && tar -xzf "$D/ab.tgz" -C "$D/x"
      "$D/x/install.sh" --from-firstboot
      systemctl start agentbox-reconcile.service
      /var/lib/agentbox/current/bin/agentbox os mark-last-good
      touch /var/lib/agentbox/.firstboot-done
      FB
      printf '%s\n' 'AGENTBOX_RELEASE_URL=<RELEASE_URL>' 'AGENTBOX_RELEASE_SHA256=<RELEASE_SHA256>' 'AGENTBOX_MINISIGN_PUBKEY=<MINISIGN_PUBKEY>' \
        > /mnt/new/etc/agentbox-firstboot.env
      printf '%s\n' '[Unit]' 'Description=agentbox first boot' 'After=network-online.target' 'Wants=network-online.target' \
        'ConditionPathExists=!/var/lib/agentbox/.firstboot-done' 'StartLimitIntervalSec=0' \
        '[Service]' 'Type=oneshot' 'ExecStart=/usr/local/sbin/agentbox-firstboot' 'PrivateMounts=yes' 'TimeoutStartSec=45min' \
        'RuntimeDirectory=agentbox-firstboot' 'RuntimeDirectoryMode=0700' \
        'Restart=on-failure' 'RestartSec=60' '[Install]' 'WantedBy=multi-user.target' > /mnt/new/etc/systemd/system/agentbox-firstboot.service
      chroot /mnt/new systemctl enable agentbox-firstboot.service
      # commit deadline (§3.3): reboot an uncommitted generation after 900 s. Plain shell, so it works before the agentbox
      # binary exists; it starts early in sysinit, so a unit that blocks boot can't stop it.
      install -m 0755 /dev/stdin /mnt/new/usr/local/sbin/agentbox-boot-deadline <<'BD'
      #!/bin/sh
      sleep "${AGENTBOX_BOOT_DEADLINE_SEC:-900}"
      g=$(findmnt -no FSROOT /); e="agentbox-${g#/@}-$(uname -r)"
      grep -qxF "saved_entry=$e" /boot/grub/grubenv && exit 0
      # an empty grubenv boots the committed generation through 09_agentbox's fallback: that one stays up too
      [ "$(cat /bootpart/agentbox/committed)" = "$e" ] && exit 0
      echo "agentbox: boot deadline: $e is not committed; rebooting into the committed generation" >&2
      exec systemctl reboot --force
      BD
      printf '%s\n' '[Unit]' 'Description=agentbox commit deadline' 'DefaultDependencies=no' \
        '[Service]' 'ExecStart=/usr/local/sbin/agentbox-boot-deadline' '[Install]' 'WantedBy=sysinit.target' \
        > /mnt/new/etc/systemd/system/agentbox-boot-deadline.service
      chroot /mnt/new systemctl enable agentbox-boot-deadline.service
      # 6. subiquity rsyncs the live /var/log/installer into /target/var/log/installer only AFTER late-commands, and /target
      #    is the btrfs top level: drop the copies of the seed and the generated curtin configs, and land the rest in @var_log
      rm -f /var/log/installer/autoinstall-user-data /var/log/installer/curtin-install*.yaml \
            /var/log/installer/subiquity-curtin-install.conf /var/log/installer/curtin-install/*.conf
      umount -R /mnt/new
      mountpoint -q /dev/pts; mountpoint -q /sys/fs/cgroup # the rslave rbinds kept umount -R out of the live installer
      mount -o subvol=@var_log "$DEV" /target/var/log
```
**Mode variants**, rendered by `agentbox seed`:
- **`tpm2`:** the bind pin is `tpm2 '{}'` (no PCR policy, §3.1) and `ip=dhcp rd.neednet=1` is dropped. `clevis-pin-sss`, `clevis-pin-tang`, `clevis-decrypt-sss` and `clevis-decrypt-tang` are left out of the dracut config and the initrd checks.
- **`none`:** no TPM precheck, keyfile, recovery key or `recovery.bin`, no `dm_crypt` entry, no `cryptsetup`, clevis or `tpm2-tools` packages, no LUKSDEV check, no clevis bind, no crypttab check, and no `ip=dhcp rd.neednet=1`. The btrfs volume is `proot`, and the driver chain is read from it. dracut forces only `btrfs`, and the initrd check is `btrfs.ko` plus the recorded drivers.
- **BIOS:** a 1 MiB `bios_grub` partition, with `grub_device` set on the disk, no ESP and no `/boot/efi` bind.
- **No `-y` on bind.** `clevis luks bind` is run **without `-y`**, so the Tang advertisement is verified against `thp` and not auto-trusted: a thp mismatch fails the install, it never prompts.

**In the spec, not yet in the template.** The six items v5.2 listed here all landed in weeks 1–2 (`df25de6`, `be318d0`), with `TestRenderModes` wants. So did the signed-kernel step (`331a6d3`) and the grub unit masks (`7ac1443`). Still open:
1. An `early-commands` probe of `<TANG_URL>/adv/<TANG_THP>`. Today a wrong Tang address, port or thp, or a Tang that is down, fails the install at `clevis luks bind`, after storage has wiped the disk. It needs a `tpm2+tang` gate run.

Accepted leftovers are in `LEDGER.md`.

## Appendix B: nftables
```
# agentbox fw load: the whole file is one nft -f transaction. No destroy: existing sets keep their elements.
add table inet agentbox
add chain inet agentbox output { type filter hook output priority filter; policy accept; }
flush chain inet agentbox output
add chain inet agentbox input { type filter hook input priority filter; policy drop; }
flush chain inet agentbox input
table inet agentbox {                    # declarative block = add: creates missing sets, merges static elements, appends rules
  set confined   { typeof meta skuid; flags interval; elements = { 70001-70999, 71001-71999, 1879048192-2013265919 } } # static: every agent and app sub-id block (§4.1)
  set port_allow { typeof meta skuid . tcp dport; }                      # rootd: 0 . 43100, 0 . 43200, 0 . 45001, <admin> . 45001
  set proxy_dst4 { typeof ip daddr . tcp dport; flags timeout; }         # filled ONLY by rootd (resolved Varlink → validated public IPs)
  set keys_dst4  { typeof ip daddr . tcp dport; flags timeout; }
  set git_dst4   { typeof ip daddr . tcp dport; flags timeout; }
  set proxy_dst6 { typeof ip6 daddr . tcp dport; flags timeout; }
  set keys_dst6  { typeof ip6 daddr . tcp dport; flags timeout; }
  set git_dst6   { typeof ip6 daddr . tcp dport; flags timeout; }
  set ntfy_dst4  { typeof ip daddr . tcp dport; flags timeout; }        # ntfy.sh:443 (iOS push upstream), refilled by rootd every 5 min (§6.1)
  set ntfy_dst6  { typeof ip6 daddr . tcp dport; flags timeout; }
  set private4   { typeof ip daddr; flags interval; elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12,
                   192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/3 } }  # IANA special-purpose
  set private6   { typeof ip6 daddr; flags interval; elements = { ::/127, ::ffff:0:0/96, 64:ff9b:1::/48, 100::/64, 2001::/23, 2001:db8::/32,
                   3fff::/20, 5f00::/16, fc00::/7, fe80::/10, fec0::/10, ff00::/8 } }
  set allow_private4 { typeof meta skuid . ip daddr . tcp dport; }      # approved allow_private tuples, filled ONLY by rootd
  set allow_private6 { typeof meta skuid . ip6 daddr . tcp dport; }
  set ssh_from4  { typeof ip saddr; flags interval; elements = { 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16 } }  # /etc/agentbox/ssh-from, or these defaults
  set ssh_from6  { typeof ip6 saddr; flags interval; elements = { fc00::/7, fe80::/10 } }
  chain output {
    type filter hook output priority filter; policy accept;
    meta skuid @confined counter drop
    ct direction original ct state established accept                    # long broker flows survive set-element expiry
    ip daddr 127.0.0.1 tcp dport 43000-45999 ct state new meta skuid . tcp dport @port_allow accept
    ip daddr 127.0.0.1 tcp dport 43000-45999 ct state new counter reject with tcp reset
    ip6 daddr ::1 tcp dport 43000-45999 ct state new counter reject with tcp reset
    meta skuid "_ntfy" ip daddr 127.0.0.53 meta l4proto { udp, tcp } th dport 53 accept
    meta skuid { "agentbox-proxy", "agentbox-keys", "agentbox-git", "_ntfy" } fib daddr type { local, broadcast, multicast, anycast } counter drop
    meta skuid . ip daddr . tcp dport @allow_private4 accept
    meta skuid . ip6 daddr . tcp dport @allow_private6 accept
    meta skuid { "agentbox-proxy", "agentbox-keys", "agentbox-git", "_ntfy" } ip daddr @private4 counter drop
    meta skuid { "agentbox-proxy", "agentbox-keys", "agentbox-git", "_ntfy" } ip6 daddr @private6 counter drop
    meta skuid "_ntfy" ip daddr . tcp dport @ntfy_dst4 accept
    meta skuid "_ntfy" ip6 daddr . tcp dport @ntfy_dst6 accept
    meta skuid "_ntfy" counter drop
    meta skuid "agentbox-proxy" ip daddr . tcp dport @proxy_dst4 accept
    meta skuid "agentbox-proxy" ip6 daddr . tcp dport @proxy_dst6 accept
    meta skuid "agentbox-proxy" counter drop
    meta skuid "agentbox-keys" ip daddr . tcp dport @keys_dst4 accept
    meta skuid "agentbox-keys" ip6 daddr . tcp dport @keys_dst6 accept
    meta skuid "agentbox-keys" counter drop
    meta skuid "agentbox-git" ip daddr . tcp dport @git_dst4 accept
    meta skuid "agentbox-git" ip6 daddr . tcp dport @git_dst6 accept
    meta skuid "agentbox-git" counter drop
    meta skuid { "agentbox", "agentbox-audit", "agentbox-approve", "agentbox-llm", "agentbox-llm-decide", "agentbox-ingress" } oif "lo" accept
    meta skuid { "agentbox", "agentbox-audit", "agentbox-approve", "agentbox-llm", "agentbox-llm-decide", "agentbox-ingress" } counter drop
  }
  chain input {
    type filter hook input priority filter; policy drop;
    iif "lo" accept
    ct state established,related accept
    iifname "tailscale0" accept
    udp dport 41641 accept                                               # Tailscale direct connections
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, mld-listener-query } accept
    udp sport 67 udp dport 68 accept
    ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept
    tcp dport 22 ip saddr @ssh_from4 accept
    tcp dport 22 ip6 saddr @ssh_from6 accept
  }
}
```
- **User names resolve at load.** nft looks up `_ntfy` and the service names with getpwnam ✓, so a missing user fails the whole load and every `Requires=` unit stays down.
- **rootd's insert checks.** rootd calls `ResolveHostname` with `flags = SD_RESOLVED_DNS | SD_RESOLVED_NO_SEARCH | SD_RESOLVED_NO_SYNTHESIZE | SD_RESOLVED_NO_ZONE` ✓: DNS only, with no LLMNR, mDNS, `/etc/hosts`, `_gateway` or local-hostname answers. rootd refuses the whole name if any address fails one check:
  1. The address is in `private4` or `private6`. rootd's Go table and the nft sets come from one constant list, and fwcheck compares them.
  2. The address is under a NAT64 prefix and its embedded IPv4 (RFC 6052, for that prefix length) is in `private4`. The prefixes are `64:ff9b::/96` and the network's own, found at each resolution: the PREF64 prefixes systemd-networkd learned from router advertisements (RFC 8781, `io.systemd.Network.Describe`) and the prefix DNS64 wraps `ipv4only.arpa` in (RFC 7050, through the same Varlink resolver). A failed `ipv4only.arpa` lookup refuses the name `unavailable`. Other NAT64 addresses pass, so NAT64-only LANs still work.
  3. `RTM_GETROUTE` for it doesn't return `RTN_UNICAST` out of the default route's interface, or the route has no gateway while the default route has one. This rejects addresses that look public by prefix: on-link LAN addresses (a LAN host's global IPv6, the box's own SLAAC address) and tailnet subnet routes.
- Approved `allow_private` tuples skip these checks and go only into `allow_private4` or `allow_private6`.
- **Element timeout** is 10 min. Broker sets are refreshed when a broker re-resolves (§6.3), and `ntfy_dst` by rootd's 5-min timer (§6.1). Every add uses `timeout 10m expires 10m` without `NLM_F_EXCL`: re-adding an element with an unchanged timeout and no expiration doesn't reset its expiry ✓.
- **Revocation.** When an allowlist entry is removed, rootd deletes its set elements and the matching conntrack entries (tcp, original dst `addr . port`) over NETLINK_NETFILTER. The cut takes effect at once.
- **Set definition changes.** If a release changes a set's type or flags, `add set` fails and the load fails closed. That release's migration runs `destroy set` for the changed set, and rootd refills it from rootd.db.

## Appendix C: per-agent and per-task runtime (agent `claude`, N=1, task T42)
```ini
# /etc/systemd/system/user@70001.service.d/50-agentbox.conf
[Unit]
Requires=agentbox-firewall.service agentbox-reconcile.service agentbox-rootd.service
After=agentbox-firewall.service agentbox-reconcile.service agentbox-rootd.service
[Service]
Environment=XDG_CONFIG_HOME=/var/lib/agentbox/control/xdg/claude/config XDG_DATA_HOME=/var/lib/agentbox/control/xdg/claude/data
Environment=CONTAINERS_STORAGE_CONF=/var/lib/agentbox/control/xdg/claude/config/containers/storage.conf
UnsetEnvironment=CONTAINERS_STORAGE_CONF_OVERRIDE
ExecStartPre=+/var/lib/agentbox/current/bin/agentbox fwcheck
```
```ini
# /var/lib/agentbox/control/xdg/claude/config/containers/storage.conf   (root-owned)
[storage]
driver = "overlay"
graphroot = "/var/lib/agentbox/data/agents/claude/storage"
runroot = "/run/user/70001/containers"
```
```sh
# launched by rootd (argv built from typed values; nothing interpolated from agent input)
systemd-run --user -M ag-claude@ --unit=agentbox-task-T42 --collect \
  -p Delegate=yes -p KillMode=mixed -p TimeoutStopSec=15 -p RuntimeMaxSec=7200 \
  -p 'ExecStopPost=-/usr/bin/podman rm -f -i -t 0 task-T42' \
  podman run --cgroups=split --rm --name task-T42 --network=none --userns=keep-id --security-opt=no-new-privileges --cap-drop=all \
  --security-opt=seccomp=/var/lib/agentbox/control/seccomp-task.json \
  --read-only --tmpfs /tmp:rw,size=2g --mount type=tmpfs,destination=/home/agent,tmpfs-size=4g,tmpfs-mode=0700,U=true --pids-limit=4096 --log-driver=none --dns=none \
  -v /var/lib/agentbox/data/workspaces/claude:/workspace \
  -v /run/agentbox-gate/t/T42:/run/agentbox/gate:ro  -v /run/agentbox-proxy/t/T42:/run/agentbox/egress:ro \
  -v /run/agentbox-keys/t/T42:/run/agentbox/llm:ro   -v /run/agentbox-git/t/T42:/run/agentbox/git:ro \
  -v /run/agentbox-witness/t/T42:/run/agentbox/witness:ro \
  -v /var/lib/agentbox/control/exports/claude:/opt/agentbox/exports:ro \
  -v /var/lib/agentbox/current/bin/agentbox:/usr/local/bin/agentbox:ro \
  -e HOME=/home/agent -e CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 -e CODEX_HOME=/home/agent/.codex \
  -e HTTPS_PROXY=http://127.0.0.1:8080 -e https_proxy=http://127.0.0.1:8080 \
  -e NO_PROXY=127.0.0.1,localhost,::1 -e no_proxy=127.0.0.1,localhost,::1 \
  -e GOPROXY=http://127.0.0.1:8083,https://proxy.golang.org,direct -e GOSUMDB=sum.golang.org -e GOTOOLCHAIN=local \
  -e npm_config_audit=false -e npm_config_fund=false -e npm_config_update_notifier=false \
  -e NO_UPDATE_NOTIFIER=1 -e PIP_DISABLE_PIP_VERSION_CHECK=1 \
  -e GIT_CONFIG_COUNT=2 -e GIT_CONFIG_KEY_0=core.hooksPath -e GIT_CONFIG_VALUE_0=/opt/agentbox/exports/nohooks \
  -e GIT_CONFIG_KEY_1=core.fsmonitor -e GIT_CONFIG_VALUE_1=false \
  localhost/agentbox-task:2026.11.1 agentbox taskrun
```
- **Go env.** This argv is for an agent whose allowlist holds `proxy.golang.org:443`. For any other agent, rootd passes `-e GOPROXY=off` instead of the `GOPROXY` and `GOSUMDB` pair. If the admin set `go.private`, rootd adds `-e GOPRIVATE=<patterns>` from `control/egress/<agent>.goprivate`, already validated. taskrun unsets `GOFLAGS`, `GONOSUMDB`, `GONOPROXY` and `GOINSECURE` before it starts the CLI, in case the image sets them, and starts the Go module filter on `127.0.0.1:8083` inside the container. No new mount and no published port: the filter uses the existing gate and proxy sockets.
- **Proxy env.** `HTTPS_PROXY` is the existing egress path, now explicit. `HTTP_PROXY` and `ALL_PROXY` are never set.
- **DNS.** The image's `/etc/resolv.conf` is `nameserver 127.0.0.1` with `options timeout:1 attempts:1`, and nothing listens on port 53. If the pinned podman doesn't leave the image's file in place under `--dns=none` (C-G2), rootd bind-mounts a root-owned read-only copy of it instead (R26).
- **Witness.** Writing a FIFO on a read-only mount is permitted, like connecting to a socket: the kernel skips the mount write check for special files. So the task can write the witness but can create nothing there. C-G2 checks this under rootless podman with `keep-id`.
- **Ids.** `T42` stands for a `task_<ULID>` id (§5.1); the example keeps the short form for readability.
- **`RuntimeMaxSec`** is `deadline − now`: 7200 for this top-level task, less for a child (§7).
- **Exports.** `claude-settings.json` and `claude-settings-attach.json` both set `"disableAllHooks": true`, so project, local and skill frontmatter hooks never run in a task or an attach session (§4.2).
- **Read-only directory mounts:** connecting to a Unix socket on a read-only mount is permitted, since sockets are exempt from `EROFS` and need write permission only on the socket inode.
- **Slice drop-in** `user-70001.slice.d/50-agentbox.conf`: `CPUWeight=100`, `MemoryHigh=6G`, `MemoryMax=8G`, `TasksMax=4096`, `IOWeight=100`.
- **PAM `login` for agent users.** In `/etc/pam.d/login`, `agentbox-reconcile` puts this line just before the two adjacent `pam_motd.so` lines (Ubuntu `util-linux` `debian/login.pam` ✓):
  `session [success=2 default=ignore] pam_succeed_if.so quiet user =~ ag-*`
  It skips both `pam_motd` lines for the `-M ag-<name>@` bridge session; humans still get motd. It is a managed conffile edit: reconcile re-checks it on every run, and dpkg conffile prompts keep the local version.

## Appendix D: Cedar
The actions are generated from the registry; an excerpt is shown. The policies are hand-written and validated.
```
namespace Agentbox {
  type Ctx = { approved: Bool, tainted: Bool, workspaceBound: Bool, riskEscalated: Bool, hop: Long, budgetLeftCents: Long, executor: Agent };
  // executor: from rootd task_registry, never from the caller
  // workspaceBound: agentboxd sets it from the registry flag, own scope, auditd's row for W and the task-executor holder kind; never for an attach session; never from the caller
  entity Human; entity Agent { skills: Set<String> }; entity Host; entity Domain; entity Repo; entity Generation; entity WorkspaceSnap;
  entity Lease { holder?: Agent };
  entity App { owner: Agent, manifestChanged: Bool, exposureChanged: Bool };
  entity Path { path: String, app?: App };
  entity Package { name: String };
  entity Unit { name: String };
  entity MemoryScope { kind: String, owner?: Agent };  // kind: agent | project | procedural; episodic views are kind agent, owner = subject
  entity Task { executor?: Agent, skill?: String, originatorAgent?: Agent, originatorHuman?: Human };
  entity Inbox { owner: Agent, peers: Set<Agent> };  // peers: agents linked to the owner by a live task, filled by agentboxd
  action Read, Safe, SideEffect, Coordination;
  action "app.logs", "app.status" in [Read] appliesTo { principal: [Agent, Human], resource: [App], context: Ctx };
  action "system.info", "disk.usage", "os.generations", "pkg.search", "bus.agents.list", "gh.issue.read", "gh.pr.read", "ask.quote", "ask.status"
    in [Read] appliesTo { principal: [Agent, Human], resource: [Host], context: Ctx };
  action "ask.batch" in [SideEffect] appliesTo { principal: [Agent, Human], resource: [Host], context: Ctx };
  action "memory.read" in [Read] appliesTo { principal: [Agent, Human], resource: [MemoryScope], context: Ctx };
  action "bus.inbox.read", "bus.inbox.ack", "bus.message.send" in [Coordination] appliesTo { principal: [Agent, Human], resource: [Inbox], context: Ctx };
  action "bus.task.get" in [Coordination] appliesTo { principal: [Agent, Human], resource: [Task], context: Ctx };
  action "app.start", "app.stop", "app.restart" in [Safe] appliesTo { principal: [Agent, Human], resource: [App], context: Ctx };
  action "workspace.snapshot", "repo.create" in [Safe] appliesTo { principal: [Agent, Human], resource: [Host, Repo], context: Ctx };
  action "app.deploy", "app.remove", "app.rollback" in [SideEffect] appliesTo { principal: [Agent, Human], resource: [App], context: Ctx };
  action "file.write" in [SideEffect] appliesTo { principal: [Agent, Human], resource: [Path], context: Ctx };
  action "os.pkg.install", "os.pkg.remove", "workbench.add_package" in [SideEffect] appliesTo { principal: [Agent, Human], resource: [Package], context: Ctx };
  action "os.unit.enable", "os.unit.disable" in [SideEffect] appliesTo { principal: [Agent, Human], resource: [Unit], context: Ctx };
  action "os.update" in [SideEffect] appliesTo { principal: [Human], resource: [Host], context: Ctx };
  action "os.rollback" in [SideEffect] appliesTo { principal: [Agent, Human], resource: [Generation], context: Ctx };
  action "workspace.restore" in [SideEffect] appliesTo { principal: [Agent, Human], resource: [WorkspaceSnap], context: Ctx };
  action "net.allow_domain" in [SideEffect] appliesTo { principal: [Agent, Human], resource: [Domain], context: Ctx };
  action "repo.merge", "repo.push", "gh.pr.create", "gh.pr.comment", "gh.issue.comment"
    in [SideEffect] appliesTo { principal: [Agent, Human], resource: [Repo], context: Ctx };
  action "memory.write", "memory.forget" in [SideEffect] appliesTo { principal: [Agent, Human], resource: [MemoryScope], context: Ctx };
  action "bus.task.send" in [Coordination] appliesTo { principal: [Agent, Human], resource: [Agent], context: Ctx };
  action "bus.task.claim", "bus.task.update", "bus.task.cancel" in [Coordination] appliesTo { principal: [Agent, Human], resource: [Task], context: Ctx };
  action "bus.lease.acquire", "bus.lease.heartbeat", "bus.lease.release" in [Coordination] appliesTo { principal: [Agent, Human], resource: [Lease], context: Ctx };
}
```
```cedar
@id("human-all") permit(principal is Agentbox::Human, action, resource);
@id("read") permit(principal is Agentbox::Agent, action in Agentbox::Action::"Read", resource)
  unless { resource is Agentbox::MemoryScope || resource is Agentbox::App };
@id("read-own-app") permit(principal is Agentbox::Agent, action in Agentbox::Action::"Read", resource is Agentbox::App) when { resource.owner == context.executor };
@id("memory-read") permit(principal is Agentbox::Agent, action == Agentbox::Action::"memory.read", resource is Agentbox::MemoryScope)
  when { resource.kind != "agent" || (resource has owner && resource.owner == context.executor) };
@id("own-inbox") permit(principal is Agentbox::Agent, action in [Agentbox::Action::"bus.inbox.read", Agentbox::Action::"bus.inbox.ack"],
  resource is Agentbox::Inbox) when { resource.owner == principal };
@id("message-linked") permit(principal is Agentbox::Agent, action == Agentbox::Action::"bus.message.send", resource is Agentbox::Inbox)
  when { resource.peers.contains(principal) };
@id("task-get") permit(principal is Agentbox::Agent, action == Agentbox::Action::"bus.task.get", resource is Agentbox::Task)
  when { (resource has executor && resource.executor == principal) || (resource has originatorAgent && resource.originatorAgent == principal) };
@id("safe-host-repo") permit(principal is Agentbox::Agent, action in Agentbox::Action::"Safe", resource) when { resource is Agentbox::Host || resource is Agentbox::Repo };
@id("safe-own-app") permit(principal is Agentbox::Agent, action in Agentbox::Action::"Safe", resource is Agentbox::App) when { resource.owner == context.executor };
@id("app-identical") permit(principal is Agentbox::Agent, action == Agentbox::Action::"app.deploy", resource is Agentbox::App)
  when { resource.owner == context.executor && !resource.manifestChanged && !resource.exposureChanged };
@id("file-own-app") permit(principal is Agentbox::Agent, action == Agentbox::Action::"file.write", resource is Agentbox::Path)
  when { resource.path like "/srv/*" && resource has app && resource.app.owner == context.executor };
@id("push-own-namespace") permit(principal is Agentbox::Agent, action == Agentbox::Action::"repo.push", resource is Agentbox::Repo);  // remote, namespace and policy enforced by floor + hook + rulesets
@id("approved-side-effects") permit(principal is Agentbox::Agent, action in Agentbox::Action::"SideEffect", resource) when { context.approved };
@id("memory-own") permit(principal is Agentbox::Agent, action in [Agentbox::Action::"memory.write", Agentbox::Action::"memory.forget"], resource is Agentbox::MemoryScope)
  when { resource.kind == "agent" && resource has owner && resource.owner == context.executor };
@id("memory-procedural-never") forbid(principal is Agentbox::Agent, action in [Agentbox::Action::"memory.write", Agentbox::Action::"memory.forget"], resource is Agentbox::MemoryScope)
  when { resource.kind == "procedural" };
// coordination: evaluated for the ACTOR only, plus the delegation capability check in agentboxd/rootd
@id("delegate") permit(principal is Agentbox::Agent, action == Agentbox::Action::"bus.task.send", resource is Agentbox::Agent);
@id("task-executor") permit(principal is Agentbox::Agent, action in [Agentbox::Action::"bus.task.claim", Agentbox::Action::"bus.task.update"],
  resource is Agentbox::Task) when { resource has executor && resource.executor == principal };
@id("task-claim-board") permit(principal is Agentbox::Agent, action == Agentbox::Action::"bus.task.claim", resource is Agentbox::Task)
  when { !(resource has executor) && resource has skill && principal.skills.contains(resource.skill) };
@id("task-cancel-originator") permit(principal is Agentbox::Agent, action == Agentbox::Action::"bus.task.cancel", resource is Agentbox::Task)
  when { resource has originatorAgent && resource.originatorAgent == principal };
@id("lease-acquire") permit(principal is Agentbox::Agent, action == Agentbox::Action::"bus.lease.acquire", resource is Agentbox::Lease);
@id("lease-holder") permit(principal is Agentbox::Agent, action in [Agentbox::Action::"bus.lease.heartbeat", Agentbox::Action::"bus.lease.release"],
  resource is Agentbox::Lease) when { resource has holder && resource.holder == principal };
@id("hop-limit") forbid(principal, action == Agentbox::Action::"bus.task.send", resource) when { context.hop > 3 };
@id("tainted-ask") forbid(principal, action in Agentbox::Action::"SideEffect", resource)
  when { context.tainted && !context.approved && !context.workspaceBound };
@id("workspace-bound-memory-only") forbid(principal, action in Agentbox::Action::"SideEffect", resource)
  when { context.workspaceBound && !context.approved }
  unless { action in [Agentbox::Action::"memory.write", Agentbox::Action::"memory.forget"] };
@id("risk-ask") forbid(principal, action in Agentbox::Action::"SideEffect", resource) when { context.riskEscalated && !context.approved };
@id("budget-ask") forbid(principal, action in Agentbox::Action::"SideEffect", resource) when { context.budgetLeftCents <= 0 && !context.approved };
```
- **`ask.batch`.** No policy permits it with `approved=false`, so `approved-side-effects` makes it Ask. Each member is also authorized as its own action, per chain member (§5.2). `ask.quote` and `ask.batch` admission skip the decide step. `memory-own`, `memory-procedural-never`, `risk-ask` and `budget-ask` are unchanged, so Risk ≥ 4 still sends a bound write to quarantine.
- **Agent-visible names (§5.6).** An agent sees an `@id` only for `hop-limit` and `memory-procedural-never`. An ancestor's block is `cedar.chain`; any other forbid is `cedar.custom`. Every ask reads reason `tainted` or `signed`. Diagnostics go only to audit.
- **Missing bus task id.** Evaluated as a synthetic Task with no optional attributes, so `task-get`, `task-executor`, `task-claim-board` and `task-cancel-originator` all fail on it.
- **Golden tests add:** a context missing `workspaceBound` gives Deny; `workspaceBound=true` on any non-memory action gives the same outcome as `false`; a session-origin write never gets `workspaceBound=true`; `ask.batch` is never Run; a human forbid on `ask.batch` or `ask.quote` gives Deny.
- **Evaluation of Read, Safe and SideEffect ops,** per chain member, with `context.executor` = the task's executor (strictest wins: Deny > Ask > Run):
  - Ownership predicates refer to the executor, so an ancestor never blocks the executor on resources the executor owns.
  - Non-owned resources still intersect across the chain, and so do the taint, risk and budget forbids. An ancestor-only resource is Deny.
  1. Authorize with `approved=false`. Allow means Run.
  2. Otherwise authorize with `approved=true`. Allow means Ask.
  3. Otherwise Deny.
  - Then, if the outcome is Run and `decide.Risk ≥ 4`, it becomes Ask.
- **Coordination ops and the bus reads** (`bus.task.get`, `bus.inbox.read`) are evaluated once, for the actor. For task ops the delegation capability must also be valid. The one exception is a `skills:` claim: no capability exists yet, so the atomic claim (§7) creates it.
- **Fail closed on evaluation errors.** cedar-go skips any policy whose evaluation errors, for example on a missing context key, entity or attribute ✓. So in each Authorize pass, `len(diag.Errors) > 0` means Deny for that chain member. The policy IDs and messages go to auditd.
- **Request validation.** Before each Authorize, agentboxd checks the request and the entity map against the generated schema with cedar-go `x/exp/schema/validate` (`Validator.Request`, `Validator.Entities`) ✓. Any error means Deny.
- **Typed context.** `Ctx` comes from one generated Go struct (`ops.Ctx`) with every field required. No map literals.
- **Policy IDs.** The loader adds policies one at a time with `PolicySet.Add(PolicyID(@id), p)`. It doesn't use `NewPolicySetFromBytes`, which names policies `policy0..N` ✓. Startup is refused if an `@id` is missing or duplicated (`Add` returns false on a duplicate). `policyDigest` covers the `@id`-keyed set.
- **Golden tests** include: a context missing `tainted` gives Deny; a misspelled context key gives Deny; a missing resource entity gives Deny.
- **The rootd floor applies on top in every case.**

## Appendix E: state
```sql
-- Every table is STRICT. Every instant is INTEGER Unix milliseconds UTC. JSON columns are TEXT CHECK(json_valid(x)).
-- state.db (agentboxd, synchronous=FULL)
CREATE TABLE principals(id TEXT PRIMARY KEY, kind TEXT CHECK(kind IN ('agent','app','human')), name TEXT, uid INTEGER UNIQUE, subuid_start INTEGER,
                        card TEXT CHECK(json_valid(card)), skills TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(skills)), state TEXT, created_at INTEGER,
                        UNIQUE(kind,name)) STRICT;  -- uid, subuid_start, skills: read-only copies pushed by rootd
CREATE TABLE tasks(id TEXT PRIMARY KEY, context_id TEXT, parent_id TEXT, chain TEXT NOT NULL CHECK(json_valid(chain)), executor TEXT, skill TEXT,
                   originator_kind TEXT NOT NULL, originator_id TEXT NOT NULL, state TEXT NOT NULL, a2a TEXT CHECK(json_valid(a2a)), trace_id TEXT, hop INTEGER,
                   deadline INTEGER, reserved_cents INTEGER, cost_cents INTEGER, result_taint INTEGER NOT NULL DEFAULT 0, created_at INTEGER, updated_at INTEGER,
                   CHECK (executor IS NOT NULL OR skill IS NOT NULL)) STRICT;
CREATE TABLE delegations(task_id TEXT PRIMARY KEY, parent TEXT NOT NULL, executor TEXT NOT NULL, allowed_transitions TEXT NOT NULL CHECK(json_valid(allowed_transitions)),
                         expires_at INTEGER NOT NULL, version INTEGER NOT NULL) STRICT;  -- read copy of rootd's row
CREATE TABLE messages(id TEXT PRIMARY KEY, task_id TEXT, sender TEXT, recipient TEXT, a2a TEXT CHECK(json_valid(a2a)), taint INTEGER NOT NULL,
                      acked_at INTEGER, created_at INTEGER) STRICT;
CREATE TABLE leases(resource TEXT PRIMARY KEY, holder_task TEXT NOT NULL, epoch INTEGER NOT NULL, expires_at INTEGER NOT NULL, max_until INTEGER NOT NULL) STRICT;  -- advisory (§7)
-- rootd.db (root-owned, synchronous=FULL)
CREATE TABLE ids(kind TEXT NOT NULL CHECK(kind IN ('agent','app')), n INTEGER NOT NULL CHECK(n BETWEEN 1 AND 999), name TEXT NOT NULL,
                 state TEXT NOT NULL CHECK(state IN ('active','retired')), created_at INTEGER NOT NULL, retired_at INTEGER, PRIMARY KEY(kind,n)) STRICT;  -- apps: name = '<agent>/<app>' (per-owner names, §4.1)
CREATE UNIQUE INDEX ids_active_name ON ids(kind,name) WHERE state='active';  -- rows never deleted; uid and sub-ids derived from (kind,n), §4.1
CREATE TABLE agent_skills(agent TEXT PRIMARY KEY, skills TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(skills))) STRICT;  -- admin only: agent.add, agent.skills.set
CREATE TABLE task_registry(task TEXT PRIMARY KEY, parent TEXT, agent TEXT NOT NULL, uid INTEGER NOT NULL, chain TEXT NOT NULL CHECK(json_valid(chain)),
                           origin TEXT NOT NULL, trace TEXT NOT NULL, deadline INTEGER NOT NULL, started_at INTEGER, ended_at INTEGER,
                           end_reason TEXT CHECK(end_reason IN ('completed','failed','canceled','timeout','deadline','parent_stopped')),
                           asks_budget INTEGER NOT NULL CHECK(asks_budget BETWEEN 0 AND 10),  -- §4.2 ask budget
                           asks_used INTEGER NOT NULL DEFAULT 0, asks_granted INTEGER NOT NULL DEFAULT 0,
                           asks_created INTEGER NOT NULL DEFAULT 0,  -- every ask row, free re-pends included; drives the recon alerts
                           quote_items INTEGER NOT NULL DEFAULT 0 CHECK(quote_items >= 0), quote_deny INTEGER NOT NULL DEFAULT 0,
                           CHECK(asks_used + asks_granted <= asks_budget)) STRICT;
CREATE INDEX task_registry_parent ON task_registry(parent, ended_at);
CREATE TABLE trace_quota(trace TEXT PRIMARY KEY, quote_items INTEGER NOT NULL DEFAULT 0 CHECK(quote_items >= 0),
                         quote_deny INTEGER NOT NULL DEFAULT 0, asks_created INTEGER NOT NULL DEFAULT 0) STRICT;  -- per-trace quote rollup (§5.2)
CREATE TABLE delegations(task TEXT PRIMARY KEY, parent TEXT NOT NULL, executor TEXT NOT NULL, allowed_transitions TEXT NOT NULL CHECK(json_valid(allowed_transitions)),
                         expires_at INTEGER NOT NULL, version INTEGER NOT NULL,
                         asks INTEGER NOT NULL DEFAULT 0) STRICT;  -- written at bus.task.send (to:) or at a skills: claim; asks = the parent's grant
-- pending.op: plaintext until a final state, then audit classes applied (§5.2)
CREATE TABLE pending(id TEXT PRIMARY KEY, task TEXT NOT NULL, agent TEXT NOT NULL, op TEXT NOT NULL CHECK(json_valid(op)), bound TEXT NOT NULL CHECK(json_valid(bound)),
                     h TEXT UNIQUE NOT NULL, nonce TEXT UNIQUE NOT NULL,
                     state TEXT NOT NULL CHECK(state IN ('pending','approved','executing','executed','refused','failed','indeterminate','denied','expired')),
                     signer TEXT, reason TEXT,  -- a §5.6 code, optionally ':<what>'; 'batch_denied' for an unstruck batch member
                     result TEXT CHECK(result IS NULL OR json_valid(result)),  -- outputs; ask.status returns only the agentbox-generated ones (§5.3)
                     match_key TEXT NOT NULL,   -- SHA-256 of JCS{op, structural args, bound inputs}; body hashes taken before the op marker (§5.4)
                     batch TEXT, batch_idx INTEGER,  -- member of an ask.batch row; NULL otherwise
                     expires_at INTEGER NOT NULL, approved_at INTEGER, created_at INTEGER NOT NULL,
                     CHECK(expires_at > created_at), CHECK((batch IS NULL) = (batch_idx IS NULL))) STRICT;
CREATE INDEX pending_task ON pending(task, state);
CREATE INDEX pending_match ON pending(task, match_key);
CREATE INDEX pending_batch ON pending(batch, batch_idx) WHERE batch IS NOT NULL;
CREATE TABLE task_denials(task TEXT NOT NULL, id TEXT NOT NULL, code TEXT NOT NULL, by TEXT NOT NULL, created_at INTEGER NOT NULL,
                          PRIMARY KEY(task, id)) STRICT;  -- floor denials rootd minted and Cedar denials agentboxd sent; deleted after the task's witness check
CREATE TABLE used_nonces(nonce TEXT PRIMARY KEY, used_at INTEGER NOT NULL) STRICT;
CREATE TABLE approvers(name TEXT PRIMARY KEY, ssh_pub TEXT, webauthn_credentials TEXT CHECK(json_valid(webauthn_credentials)),
                       phone_allowed INTEGER NOT NULL DEFAULT 1, revoked_at INTEGER) STRICT;
-- ssh_pub: one authorized_keys line (ssh-ed25519 or sk-ssh-ed25519@openssh.com). webauthn_credentials: [{credId, pub, state, revoked_at}].
-- pending.signer: '<name>:ssh' or '<name>:<credId>', so revocation can find the P each key or credential approved.
CREATE TABLE cas(digest TEXT PRIMARY KEY, kind TEXT CHECK(kind IN ('ctx','debs')), path TEXT NOT NULL, created_at INTEGER) STRICT;
-- written only by the admin op remote.set (humans via rootd-admin.sock)
CREATE TABLE remotes(id TEXT PRIMARY KEY, project TEXT NOT NULL, owner TEXT NOT NULL, remote_url TEXT NOT NULL, gh_node_id TEXT NOT NULL,
                     visibility TEXT NOT NULL CHECK(visibility IN ('private','internal','public')), created_at INTEGER) STRICT;
CREATE TABLE workspace_snapshots(id TEXT PRIMARY KEY, workspace TEXT NOT NULL, agent TEXT NOT NULL, task TEXT,
                                 kind TEXT NOT NULL CHECK(kind IN ('agent','pre-restore','clean-baseline')),
                                 tree_digest TEXT NOT NULL, created_at INTEGER NOT NULL) STRICT;  -- taint lives in taint.db as snap:<id>
CREATE TABLE os_lock(id INTEGER PRIMARY KEY CHECK(id = 1), plan TEXT NOT NULL, gen TEXT NOT NULL, taken_at INTEGER NOT NULL) STRICT;  -- §3.3
CREATE TABLE set_elements(set_name TEXT NOT NULL, element TEXT NOT NULL, expires_at INTEGER, PRIMARY KEY(set_name, element)) STRICT;  -- nft refill source (§6.1)
CREATE TABLE clock(id INTEGER PRIMARY KEY CHECK(id = 1), boot_id TEXT NOT NULL, offset_ms INTEGER NOT NULL) STRICT;  -- wall minus CLOCK_MONOTONIC when the dst expiries were last written; a change within the boot is a wall step: rootd rebases the expiries by it, fwcheck its now
-- taint.db (auditd, synchronous=FULL)
-- subject: 'task:<id>' | 'session:<id>' | 'workspace:<agent>#<N>' | 'ref:<repo>:<ref>' | 'snap:<id>' | 'fact:<id>'
-- content_id: for workspace: the clean-baseline snapshot; for ref: the cleared OID; for fact: the cleared body hash
CREATE TABLE taint(subject TEXT PRIMARY KEY, tainted INTEGER NOT NULL, epoch INTEGER NOT NULL DEFAULT 0, source TEXT, since INTEGER,
                   cleared_by TEXT, cleared_at INTEGER, content_id TEXT) STRICT;  -- epoch moves only on clean→tainted, on clear, and on a signed workspace.restore (§5.2); rows are never deleted, so epochs never repeat
CREATE TABLE writers(holder TEXT PRIMARY KEY, workspace TEXT NOT NULL) STRICT;  -- rw workspace mounts of task:/session: holders; rootd registers, stop deletes
CREATE TABLE task_subjects(task TEXT NOT NULL, subject TEXT NOT NULL, PRIMARY KEY(task, subject)) STRICT;  -- seeded at task.start; ref rows appended on tainted fetch
-- memory.db (agentboxd). taint: 0 trusted, 1 tainted. chain, task, source and confidence go in meta.
CREATE TABLE facts(id TEXT PRIMARY KEY, scope TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('quarantined','active','forgotten')),
                   taint INTEGER NOT NULL, author TEXT NOT NULL, approved_by TEXT, expires_at INTEGER, title TEXT, body TEXT NOT NULL,
                   meta TEXT CHECK(json_valid(meta)), created_at INTEGER NOT NULL,
                   ws_subject TEXT, ws_epoch INTEGER,  -- set by a workspace-bound write (§8); kept while quarantined, and while forgotten in the same epoch; NULL after release
                   CHECK((ws_subject IS NULL) = (ws_epoch IS NULL)),
                   CHECK(ws_epoch IS NULL OR (taint = 1 AND scope LIKE 'agent/%' AND ws_subject LIKE 'workspace:%'))) STRICT;
CREATE INDEX facts_ws ON facts(ws_subject, ws_epoch) WHERE ws_epoch IS NOT NULL;
CREATE VIRTUAL TABLE memory_fts USING fts5(id UNINDEXED, title, body);     -- active facts without a binding, and released facts (§8)
CREATE VIRTUAL TABLE memory_fts_ws USING fts5(id UNINDEXED, title, body);  -- active workspace-bound facts only; matched, never bm25-ranked
```
New store, `data/cache/<agent>/index.db` (agentbox-proxy, `synchronous=FULL`):
```sql
-- sha256, size and h1 never change after insert
CREATE TABLE entries(key TEXT PRIMARY KEY,  -- 'go:<module>@<version>.<mod|zip>', unescaped, canonical version
  sha256 TEXT NOT NULL, size INTEGER NOT NULL, h1 TEXT NOT NULL,  -- the checksum-database hash the fill matched
  upstream TEXT NOT NULL, filled_by_task TEXT NOT NULL, filled_at INTEGER NOT NULL,
  used_at INTEGER NOT NULL) STRICT;  -- updated at most once an hour
CREATE TABLE fill_days(day_start INTEGER PRIMARY KEY, bytes INTEGER NOT NULL) STRICT;  -- Unix ms of 00:00 UTC; daily fill budget
-- no availability column: the task's filter checks availability live (§6.2)
```
`control/budgets.toml` keys added in v5.3:

| Key | Default | Used by |
|---|---|---|
| `cache.agent_max_bytes` | 8 GiB | A: per-agent store limit (kernel qgroup) |
| `cache.task_fill_max_bytes`, `cache.task_fill_max_files` | 2 GiB, 20000 | A: fills per task |
| `cache.agent_fill_day_bytes` | 4 GiB | A: fills per agent per UTC day |
| `cache.max_idle_days` | 30 | A: nightly eviction |
| `memory.bound_max_per_epoch` | 50 | B: bound facts per (W, epoch) |
| `memory.bound_stale_ms` | 604800000 (7 days) | B: epoch age limit for binding |
| `memory.digest_interval_ms` | 21600000 (6 h) | B: ntfy digest |
| `keys.agent_day_share.<agent>` | the box day cap ÷ the number of agents | C: per-agent spend share |
| `ask.per_task`, `ask.per_daemon_task`, `ask.daemon_per_day` | 3, 1, 5 | D: ask budgets |
| `ask.agent_24h`, `ask.agent_ops_24h` | 20, 40 | D: per-agent caps (the 20 was a v5.2 constant) |
| `ask.quote_items_task`, `ask.quote_items_trace` | 32, 64 | D: quote caps |
| `ask.recon_items`, `ask.recon_deny`, `ask.enum_deny_trace` | 24, 4, 16 | D: task and trace alerts |
| `ask.agent_recon_items_24h`, `ask.agent_recon_deny_24h` | 128, 32 | D: per-agent alert |

The daemon-ask pool is counted from `pending` joined to `task_registry` on `origin='daemon'` over the last 24 h; no new column.

**Time rules.**
- Every instant (`*_at`, `deadline`, `since`, `expires_at`, `max_until`) is INTEGER Unix milliseconds UTC. Writers bind `time.Now().UnixMilli()` from Go.
- Predicates compare only against a bound `:now_ms`. `datetime('now')`, `CURRENT_TIMESTAMP`, a bound `time.Time` and string times are forbidden in SQL. A bound `time.Time` would be written as TEXT by the driver.
- `STRICT` rejects a TEXT time in an INTEGER column ✓. That is why `JSON` is spelled `TEXT CHECK(json_valid(x))`: STRICT rejects the `JSON` type name ✓.
- RFC3339 strings (App. F, exports, CLI output) are for display only. They are converted at the boundary and never compared as text.
- **Golden tests:** inserting `'2026-11-11T10:15:00Z'` into `pending.expires_at` fails. The approval UPDATE on a row that expired 1 minute ago affects 0 rows. Lease and delegation expiry use the same check.

## Appendix F: memory record
```yaml
id: mem_01JD8K3V
scope: project/website
state: active
author: agent:claude
chain: [human:boxadmin, agent:claude]
task: T42
source: tool:app.logs
taint: tainted
ws_subject: null
ws_epoch: null
confidence: 0.86
created: 2026-11-10T21:40:00Z
expires: 2026-12-10T21:40:00Z
approved_by: human:boxadmin
body: "app-website serves /srv/website/public; restart with app.restart{app: website}."
```
A workspace-bound fact sets `ws_subject` to `workspace:<agent>` and `ws_epoch` to the epoch integer. The audited title is {sha256, len}, like the body.
