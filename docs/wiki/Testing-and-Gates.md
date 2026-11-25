How agentbox is tested, what each test proves, and what it does not. For an overview, start at [Home](README.md).

agentbox is early alpha. Every gate on this page runs in a QEMU virtual machine. No real hardware has run agentbox yet.
The tests cover the installer, the OS layer, the milestone 2 host services (the firewall, the audit daemon, the root daemon skeleton, disk quotas and ntfy) the milestone 3 request checks, and the milestone 4 agent accounts, task containers and interactive sessions. The brokers, policy, approvals, agent bus and memory are not built, so no test covers them yet.

## Two kinds of tests

- **Unit tests** are Go tests. They run on macOS or Linux in about a minute. They need no VM.
- **Fuzz tests** are Go fuzz tests. Each one feeds random inputs to one parser for as long as you let it run. They need no VM.
- **Gates** are shell scripts in `hack/`. A gate installs Ubuntu into a QEMU VM, boots it, and checks the result. Each check prints one `PASS` or `FAIL` line. A gate passes only if every check passes.

The build plan also uses the word "gate" for the set of tests that ends a milestone (see [Roadmap](Roadmap.md)). The scripts on this page run the tests for milestones 1-4.

## At a glance

| Test | Command | Runs on | Time (at the time of writing) |
|---|---|---|---|
| Unit tests | `go vet ./... && go test ./...` | macOS or Linux | about 1 min |
| Install gate | `hack/gate.sh none\|tpm2\|tpm2+tang [uefi\|bios]` | Apple Silicon Mac | about 9-17 min; `tpm2+tang` about 20 min (18-24 in the recorded runs); `bios` about 60-80 min. Longer when several VMs install at once. |
| Disk guard gate | `hack/gate.sh dup-serial` | Apple Silicon Mac | about 1.5 min |
| `os.apply` gates | `hack/apply-gate.sh none\|tpm2\|tpm2+tang [uefi\|bios] [scenario ...]` | Apple Silicon Mac | about 90 min for all five scenarios on arm64 |
| Power-cut replay | `hack/powercut.sh <command>` | Apple Silicon Mac with a podman machine | depends on the log |
| Firewall gate (milestone 2) | `hack/fw-gate.sh [install] [checks]` | Apple Silicon Mac | about 16 min, with the `none` install |
| auditd gate (milestone 2) | `hack/audit-gate.sh [install] [audit]` | Apple Silicon Mac | about 13 min, with the `none` install |
| rootd gate (milestone 2) | `hack/rootd-gate.sh [install] [release] [checks]` | Apple Silicon Mac, with internet for the flow check | not timed separately |
| Quota and ntfy gate (milestone 2) | `hack/quota-ntfy-gate.sh [install\|quota\|ntfy ...]` | Apple Silicon Mac | about 2 min after the `none` install |
| Registry gate (milestone 3) | `hack/registry-gate.sh [install\|checks ...]` | Apple Silicon Mac | not timed separately |
| agentboxd gate (milestone 3) | `hack/agentboxd-gate.sh [install\|checks ...]` | Apple Silicon Mac | about 10 min, with the `none` install |
| Sockets gate (milestone 3) | `hack/sockets-gate.sh [install] [check]` | Apple Silicon Mac | not timed separately |
| Accounts gate (milestone 4) | `hack/accounts-gate.sh [install\|checks ...]` | Apple Silicon Mac | not timed separately |
| Tasks gate (milestone 4) | `hack/tasks-gate.sh [install\|checks ...]` | Apple Silicon Mac | not timed separately |
| Attach gate (milestone 4) | `hack/attach-gate.sh [install\|checks ...]` | Apple Silicon Mac, with `npm` and internet for the Claude Code CLI | not timed separately |
| Task env gate (milestone 4) | `hack/taskenv-gate.sh [install\|checks ...]` | Apple Silicon Mac, with internet for the task image build | not timed separately |
| Agent CLI gate (milestone 4) | `hack/cli-gate.sh [install\|checks ...]` | Apple Silicon Mac, with `npm` and internet for the Claude Code and Codex CLIs | not timed separately |
| Fuzz tests | `hack/fuzz-all.sh [DURATION]` | macOS or Linux | 24 h by default |

The times come from one Apple Silicon Mac. The milestone 2 and 3 times come from runs with four VMs at once.

## Unit tests

Run them from the repository root:

```sh
go vet ./... && go test ./...
```

What they check:

| Package | Its tests check |
|---|---|
| `internal/seed` | The seed's input rules: what it accepts and what it refuses. The rendered seed for every mode and boot type. The seed's shell pieces, run under `dash` with fake tools: the disk guard, the GRUB script `09_agentbox`, the commit deadline, driver detection, the kernel swap. The seeds for all three modes and both boot types pass `hack/verify-seed.py`. |
| `internal/recovery` | Recovery key generation. Weak or malformed public keys are refused. Encryption and decryption round-trip, including through `openssl`. |
| `internal/rootd/gens` | Generation logic: numbering, GRUB entries and grubenv, kernel order, retention, the fstab rewrite, initrd checks, plan parsing and the plan hash. |
| `internal/fw` | The rendered ruleset, the table hash and the per-set comparisons that `fwcheck` makes, the refill script, the reserved-ports check, and a wall-clock step between writes. |
| `internal/audit` | auditd: the hash chain, segment rotation and sealing, torn tails, clock steps, crashes at each seal step, disk-full mode, taint epochs and write rules, the checks on denial records and audit classes, and `audit verify`. On Linux, the tests that need `chattr` skip unless they run with `CAP_LINUX_IMMUTABLE`. |
| `internal/rootd`, `internal/rootd/resolve`, `internal/rootd/quota`, `internal/rootd/nl` | rootd: audited egress edits, the fixed port pairs, throttled denial records, and the broker units that will hide systemd-resolved; the resolver's refusal rules (private, special-purpose and NAT64-wrapped answers, the route check); the quota limits and `btrfs qgroup show` parsing; the netlink messages for sets and conntrack. Task start and stop, the rule that an attach and a task of one agent exclude each other, the task block that survives a restart, and `rootd.db`'s mode and STRICT tables. |
| `internal/ops` | The operation registry: every operation's fields, the generated files in `gen/` and the startup check against them, the denial codes table and its append-only golden list, the denial constructor, the argument and audit-class checks, and the reply checks a task will run on denials. |
| `internal/gate`, `internal/denial`, `internal/ids` | agentboxd's task gate: per-task sockets, caller identity from the socket, schema checks and typed denials. The denial encoder and its check. The `<kind>_<ULID>` ids. |
| `internal/task`, `internal/seccomp` | The task container's launch command, its generated CLI configs, the PAM line that skips motd for agent users, and how the task's PID 1 retries the gate. The task seccomp profile: no unconditional `ioctl` rule, and every 16-bit command, with and without high bits set, gets `EOPNOTSUPP` for btrfs and is allowed otherwise. The upstream profile is pinned by its SHA-256. Only Unix, IPv4, IPv6 and routing netlink sockets and Unix socket pairs are allowed, compared on the low 32 bits. `clone` and `unshare` get `EPERM` for every namespace flag, `setns` gets `EPERM` and `clone3` gets `ENOSYS`. |
| `internal/sockets` | The socket inventory, the tmpfiles.d and `.socket` units generated from it, and `agentbox sockets check` against a live tree. |
| `internal/ntfy` | ntfy's `server.yml`, the check that the running unit's uid is `_ntfy`, and publishing an alert over the Unix socket. |
| `internal/rootd/accounts` | Agent accounts: the `ids` table never reuses an agent number, so no uid or sub-id range comes back. The sub-id lines and the systemd drop-ins it writes. |
| `internal/controlpaths` | The workspace control-path list: lockfiles such as `go.sum` and `package-lock.json` need no acknowledgement, and a planted `.mcp.json`, skill or git hook does. |
| `internal/taskenv`, `internal/taskrun`, `internal/rootd/witness` | The task environment: Go, npm and pip settings, `GOPRIVATE` patterns and the no-DNS `resolv.conf`. The in-task forwarders, their retry and `503 BROKER_UNAVAILABLE`. `agentbox why`. The isolation probe: a clean task passes, and each broken layer fails its own check. The witness FIFO, which rootd reads and caps at 64 KiB. |
| `internal/rootd/attach` | Interactive sessions: the output filter (also fuzzed), the token scan with its git objects, rotated tokens, entry names, symlink targets and large files, the task block, the control-path baseline with session-home's instruction files, and the session-home checks that refuse a planted symlink. On Linux, a whole attach through rootd with a stand-in session. |
| `cmd/agentbox` | Flag parsing, help text, `os` arguments. `recovery decrypt` refuses an existing output file. |
| `hack/gate-dns` | The DNS test server that the rootd gate runs in the guest. |
| `install` | `install.sh` syncs to disk before it renames the release into place. It runs under `dash` with fake tools. |
| `hack/release` | Two builds of one release give the same bytes, and minisign verifies the signature. |
| `hack` | The test harness itself. The QEMU command line is right even from a path with spaces, commas and glob characters. The ISO pin check and `remaster-iso.sh` work. The `dup-serial` disk check works on real qcow2 images. No `apply-gate.sh` check runs a value from the VM as code on the host. `powercut.sh boot` puts the VM disk back whether its checks pass or fail. |

At the time of writing there are 207 top-level tests and 49 fuzz tests.

Some tests need outside tools: `dash`, `sha256sum`, `xorriso`, `openssl`, `minisign`, `qemu-img` and `qemu-io`, `uv` (or `python3` with PyYAML), and the `agentbox-powercut` image in the podman machine.

- Most tests skip when their tool is missing. `TestVMInstallPin` and `TestRemasterISO` fail without `sha256sum`.
- If the `openssl` on your `PATH` is LibreSSL, as on a stock Mac, the test of the installer's `openssl` line skips.
- If the `CI` variable is not empty, two tests fail instead of skipping when a tool is missing:
  - `TestRenderedSeedsVerify`, the seed check. It needs `dash`, plus `uv` or `python3` with PyYAML.
  - `TestBuild`, the release build. It needs `minisign`.

To list the tests that skipped:

```sh
go test -count=1 -v ./... | grep -e '--- SKIP'
```

To check a seed you rendered yourself, pass its `user-data` file, not the directory:

```sh
uv run --with pyyaml python3 -I hack/verify-seed.py <seed-dir>/user-data
```

It parses the YAML, checks the autoinstall structure, and runs `dash -n` on every embedded script.

What unit tests do not prove: they never boot anything. They do not run the Ubuntu installer, apt, dracut, GRUB, LUKS or a TPM. Most of the shell code runs against fake tools. The gates test the real thing.

## Fuzz tests

Each parser has a Go fuzz test, for example for seed files, keys, apt and GRUB output, nftables JSON, audit records, rootd and gate requests, denials, socket names and more. In normal `go test` runs, each fuzz test runs only its seed inputs.

To fuzz one test, from the repository root:

```sh
go test -run='^$' -fuzz='^FuzzDeny$' -fuzztime=10m ./internal/ops
```

To fuzz every test at once:

```sh
hack/fuzz-all.sh -l          # list the fuzz tests
caffeinate -i hack/fuzz-all.sh 24h
```

- The script runs the fuzz tests at low priority, `FUZZ_JOBS` at a time, each for the full duration. Then it writes `summary.txt` under `.fuzz/<start time>/`. It exits 1 if any test fails.
- `FUZZ_JOBS` defaults to what half the RAM holds, at most one per CPU. So 53 tests at 12 jobs take 5 times the duration: a 24 h run takes 5 days.
- Each `go test` process and each fuzz worker gets `GOMEMLIMIT=$FUZZ_MEM` (default `1GiB`). `FUZZ_PARALLEL` sets the workers per test (default 1).
- It records the commit the run started on, and each test's CPU seconds (`cpu_s`, the build included).
- Go keeps each test's corpus in `$(go env GOCACHE)/fuzz`, so the next run starts from it. `go clean -fuzzcache` deletes it.
- It fails, rather than listing nothing, if a package's tests don't build.
- A crash input lands in its package's `testdata/fuzz/<test>/`. Commit it with the fix, so it stays a regression test.
- On a Mac, `caffeinate -i` keeps the machine from idle sleep. Keep it on power with the lid open.

The `fuzz` workflow in CI runs each fuzz test for 3 hours, every night, in its own job, 8 jobs at a time. So 53 tests take about 22 hours. A run that is still going when the next night starts makes that run wait, so two runs never hold runners at once. A crash fails that job and uploads the crash input. Each job restores its test's corpus from the last run, and saves it at the end. Its log shows the corpus size at the start and the end, and the CPU seconds.

### The 24 h gate

PLAN milestone row 4 asks for "24 h of fuzzing, no crash". It passes at a commit when both of these hold:

- Every test that `hack/fuzz-all.sh -l` lists has fuzzed for at least 24 CPU-hours (86400 CPU seconds) in total, over runs at that commit, with the corpus carried from each run to the next.
- No run at that commit crashed.

Runs that count are `hack/fuzz-all.sh` runs whose `summary.txt` names the commit, with no `-dirty` suffix, and nightly `fuzz` jobs at the commit. A nightly job runs 4 workers for 3 hours, about 12 CPU-hours. A local run with one worker per test adds about 1 CPU-hour per hour.

No commit has met the gate yet.

## Before you run a gate

[Getting Started](Getting-Started.md) walks through the full setup. In short, you need:

1. An Apple Silicon Mac. The UEFI VM uses Apple's Hypervisor framework (HVF), which only macOS has.
2. The tools from [Getting Started, step 1](Getting-Started.md#step-1-install-the-tools), including `swtpm` and `podman`: `brew install go qemu xorriso minisign uv pkg-config swtpm podman`. You also need `git` and `make`. The Xcode Command Line Tools provide both.
3. A podman machine for `tpm2+tang` gates and power-cut replays: `podman machine init && podman machine start`.
4. The pinned Ubuntu Server 26.04.1 ISOs in `.vm/`, under their exact file names.
5. Internet access and a Mac that stays awake on AC power.
6. Free disk space. The UEFI or the BIOS VM alone needs about 12 GB in `.vm/`. Both ISOs and both VMs need about 18 GB. The VM disk is about 6 GB after an install. The `os.apply` gates can grow it past 7 GB. Power-cut runs need another 5-7 GB in `$TMPDIR`.

Download the ISOs from the repository root:

```sh
mkdir -p .vm
curl -fL -o .vm/ubuntu-26.04.1-live-server-arm64.iso \
  https://cdimage.ubuntu.com/releases/26.04.1/release/ubuntu-26.04.1-live-server-arm64.iso
curl -fL -o .vm/ubuntu-26.04.1-live-server-amd64.iso \
  https://releases.ubuntu.com/26.04.1/ubuntu-26.04.1-live-server-amd64.iso
```

- The UEFI gates use the arm64 ISO. The BIOS gates use the amd64 ISO.
- Every install checks the ISO against `hack/SHA256SUMS` first.
- Both download hosts drop a point release once the next one ships. Both ISOs then live under `https://old-releases.ubuntu.com/releases/26.04.1/`, with the same file names.
- The first arm64 install also downloads the pinned UEFI firmware into `.vm/fw`.
- The scripts also call `sha256sum`. Check that it is on your `PATH`: `command -v sha256sum`.

Keep these in mind:

- Gate VMs are throwaway test boxes. Gate seeds use the admin password `x`. Their recovery key and release-signing key live in `.vm/keys`. Never use any of them for a real box.
- Before it installs, a gate runs `hack/vm.sh reset`. That deletes this checkout's VM disk, UEFI vars and TPM state.
- The VM reaches the internet, and the Mac's `127.0.0.1` only on the Tang and release-serve ports. It can still reach your LAN and any Mac service that listens on a LAN address.
- Each VM gets 4 vCPUs and 4 GiB of RAM.
- `hack/apply-gate.sh` runs `caffeinate -i` to stop idle sleep. `hack/gate.sh` does not, so start it as `caffeinate -i hack/gate.sh none`. Closing the lid on battery still puts the Mac to sleep and freezes the VM.

## Install gate: `hack/gate.sh`

```sh
hack/gate.sh none         # arm64 UEFI VM, Secure Boot on, no disk encryption
hack/gate.sh tpm2         # LUKS2, unlocked by a software TPM
hack/gate.sh tpm2+tang    # TPM and Tang, then the Tang-down boots
hack/gate.sh tpm2 bios    # the amd64 legacy BIOS VM
```

The first argument is the encryption mode. The second picks the VM: `uefi` (the default) or `bios`.

One run goes like this:

1. **Prepare.** Build `bin/agentbox` and `bin/release-serve`. On the first run in a checkout, make throwaway keys in `.vm/keys` and an SSH key in `.vm/id_vm`.
2. **Make test releases.** `make release` builds the release under test and an older release with a valid signature. The gate then makes a tampered tarball and signs the release with another key. `bin/release-serve` serves them on `127.0.0.1:7600+ID`.
3. **Install.** Render a `--dev` seed, reset the VM, and install unattended. In `tpm2+tang` mode, start a test Tang container first.
4. **Check.** Run the checks as root in the VM over SSH. Reboot twice, and check after each boot.
5. **Finish.** In `tpm2+tang` mode, run the Tang-down boots below. Then power the VM off.

What the checks cover, in plain words:

- **Install.** `hack/vm.sh install` fails unless the installer booted from the zero-touch ISO's GRUB (except with `DIRECT_KERNEL=1`). The disk guard saw exactly one disk with the seed's serial.
- **Boot setup.** The box boots generation 1 through agentbox's own GRUB entries. `/boot` is generation 1's boot directory. GRUB's `saved_entry` and the `committed` file both name generation 1. `grub.cfg` has the fallback that boots the committed entry when grubenv is empty. The commit deadline is armed.
- **System.** The btrfs top level holds only `@*` subvolumes, with no nested subvolumes. zram swap is on. apt's daily timers, `nftables.service`, snapd, `lxd-installer`, `secureboot-db`, `grub2-common` and `grub-initrd-fallback` are masked. fwupd only refreshes metadata. `kdump-tools` is purged, and the kernel command line has no `crashkernel=`. Every kernel's initrd holds btrfs, the disk driver and the watchdog driver.
- **Unattended reboots.** The emergency shell is set to reboot on its own. PID 1 drives a watchdog with a 60 s timeout. (The install gate only reads the grubenv fallback and the emergency setting. The `breaks` scenario of `hack/apply-gate.sh` boots both cases for real.)
- **Logs and secrets.** The installer logs persist. The test password hash appears nowhere under `/var/log`. The installer's copy of the seed is gone. The seed refuses every other user and group name on the box as `--admin`.
- **Encrypted modes.** Root is on LUKS2, unlocked by clevis in the initramfs. `recovery.bin` exists, and the installer's key file was shredded. On the Mac, the gate decrypts `recovery.bin` with the test recovery key. The key is 48 digits, and it opens LUKS. The key appears in no file under `/var/log`, `/etc`, `/bootpart` or `/boot`. In `tpm2+tang` mode, the clevis binding names both the TPM and this VM's Tang.
- **Release and firstboot.** Firstboot refuses a tampered tarball, an older release with a valid signature, and a signature by another key. Each time it installs nothing. Then it installs the good release during a real boot. Reconcile runs. `install.sh` switches the `current` and `previous` links by rename, reruns cleanly, and refuses changed content. Firstboot does not run again. No unit failed, and nothing rewrote grubenv during the boot.
- **VM network.** The VM reaches release-serve at `10.0.2.2`. A probe on the Mac's `127.0.0.1` and `::1`, on a port with no forward, gets no TCP connection or UDP datagram from the VM.
- **Boot mode.** UEFI: `mokutil` reports Secure Boot on (or off, with `SECUREBOOT=0`), and shim's `is-not-revoked` check passes for every installed kernel. BIOS: the box booted with no EFI.

### Tang-down boots (`tpm2+tang` only)

After the normal checks, the gate stops Tang and boots three more times:

1. Tang is down and nobody types anything. clevis cannot unlock. The LUKS prompt times out, dracut retries, and the box reboots. The gate checks that at least 300 s passed between the prompt and the reboot. At the time of writing it took about 490 s.
2. At the next prompt, the gate types the recovery key on the serial console. The disk unlocks. The key does not appear in the serial log.
3. The gate reboots and starts Tang again while the prompt waits. clevis unlocks with no input and no extra reboot.

[Encryption and Recovery](Encryption-and-Recovery.md) explains the modes and the recovery key.

### Pass or fail

- The gate passes only if no line starts with `FAIL` and every check block finished. Then it prints `gate <tag>: all checks passed` and exits 0. Otherwise it exits non-zero: 1 when a check fails, 2 on a wrong argument. When any other step fails, the gate exits with that step's status.
- The results go to `.vm/gate-<tag>.txt`. The tag is the mode, with `-bios` added on BIOS: `gate-none.txt`, `gate-tpm2-bios.txt`, `gate-tpm2+tang.txt`, `gate-dup-serial.txt`.
- Trust the exit status. If a run stops before its first check, for example in the install, the results file from an earlier run stays in place.

### Disk guard gate: `hack/gate.sh dup-serial`

```sh
hack/gate.sh dup-serial
```

This gate attaches two NVMe disks with the same serial and starts an install. The install must stop before it writes any disk. The gate checks two things:

- `.vm/install.log` shows the guard's refusal: `agentbox: --disk-serial ... matched 2 disks, need exactly 1`.
- `qemu-img map` shows that the VM wrote neither disk.

It runs on the UEFI VM only and prints three check lines.

### What the install gates prove

In the VM you ran, they prove:

- An unattended install from the zero-touch ISO completes, booted through the firmware as on real hardware.
- The boot setup that fallback depends on is in place.
- Firstboot refuses three kinds of bad release and installs nothing. Then it installs a good one.
- The encrypted modes unlock with no input, and the recovery key opens LUKS.
- The test password hash is not in the logs, and the LUKS key is in no file the gate searches.

### What they do not prove

- **Real hardware.** The firmware, disks and network card are QEMU's. The TPM is `swtpm`, a software TPM. [Installing on Real Hardware](Installing-on-Real-Hardware.md) covers the first real run, which has not happened yet.
- **amd64 UEFI.** The UEFI VM is arm64, and the amd64 VM boots legacy BIOS only. No amd64 UEFI install has run anywhere.
- **A real release host.** Gate seeds use `--dev`, which accepts a plain-http URL on the Mac. Firstboot still checks the SHA-256 pin and the signature. The HTTPS download from a real host is not tested.
- **A real Tang server.** The gate's Tang is a container on the Mac's loopback.
- **The install's other stops.** No gate makes the Ubuntu archive unreachable or removes the TPM. Unit tests only check that the rendered seed contains those checks.
- **A long-running box.** A gate runs a fresh box for minutes or hours.

## Secure Boot and BIOS legs

The gate's `uefi` or `bios` argument sets the seed's `--boot` flag, and that picks the VM.

| | UEFI leg (default) | BIOS leg |
|---|---|---|
| Machine | arm64 `virt` under HVF | amd64 `q35` |
| Firmware | Ubuntu's AAVMF, pinned in `hack/SHA256SUMS`, with Microsoft's keys enrolled | SeaBIOS, QEMU's own |
| Disk | NVMe | SATA |
| Watchdog | `softdog` (the VM has no watchdog device) | `i6300esb` |
| Speed | hardware virtualization | KVM on Linux (CI, `none` and `tpm2`, every push to main). Software emulation (TCG) on a Mac, about five times slower. |
| Extra checks | Secure Boot on, per `mokutil`. shim's revocation check passes for every installed kernel. | The box booted with no EFI. |

The **Secure Boot leg** proves:

- On arm64 with Microsoft's keys enrolled, the installer boots through shim and GRUB.
- The installed box boots with Secure Boot on, and shim accepts every installed kernel.
- With `SECUREBOOT=0`, the box also boots with no Secure Boot keys enrolled.

It does not prove Secure Boot on amd64, or on firmware with other keys. agentbox uses no TPM PCR policy, so no gate tests one.

This variant boots the installer's kernel directly instead of through the firmware. On UEFI it needs Secure Boot off:

```sh
DIRECT_KERNEL=1 SECUREBOOT=0 hack/gate.sh none
```

The **BIOS leg** proves the amd64 install and boot with legacy BIOS GRUB, and every install check with it. `hack/apply-gate.sh <mode> bios` runs the `os.apply` gates on it too.

It does not prove amd64 UEFI or real BIOS hardware. `tpm2+tang` on BIOS is allowed, but it has not run.

## `os.apply` gates: `hack/apply-gate.sh`

These gates test OS generations: `os plan`, `os apply`, the trial boot, the health commit and the fallback. [Generations and Updates](Generations-and-Updates.md) explains how they work.

```sh
hack/apply-gate.sh tpm2                                    # all five scenarios, arm64 UEFI
hack/apply-gate.sh none install setup breaks               # only these scenarios, in this order
hack/apply-gate.sh tpm2 bios install setup cycles breaks   # on the amd64 BIOS VM
```

The first argument is the encryption mode. `uefi` or `bios` may come next. Then come the scenarios, which run in the order given. With no scenarios, it runs all five: `install setup cycles breaks cuts`.

| Scenario | What it does |
|---|---|
| `install` | Runs the install gate (`hack/gate.sh`) for the same mode and VM. Copies its check lines. |
| `setup` | Sets the commit deadline to `DEADLINE` seconds for later boots. Then checks the boot mode and what firstboot left: the release, the health timer, the committed generation, the armed deadline. |
| `cycles` | Three real applies. Generation 2 removes the newest kernel. Generation 3 brings it back with systemd upgraded, and its initrd is built inside the offline container. Generation 4 prunes generation 1. Once Linux has freed it, health has rootd check the disk quota counts, and a writer in a test quota group gets `EDQUOT` at its limit right away. Then the current generation cold-boots, the previous one boots once, and the deadline returns the box to current. |
| `breaks` | Five broken trials and an emptied grubenv (list below). Each must fall back with no console input. |
| `cuts` | Power cuts during an apply, a split grubenv, a failed `next_entry` write, then one apply replayed write by write (list below). Needs the podman machine. |

Every `os plan` in these gates also checks that apt ran none of the box's update hooks.

Before `cycles` upgrades systemd, the gate moves every installed systemd binary one archive version back, in place. That is a test fixture, so that the gate has a real upgrade to apply. `os apply` itself never downgrades.

The `breaks` scenario builds each trial with `os apply`, then breaks it:

1. **GRUB.** The trial's kernel is deleted. GRUB boots the committed entry in the same boot. Health then drops the broken entry from `grub.cfg`. Next, `os apply` must refuse to prune a generation that a kept fstab still binds, and delete nothing.
2. **initrd.** clevis is removed from the trial's initrd (btrfs, in `none` mode). The boot fails in the initramfs, and the box reboots.
3. **fstab, wrong `/boot`.** The trial's `/boot` points at the parent generation's boot directory. The boot succeeds, health refuses it, and the commit deadline falls back.
4. **fstab, missing `/boot` device.** Emergency mode reboots after 120 s.
5. **A unit that blocks boot forever.** Health does not commit, and the commit deadline falls back.

Each failed trial must be recorded as failed. Then a clean apply commits. An emptied grubenv must boot the committed entry, not entry 0. `os mark-last-good` must restore `saved_entry`.

The `cuts` scenario runs these steps:

1. A QMP reset (`hack/vm.sh cut`) at five points during `os apply`, plus one right after it returns. The five points are the clone, 3 s into the offline `apt-get install`, the initrd gate, `update-grub`, and the one-time boot setup.
2. A cut before the apply returns must leave the committed generation booting. A cut after it returns boots the complete trial, and health commits it. After every cut, `grub.cfg` passes `grub-script-check`, and grubenv names the committed entry.
3. A grubenv split between what GRUB reads and what Linux reads. Health must put back `saved_entry`, clear `next_entry`, and mark the trial failed. A `next_entry` write that fails after its rename must leave the trial pending, for one try at the next boot.
4. A clean apply commits and removes every interrupted build. At most three generations remain.
5. One more apply runs under `hack/powercut.sh log`. Then `hack/powercut.sh grub` checks GRUB's view of `/bootpart` after every write, and `hack/powercut.sh boot` boots each split it finds.

At the one-time boot point, the gate holds the `next_entry` write back. The cut then lands with the trial recorded but `next_entry` not yet written. Health must mark that trial failed.

Details:

- `DEADLINE` (default `300`) is the commit deadline for the gate, in seconds. A real box uses 900 s.
- The scenarios after `install` use the VM that a gate installed in this checkout. On a fresh checkout, start with `install`.
- On a used box, `cycles` makes higher generation numbers and prunes the oldest generation.
- Results go to `.vm/apply-gate-<tag>.txt`: timestamped `PASS` and `FAIL` lines, a `==` header per scenario, and `fails=N` at the end. Command output goes to `.vm/apply-gate-<tag>.log`. At the end, the log also gets the health and deadline journal of every boot.
- The results file starts fresh only when the first scenario is `install`. Otherwise the gate adds its lines to the old file.
- A step that cannot go on logs an `ABORT` line and exits 1. The gate exits 0 only with `fails=0`.
- The results file also records how long each fallback took, in lines like `back on <entry> after <N> s`.

### What the `os.apply` gates prove

- The whole `os.apply` path works on an installed Ubuntu box: plan, offline build, initrd gate, one-time boot, health commit, retention.
- A kernel and systemd change commits. Its initrd is built inside the offline container, and LUKS unlocks from it.
- Each injected break falls back to the committed generation with no console input. The failed trial is recorded.
- A power cut at any of these six moments leaves a box that boots the committed generation, or the complete trial: five points during `os apply`, plus one right after it returns.
- In the logged apply, every write to `/bootpart` left GRUB a bootable entry.

### What they do not prove

- **Other failures.** The breaks are faults the gate injects. A real broken update can fail in other ways.
- **Hostile packages.** Fallback covers crashes, not hostile code. A signed but malicious package in an approved plan runs as root at the trial boot. [Security Model](Security-Model.md) lists this as an accepted risk.
- **Boot-chain updates.** Updates to the shared boot chain are not A/B, and no gate covers them.
- **The watchdog firing.** The gates check that PID 1 arms the watchdog. No gate hangs the kernel to make it fire.
- **Lost write caches.** `hack/vm.sh cut` keeps every write QEMU already handed to the Mac. `hack/powercut.sh` covers flush points (next section).
- **Coverage at the time of writing.** The `cuts` scenario has run in `tpm2` mode only. On amd64, `os.apply` has one passing BIOS run, made on a fix branch before it merged.

## Power-cut testing

Two tools model a power cut.

**`hack/vm.sh cut`** sends QMP `system_reset` to the running VM. It keeps every write that QEMU already handed to the Mac. So it models only a disk with no volatile write cache. The `cuts` scenario uses it.

**`hack/powercut.sh`** models a disk whose write cache loses everything not yet flushed:

- QEMU's `blklogwrites` driver logs every write and flush the VM sends to its disk.
- xfstests' `replay-log` tool rebuilds the disk as it was after any log entry.
- The disk at a flush is what such a power cut leaves behind.

Replays run as root in the `agentbox-powercut` container, in the podman machine, through its `podman-machine-default-root` connection. The script builds the image on first use. That build needs network access. The base disk and the log live in `$TMPDIR/agentbox-powercut-<ID>`. In the podman machine, replayed file systems are opened read-only and never mounted.

| Command | What it does |
|---|---|
| `hack/powercut.sh log <vm.sh command> [args]` | Runs `hack/vm.sh <command>` (`boot` or `install`) with every disk write and flush logged. The disk as it was before the run is the replay base. |
| `hack/powercut.sh writes [rounds]` | In the running VM: fsynced atomic replaces and appends on btrfs and ext4, then the design's grubenv replace (copy, edit, sync, rename). Default 50 rounds. Runs once per disk. |
| `hack/powercut.sh marks` | Prints the log's entry count and the entry number of every flush. |
| `hack/powercut.sh check [from [to [every]]]` | Runs `btrfs check --readonly` on the disk at every flush in the range. Default: the whole log. With `every`, it checks the first flush and every `every`-th one after it. |
| `hack/powercut.sh boot <entry>...` | Boots the disk as it was after each entry. The VM must be off. |
| `hack/powercut.sh grub [from [to]]` | After every entry that writes `/bootpart`, reads it as GRUB does, with no ext4 journal replay. The entry GRUB boots must exist, with its kernel and initrd. Then lists the splits. |

GRUB does not replay the ext4 journal. A **split** is a point where GRUB reads a different `next_entry` or `saved_entry` than Linux reads after replay.

Each `boot` checks that the replayed disk:

- boots the entry GRUB picks, with `/boot` set to that generation's boot directory;
- has no btrfs or ext4 errors in the kernel log, and no failed units;
- settles on the committed entry once health has handled any trial the cut left, with `saved_entry` naming it and no `next_entry` set;
- holds consistent `writes` test files: no finished write is missing while a later one is present.

A fidelity run on a `none` box:

```sh
hack/gate.sh none
hack/powercut.sh log boot > .vm/logged-boot.txt 2>&1 &
until hack/vm.sh ssh true 2>/dev/null; do sleep 5; done
hack/powercut.sh writes 100
pkill -9 -F .vm/qemu.pid -f qemu-system
wait
hack/powercut.sh marks > .vm/marks.txt
hack/powercut.sh check
hack/powercut.sh boot $(awk '$1 == "flush" { f[++n] = $2 } END { print f[int(n/4)], f[int(n/2)], f[int(3*n/4)], f[n] }' .vm/marks.txt)
```

1. `gate.sh none` installs a fresh box with plain btrfs and powers it off.
2. `log boot` boots it with every disk write logged. Wait until SSH answers.
3. `writes 100` runs 100 rounds of test writes.
4. `pkill -9` stops QEMU at once. The log ends there.
5. `check` runs `btrfs check --readonly` at every flush.
6. The last line boots the disk at a quarter, half and three quarters of the flushes, and at the last flush.

In each such run so far, `check` tested 1026 flushes with 0 failures, and all four replayed disks booted clean.

What `hack/powercut.sh` does not model:

- Writes since the last flush that land out of order, or only in part. A replay is always a prefix of the log, in QEMU's order.
- Torn sectors.
- Disks that ignore flushes.
- Discards. QEMU drops them before the log.
- UEFI variables and TPM state. They keep their contents from the end of the run.
- `check` reads plain btrfs only, so it needs a `none` box. ext4, the ESP, the btrfs log tree and data checksums are left to `boot`.

QEMU 11.1's NVMe controller drops the FUA bit. So a FUA write counts as durable only at the next flush.

## Milestone 2 gates

Each milestone 2 gate script starts with `install`: `hack/gate.sh none`, which installs a fresh `none`-mode box on arm64 UEFI, Secure Boot on, and lets firstboot install this checkout's release by the real path (`make release`, `install.sh`, `systemd/`). The later steps run as root on that box. Each script writes `PASS` and `FAIL` lines to `.vm/<name>.txt`, command output to `.vm/<name>.log`, and exits 1 on any `FAIL`.

```sh
caffeinate -i hack/fw-gate.sh
caffeinate -i hack/audit-gate.sh
caffeinate -i hack/rootd-gate.sh
caffeinate -i hack/quota-ntfy-gate.sh
```

The firewall, rootd and quota gates enable `agentbox-agent-stub.service`, a stand-in for an agent unit. It `Requires=` the firewall and runs `fwcheck` before it starts, as every agent unit will.

### What the milestone 2 gates prove

| Suite | Script | What it proves |
|---|---|---|
| `w3-firewall` | `hack/fw-gate.sh` | The firewall loads at boot, with no log statement (drops are silent). Each of 9 alterations (a rule added or deleted, a static element removed, an element rootd never recorded, ntfy under another uid, the reserved-ports sysctl, `nftables.service` unmasked) keeps the stand-in from starting, and a firewall restart repairs it. Reload, restart, `fw load` and reboot keep the sets, and element expiry keeps running. 200 root connections to `127.0.0.1:43100` succeed; other users, other reserved ports and `[::1]` get a reset. A broker uid reaches only its own set; a confined uid reaches nothing. After `nft flush ruleset`, the health timer's `fwcheck` alerts and restores the table within 60 s. Inbound, with network-namespace peers standing in for a LAN host and a tailnet peer: a listener on `0.0.0.0:11434` is unreachable from the LAN, SSH works only from the seed's `--ssh-from` prefixes (IPv4 and IPv6), Tailscale's UDP 41641 arrives, the `tailscale0` peer reaches everything, and an enabled `ufw` that allows 11434 opens nothing. The input chain's policy set to accept, a rule added to it, the chain deleted, or an SSH prefix added each keep the stand-in from starting. |
| `w3-auditd` | `hack/audit-gate.sh` | Socket owners, modes and `SO_PEERCRED`. auditd stopped or hung means the test producer's effect never runs. The taint write rules hold from every producer socket: a clear works only as a rootd admin `taint.clear`, and the row stays with its epoch moved on. `taint.get` names `task` or `session` for each writer. A full disk refuses everything but rootd's admin operations, and `taint.clear` and `agent.remove` still run. A torn tail, a backward clock step across UTC midnight, and SIGKILL at each seal step in auditd and rootd don't stop acknowledgements. A reboot rotates the log. `agentbox audit verify` passes after each. |
| `w3-rootd` | `hack/rootd-gate.sh` | rootd's units, sandbox, sockets and `SO_PEERCRED` checks, and that it refuses passed file descriptors. The resolver refuses private, special-purpose, NAT64-wrapped, own, on-link and off-interface answers. A broker reaches only what rootd resolved. `READY=1` comes only after the sets match `rootd.db`; timer, notify and reboot refills work. A keys-like flow survives its element's expiry and is cut when its entry is removed. Audit segments are created and sealed. |
| `w3-quota-ntfy` | `hack/quota-ntfy-gate.sh` | Quotas in full qgroup mode. `2/0` covers every store agents can fill, and its limit leaves max(10%, 4 GiB) free; control state and generations are outside it; the content store has its cap; reconcile is idempotent. 1 GiB written outside `2/0` lowers its limit by 1 GiB at the next reconcile, and rootd's next check gives it back once removed. A writer at its `1/N` limit, or one that fills `2/0`, gets `EDQUOT` while system state keeps writing. ntfy runs as `_ntfy` from the packaged unit, with only its Unix socket (no TCP or UDP listener), topic ACLs, and egress only to the `ntfy.sh` answers rootd checked. With ntfy under another user, or an element rootd didn't add, `fwcheck` fails and the stand-in can't start. |

### What they do not prove

- They ran in `none` mode only, on arm64 UEFI and, in CI, on amd64 BIOS. `tpm2` and `tpm2+tang` were not run for them. The milestone 2 code does not touch unlock or boot.
- No broker exists yet. The gates write the answers a broker would get, or use a stand-in uid. Hiding systemd-resolved's Unix interfaces from the broker users waits for the broker units.
- The resolver's `unavailable` reason, for a systemd-resolved that is down, has no gate check.
- The QEMU VM reaches the internet through slirp. The rootd flow check needs a public HTTP server (`FLOW=host:port`, default `example.com:80`).

## Milestone 3 gates

Each milestone 3 gate script also starts with `install`: `hack/gate.sh none`, so the release's units and generated files reach the box by the real path. The later steps run as root on that box. Each script writes `PASS` and `FAIL` lines to `.vm/<name>.txt`, command output to `.vm/<name>.log`, and exits 1 on any `FAIL`.

```sh
caffeinate -i hack/registry-gate.sh
caffeinate -i hack/agentboxd-gate.sh
caffeinate -i hack/sockets-gate.sh
```

### What the milestone 3 gates prove

| Suite | Script | What it proves |
|---|---|---|
| `w4-registry` | `hack/registry-gate.sh` | rootd starts on the release's `gen/` files and logs the match. One byte added to `gen/cedar.schema`, a renamed MCP tool, an extra operation in the JSON schemas, a deleted `gen/ops.schema.json` and an extra file in `gen/` each stop rootd from starting, and the journal names the mismatch. With the files restored, rootd starts again. |
| `w4-agentboxd` | `hack/agentboxd-gate.sh` | agentboxd runs with no network and Unix sockets only. A task's gate socket works for its agent's uid only. A valid request runs as INTENT (body hashed), acknowledgement, effect and RESULT, with the task and agent taken from the socket. A request that fails its schema, forges its caller or names an operation no agent may call gets a typed denial, and no INTENT and no effect. An unhashed body, a secret and an unhashed `gh.*` body are each refused by auditd, and nothing runs. No refused value is in the audit directory. Revoking a task removes its socket. The chain verifies. |
| `w4-sockets` | `hack/sockets-gate.sh` | The installed box matches the socket inventory in `internal/sockets`, before and after a reboot. The installed tmpfiles.d is the generated one. A socket with the wrong mode or owner, a directory with the wrong mode, a per-task directory without setgid and a stray file are each reported, and the box matches again once they are undone. |

### What they do not prove

- They ran in `none` mode on arm64 UEFI only. The milestone 3 code does not touch unlock or boot.
- No real operation runs behind the gate yet. The agentboxd gate uses a test effect in rootd for `file.write`.
- The agentboxd gate registers its test task by hand. The milestone 4 tasks gate covers the real task start.
- The fuzz tests have not had their 24-hour run yet.

## Milestone 4 gates

Each milestone 4 gate script starts with `install`: `hack/gate.sh none`, so podman, the units, the seccomp profile and the PAM line reach the box by the real path. The later steps run as root on that box. Each script writes `PASS` and `FAIL` lines to `.vm/<name>.txt`, command output to `.vm/<name>.log`, and exits 1 on any `FAIL`.

```sh
caffeinate -i hack/accounts-gate.sh
caffeinate -i hack/tasks-gate.sh
caffeinate -i hack/attach-gate.sh
caffeinate -i hack/taskenv-gate.sh
caffeinate -i hack/cli-gate.sh
```

The tasks, attach and agent CLI gates need `npm` and internet on the Mac. Their `checks` step fetches the Claude Code CLI (and the CLI gate also Codex) for linux-arm64 with `npm pack`, checks it against `hack/SHA256SUMS`, and copies it to the VM. A Claude Code version bump changes the pin in all three; a unit test fails if they differ. The task env gate builds its task image on the box from `ubuntu:26.04`, so the VM needs internet too.

### What the milestone 4 gates prove

| Suite | Script | What it proves |
|---|---|---|
| `m4-accounts` | `hack/accounts-gate.sh` | `agentbox agent add` makes one Unix account per agent: uid and gid 70000+N, no login shell, a root-owned empty home, a 65536-wide sub-id block, root-owned config dirs the agent can read, a user manager that starts only behind the firewall, and workspace, storage and session-home subvolumes in the agent's own quota group under the shared disk reserve. An agent at its quota gets `EDQUOT`, also in its storage, while system state keeps writing. Removing the newest agent deletes its account and archives its data. Adding another agent never reuses its uid or sub-id range. A nested subvolume refuses the removal with `NESTED_SUBVOLUME` and taints the workspace. A foreign sub-id entry inside the agentbox range stops reconcile. After a reboot, reconcile brings back the same accounts. A removed agent's workspace stays tainted under its old N, and a new agent with the same name starts clean. With the quota counts marked inconsistent after a snapshot delete, rootd freezes the agent slices, refuses `file.write` and `task new` with `BUSY` and sends one alert. It thaws after a rescan, and `EDQUOT` still holds. |
| `m4-tasks` | `hack/tasks-gate.sh` | A human's `agentbox task new` runs as one rootless podman container with no network, no capabilities, a read-only root, the task seccomp profile and a fresh tmpfs HOME, inside its own systemd unit. rootd sets the provenance. A prompt at the 64,512-byte limit, counted as JSON and full of `<` and newlines, reaches the task whole; one byte more is refused before it leaves the CLI. Hooks, settings and MCP config that one task plants in HOME or the workspace, and a skill's frontmatter hook, don't reach the next task. The real Claude Code CLI runs the planted workspace hook and MCP server on the host without the task flags. Run the same way inside a task, or as a `--cli claude` task, it runs neither. An attach is refused while a task of the agent runs. A task tainted mid-run makes the next task start tainted. The agent can't write a user unit or podman config. A task that ignores SIGTERM and forks `sleep infinity` is gone within 20 s of its timeout or of `cgroup.kill`, and writes nothing after. Canceling a task removes its container and sockets within 5 s, also with auditd stopped. A task keeps working across restarts of the gate and of stand-in brokers. 20 launches each take under 300 ms, open one login session and run no `update-motd.d`. btrfs ioctls from a task fail with `EOPNOTSUPP`, also with high command bits set. `copy_file_range` from a task fails with `ENOSYS`, and `cp` still copies the file without sharing its disk blocks. A task can open Unix, IPv4, IPv6 and routing netlink sockets, fork, and use the gate socket and git. AF_ALG, AF_VSOCK (also with high bits set), audit netlink and an IPv4 socket pair fail. Namespace flags on `clone` and `unshare`, `setns`, `unshare -Ur true` and `clone3` fail. A network interface, a default route, another task's socket dir and an abstract socket, each added on its own, stop the task with `TASK_ISOLATION_PROBE` before the CLI runs, with an audit record and an ntfy alert. A normal task passes that probe in under 100 ms. A probe failure sent after the CLI starts raises no alert. After the user manager restarts, 3 tasks start and stop, with no podman pause process in a task unit. A reused pause PID makes podman fail once, and the next task still runs, with a `PAUSE_PID_STALE` audit record. `podman info` reports the pinned storage paths, also with storage drop-ins planted. `agentbox task undo` restores the start snapshot with its taint and keeps a pre-restore snapshot. Each workspace keeps the newest 5 start snapshots. A nested subvolume in the workspace refuses the task start. A workspace file that shares disk blocks with a file outside the agent's quota group makes the start snapshot mark the quota counts inconsistent: that task is refused with `BUSY` before it runs, rootd alerts and rescans, and the next task starts. |
| `m4-attach` | `hack/attach-gate.sh` | Hooks and servers planted in the workspace and in session-home run outside an attach. An attach is refused, naming the changed control paths, until `--ack-control-changes` quotes the digest the refusal printed. A control path changed after the refusal makes that digest fail. Each name is quoted, so one with terminal controls or a `, ` reaches the terminal escaped, as one entry. In that attach none of the plants runs: not the project, local or user SessionStart hooks, not the `.mcp.json` server, not the git pre-commit hook, a repo-local pager, or session-home's shell startup files and git config. That holds for Claude started by rootd, for Claude started by hand in a bash session, and for the bash shell. A file the session touches in the workspace shows on the host, so the marker checks can fail. A Claude skill, a Codex skill, a `CLAUDE.md` and a rewritten `~/.bashrc` that a session leaves in session-home, and the `~/.profile` and `~/.bash_profile` it removes, make the next attach refuse, naming them. The session's `CODEX_HOME` is in session-home, and is gone after it. The session can't write, remove or move session-home's Claude settings, and they stay byte for byte the same. The output filter drops a clipboard write (OSC 52), a DCS string and terminal report requests, and keeps colors. Tasks are blocked while an attach runs, and `task new` is refused. A session copies its login token into a workspace file, a commit that `git gc` then packs, and a loose git object. It also copies a token version that lives for half a second, then rotates the token. That leaves tasks blocked, names each copy, and sends an ntfy alert. A rescan lifts the block only once the token is gone. After a rootd restart, a clean rescan keeps the block until `--ack-restart`. With auditd stopped, `--ack-restart` is refused and the block stays. Each attach is audited, and so is each rescan that changes the block: the ack and the hit count, never a file name. The chain verifies. The session runs in the agent's rootless podman with a task's hardening: loopback only, the task seccomp profile and no capabilities. A `.git` symlink into session-home, and a relative `gitdir:` that climbs into it, each refuse the attach. Git reads the config of the git dir behind a `.git` file padded past 4 KiB, and of a git dir planted in `.git/refs`, and the attach names both. A `.git` file over 1 MiB refuses the attach. A `CLAUDE.md` symlink, its target, the file that target imports, `CLAUDE.local.md` and `AGENTS.override.md` are each named; once acknowledged, an edit to the imported file alone refuses the next attach. A `.claude` symlink, a FIFO and a 2 GiB `CLAUDE.md` in the workspace are each named as changed, nothing behind the link is read, and the attach still starts in seconds. |
| `m4-cli` | `hack/cli-gate.sh` | The task image holds Claude Code's managed settings and Codex's `requirements.toml`, root-owned and read-only, and Claude's `/status` names the managed file. Planted workspace Claude settings, a `.mcp.json` server and a subagent's MCP server add no hook or server, even for Claude run by hand with every settings source; on the host the same run starts them. Codex runs no planted hook (user, project, inline) in a task or an attach, even with `--dangerously-bypass-hook-trust` and the hooks feature forced on; on the host it does. A Codex request from a task carries no `web_search` tool, even with live search planted; on the host it does. A no-op Claude task and a no-op Codex task each open no connection, and send only model API requests. A canary line in `INSTRUCTIONS.md` reaches every Claude request, and the tool list is the pinned set. A task that writes a VS Code task, a nested repo, a venv named `env/`, a venv at the workspace root, a bare repo and a git dir's `commondir` target makes the next attach list each one. Git in a task finds no bare repo by itself. `--cli opencode` is refused. |
| `m4-taskenv` | `hack/taskenv-gate.sh` | Each task gets the environment its agent's allowlist implies. With `proxy.golang.org` allowed, Go fetches through the forwarder. Without it, `GOPROXY=off`, and `go mod download` and a `go.mod` that needs a newer Go fail at once with no connection. Image settings such as `GOFLAGS`, `GOINSECURE` and `HTTP_PROXY` are dropped. `npm test` and `pip list` open no connection. Caches a task writes don't reach the next task. With the proxy settings removed, a DNS lookup and `curl` each fail in under 1 s. The forwarders on `127.0.0.1:8080-8082` relay a CONNECT tunnel and an LLM `POST`. They survive a 3 s broker outage, and answer `503 BROKER_UNAVAILABLE` within 6 s when the broker stays down. `agentbox why` shows the newest denials and the seccomp guidance. Two agents get the same generated `CLAUDE.md` and `AGENTS.md`. The task can write its witness FIFO but not read it, rootd keeps at most 64 KiB of it, and a rootd restart marks it incomplete with no alert. `go.private.set` is audited. |

### What they do not prove

- They ran in `none` mode on arm64 UEFI only. The milestone 4 code does not touch unlock or boot.
- The brokers are not built yet. The tasks gate uses `agentbox broker-stub`, and the task env gate uses a small stand-in that binds each task's broker sockets. No task can reach a model or the internet yet.
- By default a task runs a small image: a root file system with the host's `/usr`, read-only. Only the task env gate builds and runs `image/task`, which adds Go. No agent CLI is in any task image yet. The tasks, attach and agent CLI gates run the CLIs from the host's `/usr/bin`. The stand-in keys broker answers every model request with an error, so no CLI has finished a model turn.
- A skill's frontmatter hook needs a model reply to fire, and tasks have no model yet. The tasks gate checks only the setting that turns it off.
- podman refuses `--dns=none` together with `--network=none`. The task env gate checks the image's `resolv.conf` instead.
- An attach session has no network, so a real Claude login can't reach its servers from an attach yet (issue #90).
- The 300 ms check times the whole `systemd-run` call, an upper bound on the bridge's own overhead.

## Several VMs at once

`AGENTBOX_VM_ID` (0-9, default 0) picks each VM's ports and names:

| Resource | Value |
|---|---|
| SSH | `127.0.0.1:2222+ID` |
| Tang container | `agentbox-tang-<ID>` on `127.0.0.1:7500+ID`. The VM reaches it as `http://10.0.2.2:7500+ID`. |
| Test release server | `127.0.0.1:7600+ID`. The VM reaches it as `http://10.0.2.2:7600+ID`. |
| Loopback probe | `127.0.0.1:7700+ID` and `[::1]:7700+ID`. The VM must not reach it. |
| Power-cut work directory | `$TMPDIR/agentbox-powercut-<ID>` |

Everything else lives in the checkout's `.vm/`. So each VM also needs its own checkout. Use one git worktree per VM. `AGENTBOX_ISO_DIR` points every worktree at one copy of the ISOs.

From the main checkout, which holds the ISOs in `.vm/`:

```sh
MAIN=$PWD
git worktree add --detach ../agentbox-b main
cd ../agentbox-b
AGENTBOX_VM_ID=1 AGENTBOX_ISO_DIR="$MAIN/.vm" hack/gate.sh tpm2+tang
```

At the same time, in another terminal, run a gate in the main checkout with the default ID 0.

- Give each VM its own ID. Two VMs with the same ID clash on their ports.
- Each worktree still builds its own zero-touch ISO (about 3 GB) and VM disk in its own `.vm/`.
- All VMs share the one podman machine.
- At the time of writing, up to four gates ran at the same time this way, and all of them passed.
- When you are done, copy the results out first. Then `git worktree remove ../agentbox-b` deletes the worktree, its `.vm/` included.

## Harness settings

These environment variables change the harness. Set them before the command, as in the examples above. The gate scripts pass them on to `hack/vm.sh`.

| Variable | Default | Effect |
|---|---|---|
| `AGENTBOX_VM_ID` | `0` | 0-9. Picks the ports and names above. |
| `AGENTBOX_ISO_DIR` | `.vm` | Where the stock ISOs live. |
| `SECUREBOOT` | `1` | arm64 only. `0` boots with no Secure Boot keys enrolled. |
| `DIRECT_KERNEL` | `0` | `1` boots the stock ISO's kernel with `-kernel`, not through the firmware. On UEFI it needs `SECUREBOOT=0`. |
| `DISKBUS` | `nvme` (UEFI), `sata` (BIOS) | `nvme`, `sata` or `virtio`. UEFI takes `nvme` or `virtio`. BIOS takes `sata` or `virtio`. The gates seed the matching disk serial. |
| `DUP_DISK` | `0` | `1` attaches a second disk with the same serial. `dup-serial` sets it. |
| `INSTALL_TIMEOUT` | 5400 s arm64, 14400 s amd64 | The install time limit. |
| `VM_USER` | `boxadmin` | The user for `hack/vm.sh ssh`. |
| `AGENTBOX_BLKLOG` | unset | Logs every disk write to this file. `hack/powercut.sh log` sets it. |
| `DEADLINE` | `300` | `hack/apply-gate.sh` only. The commit deadline for the gate, in seconds. |

## Where results go

Every gate writes into the checkout's `.vm/` directory. Git ignores `.vm/`. Power-cut runs also use `$TMPDIR/agentbox-powercut-<ID>`. The scripts upload nothing.

| File | Written by | Holds |
|---|---|---|
| `.vm/gate-<tag>.txt` | `hack/gate.sh` | `PASS` and `FAIL` lines, and `fails=N` per check block |
| `.vm/gate-<tag>.log` | `hack/gate.sh` | Output of the firstboot and `install.sh` checks |
| `.vm/gate-<tag>-journal.txt` | `hack/gate.sh` | The journal of firstboot, reconcile and `multi-user.target` |
| `.vm/apply-gate-<tag>.txt` | `hack/apply-gate.sh` | Timestamped `PASS` and `FAIL` lines per scenario |
| `.vm/apply-gate-<tag>.log` | `hack/apply-gate.sh` | Command output, plans, `os status`, and the health and deadline journal |
| `.vm/powercut-grub.txt` | the `cuts` scenario | `hack/powercut.sh grub` output |
| `.vm/install.log` | `hack/vm.sh install` | The installer's serial console |
| `.vm/boot-<time>.log` | `hack/vm.sh boot` | The serial console of one `boot` run, every reboot included |
| `.vm/release/serve.log` | `hack/gate.sh` | The test release server's log |

A later run replaces most of these files. To keep a run, copy the results out with the commit you tested:

```sh
mkdir -p ../gate-results/tpm2
git rev-parse HEAD > ../gate-results/tpm2/commit.txt
cp .vm/*.txt .vm/*.log ../gate-results/tpm2/
cp .vm/release/serve.log ../gate-results/tpm2/release-serve.log
```

Share only the `.txt` and `.log` files. `.vm/keys`, `.vm/id_vm` and `.vm/gate-seed-*` hold test keys and a test password hash.

## CI

`.github/workflows/ci.yml` runs on pushes to `main` and on pull requests. The `unit` job runs twice, on `ubuntu-26.04` (amd64) and `ubuntu-26.04-arm` (arm64), because the release ships both. The other jobs use `ubuntu-26.04`.

- **`unit`** installs `minisign`, `xorriso`, `python3-yaml` and `qemu-utils`, then runs `go vet ./...` and `go test -json ./...` through `hack/ciskips`. GitHub sets `CI=true`. So if `minisign`, `dash` or PyYAML were missing, `TestBuild` and `TestRenderedSeedsVerify` would fail instead of skipping.
- **`unit`** fails if any test skips that `hack/testdata/ci-skips.txt` does not list. A new test that skips in CI fails until someone lists it, with the reason. `TestGateUnwritten` needs `qemu-img` and `qemu-io`, so it runs in CI.
- **`unit`** then runs `go test -v ./internal/audit/...` again as root (`sudo env PATH=... GOTOOLCHAIN=...`). The unprivileged run skips the `chattr` tests, because `chattr +a` needs `CAP_LINUX_IMMUTABLE`. The root run covers them, and fails if any test still skips.
- **`test`** passes only if both `unit` runs passed. It is the check that branch protection requires.
- **`bios`** runs after `test` passes, on pushes to `main` only. It runs `hack/gate.sh none bios` and `hack/gate.sh tpm2 bios` under KVM, with a 120-minute limit. If `/dev/kvm` is missing, the job fails instead of falling back to slow software emulation.
- **`host-gates`** (`.github/workflows/host-gates.yml`) runs every Saturday, on manual dispatch, and on a pull request that changes it. On `ubuntu-26.04` under KVM, it installs one amd64 BIOS box with `hack/sockets-gate.sh bios install check`. The install seeds the `--ssh-from` prefixes that the firewall gate's checks expect, the ones `hack/fw-gate.sh` seeds itself. Then it runs the registry, agentboxd, firewall, audit, rootd and quota-ntfy gates' checks on that box. A failing gate does not stop the next one. It uploads `.vm/*-gate.txt` and `.vm/*-gate.log` as the `host-gates-amd64-bios` artifact.
- **`fuzz`** (`.github/workflows/fuzz.yml`) runs every night and on manual dispatch. Each fuzz test runs for 3 hours in its own job, at most 8 jobs at a time, so pull request CI still gets runners. A run fits in a day, and a concurrency group makes a late run wait for the one before it. Each job carries its test's corpus to the next night in the Actions cache. A crash fails that job and uploads the crash input as an artifact.
- The `ci` and `fuzz` jobs cache Go modules and builds, keyed on `go.sum`. The release build and `host-gates` start from a clean module download.
- `bios` uploads `.vm/gate-*.txt`, `.vm/gate-*.log`, `.vm/install.log` and `.vm/boot-*.log` as artifacts named `gate-<mode>-bios`, kept for 14 days. It never uploads `.vm/keys` or `.vm/id_vm`.

The `lint` job (gofmt, `go vet`, staticcheck, shellcheck, govulncheck) also runs on every push and pull request. `bios` runs on every push to `main`, weekly and on manual dispatch.

CI cannot run the arm64 UEFI gates as written, because they need HVF on macOS. The milestone 2 and 3 host-service gates run on amd64 BIOS in `host-gates` instead. Each takes `uefi` (the default) or `bios` as its first argument, which picks the box `install` makes. `hack/powercut.sh` also assumes a podman machine.

The `ubuntu-26.04-arm` runner has no `/dev/kvm`. The probe step in `unit` printed `ls: cannot access '/dev/kvm': No such file or directory` on 2026-11-22, in ci run 44975721818. So arm64 VM gates cannot run there under KVM either.

The `unit` job runs as an unprivileged user, so the `internal/audit` tests that need `chattr +a` skip in its first `go test` run. The root step after it runs them. They also run on macOS, where `chattr` is a no-op, and on the box through `hack/audit-gate.sh`.

## Results at the time of writing

2026-11-23. The "Tested at" column names the commit on `main` each result comes from. Most milestone 1 results come from `e2e53af`, after the review fixes. A later rerun of six suites at `61acfc7`, which changes only `hack/vm.sh`'s install timeout, also passed. The milestone 2 results come from `fb89de4`, the last milestone 2 code commit. The milestone 3 results come from `ac68bc8`, the last milestone 3 code commit, and from the registry gate fix that merged as `8c9a5fc`. The milestone 4 results come from the regression after the milestone 4 review fixes, at `deb0ef9`, `7394cd9` (which adds the task env gate) and `8b2a87c` (the `rootd.db` fix). The milestone 4 follow-up results come from each pull request's branch before it merged. A later commit can change a result, so rerun a gate before you rely on it.

The raw logs stay in the maintainer's local evidence store, not in the repo.

### Milestone 1

| Leg | Result | Tested at |
|---|---|---|
| Install, arm64 UEFI, Secure Boot on: `none`, `tpm2`, `tpm2+tang` (with the Tang-down boots) | Passed. `tpm2` and `tpm2+tang`: through the `install` step of `apply-gate.sh`. | `e2e53af` |
| Install, arm64 UEFI, Secure Boot off, direct kernel boot: `none` | Passed | `e2e53af` |
| Disk guard: `dup-serial` | Passed | `e2e53af` |
| Install, amd64 BIOS: `none`, `tpm2` | Passed on the Mac (TCG) at `c4ecfa6`. Passed in CI under KVM on every push to `main` from `3cdcca5` to `ad5338c`. | `c4ecfa6`, `ad5338c` |
| Install, amd64 BIOS: `tpm2+tang` | Not run | |
| `os.apply` on arm64 UEFI: `cycles` (`tpm2`, `tpm2+tang`), `breaks` (`tpm2`) | Passed | `e2e53af` |
| `os.apply` on arm64 UEFI: `breaks` (`none`, `tpm2+tang`) | Passed | `9aa64ef`, then a fix branch before it merged |
| `os.apply` on arm64 UEFI: `cuts` (`tpm2`) | Passed | `c4ecfa6`. The cut right after `os apply` returns ran on a fix branch before it merged. |
| `os.apply` on amd64 BIOS: `cycles` and `breaks` in `tpm2` | Passed once | a fix branch before it merged |
| Power-cut fidelity, `none` | Passed: 1026 flushes checked, 0 failed. 4 replayed disks booted, 0 failed. | `9aa64ef` |
| Logged apply in `cuts` | Passed: each run replayed more than 1,000 writes to `/bootpart`, and none left GRUB without a bootable entry. Each of the 4 splits found also booted clean. | `c4ecfa6`. The split boots ran on a fix branch before it merged. |
| Several gates at once | Passed: four VMs at once, one per worktree | `e2e53af` |
| amd64 UEFI | Not run anywhere | |
| Real hardware | Not run | |
| CI: `test` and `lint` | Passed on every push to `main` from `12b9e54`, which added `lint`, to `ad5338c`. Failed at `d375331`, the milestone 2 merge, for three causes: staticcheck SA4016; the `chattr` tests on an unprivileged runner; and govulncheck, which flagged 25 standard-library vulnerabilities in go1.26.0 (fixed by pinning `toolchain go1.26.11`); the staticcheck failure stopped `lint` before govulncheck, so it first showed on the next run. Fixed in the pull request for issue #45. The `chattr` tests run as root in `test` since issue #47. | `ad5338c`, `d375331` |

### Milestone 2

All on a fresh `none`-mode install, arm64 UEFI, Secure Boot on. Before the review fixes, all eight suites also passed once at `883f445`.

| Suite | Result | Tested at |
|---|---|---|
| `w3-firewall` | Passed: 54 PASS, 0 FAIL. `nft flush ruleset` repaired in 50 s. | `fb89de4` |
| `w3-auditd` | Passed: 111 PASS, 0 FAIL | `fb89de4` |
| `w3-rootd` | Passed: 104 PASS, 0 FAIL | `fb89de4` |
| `w3-quota-ntfy` | Passed: 54 PASS, 0 FAIL, in a second run. The first run at `fb89de4` was cut off mid-install by the harness clock, with no verdict. | `fb89de4` |
| Milestone 1 smoke: `gates-none`, `gates-tpm2-tang-down-typed-recovery`, `os-apply-cycles-tpm2`, `zero-touch-iso` | Passed | `fb89de4` |
| Milestone 2 gates on amd64 BIOS, in CI under KVM (`host-gates`), all on one `none`-mode install | Passed: `w3-firewall` 53, `w3-auditd` 61, `w3-rootd` 104 and `w3-quota-ntfy` 53 PASS, 0 FAIL each. The counts leave out the install, which the sockets gate ran. | the branch of pull request #178, before it merged |
| Milestone 2 gates in `tpm2`, `tpm2+tang` | Not run | |
| `go vet ./...` and `go test ./...` | Passed on the Mac | `fb89de4` |

### Milestone 3

All VM gates on a fresh `none`-mode install, arm64 UEFI, Secure Boot on, with four VMs at once.

| Suite | Result | Tested at |
|---|---|---|
| `w4-registry` | Failed 1 check at `ac68bc8`: the gate itself expected 3 files in the release's `gen/`, and the release ships 6 (issue #66). rootd refused every planted mismatch. After the fix: 12 PASS, 0 FAIL. | `ac68bc8`; the rerun on a fix branch before it merged as `8c9a5fc` |
| `w4-agentboxd` | Passed: 30 PASS, 0 FAIL | `ac68bc8` |
| `w4-sockets` | Passed: 38 PASS, 0 FAIL, before and after a reboot | `ac68bc8` |
| Milestone 2 suites | Passed again: `w3-firewall` 54, `w3-auditd` 112, `w3-rootd` 104 and `w3-quota-ntfy` 54 PASS, 0 FAIL each | `ac68bc8` |
| Milestone 1 smoke: `gates-none`, `gates-tpm2-tang-down-typed-recovery`, `os-apply-cycles-tpm2`, `zero-touch-iso` | Passed | `ac68bc8`; `zero-touch-iso` at `008e121`, which adds only docs and the docs lint |
| Fuzz tests, short run | All 45 for 12 minutes at once on macOS: 43 passed and 2 crashed. Both bugs are fixed, each crash input is a committed test, and the 4 affected fuzz tests then ran 12 minutes each with no crash. | the pull request branch before it merged as `ac68bc8` |
| Fuzz tests, 24 hours | Not run yet. A 24-hour local run stopped when the host restarted, with no result. The first nightly `fuzz` run: 41 of 46 fuzz tests ran 5 hours each with no crash, and 5 were still running. | `a6897c0` |
| CI: `internal/audit` as root | Passed: 28 PASS, 0 SKIP | `3b4c438` |
| `go vet ./...` and `go test ./...` | Passed on the Mac | `ac68bc8` |
| Milestone 3 gates on amd64 BIOS, in CI under KVM (`host-gates`), on the same install | Passed: `w4-registry` 11, `w4-agentboxd` 29 and `w4-sockets` 38 PASS, 0 FAIL each | the branch of pull request #178, before it merged |
| Milestone 3 gates in `tpm2`, `tpm2+tang` | Not run | |

### Milestone 4

The regression after the review fixes. Every VM gate ran on a fresh `none`-mode install, arm64 UEFI, Secure Boot on, with four VMs at once. Before the review, each milestone 4 gate also passed once on its own pull request branch.

| Suite | Result | Tested at |
|---|---|---|
| `m4-accounts` | Passed: 34 PASS, 0 FAIL | `deb0ef9` |
| `m4-tasks` | Passed: 43 PASS, 0 FAIL | `deb0ef9` |
| `m4-attach` | Passed: 34 PASS, 0 FAIL, with Claude Code 2.1.330 | `deb0ef9` |
| `m4-taskenv` | Passed: 40 PASS, 0 FAIL. Its first two runs could not start, because the gate script was not on `main` yet. | `8b2a87c` |
| Agent CLI lockdown (issues #77, #120, #121, #123) | `m4-cli` 25 PASS, 0 FAIL, with Claude Code 2.1.330 and Codex 0.171.0. `m4-tasks` 55 PASS, 0 FAIL (a first run failed only the pause PID takeover check, which no attempt won on a busy host; issue #169). Earlier on the branch, `m4-attach` 34 and `m4-taskenv` 40 PASS, 0 FAIL. `m4-cli` passed again, 25 PASS, after the rebase onto `2d7b1ea`. | `fb8c1af`; `m4-cli` also at `e3c4a42` |
| Podman setup checks (issues #124, #125, #149) | `m4-tasks` 54, `w3-rootd` 104, `m4-accounts` 34, `m4-attach` 34 and `m4-taskenv` 40 PASS, 0 FAIL | pull request #163, merged as `74a8ecc` |
| Task seccomp allowlist (issue #155) | `m4-tasks` 48, `m4-attach` 34 and `m4-taskenv` 40 PASS, 0 FAIL | pull request #161, merged as `448ba96` |
| Isolation probe (issue #106) | `m4-tasks` 61, `m4-taskenv` 40 and `w4-agentboxd` 30 PASS, 0 FAIL | pull request #167, merged as `758001f` |
| Session-home control paths, packfile token scan, taint keyed by N (issues #153, #154, #95) | `m4-attach` 34 PASS, 0 FAIL for each of #153 and #154. For #95: `m4-tasks` 61 PASS, `w3-auditd` 114 PASS, and `m4-accounts` and `m4-attach` 0 FAIL. A first `w3-auditd` run failed 1 check on a client race (issue #170). | pull requests #160, #162 and #159, merged as `e2bdd8a`, `2d7b1ea` and `b403d9b` |
| One safe workspace walker (issue #107) | `m4-attach` 36 PASS, 0 FAIL | pull request #174, merged as `201b15b` |
| Task-start snapshots and `task undo` (issue #103) | `m4-tasks` 69 PASS, 0 FAIL | pull request #176, merged as `48a56e4` |
| Quota fence (issue #79) | `m4-accounts` 47 PASS, 0 FAIL, and `w4-agentboxd` 30, at `c0f21cb`. `m4-tasks` 69 PASS, 0 FAIL on the final branch. Two `m4-accounts` reruns on the final branch stopped before the checks, on a firmware download error and a hung apt. | pull request #175, merged as `509eede` |
| Review fixes (issues #181 to #186) | On one tree that merged all six branches: `m4-tasks` 72, `m4-attach` 36, `m4-cli` 26 and `w4-agentboxd` 30 PASS, 0 FAIL. A first `m4-tasks` run failed only the pause PID takeover check (issue #169). A new amd64 CI test runs a 32-bit `socketcall(AF_VSOCK)` under podman: with seccomp off it gets a socket, and under the task profile it is killed with `SIGSYS`. | pull requests #187 to #192 |
| Milestone 2 and 3 suites after the CI changes (issue #100) | arm64: `w4-sockets` 38 and `w4-registry` 12 PASS, 0 FAIL; `w3-firewall` 54 then `w3-auditd` 61 PASS, 0 FAIL on one disk | pull request #178, merged as `4a13934` |
| Not merged yet | Inbound firewall (issue #80): `w3-firewall` 72, `w3-rootd` 104 and `w3-quota-ntfy` 54 PASS, 0 FAIL on its branch; `gates-none` did not finish on its own. Image checks (issues #102, #109): the new `m4-image` gate has not passed. Credential scan (issue #104): its `m4-tasks` rerun has not finished. | pull request #172; unpushed branches for #102 and #104 |
| Milestone 3 suites | Passed again: `w4-registry` 12, `w4-agentboxd` 30 and `w4-sockets` 38 PASS, 0 FAIL each | `7394cd9` |
| Milestone 2 suites | `w3-firewall` 54, `w3-auditd` 114 and `w3-quota-ntfy` 54 PASS, 0 FAIL each. `w3-rootd` failed 2 checks at `7394cd9`: `rootd.db` was world-readable, because reconcile now creates it first, and two new tables were not STRICT (issue #150). After the fix: 104 PASS, 0 FAIL. | `7394cd9`; `w3-rootd` at `8b2a87c` |
| Milestone 1 smoke: `gates-none`, `gates-tpm2-tang-down-typed-recovery`, `os-apply-cycles-tpm2`, `zero-touch-iso` | Passed | `deb0ef9` |
| Inbound firewall (issue #80) | `w3-firewall` 72 PASS, 0 FAIL, with the new inbound checks. A first run failed only the `tailscale0` check, a bug in the gate's own probe. `w3-rootd` 104 and `w3-quota-ntfy` 54 PASS, 0 FAIL. The `hack/gate.sh none` install inside `w3-quota-ntfy` passed with the default SSH ranges. Two standalone `gates-none` runs stopped early, both times because the host slept. | `d654152` |
| Milestone 4 gates in `tpm2`, `tpm2+tang`, amd64 BIOS | Not run | |
| `go vet ./...` and `go test ./...` | Passed on the Mac | `8b2a87c` |

## Troubleshooting

- **`vm.sh: install failed or timed out; see .../.vm/install.log`.** Search `install.log` for `An error occurred`. Failures seen so far: package downloads from the Ubuntu archive failed, or the Mac went to sleep during the install. The `os.apply` gates need the archive too, because `os plan` downloads packages.
- **`vm.sh: ... does not match hack/SHA256SUMS`.** The ISO is not the pinned file. Download it again, under its exact name.
- **`vm.sh: a VM is running`.** A QEMU from this checkout is still up. Stop it with `pkill -F .vm/qemu.pid -f qemu-system`.
- **`powercut.sh: ... is the disk a killed 'boot' set aside; move it back`.** An interrupted `powercut.sh boot` left the original disk at `.vm/disk.qcow2.powercut`. Move it back to `.vm/disk.qcow2`.
- **To look inside a VM after a gate,** boot it with `hack/vm.sh boot &`, then log in with `hack/vm.sh ssh`. The `sudo` password is `x`. For a `tpm2+tang` box, run `hack/vm.sh tang up` first.

## See also

- [Getting Started](Getting-Started.md): set up the Mac and run a first gate.
- [Generations and Updates](Generations-and-Updates.md): what `os plan` and `os apply` do.
- [Encryption and Recovery](Encryption-and-Recovery.md): the encryption modes, Tang and the recovery key.
- [Release Pipeline](Release-Pipeline.md): `make release` and firstboot.
- [Contributing](Contributing.md): how to send a change, and which gate covers which code.
- [Roadmap](Roadmap.md): the milestone each gate ends.
