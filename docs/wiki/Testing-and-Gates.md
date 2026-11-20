How agentbox is tested, what each test proves, and what it does not. For an overview, start at [Home](README.md).

agentbox is early alpha. Every gate on this page runs in a QEMU virtual machine. No real hardware has run agentbox yet.
The tests cover the installer and the OS layer. The agent runtime is not built, so no test covers it yet.

## Two kinds of tests

- **Unit tests** are Go tests. They run on macOS or Linux in about a minute. They need no VM.
- **Gates** are shell scripts in `hack/`. A gate installs Ubuntu into a QEMU VM, boots it, and checks the result. Each check prints one `PASS` or `FAIL` line. A gate passes only if every check passes.

The build plan also uses the word "gate" for the set of tests that ends a milestone (see [Roadmap](Roadmap.md)). The scripts on this page run the tests for weeks 1-2.

## At a glance

| Test | Command | Runs on | Time (at the time of writing) |
|---|---|---|---|
| Unit tests | `go vet ./... && go test ./...` | macOS or Linux | about 1 min |
| Install gate | `hack/gate.sh none\|tpm2\|tpm2+tang [uefi\|bios]` | Apple Silicon Mac | about 9-17 min; `tpm2+tang` about 20 min (18-24 in the recorded runs); `bios` about 60-80 min. Longer when several VMs install at once. |
| Disk guard gate | `hack/gate.sh dup-serial` | Apple Silicon Mac | about 1.5 min |
| `os.apply` gates | `hack/apply-gate.sh none\|tpm2\|tpm2+tang [uefi\|bios] [scenario ...]` | Apple Silicon Mac | about 90 min for all five scenarios on arm64 |
| Power-cut replay | `hack/powercut.sh <command>` | Apple Silicon Mac with a podman machine | depends on the log |

The times come from one Apple Silicon Mac.

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
| `cmd/agentbox` | Flag parsing, help text, `os` arguments. `recovery decrypt` refuses an existing output file. |
| `install` | `install.sh` syncs to disk before it renames the release into place. It runs under `dash` with fake tools. |
| `hack/release` | Two builds of one release give the same bytes, and minisign verifies the signature. |
| `hack` | The test harness itself. The QEMU command line is right even from a path with spaces, commas and glob characters. The ISO pin check and `remaster-iso.sh` work. The `dup-serial` disk check works on real qcow2 images. No `apply-gate.sh` check runs a value from the VM as code on the host. `powercut.sh boot` puts the VM disk back whether its checks pass or fail. |

At the time of writing there are 52 top-level tests. There are no fuzz tests yet. Fuzzers are planned for week 4.

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

## Before you run a gate

[Getting Started](Getting-Started.md) walks through the full setup. In short, you need:

1. An Apple Silicon Mac. The UEFI VM uses Apple's Hypervisor framework (HVF), which only macOS has.
2. The tools from [Getting Started, step 1](Getting-Started.md#step-1-install-the-tools), including `swtpm` and `podman`: `brew install go qemu xorriso minisign uv swtpm podman`. You also need `git` and `make`. The Xcode Command Line Tools provide both.
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
- The VM can reach every service on the Mac's `127.0.0.1` through `10.0.2.2`. Do not run untrusted code in it.
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
| Speed | hardware virtualization | KVM on Linux (the CI design; not run yet). Software emulation (TCG) on a Mac, about five times slower. |
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
| `cycles` | Three real applies. Generation 2 removes the newest kernel. Generation 3 brings it back with systemd upgraded, and its initrd is built inside the offline container. Generation 4 prunes generation 1. Then the current generation cold-boots, the previous one boots once, and the deadline returns the box to current. |
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

## Several VMs at once

`AGENTBOX_VM_ID` (0-9, default 0) picks each VM's ports and names:

| Resource | Value |
|---|---|
| SSH | `127.0.0.1:2222+ID` |
| Tang container | `agentbox-tang-<ID>` on `127.0.0.1:7500+ID`. The VM reaches it as `http://10.0.2.2:7500+ID`. |
| Test release server | `127.0.0.1:7600+ID` |
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

`.github/workflows/ci.yml` runs on pushes to `main` and on pull requests. Both jobs use `ubuntu-26.04` runners.

- **`test`** installs `minisign`, `xorriso` and `python3-yaml`, then runs `go vet ./... && go test ./...`. GitHub sets `CI=true`. So if `minisign`, `dash` or PyYAML were missing, `TestBuild` and `TestRenderedSeedsVerify` would fail instead of skipping.
- **`bios`** runs after `test` passes. It runs `hack/gate.sh none bios` and `hack/gate.sh tpm2 bios` under KVM, with a 120-minute limit. If `/dev/kvm` is missing, the job fails instead of falling back to slow software emulation.
- `bios` uploads `.vm/gate-*.txt`, `.vm/gate-*.log`, `.vm/install.log` and `.vm/boot-*.log` as artifacts named `gate-<mode>-bios`, kept for 14 days. It never uploads `.vm/keys` or `.vm/id_vm`.

At the time of writing, this workflow has never run. The repository had no remote yet.

CI cannot run the arm64 UEFI gates as written, because they need HVF on macOS. `hack/powercut.sh` also assumes a podman machine.

## Results at the time of writing

November 2026. The "Tested at" column names the commit each result comes from. `40d9832` is the head of `main` at the time of writing. A later commit can change a result, so rerun a gate before you rely on it.

| Leg | Result | Tested at |
|---|---|---|
| Install, arm64 UEFI, Secure Boot on: `none`, `tpm2`, `tpm2+tang` (with the Tang-down boots) | Passed. `tpm2` and `tpm2+tang`: through the `install` step of `apply-gate.sh`. | `40d9832` |
| Install, arm64 UEFI, Secure Boot off, direct kernel boot: `none` | Passed | `40d9832` |
| Disk guard: `dup-serial` | Passed | `40d9832` |
| Install, amd64 BIOS: `none`, `tpm2` | Passed | `54fbb46` |
| Install, amd64 BIOS: `tpm2+tang` | Not run | |
| `os.apply` on arm64 UEFI: `cycles` (`tpm2`, `tpm2+tang`), `breaks` (`tpm2`) | Passed | `40d9832` |
| `os.apply` on arm64 UEFI: `breaks` (`none`, `tpm2+tang`) | Passed | `ab8c10b`, then a fix branch before it merged |
| `os.apply` on arm64 UEFI: `cuts` (`tpm2`) | Passed | `54fbb46`. The cut right after `os apply` returns ran on a fix branch before it merged. |
| `os.apply` on amd64 BIOS: `cycles` and `breaks` in `tpm2` | Passed once | a fix branch before it merged |
| Power-cut fidelity, `none` | Passed: 1026 flushes checked, 0 failed. 4 replayed disks booted, 0 failed. | `ab8c10b` |
| Logged apply in `cuts` | Passed: each run replayed more than 1,000 writes to `/bootpart`, and none left GRUB without a bootable entry. Each of the 4 splits found also booted clean. | `54fbb46`. The split boots ran on a fix branch before it merged. |
| Several gates at once | Passed: four VMs at once, one per worktree | `40d9832` |
| amd64 UEFI | Not run anywhere | |
| Real hardware | Not run | |
| CI | Never run | |

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
- [Contributing](Contributing.md): how to send a change.
